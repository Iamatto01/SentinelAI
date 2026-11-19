import { calculateBaseScoreV4, humanizeScore } from 'cvss4'

/**
 * CVSS v4.0 Standard Scoring Module (FIRST.org Specification)
 * Standardizes vulnerability scoring, vector calculation, and qualitative rating bands.
 *
 * DESIGN CONTRACT — read before editing a vector:
 *   A CVSS v4.0 base score is a *derived* value, never a number attached to a
 *   finding. Every score in the product must come from `calculateCvss4(vector)`
 *   for a vector that actually describes the finding. Hand-assigning `cvss: 10.0`
 *   to a file-upload or IDOR finding produced an internally contradictory report
 *   (CRITICAL 9.3 ranked below HIGH 10.0), because 10.0 is unreachable without
 *   full CIA loss on BOTH the vulnerable system and subsequent systems
 *   (SC:H/SI:H/SA:H).
 *
 *   Scanner databases also accumulate *fabricated* vectors: a "Missing security
 *   header" row carrying AV:N/AC:L/.../VC:H/VI:H/VA:H because a sibling module
 *   wrote it. Trusting a persisted vector unconditionally therefore reproduces
 *   the same contradiction one layer deeper. `evaluateFindingCvss()` is the only
 *   sanctioned entry point: it classifies the finding semantically, validates any
 *   stored vector against that class, and re-derives when they disagree.
 */

export const CVSS4_SEVERITY_BANDS = {
  NONE: { min: 0.0, max: 0.0, label: 'info', name: 'None' },
  LOW: { min: 0.1, max: 3.9, label: 'low', name: 'Low' },
  MEDIUM: { min: 4.0, max: 6.9, label: 'medium', name: 'Medium' },
  HIGH: { min: 7.0, max: 8.9, label: 'high', name: 'High' },
  CRITICAL: { min: 9.0, max: 10.0, label: 'critical', name: 'Critical' },
}

/**
 * Reference vectors. Every score in this file is measured with
 * `calculateBaseScoreV4` — never typed by hand. `assertTemplateScores()`
 * enforces that at load time.
 */
export const CVSS4_TEMPLATES = {
  // Full compromise of the vulnerable system AND onward impact — the only shape
  // that legitimately reaches 10.0.
  rce: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', // 10.0 Critical
  // Code execution behind a login: same impact, PR:L drops it to 8.7.
  rce_auth: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // 8.7 High
  sqli: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // 9.3 Critical
  sqli_auth: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // 8.7 High
  // Access-control bypass reveals data without granting a write primitive.
  auth_bypass: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.7 High
  // Broken object-level authorization (read), authenticated attacker.
  idor: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 7.1 High
  // BOLA permitting modification of another tenant's object.
  idor_write: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N', // 8.6 High
  ssrf: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N', // 8.7 High
  priv_esc: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N', // 8.6 High
  xss: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.3 Medium
  xss_stored: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.1 Medium
  csrf: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.1 Medium
  // CSRF against a state-changing action the victim is authorised to perform.
  csrf_write: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N', // 6.9 Medium
  // Log/config exposure with a plausible path to a neighbouring system. This is
  // the honest ceiling for "a log file is downloadable" — deliberately not
  // critical, which is what the old fixed 9.3 template got wrong.
  log_exposure: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N', // 6.9 Medium
  info_leak: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 6.9 Medium
  // A reachable surface that leaks a little and may be a stepping stone, but
  // whose exploitability is unproven: AC:H keeps it out of High/Critical.
  low_grade_exposure: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 6.3 Medium
  // Repository/config artefact readable over HTTP (`.git`, `.env`, backups).
  config_exposure: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N', // 6.3 Medium
  // configuration file that actually carries live credentials/keys.
  config_secrets: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N', // 9.3 Critical
  dev_overlay: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 6.9 Medium
  // Debug/inspection consoles that hand over internal state or a documented path
  // to execution (Ignition, Telescope, exposed DB admin consoles).
  dev_overlay_strong: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.2 High
  // Upload writing a server-executable file, but it needs an account.
  file_upload: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N', // 8.6 High
  rate_limit: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', // 6.3 Medium
  brute_force: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', // 6.3 Medium
  // Missing hardening header: no direct C/I loss, but the vector still scores
  // > 0 so the item keeps a real Low score instead of collapsing to Info.
  missing_header: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 2.1 Low
  disclosed_secret: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.7 High
  open_redirect: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.1 Medium
  path_traversal: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.7 High
  path_traversal_write: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N', // 8.6 High
  xxe: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N', // 7.1 High
  deserialization: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // 7.7 High
  cors_wildcard: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 2.1 Low
  // Credentialed cross-origin read: attacker page reads the victim's
  // authenticated responses with no user interaction beyond loading the page and
  // no session artifact of its own. Confidentiality-only, full scope of the
  // victim's own data, so VC:H and no integrity/availability impact.
  cors_credentialed: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
  weak_tls: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 6.3 Medium
  subdomain_takeover: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.1 Medium
  // Shared cache serving one user's authenticated response to another.
  cache_deception: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 5.9 Medium
  // Unpatched/end-of-life component: future impact unknown, availability of CVE
  // coverage is guaranteed but the exploit does not exist yet.
  end_of_life: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N', // 8.3 High
  // A version with applicable NVD advisories: the default assumes a remote,
  // unauthenticated hit with high confidentiality loss (the modal advisory
  // shape), but `classScoreHint` raises it when a critical CVE applies.
  vuln_component: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.2 High
  // A shell file found on disk with no execution proof is a lead, not an RCE.
  webshell_heuristic: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N', // 8.3 High
  // Predictable/duplicated session identifiers: confidentiality loss (account
  // takeover) but no proven server-side write, so High — not Critical.
  session_prediction: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.7 High
  // Client-side amount/price tampering accepted by the server.
  payment_tamper: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N', // 6.9 Medium
  recon_info: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', // 0.0 None
}

/**
 * Severity → the *floor* vector whose score lands inside that severity band.
 *
 * This is a floor, not an equivalence. `critical` maps to SQLi (9.3) because a
 * finding labelled critical must at minimum reach the 9.0 band; escalation to
 * the 10.0 RCE template happens only in a class that proves onward impact.
 * Reading this map the other way round is what produced "CRITICAL 9.3 ranked
 * below HIGH 10.0".
 */
export const SEVERITY_TO_VECTOR = {
  critical: CVSS4_TEMPLATES.sqli,
  high: CVSS4_TEMPLATES.rce_auth,
  medium: CVSS4_TEMPLATES.xss,
  low: CVSS4_TEMPLATES.missing_header,
  info: CVSS4_TEMPLATES.recon_info,
}

/** Scores render to one decimal; anything above this is a real disagreement. */
export const CVSS_MISMATCH_TOLERANCE = 0.1

/**
 * Highest score the declared severity band can justify on its own. Used only when
 * no semantic class matched, where nothing else corroborates a stored vector.
 */
function declaredBandCeiling(severity) {
  const key = String(severity || 'info').toLowerCase()
  return key === 'critical' ? 10.0 : (CEILING_SCORE[key] ?? 0.0)
}

function scoreForVector(vector) {
  const evaluated = calculateCvss4(vector)
  return evaluated && !evaluated.error ? evaluated.score : 0.0
}

/**
 * Highest score a semantic class is allowed to produce. A class whose reference
 * vector already exceeds its ceiling is a programming error — `assertClassCeilings()`
 * refuses to load the module in that state.
 */
const CEILING_SCORE = {
  info: 0.0,
  low: 3.9,
  medium: 6.9,
  high: 8.9,
  critical: 10.0,
}

/**
 * Convert numerical CVSS v4.0 score to FIRST standard qualitative severity string.
 */
export function severityFromCvss4Score(score) {
  const s = Number(score) || 0
  if (s >= 9.0) return 'critical'
  if (s >= 7.0) return 'high'
  if (s >= 4.0) return 'medium'
  if (s > 0.0) return 'low'
  return 'info'
}

/**
 * Parse a CVSS v4.0 vector string into key-value map.
 */
export function parseCvss4Vector(vectorStr) {
  if (!vectorStr || typeof vectorStr !== 'string') return {}
  const clean = vectorStr.trim()
  const parts = clean.split('/')
  const metrics = {}
  for (const part of parts) {
    if (part.includes(':')) {
      const [k, v] = part.split(':')
      if (k && v && k !== 'CVSS') {
        metrics[k.toUpperCase()] = v.toUpperCase()
      }
    }
  }
  return metrics
}

/**
 * Format a key-value metric map into standard CVSS v4.0 vector string.
 */
export function buildCvss4Vector(metrics = {}) {
  const defaults = {
    AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
    VC: 'H', VI: 'H', VA: 'H',
    SC: 'N', SI: 'N', SA: 'N'
  }
  const m = { ...defaults, ...metrics }
  const order = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']
  const parts = ['CVSS:4.0']
  for (const k of order) {
    if (m[k]) parts.push(`${k}:${m[k]}`)
  }
  if (m.E && m.E !== 'X') parts.push(`E:${m.E}`)
  if (m.CR && m.CR !== 'X') parts.push(`CR:${m.CR}`)
  if (m.IR && m.IR !== 'X') parts.push(`IR:${m.IR}`)
  if (m.AR && m.AR !== 'X') parts.push(`AR:${m.AR}`)
  return parts.join('/')
}

/**
 * Calculate CVSS v4.0 score and qualitative label using FIRST algorithm.
 */
export function calculateCvss4(vectorStr) {
  if (!vectorStr) {
    return { score: 0.0, severity: 'info', rating: 'None', vector: CVSS4_TEMPLATES.recon_info }
  }
  try {
    const rawScore = calculateBaseScoreV4(vectorStr)
    const score = Math.round(rawScore * 10) / 10
    const rating = humanizeScore(score)
    const severity = severityFromCvss4Score(score)
    return { score, severity, rating, vector: vectorStr }
  } catch (err) {
    return { error: err.message, score: 0.0, severity: 'info', rating: 'None', vector: vectorStr }
  }
}

/** A finding states execution as fact, not as a hypothesis. */
const CONFIRMED_RE = /\bconfirmed\b|\bverified\b|\bvalidated\b|\bexploited\b|\breproduced\b|\bsuccessfully\b/i

/** Title hedges the claim: whatever the label says, the score cannot exceed a lead. */
const HEDGE_RE = /\bpossible\b|\bpotential\b|\bsuspected\b|\bmay\b|\bmight\b|\bperhaps\b|\bcandidate\b|heuristic|\?\s*$/i

/**
 * Semantic classes, ordered from most specific/impactful to most generic.
 *
 * `title` matches the finding's own title only — OWASP/severity labels in this
 * codebase are unreliable (a missing CSP header is tagged A05:Injection), so they
 * never take part in primary classification. `alt` is a CWE-only fallback used
 * when the title says nothing useful.
 *
 * `ceiling` is the highest band the class may reach, regardless of what the
 * database claims. `allowsOnward` permits SC/SI/SA:H — the only route to 10.0.
 */
const SEMANTIC_CLASSES = [
  // ── Code execution ──────────────────────────────────────────────────────────
  {
    id: 'rce_confirmed', template: 'rce', ceiling: 'critical', allowsOnward: true,
    title: /\b(rce|remote code execution|command execution|code execution|os command injection|arbitrary code|shell)\b/i,
    requiresConfirmed: true, unconfirmedFallback: 'code_injection_heuristic',
  },
  {
    id: 'webshell_confirmed', template: 'webshell_confirmed', ceiling: 'critical',
    title: /webshell|web shell|shell (?:file|uploaded)/i,
    requiresConfirmed: true, unconfirmedFallback: 'code_injection_heuristic',
  },
  {
    id: 'code_injection_heuristic', template: 'webshell_heuristic', ceiling: 'high',
    title: /webshell|web shell|shell upload|backdoor (?:file|script)|command injection|code injection|deseriali[sz]ation|\brce\b|remote code execution|arbitrary code/i,
    alt: /\bcwe-(?:78|94|502)\b/i,
  },
  // ── Injection ───────────────────────────────────────────────────────────────
  {
    id: 'nosql_injection', template: 'sqli_auth', ceiling: 'critical',
    title: /nosql injection|ldap injection|\bldapi\b|xpath injection/i,
    alt: /\bcwe-(?:943|90)\b/i,
  },
  {
    id: 'sqli', template: 'sqli', ceiling: 'critical',
    title: /sql injection|\bsqli\b|blind sql|time-based sql|error-based sql/i,
    alt: /\bcwe-89\b/i,
  },
  {
    id: 'xss_stored', template: 'xss_stored', ceiling: 'medium',
    title: /stored xss|persistent xss/i,
  },
  {
    id: 'xss', template: 'xss', ceiling: 'medium',
    title: /cross[- ]site scripting|\bxss\b/i,
    alt: /\bcwe-79\b/i,
  },
  {
    id: 'csrf_write', template: 'csrf_write', ceiling: 'medium',
    title: /\bcsrf\b[\s\S]{0,80}(write|change|transfer|update|delete|payment|order|profile)|cross[- ]site request forgery[\s\S]{0,80}(write|change|transfer|update|delete)/i,
  },
  {
    id: 'csrf', template: 'csrf', ceiling: 'medium',
    title: /\bcsrf\b|cross[- ]site request forgery/i,
    alt: /\bcwe-352\b/i,
  },
  {
    id: 'xxe', template: 'xxe', ceiling: 'high',
    title: /\bxxe\b|xml external entit/i,
    alt: /\bcwe-611\b/i,
  },
  {
    id: 'ssrf', template: 'ssrf', ceiling: 'high',
    title: /\bssrf\b|server[- ]side request forgery/i,
    alt: /\bcwe-918\b/i,
  },
  {
    id: 'deserialization', template: 'deserialization', ceiling: 'high',
    title: /insecure deseriali|unsafe deseriali|deserialization of untrusted/i,
    alt: /\bcwe-502\b/i,
  },
  // ── File / path ─────────────────────────────────────────────────────────────
  {
    id: 'path_traversal_write', template: 'path_traversal_write', ceiling: 'high',
    title: /(?:path|directory) traversal|local file inclusion|\blfi\b[\s\S]{0,100}(?:upload|write|delete|modify)/i,
  },
  {
    id: 'path_traversal', template: 'path_traversal', ceiling: 'high',
    title: /(?:path|directory) traversal|local file inclusion|\blfi\b/i,
    alt: /\bcwe-(?:22|23|98)\b/i,
  },
  {
    id: 'file_upload', template: 'file_upload', ceiling: 'high',
    title: /file upload|unrestricted upload|upload[\s\S]{0,40}(?:bypass|extension|content-type)|arbitrary file (?:write|upload)/i,
    alt: /\bcwe-434\b/i,
  },
  // ── Access control ──────────────────────────────────────────────────────────
  {
    id: 'idor_write', template: 'idor_write', ceiling: 'high',
    title: /(?:\bidor\b|\bola\b|insecure direct object|object[- ]level authori[sz]ation)[\s\S]{0,120}(?:write|update|delete|modify|edit|assign|approve|transfer)/i,
    alt: /\bcwe-(?:639|915|284)\b/i,
  },
  {
    id: 'idor', template: 'idor', ceiling: 'high',
    title: /\bidor\b|\bola\b|insecure direct object|object[- ]level authori[sz]ation|broken object property/i,
    alt: /\bcwe-(?:639|915)\b/i,
  },
  {
    id: 'priv_esc', template: 'priv_esc', ceiling: 'high',
    title: /privilege escalation|privesc|vertical escalation|missing function[- ]level authori|\bbfla\b|missing authori[sz]ation|forced browsing/i,
    alt: /\bcwe-(?:269|266|862|285)\b/i,
  },
  {
    // A credentialed cross-origin read is a session-hijack primitive only when a
    // session actually rides on a cookie. The bare phrase "session hijack" in a
    // title is a *claim*, so this class is gated on confirmed evidence and
    // degrades to `cors_policy` when the claim is unsupported.
    id: 'cors_credentialed', template: 'cors_credentialed', ceiling: 'high',
    title: /(?:cors|cross[- ]origin|access-control-allow-origin)[\s\S]{0,80}?(?:with credentials|credentialed|authenticated|cookie|session)/i,
    requiresConfirmed: true,
    unconfirmedFallback: 'cors_policy',
  },
  {
    // Deliberately ahead of every claim-based class. A title such as
    // "CORS origin reflection WITH credentials - session hijack" names a *cause*
    // (a CORS header) and a *consequence* the scanner never demonstrated.
    // Classification must follow the cause, never the loudest word in the title,
    // so this sits before every claim-based class and cannot be shadowed by one.
    id: 'cors_policy', template: 'cors_wildcard', ceiling: 'low',
    title: /\bcors\b|cross[- ]origin resource sharing|access-control-allow-origin/i,
  },
  {
    id: 'auth_bypass', template: 'auth_bypass', ceiling: 'high',
    // `session (fixation|hijack)` used to match on its own, which let any title
    // containing the phrase claim a HIGH authentication bypass without naming a
    // session artifact. It now requires an actual session identifier in the text.
    title: /auth[a-z]*\s*bypass|authentication bypass|broken[\s\S]{0,20}authentication|unauthenticated (?:access|endpoint)|default credential|weak (?:password|credential)|login bypass|session (?:fixation|hijack)[\s\S]{0,80}?(?:cookie|session id|jsessionid|phpsessid|\bsid\b|set-cookie)|\bjwt\b[\s\S]{0,30}(?:broken|bypass|none|alg|algorithm|forged|weak|missing|unsigned)/i,
    alt: /\bcwe-(?:287|288|306|384)\b/i,
  },
  {
    id: 'session_prediction', template: 'session_prediction', ceiling: 'high',
    title: /session[\s\S]{0,40}(?:token|id|cookie)[\s\S]{0,60}(?:predictable|not unique|non-unique|sequential|guessable|reuse|collision|entropy)/i,
    alt: /\bcwe-(?:330|331|340)\b/i,
  },
  // ── Credentials & configuration ─────────────────────────────────────────────
  {
    // A credentials file reachable over HTTP is the single highest-impact config
    // exposure there is: the file *is* the credentials, so the title alone proves
    // live secrets were served. It must match here, ahead of the generic
    // `.env`/`config file` alternative, or it falls through to `config_exposure`
    // (medium) and understates a critical.
    id: 'config_file_credentials', template: 'config_secrets', ceiling: 'critical',
    title: /(?:credential|secret|password|key|token)s?[- _]?(?:file|dump|store)|\b(?:env|dotenv)\b[\s\S]{0,40}(?:credential|secret|password|key|exposed|file)|\bcredentials file\b|\bsecret store\b/i,
  },
  {
    id: 'config_secrets', template: 'config_secrets', ceiling: 'critical',
    title: /(?:web\.config|wp-config|\.env|config(?:uration)? (?:file|backup)|appsettings|settings\.php|database\.yml)[\s\S]{0,80}(?:secret|password|credential|api[ _-]?key|connection string)|(?:secret|password|credential|api[ _-]?key)[\s\S]{0,60}(?:in|inside) (?:config|web\.config|\.env)/i,
  },
  {
    id: 'config_exposure', template: 'config_exposure', ceiling: 'medium',
    title: /\.git\b|\.svn\b|\.hg\b|\.env\b|(?:en|dot)v(?:ironment)? file|\bweb\.config|wp-config|config(?:uration)? (?:file|backup)|backup file|source map|\.swp\b|\.bak\b|\.old\b|git configuration|dockerfile|composer\.(?:json|lock)|(?:editor|temp|temporary) file exposed|\/(?:#[\w.]+#|[\w.-]+(?:~|\.orig|\.copy|\.rej|\.save|\.swo|\.swp|\.part))|\B\.[\w-]*(?:history|viminfo|gitconfig|bashrc|npmrc|netrc|inputrc|pgpass)\b/i,
    alt: /\bcwe-(?:538|552|16)\b/i,
  },
  {
    id: 'disclosed_secret', template: 'disclosed_secret', ceiling: 'high',
    title: /hardcoded|exposed (?:api )?(?:key|secret|token|credential)|leaked (?:key|secret|token|credential)|private key|aws access key|jwt (?:secret|key)|bearer token (?:leak|expos)/i,
    alt: /\bcwe-(?:798|321|312|259)\b/i,
  },
  // ── Exposed surfaces ────────────────────────────────────────────────────────
  {
    id: 'dev_overlay_strong', template: 'dev_overlay_strong', ceiling: 'high',
    title: /telescope|ignition (?:debug|endpoint)|debug (?:console|dashboard|endpoint) exposed|(?:database|db) admin(?:istration)? (?:interface|console|panel)?[\s\S]{0,40}expos|phpmyadmin|adminer|mongo[- ]express|redis commander|kibana|elasticsearch head/i,
    requiresConfirmed: true, unconfirmedFallback: 'admin_surface',
  },
  {
    // A runtime-mode flag is an observation about configuration, not a defect.
    // "NODE_ENV development mode" was scoring 6.9 Medium through `dev_overlay`,
    // which is the same number as a reachable debug console — a claim nobody
    // made. It caps at Low until something is shown to be reachable through it.
    id: 'dev_mode_indicator', template: 'missing_header', ceiling: 'low',
    title: /node_env|\bdevelopment mode\b|\bdebug mode\b\s*(?:enabled|on|active)?|dev(?:elopment)? mode (?:enabled|on|active)|running in (?:dev|development|debug)/i,
  },
  {
    id: 'dev_overlay', template: 'dev_overlay', ceiling: 'medium',
    title: /actuator|heapdump|phpinfo|dev(?:eloper)? (?:overlay|toolbar|debug page)|graphql introspection|swagger|openapi (?:spec|ui)|debug (?:page|mode) exposed|stack trace/i,
  },
  {
    id: 'log_exposure', template: 'log_exposure', ceiling: 'medium',
    title: /log file|\S+\.log\b|access\.log|error log|debug log|elmah|laravel log|log disclosure|logs? (?:folder|directory) (?:exposed|listing)/i,
    alt: /\bcwe-(?:532|209|117)\b/i,
  },
  {
    id: 'admin_surface', template: 'low_grade_exposure', ceiling: 'medium',
    title: /admin(?:istration)? (?:panel|console|interface|portal|login|dashboard)[\s\S]{0,40}(?:discovered|exposed|accessible|reachable)|management (?:console|interface)[\s\S]{0,40}(?:discovered|exposed)|(?:discovered|exposed)[\s\S]{0,30}admin/i,
  },
  // ── Component hygiene ───────────────────────────────────────────────────────
  {
    id: 'end_of_life', template: 'end_of_life', ceiling: 'high',
    title: /end[- ]of[- ]life|\beol\b|no longer (?:supported|maintained|patched)|unsupported (?:version|release)|obsolete version|outdated (?:version|component|software)/i,
    alt: /\bcwe-1104\b/i,
  },
  // Version fingerprint whose NVD correlation returned APPLICABLE advisories.
  // Distinct from end_of_life: here we can name exact CVEs with published
  // scores, so the impact is known rather than prospective. Ranked on the
  // worst applicable advisory's score (see classScoreHint).
  {
    id: 'vulnerable_component', template: 'vuln_component', ceiling: 'critical',
    title: /applicable (?:cve|advisor)|matched (?:cve|advis)\w*|known cves? (?:affect|apply)|vulnerable (?:version|component|release)|nvd (?:advisories|match)/i,
  },
  // ── Headers & transport ─────────────────────────────────────────────────────
  {
    id: 'session_flags', template: 'missing_header', ceiling: 'low',
    title: /cookie[\s\S]{0,60}(?:httponly|secure flag|samesite|flag|attribute)|(?:httponly|samesite|secure attribute)[\s\S]{0,40}cookie/i,
    alt: /\bcwe-(?:1004|614|1275)\b/i,
  },
  {
    id: 'version_disclosure', template: 'missing_header', ceiling: 'low',
    title: /server (?:header|banner|version)|x-powered-by|version (?:disclosed|disclosure|detect)|banner grab|technology (?:detection|fingerprint)|wappalyzer/i,
    alt: /\bcwe-(?:200|497)\b/i,
  },
  {
    id: 'header_hardening', template: 'missing_header', ceiling: 'low',
    title: /content[- ]security[- ]policy|strict[- ]transport[- ]security|x[- ]frame[- ]options|x[- ]content[- ]type[- ]options|permissions[- ]policy|referrer[- ]policy|cross[- ]origin[- ](?:opener|embedder|resource)[- ]policy|\bcsp\b|\bhsts\b|security header|clickjacking|frame protection|server_tokens/i,
    alt: /\bcwe-(?:693|1021|319)\b/i,
  },
  {
    id: 'http_methods', template: 'rate_limit', ceiling: 'medium',
    title: /http (?:method|verb)|(?:trace|options|put|delete) method|dangerous http|xst\b|verb tampering/i,
    alt: /\bcwe-(?:650|749)\b/i,
  },
  {
    // A hostname resolved to a CDN or WAF edge answers with the edge's own
    // configuration, not the origin's. Cloudflare's default cipher list and TLS
    // floor then surface as "Weak Cipher Suites Detection" and "Deprecated TLS
    // Detection" on every proxied host, which read as origin defects the operator
    // cannot act on: the certificate and the cipher list belong to Cloudflare,
    // and the origin is not even reachable directly. This class must stay ABOVE
    // `transport_hardening` — Pass 1 is first-match-wins, so a plain
    // unqualified TLS finding still lands in `transport_hardening`, while one
    // that names the edge is downgraded to an infrastructure fact.
    id: 'cdn_edge_transport', template: 'recon_info', ceiling: 'info',
    title: /(?:cloudflare|akamai|cloudfront|fastly|incapsula|sucuri|stackpath|bunnycdn|imperva|azure front door|google cloud cdn)[\s\S]{0,48}?(?:tls|ssl|cipher|cert(?:ificate)?|hsts|http\/[23]|transport|edge|cdn|proxy|banner)|(?:tls|ssl|cipher|cert(?:ificate)?|hsts|http\/[23]|transport)[\s\S]{0,48}?(?:cloudflare|akamai|cloudfront|fastly|incapsula|sucuri|stackpath|bunnycdn|imperva|behind (?:a )?(?:cdn|waf|proxy)|cdn edge|edge (?:server|node)|proxied)/i,
  },
  {
    id: 'transport_hardening', template: 'weak_tls', ceiling: 'medium',
    // Only an *asserted* transport weakness belongs here. The previous regex
    // listed the bare tokens `ssl`, `tls` and `certificate`, so pure
    // reconnaissance ("SSL DNS Names", "TLS Version - Detect", "Detect SSL
    // Certificate Issuer") was scored as a 6.3 Medium transport defect. A
    // finding must now name a weakness AND the transport it weakens.
    title: /no https? to https|missing https|plaintext http|insecure transport|(?:weak|deprecated|insecure|obsolete|expired|export[- ]grade|null|rc4|des|3des|md5)[\s\S]{0,24}?(?:cipher|tls|ssl|https)|(?:tls|ssl|https)[\s\S]{0,24}?(?:1\.[01]\b|v2\b|v3\b|weak|deprecated|insecure|obsolete|expired|disabled|untrusted)|(?:expired|self[- ]signed|untrusted|invalid|revoked|hostname mismatch)[\s\S]{0,24}?cert/i,
    alt: /\bcwe-(?:295|326|327|523)\b/i,
  },
  {
    // Reconnaissance *about* transport that asserts no weakness: certificate
    // issuer/SAN/expiry listings, TLS version or cipher-suite enumeration,
    // CDN/WAF banners. These are useful inventory, never a defect on their own,
    // so they must not borrow the transport ceiling.
    id: 'transport_inventory', template: 'recon_info', ceiling: 'info',
    title: /(?:cert(?:ificate)?)[\s\S]{0,24}?(?:issuer|dns names?|subject|san\b|alt names?|expiry|validity|chain)|(?:tls|ssl)[\s\S]{0,24}?(?:version[\s\S]{0,16}?(?:detect|detected|disclosure|enumerat)|certificate[\s\S]{0,16}?(?:detect|detected|issuer|subject))|cipher suites?[\s\S]{0,24}?(?:detect|enumerat|list|support)|(?:cloudflare|akamai|cloudfront|fastly|incapsula)[\s\S]{0,32}?(?:detected|banner|cf-ray|header)|dns names?\b\s*:?/i,
  },
  // ── Abuse & logic ───────────────────────────────────────────────────────────
  {
    id: 'rate_limit', template: 'rate_limit', ceiling: 'medium',
    title: /rate limit|no rate|unlimited attempts|brute[- ]force|credential stuffing|account lockout|missing throttl/i,
    alt: /\bcwe-(?:307|770|799)\b/i,
  },
  {
    id: 'cache_deception', template: 'cache_deception', ceiling: 'medium',
    title: /cache (?:deception|poisoning|key)|web cache|cached (?:page|response) (?:leak|mix)/i,
  },
  {
    id: 'payment_tamper', template: 'payment_tamper', ceiling: 'medium',
    title: /negative (?:amount|price|quantity|value)|(?:amount|price|quantity|total)[\s\S]{0,40}(?:tamper|manipulat|accept)|client[- ]side (?:price|amount)|double[- ]spend|refund abuse|coupon (?:reuse|stack)/i,
    alt: /\bcwe-(?:472|840)\b/i,
  },
  {
    id: 'subdomain_takeover', template: 'subdomain_takeover', ceiling: 'medium',
    title: /subdomain takeover|dangling (?:dns|cname)|unclaimed (?:bucket|app)/i,
  },
  {
    id: 'open_redirect', template: 'open_redirect', ceiling: 'medium',
    title: /open redirect|unvalidated redirect/i,
    alt: /\bcwe-601\b/i,
  },
  // ── Generic disclosure (order matters: after every specific family) ─────────
  {
    id: 'info_page', template: 'low_grade_exposure', ceiling: 'medium',
    // `internal ip`/`hostname` was matched here and scored 6.3 Medium. An RFC1918
    // address appearing in a header or body is an information leak with no
    // demonstrated path to the internal network; it belongs in the recon class.
    title: /information disclosure|info disclosure|sensitive (?:data|information) (?:exposure|disclosure)|directory listing|internal (?:path|url)|error (?:page|message) disclosure|verbose error|source code disclosure/i,
    alt: /\bcwe-(?:200|209|548|538)\b/i,
  },
  {
    id: 'info_leak', template: 'info_leak', ceiling: 'medium',
    title: /metadata file|thumbs\.db|\.ds_store|backup (?:archive|zip)|\.sql (?:dump|file)/i,
  },
  // ── Reconnaissance (lowest) ────────────────────────────────────────────────
  {
    id: 'api_endpoint', template: 'recon_info', ceiling: 'low',
    title: /api endpoint|endpoint discovered|discovered endpoint|api (?:route|path) (?:found|exposed)|form discovered|injection surface/i,
  },
  {
    id: 'recon', template: 'recon_info', ceiling: 'low',
    title: /open port|port scan|subdomains? discovered|robots\.txt|sitemap|fingerprint|waf detection|dns record|certificate transparency|keep-alive|allowed options|infrastructure|internal (?:ip|hostname|address)|\brfc[- ]?1918\b|private (?:ip|address)/i,
  },
]

/**
 * Template aliases: several classes describe the same CVSS shape. Keeping the
 * alias list explicit means `assertTemplateScores` still covers every class.
 */
Object.assign(CVSS4_TEMPLATES, {
  webshell_confirmed: CVSS4_TEMPLATES.sqli, // 9.3 — proven shell on the server
  db_admin_exposed: CVSS4_TEMPLATES.dev_overlay_strong, // 8.2 — console reachable
  idor_unauth: CVSS4_TEMPLATES.auth_bypass, // 8.7 — BOLA with no account needed
  idor_unauth_write: CVSS4_TEMPLATES.sqli, // 9.3 — unauthenticated cross-tenant write
  admin_surface_confirmed: CVSS4_TEMPLATES.dev_overlay_strong, // 8.2
})

function findingTitleText(finding = {}) {
  return String(finding.title || finding.name || '').trim()
}

function findingCweText(finding = {}) {
  return String(finding.cweId || finding.cwe_id || '').trim()
}

function confirmationBlob(finding = {}) {
  const poc = typeof finding.poc === 'string' ? finding.poc : (finding.poc ? JSON.stringify(finding.poc) : '')
  return [
    findingTitleText(finding),
    finding.status,
    finding.agentVerdict,
    finding.agent_verdict,
    poc.slice(0, 600),
  ].filter(Boolean).join(' ')
}

/**
 * The scanner's own confidence that a finding is real, independent of any title.
 *
 * `classifyFinding` used to derive "confirmed" from the title, status and agent
 * verdict alone. That made a class like `cors_credentialed` unreachable: a card
 * is auto-`verified` at aggregate time, but the same finding object at scoring
 * time carries no marker, so the very card whose title says "WITH credentials"
 * was downgraded for lacking a confirmation it could never have carried. When
 * the report has already classified the row, that verdict is the confirmation.
 *
 * Bounded deliberately: only a row the contract already marked `confirmed` (or
 * that carries a captured artifact) unlocks a `requiresConfirmed` class. A bare
 * `confidence: 90` or a stored `verified` string still does not.
 *
 * @param {object} finding
 * @returns {boolean}
 */
function isContractConfirmed(finding = {}) {
  if (String(finding.verifyStatus || finding.verify_status || '').toLowerCase() === 'confirmed') return true
  if (finding.artifact || finding.capture) return true
  // Stamped by the pipeline once `findCaptures()` has seen a real response body,
  // header set or status line. This is the only confirmation signal available at
  // scoring time; `verifyStatus` is attached later, by the report contract.
  if (finding.captureConfirmed === true) return true
  const verdict = finding.agentVerdict ?? finding.agent_verdict
  if (verdict != null && String(verdict).toLowerCase() === 'confirmed') return true
  return false
}

/**
 * Classify a finding into a semantic CVSS class.
 *
 * Classification is title-first because it is the only field the scanner
 * authored deliberately; OWASP categories, severities and stored vectors in this
 * database are demonstrably shuffled between findings.
 *
 * @returns {object|null} the matched class, or null when nothing fits.
 */
export function classifyFinding(finding = {}) {
  const explicit = finding.cvssTemplate || finding.cvss_template
  if (explicit && CVSS4_TEMPLATES[explicit]) {
    const declared = SEMANTIC_CLASSES.find((c) => c.template === explicit)
    if (declared) return declared
  }

  const title = findingTitleText(finding)
  const cwe = findingCweText(finding).toLowerCase()
  const confirmed = CONFIRMED_RE.test(confirmationBlob(finding)) || isContractConfirmed(finding)
  const hedged = HEDGE_RE.test(title)

  // Pass 1 — the title names the vulnerability.
  for (const cls of SEMANTIC_CLASSES) {
    if (!cls.title.test(title)) continue
    if (cls.requiresConfirmed && (!confirmed || hedged)) continue
    return cls
  }

  // Pass 2 — CWE fallback for titles that say nothing useful.
  if (cwe) {
    for (const cls of SEMANTIC_CLASSES) {
      if (!cls.alt) continue
      if (!cls.alt.test(cwe)) continue
      if (cls.requiresConfirmed && (!confirmed || hedged)) continue
      return cls
    }
  }

  // Pass 3 — a class that matches the title but was refused only because the
  // finding never corroborated itself. Returning null here would let the row
  // fall back to its declared score, which is exactly the fabricated rating we
  // are removing; an unconfirmed claim must degrade to the exposure class.
  for (const cls of SEMANTIC_CLASSES) {
    if (!cls.requiresConfirmed) continue
    if (!cls.title.test(title)) continue
    return SEMANTIC_CLASSES.find((c) => c.id === (cls.unconfirmedFallback || 'config_exposure')) || null
  }

  return null
}

/**
 * Derive a well-aligned CVSS v4.0 vector for a finding from its own content.
 *
 * Precedence: explicit template on the finding → semantic class → severity floor.
 * The severity floor is the last resort, because a label the scanner guessed must
 * never outrank evidence about what the finding actually is.
 */
export function defaultVectorForFinding(finding = {}) {
  const cls = classifyFinding(finding)
  if (cls) return CVSS4_TEMPLATES[cls.template]

  const s = String(finding.severity || 'info').toLowerCase()
  return SEVERITY_TO_VECTOR[s] || CVSS4_TEMPLATES.recon_info
}

/** Metrics that define a class's shape. A stored vector must agree on all of them. */
const SHAPE_METRICS = ['PR', 'UI', 'VI', 'VA']
/**
 * Impact metrics that must also agree. Comparing them catches the reverse of the
 * usual lie: a "Server header version disclosure" stored as VC:N (2.1) while its
 * class leaks a version — and, worse, a `Database admin interface exposed` row
 * stored with the XSS vector (5.3) while its class grants read of a live console.
 */
const IMPACT_METRICS = ['VC']
const ONWARD_METRICS = ['SC', 'SI', 'SA']

/**
 * Decide whether a persisted vector is trustworthy for this finding.
 *
 * Three rejections matter, and each one reproduced a real defect in shipped
 * reports:
 *   1. score above the class ceiling  → "Missing Security Header: 10.0".
 *   2. onward impact (SC/SI/SA:H) on a class that cannot reach other systems
 *      → the fabricated maximal vector that made every card CRITICAL 10.0.
 *   3. PR/UI/VI/VA/VC contradicting the class shape → a DB-admin row carrying
 *      the XSS vector (5.3), an end-of-life row carrying a full-write vector.
 *
 * @returns {{ok:boolean, score?:number, reason?:string}}
 */
export function validateStoredVector(vector, cls) {
  const evaluated = calculateCvss4(vector)
  if (!evaluated || evaluated.error) return { ok: false, reason: 'vector does not evaluate' }
  if (!cls) return { ok: true, score: evaluated.score }

  const ceilingSource = String(cls.ceiling || 'critical').toLowerCase()
  const ceiling = CEILING_SCORE[ceilingSource] ?? CEILING_SCORE.critical
  if (evaluated.score > ceiling + 1e-9) {
    return {
      ok: false,
      reason: `declared ${evaluated.score.toFixed(1)} exceeds the ${ceilingSource} ceiling (${ceiling.toFixed(1)}) for class "${cls.id}"`,
    }
  }

  const stored = parseCvss4Vector(vector)
  if (!cls.allowsOnward && ONWARD_METRICS.some((m) => stored[m] === 'H')) {
    return {
      ok: false,
      reason: `declares onward impact (${ONWARD_METRICS.map((m) => `${m}:${stored[m]}`).join('/')}) but class "${cls.id}" cannot reach other systems`,
    }
  }

  const reference = parseCvss4Vector(CVSS4_TEMPLATES[cls.template])
  for (const metric of [...SHAPE_METRICS, ...IMPACT_METRICS]) {
    const want = reference[metric] || 'N'
    const got = stored[metric] || 'N'
    if (want !== got) {
      return {
        ok: false,
        reason: `declares ${metric}:${got} but class "${cls.id}" is ${metric}:${want}`,
      }
    }
  }

  return { ok: true, score: evaluated.score }
}

/**
 * Metrics whose values must match between a stored vector and a class reference.
 */
const CLASS_BORROWABLE = new Set(['vulnerable_component'])

/**
 * When a component finding carries real NVD advisories, the component's own
 * template is only a default. The strongest applicable advisory vector is better
 * evidence than a guess — but only if it is CVSS v4.0 (v3.1 metrics have no
 * homologues for AT/SC/SI/SA, so borrowing them would fabricate metrics) and it
 * survives the class ceiling and the onward-impact rule.
 *
 * @returns {{vector:string, source:string, cveId:string, score:number}|null}
 */
function borrowAdvisoryVector(finding, cls) {
  if (!cls || !CLASS_BORROWABLE.has(cls.id)) return null
  const known = finding.knownCves || finding.evidence?.knownCves
  if (!Array.isArray(known) || !known.length) return null
  let best = null
  for (const cve of known) {
    const vector = cve && typeof cve.vector === 'string' ? cve.vector : null
    if (!vector || !/^CVSS:4\.0\//.test(vector)) continue
    const verdict = validateStoredVector(vector, cls)
    if (!verdict.ok) continue
    if (!best || verdict.score > best.score) {
      best = { vector, score: verdict.score, cveId: cve.id || null, source: 'advisory' }
    }
  }
  return best
}

/**
 * THE single authority for a finding's CVSS score and severity.
 *
 *  1. Classify the finding semantically.
 *  2. Accept the persisted vector only if it survives `validateStoredVector()`.
 *  3. Otherwise use the class reference vector — a real CVSS computation for a
 *     vector that describes the finding, not a made-up number.
 *  4. Severity is always re-derived from the resulting score; an incoming
 *     severity label is advisory. This is what makes "CRITICAL 9.3" and
 *     "HIGH 10.0" impossible to emit in the same report.
 *
 * @param {object} finding
 * @returns {{vector:string, score:number, severity:string, rating:string,
 *            declaredScore:number|null, declaredSeverity:string|null,
 *            reconciled:boolean, source:'declared'|'derived',
 *            vectorSource:'declared'|'class'|'severity-floor',
 *            findingClass:string|null, rejectedVectorReason:string|null}}
 */
export function evaluateFindingCvss(finding = {}) {
  const rawDeclared = finding.cvss
  const declaredScore = rawDeclared != null && rawDeclared !== '' && !isNaN(Number(rawDeclared))
    ? Math.round(Number(rawDeclared) * 10) / 10
    : null
  const declaredSeverity = finding.severity ? String(finding.severity).toLowerCase() : null

  const declaredVector = typeof finding.cvssVector === 'string' ? finding.cvssVector
    : typeof finding.cvss_vector === 'string' ? finding.cvss_vector
      : null

  const cls = classifyFinding(finding)

  let vector = null
  let vectorSource = 'class'
  let rejectedVectorReason = null
  let evaluated = null
  let advisoryCve = null

  if (declaredVector) {
    const verdict = validateStoredVector(declaredVector, cls)
    if (verdict.ok) {
      // With no matched class nothing corroborates the declared vector, so it is
      // never allowed to exceed what the declared severity band can justify.
      const uncorroborated = !cls && scoreForVector(declaredVector) > declaredBandCeiling(declaredSeverity) + 1e-9
      if (uncorroborated) {
        rejectedVectorReason = `declared ${scoreForVector(declaredVector).toFixed(1)} is uncorroborated: no semantic class matched this finding and "${declaredSeverity}" caps at ${declaredBandCeiling(declaredSeverity).toFixed(1)}`
      } else {
        vector = declaredVector
        vectorSource = 'declared'
        evaluated = calculateCvss4(vector)
      }
    } else {
      rejectedVectorReason = verdict.reason
    }
  }

  if (!evaluated || evaluated.error) {
    // A component with a real, in-range critical advisory is not a guess: score
    // it from the advisory instead of the generic component template.
    const borrowed = borrowAdvisoryVector(finding, cls)
    if (borrowed) {
      vector = borrowed.vector
      vectorSource = 'advisory'
      evaluated = calculateCvss4(vector)
      advisoryCve = borrowed.cveId
    } else if (cls) {
      vector = CVSS4_TEMPLATES[cls.template]
      vectorSource = 'class'
    } else {
      vector = SEVERITY_TO_VECTOR[declaredSeverity] || CVSS4_TEMPLATES.recon_info
      vectorSource = 'severity-floor'
    }
    evaluated = calculateCvss4(vector)
  }

  // Belt-and-braces: no path may emit a score above the class ceiling.
  if (cls) {
    const ceiling = CEILING_SCORE[String(cls.ceiling || 'critical').toLowerCase()] ?? CEILING_SCORE.critical
    if (evaluated.score > ceiling + 1e-9) {
      vector = CVSS4_TEMPLATES[cls.template]
      vectorSource = 'class'
      evaluated = calculateCvss4(vector)
      rejectedVectorReason = rejectedVectorReason || 'score exceeded the class ceiling'
    }
  }

  // The class template is a CEILING, never a floor. A component class such as
  // `end_of_life` or `webshell_heuristic` carries a worst-case reference vector
  // (8.2–8.7) because that is what the flaw costs WHEN the affected thing is
  // actually in play. Applying that vector to a declaration of `info` is an
  // upward promotion: a nuclei template that deliberately declares `info`
  // ("Nginx End-of-Life - Detect") was being stored and rendered as HIGH 8.3,
  // which then emitted a card whose severity contradicted its own template.
  // The caller (pipeline.ingestFinding) treats declared severity as a floor for
  // *inference*; it must equally refuse to let a class template invent impact
  // the declaring tool never claimed. So when the declared band sits BELOW the
  // class result and no vector good enough to corroborate the higher band was
  // captured, hold the score at the declared band's representative vector.
  const declaredBandVector = SEVERITY_TO_VECTOR[declaredSeverity] || null
  if (cls && declaredBandVector && vectorSource !== 'declared' && vectorSource !== 'advisory') {
    const declaredBandCeilingScore = declaredBandCeiling(declaredSeverity)
    if (evaluated.score > declaredBandCeilingScore + 1e-9) {
      vector = declaredBandVector
      vectorSource = 'severity-floor'
      evaluated = calculateCvss4(vector)
      rejectedVectorReason = rejectedVectorReason
        || `class "${cls.id}" would score ${scoreForVector(CVSS4_TEMPLATES[cls.template]).toFixed(1)} but the declaring tool rated this "${declaredSeverity}"; a class template describes the worst case, not the observed one`
    }
  }

  const score = Math.round((evaluated?.score || 0) * 10) / 10
  const severity = severityFromCvss4Score(score)
  const reconciled = (declaredScore != null && Math.abs(declaredScore - score) > CVSS_MISMATCH_TOLERANCE)
    || (declaredSeverity != null && declaredSeverity !== severity)
    || rejectedVectorReason != null

  return {
    vector,
    score,
    severity,
    rating: evaluated?.rating || 'None',
    declaredScore,
    declaredSeverity,
    declaredVector,
    reconciled,
    source: vectorSource === 'declared' ? 'declared' : 'derived',
    vectorSource,
    findingClass: cls ? cls.id : null,
    rejectedVectorReason,
    advisoryCve,
    // A one-line, human-auditable explanation of every correction. This is what
    // lets a reader check the arithmetic instead of trusting a different number.
    auditNote: buildAuditNote({
      finding, cls, declaredVector, declaredScore, declaredSeverity,
      vector, score, severity, vectorSource, rejectedVectorReason,
    }),
  }
}

/**
 * Plain-language explanation of a severity correction, for the report reader.
 *
 * The raw "declared → derived" arithmetic, including the rejected vector string,
 * goes to the scan log rather than the document. A reader who is shown one score
 * must never be handed a second, conflicting score on the same card. Returns null
 * when nothing was overruled.
 */
function buildAuditNote({ cls, declaredVector, declaredScore, declaredSeverity, score, severity, vectorSource, rejectedVectorReason }) {
  if (vectorSource === 'declared') {
    return null
  }
  const declaredBits = []
  if (declaredSeverity) declaredBits.push(declaredSeverity.toUpperCase())
  if (declaredScore != null) declaredBits.push(declaredScore.toFixed(1))
  if (declaredVector) declaredBits.push(declaredVector)
  const origin = declaredBits.length ? declaredBits.join(' / ') : 'no declared rating'
  if (declaredBits.length) {
    const why = rejectedVectorReason
      ? `declared vector rejected: ${rejectedVectorReason}`
      : cls
        ? `class "${cls.id}" has no trusted declaring vector`
        : 'no semantic class matched'
    console.warn(`[cvss4] reconciled "${origin}" -> ${severity.toUpperCase()} ${score.toFixed(1)} (${why})`)
  }
  const from = declaredSeverity ? declaredSeverity.toUpperCase() : null
  if (rejectedVectorReason) {
    return `Reclassified${from ? ` from ${from}` : ''} to ${severity.toUpperCase()} ${score.toFixed(1)}: the stored rating could not be matched to a reproducible impact on this target.`
  }
  if (cls) {
    return from
      ? `Reclassified from ${from} to ${severity.toUpperCase()} ${score.toFixed(1)}: the finding's category determines its impact, not the stored rating.`
      : `Scored at ${severity.toUpperCase()} ${score.toFixed(1)}: the finding's category determines its impact.`
  }
  return `Scored at ${severity.toUpperCase()} ${score.toFixed(1)}: the stored rating could not be independently confirmed, so the severity reflects the observed evidence only.`
}

/** Convenience wrapper: the numeric score a finding must render with. */
export function findingCvssScore(finding = {}) {
  return evaluateFindingCvss(finding).score
}

/** The severity band the finding's own evidence supports. */
export function reconcileSeverity(finding = {}) {
  return evaluateFindingCvss(finding).severity
}

/**
 * Self-check: every template comment must match the FIRST algorithm. Turns a
 * silent scoring drift into a startup warning instead of a report that quietly
 * claims a file upload is CVSS 10.0.
 */
export function assertTemplateScores({ onMismatch = null } = {}) {
  const expected = {
    rce: 10.0, rce_auth: 8.7, sqli: 9.3, sqli_auth: 8.7, auth_bypass: 8.7,
    idor: 7.1, idor_write: 8.6, ssrf: 8.7, priv_esc: 8.6, xss: 5.3,
    xss_stored: 5.1, csrf: 5.1, csrf_write: 6.9, log_exposure: 6.9, info_leak: 6.9,
    low_grade_exposure: 6.3, config_exposure: 6.3, config_secrets: 9.3,
    dev_overlay: 6.9, dev_overlay_strong: 8.2, file_upload: 8.6, rate_limit: 6.3,
    brute_force: 6.3, missing_header: 2.1, disclosed_secret: 8.7, open_redirect: 5.1,
    path_traversal: 8.7, path_traversal_write: 8.6, xxe: 7.1, deserialization: 7.7,
    cors_wildcard: 2.1, weak_tls: 6.3, subdomain_takeover: 5.1, cache_deception: 5.9,
    cors_credentialed: 8.2,
    end_of_life: 8.3, webshell_heuristic: 8.3, session_prediction: 8.7,
    vuln_component: 8.2,
    payment_tamper: 6.9, webshell_confirmed: 9.3, db_admin_exposed: 8.2,
    idor_unauth: 8.7, idor_unauth_write: 9.3, admin_surface_confirmed: 8.2,
    recon_info: 0.0,
  }
  const mismatches = []
  for (const [name, want] of Object.entries(expected)) {
    const vector = CVSS4_TEMPLATES[name]
    if (!vector) { mismatches.push({ name, want, got: 'missing' }); continue }
    const got = Math.round(calculateCvss4(vector).score * 10) / 10
    if (Math.abs(got - want) > 0.001) mismatches.push({ name, want, got })
  }
  if (mismatches.length && typeof onMismatch === 'function') onMismatch(mismatches)
  return { ok: mismatches.length === 0, mismatches }
}

/**
 * Self-check: no class may reference a template that scores above its ceiling,
 * otherwise the ceiling can never be honoured and the report would print a score
 * its own vector contradicts.
 */
export function assertClassCeilings({ onMismatch = null } = {}) {
  const violations = []
  for (const cls of SEMANTIC_CLASSES) {
    const vector = CVSS4_TEMPLATES[cls.template]
    if (!vector) { violations.push({ id: cls.id, reason: `missing template "${cls.template}"` }); continue }
    const score = Math.round(calculateCvss4(vector).score * 10) / 10
    const ceiling = CEILING_SCORE[String(cls.ceiling || 'critical').toLowerCase()] ?? CEILING_SCORE.critical
    if (score > ceiling + 1e-9) {
      violations.push({ id: cls.id, reason: `template scores ${score} above its ${cls.ceiling} ceiling (${ceiling})` })
    }
  }
  if (violations.length && typeof onMismatch === 'function') onMismatch(violations)
  return { ok: violations.length === 0, violations }
}

// Fail loudly at import time rather than emitting a self-contradicting report.
const templateCheck = assertTemplateScores()
if (!templateCheck.ok) {
  console.warn('[cvss4] template score drift detected:', JSON.stringify(templateCheck.mismatches))
}
const ceilingCheck = assertClassCeilings()
if (!ceilingCheck.ok) {
  console.warn('[cvss4] class ceiling violations:', JSON.stringify(ceilingCheck.violations))
}
