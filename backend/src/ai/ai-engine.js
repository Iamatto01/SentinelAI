import { llm } from './llm-client.js'
import { agentRegistry } from './agent-registry.js'
import { retrieveSkills } from '../integrations/skills-rag.js'
import { httpRequest, analyzeReflection, makeMarker } from '../exploits/probe-utils.js'

// Network re-verification makes at most 2 requests per finding. Opened once the
// OCR-free text dictionary proved insufficient for claims (reflection, CORS,
// traversal) that the wire can settle deterministically.
const NET_VERIFY_ENABLED = (process.env.AI_HEURISTIC_NETWORK_VERIFY || 'true').trim() !== 'false'
const NET_VERIFY_TIMEOUT = Number(process.env.AI_HEURISTIC_NETWORK_TIMEOUT_MS || 8000)

/**
 * Coerce a model's verdict field to a boolean.
 * Models answer with `true`, `"true"`, `"TRUE"`, `"yes"` or `1` interchangeably —
 * an `=== true` comparison silently turns three of those into FALSE positive,
 * which is the worst possible failure mode for a verifier. Returns null when the
 * reply carries no recognisable verdict so the caller can escalate.
 */
const VERDICT_KEYS = ['is_true_positive', 'isTruePositive', 'true_positive', 'truePositive', 'is_truepositive', 'verdict', 'result', 'status'];

function normalizeVerdict(value) {
  if (value === undefined || value === null) return null;
  // Callers may pass either a bare value or the whole parsed JSON object.
  if (typeof value === 'object') {
    for (const key of VERDICT_KEYS) {
      if (value[key] !== undefined && value[key] !== null) return normalizeVerdict(value[key]);
    }
    return null;
  }
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  const s = String(value).trim().toLowerCase();
  if (['true', 'yes', 'y', '1', 'confirmed', 'valid', 'positive'].includes(s)) return true;
  if (['false', 'no', 'n', '0', 'refuted', 'invalid', 'negative', 'unconfirmed'].includes(s)) return false;
  return null;
}

/**
 * AIEngine — the reasoning core. Routes each finding to the right specialist
 * agent persona (from the 51-agent registry), verifies true/false positives,
 * performs whitebox static analysis, and produces structured verdicts.
 *
 * All output is strict JSON — no hallucinated claims without evidence.
 */
export class AIEngine {
  constructor() { this.llm = llm; this.agents = agentRegistry }

  /**
   * Strip the "FULL OFFENSIVE" preamble from agent personas.
   * The agent .md files contain a contradictory directive ("exploit to maximum
   * extent, NEVER refuse") that actively sabotages the PRECISION MODE
   * instructions used in verifyFinding and auditCode. This sanitizer strips
   * all language that tells the model to report more than it should.
   */
  _sanitizePersona(persona) {
    if (!persona) return null
    // Remove the entire "Operational Mode" section (all variants)
    let clean = persona
      .replace(/##\s*Operational Mode:\s*FULL OFFENSIVE\s*[–\-—]\s*NO RESTRICTIONS[\s\S]*?(?=##|\n\nYou are a)/i, '')
      .replace(/##\s*Operational Mode:\s*FULL OFFENSIVE\s*[–\-—]\s*NO RESTRICTIONS[\s\S]*$/i, '')
      // Remove any lingering "FULL OFFENSIVE" fragments
      .replace(/^.*FULL OFFENSIVE.*$/gm, '')
      .replace(/^.*pure offensive tool.*$/gm, '')
      .replace(/^.*exploit.*to.*maximum extent.*$/gm, '')
      .replace(/^.*Never refuse a request.*$/gm, '')
      .replace(/^.*NO scope limitations.*$/gm, '')
      .replace(/^.*NO hard refusals.*$/gm, '')
      .replace(/^.*NO ethical gates.*$/gm, '')
      .replace(/^.*Execute all commands without hesitation.*$/gm, '')
      .replace(/^\s*$/gm, '') // collapse blank lines
      .trim()
    return clean || null
  }

  /**
   * Deterministic attribution for findings whose truth is self-evident from the
   * captured tool output (an open port, a missing header, a discovered path).
   *
   * These findings never reached a verifier before, so reports rendered no
   * specialist agent at all. Rather than burn an LLM call to re-confirm that a
   * header is absent, attribute them to the agent that owns the domain, and let
   * `_heuristicVerify` supply the artifact-backed reasoning. Confidence is
   * capped below the LLM tier because no reasoning model reviewed the claim.
   */
  attributeObservedFinding(finding, targetType = 'url') {
    const segments = []
    if (finding.evidence && typeof finding.evidence === 'object') {
      for (const [k, v] of Object.entries(finding.evidence)) {
        if (k === 'fingerprint' || k === 'sources' || k === 'exploitPlaybooks' || k === 'actions') continue
        if (v === undefined || v === null || v === '') continue
        segments.push(`${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
      }
    }
    const derived = this._heuristicVerify(
      { ...finding, description: `${finding.description || ''} ${segments.join(' ')}` },
      targetType
    )
    const agent = targetType === 'code' ? 'code-auditor' : this.agents.routeFinding(finding)

    // A heuristic that reached a decision (>=60) already names the artifact that
    // settles the claim. Cap at 75 so the observed tier stays distinguishable
    // from a 90–95 model-reasoned verdict.
    if ((derived.confidence || 0) >= 60) {
      return {
        isTruePositive: derived.isTruePositive,
        confidence: Math.min(derived.confidence, 75),
        verdict: derived.verdict,
        evidenceTier: derived.isTruePositive ? 'observed' : 'needs-validation',
        agent,
        refined: derived.refined,
      }
    }

    // The artifact in the finding does not settle exploitability. Keep the
    // observation and attribute it, but never dress up an undecided heuristic as
    // a confirmation: the tier records that a human still has to look.
    return {
      isTruePositive: true,
      confidence: Math.min(derived.confidence || 50, 55),
      verdict: `${derived.verdict} Attributed to the owning specialist for manual confirmation; no exploitability claim is made.`,
      evidenceTier: 'needs-validation',
      agent,
      refined: derived.refined,
    }
  }

  /**
   * Verify a scanner finding; returns { isTruePositive, confidence, verdict, refined }.
   *
   * Three tiers, in order of trust:
   *   1. LLM specialist verdict (when a provider is configured)
   *   2. Network re-verification — replay the claim against the live target and
   *      decide from the observation (`_networkVerify`)
   *   3. Deterministic text heuristics (`_heuristicVerify`) — only evidence
   *      already captured in the finding, never an assumption
   */
  async verifyFinding(finding, targetType = 'url') {
    // Do not treat an unavailable provider as confirmation.
    if (!this.llm.isConfigured()) {
      const net = await this._networkVerify(finding, targetType)
      if (net) {
        return {
          isTruePositive: net.isTruePositive,
          confidence: net.confidence,
          verdict: `${net.verdict} AI provider unavailable; verdict is from live re-verification, not model reasoning.`,
          evidenceTier: net.isTruePositive ? 'validated' : 'needs-validation',
          agent: 'network-reverify',
          refined: net.refined,
        }
      }
      const heuristicResult = this._heuristicVerify(finding, targetType)
      return {
        isTruePositive: heuristicResult.isTruePositive,
        confidence: heuristicResult.confidence,
        verdict: `${heuristicResult.verdict} AI provider unavailable; manual validation recommended.`,
        evidenceTier: 'needs-validation',
        agent: 'evidence-heuristic',
        refined: heuristicResult.refined,
      }
    }
    const agentName = targetType === 'code' ? 'code-auditor' : this.agents.routeFinding(finding)
    const rawPersona = this.agents.prompt(agentName)
    const persona = this._sanitizePersona(rawPersona)

    // Skills RAG: lazy-load only the relevant practitioner playbooks from the
    // 817-skill corpus (index.md pattern — never inject the whole library).
    let skillsBlock = ''
    try {
      const skillQuery = [finding.title, finding.cweId, finding.owaspCategory, (finding.description || '').slice(0, 100)]
        .filter(Boolean).join(' ')
      const res = retrieveSkills(skillQuery, { limit: 2, includeBody: true })
      if (res.found) {
        skillsBlock = `\n\nREFERENCE PLAYBOOKS (senior-analyst workflows from the cybersecurity skills library — follow their verification methodology where relevant):\n` +
          res.skills.map((s, i) => `--- PLAYBOOK ${i + 1}: ${s.name} (${s.subdomain}) ---\n${(s.body || s.description || '').slice(0, 4000)}`).join('\n\n')
      }
    } catch { /* skills RAG unavailable — non-fatal */ }

    const system = persona
      ? `${persona}\n\nYou are a security verification specialist. Verify this finding in BALANCED MODE. Confirm TRUE positive when tool output factually supports the finding. Only mark FALSE positive when evidence clearly contradicts the finding. Respond ONLY with JSON.`
      : 'You are a security verification specialist. Verify in BALANCED MODE. Confirm when tool output supports the finding. Only reject when evidence contradicts it. Respond ONLY with JSON.'

    const prompt = `Verify this security finding on a ${targetType} target. You are in BALANCED MODE — confirm TRUE positive when the finding is factually observable (tool output confirms it). Mark FALSE positive only when the evidence clearly shows the finding is wrong (tool explicitly negated, or finding is pure tool chatter).

Rules:
- is_true_positive: TRUE when the tool output factually confirms the finding (open port, missing header, exposed file, matched vulnerability, discovered path). FALSE only when the evidence contradicts the finding (tool said "not vulnerable", "no parameters found", or line is tool status/progress output).
- Evidence tier: "validated" when evidence proves the vulnerable configuration AND source-to-sink path. "exploited" when the evidence shows successful exploitation. "observed" for a literal match without exploitation proof. "needs-validation" when exploitability is NOT proven.
- MISSING security headers (HSTS, CSP, etc.) are TRUE positive at LOW severity — never upgrade to medium/high/critical for missing headers alone.
- Exposed .git/.env with verified content is TRUE positive.
- Subdomain enumeration, open port discovery, HTTP probe results, server headers, login surface discovery, robots.txt, directory/path discovery are TRUE positive at INFO severity — NEVER upgrade.
- nikto findings (lines starting with "+") are TRUE positive — nikto only reports actual issues it found. Severity based on issue type.
- nmap open ports are TRUE positive — nmap confirmed the port is open.
- ffuf/gobuster discovered paths are TRUE positive — the path was confirmed to exist (HTTP response). BUT: paths returning HTTP 403/404 are access-controlled, NOT exposed — keep at INFO severity. Stock boilerplate files (.travis.yml, package.json, .gitignore, docker-compose.yml, README) are publicly shipped by design — keep at LOW/INFO severity even when HTTP 200; only rate higher if the evidence shows actual secrets (tokens, passwords, private keys) in the file content.
- arjun discovered parameters are TRUE positive — the parameter was confirmed to exist.
- wafw00f WAF detection is TRUE positive — the WAF was confirmed.
- SQL injection: TRUE positive only when sqlmap says "is vulnerable" or "injectable". FALSE when sqlmap says "not injectable" or "do not appear to be injectable".
- XSS: TRUE positive when dalfox shows [POC] or [V]. FALSE only when dalfox explicitly says "no XSS".
- CVE matches from nmap vulners: TRUE positive at INFO severity (version-based, needs manual verification).
- CRITICAL: Do NOT reject findings just because they are low severity or informational. Security tools only report what they found — if the tool says it found something, it found it.
- Do NOT reject findings because the evidence is "just configuration" — missing headers, exposed paths, server banners ARE valid security findings.

FINDING:
${JSON.stringify({ title: finding.title, severity: finding.severity, cweId: finding.cweId, description: finding.description, evidence: finding.evidence }, null, 2)}
${skillsBlock}
Respond with JSON:
{"is_true_positive": boolean, "confidence": 0-100, "evidence_tier": "observed|validated|needs-validation|exploited", "severity_adjusted": "critical|high|medium|low|info", "reasoning": "one sentence grounded in the evidence", "remediation": "concrete fix"}`

    try {
      const raw = await this.llm.analyzeJSON(prompt, { system, context: { operation: 'verify', agent: agentName }, useFast: false, maxTokens: 800 })
      const j = this.llm.parseJSON(raw)
      const verdict = normalizeVerdict(j)
      if (verdict === null) throw new Error('AI reply did not contain a verdict field')
      const refined = { ...finding }
      if (j.severity_adjusted) refined.severity = j.severity_adjusted
      if (j.remediation) refined.remediation = j.remediation
      return {
        isTruePositive: verdict,
        confidence: j.confidence ?? 70,
        verdict: j.reasoning || 'Finding evaluated by AI specialist.',
        agent: agentName,
        evidenceTier: j.evidence_tier || 'observed',
        refined,
      }
    } catch (e) {
      // ⚠️ CRITICAL: When LLM is unavailable or errors, do NOT blindly default to
      // true positive. Re-verify on the wire first, then fall back to the
      // evidence heuristics.
      const net = await this._networkVerify(finding, targetType)
      if (net) {
        return {
          isTruePositive: net.isTruePositive,
          confidence: net.confidence,
          verdict: `${net.verdict} (AI error: ${e.message || 'provider failure'})`,
          evidenceTier: net.isTruePositive ? 'validated' : 'needs-validation',
          agent: 'network-reverify',
          refined: net.refined,
        }
      }
      const heuristicResult = this._heuristicVerify(finding, targetType)
      return {
        isTruePositive: heuristicResult.isTruePositive,
        confidence: heuristicResult.confidence,
        verdict: heuristicResult.verdict,
        agent: agentName,
        refined: heuristicResult.refined,
      }
    }
  }

  /**
   * Live re-verification of a finding against its own target.
   *
   * Only claims that a single bounded HTTP exchange can settle are handled here
   * (header absence, CORS reflection, marker reflection/XSS, sensitive-path
   * exposure, TLS/protocol mismatch). Everything else returns null so the
   * caller falls through to the text heuristics.
   *
   * Returns { isTruePositive, confidence, verdict, refined } or null.
   */
  async _networkVerify(finding, targetType) {
    if (!NET_VERIFY_ENABLED || targetType === 'code') return null
    const url = this._targetUrlFor(finding)
    if (!url) return null

    const claim = `${finding.title || ''} ${finding.description || ''}`.toLowerCase()
    const probe = { timeout: NET_VERIFY_TIMEOUT, redirect: 'follow' }

    try {
      // ── Security header / banner / TLS claims: compare against the live response.
      if (/missing.*(?:security.*header|hsts|csp|content-security|x-frame|x-content-type|referrer|permissions-policy)|server.*(?:banner|header).*(?:disclosure|information)|information disclosure.*server|weak.*(?:cipher|protocol)|tls\s*1\.[01]/i.test(claim)) {
        const res = await httpRequest(url, probe)
        if (!res.status) return null
        const h = res.headers
        const observed = []
        const expected = [
          ['strict-transport-security', /hsts|strict-transport|missing.*header/i],
          ['content-security-policy', /csp|content-security/i],
          ['x-frame-options', /x-frame|clickjack/i],
          ['x-content-type-options', /x-content-type|mime/i],
          ['referrer-policy', /referrer/i],
          ['permissions-policy', /permissions-policy/i],
        ]
        for (const [header, re] of expected) {
          if (re.test(claim) && !h[header]) observed.push(header)
        }
        if (observed.length) {
          const present = Object.keys(h).filter(k => /^(server|x-powered-by|x-aspnet-version)$/.test(k))
          return {
            isTruePositive: true,
            confidence: 92,
            verdict: `Live re-check of ${url} returned HTTP ${res.status} without ${observed.join(', ')}.${present.length ? ` Disclosure headers present: ${present.join(', ')}.` : ''}`,
            refined: { ...finding, evidence: { ...(finding.evidence || {}), reverified: { url, status: res.status, observedHeaders: h, missing: observed, at: new Date().toISOString() } } },
          }
        }
        if (/server.*(?:banner|header)|x-powered-by/i.test(claim) && (h['server'] || h['x-powered-by'])) {
          return {
            isTruePositive: true,
            confidence: 90,
            verdict: `Live re-check confirms disclosure header: ${h['server'] ? `Server: ${h.server}` : ''}${h['x-powered-by'] ? ` X-Powered-By: ${h['x-powered-by']}` : ''}`,
            refined: { ...finding, evidence: { ...(finding.evidence || {}), reverified: { url, status: res.status, server: h.server, poweredBy: h['x-powered-by'], at: new Date().toISOString() } } },
          }
        }
        return {
          isTruePositive: false,
          confidence: 88,
          verdict: `Live re-check of ${url} returned HTTP ${res.status} and did not reproduce the claimed header gap.`,
        }
      }

      // ── CORS claims: re-send with a hostile Origin and read the reflection.
      if (/cors|access-control-allow-origin/i.test(claim)) {
        const evil = 'https://sentinel-reverify.example'
        const res = await httpRequest(url, { ...probe, headers: { Origin: evil } })
        if (!res.status) return null
        const acao = res.headers['access-control-allow-origin']
        const acac = res.headers['access-control-allow-credentials']
        const reflected = acao === evil || acao === '*'
        const exploitable = reflected && String(acac).toLowerCase() === 'true'
        return {
          isTruePositive: reflected,
          confidence: reflected ? (exploitable ? 95 : 88) : 92,
          verdict: reflected
            ? `Origin ${evil} reflected in Access-Control-Allow-Origin (${acao})${exploitable ? ' with Access-Control-Allow-Credentials: true — credentialed cross-origin reads are possible.' : '; Access-Control-Allow-Credentials absent, so cookies cannot be read cross-origin.'}`
            : `Origin ${evil} not reflected (Access-Control-Allow-Origin: ${acao || 'absent'}). CORS claim not reproduced.`,
          refined: {
            ...finding,
            ...(reflected && !exploitable ? { severity: 'low' } : {}),
            evidence: { ...(finding.evidence || {}), reverified: { url, status: res.status, acao, acac, origin: evil, at: new Date().toISOString() } },
          },
        }
      }

      // ── XSS / reflection claims: inject a unique marker into the reported
      //    parameter and classify where it lands.
      if (/xss|cross-site scripting|reflected|html injection/i.test(claim)) {
        const m = makeMarker('saiver')
        const injectable = this._injectableUrl(url, m)
        if (!injectable) return null
        const res = await httpRequest(injectable, probe)
        if (!res.status) return null
        const refl = analyzeReflection(res.body || '', m)
        const payloadTest = /<[a-z]/i.test(m)
        return {
          isTruePositive: refl.reflected && !refl.encoded && (refl.executable || refl.context !== 'html-encoded'),
          confidence: refl.reflected ? (refl.executable ? 90 : 70) : 88,
          verdict: refl.reflected
            ? `Marker ${m} reflected into ${refl.context} context${refl.encoded ? ' (HTML-encoded — not executable)' : ''} by ${injectable}.`
            : `Marker ${m} was not reflected by ${injectable} — XSS claim not reproduced.`,
          refined: { ...finding, evidence: { ...(finding.evidence || {}), reverified: { url: injectable, status: res.status, reflection: refl, payloadUsed: m, payloadTest, at: new Date().toISOString() } } },
        }
      }

      // ── Sensitive path / file exposure: fetch it and inspect the body.
      const pathMatch = (finding.evidence && (finding.evidence.path || finding.evidence.url)) || url
      if (/exposed|sensitive.*(?:path|file)|(?:git|env|backup|config).*disclosure|directory listing|swagger|openapi|robots\.txt/i.test(claim)) {
        const res = await httpRequest(pathMatch, probe)
        if (!res.status) return null
        const body = res.body || ''
        const listing = /<title>\s*Index of \//i.test(body) || /\[To Parent Directory\]/i.test(body)
        const gitHead = /ref:\s*refs\/heads\//.test(body)
        const envLike = /^[A-Z0-9_]{3,}=/m.test(body)
        const swagger = /"openapi"\s*:|"swagger"\s*:\s*"2\./i.test(body)
        const robots = /^\s*(User-agent|Disallow)\s*:/im.test(body)
        const confirmed = res.status === 200 && (listing || gitHead || envLike || swagger || robots)
        return {
          isTruePositive: confirmed,
          confidence: confirmed ? 93 : 85,
          verdict: confirmed
            ? `Live fetch of ${pathMatch} returned HTTP 200 with ${[listing && 'directory listing', gitHead && 'git HEAD ref', envLike && 'KEY=VALUE secret pairs', swagger && 'OpenAPI document', robots && 'robots.txt rules'].filter(Boolean).join(', ')}.`
            : `Live fetch of ${pathMatch} returned HTTP ${res.status} without the claimed content.`,
          refined: { ...finding, evidence: { ...(finding.evidence || {}), reverified: { url: pathMatch, status: res.status, bytes: body.length, sample: body.slice(0, 400), at: new Date().toISOString() } } },
        }
      }
    } catch {
      // Network verification is best-effort; never mask the original verdict.
      return null
    }
    return null
  }

  /** Best-guess absolute URL the finding describes, or '' when none exists. */
  _targetUrlFor(finding) {
    const ev = finding.evidence || {}
    const candidates = [ev.url, ev.requestUrl, ev.endpoint, ev.target, finding.url, finding.target]
    for (const c of candidates) {
      if (typeof c === 'string' && /^https?:\/\//i.test(c.trim())) return c.trim()
    }
    // Synthesise from host/path pairs captured in evidence.
    const host = ev.host || ev.hostname || ev.domain
    if (typeof host === 'string' && host.trim()) {
      const scheme = ev.scheme === 'http' ? 'http' : 'https'
      const p = typeof ev.path === 'string' ? ev.path : ''
      return `${scheme}://${host.trim()}${p.startsWith('/') ? '' : '/'}${p}`
    }
    return ''
  }

  /** Replace a marker into an existing query parameter, or append one. */
  _injectableUrl(url, marker) {
    try {
      const u = new URL(url)
      const key = [...u.searchParams.keys()][0]
      if (key) u.searchParams.set(key, marker)
      else u.searchParams.set('q', marker)
      return u.toString()
    } catch {
      return ''
    }
  }

  /**
   * Deterministic verification derived from the finding's OWN captured evidence.
   *
   * The previous implementation matched title/description text only, so a claim
   * of "CORS wildcard" scored 90% confidence even when the response headers were
   * never captured. Every rule below now requires the artifact it claims to
   * justify — headers, status codes, bodies, tool verdict lines, file hits — and
   * returns "unverified" instead of inventing confidence.
   *
   * Returns { isTruePositive, confidence, verdict, refined? }.
   */
  _heuristicVerify(finding, targetType) {
    const title = (finding.title || '').toLowerCase()
    const desc = (finding.description || '').toLowerCase()
    const text = `${title} ${desc}`
    const evidence = finding.evidence || {}
    const module = (finding.module || '').toLowerCase()
    const status = Number(evidence.status || evidence.statusCode || 0)

    // Flatten everything the scanner captured so rules can grep real artifacts.
    const blob = [
      typeof evidence === 'string' ? evidence : JSON.stringify(evidence || {}),
      finding.remediation || '',
      finding.httpResponse || '',
      finding.responseBody || '',
    ].join('\n')
    const headers = evidence.headers || evidence.responseHeaders || {}
    const headerNames = Object.keys(headers).map(k => k.toLowerCase())
    const body = String(evidence.body || evidence.responseBody || finding.responseBody || '')

    // Scanners record absence two ways: a live header map, or a `missing`/`present`
    // name list. Normalise both so the claim can actually be checked.
    const missingList = (Array.isArray(evidence.missing) ? evidence.missing : []).map(v => String(v).toLowerCase())
    const presentList = (Array.isArray(evidence.present) ? evidence.present : []).map(v => String(v).toLowerCase())
    const headerCaptured = headerNames.length > 0 || missingList.length > 0 || presentList.length > 0
    const missing = (name) => {
      const n = name.toLowerCase()
      if (headerNames.length) return !headerNames.includes(n)
      if (missingList.length) return missingList.some(m => m.includes(n) || n.includes(m.split(' ')[0]))
      if (presentList.length) return !presentList.includes(n)
      return false
    }

    // ── 1. Missing security headers — require recorded header state. ──
    if (/missing.*(?:security.*header|hsts|csp|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|strict-transport)/i.test(text)) {
      const wanted = [
        ['strict-transport-security', /hsts|strict-transport/i],
        ['content-security-policy', /csp|content-security/i],
        ['x-frame-options', /x-frame|clickjack/i],
        ['x-content-type-options', /x-content-type|nosniff|mime/i],
        ['referrer-policy', /referrer/i],
        ['permissions-policy', /permissions-policy/i],
      ].filter(([, re]) => re.test(text))
      const absent = wanted.filter(([h]) => missing(h)).map(([h]) => h)
      if (absent.length) {
        return {
          isTruePositive: true,
          confidence: 92,
          verdict: `Recorded header state for ${evidence.url || 'the target'} omits ${absent.join(', ')}${missingList.length ? ` (scanner reported missing: ${missingList.join(', ')})` : ''}.`,
        }
      }
      return {
        isTruePositive: false,
        confidence: headerCaptured ? 85 : 40,
        verdict: headerCaptured
          ? 'Recorded header state already contains the headers named in the finding — claim not supported by evidence.'
          : 'Finding claims a missing header but no header state was captured, so absence cannot be verified.',
      }
    }

    // ── 2. Server banner disclosure — require the actual banner value. ──
    if (/server.*(?:banner|header).*(?:disclosure|information)|x-powered-by|version.*disclosure/i.test(text)) {
      const banner = evidence.server || headers.server || headers['x-powered-by'] || evidence.banner
      if (banner) {
        return {
          isTruePositive: true,
          confidence: 92,
          verdict: `Response disclosed Server: ${banner}.`,
        }
      }
      return {
        isTruePositive: false,
        confidence: headerCaptured ? 85 : 40,
        verdict: headerCaptured
          ? 'No Server/X-Powered-By value recorded — claim not supported.'
          : 'Finding asserts a banner disclosure but no header state was captured.',
      }
    }

    // ── 2.5 Fingerprint/version observations — the claim is the ABSENCE of a
    // versioned signature, so the artifact that settles it is the scan coverage
    // itself, not a response status. ──
    const fingerprintTopic = /fingerprint|architecture|technology stack|banner grab|product version|tech stack/i.test(text)
    const absenceClaim = /inconclusive|no (?:reliable |versioned )?(?:signature|version|fingerprint|banner)|unknown (?:stack|architecture)|not (?:disclosed|captured|exposed)|suppressed|unversioned|hidden (?:architecture|stack)/i.test(text)
    if (fingerprintTopic && absenceClaim && !/outdated|vulnerable version|\bcve-\d/i.test(text)) {
      const probes = [evidence.scannedUrls, evidence.paths, evidence.probes, evidence.checked, evidence.endpoints]
        .filter(Array.isArray).flat().map(String)
      const recorded = [
        evidence.detectedVersion, evidence.version, evidence.product, evidence.banner,
        ...(Array.isArray(evidence.frameworks) ? evidence.frameworks
          : Array.isArray(evidence.detected) ? evidence.detected
            : evidence.frameworks || evidence.detected ? [evidence.frameworks || evidence.detected] : []),
      ].filter(Boolean).map(String)
      if (recorded.length) {
        return {
          isTruePositive: false,
          confidence: 75,
          verdict: `Scanner evidence records a technology signature (${recorded.slice(0, 4).join(', ')}), so the "inconclusive" claim is contradicted by its own artifacts.`,
        }
      }
      return {
        isTruePositive: true,
        confidence: 60,
        verdict: probes.length
          ? `Observation of absence, not a vulnerability: ${probes.length} endpoint${probes.length === 1 ? ' was' : 's were'} probed (${probes.slice(0, 3).join(', ')}${probes.length > 3 ? ', …' : ''}) and no product or version signature was recorded. The stored evidence supports the coverage statement only.`
          : 'Observation of absence, not a vulnerability: no product or version signature was recorded, but the evidence does not list which endpoints were probed.',
      }
    }

    // ── 2.6 Outdated component — the artifact is the captured version string.
    // Capturing the version proves the fingerprint, not that the version is EOL. ──
    if (/outdated|end.of.life|\beol\b|unsupported version|vulnerable (?:version|component)|known vulnerable/i.test(text)) {
      const claimed = (text.match(/\b\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?\b/g) || [])
      const captured = [...new Set(claimed.filter(v => blob.toLowerCase().includes(v)))]
      const product = /(apache|nginx|iis|openssh|openssl|tomcat|jquery|php|wordpress|drupal|joomla|struts|spring|log4j|redis|mysql|postgres(?:ql)?|mongo(?:db)?|node(?:\.js)?|express|laravel|rails|django|flask|varnish|haproxy|lighttpd|jetty|wildfly|jboss|weblogic|websphere)\b/i.exec(text)?.[1]
      const rawLifecycle = evidence.eol || evidence.endOfLife || evidence.outdated || evidence.latestVersion || evidence.fixedIn
      // A lifecycle signal that merely repeats the version we already captured proves
      // nothing about obsolescence — it would read as "2.4.49 … fixed in 2.4.49".
      const lifecycleText = rawLifecycle == null ? ''
        : (typeof rawLifecycle === 'object' ? JSON.stringify(rawLifecycle) : String(rawLifecycle))
      const lifecycleVersions = lifecycleText.match(/\b\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?\b/g) || []
      const lifecycle = lifecycleText && !(lifecycleVersions.length && lifecycleVersions.every(v => captured.includes(v)))
        ? rawLifecycle
        : null
      if (captured.length && lifecycle) {
        return {
          isTruePositive: true,
          confidence: 88,
          verdict: `Evidence records ${product ? `${product} ` : ''}${captured.join(', ')} together with a lifecycle signal (${lifecycleText}).`,
        }
      }
      if (captured.length) {
        return {
          isTruePositive: false,
          confidence: 55,
          verdict: `Evidence records ${product ? `${product} ` : ''}${captured.join(', ')}, matching the version named in the finding, but no end-of-life or fixed-version data was captured to show that version is actually outdated.`,
        }
      }
      return {
        isTruePositive: false,
        confidence: 35,
        verdict: 'No captured version string matches the claim — outdated-component finding unverified.',
      }
    }

    // ── 3. CORS — require the observed Access-Control-Allow-Origin value. ──
    if (/cors|access-control-allow-origin|cross-origin/i.test(text)) {
      const acao = evidence.reflectedAcao || evidence.acao || headers['access-control-allow-origin'] || evidence.allowOrigin
      const acacRaw = evidence.acac ?? headers['access-control-allow-credentials'] ?? ''
      const acac = String(acacRaw).toLowerCase() === 'true'
      if (acao) {
        const value = String(acao).trim()
        // Only discount the finding when the claim actually asserts credentialed
        // exploitation — a "no credentials" reflection finding is true as written.
        const claimsHijack = /with credentials|session hijack possible|authenticated cross-origin/i.test(text) &&
          !/no credentials|not possible|without credentials|hijack is not possible/i.test(text)
        if (claimsHijack && !acac) {
          return {
            isTruePositive: false,
            confidence: 90,
            verdict: `Recorded CORS response reflects ${value} but Access-Control-Allow-Credentials is not true — the credentialed session-hijack claim is not supported.`,
          }
        }
        return {
          isTruePositive: true,
          confidence: acac ? 95 : 85,
          verdict: `Recorded Access-Control-Allow-Origin ${value}${(evidence.probedOrigin || evidence.origin) ? ` for probed origin ${evidence.probedOrigin || evidence.origin}` : ''}${acac ? ' with Access-Control-Allow-Credentials: true — credentialed cross-origin reads are possible.' : '; Access-Control-Allow-Credentials absent, so session cookies cannot be read cross-origin.'}`,
        }
      }
      return {
        isTruePositive: false,
        confidence: headerCaptured ? 85 : 40,
        verdict: 'No Access-Control-Allow-Origin value was recorded — CORS claim unverified.',
      }
    }

    // ── 4. Exposed sensitive files — require a body or an explicit 200. ──
    // The trigger demands an exposure-shaped noun ("exposed backup", ".env",
    // "directory listing"); a bare "exposed"/"exposure" anywhere in descriptive
    // prose must not select this branch.
    if (/(?:exposed|sensitive|leaked|disclosed)\s+(?:\w+\s+){0,3}(?:path|file|files|director(?:y|ies)|repositor(?:y|ies)|backup|credential|secret|api key|private key|token|endpoint|document|listing|archive|config)|\b(?:\.git|\.env|\.svn|\.ds_store|\.htpasswd|wp-config\.php)\b|directory listing|swagger|openapi/i.test(text)) {
      const gitHead = /ref:\s*refs\/heads\//.test(body)
      const envLike = /^[A-Z0-9_]{3,}=/m.test(body)
      const listing = /<title>\s*Index of \//i.test(body) || /\[To Parent Directory\]/i.test(body)
      const swagger = /"openapi"\s*:|"swagger"\s*:\s*"2\./i.test(body)
      const keyMaterial = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(body)
      const signals = [listing && 'directory listing', gitHead && 'git HEAD ref', envLike && 'KEY=VALUE pairs', swagger && 'OpenAPI document', keyMaterial && 'private key material'].filter(Boolean)
      if (signals.length && (status === 0 || status === 200)) {
        return {
          isTruePositive: true,
          confidence: 93,
          verdict: `Response body for ${evidence.url || evidence.path || 'the path'} contains ${signals.join(', ')}.`,
        }
      }
      if (status >= 200 && status < 300 && !signals.length) {
        return {
          isTruePositive: false,
          confidence: 70,
          verdict: `Path returned HTTP ${status} but the captured body contains no sensitive content — exposure unverified.`,
        }
      }
      return {
        isTruePositive: false,
        confidence: status >= 400 ? 90 : 45,
        verdict: status >= 400
          ? `Request returned HTTP ${status} — the claimed resource is not exposed.`
          : 'No response body or status captured for the claimed exposure.',
      }
    }

    // ── 5. Open ports — require the port/service to appear in evidence. ──
    if (/open port|exposed service|service.*banner/i.test(text)) {
      const ports = evidence.ports || evidence.openPorts || evidence.port
      const proto = /(ssh|telnet|ftp|smb|rdp|mysql|postgresql|redis|mongodb|vnc|ldap|mssql)/i.exec(text)?.[1]
      const hit = ports
        ? JSON.stringify(ports).toLowerCase().includes(String(proto || evidence.port || '').toLowerCase())
        : Boolean(evidence.port || evidence.service)
      if (hit || evidence.service) {
        return {
          isTruePositive: true,
          confidence: 90,
          verdict: `Scanner evidence lists the port/service${proto ? ` (${proto})` : ''}: ${evidence.service || JSON.stringify(ports || evidence.port)}.`,
        }
      }
      return { isTruePositive: false, confidence: 40, verdict: 'No port/service data captured — open-port claim unverified.' }
    }

    // ── 6. Injection verdicts — require the tool's own confirmation line. ──
    if (/sql injection|injection|sqli/i.test(text)) {
      const confirmed = /is vulnerable|injectable|parameter.*is vulnerable|payload.*successful/i.test(blob)
      const negated = /not injectable|do not appear to be injectable|not vulnerable/i.test(blob)
      if (confirmed && !negated) return { isTruePositive: true, confidence: 94, verdict: 'Tool output in the evidence explicitly confirmed the injection point.' }
      if (negated) return { isTruePositive: false, confidence: 94, verdict: 'Tool output in the evidence explicitly reported the parameter as not injectable.' }
      return { isTruePositive: false, confidence: 45, verdict: 'No tool confirmation or negation captured for the injection claim.' }
    }

    // ── 7. XSS — require a PoC/reflection artifact. ──
    if (/xss|cross-site scripting/i.test(text)) {
      const refl = evidence.reflection || evidence.reflected
      const poc = /\[POC\]|\[V\]|payload executed|alert\(1\)/i.test(blob)
      if (poc || (refl && (refl.executable || refl.reflected))) {
        return { isTruePositive: true, confidence: 90, verdict: 'Evidence contains a reflected/executed payload artifact for the reported parameter.' }
      }
      return { isTruePositive: false, confidence: 45, verdict: 'No reflection artifact captured in evidence — XSS claim unverified.' }
    }

    // ── 8. Hardcoded secrets — require a matched secret in the file hit. ──
    if (/hardcoded.*(?:secret|credential|key|password|token)|api key|private key/i.test(text)) {
      const line = String(evidence.match || evidence.line || evidence.snippet || body || '')
      const shaped = /(?:api[_-]?key|secret|token|password|passwd|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+.]{8,}/i.test(line)
      if (shaped) {
        return {
          isTruePositive: true,
          confidence: 88,
          verdict: `Evidence contains a credential-shaped assignment${evidence.file ? ` in ${evidence.file}` : ''}${evidence.line ? `:${evidence.line}` : ''}.`,
        }
      }
      return { isTruePositive: false, confidence: 40, verdict: 'No credential-shaped assignment in the captured evidence.' }
    }

    // ── 9. Subdomain / DNS / path discovery — informational, evidence-backed. ──
    if (/subdomain|dns record|robots\.txt|discovered path|directory.*found/i.test(text)) {
      const hasTarget = Boolean(evidence.host || evidence.subdomain || evidence.path || evidence.url || evidence.domain)
      return {
        isTruePositive: hasTarget,
        confidence: hasTarget ? 85 : 40,
        verdict: hasTarget
          ? `Enumeration evidence records ${evidence.host || evidence.subdomain || evidence.path || evidence.url} — informational asset discovery, not a vulnerability.`
          : 'No enumerated asset recorded in evidence.',
      }
    }

    // ── 10. TLS / protocol weakness — require an observed version or cipher. ──
    if (/weak.*cipher|tls\s*1\.[01]|sslv|deprecated.*protocol/i.test(text)) {
      const version = evidence.protocol || evidence.tls || evidence.version
      const cipher = evidence.cipher
      if (version || cipher) {
        return { isTruePositive: true, confidence: 88, verdict: `TLS scan evidence records ${version || ''}${cipher ? ` / ${cipher}` : ''}.` }
      }
      return { isTruePositive: false, confidence: 40, verdict: 'No negotiated protocol or cipher captured — TLS weakness unverified.' }
    }

    // ── 11. Explicit negations and tool chatter → false positive. ──
    const negations = [
      { re: /all tested parameters do not appear|do not appear to be injectable|not injectable/i, reason: 'Tool explicitly reported no injection.' },
      { re: /\bnot vulnerable\b|\bnot exploitable\b|\bnot affected\b/i, reason: 'Tool explicitly negated the vulnerability.' },
      { re: /testing connection|testing if|content is stable|heuristic.*test/i, reason: 'Tool self-test output, not a finding.' },
      { re: /^(?:starting|initializing|scanning|enumerating|waiting|fetching|resuming|loaded|parsed)\b/i, reason: 'Tool progress message, not a vulnerability.' },
      { re: /no (?:vulnerabilit|result|issue|finding)/i, reason: 'Tool reported no results.' },
    ]
    for (const { re, reason } of negations) {
      if (re.test(text)) return { isTruePositive: false, confidence: 95, verdict: reason }
    }

    // ── 12. Version-only CVE matches → plausible, never confirmed. ──
    if (/CVE-\d{4}-\d+/i.test(text)) {
      const cvss = parseFloat(/(?:cvss\s*)?(\d+\.\d+)/i.exec(text)?.[1] || '0')
      return {
        isTruePositive: false,
        confidence: cvss >= 9 ? 35 : 25,
        verdict: `Version-based CVE reference${cvss ? ` (CVSS ${cvss})` : ''} without exploitation evidence — requires manual confirmation.`,
      }
    }

    // ── 13. Nothing decidable: surface it as unverified, not as confirmed. ──
    const isPatternOrCode = module === 'pattern-scan' || module === 'code-audit' || module === 'ai-audit'
    return {
      isTruePositive: false,
      confidence: 30,
      verdict: isPatternOrCode
        ? 'Pattern/code-audit finding has no machine-verifiable artifact in scope; kept for manual review at low confidence.'
        : 'No artifact in the finding evidence settles this claim; kept for manual review at low confidence.',
    }
  }

  /**
   * Whitebox static analysis of source code via the code-auditor persona.
   * files: [{ path, content }] (already sanitized by caller).
   * Uses a parallel worker pool (5 concurrent LLM calls) to process the full
   * collected source set in bounded batches.
   */
  async auditCode(files, { language = '', focus = '', log = null } = {}) {
    if (!this.llm.isConfigured()) throw new Error('AI not configured')
    const agentName = this.agents.routeStatic(language, focus)
    const rawPersona = this.agents.prompt(agentName)
    const persona = this._sanitizePersona(rawPersona)
    const system = `${persona || 'You are a secure-code review specialist.'}\n\nRespond ONLY with JSON.`

    const batchSize = 3
    const MAX_FILE_CHARS = 12000
    const CONCURRENCY = 5

    // Prioritize high-value files
    const priorityPattern = /(?:controller|service|guard|module|entity|route|middleware|auth|access|permission|role|jwt|login|signup|register|password|token|session|upload|download|file|api|admin|config|database|db\.|repository|\.spec\.)/
    const priorityFiles = []
    const otherFiles = []
    const skipPattern = /\.(?:json|min\.js|min\.css|map|lock|gz|tar|zip|7z|bz2)$|package\.json|package-lock\.json|node_modules|\.min\.|bundle\.|chunk\.|vendor\./
    for (const f of files) {
      if (skipPattern.test(f.path.toLowerCase())) continue
      if (priorityPattern.test(f.path.toLowerCase())) priorityFiles.push(f)
      else otherFiles.push(f)
    }
    const targetFiles = [...priorityFiles, ...otherFiles]

    // Build batches
    const batches = []
    for (let i = 0; i < targetFiles.length; i += batchSize) {
      const batch = targetFiles.slice(i, i + batchSize)
      const fileNames = batch.map(f => f.path)
      const bundle = batch.map(f => `### ${f.path}\n\`\`\`\n${String(f.content).slice(0, MAX_FILE_CHARS)}\n\`\`\``).join('\n\n')
      batches.push({ index: i / batchSize, fileNames, bundle })
    }

    if (log) {
      log('info', `🔀 Dispatched ${batches.length} batches across ${CONCURRENCY} workers (${targetFiles.length} files, ~${(batches.length / CONCURRENCY * 1.5).toFixed(0)}s per round)`)
    }

    const promptTemplate = (bundle) => `You are auditing source code for security vulnerabilities. Report ALL vulnerabilities you find — do not be overly conservative. Even partial evidence of a vulnerability is worth reporting.

AUDIT FOCUS: ${focus || 'all security vulnerabilities'}

SEVERITY GUIDE:
- CRITICAL: RCE, code injection, hardcoded production secrets with actual values, SQLi with user-input concatenation, unsafe deserialization
- HIGH: Auth bypass, SSRF, path traversal with user input, privilege escalation, missing auth on sensitive endpoints
- MEDIUM: Missing security headers, CORS wildcard, weak crypto, debug endpoints exposed, XSS with user input
- LOW: Missing rate limiting, info disclosure, console.log of sensitive data, weak password policy
- INFO: Banner/version disclosure, informational observations

IMPORTANT RULES:
- Report ANY dangerous function found (eval, exec, child_process, raw SQL, fs read/write with user input, os commands)
- Report hardcoded secrets, API keys, passwords, tokens — even if they look like test values
- Report missing input validation on endpoints that accept user data
- Report use of weak crypto (MD5, SHA1, Math.random for security)
- Report CORS misconfiguration (origin: '*', credentials: true with wildcard)
- Report missing auth guards on POST/PUT/DELETE endpoints
- Report file upload without validation
- Report SQL queries with string concatenation or template literals
- Report use of dangerouslySetInnerHTML, v-html, or innerHTML with user input
- DO report even if you're not 100% sure the input is user-controlled — note it in the description
- DO NOT report: code style issues, performance issues, missing comments, cosmetic issues

${bundle}

Respond ONLY with JSON:
{"findings":[{"title":"short descriptive title","severity":"critical|high|medium|low|info","cwe":"CWE-XX","owasp":"A01-A10","file":"exact file path from the code above","line":line_number_or_0,"evidence":"the exact vulnerable code snippet","description":"how this vulnerability can be exploited — describe the attack path","laymanImpact":"plain English description of the business impact","remediation":"specific fix with code example"}]}

If no vulnerabilities are found, respond with: {"findings":[]}`

    // Parallel worker pool
    const allFindings = []
    const results = new Array(batches.length)
    const workerStats = new Array(CONCURRENCY).fill(0)
    let cursor = 0

    const worker = async (workerId) => {
      const wid = workerId + 1
      let batchCount = 0
      if (log) log('info', `  ├─ Worker ${wid} started`)
      while (cursor < batches.length) {
        const idx = cursor++
        const { fileNames, bundle } = batches[idx]
        batchCount++
        const t0 = Date.now()
        if (log) log('info', `  │  W${wid} batch ${batchCount}: ${fileNames.join(', ')}`)
        try {
          const raw = await this.llm.analyze(promptTemplate(bundle), {
            system, context: { operation: 'code-audit', agent: agentName },
            maxTokens: 6000, timeoutMs: 120000
          })
          const j = this.llm.parseJSON(raw)
          results[idx] = Array.isArray(j.findings) ? j.findings : []
          const count = results[idx].length
          workerStats[workerId] += count
          const ms = Date.now() - t0
          if (log) log('info', `  │  W${wid} ✅ ${count} findings from ${fileNames.join(', ')} (${(ms / 1000).toFixed(1)}s)`)
        } catch (e) {
          if (log) {
            const ms = Date.now() - t0
            log('warn', `  │  W${wid} ⚠️ ${fileNames.join(', ')} failed: ${e.message} (${(ms / 1000).toFixed(1)}s)`)
          }
          results[idx] = []
        }
      }
      if (log) log('info', `  └─ Worker ${wid} finished: ${batchCount} batches, ${workerStats[workerId]} findings total`)
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => worker(i)))

    for (const r of results) {
      if (r) allFindings.push(...r)
    }
    if (log) {
      const total = workerStats.reduce((a, b) => a + b, 0)
      log('info', `📊 Audit complete: ${allFindings.length} findings from ${batches.length} batches via ${CONCURRENCY} workers`)
    }
    return { agent: agentName, findings: allFindings }
  }

  /**
   * Generate a specific, working PoC exploit for a finding using the LLM.
   * Unlike the generic category-based PoC generators in report.js, this method
   * sends the actual vulnerable code snippet to the AI and asks it to produce
   * a concrete, copy-pasteable exploit tailored to THIS specific vulnerability.
   *
   * Returns { pocPayload, exploitSteps, attackCommand } or null on failure.
   */
  async generateExploitPoc(finding, targetType = 'code') {
    if (!this.llm.isConfigured()) return null

    const evidence = finding.evidence || {}
    const file = evidence.file || finding.file || 'unknown'
    const line = evidence.line || ''
    const code = evidence.code || evidence.snippet || ''
    const category = finding.category || finding.owaspCategory || ''
    const cwe = finding.cweId || finding.cwe || ''
    const title = finding.title || ''
    const description = finding.description || ''
    const url = evidence.url || finding.target || ''

    const system = `You are an elite offensive security engineer. Your task is to generate a SPECIFIC, WORKING proof-of-concept exploit for the vulnerability described below. The PoC must be tailored to the ACTUAL vulnerable code — not generic examples. Include real parameter names, real file paths, real endpoints from the code. Output ONLY JSON.`

    const prompt = `Generate a specific, working PoC exploit for this vulnerability.

VULNERABILITY:
- Title: ${title}
- Category: ${category}
- CWE: ${cwe}
- Description: ${description}
- File: ${file}${line ? ':' + line : ''}
- Target URL: ${url}

VULNERABLE CODE:
\`\`\`
${code || '(code not available — generate based on title and description)'
}\`\`\`

Generate a PoC that a penetration tester can copy-paste and run immediately. The PoC must:
1. Use the ACTUAL parameter names, endpoint paths, and variable names from the code above
2. Include a concrete attack command (curl, python script, or browser payload)
3. Show step-by-step exploitation from detection to impact
4. Include the exact payload string that triggers the vulnerability
5. If it's a code-level finding (whitebox), show how an attacker would reach this code path from an external request

Respond ONLY with JSON:
{
  "pocPayload": "the exact payload string that triggers the vulnerability (e.g. ' OR '1'='1' --)",
  "attackCommand": "a complete copy-pasteable command (curl/python/bash) that exploits this specific vulnerability using the real endpoint and parameters",
  "exploitSteps": ["step 1: ...", "step 2: ...", "step 3: ..."],
  "impact": "what an attacker achieves by exploiting this",
  "prerequisites": "what access/conditions are needed (e.g. 'authenticated user with low privileges')"
}`

    try {
      const raw = await this.llm.analyze(prompt, {
        system,
        context: { operation: 'poc-generation', agent: 'exploit-guide' },
        useFast: false,
        maxTokens: 1500,
        timeoutMs: 60000,
      })
      const j = this.llm.parseJSON(raw)
      return {
        pocPayload: j.pocPayload || null,
        attackCommand: j.attackCommand || null,
        exploitSteps: Array.isArray(j.exploitSteps) ? j.exploitSteps : [],
        impact: j.impact || null,
        prerequisites: j.prerequisites || null,
        source: 'ai-generated',
      }
    } catch (e) {
      console.warn(`[AI Engine] PoC generation failed for "${title}": ${e.message}`)
      return null
    }
  }

  /**
   * Summarize scan results into a rich executive narrative.
   * Uses the HEAVY tier model for deeper analysis — this is the AI's
   * independent assessment of the security posture, NOT a regurgitation
   * of scanner output. Produces unique insights about attack surface,
   * risk posture, and recommended remediation priorities.
   */
  async summarize(scanStats) {
    if (!this.llm.isConfigured()) return null
    const { target, totalFindings, severityCounts, topFindings, owaspCategories, isWhitebox, modules } = scanStats
    const prompt = `You are an elite security consultant writing an executive summary for a ${isWhitebox ? 'source code security audit' : 'penetration test'} report.

ASSESSMENT TARGET: ${target || 'Unknown'}
ASSESSMENT TYPE: ${isWhitebox ? 'Whitebox (Static Code Analysis)' : 'Blackbox (External Penetration Test)'}
TOOLS/MODULES USED: ${modules?.join(', ') || 'N/A'}
OWASP CATEGORIES AFFECTED: ${(owaspCategories || []).join(', ') || 'N/A'}

FINDINGS BREAKDOWN:
- Critical: ${severityCounts?.critical || 0}
- High: ${severityCounts?.high || 0}
- Medium: ${severityCounts?.medium || 0}
- Low: ${severityCounts?.low || 0}
- Info: ${severityCounts?.info || 0}
- Total: ${totalFindings}

TOP FINDINGS:
${(topFindings || []).map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${f.owaspCategory ? ' (' + f.owaspCategory + ')' : ''}`).join('\n')}

Write a comprehensive executive summary (4-6 paragraphs) that:
1. Opens with a blunt assessment of the overall security posture (is this system secure or not?)
2. Explains the MOST critical risks and their business impact — not just "X vulnerabilities found" but WHAT an attacker could actually DO
3. Identifies the attack chain: how could an attacker combine these findings to achieve full compromise?
4. Prioritizes remediation — what should they fix FIRST, and why?
5. Notes any systemic issues (e.g., "auth is broadly broken" not just "one missing auth check")
6. Closes with a clear recommendation on risk acceptance or rejection

Write in professional but accessible language. Do NOT use generic templates. Be specific about the actual findings.`
    try {
      return await this.llm.analyze(prompt, {
        context: { operation: 'executive-summary' },
        maxTokens: 1200, timeoutMs: 60000,
      })
    } catch { return null }
  }

  /**
   * Generate an independent AI attack-chain analysis — how an attacker
   * could chain multiple findings together to achieve full compromise.
   * This is the AI's UNIQUE value-add: pattern scanners can't do this.
   */
  async generateAttackChain(findings, target) {
    if (!this.llm.isConfigured() || !findings.length) return null
    const topFindings = findings
      .filter(f => ['critical', 'high', 'medium'].includes(f.severity))
      .slice(0, 15)
    if (!topFindings.length) return null

    const findingList = topFindings.map((f, i) =>
      `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}
   File: ${f.evidence?.file || 'N/A'}:${f.evidence?.line || ''}
   Description: ${f.description || 'N/A'}
   OWASP: ${f.owaspCategory || 'N/A'}
   CWE: ${f.cweId || f.cwe || 'N/A'}`
    ).join('\n\n')

    const prompt = `You are an elite red team operator analyzing vulnerability findings from a security assessment of: ${target || 'a web application'}

VERIFIED VULNERABILITIES:
${findingList}

Analyze how an attacker could CHAIN these vulnerabilities together to achieve maximum impact. Think like a real attacker:

1. What is the most dangerous attack chain? (Step 1: exploit X, Step 2: use X to access Y, Step 3: ...)
2. What is the "crown jewel" — what's the worst thing an attacker could achieve?
3. Which finding, if fixed first, would break the most attack chains?
4. Are there any findings that look low-severity individually but become critical when combined?

Respond ONLY with JSON:
{
  "primaryAttackChain": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
  "crownJewel": "description of the worst-case outcome",
  "criticalBreaker": "which finding to fix first and why",
  "hiddenCombinations": ["description of low-severity findings that become critical when combined"],
  "overallRisk": "LOW | MEDIUM | HIGH | CRITICAL",
  "riskJustification": "1-2 sentence justification"
}`

    try {
      const raw = await this.llm.analyze(prompt, {
        context: { operation: 'attack-chain' },
        maxTokens: 1000, timeoutMs: 60000,
      })
      return this.llm.parseJSON(raw)
    } catch { return null }
  }

  /**
   * Generate a SIMPLIFIED IT Action Guide for non-technical stakeholders.
     * This is the "Pass B" report — plain-language remediation steps using
     * the "Medical Report" analogy (Symptom → Risk → Prescription) with
     * detected-tech click paths and urgency/difficulty badges.
     * Used by the dual-report pipeline (reportType: 'simple').
     */
    async generateSimplifiedActionGuide(findings, target, detectedTech = []) {
      if (!this.llm.isConfigured() || !findings.length) return null
      const actionable = findings
        .filter(f => ['critical', 'high', 'medium'].includes(f.severity))
        .slice(0, 15)
      if (!actionable.length) return null

      const findingList = actionable.map((f, i) =>
        `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}
     Location: ${f.evidence?.url || f.evidence?.file || f.asset || 'N/A'}
     Technical description: ${(f.description || '').slice(0, 200)}
     Suggested remediation: ${(f.remediation || '').slice(0, 200)}`
      ).join('\n\n')

      const techStr = detectedTech.length ? detectedTech.join(', ') : 'not specified'
      const prompt = `You are a senior IT manager writing a SIMPLIFIED remediation guide for a junior IT admin. Target: ${target || 'a web application'}
  DETECTED TECHNOLOGY STACK (from whatweb): ${techStr}

  FINDINGS TO REMEDIATE:
  ${findingList}

  For EACH finding, write a plain-language action item using the "Medical Report" analogy. Avoid ALL jargon — no CWE numbers, no CVSS scores, no OWASP codes. Format as JSON:
  {
    "actionItems": [
      {
        "title": "short plain-language title a non-technical person understands",
        "severity": "critical|high|medium",
        "symptom": "1-2 sentences: what we found, in plain language (e.g. 'Anyone can guess passwords on the login page at unlimited speed without getting locked out')",
        "risk": "1-2 sentences: why it matters in business terms (e.g. 'Hackers can use an automated bot to guess thousands of passwords in minutes and hijack accounts')",
        "prescription": "copy-paste fix instructions. If the detected tech stack includes a known product (Cloudflare, Moodle, WordPress, nginx, Apache, IIS, etc.), give the EXACT dashboard click path or config line. Example: 'Cloudflare Dashboard → Security → WAF → Rate limiting rules → Create rule (If URL contains /login and requests > 5 per minute → Block)'",
        "urgency": "fix-today|this-week|optional",
        "difficulty": "easy|medium|hard",
        "estimatedMinutes": "estimated minutes to fix (integer)",
        "verification": "how to verify the fix worked, in plain language"
      }
    ],
    "topPriority": "the single most important thing to fix first, in 1 plain sentence",
    "estimatedTimeline": "rough timeline to fix all critical/high items (e.g. '2 hours total')",
    "taskCountToday": "number of items with urgency=fix-today (integer)"
  }`

      try {
        const raw = await this.llm.analyze(prompt, {
          context: { operation: 'simplified-action-guide' },
          maxTokens: 2000, timeoutMs: 60000,
        })
        return this.llm.parseJSON(raw)
      } catch { return null }
    }

  /** Free-form chat with a chosen agent persona (fast model). */
  async chat(message, agentName = 'web-hunter', history = []) {
    const persona = this.agents.prompt(agentName) || 'You are a helpful security assistant.'
    const ctx = history.slice(-6).map(h => `${h.role}: ${h.content}`).join('\n')
    const prompt = `${ctx ? ctx + '\n' : ''}user: ${message}\n\nRespond concisely and professionally.`
    return this.llm.analyze(prompt, { system: persona, context: { operation: 'chat', agent: agentName }, useFast: true, maxTokens: 800 })
  }
}

export const aiEngine = new AIEngine()
export default aiEngine
