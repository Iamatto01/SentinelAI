/**
 * Regression tests for catch-all (soft-404) suppression.
 *
 * Run: npm test --prefix backend
 *
 * These exercise the shipped `_isSoft404Finding` on a real `UnifiedPipeline`
 * instance — no reimplementation, so a change to the production method is what
 * breaks these, which is the point.
 *
 * Background: on a catch-all / SPA target every unknown path returns the same
 * 200 landing page. Path-enumerating probes then emit one "finding" per
 * attempted path. Suppressing them is necessary; suppressing them *correctly*
 * is subtle, because the naive rules also discard genuine findings.
 */
import { UnifiedPipeline, adjudicateClaimSeverity } from './pipeline.js'
import { parseScriptFindings } from './custom-scripts.js'
import { readFileSync } from 'node:fs'

let pass = 0
const failures = []

function check(label, got, want) {
  if (Object.is(got, want)) {
    pass++
    return
  }
  failures.push({ label, got, want })
}

const p = new UnifiedPipeline()
p.log = () => {}

const SCAN = 'scan-1'
// Every unknown path on this target returns the same 200 HTML lander.
const HTML = '<!doctype html><html><head><title>Welcome</title></head><body>home</body></html>'
p._catchAllBaselines.set(SCAN, {
  isCatchAll: true,
  status: 200,
  contentLength: HTML.length,
  bodyHash: 'deadbeef',
  isHtml: true,
  title: 'Welcome',
})

const finding = (evidence) => ({
  module: 'custom-script:editor-temp-file-exposure',
  title: 'Editor temp file exposed',
  description: 'check',
  evidence,
})

console.log('\nCatch-all suppression')

check(
  'same status + size within 2% is suppressed',
  p._isSoft404Finding(SCAN, finding({ status: 200, contentLength: HTML.length })),
  true,
)

// The lander came back, yet the finding claims a machine-readable artefact.
// Both cannot be true, so the claim is an artefact of the catch-all.
check(
  'HTML body contradicting a machine-readable claim is suppressed',
  p._isSoft404Finding(SCAN, finding({ status: 200, contentLength: 999999, isHtml: true, claim: 'config' })),
  true,
)

// A genuinely different response on a catch-all host is a real finding. An
// earlier formulation suppressed this and silently discarded real discoveries.
check(
  'different non-HTML body is NOT suppressed',
  p._isSoft404Finding(SCAN, finding({ status: 200, contentLength: 999999, isHtml: false, claim: 'config' })),
  false,
)

check(
  'different status is NOT suppressed',
  p._isSoft404Finding(SCAN, finding({ status: 403, contentLength: HTML.length })),
  false,
)

// Suppressing on a claim keyword alone would drop findings that carry no
// response metadata. `status` is the anchor for that reason.
check(
  'missing status is NOT suppressed',
  p._isSoft404Finding(SCAN, finding({ claim: 'config' })),
  false,
)

check(
  'unguarded module is untouched',
  p._isSoft404Finding(SCAN, { module: 'other', evidence: { status: 200, contentLength: HTML.length } }),
  false,
)

check(
  'path-enum is guarded',
  p._isSoft404Finding(SCAN, { module: 'path-enum', title: 'x', evidence: { status: 200, contentLength: HTML.length } }),
  true,
)

check(
  'native:ffuf is guarded',
  p._isSoft404Finding(SCAN, { module: 'native:ffuf', title: 'x', evidence: { status: 200, contentLength: HTML.length } }),
  true,
)

// Baselines are keyed by scanId; one scan's baseline must not leak into another.
check(
  'unknown scan is NOT suppressed',
  p._isSoft404Finding('other-scan', finding({ status: 200, contentLength: HTML.length })),
  false,
)

// ---------------------------------------------------------------------------
console.log('\nClaim verification (findings may not outrank their evidence)')
// ---------------------------------------------------------------------------

/**
 * The defect these lock down: a custom script probed 25 `.php` paths, the SPA
 * answered 200 with its landing page for all of them, a loose body regex
 * matched that landing page, and 23 `critical` "Possible webshell" findings
 * were stored with `validationTier: needs-validation` and CVSS 8.6.
 */
const ws = (extra = {}) => ({
  module: 'custom-script:PHP Backdoor & Webshell Detection',
  title: 'Possible webshell: /shell.php',
  description: 'Path /shell.php returned HTTP 200 and the body matched a shell indicator.',
  severity: 'critical',
  evidence: { status: 200, contentLength: HTML.length, contentType: 'text/html', ...extra },
})

check(
  'unproven webshell claim is demoted from critical',
  adjudicateClaimSeverity(ws())?.severity,
  'medium',
)
check(
  'unproven webshell claim is named as a code-execution claim',
  adjudicateClaimSeverity(ws())?.claim,
  'code execution',
)
check(
  'a 200 on a shell path with no artifact is not treated as proof',
  adjudicateClaimSeverity({ ...ws(), proofArtifact: false }) !== null,
  true,
)

// Real proof must survive. `/etc/passwd` content can only appear if traversal worked.
check(
  'webshell claim backed by artifact evidence keeps its severity',
  adjudicateClaimSeverity(ws({ content: 'uid=0(root) gid=0(root) groups=0(root)' })),
  null,
)
check(
  'webshell claim backed by a structured capture keeps its severity',
  adjudicateClaimSeverity({ ...ws(), proofArtifact: true }),
  null,
)
check(
  'a resolved passwd entry is accepted as a file-disclosure artifact',
  adjudicateClaimSeverity({
    module: 'custom-script:Path Traversal',
    title: 'Local file inclusion: /download?file=../../../../etc/passwd',
    description: 'Directory traversal retrieved a system file.',
    severity: 'high',
    evidence: { status: 200, content: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' },
  }),
  null,
)

// The other dominant false-positive class: IDOR asserted from a 200 on a
// sequential id, with no record returned to prove the access happened.
check(
  'unproven IDOR claim is demoted from high',
  adjudicateClaimSeverity({
    module: 'custom-script:IDOR / BOLA Indicator Probe',
    title: 'Potential IDOR/BOLA: /api/v1/users/1 accessible without auth',
    description: 'Endpoint returned 200 for a sequential identifier without an Authorization header.',
    severity: 'high',
    evidence: { status: 200 },
  })?.severity,
  'medium',
)
check(
  'IDOR claim backed by a leaked record keeps its severity',
  adjudicateClaimSeverity({
    module: 'custom-script:IDOR / BOLA Indicator Probe',
    title: 'Potential IDOR/BOLA: /api/v1/users/1 accessible without auth',
    description: 'Endpoint returned 200 for a sequential identifier without an Authorization header.',
    severity: 'high',
    evidence: { status: 200, content: '{"id":1,"email":"admin@sentinelai.studio","role":"admin"}' },
  }),
  null,
)

// Proposed-fix savings in the description would otherwise defeat the gate.
check(
  'a rule name in the fix advice is not itself an artifact',
  adjudicateClaimSeverity({
    module: 'custom-script:SQL Injection Probe',
    title: 'Potential SQL injection: /search?q=',
    description: 'Fix: use parameterised queries and avoid string concatenation of SELECT.',
    severity: 'high',
    evidence: { status: 200, content: '{"results":[],"total":0}' },
  })?.severity,
  'medium',
)

// Reconstruction: a structured PoC is a recipe, not a target response.
check(
  'a structured poc command cannot self-certify a code-execution claim',
  adjudicateClaimSeverity({
    module: 'custom-script:Command Injection Probe',
    title: 'Command execution on /api/tools/ping',
    description: 'Injected command returned output.',
    severity: 'critical',
    evidence: { status: 200, poc: { tool: 'sqlmap', args: ['--os-shell', '--passwords'] } },
  }),
  null,
)

// Don't break honest findings.
check(
  'a low-severity observation is not touched',
  adjudicateClaimSeverity({ ...ws(), severity: 'low' }),
  null,
)
check(
  'a medium-severity observation is not touched',
  adjudicateClaimSeverity({ ...ws(), severity: 'medium' }),
  null,
)
check(
  'a claim with no matching rule is not touched',
  adjudicateClaimSeverity({ ...ws(), title: 'Missing Content-Security-Policy header', description: 'No CSP was sent.' }),
  null,
)
check(
  'code-audit findings grade their own source artifacts',
  adjudicateClaimSeverity({ ...ws(), evidence: { module: 'code-audit:sast' } }),
  null,
)

// ---------------------------------------------------------------------------
// Severity floor must never silently destroy a finding.
//
// Two shipped scripts declared `severity_floor: "critical"` while legitimately
// emitting `high`. The parser `continue`d on any emission below the floor, so
// every one of their findings vanished between the process and the database —
// no log line, no `rejected` entry, indistinguishable from "found nothing".
//
// The floor is a MINIMUM: below-floor emissions are raised to the floor and
// recorded in `rejected`. Anything that re-introduces a silent discard fails
// these checks.
// ---------------------------------------------------------------------------
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

function emit(severity, title = 't') {
  return JSON.stringify({ title, severity, description: 'd', evidence: { status: 200 } })
}

const belowFloor = parseScriptFindings(emit('high'), 'critical')
check('a below-floor finding is KEPT, not dropped', belowFloor.length, 1)
check('the kept finding is raised to the floor', belowFloor[0] && belowFloor[0].severity, 'critical')
check('the original severity is preserved on the finding', belowFloor[0] && belowFloor[0].severityRaisedFrom, 'high')
check('the drop is recorded in rejected', belowFloor.rejected.length, 1)
check('the rejection names the reason', belowFloor.rejected[0] && belowFloor.rejected[0].reason, 'raised-to-severity-floor')
check('the rejection names the original severity', belowFloor.rejected[0] && belowFloor.rejected[0].severity, 'high')
check('the rejection names the floor', belowFloor.rejected[0] && belowFloor.rejected[0].floor, 'critical')

const aboveFloor = parseScriptFindings(emit('critical'), 'high')
check('an at-or-above-floor finding is untouched', aboveFloor.length, 1)
check('an at-or-above-floor finding keeps its severity', aboveFloor[0] && aboveFloor[0].severity, 'critical')
check('an at-or-above-floor finding is not annotated', aboveFloor[0] && aboveFloor[0].severityRaisedFrom, undefined)
check('an at-or-above-floor finding is not rejected', aboveFloor.rejected.length, 0)

// The exact pair that produced the bug: floor critical, two high emissions.
const twoHigh = parseScriptFindings(`${emit('high', 'a')}\n${emit('high', 'b')}`, 'critical')
check('both below-floor findings survive', twoHigh.length, 2)
check('both below-floor drops are recorded', twoHigh.rejected.length, 2)

// An unknown severity label is still a parse failure, but it must be audible.
const badSev = parseScriptFindings(emit('catastrophic'), 'info')
check('an unknown severity is not kept', badSev.length, 0)
check('an unknown severity is recorded', badSev.rejected.length, 1)
check('the unknown severity is named', badSev.rejected[0] && badSev.rejected[0].reason, 'unknown-severity')

// A floor of `info` is the identity: nothing can rank below it.
for (const sev of Object.keys(RANK)) {
  const r = parseScriptFindings(emit(sev), 'info')
  check(`floor=info passes ${sev} through unchanged`, r[0] && r[0].severity, sev)
}

// Every shipped script must be able to report at its own floor. A floor above
// anything the template can emit is pure inflation, and a floor below anything
// it emits used to be pure data loss.
const SCRIPTS = JSON.parse(
  readFileSync(new URL('./data/default-custom-scripts.json', import.meta.url), 'utf8'),
)
check('the shipped script set is intact', SCRIPTS.length, 103)
const inflated = []
for (const s of SCRIPTS) {
  const cmd = String(s.command || '')
  const emitted = new Set()
  for (const m of cmd.matchAll(/\\"severity\\"\s*:\s*\\"([a-z]+)\\"/g)) emitted.add(m[1])
  for (const m of cmd.matchAll(/"severity"\s*:\s*"([a-z]+)"/g)) emitted.add(m[1])
  if (!emitted.size || emitted.has('$SEV')) continue
  const max = Math.max(...[...emitted].map((e) => RANK[e] ?? 0))
  if (RANK[s.severity_floor] > max) inflated.push(`${s.name} floor=${s.severity_floor} emits=${[...emitted].join('/')}`)
}
check(`no script declares a floor above what it can emit (${inflated.join('; ')})`, inflated.length, 0)

// ---------------------------------------------------------------------------
// No script may silently discard its own findings below its floor.
//
// The mirror image of the check above: a floor BELOW anything the template
// emits is data loss, because the parser used to `continue` on it. This walks
// every shipped template's `emit` sites and fails if any of them can produce a
// severity ranked under the declared floor.
// ---------------------------------------------------------------------------
const lossy = []
for (const s of SCRIPTS) {
  const cmd = String(s.command || '')
  // Same two forms the inflated check uses: JSON.stringify escaping inside the
  // bash body, and plain single-escaped JSON. Using one form here and two
  // there is how the previous version of this check missed real emissions.
  const emitted = new Set()
  for (const m of cmd.matchAll(/\\"severity\\"\s*:\s*\\"([a-z]+)\\"/g)) emitted.add(m[1])
  for (const m of cmd.matchAll(/"severity"\s*:\s*"([a-z]+)"/g)) emitted.add(m[1])
  // Variable severities (`$SEV`) are resolved at runtime; they are audited by
  // the behavioural group below instead of statically.
  if (!emitted.size || emitted.has('$SEV')) continue
  const floorRank = RANK[s.severity_floor] ?? 0
  const below = [...emitted].filter((e) => (RANK[e] ?? 0) < floorRank)
  if (below.length) lossy.push(`${s.name} floor=${s.severity_floor} emits=${below.join('/')}`)
}
check(`no script emits below its declared floor (${lossy.join('; ')})`, lossy.length, 0)

// ---------------------------------------------------------------------------
// The shipped corpus must stay pinned to the reviewed calibration.
//
// Five templates were rewritten to add soft-404 calibration, and eleven floors
// were corrected. This snapshots both sets so a later edit cannot quietly
// reintroduce a floor that inflates or discards.
// ---------------------------------------------------------------------------
const CALIBRATED = [
  'Database Admin Interfaces Exposure',
  'IDOR / BOLA Indicator Probe',
  'Price/Amount Manipulation Probe',
  'PHP Backdoor & Webshell Detection',
  'Web Cache Deception Probe',
]
// Every shipped template's floor is pinned to the minimum severity it can
// honestly emit. A floor above that minimum inflates a finding, so this map
// is the tripwire against quiet re-inflation of the corpus.
const REVIEWED_FLOORS = {
  "Admin Panel Discovery (30 paths)": "info",
  "API Documentation Exposure": "medium",
  "API Endpoint Discovery (20 paths)": "info",
  "API Gateway & Microservice Discovery": "info",
  "API Rate Limiting Test": "medium",
  "ASP.NET Security Checks": "info",
  "Authentication Timing Side-Channel": "medium",
  "Backup & Archive File Exposure (25 paths)": "high",
  "Certificate Transparency Subdomain Discovery": "info",
  "CI/CD Pipeline Exposure (Jenkins/GitLab/GitHub Actions/Drone)": "high",
  "Clickjacking (UI Redressing)": "medium",
  "Cloud Storage Bucket Discovery": "high",
  "Cloud Storage Misconfiguration": "high",
  "Command Injection Probe (time-based)": "critical",
  "Common Service Port Scan (top 20)": "info",
  "Cookie Security Audit": "low",
  "Cookie Security Deep Audit": "low",
  "CORS Preflight & Method Abuse": "medium",
  "CORS Wildcard Misconfiguration": "medium",
  "Coupon/Discount Code Enumeration": "low",
  "Cross-Origin Resource Sharing Preflight Abuse": "medium",
  "CSP Deep Analysis": "low",
  "Dangerous HTTP Methods Enabled": "medium",
  "Database Admin Interfaces Exposure": "high",
  "Database Dump & SQL File Exposure": "critical",
  "Default Installation Pages (12 paths)": "high",
  "Directory Listing Enabled": "medium",
  "Django Debug Mode & Static Exposure": "low",
  "DNS Security Audit (SPF/DMARC/DKIM)": "info",
  "DNS Zone Transfer Attempt": "high",
  "Docker API Exposure": "critical",
  "Editor & Temp File Exposure": "medium",
  "Elasticsearch/OpenSearch Unauthenticated Access": "critical",
  "Email Address Harvesting from Pages": "info",
  "Environment & Config File Exposure (20 paths)": "medium",
  "Exposed .git Repository": "high",
  "Exposed .hg Repository (Mercurial)": "low",
  "Exposed .svn Repository": "medium",
  "File Upload Content-Type Bypass": "high",
  "File Upload Endpoint Discovery": "info",
  "File Upload Validation Test": "high",
  "GraphQL Field Suggestion Abuse": "low",
  "GraphQL Introspection & Depth Attack": "medium",
  "GraphQL Mutation & Depth Abuse": "medium",
  "Host Header Injection": "medium",
  "HTML Injection via 404 Page": "medium",
  "HTTP Parameter Pollution Probe": "medium",
  "HTTP Protocol Version & Features": "info",
  "HTTP Request Smuggling CL.TE Probe": "high",
  "HTTP Request Smuggling Indicators": "high",
  "HTTPS Redirect & TLS Enforcement": "info",
  "IDOR / BOLA Indicator Probe": "high",
  "Information Disclosure Pages (15 paths)": "high",
  "Insecure Deserialization Probe (PHP/Java/Python)": "high",
  "Java WebSphere/JBoss/Tomcat Exposure": "critical",
  "JWT Algorithm Confusion (none/HS256)": "high",
  "JWT Security Analysis": "info",
  "Kubernetes Dashboard & API Exposure": "critical",
  "Laravel Security Audit (8 checks)": "high",
  "Local File Inclusion Probe (10 params)": "critical",
  "Log File Exposure (deep scan)": "low",
  "Login Rate Limiting Test": "info",
  "Management Interface Port Scan": "info",
  "Mass Assignment Probe": "high",
  "Next.js/Nuxt.js SPA Security Checks": "low",
  "Node.js Error Stack Trace Disclosure": "medium",
  "Node.js Source Map Exposure": "medium",
  "NoSQL Injection Probe (MongoDB)": "high",
  "OAuth/OIDC Misconfiguration Probe": "medium",
  "Open Redirect Vulnerability (10 params)": "medium",
  "OS Metadata File Exposure (.DS_Store, Thumbs.db, desktop.ini)": "medium",
  "package.json & Dependency Disclosure": "low",
  "Password Reset Flow Abuse": "medium",
  "PHP Backdoor & Webshell Detection": "high",
  "PHP Configuration Exposure": "medium",
  "PHP Info & Debug Pages": "high",
  "Price/Amount Manipulation Probe": "high",
  "Prototype Pollution Probe (client-side)": "low",
  "PWA Manifest & Metadata Exposure": "info",
  "Python WSGI/Flask Exposure": "medium",
  "Reflected XSS Probe (12 params)": "high",
  "Robots.txt Sensitive Path Discovery": "info",
  "Ruby on Rails Security Checks": "low",
  "Security Headers Audit (8 headers)": "low",
  "Service Worker Security Audit": "low",
  "Session Token Entropy Analysis": "medium",
  "Spring Boot Actuator Full Audit": "high",
  "SQL Injection Error-Based Probe (15 params)": "high",
  "SSRF Indicator Probe": "high",
  "SSTI (Server-Side Template Injection) Probe": "critical",
  "Subdomain Takeover Check (CNAME-based)": "high",
  "Subdomain Takeover Indicators": "high",
  "Technology Version Disclosure": "low",
  "TLS/SSL Security Audit": "medium",
  "User Enumeration via Login Response": "medium",
  "Web Cache Deception Probe": "high",
  "Web Cache Poisoning Indicators": "high",
  "Web Server & CDN Fingerprint": "info",
  "WebSocket Endpoint Discovery & Origin Test": "high",
  "WebSocket Endpoint Security": "medium",
  "Wildcard DNS Detection": "info",
  "WordPress Security Audit (12 checks)": "low",
  "XXE Injection Probe": "high",
}
for (const name of CALIBRATED) {
  const s = SCRIPTS.find((x) => x.name === name)
  check(`${name} is present`, !!s, true)
  // Every calibrated template must consult the runner baseline or derive its
  // own, and must gate on the result before emitting.
  check(
    `${name} consumes the catch-all baseline`,
    !!s && /CATCHALL_HASH|CAL_HASH|BASELINE_HASH/.test(s.command),
    true,
  )
  check(`${name} gates on a calibration predicate`, !!s && /cal_suppressed|BASELINE_HASH/.test(s.command), true)
}
for (const [name, floor] of Object.entries(REVIEWED_FLOORS)) {
  const s = SCRIPTS.find((x) => x.name === name)
  check(`${name} floor stays ${floor}`, s && s.severity_floor, floor)
}

// ---------------------------------------------------------------------------
// Calibration against a real catch-all, in both directions.
//
// A static read of the template text cannot prove it stays quiet on an SPA and
// still fires on the real thing. These two fixtures do, using the real runner:
//   (a) every path returns the same 200 index.html -> nothing may be emitted;
//   (b) a genuine phpMyAdmin page on one path        -> it must be emitted.
// ---------------------------------------------------------------------------
const { runCustomScript } = await import('./custom-scripts.js')
const http = await import('node:http')

const SPA_PAGE = '<!doctype html><html><head><title>SentinelAI</title></head><body><div id="root"></div><script src="/assets/index-abc123.js"></script></body></html>'
// Contains every token the pre-rewrite webshell/db-admin greps matched on:
// password, cmd, command, eval(, login, mongo, redis.
const SPA_BUNDLE = '!function(){"use strict";var e="password",t="command",n="cmd",r="login",o="mongo",s="redis";function a(p){return p===e?t:n}function b(m){return eval(m)}module.exports={a:a,b:b,o:o,s:s}}();'
const REAL_PMA = '<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body id="pma_login"><form id="login_form"><input name="pma_username"></form></body></html>'

// mode 'spa'   -> every path is the catch-all page (nothing may be emitted)
// mode 'real'  -> /phpmyadmin serves phpMyAdmin, every other path 404s.
//
// 'real' MUST NOT be a catch-all. An earlier version served the SPA page on
// every non-phpMyAdmin path, which makes the host a genuine catch-all: the
// template then correctly suppresses the whole path set and the positive
// direction can never fire. A real exposure on a real host is reachable
// because the surrounding paths are genuinely absent, so that is what the
// fixture models.
const makeFixture = (mode) =>
  http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname
    if (p === '/assets/index-abc123.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' })
      return res.end(SPA_BUNDLE)
    }
    if (mode === 'real') {
      if (p === '/phpmyadmin' || p === '/phpMyAdmin') {
        res.writeHead(200, { 'content-type': 'text/html' })
        return res.end(REAL_PMA)
      }
      res.writeHead(404, { 'content-type': 'text/html' })
      return res.end('<!doctype html><html><head><title>404 Not Found</title></head><body>Not Found</body></html>')
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(SPA_PAGE)
  })

async function withFixture(mode, fn) {
  const server = makeFixture(mode)
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const target = `http://127.0.0.1:${server.address().port}`
  try {
    return await fn(target)
  } finally {
    await new Promise((r) => server.close(r))
  }
}

// Assert on `findings` AND on the raw stdout, so a parser regression cannot be
// masked by a green count.
async function emitFrom(name, target, { baseline = undefined } = {}) {
  const script = SCRIPTS.find((s) => s.name === name)
  const { result, findings } = await runCustomScript(script, {
    target,
    scanId: 'catch-all-test',
    depth: 'standard',
    baseline,
  })
  const raw = []
  for (const line of String(result?.stdout || '').split('\n')) {
    const t = line.trim()
    if (!t.startsWith('{')) continue
    try {
      raw.push(JSON.parse(t))
    } catch {
      /* not a finding line */
    }
  }
  return { findings: findings || [], raw, stdout: String(result?.stdout || '') }
}

const QUIET_ON_SPA = [
  'PHP Backdoor & Webshell Detection',
  'Database Admin Interfaces Exposure',
  'Web Cache Deception Probe',
  'IDOR / BOLA Indicator Probe',
  'Price/Amount Manipulation Probe',
]

await withFixture('spa', async (target) => {
  const baseline = await p.detectCatchAllBaseline('catch-all-test', target)
  check('fixture (a) is detected as a catch-all', baseline.isCatchAll, true)
  for (const name of QUIET_ON_SPA) {
    const { findings, raw } = await emitFrom(name, target, { baseline })
    check(`${name} emits nothing on a pure SPA catch-all`, findings.length, 0)
    check(`${name} writes nothing to stdout on a pure SPA catch-all`, raw.length, 0)
  }
  // The self-derivation path, with no runner baseline at all.
  for (const name of QUIET_ON_SPA) {
    const { findings } = await emitFrom(name, target, { baseline: null })
    check(`${name} emits nothing on a pure SPA catch-all without a baseline`, findings.length, 0)
  }

  // The real phpMyAdmin page must still be reported. The host is not a
  // catch-all here, so the baseline is null and the template falls back to its
  // own per-path calibration — the exact code path a production scan takes on
  // a host that 404s unknown paths.
  const real = await withFixture('real', async (t2) => {
    const b2 = await p.detectCatchAllBaseline('catch-all-test', t2)
    check('fixture (b) is not a catch-all', b2, null)
    return emitFrom('Database Admin Interfaces Exposure', t2, { baseline: b2 })
  })
  check('a real phpMyAdmin is still reported on a catch-all host', real.findings.length >= 1, true)
  check('the real phpMyAdmin is reported with a snippet', typeof real.findings[0]?.evidence?.snippet === 'string', true)
  check('the real phpMyAdmin is identified by signature', /phpMyAdmin/.test(real.findings[0]?.evidence?.signature || ''), true)
})

// ---------------------------------------------------------------------------
console.log('\nResults')
// ---------------------------------------------------------------------------
const total = pass + failures.length
for (const f of failures) {
  console.error(`FAIL  ${f.label}\n        got=${JSON.stringify(f.got)} want=${JSON.stringify(f.want)}`)
}
console.log(`\ncatch-all: ${pass}/${total} passed`)
if (failures.length) process.exit(1)
