// Exercises the shipped title/narrative normalisers in report.js.
//
// report.js pulls in pdfkit and the agents loader, so it cannot be imported in
// isolation. The functions are lifted from source by brace-matching and rebuilt
// with `new Function` — assertions therefore run against the real shipped
// bodies, never a hand-copied duplicate that could drift.
import { readFileSync } from 'node:fs'

const src = readFileSync(new URL('./report.js', import.meta.url), 'utf8')

function extractFn(name) {
  const start = src.indexOf(`function ${name}(`)
  if (start < 0) throw new Error(`not found: ${name}`)
  let depth = 0
  for (let j = src.indexOf('{', start); j < src.length; j++) {
    if (src[j] === '{') depth++
    else if (src[j] === '}') { depth--; if (depth === 0) return src.slice(start, j + 1) }
  }
  throw new Error(`unbalanced: ${name}`)
}

// Mirrors the shipped sanitiser closely enough for these cases: drop non-printable
// characters, keep newlines, trim. Deliberately does NOT strip brackets — the log
// filter must see `[INFO]` intact, and an earlier version of this harness masked
// that by removing them.
const sanitizePdfText = (v) => String(v ?? '').replace(/[^\x20-\x7E\n]/g, '').trim()

const reportFindingTitle = new Function('sanitizePdfText',
  `${extractFn('reportFindingTitle')}; return reportFindingTitle`)(sanitizePdfText)
const cleanReportNarrative = new Function('sanitizePdfText',
  `${extractFn('cleanReportNarrative')}; return cleanReportNarrative`)(sanitizePdfText)

let pass = 0, fail = 0
const check = (label, got, want) => {
  if (Object.is(got, want)) pass++
  else { fail++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`) }
}

console.log('\nreportFindingTitle')

// Version-audit findings get a synthesised, product-named title.
check('version-audit synthesises product title',
  reportFindingTitle({ module: 'version-audit', title: 'junk', evidence: { product: 'nginx', version: '1.18.0' } }),
  'nginx 1.18.0 Outdated or Unsupported')

// Leading severity brackets and warnings are stripped.
check('strips leading [HIGH] tag',
  reportFindingTitle({ title: '[HIGH] SQL Injection' }), 'SQL Injection')

check('strips leading severity prefix',
  reportFindingTitle({ title: 'Warning: exposed .env' }), 'exposed .env')

// A trailing parenthesised URL is boilerplate, not part of the finding name.
check('strips trailing (url)',
  reportFindingTitle({ title: 'Admin panel exposed (https://x.com/admin)' }), 'Admin panel exposed')

check('strips trailing (bare host)',
  reportFindingTitle({ title: 'Admin panel exposed (x.com/admin)' }), 'Admin panel exposed')

check('collapses internal whitespace',
  reportFindingTitle({ title: 'A    B' }), 'A B')

// Never render an empty heading.
check('empty title falls back', reportFindingTitle({ title: '' }), 'Security Finding')
check('missing title falls back', reportFindingTitle({}), 'Security Finding')

console.log('\ncleanReportNarrative')

// Log noise and JSON blobs must not leak into prose.
check('drops timestamped log lines',
  cleanReportNarrative('Real sentence.\n2026-01-01T10:00:00Z noise'), 'Real sentence.')

check('drops raw JSON lines',
  cleanReportNarrative('Real sentence.\n{"a":1}'), 'Real sentence.')

check('joins remaining lines with a space',
  cleanReportNarrative('One.\nTwo.'), 'One. Two.')

check('empty input uses fallback', cleanReportNarrative('', 'fallback'), 'fallback')

check('whitespace-only input uses fallback', cleanReportNarrative('   \n  ', 'fallback'), 'fallback')

// Bare level words, in any case, optionally separated.
check('drops bare lowercase level word',
  cleanReportNarrative('Real sentence.\ninfo: chatter'), 'Real sentence.')
check('drops bare uppercase level word',
  cleanReportNarrative('Real sentence.\nERROR something'), 'Real sentence.')

// Bracketed level tags. Regression guard: a combined
// `^(?:\[[^\]]+\]\s*)?(?:LEVEL)\b` pattern fails here, because the optional tag
// group consumes `[INFO] ` and then demands a level word from `chatter`.
check('drops bracketed log levels',
  cleanReportNarrative('Real sentence.\n[INFO] chatter'), 'Real sentence.')
check('drops bracketed uppercase WARN',
  cleanReportNarrative('Real sentence.\n[WARN] only noise'), 'Real sentence.')
check('drops bracketed lowercase tag',
  cleanReportNarrative('Real sentence.\n[info] chatter'), 'Real sentence.')
check('drops bracketed long level',
  cleanReportNarrative('Real sentence.\n[CRITICAL] disk full'), 'Real sentence.')

// Timestamped log lines, with and without a bracketed tag.
check('drops timestamped line with tag',
  cleanReportNarrative('Real sentence.\n2026-01-01T10:00:00Z [INFO] wait'), 'Real sentence.')
check('drops bare clock-time log line',
  cleanReportNarrative('Real sentence.\n10:00:01 [INFO] wait'), 'Real sentence.')

// A bracketed tag whose contents are not a level word is a heading, not noise.
check('keeps non-level bracketed heading',
  cleanReportNarrative('[Overview] Ports 80 and 443 are open'),
  '[Overview] Ports 80 and 443 are open')

check('all-noise input uses fallback',
  cleanReportNarrative('[WARN] only noise', 'fallback'), 'fallback')

check('mixed noise still yields the real sentence',
  cleanReportNarrative('[INFO] start\nReal sentence.\n[ERROR] boom', 'fallback'), 'Real sentence.')

// --- a.11: reproduction hints must never name an un-runnable target -----------
//
// `locations` is harvested from the title when no structured field names one, so
// "X-Powered-By header exposed: Express/4.21.2" produced the location `/4.21.2`
// and the report printed `To confirm: curl -sI /4.21.2 ...` — a command that
// cannot run and a defect claim that cannot be reproduced. Every hint is shell
// text, so only a value naming a real host may become the command target.
const safeReproTarget = new Function(`${extractFn('safeReproTarget')}; return safeReproTarget`)()
const describeReproduction = new Function('safeReproTarget',
  `${extractFn('describeReproduction')}; return describeReproduction`)(safeReproTarget)

// Any `/` immediately followed by digits and dots is a version fragment, not a
// path. `https://host/4.21.2` is legal, so the scheme prefix is allowed through.
const VERSION_AS_PATH = /(^|[^:\w.])\/(?:v)?\d+(?:\.\d+)+/

console.log('\ndescribeReproduction')

const reproCases = [
  { label: 'header finding with a version-fragment location',
    v: { title: 'X-Powered-By header exposed: Express/4.21.2', locations: ['/4.21.2'], asset: 'https://abuse.example' } },
  { label: 'cors finding with a version-fragment location',
    v: { title: 'CORS misconfiguration', locations: ['/4.21.2'] } },
  { label: 'auth finding with a version-fragment location',
    v: { title: 'Admin panel login exposed', locations: ['/4.21.2'] } },
  { label: 'traversal finding with a version-fragment location',
    v: { title: 'Path traversal', locations: ['/4.21.2'] } },
  { label: 'no location at all', v: { title: 'Weak TLS cipher suite' } },
  { label: 'blank location', v: { title: 'Missing HSTS header', locations: [''] } },
  { label: 'location is a bare relative path',
    v: { title: 'Missing HSTS header', locations: ['/api/health'] } },
  { label: 'version-named finding with no asset',
    v: { title: 'Express/4.21.2 version disclosure', locations: ['/4.21.2', '/v2.0.1'] } },
]

for (const { label, v } of reproCases) {
  const out = describeReproduction(v)
  check(`no version-as-path in hint: ${label}`, VERSION_AS_PATH.test(out), false)
  check(`hint is non-empty: ${label}`, out.length > 10, true)
}

// A real URL must survive verbatim — the guard must not blunt a valid hint.
check('valid URL location is preserved',
  describeReproduction({ title: 'Missing Content-Security-Policy header', locations: ['https://abuse.example/app'] }).includes('https://abuse.example/app'),
  true)

check('valid URL location still works when it is only in evidence.url',
  describeReproduction({ title: 'Admin panel exposed', evidence: { url: 'https://abuse.example/admin' } }).includes('https://abuse.example/admin'),
  true)

// A bare host is routable knowledge, so it is kept rather than discarded.
check('bare host is preserved',
  describeReproduction({ title: 'Missing HSTS header', locations: ['abuse.example:8443'] }).includes('abuse.example:8443'),
  true)

// Purely-version assets must never be promoted to a command target.
check('version fragment is replaced by the generic target',
  describeReproduction({ title: 'Header disclosure', locations: ['/4.21.2'], asset: '/4.21.2' }).includes('the target'),
  true)

check('safeReproTarget ignores a version fragment in favour of a real asset',
  safeReproTarget({ locations: ['/4.21.2'], asset: 'https://abuse.example' }),
  'https://abuse.example')

// --- a.12: a CDN edge answers for itself, not for the origin -----------------
//
// A scan that lands on Cloudflare gets Cloudflare's cipher list and TLS floor
// back, which printed as "Weak Cipher Suites Detection" on the origin — advice
// the operator cannot act on, because the origin is not reachable directly. The
// edge evidence already exists as its own rows (banner, cf-ray header), so the
// labelling pass reads it from the row set rather than guessing from the host.
//
// These helpers read module-level `EDGE_*` constants, so the whole region is
// evaluated rather than each function body via extractFn.
const edgeRegion = (() => {
  const start = src.indexOf('// \u2500\u2500 CDN edge attribution \u2500\u2500')
  if (start < 0) throw new Error('not found: CDN edge attribution region')
  const end = src.indexOf('/** Normalize stored finding row into view model. */', start)
  if (end < 0) throw new Error('not found: end of CDN edge attribution region')
  return src.slice(start, end)
})()
const { labelEdgeTransport, scanInfrastructureFrom, EDGE_LABEL } =
  new Function(`${edgeRegion}; return { labelEdgeTransport, scanInfrastructureFrom, EDGE_LABEL }`)()

const EDGE_EVIDENCE = { evidence: { tools: [{ tool: 'nuclei', output: 'cloudflare' }], header: 'cf-ray: 8a1b2c3d' } }
const edgeRows = (titles) => titles.map((title, i) => ({ id: i + 1, title, severity: 'medium', ...EDGE_EVIDENCE }))

console.log('\nlabelEdgeTransport')

const REAL_EDGE_TITLES = [
  'Deprecated TLS Detection',
  'TLS Version - Detect',
  'Weak Cipher Suites Detection',
  'Detect SSL Certificate Issuer',
  'SSL DNS Names',
]

const labelled = labelEdgeTransport(edgeRows(REAL_EDGE_TITLES))
for (let i = 0; i < REAL_EDGE_TITLES.length; i++) {
  check(`edge transport title is labelled: ${REAL_EDGE_TITLES[i]}`,
    labelled[i].title.includes('(CDN edge - not origin infrastructure)'), true)
}

// HSTS and the HTTPS redirect are the operator's to fix even when a CDN fronts
// the site, so they must never be folded into the edge's infrastructure facts.
const policyRows = labelEdgeTransport(edgeRows([
  'Missing HSTS header',
  'Missing Content-Security-Policy header',
  'No HTTPS to HTTPS Redirect',
]))
check('HSTS is not treated as edge infrastructure', policyRows[0].title, 'Missing HSTS header')
check('CSP is not treated as edge infrastructure', policyRows[1].title, 'Missing Content-Security-Policy header')
check('HTTPS redirect is not treated as edge infrastructure', policyRows[2].title, 'No HTTPS to HTTPS Redirect')

// Without edge evidence the pass must be a no-op — a non-CDN target's transport
// findings are genuinely the origin's defects.
const bareRows = REAL_EDGE_TITLES.map((title, i) => ({ id: i + 1, title }))
check('no edge evidence leaves the rows untouched',
  labelEdgeTransport(bareRows)[2].title, 'Weak Cipher Suites Detection')
check('no edge evidence yields no infrastructure verdict',
  scanInfrastructureFrom(bareRows), null)

// A scan that reached the origin directly is the one case where the transport
// advice is actionable, so the origin verdict must win over a lingering banner.
const bypassed = labelEdgeTransport([...edgeRows(REAL_EDGE_TITLES), { id: 9, title: 'Origin IP exposed', evidence: {} }])
check('origin exposure suppresses the edge label',
  bypassed[2].title, 'Weak Cipher Suites Detection')

// The label is what the severity classifier matches on, so labelling alone must
// move the card out of the actionable tier.
const { classifyFinding } = await import('./cvss4.js')
const edgeCls = classifyFinding({ title: labelled[2].title })
check('labelled cipher card classifies as edge transport',
  edgeCls && edgeCls.id, 'cdn_edge_transport')
check('labelled cipher card is informational',
  edgeCls && edgeCls.ceiling, 'info')
const plainCls = classifyFinding({ title: 'Weak Cipher Suites Detection' })
check('unlabelled cipher card still needs hardening',
  plainCls && plainCls.id, 'transport_hardening')

// A second pass over already-labelled rows must not stack the suffix.
check('relabelling is idempotent',
  labelEdgeTransport(labelled)[2].title, labelled[2].title)
check('idempotent pass labels exactly once',
  labelled[2].title.split('(CDN edge - not origin infrastructure)').length - 1, 1)

// Regression: Cloudflare advertises itself with `origin-cf-ray` / `origin-ip` /
// `origin-agent-cluster` header names, and those names sit in the `present`
// array of the missing-headers row. Read as origin exposure they flipped
// proxied scans to the `origin` verdict and suppressed the label on exactly the
// targets the label exists for — a live scan of https://x.com did this.
const CF_HEADERS = {
  url: 'https://cdn.example.com',
  missing: ['Permissions-Policy'],
  present: ['cache-control', 'cf-cache-status', 'cf-ray', 'origin-agent-cluster', 'origin-cf-ray', 'perf', 'server'],
}
const cfScan = [
  ...edgeRows(REAL_EDGE_TITLES),
  { id: 90, title: 'Server Header Information Disclosure (cloudflare envoy)', evidence: { url: 'https://cdn.example.com', server: 'cloudflare envoy' } },
  { id: 91, title: 'Missing Security Headers (1)', evidence: CF_HEADERS },
]
check('a CDN header name is not read as origin exposure',
  scanInfrastructureFrom(cfScan), 'edge')
check('a CDN-header scan still gets its transport rows labelled',
  labelEdgeTransport(cfScan)[2].title, `Weak Cipher Suites Detection${EDGE_LABEL}`)

// The `origin` verdict must still work, and only a title may assert it.
check('an exposure title still suppresses the label',
  scanInfrastructureFrom([...edgeRows(REAL_EDGE_TITLES), { id: 92, title: 'Origin IP exposed', evidence: {} }]), 'origin')
check('a real exposure title keeps transport rows unlabelled',
  labelEdgeTransport([...edgeRows(REAL_EDGE_TITLES), { id: 93, title: 'Origin IP exposed', evidence: {} }])[2].title,
  'Weak Cipher Suites Detection')
// Prose in the evidence blob is likewise not a claim.
check('exposure prose in evidence does not count',
  scanInfrastructureFrom([...edgeRows(REAL_EDGE_TITLES), { id: 94, title: 'TLS Version - Detect', evidence: { note: 'cdn bypass observed' } }]), 'edge')

// The transport matcher must not swallow non-transport titles that merely
// mention a certificate. "28 subdomains discovered via certificate
// transparency" is a real title from the live database.
check('certificate transparency is not a transport finding',
  labelEdgeTransport(edgeRows(['28 subdomains discovered via certificate transparency']))[0].title,
  '28 subdomains discovered via certificate transparency')
check('Detect SSL Certificate Issuer is a transport finding',
  labelEdgeTransport(edgeRows(['Detect SSL Certificate Issuer']))[0].title,
  `Detect SSL Certificate Issuer${EDGE_LABEL}`)

console.log(`\nreport-helpers: ${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
