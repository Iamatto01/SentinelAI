/**
 * Regression tests for scan-coverage modelling.
 *
 * Run: npm test --prefix backend
 *
 * Background: the abuse.sentinelai.studio report printed an
 * "ELEVATED RISK - ACTION REQUIRED THIS WEEK" posture while the scanning host
 * had no `sqlmap` and no `dalfox` on PATH. Injection and XSS were never
 * exercised, yet nothing in the PDF said so. These tests pin the rule that a
 * missing critical-ability tool degrades the scan and forces the report to
 * stop advertising a headline posture.
 */
import { buildCoverage, rehydrateCoverage, coverageFromMeta, COVERAGE_CLASSES, COVERAGE_CLASS_IDS } from './integrations/coverage.js'
import { coverageView } from './report-contract.js'
import { resolvePosture } from './report.js'

let pass = 0
const failures = []

function check(label, got, want) {
  if (Object.is(got, want)) {
    pass++
    return
  }
  failures.push({ label, got, want })
}

function checkDeep(label, got, want) {
  const a = JSON.stringify(got)
  const b = JSON.stringify(want)
  if (a === b) {
    pass++
    return
  }
  failures.push({ label, got: a, want: b })
}

// A host with the complete registry installed.
const FULL = {
  subfinder: true, amass: true, gobuster: true, httpx: true, katana: true,
  dalfox: true, sqlmap: true, arjun: true, nmap: true, nuclei: true,
  ffuf: true, whatweb: true, feroxbuster: true, gau: true, sslscan: true,
  dirsearch: true, nikto: false, wpscan: false, masscan: false,
}

// ---------------------------------------------------------------------------
console.log('\nCoverage model')
// ---------------------------------------------------------------------------

check('class ids are unique', new Set(COVERAGE_CLASS_IDS).size, COVERAGE_CLASSES.length)
check(
  'every class declares at least one tool',
  COVERAGE_CLASSES.every((c) => Array.isArray(c.anyOf) && c.anyOf.length > 0),
  true,
)

const full = buildCoverage(FULL)
check('full host is not degraded', full.degraded, false)
checkDeep('full host has no critical gaps', full.criticalGaps, [])
check('full host summary admits completeness', full.summary.includes('Full toolchain available'), true)
check('full host is not passive-only', full.passiveOnly, false)

// The actual abuse.sentinelai.studio condition.
const noSqlmap = buildCoverage({ ...FULL, sqlmap: false })
check('missing sqlmap -> injection gap', noSqlmap.gaps.includes('injection'), true)
check('missing sqlmap -> critical gap', noSqlmap.criticalGaps.includes('injection'), true)
check('missing sqlmap -> degraded', noSqlmap.degraded, true)
check('missing sqlmap -> headline suppressed', noSqlmap.summary.includes('INCOMPLETE ASSESSMENT'), true)
check('missing sqlmap -> says NOT TESTED', noSqlmap.summary.includes('NOT TESTED'), true)
check('missing sqlmap -> names the tool', noSqlmap.summary.includes('sqlmap'), true)
check('missing sqlmap -> xss still covered', noSqlmap.gaps.includes('xss'), false)

const noXss = buildCoverage({ ...FULL, dalfox: false })
check('missing dalfox -> xss critical gap', noXss.criticalGaps.includes('xss'), true)
check('missing dalfox -> degraded', noXss.degraded, true)

// A cosmetic-only gap narrows the report but does not invalidate it.
const noTls = buildCoverage({ ...FULL, sslscan: false })
check('missing sslscan -> tls gap', noTls.gaps.includes('tls'), true)
check('missing sslscan -> not critical', noTls.criticalGaps.length, 0)
check('missing sslscan -> not degraded', noTls.degraded, false)
check('missing sslscan -> reduced, not incomplete', noTls.summary.includes('Reduced coverage'), true)

// Explicit module selection narrows scope: a class whose tool was never
// requested is out of scope, not a gap.
const scoped = buildCoverage({ ...FULL, sqlmap: false }, { modules: ['nuclei', 'httpx'] })
check('explicit modules exclude injection from gaps', scoped.gaps.includes('injection'), false)
check('explicit modules keep nuclei in scope', scoped.covered.includes('cve'), true)
check('explicit modules hold arjun out of scope', scoped.gaps.includes('parameter_discovery'), false)

// An empty module list means "full toolchain", i.e. nothing is excused.
const emptyModules = buildCoverage({ ...FULL, sqlmap: false }, { modules: [] })
check('empty module list still flags injection', emptyModules.gaps.includes('injection'), true)

// Availability maps arrive in several shapes from the native runner.
check('array input is accepted', buildCoverage(['nuclei', 'httpx']).covered.includes('fingerprinting'), true)
check('truthy string is accepted', buildCoverage({ httpx: 'true' }).covered.includes('fingerprinting'), true)
check('false-y values are not available', buildCoverage({ httpx: false, whatweb: 0 }).covered.includes('fingerprinting'), false)
check('never-ran toolchain is passive only', buildCoverage({}).passiveOnly, true)
check('never-ran toolchain is degraded', buildCoverage({}).degraded, true)

checkDeep('missing list enumerates absent tools', buildCoverage({ a: false, b: true }).missing, ['a'])

// ---------------------------------------------------------------------------
console.log('\nCoverage rehydration')
// ---------------------------------------------------------------------------

const stored = { untestedClasses: [{ id: 'injection' }], gaps: ['injection'], degraded: true, criticalGaps: ['injection'] }
check('descriptor round-trips', rehydrateCoverage(stored) === stored, true)
check('descriptor round-trips from a string', rehydrateCoverage(JSON.stringify(stored)).degraded, true)

// Legacy rows stored a bare `{ tool: boolean }` map.
const legacy = rehydrateCoverage({ tools: { sqlmap: false, nuclei: true, httpx: true, whatweb: true } })
check('legacy bool map is rebuilt', legacy.degraded, true)
check('legacy bool map names the gap', legacy.gaps.includes('injection'), true)

check('garbage yields the fallback', rehydrateCoverage('not json', { sentinel: 1 }).sentinel, 1)
check('null yields the fallback', rehydrateCoverage(null, { sentinel: 2 }).sentinel, 2)
check('unrecognised shape yields the fallback', rehydrateCoverage({ subdomains: [], urls: [] }, null), null)

// The blob written by the pipeline carries `{ tools, subdomains, urls }`; an
// empty tools map must not be mistaken for a full toolchain.
const pipelineBlob = rehydrateCoverage({ tools: {}, subdomains: [], urls: [], totalUrls: 0 }, null)
check('empty pipeline blob yields fallback', pipelineBlob, null)

// ---------------------------------------------------------------------------
console.log('\nCoverage extraction from a scan row')
// ---------------------------------------------------------------------------

const covDescriptor = buildCoverage({ sqlmap: false, nuclei: true, httpx: true, whatweb: true })
check('coverageFromMeta reads blob.coverage', coverageFromMeta(JSON.stringify({ tools: [], coverage: covDescriptor })).degraded, true)
check('coverageFromMeta tolerates a pre-feature row', coverageFromMeta(JSON.stringify({ tools: [], subdomains: [] })), null)
check('coverageFromMeta tolerates null', coverageFromMeta(null), null)
check('coverageFromMeta tolerates a corrupt blob', coverageFromMeta('{ not json'), null)
const doubleEncoded = coverageFromMeta(JSON.stringify({ coverage: JSON.stringify(covDescriptor) }))
check('coverageFromMeta survives a double-encoded blob', doubleEncoded.criticalGaps.includes('injection'), true)
check('coverageFromMeta double-encoded blob stays degraded', doubleEncoded.degraded, true)

// ---------------------------------------------------------------------------
console.log('\nCoverage view for the report header')
// ---------------------------------------------------------------------------

const view = coverageView(JSON.stringify({ coverage: covDescriptor }))
check('view reports degradation', view.degraded, true)
check('view enumerates critical gaps', view.criticalGaps.includes('injection'), true)
check('view names the absent tool', view.missingTools.includes('sqlmap'), true)
check('view carries a summary string', typeof view.summary === 'string' && view.summary.includes('NOT TESTED'), true)

const emptyView = coverageView(null)
check('view on a pre-feature scan is not degraded', emptyView.degraded, false)
check('view on a pre-feature scan has no summary', emptyView.summary, null)
check('view on a pre-feature scan has no gaps', emptyView.gaps.length, 0)

const fullView = coverageView(JSON.stringify({ coverage: buildCoverage(Object.fromEntries(COVERAGE_CLASSES.flatMap((c) => c.anyOf.map((t) => [t, true]))) ) }))
check('full toolchain view is not degraded', fullView.degraded, false)
check('full toolchain view names no gaps', fullView.gaps.length, 0)

// ---------------------------------------------------------------------------
console.log('\nCover-page posture precedence')
// ---------------------------------------------------------------------------
// A degraded scan must never publish a reassuring headline, even when the
// findings it did collect are all low severity. This is the exact defect the
// abuse report exhibited: ELEVATED RISK while injection and XSS were untested.

const degradedCoverage = coverageView(JSON.stringify({ coverage: covDescriptor }))
const healthyButDegraded = resolvePosture({ todayCount: 0, weekCount: 0, laterCount: 0, vulnerabilityCount: 0, coverage: degradedCoverage })
check('degraded scan overrides a clean result', healthyButDegraded.key, 'incomplete')
check('degraded scan headline is not healthy', /INCOMPLETE/.test(healthyButDegraded.title), true)
check('degraded scan headline never claims health', /HEALTHY/.test(healthyButDegraded.title), false)
check('degraded scan description explains the gap', /not evidence of absence/.test(healthyButDegraded.description), true)

const degradedWithCritical = resolvePosture({ todayCount: 3, weekCount: 2, laterCount: 1, vulnerabilityCount: 9, coverage: degradedCoverage })
check('degraded scan outranks even a critical finding', degradedWithCritical.key, 'incomplete')

const healthyScan = resolvePosture({ coverage: coverageView(null) })
check('pre-feature scan falls through to healthy', healthyScan.key, 'healthy')

// The healthy branch reads SEV_COLORS.success, which did not exist: a scan with
// zero actionable findings crashed the renderer on `postureColor.light`.
check('healthy posture has a defined colour', Boolean(healthyScan.color), true)
check('healthy posture colour has a light fill', typeof healthyScan.color.light, 'string')
check('healthy posture colour has a border', typeof healthyScan.color.border, 'string')
check('incomplete posture colour is distinct from critical', resolvePosture({ coverage: degradedCoverage }).color.bg !== resolvePosture({ todayCount: 1 }).color.bg, true)

check('posture cascade still escalates on today', resolvePosture({ todayCount: 1 }).key, 'critical')
check('posture cascade still escalates on this week', resolvePosture({ weekCount: 1 }).key, 'high')
check('posture cascade still escalates on medium', resolvePosture({ laterCount: 1 }).key, 'medium')
check('posture cascade still reports low-grade exposure', resolvePosture({ vulnerabilityCount: 1 }).key, 'low')

// ---------------------------------------------------------------------------
console.log('\nResults')
// ---------------------------------------------------------------------------
const total = pass + failures.length
for (const f of failures) {
  console.error(`FAIL  ${f.label}\n        got=${f.got}\n        want=${f.want}`)
}
console.log(`\ntool-coverage: ${pass}/${total} passed`)
if (failures.length) process.exit(1)
