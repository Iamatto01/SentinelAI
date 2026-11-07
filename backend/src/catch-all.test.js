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
import { UnifiedPipeline } from './pipeline.js'

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
console.log('\nResults')
// ---------------------------------------------------------------------------
const total = pass + failures.length
for (const f of failures) {
  console.error(`FAIL  ${f.label}\n        got=${JSON.stringify(f.got)} want=${JSON.stringify(f.want)}`)
}
console.log(`\ncatch-all: ${pass}/${total} passed`)
if (failures.length) process.exit(1)
