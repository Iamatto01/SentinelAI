/**
 * Regression tests for the report evidence contract.
 *
 * Run: npm test --prefix backend
 *
 * Dependency-free by design — `report-contract.js` is deliberately free of
 * pdfkit and friends so it can be exercised directly with plain node. Every
 * case below encodes a defect that actually shipped at least once; the comments
 * say which, so a future refactor knows what it is about to undo.
 */
import { findCaptures, classifyFinding, VERIFY_STATUS } from './report-contract.js'

let pass = 0
const failures = []

function check(label, got, want) {
  if (Object.is(got, want)) {
    pass++
    return
  }
  failures.push({ label, got, want })
}

function section(title) {
  console.log(`\n${title}`)
}

// ---------------------------------------------------------------------------
// Capture detection
// ---------------------------------------------------------------------------
section('Capture detection')

// The PoC generator fills pocPayload/pocSource on EVERY templated finding. If
// they count as captures, any finding carrying a template string self-confirms —
// the exact "artifact observed" defect the NON_ARTIFACT list documents.
check(
  'templated pocPayload is not a capture',
  findCaptures({
    evidence: {
      pocPayload: 'java -jar ysoserial.jar CommonsCollections1 "id"',
      pocSource: 'template',
      url: 'https://example.com/api',
    },
  }).length,
  0
)

// What we sent is not what came back.
check(
  'requestBody is not a capture',
  findCaptures({ evidence: { requestBody: '{"a":1}' } }).length,
  0
)
check(
  'requestHeaders is not a capture',
  findCaptures({ evidence: { requestHeaders: { a: 'b' } } }).length,
  0
)

// A field that names itself "evidence"/"proof" is an assertion. Whoever chooses
// the key name must not be able to select the classification.
check(
  'bare evidence label is not a capture',
  findCaptures({ evidence: { evidence: 'some assertion' } }).length,
  0
)
check(
  'bare proof label is not a capture',
  findCaptures({ evidence: { proof: 'trust me' } }).length,
  0
)

// Real target output must always count.
check('response body is a capture', findCaptures({ evidence: { body: '<html>x</html>' } }).join(), 'body')
check('statusCode is a capture', findCaptures({ evidence: { statusCode: 200 } }).join(), 'statusCode')
check('banner is a capture', findCaptures({ evidence: { banner: 'OpenSSH_8.2p1' } }).join(), 'banner')
check('openPorts is a capture', findCaptures({ evidence: { openPorts: [22, 80] } }).join(), 'openPorts')
check('cert is a capture', findCaptures({ evidence: { cert: { cn: 'a.com' } } }).join(), 'cert')

// Emptiness is not a capture. A flag records an assertion, never a response.
check('blank string is not a capture', findCaptures({ evidence: { body: '   ' } }).length, 0)
check('boolean flag is not a capture', findCaptures({ evidence: { present: true } }).length, 0)
check('empty array is not a capture', findCaptures({ evidence: { matches: [] } }).length, 0)
check('empty object is not a capture', findCaptures({ evidence: { headers: {} } }).length, 0)
check('null is not a capture', findCaptures({ evidence: { body: null } }).length, 0)
check('NaN is not a capture', findCaptures({ evidence: { statusCode: NaN } }).length, 0)
check('unknown key is not a capture', findCaptures({ evidence: { somethingElse: 'x' } }).length, 0)
check('missing evidence object is not a capture', findCaptures({}).length, 0)

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
section('Classification')

// BUG (contract): a live capture must survive a `needs-validation` stamp. The
// stamp is prose-derived and was blanket-demoting 707 findings that had in fact
// photographed the target's response.
check(
  'capture survives needs-validation stamp',
  classifyFinding({
    name: 'Exposed .env',
    validationTier: 'needs-validation',
    evidence: { body: 'DB_PASSWORD=hunter2', statusCode: 200 },
  }).verifyStatus,
  VERIFY_STATUS.CONFIRMED
)

// BUG (contract): a model rejection must not delete a finding the scanner saw
// respond. The model read prose; the scanner read the wire.
check(
  'capture survives a confident AI rejection',
  classifyFinding({
    name: 'Exposed .env',
    aiVerification: false,
    aiConfidence: 0.95,
    evidence: { body: 'DB_PASSWORD=hunter2' },
  }).verifyStatus,
  VERIFY_STATUS.CONFIRMED
)

// BUG: template-only findings were reaching the executive summary as verified.
check(
  'template-only finding is not confirmed',
  classifyFinding({
    name: 'Deserialization',
    pocSource: 'template',
    pocPayload: 'ysoserial ...',
    evidence: { pocPayload: 'ysoserial ...', pocSource: 'template' },
  }).verifyStatus !== VERIFY_STATUS.CONFIRMED,
  true
)

// A high-confidence rejection with nothing captured is genuinely dropped.
check(
  'confident rejection without capture is rejected',
  classifyFinding({ name: 'x', aiVerification: false, aiConfidence: 0.9 }).verifyStatus,
  VERIFY_STATUS.REJECTED
)

// A low-confidence rejection stays visible as a lead.
check(
  'unconfident rejection without capture is unverified',
  classifyFinding({ name: 'x', aiVerification: false, aiConfidence: 0.2 }).verifyStatus,
  VERIFY_STATUS.UNVERIFIED
)

// A bare model assertion is not evidence: `aiVerification: true` with nothing
// captured grades model-assertion-only and is demoted back to a lead. This is
// deliberate (see the "A model assertion is not evidence" block) — the model's
// yes/no is a verdict about the claim, not a record of the target responding.
check(
  'bare AI confirmation without capture is not confirmed',
  classifyFinding({ name: 'x', aiVerification: true }).verifyStatus,
  VERIFY_STATUS.UNVERIFIED
)

// The same confirmation, but resting on a live capture, is genuinely confirmed.
check(
  'AI confirmation backed by a capture is confirmed',
  classifyFinding({ name: 'x', aiVerification: true, evidence: { body: 'hit' } }).verifyStatus,
  VERIFY_STATUS.CONFIRMED
)

// Grade should name how the finding earned its status.
check(
  'capture grades as artifact-observed',
  classifyFinding({ name: 'x', evidence: { body: 'hi' } }).evidenceGrade,
  'artifact-observed'
)

// 404 response on exposure/discovery claim refutes the claim
check(
  '404 status refutes admin panel claim',
  classifyFinding({
    title: 'Admin panel discovered: /wp-login.php (HTTP 200)',
    evidence: { status: 404, contentLength: 760 },
  }).verifyStatus,
  VERIFY_STATUS.REJECTED
)

check(
  '404 status does not count as capture for file exposure',
  findCaptures({
    title: 'OS metadata file exposed: /.DS_Store',
    evidence: { status: 404, contentLength: 757 },
  }).length,
  0
)

check(
  '404 status on legitimate error page disclosure is preserved',
  classifyFinding({
    title: 'Detailed stack trace disclosed in custom 404 error page',
    evidence: { status: 404, body: 'org.apache.catalina.core.StandardWrapperValve.invoke' },
  }).verifyStatus,
  VERIFY_STATUS.CONFIRMED
)

// ---------------------------------------------------------------------------
section('Results')
// ---------------------------------------------------------------------------
const total = pass + failures.length
for (const f of failures) {
  console.error(`FAIL  ${f.label}\n        got=${JSON.stringify(f.got)} want=${JSON.stringify(f.want)}`)
}
console.log(`\nreport-contract: ${pass}/${total} passed`)
if (failures.length) process.exit(1)
