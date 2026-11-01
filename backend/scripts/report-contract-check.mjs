/**
 * Self-check for the report output contract.
 *
 * Run: node scripts/report-contract-check.mjs
 *
 * These cases encode the defects that were actually observed in rendered
 * reports, so a regression fails here instead of shipping to a stakeholder.
 */
import assert from 'node:assert/strict'
import {
  VERIFY_STATUS,
  extractArtifact,
  classifyFinding,
  aggregateFindings,
} from '../src/report-contract.js'

const { CONFIRMED, UNVERIFIED, REJECTED } = VERIFY_STATUS

// Mirror of the shape left by JSON.parse over the findings table.
const mk = (over = {}) => ({
  title: 'Some Finding',
  severity: 'medium',
  module: 'web',
  ...over,
})

const S = (f) => classifyFinding(f).verifyStatus
const agg = (arr) => aggregateFindings(arr.map(classifyFinding))

const results = []
const test = (name, fn) => {
  try {
    fn()
    results.push({ name, ok: true })
  } catch (e) {
    results.push({ name, ok: false, err: e.message.split('\n')[0] })
  }
}

/* ------------------------------------------------------------------ */
/* The canonical defect: a model verdict is not an artifact            */
/* ------------------------------------------------------------------ */

test('model verdict alone does not confirm a finding', () => {
  // "Admin panel discovered: /cpanel" — the exact finding that shipped as
  // MEDIUM/Open while its own verdict said no artifact settled the claim.
  const f = mk({
    title: 'Admin panel discovered: /cpanel',
    severity: 'medium',
    evidence: { url: 'https://t/cpanel' },
    aiVerification: true,
    aiConfidence: 0.3,
    aiEvidenceTier: 'inferred',
    aiReasoning: 'No artifact in the finding evidence settles this claim',
  })
  assert.equal(S(f), UNVERIFIED)
})

test('a captured HTTP response does confirm a finding', () => {
  const f = mk({
    evidence: { url: 'https://t/api/invoices/1042', status: 200, body: '{"id":1042}' },
  })
  assert.equal(S(f), CONFIRMED)
})

test('a strong validation tier confirms even with no captured body', () => {
  assert.equal(S(mk({ aiVerification: true, aiEvidenceTier: 'exploited' })), CONFIRMED)
  assert.equal(S(mk({ aiVerification: true, aiEvidenceTier: 'validated' })), CONFIRMED)
})

test('a registry playbook match is not target evidence', () => {
  const f = mk({
    evidence: { url: 'https://t/x', exploitPlaybooks: [{ id: 'p1', name: 'XSS' }] },
    aiVerification: true,
    aiConfidence: 0.9,
  })
  assert.equal(S(f), UNVERIFIED)
  assert.equal(classifyFinding(f).evidenceGrade, 'playbook-only')
})

test('a bare url proves only where we looked', () => {
  const f = mk({ title: 'Missing Security Header: HSTS', evidence: { url: 'https://t/' } })
  assert.equal(S(f), UNVERIFIED)
  assert.deepEqual(classifyFinding(f).evidenceFields, [])
})

test('a boolean/object/blank value is not an artifact', () => {
  assert.notEqual(S(mk({ evidence: { verified: true } })), CONFIRMED)
  assert.notEqual(S(mk({ evidence: { response: {} } })), CONFIRMED)
  assert.notEqual(S(mk({ evidence: { body: '   ' } })), CONFIRMED)
})

test('a model flag nested inside evidence is not an artifact', () => {
  // Side door for the /cpanel defect: verdict smuggled into the evidence blob.
  const f = mk({ evidence: { url: 'https://t/cpanel', aiVerification: true, evidenceTier: 'inferred' } })
  assert.equal(S(f), UNVERIFIED)
})

test('malformed evidence does not throw', () => {
  assert.equal(S(mk({ evidence: 'raw string from an old scan' })), UNVERIFIED)
  assert.equal(S(mk({ evidence: null })), UNVERIFIED)
})

/* ------------------------------------------------------------------ */
/* Rejection semantics                                                 */
/* ------------------------------------------------------------------ */

test('confident rejection is excluded from remediation', () => {
  assert.equal(S(mk({ aiVerification: false, aiConfidence: 0.88 })), REJECTED)
})

test('unconfident rejection stays visible as a lead', () => {
  assert.equal(S(mk({ aiVerification: false, aiConfidence: 0.2 })), UNVERIFIED)
})

test('rejection threshold means the same on a 0-100 confidence scale', () => {
  // Raw agent verdicts store percent; the view layer stores a fraction. Both
  // must land on the same side of the 0.6 bar.
  assert.equal(S(mk({ aiVerification: false, aiConfidence: 88 })), REJECTED)
  assert.equal(S(mk({ aiVerification: false, aiConfidence: 20 })), UNVERIFIED)
})

/* ------------------------------------------------------------------ */
/* Aggregation                                                         */
/* ------------------------------------------------------------------ */

test('repeated warnings collapse into one counted entry', () => {
  const rows = []
  for (let i = 0; i < 40; i++) {
    rows.push(mk({
      title: `Missing Security Header: HSTS`,
      severity: 'low',
      evidence: { url: `https://t/page${i}` },
    }))
  }
  const out = agg(rows)
  assert.equal(out.length, 1)
  assert.equal(out[0].occurrences, 40)
})

test('bare-path suffixes normalise into one group', () => {
  const out = agg([
    mk({ title: 'Missing Header on /admin' }),
    mk({ title: 'Missing Header on /login' }),
  ])
  assert.equal(out.length, 1)
  assert.equal(out[0].occurrences, 2)
})

test('severity is not part of the grouping key and promotes upward', () => {
  const out = agg([
    mk({ title: 'Same Thing', severity: 'low' }),
    mk({ title: 'Same Thing', severity: 'high' }),
  ])
  assert.equal(out.length, 1)
  assert.equal(out[0].severity, 'high')
})

test('a confirmed member makes the group confirmed', () => {
  const out = agg([
    mk({ title: 'Same Thing', evidence: { url: '/a' } }),
    mk({ title: 'Same Thing', evidence: { url: '/b', status: 200, body: 'ok' } }),
  ])
  assert.equal(out.length, 1)
  assert.equal(out[0].verifyStatus, CONFIRMED)
})

test('a confirmed group renders the witness artifact, not an empty box', () => {
  // Regression: the group inherited `evidence` from the best-scoring member
  // while `evidenceFields` still described the first member, so the report
  // printed "Confirmed" above "No tool output was captured".
  const out = agg([
    mk({ title: 'Same Thing', evidence: { url: '/a' }, aiVerification: true, aiEvidenceTier: 'inferred' }),
    mk({ title: 'Same Thing', evidence: { url: '/b', status: 200, body: 'ok' } }),
  ])
  assert.equal(out.length, 1)
  assert.equal(out[0].verifyStatus, CONFIRMED)
  assert.ok(out[0].evidenceFields.length > 0, 'confirmed group must name the artifact it rests on')
  assert.equal(out[0].evidence.body, 'ok')
})

test('a group is rejected only when nothing in it survived', () => {
  const out = agg([
    mk({ title: 'Same Thing', aiVerification: false, aiConfidence: 0.9 }),
    mk({ title: 'Same Thing', aiVerification: false, aiConfidence: 0.9 }),
  ])
  assert.equal(out[0].verifyStatus, REJECTED)

  const mixed = agg([
    mk({ title: 'Other Thing', aiVerification: false, aiConfidence: 0.9 }),
    mk({ title: 'Other Thing' }),
  ])
  assert.equal(mixed[0].verifyStatus, UNVERIFIED)
})

/* ------------------------------------------------------------------ */
/* Artifact extraction details                                         */
/* ------------------------------------------------------------------ */

test('template PoC is not treated as an artifact hint', () => {
  const a = extractArtifact({ evidence: {}, poc: { pocPayload: 'x', pocSource: 'template' } })
  assert.equal(a.hasArtifact, false)
  assert.equal(a.hint, null)
})

test('a real PoC source is reported as a hint', () => {
  const a = extractArtifact({ evidence: {}, poc: { pocSource: 'ai-generated' } })
  assert.equal(a.hint, 'ai-generated')
})

/* ------------------------------------------------------------------ */

let failed = 0
for (const r of results) {
  if (r.ok) console.log(`  PASS  ${r.name}`)
  else {
    failed++
    console.log(`  FAIL  ${r.name}  (${r.err})`)
  }
}
console.log(`\n${results.length - failed}/${results.length} contract cases passed`)
process.exit(failed === 0 ? 0 : 1)
