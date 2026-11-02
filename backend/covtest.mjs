import { coversVersion, compareVersions } from './src/cve.js'
import { computeRiskScore, riskRatingFromScore } from './src/pipeline.js'

const cases = [
  // [observed, bound, expected]
  ['1.18', '1.18.0', true],
  ['1.18', '1.18.7', true],
  ['1.18', '1.19.0', false],
  ['1.18.0', '1.18.0', true],
  ['1.18.1', '1.18.0', false],
  ['1.18', '1.17.9', false],
  ['2.0', '2.0.1', true],
  ['1.18', '1.180', false],
  ['nginx/1.18', '1.18.0', false], // non-version noise must not cover
]
let fail = 0
for (const [a, b, want] of cases) {
  const got = coversVersion(a, b)
  if (got !== want) { fail++; console.log(`FAIL coversVersion(${a}, ${b}) = ${got}, want ${want}`) }
}
console.log(`coverage: ${cases.length - fail}/${cases.length} ok`)

// antisymmetry sanity on compareVersions (unchanged behaviour)
const pairs = [['1.18','1.18.0'],['1.18','1.19'],['1.9','1.10'],['2.0','10.0'],['1.18.0-rc1','1.18.0']]
for (const [a,b] of pairs) {
  const x = compareVersions(a,b), y = compareVersions(b,a)
  if (x !== -y && !(x === 0 && y === 0)) { fail++; console.log(`FAIL antisymmetry ${a} vs ${b}: ${x}/${y}`) }
}
console.log(fail === 0 ? 'ALL PASS' : `${fail} FAILURES`)

// ── Risk-score invariants ────────────────────────────────────────────────
// Regression guard for the scoring inversion Jack reported: the headline score
// was built by adding a prevalence "residual" on top of the worst CVSS, so a
// scan whose worst finding was 9.3 was reported as 10.0 — worse than any
// vulnerability actually found. CVSS is per-vulnerability, never additive.
const scoreCases = [
  // [label, counts, maxCvss, expected]
  ['worst 9.3, many findings', { critical: 3, high: 40, medium: 30, low: 17, info: 159 }, 9.3, 9.3],
  ['worst 2.1, medium only', { critical: 0, high: 0, medium: 6, low: 1, info: 0 }, 2.1, 2.1],
  ['two criticals, worst 8.7', { critical: 2, high: 0, medium: 0, low: 0, info: 0 }, 8.7, 8.7],
]
for (const [label, counts, maxCvss, want] of scoreCases) {
  const got = computeRiskScore(counts, maxCvss)
  if (Math.abs(got - want) > 1e-9) { fail++; console.log(`FAIL risk ${label}: ${got}, want ${want}`) }
}
for (const worst of [2.1, 5.3, 6.9, 8.7, 9.3, 9.9]) {
  const got = computeRiskScore({ critical: 9, high: 9, medium: 9, low: 9, info: 9 }, worst)
  if (got > worst + 1e-9) { fail++; console.log(`FAIL risk headline ${got} exceeds its own worst finding ${worst}`) }
}
console.log(fail === 0 ? 'ALL PASS (coverage + risk score)' : `${fail} FAILURES`)
process.exit(fail === 0 ? 0 : 1)
