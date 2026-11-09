import assert from 'node:assert/strict'
import { buildCvss4Vector, calculateCvss4, parseCvss4Vector, severityFromCvss4Score } from './cvss4.js'

const rce = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
const xss = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N'

assert.equal(calculateCvss4(rce).score, 10)
assert.equal(calculateCvss4(rce).severity, 'critical')
assert.equal(calculateCvss4(xss).score, 5.3)
assert.deepEqual(parseCvss4Vector(rce), {
  AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
  VC: 'H', VI: 'H', VA: 'H', SC: 'H', SI: 'H', SA: 'H',
})
assert.equal(buildCvss4Vector(parseCvss4Vector(rce)), rce)
assert.equal(severityFromCvss4Score(7), 'high')
assert.equal(severityFromCvss4Score(0), 'info')

console.log('cvss4 tests: all pass')
