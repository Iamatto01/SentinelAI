import assert from 'node:assert/strict'
import {
  applyCvssAssessment,
  assessUrgency,
  calculateCvssVector,
} from '../src/risk-scoring.js'

const firstBaseVector =
  'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
const baseAssessment = calculateCvssVector(firstBaseVector)
assert.equal(baseAssessment.version, 'CVSS:4.0')
assert.equal(baseAssessment.score, 7.7)
assert.equal(baseAssessment.baseScore, 7.7)
assert.equal(baseAssessment.severity, 'high')
assert.equal(assessUrgency({ severity: baseAssessment.severity, evidence: { cvssAssessment: baseAssessment } }).key, 'this-week')

const firstThreatVector = `${firstBaseVector}/E:U`
const threatAssessment = calculateCvssVector(firstThreatVector)
assert.equal(threatAssessment.baseScore, 7.7)
assert.equal(threatAssessment.score, 5.2)
assert.equal(threatAssessment.scoreType, 'adjusted')
assert.equal(threatAssessment.severity, 'medium')
assert.equal(assessUrgency({ severity: threatAssessment.severity, evidence: { cvssAssessment: threatAssessment } }).key, 'this-month')

const noVector = applyCvssAssessment({ severity: 'medium', evidence: {} })
assert.equal(noVector.cvss, null)
assert.equal(noVector.evidence.cvssAssessment.status, 'not-scored')
assert.equal(assessUrgency(noVector).key, 'this-month')

const needsValidation = assessUrgency({
  severity: 'critical',
  evidence: { validationTier: 'needs-validation' },
})
assert.equal(needsValidation.key, 'immediate')
assert.equal(needsValidation.action, 'Validate')

const exploited = assessUrgency({
  severity: 'low',
  evidence: { cisaKev: true },
})
assert.equal(exploited.key, 'immediate')
assert.equal(exploited.knownExploited, true)

const invalidVector = applyCvssAssessment({
  severity: 'high',
  cvssVector: 'CVSS:4.0/AV:INVALID',
  evidence: {},
})
assert.equal(invalidVector.cvss, null)
assert.equal(invalidVector.severity, 'high')
assert.equal(invalidVector.evidence.cvssAssessment.status, 'invalid-vector')

console.log('CVSS vector scoring and urgency policy tests passed.')
