import cvssCalculator from 'ae-cvss-calculator'

const { fromVector } = cvssCalculator

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

function validScore(value) {
  if (value == null || value === '') return null
  const score = Number(value)
  return Number.isFinite(score) && score >= 0 && score <= 10 ? score : null
}

function severityForScore(score, version) {
  if (score === 0) return 'info'
  if (version === 'CVSS:2.0') {
    if (score >= 7) return 'high'
    if (score >= 4) return 'medium'
    return 'low'
  }
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

export function calculateCvssVector(vector) {
  const parsed = fromVector(String(vector || '').trim())
  if (!parsed) throw new Error('Unsupported or invalid CVSS vector')

  const scores = parsed.calculateScores()
  const version = parsed.getVectorName()
  const score = validScore(scores.overall ?? scores.base)
  const baseScore = validScore(scores.baseMetricsOnly ?? scores.base ?? scores.overall)
  if (score == null || baseScore == null) {
    throw new Error(`CVSS calculator returned no valid score for ${version}`)
  }

  const roundedScore = Math.round(score * 10) / 10
  const roundedBaseScore = Math.round(baseScore * 10) / 10
  return {
    status: 'calculated',
    source: 'vector',
    version,
    vector: scores.vector || String(vector).trim(),
    score: roundedScore,
    baseScore: roundedBaseScore,
    scoreType: roundedScore === roundedBaseScore ? 'base' : 'adjusted',
    severity: severityForScore(score, version),
  }
}

export function getCvssAssessment(finding) {
  const evidence = finding?.evidence || {}
  const vector =
    finding?.cvssVector ||
    finding?.cvss_vector ||
    finding?.cvss?.vector ||
    evidence.cvssVector ||
    evidence.cvss_vector ||
    evidence.cvss?.vector ||
    evidence.cvssAssessment?.vector

  if (vector) {
    try {
      return calculateCvssVector(vector)
    } catch (error) {
      return {
        status: 'invalid-vector',
        source: 'vector',
        version: String(vector).match(/^CVSS:\d+\.\d+/i)?.[0]?.toUpperCase() || null,
        vector: String(vector),
        score: null,
        baseScore: null,
        severity: null,
        error: error.message,
      }
    }
  }

  const score = validScore(finding?.cvss?.score ?? finding?.cvss)
  if (score != null) {
    return {
      status: 'reported-without-vector',
      source: finding?.cvss?.source || 'scanner-or-legacy',
      version: finding?.cvss?.version || finding?.cvssVersion || evidence.cvssVersion || null,
      vector: null,
      score,
      baseScore: null,
      severity: null,
    }
  }

  return {
    status: 'not-scored',
    source: null,
    version: null,
    vector: null,
    score: null,
    baseScore: null,
    severity: null,
  }
}

export function applyCvssAssessment(finding) {
  const assessment = getCvssAssessment(finding)
  const evidence = { ...(finding.evidence || {}), cvssAssessment: assessment }
  const updated = { ...finding, evidence }

  if (assessment.status === 'calculated') {
    updated.cvss = assessment.score
    updated.cvssVersion = assessment.version
    updated.cvssVector = assessment.vector
    updated.severity = assessment.severity
  } else if (assessment.status === 'reported-without-vector') {
    updated.cvss = assessment.score
    updated.cvssVersion = assessment.version
  } else if (assessment.status === 'invalid-vector' || assessment.status === 'not-scored') {
    updated.cvss = null
  }

  return updated
}

export function assessUrgency(finding) {
  const evidence = finding?.evidence || {}
  const assessment = getCvssAssessment(finding)
  const severity = assessment.status === 'calculated'
    ? assessment.severity
    : String(finding?.severity || 'info').toLowerCase()
  const needsValidation =
    evidence.aiEvidenceTier === 'needs-validation' ||
    evidence.validationTier === 'needs-validation'
  const knownExploited =
    evidence.knownExploited === true ||
    evidence.cisaKev === true ||
    evidence.activeExploitation === true ||
    evidence.exploited === true

  let key
  let sla
  let basis
  if (knownExploited) {
    key = 'immediate'
    sla = 'Within 24 hours'
    basis = 'Explicit known-exploitation evidence'
  } else if (severity === 'critical') {
    key = 'immediate'
    sla = 'Within 24 hours'
    basis = assessment.status === 'calculated'
      ? 'CVSS severity band: Critical'
      : 'Source-reported severity: Critical; no verifiable CVSS vector'
  } else if (severity === 'high') {
    key = 'this-week'
    sla = 'Within 7 days'
    basis = assessment.status === 'calculated'
      ? 'CVSS severity band: High'
      : 'Source-reported severity: High; no verifiable CVSS vector'
  } else if (severity === 'medium') {
    key = 'this-month'
    sla = 'Within 30 days'
    basis = assessment.status === 'calculated'
      ? 'CVSS severity band: Medium'
      : 'Source-reported severity: Medium; no verifiable CVSS vector'
  } else if (severity === 'low') {
    key = 'planned'
    sla = 'Next planned maintenance release'
    basis = assessment.status === 'calculated'
      ? 'CVSS severity band: Low'
      : 'Source-reported severity: Low; no verifiable CVSS vector'
  } else {
    key = 'informational'
    sla = 'No remediation SLA'
    basis = 'Informational severity'
  }

  return {
    key,
    sla,
    basis,
    action: needsValidation ? 'Validate' : 'Remediate',
    label: needsValidation ? `Validate ${key === 'immediate' ? 'today' : key === 'this-week' ? 'this week' : key === 'this-month' ? 'this month' : 'when scheduled'}` : key,
    severity,
    needsValidation,
    knownExploited,
  }
}

export function countByUrgency(findings) {
  const counts = {
    immediate: 0,
    'this-week': 0,
    'this-month': 0,
    planned: 0,
    informational: 0,
  }
  for (const finding of findings) {
    const key = assessUrgency(finding).key
    counts[key] = (counts[key] || 0) + 1
  }
  return counts
}

export function compareUrgency(a, b) {
  const rank = { immediate: 0, 'this-week': 1, 'this-month': 2, planned: 3, informational: 4 }
  return (rank[assessUrgency(a).key] ?? 4) - (rank[assessUrgency(b).key] ?? 4) ||
    (SEVERITY_RANK[String(b.severity || 'info').toLowerCase()] || 0) -
    (SEVERITY_RANK[String(a.severity || 'info').toLowerCase()] || 0)
}
