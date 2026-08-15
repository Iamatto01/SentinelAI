import { llm } from './llm-client.js'

/**
 * AI Feedback Loop — Dynamic self-correction for SentinelAI findings.
 *
 * After the AI engine produces a finding or PoC, this module reviews the output
 * for common errors (hallucinated CVEs, wrong severity, missing evidence, etc.)
 * and optionally re-prompts the LLM to fix them.
 *
 * Also maintains an in-memory review history and adjustments log for API access.
 */

// In-memory stores (reset on restart — acceptable for FYP scope)
const reviewHistory = new Map()   // scanId → [{ reviewLog, corrected, timestamp }]
const adjustments = []            // [{ agent, field, oldValue, newValue, reason, timestamp }]

/**
 * Deterministic error checks on a finding object.
 * Returns an array of { field, issue } entries.
 */
function detectErrors(finding, targetType) {
  const errors = []

  // 1. Hallucinated / malformed CVE IDs
  if (finding.cveId && !/^CVE-\d{4}-\d{4,}$/i.test(finding.cveId)) {
    errors.push({ field: 'cveId', issue: `Malformed CVE ID "${finding.cveId}"` })
  }

  // 2. Severity / CVSS mismatch
  const severityCvssBands = {
    critical: [9.0, 10.0],
    high: [7.0, 8.9],
    medium: [4.0, 6.9],
    low: [0.1, 3.9],
    info: [0, 0],
  }
  const band = severityCvssBands[finding.severity]
  if (band && typeof finding.cvss === 'number' && finding.cvss > 0) {
    if (finding.cvss < band[0] || finding.cvss > band[1]) {
      errors.push({ field: 'cvss', issue: `CVSS ${finding.cvss} does not match severity "${finding.severity}" (expected ${band[0]}–${band[1]})` })
    }
  }

  // 3. Empty / placeholder description
  if (!finding.description || finding.description.length < 15) {
    errors.push({ field: 'description', issue: 'Description is missing or too short' })
  }

  // 4. Missing remediation for non-info findings
  if (finding.severity !== 'info' && (!finding.remediation || finding.remediation.length < 10)) {
    errors.push({ field: 'remediation', issue: 'Remediation advice is missing for a non-info finding' })
  }

  // 5. Code-type findings without code evidence
  if (targetType === 'code' && (!finding.evidence?.code || finding.evidence.code.length < 5)) {
    errors.push({ field: 'evidence.code', issue: 'Whitebox finding lacks code snippet evidence' })
  }

  return errors
}

/**
 * selfCorrect — Review a finding for errors; if errors are found AND an LLM
 * is available, re-prompt the AI to fix them. Otherwise just log the issues.
 *
 * @param {Object} finding - The finding to review
 * @param {string} targetType - 'url' | 'code'
 * @param {Function} logFn - (scanId, level, message)
 * @param {string} scanId
 * @returns {{ corrected: boolean, finding: Object, reviewLog: Object }}
 */
async function selfCorrect(finding, targetType, logFn, scanId) {
  const errors = detectErrors(finding, targetType)
  const reviewLog = {
    timestamp: new Date().toISOString(),
    findingTitle: finding.title,
    errors_found: errors.length,
    errors,
    corrected: false,
  }

  if (errors.length === 0) {
    return { corrected: false, finding, reviewLog }
  }

  // Try LLM-based correction if provider is available
  if (llm.isConfigured()) {
    try {
      const errorSummary = errors.map(e => `- ${e.field}: ${e.issue}`).join('\n')
      const prompt = `You previously generated this security finding but it has errors. Fix ONLY the listed errors and return the corrected finding as JSON.

FINDING:
${JSON.stringify(finding, null, 2)}

ERRORS TO FIX:
${errorSummary}

Return ONLY a JSON object with the corrected fields. Keep all other fields unchanged.`

      const resp = await llm.chat([
        { role: 'system', content: 'You are a precision security finding corrector. Fix only the stated errors. Respond with valid JSON only.' },
        { role: 'user', content: prompt },
      ], { temperature: 0.1, max_tokens: 1500 })

      try {
        const corrected = JSON.parse(resp.replace(/```json?\n?|```/g, '').trim())
        const merged = { ...finding, ...corrected }
        reviewLog.corrected = true

        // Log adjustments
        for (const err of errors) {
          const oldVal = finding[err.field]
          const newVal = corrected[err.field]
          if (newVal !== undefined && newVal !== oldVal) {
            adjustments.push({
              agent: 'feedback-loop',
              field: err.field,
              oldValue: oldVal,
              newValue: newVal,
              reason: err.issue,
              timestamp: new Date().toISOString(),
            })
          }
        }

        return { corrected: true, finding: merged, reviewLog }
      } catch {
        // LLM returned invalid JSON — fall through to deterministic fixes
      }
    } catch {
      // LLM call failed — fall through
    }
  }

  // Deterministic fallback fixes (no LLM needed)
  let corrected = false
  const fixed = { ...finding }

  for (const err of errors) {
    if (err.field === 'cveId') {
      fixed.cveId = null // Remove malformed CVE
      corrected = true
    }
    if (err.field === 'cvss') {
      // Snap CVSS to the middle of the correct band
      const band = { critical: 9.5, high: 7.5, medium: 5.5, low: 3.0, info: 0 }
      fixed.cvss = band[finding.severity] ?? finding.cvss
      corrected = true
    }
  }

  reviewLog.corrected = corrected
  return { corrected, finding: fixed, reviewLog }
}

/**
 * logReview — Store a review result for a scan's audit trail.
 */
function logReview(scanId, agentName, reviewLog, corrected) {
  if (!reviewHistory.has(scanId)) reviewHistory.set(scanId, [])
  reviewHistory.get(scanId).push({
    ...reviewLog,
    agent: agentName || 'feedback-loop',
    corrected: corrected || false,
    timestamp: new Date().toISOString(),
  })
}

/**
 * getScanReviewHistory — Return all review entries for a given scan.
 */
function getScanReviewHistory(scanId) {
  return reviewHistory.get(scanId) || []
}

/**
 * getAdjustments — Return adjustments, optionally filtered by agent.
 */
function getAdjustments(agentFilter = null) {
  if (agentFilter) return adjustments.filter(a => a.agent === agentFilter)
  return [...adjustments]
}

export const aiFeedbackLoop = {
  selfCorrect,
  logReview,
  getScanReviewHistory,
  getAdjustments,
  detectErrors,
}
