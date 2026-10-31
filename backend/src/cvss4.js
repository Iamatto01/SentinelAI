import { calculateBaseScoreV4, humanizeScore } from 'cvss4'

/**
 * CVSS v4.0 Standard Scoring Module (FIRST.org Specification)
 * Standardizes vulnerability scoring, vector calculation, and qualitative rating bands.
 */

export const CVSS4_SEVERITY_BANDS = {
  NONE: { min: 0.0, max: 0.0, label: 'info', name: 'None' },
  LOW: { min: 0.1, max: 3.9, label: 'low', name: 'Low' },
  MEDIUM: { min: 4.0, max: 6.9, label: 'medium', name: 'Medium' },
  HIGH: { min: 7.0, max: 8.9, label: 'high', name: 'High' },
  CRITICAL: { min: 9.0, max: 10.0, label: 'critical', name: 'Critical' },
}

export const CVSS4_TEMPLATES = {
  rce: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', // 10.0 Critical
  sqli: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // 9.3 Critical
  auth_bypass: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', // 8.7 High
  ssrf: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N', // 8.7 High
  priv_esc: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N', // 8.4 High
  xss: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.3 Medium
  csrf: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N', // 5.1 Medium
  info_leak: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', // 5.3 Medium
  missing_header: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N', // 2.1 Low
  recon_info: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', // 0.0 Info
}

export const SEVERITY_TO_VECTOR = {
  critical: CVSS4_TEMPLATES.sqli,
  high: CVSS4_TEMPLATES.auth_bypass,
  medium: CVSS4_TEMPLATES.xss,
  low: CVSS4_TEMPLATES.missing_header,
  info: CVSS4_TEMPLATES.recon_info,
}

/**
 * Convert numerical CVSS v4.0 score to FIRST standard qualitative severity string.
 */
export function severityFromCvss4Score(score) {
  const s = Number(score) || 0
  if (s >= 9.0) return 'critical'
  if (s >= 7.0) return 'high'
  if (s >= 4.0) return 'medium'
  if (s > 0.0) return 'low'
  return 'info'
}

/**
 * Parse a CVSS v4.0 vector string into key-value map.
 */
export function parseCvss4Vector(vectorStr) {
  if (!vectorStr || typeof vectorStr !== 'string') return {}
  const clean = vectorStr.trim()
  const parts = clean.split('/')
  const metrics = {}
  for (const part of parts) {
    if (part.includes(':')) {
      const [k, v] = part.split(':')
      if (k && v && k !== 'CVSS') {
        metrics[k.toUpperCase()] = v.toUpperCase()
      }
    }
  }
  return metrics
}

/**
 * Format a key-value metric map into standard CVSS v4.0 vector string.
 */
export function buildCvss4Vector(metrics = {}) {
  const defaults = {
    AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
    VC: 'H', VI: 'H', VA: 'H',
    SC: 'N', SI: 'N', SA: 'N'
  }
  const m = { ...defaults, ...metrics }
  const order = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']
  const parts = ['CVSS:4.0']
  for (const k of order) {
    if (m[k]) parts.push(`${k}:${m[k]}`)
  }
  if (m.E && m.E !== 'X') parts.push(`E:${m.E}`)
  if (m.CR && m.CR !== 'X') parts.push(`CR:${m.CR}`)
  if (m.IR && m.IR !== 'X') parts.push(`IR:${m.IR}`)
  if (m.AR && m.AR !== 'X') parts.push(`AR:${m.AR}`)
  return parts.join('/')
}

/**
 * Calculate CVSS v4.0 score and qualitative label using FIRST algorithm.
 */
export function calculateCvss4(vectorStr) {
  if (!vectorStr) {
    return { score: 0.0, severity: 'info', rating: 'None', vector: CVSS4_TEMPLATES.recon_info }
  }
  try {
    const rawScore = calculateBaseScoreV4(vectorStr)
    const score = Math.round(rawScore * 10) / 10
    const rating = humanizeScore(score)
    const severity = severityFromCvss4Score(score)
    return { score, severity, rating, vector: vectorStr }
  } catch (err) {
    return { error: err.message, score: 0.0, severity: 'info', rating: 'None', vector: vectorStr }
  }
}

/**
 * Derive a well-aligned CVSS v4.0 vector for a finding from its title, CWE, and category.
 */
export function defaultVectorForFinding(finding = {}) {
  const text = [
    finding.title,
    finding.cweId || finding.cwe_id,
    finding.owaspCategory || finding.owasp_category,
    finding.description,
  ].filter(Boolean).join(' ').toLowerCase()

  if (/rce|remote code execution|command injection|shell upload|cwe-78|cwe-94/i.test(text)) {
    return CVSS4_TEMPLATES.rce
  }
  if (/sql injection|sqli|cwe-89/i.test(text)) {
    return CVSS4_TEMPLATES.sqli
  }
  if (/auth.*bypass|unauthenticated|cwe-287|cwe-306/i.test(text)) {
    return CVSS4_TEMPLATES.auth_bypass
  }
  if (/ssrf|server-side request forgery|cwe-918/i.test(text)) {
    return CVSS4_TEMPLATES.ssrf
  }
  if (/privilege escalation|privesc|cwe-269/i.test(text)) {
    return CVSS4_TEMPLATES.priv_esc
  }
  if (/cross[- ]site scripting|xss|cwe-79/i.test(text)) {
    return CVSS4_TEMPLATES.xss
  }
  if (/csrf|cross[- ]site request forgery|cwe-352/i.test(text)) {
    return CVSS4_TEMPLATES.csrf
  }
  if (/missing.*(security.*header|hsts|csp|x-frame|content-type)|server banner/i.test(text)) {
    return CVSS4_TEMPLATES.missing_header
  }
  if (/open port|subdomain|robots\.txt|recon|discovered/i.test(text)) {
    return CVSS4_TEMPLATES.recon_info
  }

  // Fallback to designated template for stated severity
  const s = (finding.severity || 'info').toLowerCase()
  return SEVERITY_TO_VECTOR[s] || CVSS4_TEMPLATES.recon_info
}
