import { GroqAI } from './groq-client.js'
import { db } from '../data.js'

/**
 * Voice Summary Generator — produces client-friendly plain-text summaries
 * optimised for being read aloud via Text-to-Speech.
 *
 * Uses the existing Groq AI client for generation.
 */

const groq = new GroqAI()

/**
 * Generate a spoken-friendly summary for a single vulnerability.
 * @param {object} vulnerability
 * @returns {Promise<string>}
 */
export async function generateVulnSummary(vulnerability) {
  const prompt = `You are a professional cybersecurity consultant presenting findings to a non-technical client.

Generate a clear, spoken-friendly summary of this vulnerability that could be read aloud during a client meeting. 

Rules:
- Use plain, natural language (no markdown, no bullet symbols, no tables)
- Start with the severity and title
- Explain the business impact in simple terms
- End with a clear remediation recommendation
- Keep it under 120 words
- Use complete sentences suitable for speech

Vulnerability data:
Title: ${vulnerability.title || 'Unknown'}
Severity: ${vulnerability.severity || 'Unknown'}
CVSS Score: ${vulnerability.cvss ?? 'N/A'}
CWE: ${vulnerability.cweId || 'N/A'}
Status: ${vulnerability.status || 'open'}
Affected Asset: ${vulnerability.asset || 'Unknown'}
Description: ${vulnerability.description || 'No description available'}
Remediation: ${vulnerability.remediation || 'Not specified'}
Module: ${vulnerability.module || 'Unknown'}
${vulnerability.aiAnalysis ? `AI Risk Score: ${vulnerability.aiAnalysis.riskScore}/10` : ''}`

  try {
    const summary = await groq.analyze(prompt, {
      temperature: 0.3,
      maxTokens: 300,
      context: { operation: 'voice_vuln_summary' },
    })
    return summary.trim()
  } catch (error) {
    console.error('[VoiceSummary] Vulnerability summary failed:', error.message)
    return `${vulnerability.severity || 'Unknown severity'} vulnerability found: ${vulnerability.title || 'Unknown'}. ${vulnerability.description || 'Please review the detailed report for more information.'}. Recommended action: ${vulnerability.remediation || 'Consult with the security team for remediation steps.'}`
  }
}

/**
 * Generate an executive summary for an entire project — suitable for
 * reading aloud to a client.
 * @param {string} projectId
 * @returns {Promise<string>}
 */
export async function generateProjectSummary(projectId) {
  const project = db.projects.find((p) => p.id === projectId)
  if (!project) throw new Error('Project not found')

  // Gather vulnerabilities across all scans for this project
  const scans = db.scans.filter((s) => s.projectId === projectId)
  const allVulns = []
  for (const scan of scans) {
    const vulns = db.vulnerabilitiesByScanId.get(scan.id) || []
    allVulns.push(...vulns)
  }

  const counts = {
    total: allVulns.length,
    critical: allVulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length,
    high: allVulns.filter((v) => (v.severity || '').toLowerCase() === 'high').length,
    medium: allVulns.filter((v) => (v.severity || '').toLowerCase() === 'medium').length,
    low: allVulns.filter((v) => (v.severity || '').toLowerCase() === 'low').length,
    open: allVulns.filter((v) => (v.status || 'open') === 'open').length,
  }

  const prompt = `You are a professional cybersecurity consultant presenting an executive summary to a non-technical client.

Generate a spoken-friendly executive summary for a penetration testing engagement.

Rules:
- Use plain, natural language (no markdown, no bullet symbols, no tables)
- Start with a brief overview of the engagement
- Summarise the findings by severity
- Highlight critical items that need immediate attention
- End with a high-level recommendation
- Keep it under 200 words
- Use complete sentences suitable for speech
- Sound professional and reassuring

Project: ${project.name || 'Security Assessment'}
Client: ${project.client || 'Client'}
Scope: ${project.scope || 'Not specified'}
Total Scans Completed: ${scans.length}
Total Vulnerabilities: ${counts.total}
  - Critical: ${counts.critical}
  - High: ${counts.high}
  - Medium: ${counts.medium}
  - Low: ${counts.low}
Open Issues: ${counts.open}

${counts.critical > 0 ? `Critical vulnerabilities found: ${allVulns.filter(v => (v.severity || '').toLowerCase() === 'critical').map(v => v.title).join(', ')}` : 'No critical vulnerabilities found.'}
${counts.high > 0 ? `High severity items: ${allVulns.filter(v => (v.severity || '').toLowerCase() === 'high').map(v => v.title).join(', ')}` : ''}`

  try {
    const summary = await groq.analyze(prompt, {
      temperature: 0.3,
      maxTokens: 500,
      context: { operation: 'voice_project_summary', projectId },
    })
    return summary.trim()
  } catch (error) {
    console.error('[VoiceSummary] Project summary failed:', error.message)

    // Fallback: generate a basic summary without AI
    let fallback = `Executive summary for ${project.name || 'the security assessment'}. `
    fallback += `We completed ${scans.length} scan${scans.length !== 1 ? 's' : ''} and identified ${counts.total} total vulnerabilit${counts.total !== 1 ? 'ies' : 'y'}. `
    if (counts.critical > 0) fallback += `There are ${counts.critical} critical findings that require immediate attention. `
    if (counts.high > 0) fallback += `${counts.high} high severity issues were also found. `
    fallback += `${counts.open} issue${counts.open !== 1 ? 's remain' : ' remains'} open. `
    fallback += `We recommend addressing all critical and high severity findings as a priority.`
    return fallback
  }
}
