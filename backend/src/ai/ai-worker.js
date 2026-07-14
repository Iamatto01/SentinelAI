import { GroqAI } from './groq-client.js'

/**
 * AI Worker — Analyzes monitoring check results, detects changes,
 * generates summaries, and classifies severity for the SIEM system.
 */
export class AIWorker {
  constructor() {
    this.groq = new GroqAI()
    this.isActive = false
  }

  async initialize() {
    if (!process.env.GROQ_API_KEY) {
      console.warn('⚠️  GROQ_API_KEY not found — AI Worker disabled.')
      return false
    }
    const ok = await this.groq.testConnection()
    if (ok) {
      this.isActive = true
      console.log('✅ AI Worker initialized')
      return true
    }
    console.error('❌ AI Worker: Groq connection failed')
    return false
  }

  getStatus() {
    return {
      isActive: this.isActive,
      groqConfigured: !!process.env.GROQ_API_KEY,
    }
  }

  /**
   * Analyze scan findings and produce a health assessment + AI summary.
   * @param {object} monitor - The monitor record
   * @param {Array} findings - Array of vulnerability findings from the check
   * @param {Array|null} previousFindings - Findings from the previous check (for diff)
   * @returns {{ healthStatus: string, aiSummary: string, changes: object, alerts: Array }}
   */
  async analyzeCheck(monitor, findings, previousFindings = null) {
    if (!this.isActive) {
      return this._fallbackAnalysis(findings, previousFindings)
    }

    try {
      const prompt = this._buildAnalysisPrompt(monitor, findings, previousFindings)
      const raw = await this.groq.analyze(prompt, {
        maxTokens: 800,
        temperature: 0.15,
        context: { operation: 'monitor_check', projectId: monitor.projectId },
      })

      return this._parseAnalysisResponse(raw, findings, previousFindings)
    } catch (err) {
      console.error('[AIWorker] Analysis failed, using fallback:', err.message)
      return this._fallbackAnalysis(findings, previousFindings)
    }
  }

  /**
   * Generate a periodic report summary for a monitor.
   */
  async generateReportSummary(monitor, events, alerts, period) {
    if (!this.isActive) {
      return `Monitoring report for ${monitor.target} (${period}). Total events: ${events.length}, Alerts: ${alerts.length}.`
    }

    try {
      const prompt = `You are a cybersecurity analyst generating a monitoring report.

Target: ${monitor.target}
Period: ${period}
Total checks: ${events.filter(e => e.type === 'check').length}
Alerts triggered: ${alerts.length}
Current health: ${monitor.healthStatus}

Recent alerts:
${alerts.slice(0, 10).map(a => `- [${a.severity}] ${a.title}`).join('\n') || 'None'}

Recent events:
${events.slice(0, 15).map(e => `- [${e.type}] ${e.title}`).join('\n') || 'None'}

Write a concise executive summary (3-5 sentences) covering:
1. Overall security posture during this period
2. Key findings or concerns
3. Recommended actions

Be direct and professional. No markdown formatting.`

      return await this.groq.analyze(prompt, {
        maxTokens: 400,
        temperature: 0.2,
        context: { operation: 'report_summary', projectId: monitor.projectId },
      })
    } catch (err) {
      console.error('[AIWorker] Report summary failed:', err.message)
      return `Monitoring report for ${monitor.target} (${period}). Total events: ${events.length}, Alerts: ${alerts.length}. AI summary unavailable.`
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  _buildAnalysisPrompt(monitor, findings, previousFindings) {
    const prevTitles = previousFindings ? previousFindings.map(f => f.title) : []
    const currTitles = findings.map(f => f.title)
    const newFindings = findings.filter(f => !prevTitles.includes(f.title))
    const resolvedFindings = previousFindings
      ? previousFindings.filter(f => !currTitles.includes(f.title))
      : []

    return `You are a SIEM security analyst reviewing automated monitoring results.

Target: ${monitor.target}
Check time: ${new Date().toISOString()}
Total findings this check: ${findings.length}
New findings (not in previous check): ${newFindings.length}
Resolved findings (were in previous, now gone): ${resolvedFindings.length}

Current findings:
${findings.slice(0, 20).map(f => `- [${f.severity}] ${f.title}: ${(f.description || '').slice(0, 100)}`).join('\n') || 'None'}

${newFindings.length > 0 ? `NEW findings:\n${newFindings.map(f => `- [${f.severity}] ${f.title}`).join('\n')}` : ''}
${resolvedFindings.length > 0 ? `RESOLVED findings:\n${resolvedFindings.map(f => `- [${f.severity}] ${f.title}`).join('\n')}` : ''}

Respond in this exact JSON format (no markdown, no code fences):
{"healthStatus":"healthy|degraded|critical","summary":"2-3 sentence summary of the current state","alerts":[{"type":"new_vuln|vuln_resolved|config_change","severity":"info|low|medium|high|critical","title":"short alert title"}]}`
  }

  _parseAnalysisResponse(raw, findings, previousFindings) {
    const changes = this._detectChanges(findings, previousFindings)

    try {
      // Clean the response — strip markdown fences if present
      const cleaned = raw.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim()
      const parsed = JSON.parse(cleaned)

      return {
        healthStatus: parsed.healthStatus || this._computeHealth(findings),
        aiSummary: parsed.summary || 'Check completed.',
        changes,
        alerts: Array.isArray(parsed.alerts) ? parsed.alerts : [],
      }
    } catch {
      return {
        healthStatus: this._computeHealth(findings),
        aiSummary: raw.slice(0, 300),
        changes,
        alerts: [],
      }
    }
  }

  _fallbackAnalysis(findings, previousFindings) {
    const changes = this._detectChanges(findings, previousFindings)
    const healthStatus = this._computeHealth(findings)
    const alerts = []

    // Generate alerts for new high/critical findings
    for (const f of changes.newFindings) {
      if (f.severity === 'critical' || f.severity === 'high') {
        alerts.push({
          type: 'new_vuln',
          severity: f.severity,
          title: `New ${f.severity} finding: ${f.title}`,
        })
      }
    }

    // Generate alerts for resolved findings
    for (const f of changes.resolvedFindings) {
      alerts.push({
        type: 'vuln_resolved',
        severity: 'info',
        title: `Resolved: ${f.title}`,
      })
    }

    const summary = findings.length === 0
      ? 'No security issues detected. System appears healthy.'
      : `Found ${findings.length} issue(s). ${changes.newFindings.length} new, ${changes.resolvedFindings.length} resolved since last check.`

    return { healthStatus, aiSummary: summary, changes, alerts }
  }

  _detectChanges(findings, previousFindings) {
    if (!previousFindings) {
      return { newFindings: findings, resolvedFindings: [], unchanged: [] }
    }

    const prevTitles = new Set(previousFindings.map(f => f.title))
    const currTitles = new Set(findings.map(f => f.title))

    return {
      newFindings: findings.filter(f => !prevTitles.has(f.title)),
      resolvedFindings: previousFindings.filter(f => !currTitles.has(f.title)),
      unchanged: findings.filter(f => prevTitles.has(f.title)),
    }
  }

  _computeHealth(findings) {
    const hasCritical = findings.some(f => f.severity === 'critical')
    const hasHigh = findings.some(f => f.severity === 'high')
    const hasMedium = findings.some(f => f.severity === 'medium')

    if (hasCritical) return 'critical'
    if (hasHigh) return 'degraded'
    if (hasMedium) return 'degraded'
    return 'healthy'
  }
}
