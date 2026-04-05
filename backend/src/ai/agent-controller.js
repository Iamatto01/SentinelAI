import { GroqAI } from './groq-client.js'
import { db, addLog, saveScan, addAudit } from '../data.js'
import { runScan, getModuleSelection } from '../scanner/orchestrator.js'
import { buildAIScanGraph, executeAIScanGraph } from './scan-graph.js'

const BRIDGE_URL = process.env.AI_BRIDGE_URL || 'http://localhost:5001'
const BRIDGE_TIMEOUT_MS = Number(process.env.AI_BRIDGE_TIMEOUT_MS || 90_000)

/**
 * Fetch helper that correctly handles timeouts via AbortController.
 * Node.js fetch does NOT support a `timeout` option — only `signal`.
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = BRIDGE_TIMEOUT_MS) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, { ...options, signal: controller.signal })
    return response
  } finally {
    clearTimeout(timer)
  }
}

export class AIAgentController {
  constructor({ sessionLogger = null, costTracker = null } = {}) {
    this.groq = new GroqAI()
    this.activeScans = new Map()
    this.discoveryCache = new Map()
    this.sessionLogger = sessionLogger
    this.costTracker = costTracker

    this.groq.setUsageCallback(({ usage, model, context }) => {
      if (!this.costTracker) return
      this.costTracker.trackUsage({
        projectId: context.projectId || null,
        sessionId: context.sessionId || null,
        operation: context.operation || 'unknown',
        model,
        usage,
      })
    })
  }

  // ---------------------------------------------------------------------------
  // Initialise
  // ---------------------------------------------------------------------------

  async initialize() {
    console.log('🤖 Initialising AI Agent Controller…')

    if (!process.env.GROQ_API_KEY) {
      console.warn('⚠️  GROQ_API_KEY not found — AI features disabled.')
      return false
    }

    const ok = await this.groq.testConnection()
    if (ok) {
      console.log('✅ Groq AI connection established')
      await addAudit({ user: 'ai-system', action: 'AI_INITIALIZED', resource: 'ai-controller', details: 'AI Agent Controller started successfully' })
      return true
    }

    console.error('❌ Groq AI connection failed')
    return false
  }

  // ---------------------------------------------------------------------------
  // AI-enhanced scan
  // ---------------------------------------------------------------------------

  async runAIScan(scanId, target, options, ctx, meta = {}) {
    console.log(`🧠 Starting AI-enhanced scan for ${target}`)
    this.activeScans.set(scanId, { target, startedAt: Date.now() })

    try {
      const graph = buildAIScanGraph()
      let optimization = {
        recommendedTemplate: options.template || 'standard',
        moduleOverrides: {},
        reasoning: 'Default — no optimization produced',
      }

      await executeAIScanGraph({
        graph,
        handlers: {
          optimize: async () => {
            optimization = await this.optimizeScanStrategy(options.projectId, target, meta)
            await this.logScan(scanId, 'info', `AI Optimization: ${optimization.recommendedTemplate} — ${optimization.reasoning}`, ctx)
            return optimization
          },
          scan: async () => {
            const aiOptions = {
              ...options,
              template: optimization.recommendedTemplate,
              modules: { ...getModuleSelection(optimization.recommendedTemplate), ...optimization.moduleOverrides },
            }
            const scan = db.scans.find(s => s.id === scanId)
            if (scan) {
              scan.aiEnhanced = true
              scan.aiOptimization = optimization
              await saveScan(scan)
            }
            await runScan(scanId, target, aiOptions, ctx)
            return aiOptions
          },
          analyze: async () => this.enhanceVulnerabilityAnalysis(scanId, ctx, meta),
          followup: async () => this.planFollowUpActions(scanId, ctx),
        },
        onStep: async (status, step) => {
          await this.logScan(scanId, status === 'started' ? 'info' : 'success', `Graph step ${status}: ${step.title}`, ctx)
          await this.appendTranscript(meta.sessionId, {
            event: 'graph_step',
            timestamp: new Date().toISOString(),
            payload: { status, stepId: step.id, title: step.title, durationMs: step.durationMs || null },
          })
        },
      })

      return { scanId, aiEnhanced: true, optimization, orchestrator: 'graph' }

    } catch (error) {
      console.error('AI scan failed:', error.message)
      await this.logScan(scanId, 'error', `AI scan error: ${error.message}`, ctx)
      await this.logScan(scanId, 'info', 'Falling back to standard scan', ctx)
      await runScan(scanId, target, options, ctx)
      throw error
    } finally {
      this.activeScans.delete(scanId)
    }
  }

  // ---------------------------------------------------------------------------
  // Vulnerability enhancement
  // ---------------------------------------------------------------------------

  async enhanceVulnerabilityAnalysis(scanId, ctx = null, meta = {}) {
    const vulnerabilities = db.vulnerabilitiesByScanId.get(scanId) || []
    let enhanced = 0

    for (const vuln of vulnerabilities) {
      if (vuln.aiAnalysis) continue
      try {
        const scan = db.scans.find(s => s.id === scanId)
        const analysis = await this.groq.analyzeVulnerability(vuln, {
          projectId: scan?.projectId || meta.projectId || null,
          sessionId: meta.sessionId || null,
          operation: 'scan_vulnerability_analysis',
        })

        vuln.aiAnalysis = { ...analysis, analyzedAt: new Date().toISOString(), model: this.groq.defaultModel }
        vuln.confidence = Math.max(vuln.confidence || 0.7, 1 - (analysis.falsePositiveProbability / 10))
        enhanced++

        await this.logScan(scanId, 'info',
          `AI enhanced: ${vuln.title} (Risk: ${analysis.riskScore}/10, Priority: ${analysis.priority})`, ctx)
      } catch (err) {
        console.error(`AI analysis failed for vuln ${vuln.id}:`, err.message)
      }
    }

    if (enhanced > 0) {
      await this.logScan(scanId, 'success', `AI enhanced ${enhanced} vulnerabilities`, ctx)
      await addAudit({ user: 'ai-system', action: 'AI_ANALYSIS_COMPLETED', resource: `scan:${scanId}`, details: `Enhanced ${enhanced} vulnerabilities` })
    }
  }

  // ---------------------------------------------------------------------------
  // Scan strategy optimisation
  // ---------------------------------------------------------------------------

  async optimizeScanStrategy(projectId, target, meta = {}) {
    try {
      const project = db.projects.find(p => p.id === projectId)
      const prevScans = db.scans.filter(s => s.projectId === projectId)

      const context = {
        target,
        client: project?.client,
        riskLevel: project?.riskLevel,
        previousScansCount: prevScans.length,
        hasVulnerabilities: prevScans.some(s => (db.vulnerabilitiesByScanId.get(s.id) || []).length > 0),
        targetType: this.analyzeTargetType(target),
      }

      return await this.groq.optimizeScanStrategy(context, {
        projectId,
        sessionId: meta.sessionId || null,
        operation: 'scan_strategy_optimization',
      })
    } catch (error) {
      console.error('Scan optimisation failed:', error.message)
      return { recommendedTemplate: 'standard', moduleOverrides: {}, scanFrequency: 'weekly', reasoning: 'Default (optimisation failed)' }
    }
  }

  // ---------------------------------------------------------------------------
  // Asset discovery — Groq + Python agent bridge
  // ---------------------------------------------------------------------------

  async discoverAssets(projectId, meta = {}) {
    const project = db.projects.find(p => p.id === projectId)
    if (!project?.scope) return []

    const cacheKey = `${projectId}:${project.scope}`
    const cached = this.discoveryCache.get(cacheKey)
    if (cached && Date.now() - cached.timestamp < 3_600_000) return cached.assets

    const domains = project.scope.split(',').map(s => s.trim().replace(/^https?:\/\//, ''))
    const allAssets = []

    for (const domain of domains) {
      try {
        const [groqAssets, agentAssets] = await Promise.allSettled([
          this.groq.discoverAssets(domain, { projectId, sessionId: meta.sessionId || null, operation: 'asset_discovery' }),
          this.discoverAssetsWithAgents(domain),
        ])

        const combined = [
          ...(groqAssets.status === 'fulfilled' ? groqAssets.value : []),
          ...(agentAssets.status === 'fulfilled' ? agentAssets.value : []),
        ]
        allAssets.push(...this.deduplicateAssets(combined))
      } catch (err) {
        console.error(`Asset discovery failed for ${domain}:`, err.message)
      }
    }

    this.discoveryCache.set(cacheKey, { assets: allAssets, timestamp: Date.now() })

    await addAudit({
      user: 'ai-system',
      action: 'ASSET_DISCOVERY_COMPLETED',
      resource: `project:${projectId}`,
      details: `Discovered ${allAssets.length} assets`,
    })

    return allAssets
  }

  /**
   * Call the Python agent bridge with a properly handled timeout.
   */
  async discoverAssetsWithAgents(domain) {
    try {
      const response = await fetchWithTimeout(
        `${BRIDGE_URL}/ai/discover`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain }),
        },
        BRIDGE_TIMEOUT_MS,
      )

      if (!response.ok) {
        throw new Error(`Bridge responded with HTTP ${response.status}`)
      }

      const data = await response.json()
      return this.parseAgentDiscoveryResults(data.discovery_results || '')

    } catch (error) {
      if (error.name === 'AbortError') {
        console.warn(`[AI] Agent bridge timed out for domain ${domain}`)
      } else {
        console.error('[AI] Python agent discovery failed:', error.message)
      }
      return []
    }
  }

  parseAgentDiscoveryResults(results) {
    const assets = []
    const urlPattern = /https?:\/\/[^\s<>"[\]{}]*/g
    for (const url of (results.match(urlPattern) || [])) {
      try {
        const { hostname } = new URL(url)
        assets.push({ target: url, type: this.classifyAsset(hostname, url), priority: this.calculatePriority(hostname, url), source: 'ai_agent' })
      } catch { /* skip invalid URLs */ }
    }
    return assets.slice(0, 20)
  }

  deduplicateAssets(assets) {
    const seen = new Set()
    return assets.filter(a => {
      const key = a.target || a.url || a.domain
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  classifyAsset(hostname, url = '') {
    if (hostname.includes('api.') || url.includes('/api/'))   return 'api'
    if (hostname.includes('admin.') || url.includes('admin')) return 'admin'
    if (/staging\.|dev\.|test\./.test(hostname))              return 'staging'
    if (hostname.includes('mail.'))                            return 'mail'
    return 'web'
  }

  calculatePriority(hostname, url = '') {
    if (hostname.includes('admin.') || url.includes('admin'))  return 'critical'
    if (hostname.includes('api.') || url.includes('/api/'))    return 'high'
    if (/staging\.|dev\.|test\./.test(hostname))               return 'medium'
    return 'medium'
  }

  async planFollowUpActions(scanId, ctx = null) {
    const vulnerabilities = db.vulnerabilitiesByScanId.get(scanId) || []
    const criticalVulns = vulnerabilities.filter(v =>
      v.severity === 'Critical' || (v.aiAnalysis?.priority === 'critical')
    )

    if (criticalVulns.length > 0) {
      await this.logScan(scanId, 'warn', `🚨 ${criticalVulns.length} critical vulnerabilities — immediate action required`, ctx)
      await addAudit({ user: 'ai-system', action: 'CRITICAL_VULNS_DETECTED', resource: `scan:${scanId}`, details: `${criticalVulns.length} critical vulnerabilities` })
    }

    const highConfidence = vulnerabilities.filter(v => v.confidence > 0.9)
    if (highConfidence.length > 0) {
      await this.logScan(scanId, 'info', `✅ ${highConfidence.length} high-confidence vulnerabilities validated`, ctx)
    }
  }

  analyzeTargetType(target) {
    if (/api\.|\/api\//.test(target))          return 'api'
    if (/admin\.|dashboard\./.test(target))    return 'admin'
    if (/staging\.|dev\./.test(target))        return 'staging'
    if (/^\d+\.\d+\.\d+\.\d+/.test(target))   return 'ip'
    return 'web'
  }

  getStatus() {
    return {
      isActive: !!process.env.GROQ_API_KEY,
      activeScans: this.activeScans.size,
      cacheEntries: this.discoveryCache.size,
      model: this.groq.defaultModel,
      bridgeUrl: BRIDGE_URL,
    }
  }

  async logScan(scanId, level, message, ctx = null) {
    if (ctx?.pushLog) return ctx.pushLog(scanId, level, message, 'ai')
    return addLog(scanId, { timestamp: new Date().toISOString(), level, message, module: 'ai' })
  }

  async appendTranscript(sessionId, entry) {
    if (!this.sessionLogger || !sessionId) return
    await this.sessionLogger.appendTranscript(sessionId, entry)
  }
}
