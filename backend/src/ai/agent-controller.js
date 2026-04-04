import { GroqAI } from './groq-client.js'
import { db, addLog, saveScan, addAudit } from '../data.js'
import { runScan, getModuleSelection } from '../scanner/orchestrator.js'
import { buildAIScanGraph, executeAIScanGraph } from './scan-graph.js'

/**
 * AI Agent Controller for SentinelAI
 * Coordinates AI-enhanced security scanning operations
 */
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

  /**
   * Initialize AI system and test connections
   */
  async initialize() {
    console.log('🤖 Initializing AI Agent Controller...')

    if (!process.env.GROQ_API_KEY) {
      console.warn('⚠️  GROQ_API_KEY not found. AI features will be disabled.')
      return false
    }

    const isConnected = await this.groq.testConnection()
    if (isConnected) {
      console.log('✅ Groq AI connection established')
      await addAudit({
        user: 'ai-system',
        action: 'AI_INITIALIZED',
        resource: 'ai-controller',
        details: 'AI Agent Controller started successfully'
      })
      return true
    } else {
      console.error('❌ Groq AI connection failed')
      return false
    }
  }

  /**
   * AI-enhanced scan execution
   * @param {string} scanId - Scan ID
   * @param {string} target - Target to scan
   * @param {object} options - Scan options
   * @param {object} ctx - Scan context
   * @returns {Promise<object>} Enhanced scan results
   */
  async runAIScan(scanId, target, options, ctx, meta = {}) {
    console.log(`🧠 Starting AI-enhanced scan for ${target}`)
    this.activeScans.set(scanId, { target, startedAt: Date.now() })

    try {
      const graph = buildAIScanGraph()
      let optimization = {
        recommendedTemplate: options.template || 'standard',
        moduleOverrides: {},
        reasoning: 'No optimization produced',
      }

      await executeAIScanGraph({
        graph,
        handlers: {
          optimize: async () => {
            optimization = await this.optimizeScanStrategy(options.projectId, target, meta)
            await this.logScan(scanId, 'info', `AI Optimization: ${optimization.recommendedTemplate} - ${optimization.reasoning}`, ctx)
            return optimization
          },
          scan: async () => {
            const aiOptions = {
              ...options,
              template: optimization.recommendedTemplate,
              modules: { ...getModuleSelection(optimization.recommendedTemplate), ...optimization.moduleOverrides },
            }

            const scan = db.scans.find((s) => s.id === scanId)
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

      // Fallback to normal scan
      await this.logScan(scanId, 'info', 'Falling back to standard scan execution', ctx)
      await runScan(scanId, target, options, ctx)

      throw error
    } finally {
      this.activeScans.delete(scanId)
    }
  }

  /**
   * AI-enhanced vulnerability analysis
   * @param {string} scanId - Scan ID to analyze
   */
  async enhanceVulnerabilityAnalysis(scanId, ctx = null, meta = {}) {
    console.log(`🔍 Analyzing vulnerabilities for scan ${scanId}`)

    const vulnerabilities = db.vulnerabilitiesByScanId.get(scanId) || []
    let enhancedCount = 0

    for (const vuln of vulnerabilities) {
      try {
        // Skip if already AI-analyzed
        if (vuln.aiAnalysis) continue

        const scan = db.scans.find((s) => s.id === scanId)
        const analysis = await this.groq.analyzeVulnerability(vuln, {
          projectId: scan?.projectId || meta.projectId || null,
          sessionId: meta.sessionId || null,
          operation: 'scan_vulnerability_analysis',
        })

        // Enhance vulnerability with AI insights
        vuln.aiAnalysis = {
          ...analysis,
          analyzedAt: new Date().toISOString(),
          model: this.groq.defaultModel
        }

        // Update confidence score based on AI analysis
        vuln.confidence = Math.max(vuln.confidence || 0.7, 1 - (analysis.falsePositiveProbability / 10))

        enhancedCount++

        await this.logScan(scanId, 'info', `AI enhanced vulnerability: ${vuln.title} (Risk: ${analysis.riskScore}/10, Priority: ${analysis.priority})`, ctx)

      } catch (error) {
        console.error(`AI analysis failed for vulnerability ${vuln.id}:`, error.message)
      }
    }

    if (enhancedCount > 0) {
      await this.logScan(scanId, 'success', `AI enhanced ${enhancedCount} vulnerabilities with advanced analysis`, ctx)

      await addAudit({
        user: 'ai-system',
        action: 'AI_ANALYSIS_COMPLETED',
        resource: `scan:${scanId}`,
        details: `Enhanced ${enhancedCount} vulnerabilities`
      })
    }
  }

  /**
   * AI scan strategy optimization
   * @param {string} projectId - Project ID
   * @param {string} target - Target to scan
   * @returns {Promise<object>} Optimization recommendations
   */
  async optimizeScanStrategy(projectId, target, meta = {}) {
    try {
      const project = db.projects.find(p => p.id === projectId)
      const previousScans = db.scans.filter(s => s.projectId === projectId)

      const context = {
        target,
        client: project?.client,
        riskLevel: project?.riskLevel,
        previousScansCount: previousScans.length,
        hasVulnerabilities: previousScans.some(s => (db.vulnerabilitiesByScanId.get(s.id) || []).length > 0),
        targetType: this.analyzeTargetType(target)
      }

      return await this.groq.optimizeScanStrategy(context, {
        projectId,
        sessionId: meta.sessionId || null,
        operation: 'scan_strategy_optimization',
      })

    } catch (error) {
      console.error('Scan optimization failed:', error.message)
      return {
        recommendedTemplate: "standard",
        moduleOverrides: {},
        scanFrequency: "weekly",
        reasoning: "Using default strategy due to optimization failure"
      }
    }
  }

  /**
   * Autonomous asset discovery using Python AI agents
   * @param {string} projectId - Project ID
   * @returns {Promise<Array>} Discovered assets
   */
  async discoverAssets(projectId, meta = {}) {
    console.log(`🔍 Starting AI-powered asset discovery for project ${projectId}`)

    try {
      const project = db.projects.find(p => p.id === projectId)
      if (!project?.scope) {
        console.warn(`No scope defined for project ${projectId}`)
        return []
      }

      // Check cache first
      const cacheKey = `${projectId}:${project.scope}`
      if (this.discoveryCache.has(cacheKey)) {
        const cached = this.discoveryCache.get(cacheKey)
        if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
          console.log('📋 Using cached discovery results')
          return cached.assets
        }
      }

      // Extract domain from scope for AI discovery
      const domains = project.scope.split(',').map(s => s.trim().replace(/^https?:\/\//, ''))
      const allAssets = []

      for (const domain of domains) {
        console.log(`🌐 AI discovering assets for ${domain}`)

        try {
          // Use both Groq AI and Python agent bridge for discovery
          const [groqAssets, agentAssets] = await Promise.all([
            // Groq-based discovery (existing)
            this.groq.discoverAssets(domain, {
              projectId,
              sessionId: meta.sessionId || null,
              operation: 'asset_discovery',
            }),
            // Python agent-based discovery (new)
            this.discoverAssetsWithAgents(domain)
          ])

          // Combine and deduplicate results
          const combinedAssets = [...groqAssets, ...agentAssets]
          const uniqueAssets = this.deduplicateAssets(combinedAssets)
          allAssets.push(...uniqueAssets)

          console.log(`✅ Discovered ${uniqueAssets.length} assets for ${domain}`)

        } catch (error) {
          console.error(`Asset discovery failed for ${domain}:`, error.message)
          // Continue with other domains
        }
      }

      // Cache results
      this.discoveryCache.set(cacheKey, {
        assets: allAssets,
        timestamp: Date.now()
      })

      await addAudit({
        user: 'ai-system',
        action: 'ASSET_DISCOVERY_COMPLETED',
        resource: `project:${projectId}`,
        details: `Discovered ${allAssets.length} assets using AI agents`
      })

      console.log(`✅ Total discovered assets: ${allAssets.length} for ${project.client}`)
      return allAssets

    } catch (error) {
      console.error('Asset discovery failed:', error.message)
      return []
    }
  }

  /**
   * Discover assets using Python AI agents via bridge
   * @param {string} domain - Domain to discover
   * @returns {Promise<Array>} Discovered assets
   */
  async discoverAssetsWithAgents(domain) {
    try {
      const response = await fetch('http://localhost:5001/ai/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
        timeout: 60000 // 60 second timeout
      })

      if (!response.ok) {
        throw new Error(`Agent bridge responded with status ${response.status}`)
      }

      const data = await response.json()
      return this.parseAgentDiscoveryResults(data.discovery_results || '')

    } catch (error) {
      console.error('Python agent discovery failed:', error.message)
      return [] // Fallback gracefully
    }
  }

  /**
   * Parse agent discovery results into structured format
   * @param {string} results - Raw agent results
   * @returns {Array} Structured assets
   */
  parseAgentDiscoveryResults(results) {
    try {
      const assets = []

      // Extract URLs and endpoints from agent results
      const urlPattern = /https?:\/\/[^\s]+/g
      const urls = results.match(urlPattern) || []

      urls.forEach(url => {
        try {
          const urlObj = new URL(url)
          assets.push({
            target: url,
            type: this.classifyAsset(urlObj.hostname, url),
            priority: this.calculatePriority(urlObj.hostname, url),
            source: 'ai_agent'
          })
        } catch (e) {
          // Skip invalid URLs
        }
      })

      // Extract domain/subdomain patterns
      const domainPattern = /([a-z0-9-]+\.)+[a-z]{2,}/gi
      const domains = results.match(domainPattern) || []

      domains.forEach(domain => {
        if (!assets.find(a => a.target.includes(domain))) {
          assets.push({
            target: `https://${domain}`,
            type: this.classifyAsset(domain),
            priority: this.calculatePriority(domain),
            source: 'ai_agent'
          })
        }
      })

      return assets.slice(0, 20) // Limit results
    } catch (error) {
      console.error('Error parsing agent results:', error.message)
      return []
    }
  }

  /**
   * Deduplicate discovered assets
   * @param {Array} assets - Assets to deduplicate
   * @returns {Array} Unique assets
   */
  deduplicateAssets(assets) {
    const seen = new Set()
    return assets.filter(asset => {
      const key = asset.target || asset.url || asset.domain
      if (seen.has(key)) {
        return false
      }
      seen.add(key)
      return true
    })
  }

  /**
   * Classify asset type
   * @param {string} hostname - Asset hostname
   * @param {string} url - Full URL (optional)
   * @returns {string} Asset type
   */
  classifyAsset(hostname, url = '') {
    if (hostname.includes('api.') || url.includes('/api/')) return 'api'
    if (hostname.includes('admin.') || url.includes('admin')) return 'admin'
    if (hostname.includes('staging.') || hostname.includes('dev.')) return 'staging'
    if (hostname.includes('test.')) return 'test'
    if (hostname.includes('mail.')) return 'mail'
    return 'web'
  }

  /**
   * Calculate asset priority
   * @param {string} hostname - Asset hostname
   * @param {string} url - Full URL (optional)
   * @returns {string} Priority level
   */
  calculatePriority(hostname, url = '') {
    if (hostname.includes('admin.') || url.includes('admin')) return 'critical'
    if (hostname.includes('api.') || url.includes('/api/')) return 'high'
    if (hostname.includes('staging.') || hostname.includes('dev.')) return 'medium'
    if (hostname.includes('test.')) return 'low'
    return 'medium'
  }

  /**
   * Plan follow-up actions based on scan results
   * @param {string} scanId - Scan ID
   */
  async planFollowUpActions(scanId, ctx = null) {
    try {
      const vulnerabilities = db.vulnerabilitiesByScanId.get(scanId) || []
      const criticalVulns = vulnerabilities.filter(v =>
        v.severity === 'Critical' ||
        (v.aiAnalysis && v.aiAnalysis.priority === 'critical')
      )

      if (criticalVulns.length > 0) {
        await this.logScan(scanId, 'warn', `🚨 ${criticalVulns.length} critical vulnerabilities detected - Immediate attention required`, ctx)

        // TODO: Trigger notifications, create tickets, schedule retests
        await addAudit({
          user: 'ai-system',
          action: 'CRITICAL_VULNS_DETECTED',
          resource: `scan:${scanId}`,
          details: `${criticalVulns.length} critical vulnerabilities require immediate attention`
        })
      }

      const highConfidenceVulns = vulnerabilities.filter(v => v.confidence > 0.9)
      if (highConfidenceVulns.length > 0) {
        await this.logScan(scanId, 'info', `✅ ${highConfidenceVulns.length} high-confidence vulnerabilities validated by AI`, ctx)
      }

    } catch (error) {
      console.error('Follow-up planning failed:', error.message)
    }
  }

  /**
   * Analyze target type for optimization
   * @param {string} target - Target URL/IP
   * @returns {string} Target type
   */
  analyzeTargetType(target) {
    if (target.includes('api.') || target.includes('/api/')) return 'api'
    if (target.includes('admin.') || target.includes('dashboard.')) return 'admin'
    if (target.includes('staging.') || target.includes('dev.')) return 'staging'
    if (target.match(/^\d+\.\d+\.\d+\.\d+/)) return 'ip'
    return 'web'
  }

  /**
   * Get AI system status
   * @returns {object} Status information
   */
  getStatus() {
    return {
      isActive: !!process.env.GROQ_API_KEY,
      activeScans: this.activeScans.size,
      cacheEntries: this.discoveryCache.size,
      model: this.groq.defaultModel
    }
  }

  async logScan(scanId, level, message, ctx = null) {
    if (ctx?.pushLog) {
      return ctx.pushLog(scanId, level, message, 'ai')
    }
    return addLog(scanId, {
      timestamp: new Date().toISOString(),
      level,
      message,
      module: 'ai',
    })
  }

  async appendTranscript(sessionId, entry) {
    if (!this.sessionLogger || !sessionId) return
    await this.sessionLogger.appendTranscript(sessionId, entry)
  }
}