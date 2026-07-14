import { GroqAI } from './groq-client.js'

/**
 * AI Agent Controller — Simplified version for the SIEM monitoring system.
 * Provides the Groq client for AI chat and voice features,
 * while the heavy monitoring work is handled by MonitorScheduler + AIWorker.
 */
export class AIAgentController {
  constructor({ sessionLogger = null, costTracker = null } = {}) {
    this.groq = new GroqAI()
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

  async initialize() {
    console.log('🤖 Initialising AI Agent Controller…')

    if (!process.env.GROQ_API_KEY) {
      console.warn('⚠️  GROQ_API_KEY not found — AI features disabled.')
      return false
    }

    const ok = await this.groq.testConnection()
    if (ok) {
      console.log('✅ Groq AI connection established')
      return true
    }

    console.error('❌ Groq AI connection failed')
    return false
  }

  getStatus() {
    return {
      isActive: !!process.env.GROQ_API_KEY,
      groqConfigured: !!process.env.GROQ_API_KEY,
    }
  }
}
