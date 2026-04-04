import Groq from 'groq-sdk'

/**
 * Groq AI Client for SentinelAI
 * Provides fast inference using Groq's optimized hardware
 */
export class GroqAI {
  constructor() {
    this.client = new Groq({
      apiKey: process.env.GROQ_API_KEY
    })
    this.defaultModel = "llama-3.1-8b-instant"  // Updated to working model
    this.usageCallback = null
  }

  setUsageCallback(cb) {
    this.usageCallback = typeof cb === 'function' ? cb : null
  }

  /**
   * Analyze text with Groq AI
   * @param {string} prompt - The prompt to analyze
   * @param {object} options - Configuration options
   * @returns {Promise<string>} AI response
   */
  async analyze(prompt, options = {}) {
    try {
      const response = await this.client.chat.completions.create({
        messages: [{
          role: "user",
          content: prompt
        }],
        model: options.model || this.defaultModel,
        temperature: options.temperature || 0.1, // Low temperature for consistent security analysis
        max_tokens: options.maxTokens || 1024,
        top_p: 0.9
      })

      if (this.usageCallback) {
        this.usageCallback({
          usage: response.usage || {},
          model: options.model || this.defaultModel,
          context: options.context || {},
        })
      }

      return response.choices[0]?.message?.content || "No response generated"
    } catch (error) {
      console.error('Groq API Error:', error.message)
      throw new Error(`AI Analysis failed: ${error.message}`)
    }
  }

  /**
   * Analyze vulnerability data with structured output
   * @param {object} vulnerability - Vulnerability data
   * @returns {Promise<object>} Enhanced vulnerability analysis
   */
  async analyzeVulnerability(vulnerability, meta = {}) {
    const prompt = `
Analyze this security vulnerability and provide a JSON response with the following structure:
{
  "riskScore": 1-10,
  "exploitability": 1-10,
  "falsePositiveProbability": 1-10,
  "priority": "critical|high|medium|low",
  "businessImpact": "description",
  "remediation": "specific steps",
  "reasoning": "why this assessment"
}

Vulnerability Data:
${JSON.stringify(vulnerability, null, 2)}

Provide only the JSON response, no additional text.
`

    try {
      const response = await this.analyze(prompt, {
        temperature: 0.05,
        context: { operation: 'analyze_vulnerability', ...meta },
      })
      return JSON.parse(response)
    } catch (error) {
      console.error('Vulnerability analysis failed:', error.message)
      return {
        riskScore: 5,
        exploitability: 5,
        falsePositiveProbability: 5,
        priority: "medium",
        businessImpact: "Analysis unavailable",
        remediation: "Manual review required",
        reasoning: "AI analysis failed"
      }
    }
  }

  /**
   * Optimize scan strategy for a target
   * @param {object} context - Scan context (target, history, etc.)
   * @returns {Promise<object>} Optimized scan configuration
   */
  async optimizeScanStrategy(context, meta = {}) {
    const prompt = `
Based on this context, recommend optimal security scanning strategy.
Respond with JSON:
{
  "recommendedTemplate": "quick|standard|full",
  "moduleOverrides": {"nuclei": true, "external": false, ...},
  "scanFrequency": "daily|weekly|monthly",
  "reasoning": "explanation"
}

Context:
${JSON.stringify(context, null, 2)}

Provide only JSON response.
`

    try {
      const response = await this.analyze(prompt, {
        temperature: 0.1,
        context: { operation: 'optimize_scan_strategy', ...meta },
      })
      return JSON.parse(response)
    } catch (error) {
      console.error('Scan optimization failed:', error.message)
      return {
        recommendedTemplate: "standard",
        moduleOverrides: {},
        scanFrequency: "weekly",
        reasoning: "Default strategy due to AI analysis failure"
      }
    }
  }

  /**
   * Discover potential assets from a domain
   * @param {string} domain - Base domain to analyze
   * @returns {Promise<Array>} List of potential targets
   */
  async discoverAssets(domain, meta = {}) {
    const prompt = `
Given this domain: ${domain}

Suggest potential subdomains and endpoints to investigate for security assessment.
Respond with JSON array of targets:
[
  {"target": "api.domain.com", "type": "api", "priority": "high"},
  {"target": "admin.domain.com", "type": "admin", "priority": "critical"}
]

Focus on realistic, common patterns. Provide only JSON array.
`

    try {
      const response = await this.analyze(prompt, {
        temperature: 0.2,
        context: { operation: 'discover_assets', domain, ...meta },
      })
      return JSON.parse(response)
    } catch (error) {
      console.error('Asset discovery failed:', error.message)
      return []
    }
  }

  /**
   * Test Groq API connection
   * @returns {Promise<boolean>} Connection status
   */
  async testConnection() {
    try {
      const response = await this.analyze("Respond with 'OK' if you receive this message.")
      return response.includes('OK')
    } catch (error) {
      console.error('Groq connection test failed:', error.message)
      return false
    }
  }
}