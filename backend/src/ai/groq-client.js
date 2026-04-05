import Groq from 'groq-sdk'

/**
 * Groq AI Client — with JSON sanitization, retry logic, and better error handling.
 */
export class GroqAI {
  constructor() {
    this.client = new Groq({ apiKey: process.env.GROQ_API_KEY })
    this.defaultModel = 'llama-3.1-8b-instant'
    this.usageCallback = null
  }

  setUsageCallback(cb) {
    this.usageCallback = typeof cb === 'function' ? cb : null
  }

  /**
   * Core LLM call with automatic retry on rate-limit / transient errors.
   * @param {string} prompt
   * @param {object} options
   * @returns {Promise<string>}
   */
  async analyze(prompt, options = {}) {
    const maxRetries = options.maxRetries ?? 2
    let lastError

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await this.client.chat.completions.create({
          messages: [{ role: 'user', content: prompt }],
          model: options.model || this.defaultModel,
          temperature: options.temperature ?? 0.1,
          max_tokens: options.maxTokens ?? 1024,
          top_p: 0.9,
        })

        if (this.usageCallback) {
          this.usageCallback({
            usage: response.usage || {},
            model: options.model || this.defaultModel,
            context: options.context || {},
          })
        }

        return response.choices[0]?.message?.content ?? ''

      } catch (error) {
        lastError = error
        const status = error?.status || error?.statusCode
        const isRetryable = status === 429 || status === 503 || status === 502

        if (isRetryable && attempt < maxRetries) {
          const delay = (attempt + 1) * 1500  // 1.5s, 3s
          console.warn(`[Groq] Retrying after ${delay}ms (attempt ${attempt + 1}/${maxRetries}) — ${error.message}`)
          await new Promise(r => setTimeout(r, delay))
          continue
        }
        throw new Error(`AI analysis failed: ${error.message}`)
      }
    }

    throw lastError
  }

  /**
   * Strip markdown code fences from a string, then JSON.parse.
   * Groq sometimes wraps JSON output in ```json … ``` blocks.
   * @param {string} raw
   * @returns {any}
   */
  _parseJSON(raw) {
    if (!raw) throw new Error('Empty response from AI')

    // Remove markdown code blocks (```json ... ``` or ``` ... ```)
    let clean = raw
      .replace(/^```(?:json)?\s*/im, '')
      .replace(/\s*```$/im, '')
      .trim()

    // Sometimes the model produces extra text before/after the JSON object
    const firstBrace  = clean.indexOf('{')
    const firstBracket = clean.indexOf('[')

    if (firstBrace !== -1 || firstBracket !== -1) {
      const start = (firstBrace === -1) ? firstBracket
                  : (firstBracket === -1) ? firstBrace
                  : Math.min(firstBrace, firstBracket)
      const lastBrace   = clean.lastIndexOf('}')
      const lastBracket = clean.lastIndexOf(']')
      const end = Math.max(lastBrace, lastBracket)
      if (start < end) {
        clean = clean.slice(start, end + 1)
      }
    }

    return JSON.parse(clean)
  }

  /**
   * Analyze a vulnerability and return a structured object.
   * @param {object} vulnerability
   * @param {object} meta
   * @returns {Promise<object>}
   */
  async analyzeVulnerability(vulnerability, meta = {}) {
    const prompt = `Analyze this security vulnerability and respond ONLY with a valid JSON object — no markdown, no extra text.

Required JSON structure:
{
  "riskScore": <1-10 integer>,
  "exploitability": <1-10 integer>,
  "falsePositiveProbability": <1-10 integer>,
  "priority": "critical|high|medium|low",
  "businessImpact": "<concise description>",
  "remediation": "<specific actionable steps>",
  "reasoning": "<brief explanation of assessment>"
}

Vulnerability data:
${JSON.stringify(vulnerability, null, 2)}`

    try {
      const raw = await this.analyze(prompt, {
        temperature: 0.05,
        maxTokens: 512,
        context: { operation: 'analyze_vulnerability', ...meta },
      })
      return this._parseJSON(raw)
    } catch (error) {
      console.error('[Groq] Vulnerability analysis parse error:', error.message)
      return {
        riskScore: 5,
        exploitability: 5,
        falsePositiveProbability: 5,
        priority: 'medium',
        businessImpact: 'Analysis unavailable — manual review required',
        remediation: 'Review vulnerability manually and apply vendor patches',
        reasoning: 'AI analysis failed: ' + error.message,
      }
    }
  }

  /**
   * Recommend an optimal scan strategy.
   * @param {object} context
   * @param {object} meta
   * @returns {Promise<object>}
   */
  async optimizeScanStrategy(context, meta = {}) {
    const prompt = `Based on this security scanning context, recommend an optimal strategy.
Respond ONLY with valid JSON — no markdown, no explanation outside the JSON.

Required JSON structure:
{
  "recommendedTemplate": "quick|standard|full",
  "moduleOverrides": {},
  "scanFrequency": "daily|weekly|monthly",
  "reasoning": "<brief explanation>"
}

Context:
${JSON.stringify(context, null, 2)}`

    try {
      const raw = await this.analyze(prompt, {
        temperature: 0.1,
        maxTokens: 300,
        context: { operation: 'optimize_scan_strategy', ...meta },
      })
      return this._parseJSON(raw)
    } catch (error) {
      console.error('[Groq] Scan optimization parse error:', error.message)
      return {
        recommendedTemplate: 'standard',
        moduleOverrides: {},
        scanFrequency: 'weekly',
        reasoning: 'Default strategy (optimization unavailable): ' + error.message,
      }
    }
  }

  /**
   * Discover likely attack-surface targets for a domain.
   * @param {string} domain
   * @param {object} meta
   * @returns {Promise<Array>}
   */
  async discoverAssets(domain, meta = {}) {
    const prompt = `Given domain: ${domain}

Suggest realistic subdomains and endpoints for a security assessment.
Respond ONLY with a valid JSON array — no markdown, no explanation.

Example structure:
[
  {"target": "api.${domain}", "type": "api", "priority": "high"},
  {"target": "admin.${domain}", "type": "admin", "priority": "critical"}
]

Focus on common patterns (api, admin, staging, dev, ci, git, docs, mail, vpn).`

    try {
      const raw = await this.analyze(prompt, {
        temperature: 0.2,
        maxTokens: 400,
        context: { operation: 'discover_assets', domain, ...meta },
      })
      const result = this._parseJSON(raw)
      return Array.isArray(result) ? result : []
    } catch (error) {
      console.error('[Groq] Asset discovery parse error:', error.message)
      return []
    }
  }

  /**
   * Test the Groq API connection.
   * @returns {Promise<boolean>}
   */
  async testConnection() {
    try {
      const response = await this.analyze("Reply with exactly the word: OK")
      return response.trim().toUpperCase().includes('OK')
    } catch {
      return false
    }
  }
}
