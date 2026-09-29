import { config } from '../config.js'

/**
 * Unified LLM client with multi-provider fallback order:
 *  1. OpenRouter (primary, if OPENROUTER_API_KEY configured)
 *  2. Bandelbanget (provider 2, if BANDELBANGET_API_KEY configured)
 *  3. Groq API (fallback, if GROQ_API_KEY configured)
 * Retries with backoff on 429/5xx. Redacts nothing here (callers sanitize).
 */
export class LLMClient {
  constructor() {
    this.openrouter = config.ai.openrouter
    this.bandelbanget = config.ai.bandelbanget
    this.groq = config.ai.groq
    this.usageCallback = null
  }

  setUsageCallback(cb) { this.usageCallback = typeof cb === 'function' ? cb : null }

  isConfigured() { return Boolean(this.openrouter?.key || this.bandelbanget?.key || this.groq?.key) }

  async checkProvidersHealth() {
    const list = [
      {
        id: 'bandelbanget',
        name: 'Bandelbanget AI (DeepSeek V4)',
        role: '2. Provider 2',
        model: this.bandelbanget?.model || 'deepseek-v4-pro',
        baseUrl: this.bandelbanget?.baseUrl || 'https://bandelbanget.xyz/v1',
        hasKey: Boolean(this.bandelbanget?.key),
        key: this.bandelbanget?.key,
      },
      {
        id: 'openrouter',
        name: 'OpenRouter AI',
        role: '3. Fallback 1',
        model: this.openrouter?.model || 'inclusionai/ling-3.0-flash-sante:free',
        baseUrl: this.openrouter?.baseUrl || 'https://openrouter.ai/api/v1',
        hasKey: Boolean(this.openrouter?.key),
        key: this.openrouter?.key,
      },
      {
        id: 'groq',
        name: 'Groq Cloud AI',
        role: '4. Fallback 2',
        model: this.groq?.model || 'llama-3.3-70b-versatile',
        baseUrl: this.groq?.baseUrl || 'https://api.groq.com/openai/v1',
        hasKey: Boolean(this.groq?.key),
        key: this.groq?.key,
      },
    ]

    return Promise.all(list.map(async (p) => {
      if (!p.hasKey) {
        return {
          id: p.id,
          name: p.name,
          role: p.role,
          model: p.model,
          baseUrl: p.baseUrl,
          online: false,
          status: 'OFFLINE',
          reason: 'No API Key configured',
        }
      }
      try {
        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), 4000)
        const headers = { 'Authorization': `Bearer ${p.key}` }
        const res = await fetch(`${p.baseUrl}/models`, {
          method: 'GET',
          headers,
          signal: ctrl.signal,
        }).catch(() => null)
        clearTimeout(timer)

        let isOnline = false
        let reason = 'Unreachable or HTTP error'
        
        if (res) {
          if (res.status === 200) {
            isOnline = true
            reason = 'Service Reachable & Active'
          } else if (res.status === 401 || res.status === 403) {
            isOnline = false
            reason = 'API Key Invalid or Unauthorized'
          } else if (res.status === 429) {
            isOnline = false
            reason = 'Rate Limited / Quota Exceeded'
          } else {
            isOnline = false
            reason = `HTTP Error ${res.status}`
          }
        }

        return {
          id: p.id,
          name: p.name,
          role: p.role,
          model: p.model,
          baseUrl: p.baseUrl,
          online: isOnline,
          status: isOnline ? 'ONLINE' : 'OFFLINE',
          statusCode: res ? res.status : null,
          reason,
        }
      } catch (e) {
        return {
          id: p.id,
          name: p.name,
          role: p.role,
          model: p.model,
          baseUrl: p.baseUrl,
          online: false,
          status: 'OFFLINE',
          reason: e.name === 'AbortError' ? 'Connection timeout (4s)' : e.message,
        }
      }
    }))
  }

  async analyze(prompt, options = {}) {
    const maxRetries = options.maxRetries ?? 3
    const useFast = options.useFast === true
    let lastError = null

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (useFast) {
        // ── FAST TIER: OpenRouter free models first, Bandelbanget heavy as fallback ──
        // Used for verifyFinding, summarize, chat — high-volume, low-complexity tasks.
        // This preserves your Bandelbanget DeepSeek V4 quota for auditCode.

        // 1. OpenRouter free (primary for fast tier)
        if (this.openrouter?.key) {
          try {
            const res = await this.#openrouter(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] OpenRouter (fast) returned empty text, trying Groq...')
          } catch (e1) {
            lastError = e1
            console.warn(`[AI Engine] OpenRouter (fast) failed (${e1.message}), falling back to Groq...`)
          }
        }

        // 2. Groq free (fast fallback)
        if (this.groq?.key) {
          try {
            const res = await this.#groq(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] Groq (fast) returned empty text, falling back to Bandelbanget heavy...')
          } catch (e2) {
            lastError = e2
            console.warn(`[AI Engine] Groq (fast) failed (${e2.message}), falling back to Bandelbanget heavy...`)
          }
        }

        // 3. Bandelbanget heavy (last resort for fast tier)
        if (this.bandelbanget?.key) {
          try {
            const res = await this.#bandelbanget(prompt, options)
            if (res && res.trim().length > 0) return res
          } catch (e3) {
            lastError = e3
          }
        }
      } else {
        // ── HEAVY TIER: Bandelbanget DeepSeek V4 first, free models as fallback ──
        // Used for auditCode — complex reasoning needs DeepSeek V4.

        // 1. Bandelbanget (DeepSeek V4 Pro)
        if (this.bandelbanget?.key) {
          try {
            const res = await this.#bandelbanget(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] Bandelbanget returned empty text, trying OpenRouter...')
          } catch (e1) {
            lastError = e1
            console.warn(`[AI Engine] Bandelbanget failed (${e1.message}), falling back to OpenRouter...`)
          }
        }

        // 2. OpenRouter free (fallback)
        if (this.openrouter?.key) {
          try {
            const res = await this.#openrouter(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] OpenRouter returned empty text, trying Groq...')
          } catch (e2) {
            lastError = e2
            console.warn(`[AI Engine] OpenRouter failed (${e2.message}), falling back to Groq...`)
          }
        }

        // 3. Groq (last resort)
        if (this.groq?.key) {
          try {
            const res = await this.#groq(prompt, options)
            if (res && res.trim().length > 0) return res
          } catch (e3) {
            lastError = e3
          }
        }
      }

      if (!this.isConfigured()) throw new Error('No AI API key configured')

      const status = lastError?.status || lastError?.statusCode
      const errMsg = String(lastError?.message || '')
      // Detect Groq daily token limit exhaustion — retrying is pointless
      const isDailyLimit = status === 429 && /tokens?\.?per\.?day|try again in \d+h|daily.*limit|tpd/i.test(errMsg)
      const retryable = (status === 429 || status === 502 || status === 503 || status === 408) && !isDailyLimit
      if (retryable && attempt < maxRetries) {
        const delay = Math.min(2000 * Math.pow(2, attempt), 15000)
        console.warn(`[AI Engine] Provider busy/rate-limited (${lastError?.message}). Retrying in ${delay / 1000}s... (Attempt ${attempt + 1}/${maxRetries})`)
        await new Promise(r => setTimeout(r, delay))
        continue
      }
      throw new Error(`AI service temporarily unavailable (${lastError?.message || 'all providers failed'})`)
    }
    throw lastError
  }

  async #openrouter(prompt, options) {
    const baseUrl = (this.openrouter.baseUrl || 'https://openrouter.ai/api/v1').replace(/\/$/, '')
    const url = `${baseUrl}/chat/completions`
    const messages = []
    if (options.system) messages.push({ role: 'system', content: options.system })
    messages.push({ role: 'user', content: prompt })
    
    // Top free models list from OpenRouter — keep to 3 to avoid wasting time
    // on sequential 60s timeouts. Each failing model wastes a full API call.
    const modelsToTry = Array.from(new Set([
      this.openrouter.model,
      'nvidia/nemotron-3-super-120b-a12b:free',
      'google/gemma-4-26b-a4b-it:free',
    ].filter(Boolean)))

    let lastErr = null
    for (const modelCandidate of modelsToTry) {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? 60000)
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.openrouter.key}`,
            'HTTP-Referer': 'https://sentinelai.studio',
            'X-Title': 'FYP2 Sentinel AI',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: modelCandidate,
            messages,
            temperature: options.temperature ?? 0.1,
            max_tokens: options.maxTokens ?? 8000,
          }),
          signal: ctrl.signal,
        })
        clearTimeout(timer)
        if (!res.ok) {
          const errText = await res.text()
          throw Object.assign(new Error(`OpenRouter (${modelCandidate}) HTTP ${res.status}: ${errText}`), { status: res.status })
        }
        const data = await res.json()
        const text = data.choices?.[0]?.message?.content ?? ''
        if (text.trim().length > 0) {
          this.#usage(data.usage, modelCandidate, options.context)
          return text
        }
      } catch (e) {
        clearTimeout(timer)
        lastErr = e
        console.warn(`[AI Engine] OpenRouter candidate ${modelCandidate} failed: ${e.message}`)
      }
    }
    throw lastErr || new Error('All OpenRouter free model candidates failed')
  }

  async #bandelbanget(prompt, options) {
    const baseUrl = (this.bandelbanget.baseUrl || 'https://bandelbanget.xyz/v1').replace(/\/$/, '')
    const url = `${baseUrl}/chat/completions`
    const messages = []
    if (options.system) messages.push({ role: 'system', content: options.system })
    messages.push({ role: 'user', content: prompt })

    const keys = (this.bandelbanget.keys && this.bandelbanget.keys.length > 0)
      ? this.bandelbanget.keys
      : [this.bandelbanget.key].filter(Boolean)

    let lastErr = null
    for (const key of keys) {
      const ctrl = new AbortController()
      const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? 60000)
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${key}`,
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 SentinelAI/2.0',
          },
          body: JSON.stringify({
            model: this.bandelbanget.model || 'deepseek-v4-pro',
            messages,
            temperature: options.temperature ?? 0.1,
            max_tokens: options.maxTokens ?? 8000,
          }),
          signal: ctrl.signal,
        })
        clearTimeout(timer)
        if (!res.ok) {
          const errText = await res.text()
          throw Object.assign(new Error(`Bandelbanget HTTP ${res.status}: ${errText}`), { status: res.status })
        }
        const data = await res.json()
        const text = data.choices?.[0]?.message?.content ?? ''
        this.#usage(data.usage, this.bandelbanget.model, options.context)
        if (text.trim().length > 0) return text
      } catch (e) {
        clearTimeout(timer)
        lastErr = e
        console.warn(`[AI Engine] Bandelbanget key (...${key.slice(-8)}) error: ${e.message}`)
      }
    }
    throw lastErr || new Error('All Bandelbanget API keys failed')
  }

  async #groq(prompt, options) {
    const url = 'https://api.groq.com/openai/v1/chat/completions'
    const messages = []
    if (options.system) messages.push({ role: 'system', content: options.system })
    messages.push({ role: 'user', content: prompt })

    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? 60000)
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${this.groq.key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.groq.model,
          messages,
          temperature: options.temperature ?? 0.2,
          max_tokens: options.maxTokens ?? 8000,
        }),
        signal: ctrl.signal,
      })
      clearTimeout(timer)
      if (!res.ok) throw Object.assign(new Error(`Groq HTTP ${res.status}: ${await res.text()}`), { status: res.status })
      const data = await res.json()
      this.#usage(data.usage, this.groq.model, options.context)
      return data.choices?.[0]?.message?.content ?? ''
    } catch (e) {
      clearTimeout(timer)
      if (e.name === 'AbortError') throw new Error('Groq Cloud request timed out (60s limit)')
      throw e
    }
  }

  #usage(usage, model, context) {
    if (this.usageCallback) this.usageCallback({ usage: usage || {}, model, context: context || {} })
  }

  /** Parse JSON robustly from an LLM response (strips fences, finds braces). */
  parseJSON(raw) {
    if (!raw) throw new Error('empty AI response')
    let clean = String(raw).replace(/^```(?:json)?\s*/im, '').replace(/\s*```$/im, '').trim()
    const fb = clean.indexOf('{'), fk = clean.indexOf('[')
    if (fb !== -1 || fk !== -1) {
      const start = fb === -1 ? fk : fk === -1 ? fb : Math.min(fb, fk)
      const end = Math.max(clean.lastIndexOf('}'), clean.lastIndexOf(']'))
      if (start < end) clean = clean.slice(start, end + 1)
    }
    try {
      return JSON.parse(clean)
    } catch (error) {
      const recovered = this.#recoverFindings(clean)
      if (recovered) return recovered
      throw error
    }
  }

  /** Recover complete findings when an LLM truncates the final JSON array item. */
  #recoverFindings(raw) {
    const match = /"findings"\s*:\s*\[/.exec(raw)
    if (!match) return null

    const findings = []
    let depth = 0, start = -1, quoted = false, escaped = false
    for (let index = match.index + match[0].length; index < raw.length; index++) {
      const char = raw[index]
      if (quoted) {
        if (escaped) escaped = false
        else if (char === '\\') escaped = true
        else if (char === '"') quoted = false
        continue
      }
      if (char === '"') { quoted = true; continue }
      if (char === '{') {
        if (depth++ === 0) start = index
      } else if (char === '}' && depth > 0 && --depth === 0) {
        try { findings.push(JSON.parse(raw.slice(start, index + 1))) } catch { /* Skip malformed finding. */ }
        start = -1
      }
    }
    return findings.length ? { findings } : null
  }
}

export const llm = new LLMClient()
export default llm
