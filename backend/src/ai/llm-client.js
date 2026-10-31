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
    // { providerId: { ok: boolean, reason: string, at: number } } — see #isLive()
    this.healthCache = new Map()
    this.healthTtlMs = Number(process.env.AI_PROBE_TTL_MS || 600000)
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
        const probed = await this.#probeCompletion(p)
        this.healthCache.set(p.id, { ok: probed.online, reason: probed.reason, at: Date.now() })
        return {
          id: p.id, name: p.name, role: p.role, model: p.model, baseUrl: p.baseUrl,
          online: probed.online,
          status: probed.online ? 'ONLINE' : 'OFFLINE',
          statusCode: probed.statusCode ?? null,
          reason: probed.reason,
        }
      } catch (e) {
        this.healthCache.set(p.id, { ok: false, reason: e.message, at: Date.now() })
        return {
          id: p.id, name: p.name, role: p.role, model: p.model, baseUrl: p.baseUrl,
          online: false,
          status: 'OFFLINE',
          statusCode: null,
          reason: e.name === 'AbortError' ? 'Connection timeout during completion probe' : e.message,
        }
      }
    }))
  }

  /**
   * Real liveness probe — a chat completion, not a `/models` listing.
   *
   * `GET /models` returns 200 for any key that authenticates, which says nothing
   * about whether the gateway can run inference. A reachable-but-broken relay
   * therefore reported ONLINE and stayed at the head of every fallback chain,
   * poisoning results before any working provider was tried. The honest test is
   * the thing we actually need: send a tiny prompt and inspect the answer.
   */
  async #probeCompletion(p) {
    const baseUrl = String(p.baseUrl || '').replace(/\/$/, '')
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), Number(process.env.AI_PROBE_TIMEOUT_MS || 12000))
    let res
    try {
      res = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${p.key}`,
          'Content-Type': 'application/json',
          ...(p.id === 'openrouter' ? { 'HTTP-Referer': 'https://sentinelai.studio', 'X-Title': 'FYP2 Sentinel AI' } : {}),
        },
        body: JSON.stringify({
          model: p.model,
          messages: [
            { role: 'system', content: 'Reply with compact JSON only. No prose.' },
            { role: 'user', content: 'Return {"ok": true}' },
          ],
          temperature: 0,
          max_tokens: 64,
        }),
        signal: ctrl.signal,
      })
    } finally {
      clearTimeout(timer)
    }

    if (!res.ok) {
      const detail = await res.text().catch(() => '')
      const reason = res.status === 401 || res.status === 403
        ? 'API Key Invalid or Unauthorized'
        : res.status === 429
          ? 'Rate Limited / Quota Exceeded'
          : `HTTP Error ${res.status}${detail ? `: ${detail.slice(0, 160)}` : ''}`
      return { online: false, statusCode: res.status, reason }
    }

    const data = await res.json().catch(() => null)
    const text = this.#textFrom(data)
    if (!text) return { online: false, statusCode: res.status, reason: 'Reachable but returned an empty completion' }
    if (!this.#looksRelevant(text)) {
      return {
        online: false,
        statusCode: res.status,
        reason: `Reachable but ignored the prompt (echoed "${text.slice(0, 60).replace(/\s+/g, ' ')}") — gateway is not serving this model`,
      }
    }
    return { online: true, statusCode: res.status, reason: 'Inference verified against a live completion probe' }
  }

  /**
   * Does a probe reply reflect the question we actually asked?
   * A gateway with no working upstream answers 200 with a canned sentence. We
   * asked for an object, so an honest answer parses as JSON or echoes the JSON
   * vocabulary. Anything else means the endpoint is a placeholder.
   */
  #looksRelevant(text) {
    if (!String(text || '').trim()) return false
    if (this.#looksLikeJson(text)) return true
    return /\b(ok|true|yes|json|object|return)\b/i.test(String(text))
  }

  /** Cached liveness for a provider id. Unknown or expired entries stay usable. */
  #isLive(id) {
    const entry = this.healthCache.get(id)
    if (!entry) return true
    if (Date.now() - entry.at > this.healthTtlMs) return true
    return entry.ok
  }

  /** Record a runtime failure so subsequent calls skip this provider. */
  #markDead(id, reason) {
    this.healthCache.set(id, { ok: false, reason: String(reason || 'failed').slice(0, 200), at: Date.now() })
  }

  /**
   * Pull the assistant text out of a chat-completion payload.
   * Some providers (and reasoning models that hit the token cap) return
   * `content: null` with the answer stranded in a `reasoning` field — reading
   * only `content` silently turns a usable reply into "provider failure".
   */
  #textFrom(data) {
    const message = data?.choices?.[0]?.message ?? {}
    const direct = typeof message.content === 'string' ? message.content.trim() : ''
    if (direct) return direct
    const reasoning = typeof message.reasoning === 'string' ? message.reasoning.trim() : ''
    return reasoning
  }

  /**
   * `analyze` with a JSON-output contract.
   *
   * Free-tier models routinely narrate their reasoning instead of emitting the
   * requested object, and reasoning models burn the token budget mid-thought.
   * Rather than hand prose back to a caller that will fail to parse it, retry
   * once with a clipped prompt plus the assistant turn pre-seeded (forces the
   * model straight into the object), then escalate to the other tier, then fall
   * back to extracting whatever object is embedded in the prose.
   */
  async analyzeJSON(prompt, options = {}) {
    const wantFast = options.useFast === true

    const first = await this.analyze(prompt, options)
    if (this.#looksLikeJson(first)) return first

    // Reasoning models narrate at length and hit the token cap before the
    // object. A clipped retry costs a fraction of the first call and usually
    // lands the answer; the prefill makes a prose continuation impossible for
    // chat-completion models that honour an assistant turn.
    const concise = this.#concisePrompt(prompt)
    const forced = await this.analyze(concise, {
      ...options,
      prefill: '{',
      maxTokens: Math.min(Number(options.maxTokens) || 800, 900),
    }).catch(() => null)
    if (forced && this.#looksLikeJson('{' + forced)) return '{' + forced
    if (forced && this.#looksLikeJson(forced)) return forced

    const escalated = await this.analyze(concise, {
      ...options,
      useFast: !wantFast,
      prefill: '{',
      maxTokens: Math.min(Number(options.maxTokens) || 800, 900),
    }).catch(() => null)
    if (escalated && this.#looksLikeJson('{' + escalated)) return '{' + escalated
    if (escalated && this.#looksLikeJson(escalated)) return escalated

    // Last resort: scrape the first balanced object/array out of the prose.
    for (const candidate of [first, forced, escalated]) {
      const scraped = this.#scrapeJson(candidate)
      if (scraped) return scraped
    }
    return first
  }

  /**
   * Shrink a JSON-contract prompt to the essentials for a retry.
   *
   * Long reference playbooks are useful context on the first attempt but they
   * are what pushes a reasoning model into narration — on the retry the
   * contract matters more than the reading material. The FINDING block and the
   * response contract must survive: a retry that drops the evidence produces a
   * confident "cannot assess" verdict, which is a false negative dressed up as
   * an answer.
   */
  #concisePrompt(prompt) {
    let s = String(prompt || '')
    // Drop retrieved reference playbooks (bulk of the tokens, least of the signal).
    s = s.replace(/\n*REFERENCE PLAYBOOKS[\s\S]*?(?=Respond with JSON|$)/i, '\n\n')
    s = s.replace(/---\s*PLAYBOOK \d+[\s\S]*?(?=---\s*PLAYBOOK \d+|Respond with JSON|$)/gi, '')
    s = s.replace(/\n{3,}/g, '\n\n').trim()
    if (s.length <= 6000) return s

    // Still large: keep the opening instructions, the finding, and the contract.
    const idx = s.search(/FINDING:/i)
    const contractAt = s.search(/Respond with JSON/i)
    const head = s.slice(0, Math.min(idx > -1 ? idx : 1200, 1200))
    const finding = idx > -1 ? s.slice(idx, contractAt > idx ? contractAt : idx + 3000) : ''
    const contract = contractAt > -1 ? s.slice(contractAt) : 'Respond with JSON only. No prose, no markdown.'
    return `${head}\n${finding}\n${contract}`.slice(0, 6000)
  }

  /**
   * Extract the first balanced JSON object/array from free text.
   * A model that wraps the answer in "Here is the JSON:" is still correct — it
   * is only misformatted, so salvage it instead of discarding the verdict.
   */
  #scrapeJson(text) {
    const s = String(text || '')
    for (let i = 0; i < s.length; i++) {
      const ch = s[i]
      if (ch !== '{' && ch !== '[') continue
      const close = ch === '{' ? '}' : ']'
      let depth = 0, quoted = false, escaped = false
      for (let j = i; j < s.length; j++) {
        const c = s[j]
        if (quoted) {
          if (escaped) escaped = false
          else if (c === '\\') escaped = true
          else if (c === '"') quoted = false
          continue
        }
        if (c === '"') { quoted = true; continue }
        if (c === ch) depth++
        else if (c === close) {
          depth--
          if (depth === 0) {
            const slice = s.slice(i, j + 1)
            if (this.#looksLikeJson(slice)) return slice
            break
          }
        }
      }
    }
    return null
  }

  /** Cheap test for "this reply contains an object/array the caller can parse". */
  #looksLikeJson(text) {
    const s = String(text || '')
    if (!s.trim()) return false
    try {
      this.parseJSON(s)
      return true
    } catch {
      return false
    }
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
        if (this.openrouter?.key && this.#isLive('openrouter')) {
          try {
            const res = await this.#openrouter(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] OpenRouter (fast) returned empty text, trying Groq...')
          } catch (e1) {
            lastError = e1
            this.#markDead('openrouter', e1.message)
            console.warn(`[AI Engine] OpenRouter (fast) failed (${e1.message}), falling back to Groq...`)
          }
        }

        // 2. Groq free (fast fallback)
        if (this.groq?.key && this.#isLive('groq')) {
          try {
            const res = await this.#groq(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] Groq (fast) returned empty text, falling back to Bandelbanget heavy...')
          } catch (e2) {
            lastError = e2
            this.#markDead('groq', e2.message)
            console.warn(`[AI Engine] Groq (fast) failed (${e2.message}), falling back to Bandelbanget heavy...`)
          }
        }

        // 3. Bandelbanget heavy (last resort for fast tier)
        if (this.bandelbanget?.key && this.#isLive('bandelbanget')) {
          try {
            const res = await this.#bandelbanget(prompt, options)
            if (res && res.trim().length > 0) return res
            this.#markDead('bandelbanget', 'empty completion')
          } catch (e3) {
            lastError = e3
            this.#markDead('bandelbanget', e3.message)
          }
        }
      } else {
        // ── HEAVY TIER: Bandelbanget DeepSeek V4 first, free models as fallback ──
        // Used for auditCode — complex reasoning needs DeepSeek V4.

        // 1. Bandelbanget (DeepSeek V4 Pro) — skipped while marked dead by the probe
        if (this.bandelbanget?.key && this.#isLive('bandelbanget')) {
          try {
            const res = await this.#bandelbanget(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] Bandelbanget returned empty text, trying OpenRouter...')
          } catch (e1) {
            lastError = e1
            this.#markDead('bandelbanget', e1.message)
            console.warn(`[AI Engine] Bandelbanget failed (${e1.message}), falling back to OpenRouter...`)
          }
        }

        // 2. OpenRouter free (fallback)
        if (this.openrouter?.key && this.#isLive('openrouter')) {
          try {
            const res = await this.#openrouter(prompt, options)
            if (res && res.trim().length > 0) return res
            console.warn('[AI Engine] OpenRouter returned empty text, trying Groq...')
          } catch (e2) {
            lastError = e2
            this.#markDead('openrouter', e2.message)
            console.warn(`[AI Engine] OpenRouter failed (${e2.message}), falling back to Groq...`)
          }
        }

        // 3. Groq (last resort)
        if (this.groq?.key && this.#isLive('groq')) {
          try {
            const res = await this.#groq(prompt, options)
            if (res && res.trim().length > 0) return res
          } catch (e3) {
            lastError = e3
            this.#markDead('groq', e3.message)
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
    if (options.prefill) messages.push({ role: 'assistant', content: options.prefill })
    
    // Top free models list from OpenRouter — keep to 3 to avoid wasting time
    // on sequential 60s timeouts. Each failing model wastes a full API call.
    const modelsToTry = Array.from(new Set([
      this.openrouter.model,
      'openrouter/free',
      'minimax/minimax-m3.1-flash:free',
      'nvidia/nemotron-3-super-120b-a12b:free',
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
        const text = this.#textFrom(data)
        if (text.length > 0) {
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
    if (options.prefill) messages.push({ role: 'assistant', content: options.prefill })

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
        const text = this.#textFrom(data)
        this.#usage(data.usage, this.bandelbanget.model, options.context)
        if (text.length > 0) return text
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
    if (options.prefill) messages.push({ role: 'assistant', content: options.prefill })

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
      return this.#textFrom(data)
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
