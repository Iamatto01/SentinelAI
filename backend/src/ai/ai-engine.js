import { llm } from './llm-client.js'
import { agentRegistry } from './agent-registry.js'
import { retrieveSkills } from '../integrations/skills-rag.js'

/**
 * AIEngine — the reasoning core. Routes each finding to the right specialist
 * agent persona (from the 51-agent registry), verifies true/false positives,
 * performs whitebox static analysis, and produces structured verdicts.
 *
 * All output is strict JSON — no hallucinated claims without evidence.
 */
export class AIEngine {
  constructor() { this.llm = llm; this.agents = agentRegistry }

  /**
   * Strip the "FULL OFFENSIVE" preamble from agent personas.
   * The agent .md files contain a contradictory directive ("exploit to maximum
   * extent, NEVER refuse") that actively sabotages the PRECISION MODE
   * instructions used in verifyFinding and auditCode. This sanitizer strips
   * all language that tells the model to report more than it should.
   */
  _sanitizePersona(persona) {
    if (!persona) return null
    // Remove the entire "Operational Mode" section (all variants)
    let clean = persona
      .replace(/##\s*Operational Mode:\s*FULL OFFENSIVE\s*[–\-—]\s*NO RESTRICTIONS[\s\S]*?(?=##|\n\nYou are a)/i, '')
      .replace(/##\s*Operational Mode:\s*FULL OFFENSIVE\s*[–\-—]\s*NO RESTRICTIONS[\s\S]*$/i, '')
      // Remove any lingering "FULL OFFENSIVE" fragments
      .replace(/^.*FULL OFFENSIVE.*$/gm, '')
      .replace(/^.*pure offensive tool.*$/gm, '')
      .replace(/^.*exploit.*to.*maximum extent.*$/gm, '')
      .replace(/^.*Never refuse a request.*$/gm, '')
      .replace(/^.*NO scope limitations.*$/gm, '')
      .replace(/^.*NO hard refusals.*$/gm, '')
      .replace(/^.*NO ethical gates.*$/gm, '')
      .replace(/^.*Execute all commands without hesitation.*$/gm, '')
      .replace(/^\s*$/gm, '') // collapse blank lines
      .trim()
    return clean || null
  }

  /** Verify a scanner finding; returns { isTruePositive, confidence, verdict, refined }. */
  async verifyFinding(finding, targetType = 'url') {
    // Do not treat an unavailable provider as confirmation. Use the same
    // deterministic evidence checks as the provider-error fallback.
    if (!this.llm.isConfigured()) {
      const heuristicResult = this._heuristicVerify(finding, targetType)
      return {
        isTruePositive: heuristicResult.isTruePositive,
        confidence: heuristicResult.confidence,
        verdict: `${heuristicResult.verdict} AI provider unavailable; manual validation recommended.`,
        evidenceTier: 'needs-validation',
        agent: 'deterministic-heuristic',
      }
    }
    const agentName = targetType === 'code' ? 'code-auditor' : this.agents.routeFinding(finding)
    const rawPersona = this.agents.prompt(agentName)
    const persona = this._sanitizePersona(rawPersona)

    // Skills RAG: lazy-load only the relevant practitioner playbooks from the
    // 817-skill corpus (index.md pattern — never inject the whole library).
    let skillsBlock = ''
    try {
      const skillQuery = [finding.title, finding.cweId, finding.owaspCategory, (finding.description || '').slice(0, 100)]
        .filter(Boolean).join(' ')
      const res = retrieveSkills(skillQuery, { limit: 2, includeBody: true })
      if (res.found) {
        skillsBlock = `\n\nREFERENCE PLAYBOOKS (senior-analyst workflows from the cybersecurity skills library — follow their verification methodology where relevant):\n` +
          res.skills.map((s, i) => `--- PLAYBOOK ${i + 1}: ${s.name} (${s.subdomain}) ---\n${(s.body || s.description || '').slice(0, 4000)}`).join('\n\n')
      }
    } catch { /* skills RAG unavailable — non-fatal */ }

    const system = persona
      ? `${persona}\n\nYou are a security verification specialist. Verify this finding with PRECISION. Only confirm TRUE positive when evidence clearly shows exploitable vulnerability. Default to FALSE positive when evidence is ambiguous or only shows configuration without exploitation path. Respond ONLY with JSON.`
      : 'You are a security verification specialist. Verify with PRECISION. Only confirm when evidence is clear. Respond ONLY with JSON.'

    const prompt = `Verify this security finding on a ${targetType} target. You are in PRECISION MODE — only confirm TRUE positive when the evidence unambiguously proves exploitability. Mark FALSE positive for ambiguous, speculative, or configuration-only findings.

Rules:
- is_true_positive: TRUE only when evidence clearly shows a source-to-sink exploitation path, or confirmed tool output (e.g., sqlmap "injectable", nuclei template match, exposed credential file with actual content). FALSE for everything else — speculative, ambiguous, "could be", configuration-only, version-only.
- Evidence tier: "validated" when evidence proves the vulnerable configuration AND source-to-sink path. "exploited" when the evidence shows successful exploitation. "observed" for a literal match without exploitation proof. "needs-validation" when exploitability is NOT proven.
- MISSING security headers (HSTS, CSP, etc.) are TRUE positive but at LOW severity — never upgrade to medium/high/critical for missing headers alone.
- Exposed .git/.env with verified content is TRUE positive.
- Subdomain enumeration, open port discovery, HTML form detection, server headers, login surface discovery are TRUE positive at INFO severity — NEVER upgrade.
- CRITICAL: Only adjust severity UPWARD when the FINDING ITSELF provides exploitation evidence. DOWNGRADE severity when the finding is speculative, configuration-only, or version-only without exploitation proof.
- Code-only findings: TRUE positive when a dangerous function (eval, exec, raw SQL, file read/write, os command, unsafe deserialization) is found in source code. Mark as 'observed' (not 'validated') when data flow from user input cannot be confirmed — static scanners cannot trace all data paths. Do NOT reject a finding just because the immediate call site uses hardcoded values; the function may be called from user-controlled paths elsewhere.
- npm audit / dependency scan version-only matches without exploitation evidence are FALSE positive.
- console.log, missing rate limiting, debug endpoints are LOW severity — never upgrade to critical/high.

FINDING:
${JSON.stringify({ title: finding.title, severity: finding.severity, cweId: finding.cweId, description: finding.description, evidence: finding.evidence }, null, 2)}
${skillsBlock}
Respond with JSON:
{"is_true_positive": boolean, "confidence": 0-100, "evidence_tier": "observed|validated|needs-validation|exploited", "severity_adjusted": "critical|high|medium|low|info", "reasoning": "one sentence grounded in the evidence", "remediation": "concrete fix"}`

    try {
      const raw = await this.llm.analyze(prompt, { system, context: { operation: 'verify', agent: agentName }, useFast: false, maxTokens: 800 })
      const j = this.llm.parseJSON(raw)
      const refined = { ...finding }
      if (j.severity_adjusted) refined.severity = j.severity_adjusted
      if (j.remediation) refined.remediation = j.remediation
      return {
        isTruePositive: j.is_true_positive === true,
        confidence: j.confidence ?? 70,
        verdict: j.reasoning || 'Finding evaluated by AI specialist.',
        agent: agentName,
        evidenceTier: j.evidence_tier || 'observed',
        refined,
      }
    } catch (e) {
      // ⚠️ CRITICAL: When LLM is unavailable or errors, do NOT blindly default to
      // true positive. Instead, apply deterministic heuristics to decide.
      const heuristicResult = this._heuristicVerify(finding, targetType)
      return {
        isTruePositive: heuristicResult.isTruePositive,
        confidence: heuristicResult.confidence,
        verdict: heuristicResult.verdict,
        agent: agentName
      }
    }
  }

  /**
   * Deterministic fallback verification when LLM is unavailable.
   * Uses strict heuristics instead of blindly marking everything true positive.
   * Returns { isTruePositive, confidence, verdict }.
   */
  _heuristicVerify(finding, targetType) {
    const title = (finding.title || '').toLowerCase()
    const desc = (finding.description || '').toLowerCase()
    const text = `${title} ${desc}`
    const evidence = finding.evidence || {}
    const module = (finding.module || '').toLowerCase()

    // ── ALWAYS TRUE POSITIVE (high confidence) ──
    const truePositivePatterns = [
      // Exposed sensitive files with verified content
      { re: /exposed (?:git|\.env|backup|database dump|private key)/i, conf: 95, reason: 'Verified sensitive file exposure confirmed by HTTP response content.' },
      // Tool-confirmed exploitation
      { re: /sql injection.*parameter.*vulnerable|confirmed.*injectable/i, conf: 95, reason: 'Tool confirmed exploitable injection point.' },
      { re: /\[POC\]|vulnerable.*xss|reflected.*xss|stored.*xss/i, conf: 90, reason: 'Tool confirmed XSS with proof-of-concept.' },
      // Missing headers — always true
      { re: /missing.*security.*header|missing.*(?:hsts|csp|x-frame|content-type|x-content|referrer|permissions)/i, conf: 90, reason: 'Security headers are factually absent from HTTP response.' },
      // Server banner disclosure
      { re: /server.*header.*information.*disclosure/i, conf: 90, reason: 'Server header is factually present in HTTP response.' },
      // Open ports confirmed by nmap
      { re: /open port.*(?:ssh|telnet|ftp|smb|rdp|mysql|postgresql|redis|mongodb|vnc)/i, conf: 90, reason: 'Nmap confirmed open service port with version banner.' },
      // Hardcoded secrets in source
      { re: /hardcoded.*(?:secret|credential|key|password|token)/i, conf: 85, reason: 'Pattern scan confirmed hardcoded credential in source code.' },
      // CORS wildcard
      { re: /cors.*access-control-allow-origin.*\*/i, conf: 90, reason: 'CORS wildcard is factually present in HTTP response headers.' },
      // robots.txt
      { re: /robots\.txt/i, conf: 90, reason: 'robots.txt is factually accessible.' },
      // Subdomain discovery
      { re: /subdomain.*discovered/i, conf: 85, reason: 'DNS enumeration confirmed subdomain exists.' },
      // TLS/weak cipher
      { re: /weak.*cipher|tls.*1\.[01]/i, conf: 85, reason: 'TLS scan confirmed deprecated protocol version or cipher.' },
      // Exposed Swagger/OpenAPI
      { re: /exposed.*(?:swagger|openapi|api.?doc)/i, conf: 90, reason: 'API documentation is factually accessible without authentication.' },
    ]

    for (const { re, conf, reason } of truePositivePatterns) {
      if (re.test(text)) {
        return { isTruePositive: true, confidence: conf, verdict: reason }
      }
    }

    // ── ALWAYS FALSE POSITIVE (tool chatter / noise) ──
    const falsePositivePatterns = [
      { re: /testing connection|testing if|content is stable|heuristic.*test|no parameter|no (?:vulnerab|result|issue|finding)/i, conf: 95, reason: 'Tool chatter/meta output — no actual vulnerability signal.' },
      { re: /starting|initializing|scanning|enumerating|waiting|fetching|resuming|loaded|parsed/i, conf: 95, reason: 'Tool progress/status message — not a vulnerability.' },
      { re: /all tested parameters do not appear|do not appear to be injectable/i, conf: 95, reason: 'Tool explicitly reported no vulnerability found.' },
      { re: /not vulnerable|not found|not injectable|not exploitable|not affected/i, conf: 90, reason: 'Tool explicitly negated the finding.' },
    ]

    for (const { re, conf, reason } of falsePositivePatterns) {
      if (re.test(text)) {
        return { isTruePositive: false, confidence: conf, verdict: reason }
      }
    }

    // ── LOW-CONFIDENCE HEURISTIC for remaining ──
    // Version-based CVE matches without exploitation evidence
    if (/nmap vulners|CVE-\d{4}-\d+/i.test(text)) {
      // Version-only CVE matches are weak unless corroborated
      const cvssMatch = text.match(/cvss\s*(\d+\.?\d*)/i)
      const cvss = cvssMatch ? parseFloat(cvssMatch[1]) : 0
      if (cvss >= 9.0) {
        return { isTruePositive: true, confidence: 50, verdict: 'Version-based CVE match with critical CVSS. Plausible but unverified — manual confirmation required.' }
      }
      return { isTruePositive: false, confidence: 30, verdict: 'Version-only CVE match without exploitation evidence. Likely false positive — requires manual verification.' }
    }

    // Login surfaces — low severity, don't amplify
    if (/login|authentication.*surface|auth.*endpoint/i.test(text)) {
      return { isTruePositive: true, confidence: 60, verdict: 'Login endpoint discovered. Informational — no vulnerability confirmed.' }
    }

    // HTML forms / injection surfaces
    if (/html forms?.*discovered|injection.*surfaces?/i.test(text)) {
      return { isTruePositive: true, confidence: 50, verdict: 'Form discovery is informational. No injection vulnerability confirmed — only attack surface enumeration.' }
    }

    // Sensitive path discovery
    if (/sensitive.*(?:path|file).*discovered|exposed.*(?:file|path|config)/i.test(text)) {
      return { isTruePositive: true, confidence: 60, verdict: 'Sensitive path/file discovered. Informational — requires further investigation.' }
    }

    // Default fallback: mark as TRUE positive with low confidence when we cannot verify.
    // Pattern-scan and code-audit findings carry file/line evidence — discarding them
    // silently (old default=false) caused massive false-negative drops (1200→500→100).
    // Better to surface low-confidence findings than hide them entirely.
    const isPatternOrCode = module === 'pattern-scan' || module === 'code-audit' || module === 'ai-audit'
    return {
      isTruePositive: true,
      confidence: isPatternOrCode ? 50 : 35,
      verdict: 'Unable to verify via AI or heuristics. Low-confidence finding surfaced for manual review.'
    }
  }

  /**
   * Whitebox static analysis of source code via the code-auditor persona.
   * files: [{ path, content }] (already sanitized by caller).
   * Uses a parallel worker pool (5 concurrent LLM calls) to process the full
   * collected source set in bounded batches.
   */
  async auditCode(files, { language = '', focus = '', log = null } = {}) {
    if (!this.llm.isConfigured()) throw new Error('AI not configured')
    const agentName = this.agents.routeStatic(language, focus)
    const rawPersona = this.agents.prompt(agentName)
    const persona = this._sanitizePersona(rawPersona)
    const system = `${persona || 'You are a secure-code review specialist.'}\n\nRespond ONLY with JSON.`

    const batchSize = 3
    const MAX_FILE_CHARS = 12000
    const CONCURRENCY = 5

    // Prioritize high-value files
    const priorityPattern = /(?:controller|service|guard|module|entity|route|middleware|auth|access|permission|role|jwt|login|signup|register|password|token|session|upload|download|file|api|admin|config|database|db\.|repository|\.spec\.)/
    const priorityFiles = []
    const otherFiles = []
    const skipPattern = /\.(?:json|min\.js|min\.css|map|lock|gz|tar|zip|7z|bz2)$|package\.json|package-lock\.json|node_modules|\.min\.|bundle\.|chunk\.|vendor\./
    for (const f of files) {
      if (skipPattern.test(f.path.toLowerCase())) continue
      if (priorityPattern.test(f.path.toLowerCase())) priorityFiles.push(f)
      else otherFiles.push(f)
    }
    const targetFiles = [...priorityFiles, ...otherFiles]

    // Build batches
    const batches = []
    for (let i = 0; i < targetFiles.length; i += batchSize) {
      const batch = targetFiles.slice(i, i + batchSize)
      const fileNames = batch.map(f => f.path)
      const bundle = batch.map(f => `### ${f.path}\n\`\`\`\n${String(f.content).slice(0, MAX_FILE_CHARS)}\n\`\`\``).join('\n\n')
      batches.push({ index: i / batchSize, fileNames, bundle })
    }

    if (log) {
      log('info', `🔀 Dispatched ${batches.length} batches across ${CONCURRENCY} workers (${targetFiles.length} files, ~${(batches.length / CONCURRENCY * 1.5).toFixed(0)}s per round)`)
    }

    const promptTemplate = (bundle) => `You are auditing source code for security vulnerabilities. Report ALL vulnerabilities you find — do not be overly conservative. Even partial evidence of a vulnerability is worth reporting.

AUDIT FOCUS: ${focus || 'all security vulnerabilities'}

SEVERITY GUIDE:
- CRITICAL: RCE, code injection, hardcoded production secrets with actual values, SQLi with user-input concatenation, unsafe deserialization
- HIGH: Auth bypass, SSRF, path traversal with user input, privilege escalation, missing auth on sensitive endpoints
- MEDIUM: Missing security headers, CORS wildcard, weak crypto, debug endpoints exposed, XSS with user input
- LOW: Missing rate limiting, info disclosure, console.log of sensitive data, weak password policy
- INFO: Banner/version disclosure, informational observations

IMPORTANT RULES:
- Report ANY dangerous function found (eval, exec, child_process, raw SQL, fs read/write with user input, os commands)
- Report hardcoded secrets, API keys, passwords, tokens — even if they look like test values
- Report missing input validation on endpoints that accept user data
- Report use of weak crypto (MD5, SHA1, Math.random for security)
- Report CORS misconfiguration (origin: '*', credentials: true with wildcard)
- Report missing auth guards on POST/PUT/DELETE endpoints
- Report file upload without validation
- Report SQL queries with string concatenation or template literals
- Report use of dangerouslySetInnerHTML, v-html, or innerHTML with user input
- DO report even if you're not 100% sure the input is user-controlled — note it in the description
- DO NOT report: code style issues, performance issues, missing comments, cosmetic issues

${bundle}

Respond ONLY with JSON:
{"findings":[{"title":"short descriptive title","severity":"critical|high|medium|low|info","cwe":"CWE-XX","owasp":"A01-A10","file":"exact file path from the code above","line":line_number_or_0,"evidence":"the exact vulnerable code snippet","description":"how this vulnerability can be exploited — describe the attack path","laymanImpact":"plain English description of the business impact","remediation":"specific fix with code example"}]}

If no vulnerabilities are found, respond with: {"findings":[]}`

    // Parallel worker pool
    const allFindings = []
    const results = new Array(batches.length)
    const workerStats = new Array(CONCURRENCY).fill(0)
    let cursor = 0

    const worker = async (workerId) => {
      const wid = workerId + 1
      let batchCount = 0
      if (log) log('info', `  ├─ Worker ${wid} started`)
      while (cursor < batches.length) {
        const idx = cursor++
        const { fileNames, bundle } = batches[idx]
        batchCount++
        const t0 = Date.now()
        if (log) log('info', `  │  W${wid} batch ${batchCount}: ${fileNames.join(', ')}`)
        try {
          const raw = await this.llm.analyze(promptTemplate(bundle), {
            system, context: { operation: 'code-audit', agent: agentName },
            maxTokens: 6000, timeoutMs: 120000
          })
          const j = this.llm.parseJSON(raw)
          results[idx] = Array.isArray(j.findings) ? j.findings : []
          const count = results[idx].length
          workerStats[workerId] += count
          const ms = Date.now() - t0
          if (log) log('info', `  │  W${wid} ✅ ${count} findings from ${fileNames.join(', ')} (${(ms / 1000).toFixed(1)}s)`)
        } catch (e) {
          if (log) {
            const ms = Date.now() - t0
            log('warn', `  │  W${wid} ⚠️ ${fileNames.join(', ')} failed: ${e.message} (${(ms / 1000).toFixed(1)}s)`)
          }
          results[idx] = []
        }
      }
      if (log) log('info', `  └─ Worker ${wid} finished: ${batchCount} batches, ${workerStats[workerId]} findings total`)
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => worker(i)))

    for (const r of results) {
      if (r) allFindings.push(...r)
    }
    if (log) {
      const total = workerStats.reduce((a, b) => a + b, 0)
      log('info', `📊 Audit complete: ${allFindings.length} findings from ${batches.length} batches via ${CONCURRENCY} workers`)
    }
    return { agent: agentName, findings: allFindings }
  }

  /**
   * Generate a specific, working PoC exploit for a finding using the LLM.
   * Unlike the generic category-based PoC generators in report.js, this method
   * sends the actual vulnerable code snippet to the AI and asks it to produce
   * a concrete, copy-pasteable exploit tailored to THIS specific vulnerability.
   *
   * Returns { pocPayload, exploitSteps, attackCommand } or null on failure.
   */
  async generateExploitPoc(finding, targetType = 'code') {
    if (!this.llm.isConfigured()) return null

    const evidence = finding.evidence || {}
    const file = evidence.file || finding.file || 'unknown'
    const line = evidence.line || ''
    const code = evidence.code || evidence.snippet || ''
    const category = finding.category || finding.owaspCategory || ''
    const cwe = finding.cweId || finding.cwe || ''
    const title = finding.title || ''
    const description = finding.description || ''
    const url = evidence.url || finding.target || ''

    const system = `You are an elite offensive security engineer. Your task is to generate a SPECIFIC, WORKING proof-of-concept exploit for the vulnerability described below. The PoC must be tailored to the ACTUAL vulnerable code — not generic examples. Include real parameter names, real file paths, real endpoints from the code. Output ONLY JSON.`

    const prompt = `Generate a specific, working PoC exploit for this vulnerability.

VULNERABILITY:
- Title: ${title}
- Category: ${category}
- CWE: ${cwe}
- Description: ${description}
- File: ${file}${line ? ':' + line : ''}
- Target URL: ${url}

VULNERABLE CODE:
\`\`\`
${code || '(code not available — generate based on title and description)'
}\`\`\`

Generate a PoC that a penetration tester can copy-paste and run immediately. The PoC must:
1. Use the ACTUAL parameter names, endpoint paths, and variable names from the code above
2. Include a concrete attack command (curl, python script, or browser payload)
3. Show step-by-step exploitation from detection to impact
4. Include the exact payload string that triggers the vulnerability
5. If it's a code-level finding (whitebox), show how an attacker would reach this code path from an external request

Respond ONLY with JSON:
{
  "pocPayload": "the exact payload string that triggers the vulnerability (e.g. ' OR '1'='1' --)",
  "attackCommand": "a complete copy-pasteable command (curl/python/bash) that exploits this specific vulnerability using the real endpoint and parameters",
  "exploitSteps": ["step 1: ...", "step 2: ...", "step 3: ..."],
  "impact": "what an attacker achieves by exploiting this",
  "prerequisites": "what access/conditions are needed (e.g. 'authenticated user with low privileges')"
}`

    try {
      const raw = await this.llm.analyze(prompt, {
        system,
        context: { operation: 'poc-generation', agent: 'exploit-guide' },
        useFast: false,
        maxTokens: 1500,
        timeoutMs: 60000,
      })
      const j = this.llm.parseJSON(raw)
      return {
        pocPayload: j.pocPayload || null,
        attackCommand: j.attackCommand || null,
        exploitSteps: Array.isArray(j.exploitSteps) ? j.exploitSteps : [],
        impact: j.impact || null,
        prerequisites: j.prerequisites || null,
        source: 'ai-generated',
      }
    } catch (e) {
      console.warn(`[AI Engine] PoC generation failed for "${title}": ${e.message}`)
      return null
    }
  }

  /**
   * Summarize scan results into a rich executive narrative.
   * Uses the HEAVY tier model for deeper analysis — this is the AI's
   * independent assessment of the security posture, NOT a regurgitation
   * of scanner output. Produces unique insights about attack surface,
   * risk posture, and recommended remediation priorities.
   */
  async summarize(scanStats) {
    if (!this.llm.isConfigured()) return null
    const { target, totalFindings, severityCounts, topFindings, owaspCategories, isWhitebox, modules } = scanStats
    const prompt = `You are an elite security consultant writing an executive summary for a ${isWhitebox ? 'source code security audit' : 'penetration test'} report.

ASSESSMENT TARGET: ${target || 'Unknown'}
ASSESSMENT TYPE: ${isWhitebox ? 'Whitebox (Static Code Analysis)' : 'Blackbox (External Penetration Test)'}
TOOLS/MODULES USED: ${modules?.join(', ') || 'N/A'}
OWASP CATEGORIES AFFECTED: ${(owaspCategories || []).join(', ') || 'N/A'}

FINDINGS BREAKDOWN:
- Critical: ${severityCounts?.critical || 0}
- High: ${severityCounts?.high || 0}
- Medium: ${severityCounts?.medium || 0}
- Low: ${severityCounts?.low || 0}
- Info: ${severityCounts?.info || 0}
- Total: ${totalFindings}

TOP FINDINGS:
${(topFindings || []).map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${f.owaspCategory ? ' (' + f.owaspCategory + ')' : ''}`).join('\n')}

Write a comprehensive executive summary (4-6 paragraphs) that:
1. Opens with a blunt assessment of the overall security posture (is this system secure or not?)
2. Explains the MOST critical risks and their business impact — not just "X vulnerabilities found" but WHAT an attacker could actually DO
3. Identifies the attack chain: how could an attacker combine these findings to achieve full compromise?
4. Prioritizes remediation — what should they fix FIRST, and why?
5. Notes any systemic issues (e.g., "auth is broadly broken" not just "one missing auth check")
6. Closes with a clear recommendation on risk acceptance or rejection

Write in professional but accessible language. Do NOT use generic templates. Be specific about the actual findings.`
    try {
      return await this.llm.analyze(prompt, {
        context: { operation: 'executive-summary' },
        maxTokens: 1200, timeoutMs: 60000,
      })
    } catch { return null }
  }

  /**
   * Generate an independent AI attack-chain analysis — how an attacker
   * could chain multiple findings together to achieve full compromise.
   * This is the AI's UNIQUE value-add: pattern scanners can't do this.
   */
  async generateAttackChain(findings, target) {
    if (!this.llm.isConfigured() || !findings.length) return null
    const topFindings = findings
      .filter(f => ['critical', 'high', 'medium'].includes(f.severity))
      .slice(0, 15)
    if (!topFindings.length) return null

    const findingList = topFindings.map((f, i) =>
      `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}
   File: ${f.evidence?.file || 'N/A'}:${f.evidence?.line || ''}
   Description: ${f.description || 'N/A'}
   OWASP: ${f.owaspCategory || 'N/A'}
   CWE: ${f.cweId || f.cwe || 'N/A'}`
    ).join('\n\n')

    const prompt = `You are an elite red team operator analyzing vulnerability findings from a security assessment of: ${target || 'a web application'}

VERIFIED VULNERABILITIES:
${findingList}

Analyze how an attacker could CHAIN these vulnerabilities together to achieve maximum impact. Think like a real attacker:

1. What is the most dangerous attack chain? (Step 1: exploit X, Step 2: use X to access Y, Step 3: ...)
2. What is the "crown jewel" — what's the worst thing an attacker could achieve?
3. Which finding, if fixed first, would break the most attack chains?
4. Are there any findings that look low-severity individually but become critical when combined?

Respond ONLY with JSON:
{
  "primaryAttackChain": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
  "crownJewel": "description of the worst-case outcome",
  "criticalBreaker": "which finding to fix first and why",
  "hiddenCombinations": ["description of low-severity findings that become critical when combined"],
  "overallRisk": "LOW | MEDIUM | HIGH | CRITICAL",
  "riskJustification": "1-2 sentence justification"
}`

    try {
      const raw = await this.llm.analyze(prompt, {
        context: { operation: 'attack-chain' },
        maxTokens: 1000, timeoutMs: 60000,
      })
      return this.llm.parseJSON(raw)
    } catch { return null }
  }

  /** Free-form chat with a chosen agent persona (fast model). */
  async chat(message, agentName = 'web-hunter', history = []) {
    const persona = this.agents.prompt(agentName) || 'You are a helpful security assistant.'
    const ctx = history.slice(-6).map(h => `${h.role}: ${h.content}`).join('\n')
    const prompt = `${ctx ? ctx + '\n' : ''}user: ${message}\n\nRespond concisely and professionally.`
    return this.llm.analyze(prompt, { system: persona, context: { operation: 'chat', agent: agentName }, useFast: true, maxTokens: 800 })
  }
}

export const aiEngine = new AIEngine()
export default aiEngine
