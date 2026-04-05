/**
 * kali_advanced.js — Advanced Kali Linux Tool Integrations
 *
 * Tools: ffuf, wfuzz, feroxbuster, dalfox, xsstrike, xsser,
 *        commix, nosqlmap, ssrfmap, jwt_tool, linkfinder, corsy,
 *        dnsrecon, fierce, amass, sublist3r, arjun, kiterunner,
 *        wapiti, joomscan, droopescan, cmsmap, zap, testssl
 *
 * Enable: EXTERNAL_SCANNER_ENABLED=true
 * Override: ADVANCED_TOOL_LIST=ffuf,dalfox,...
 */

import { randomUUID } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { URL } from 'node:url'

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity || 'info',
    cvss: opts.cvss ?? 0,
    cweId: opts.cweId || 'CWE-200',
    cveIds: opts.cveIds || [],
    status: 'open',
    asset: opts.asset || targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description || '',
    remediation: opts.remediation || '',
    module: 'Advanced Kali Tools',
    aiConfidence: opts.aiConfidence ?? 0.8,
    aiReasoning: opts.aiReasoning || 'Output from specialised Kali Linux security tool.',
    evidence: opts.evidence || {},
  }
}

function isToolAvailable(tool) {
  try {
    const r = spawnSync('which', [tool], { encoding: 'utf8' })
    return r.status === 0 && Boolean(r.stdout?.trim())
  } catch { return false }
}

function runCommand(cmd, args, timeoutMs = 120_000) {
  return new Promise(resolve => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false })
    let stdout = '', stderr = ''
    const to = setTimeout(() => { try { child.kill('SIGKILL') } catch {} ; resolve({ timedOut: true, stdout, stderr, code: null }) }, timeoutMs)
    child.stdout.on('data', d => { stdout += String(d) })
    child.stderr.on('data', d => { stderr += String(d) })
    child.on('close', code => { clearTimeout(to); resolve({ timedOut: false, stdout, stderr, code }) })
    child.on('error', err => { clearTimeout(to); resolve({ timedOut: false, stdout, stderr: String(err.message), code: null }) })
  })
}

function cap(str, bytes = 60_000) {
  if (!str) return ''
  return str.length > bytes ? str.substring(0, bytes) + '\n…[truncated]' : str
}

function extractCVEs(text = '') {
  const m = text.match(/CVE-\d{4}-\d{4,7}/gi) || []
  return [...new Set(m.map(c => c.toUpperCase()))]
}

// ---------------------------------------------------------------------------
// Tool: ffuf — fast web fuzzer
// ---------------------------------------------------------------------------
async function runFfuf(targetUrl, onFinding, onLog) {
  const wordlist = process.env.FFUF_WORDLIST
    || '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt'
    || '/usr/share/wordlists/dirb/common.txt'

  onLog('info', `ffuf: recursive directory fuzzing (${wordlist})`)

  const out = await runCommand('ffuf', [
    '-u', `${targetUrl}/FUZZ`, '-w', wordlist,
    '-mc', '200,204,301,302,307,401,403,405',
    '-fc', '404', '-c', '-of', 'json', '-o', '/tmp/ffuf_sentinelai.json',
    '-t', '40', '-p', '0.1',
    '-recursion', '-recursion-depth', '2',
    '-e', '.php,.asp,.aspx,.jsp,.bak,.sql,.zip,.conf,.env,.txt,.xml,.json,.yaml',
  ], 180_000)

  let results = []
  try {
    const { readFileSync } = await import('node:fs')
    results = JSON.parse(readFileSync('/tmp/ffuf_sentinelai.json', 'utf8')).results || []
  } catch {
    results = (out.stdout || '').split('\n')
      .filter(l => /\[Status:\s*\d+/.test(l))
      .slice(0, 100)
      .map(l => ({ url: l.match(/[^\s]+/)?.[0] || '', status: parseInt(l.match(/Status:\s*(\d+)/)?.[1] || '0') }))
  }

  if (!results.length) { onLog('info', 'ffuf: no results'); return }

  const sensitive = results.filter(r => /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|private|staging|dev\//i.test(String(r.url || r.input?.FUZZ || '')))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `FFUF: ${sensitive.length} sensitive endpoint(s) found`,
      severity: 'high', cvss: 7.5, cweId: 'CWE-548',
      description: `Recursive fuzzing found sensitive paths: ${sensitive.slice(0, 5).map(r => r.url || r.input?.FUZZ).join(', ')}`,
      remediation: 'Remove or restrict sensitive files. Block with web server config.',
      aiConfidence: 0.88,
      evidence: { type: 'list', label: 'ffuf sensitive', data: sensitive.slice(0, 30).map(r => JSON.stringify(r)).join('\n') },
    }, targetUrl))
  }

  const byStatus = results.reduce((a, r) => { a[r.status] = (a[r.status] || 0) + 1; return a }, {})
  onFinding(makeFinding({
    title: `FFUF: ${results.length} endpoint(s) found (${Object.entries(byStatus).map(([s, n]) => `${n}×${s}`).join(', ')})`,
    severity: 'info', cvss: 0, cweId: 'CWE-548',
    description: `FFUF recursive fuzzing found ${results.length} paths.`,
    remediation: 'Audit all discovered paths. Disable directory listing.',
    aiConfidence: 0.82,
    evidence: { type: 'raw', label: 'ffuf results', data: results.slice(0, 50).map(r => JSON.stringify(r)).join('\n') },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: wfuzz — web brute-force and fuzzing
// ---------------------------------------------------------------------------
async function runWfuzz(targetUrl, onFinding, onLog) {
  const wordlist = process.env.WFUZZ_WORDLIST || '/usr/share/wordlists/dirb/common.txt'
  onLog('info', `wfuzz: content discovery (${wordlist})`)

  const out = await runCommand('wfuzz', [
    '-c',
    '-z', `file,${wordlist}`,
    '--hc', '404',
    `${targetUrl.replace(/\/+$/, '')}/FUZZ`,
  ], 180_000)

  const lines = (out.stdout || '')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)

  const hits = lines.filter(l => /^\d{6,9}:\s+\d{3}\s+/i.test(l))
  if (!hits.length) return

  const sensitive = hits.filter(l => /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|private|debug|internal/i.test(l))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Wfuzz: ${sensitive.length} sensitive endpoint(s) discovered`,
      severity: 'high', cvss: 7.5, cweId: 'CWE-548',
      description: `Wfuzz found potentially sensitive resources: ${sensitive.slice(0, 5).join(' | ')}`,
      remediation: 'Restrict access to sensitive paths and remove obsolete files from public web root.',
      aiConfidence: 0.86,
      evidence: { type: 'raw', label: 'wfuzz sensitive hits', data: sensitive.slice(0, 50).join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `Wfuzz: ${hits.length} endpoint(s) found`,
    severity: 'info', cvss: 0, cweId: 'CWE-548',
    description: `Wfuzz discovered ${hits.length} non-404 endpoint(s).`,
    remediation: 'Review discovered endpoints and remove or protect unnecessary resources.',
    aiConfidence: 0.8,
    evidence: { type: 'raw', label: 'wfuzz output', data: hits.slice(0, 80).join('\n') },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: feroxbuster — recursive content discovery
// ---------------------------------------------------------------------------
async function runFeroxbuster(targetUrl, onFinding, onLog) {
  const wordlist = process.env.FEROX_WORDLIST
    || '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt'
    || '/usr/share/wordlists/dirb/common.txt'

  onLog('info', 'feroxbuster: recursive content discovery')

  const out = await runCommand('feroxbuster', [
    '-u', targetUrl, '-w', wordlist, '-d', '3', '-t', '30',
    '--status-codes', '200,204,301,302,307,401,403', '--filter-status', '404',
    '-q', '--no-state', '-x', 'php,asp,aspx,jsp,bak,sql,conf,env',
  ], 180_000)

  const lines = (out.stdout || '').split('\n').filter(l => l.trim() && /http/i.test(l))
  if (!lines.length) return

  const sensitive = lines.filter(l => /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|credentials|private|phpmyadmin|panel/i.test(l))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Feroxbuster: ${sensitive.length} sensitive resource(s)`,
      severity: 'high', cvss: 7.5, cweId: 'CWE-548',
      description: `Feroxbuster found: ${sensitive.slice(0,5).join(' | ')}`,
      remediation: 'Remove or restrict sensitive resources.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'feroxbuster sensitive', data: sensitive.slice(0, 50).join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `Feroxbuster: ${lines.length} URL(s) discovered`,
    severity: 'info', cvss: 0, cweId: 'CWE-548',
    description: `Recursive scan found ${lines.length} accessible paths.`,
    remediation: 'Audit all paths. Restrict unnecessary endpoints.',
    aiConfidence: 0.83,
    evidence: { type: 'raw', label: 'feroxbuster output', data: cap(out.stdout) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: dalfox — XSS parameter scanner
// ---------------------------------------------------------------------------
async function runDalfox(targetUrl, onFinding, onLog) {
  onLog('info', 'dalfox: XSS parameter scanning')
  const out = await runCommand('dalfox', ['url', targetUrl, '--skip-bav', '--no-spinner', '--silence', '--format', 'plain'], 120_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const xssLines    = evidence.split('\n').filter(l => /\[V\]|POC:|XSS|payload/i.test(l))
  const reflectLines = evidence.split('\n').filter(l => /\[R\]|reflected/i.test(l))

  if (xssLines.length > 0) {
    for (const line of xssLines.slice(0, 5)) {
      onFinding(makeFinding({
        title: `Dalfox: XSS confirmed — ${line.substring(0, 100)}`,
        severity: 'high', cvss: 7.2, cweId: 'CWE-79',
        description: `Dalfox verified XSS payload: ${line}`,
        remediation: 'Implement context-aware output encoding. Apply strict Content-Security-Policy. Sanitise all input.',
        aiConfidence: 0.9, aiReasoning: 'Dalfox [V] status = verified payload execution.',
        evidence: { type: 'raw', label: 'dalfox XSS PoC', data: line },
      }, targetUrl))
    }
  } else if (reflectLines.length > 0) {
    onFinding(makeFinding({
      title: `Dalfox: ${reflectLines.length} reflected parameter(s) — potential XSS`,
      severity: 'medium', cvss: 5.5, cweId: 'CWE-79',
      description: `${reflectLines.length} reflected parameters detected. Manual verification recommended.`,
      remediation: 'Sanitise and encode all reflected user input. Apply strict CSP.',
      aiConfidence: 0.75,
      evidence: { type: 'raw', label: 'dalfox reflections', data: reflectLines.slice(0, 20).join('\n') },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: XSStrike — advanced XSS scanner with WAF bypass
// ---------------------------------------------------------------------------
async function runXsstrike(targetUrl, onFinding, onLog) {
  // XSStrike may be installed as 'xsstrike' or called via python3
  const bin = isToolAvailable('xsstrike') ? 'xsstrike' : null
  if (!bin) { onLog('warn', 'xsstrike: not found — install: pip3 install xsstrike or clone from GitHub'); return }

  onLog('info', `xsstrike: advanced XSS scan on ${targetUrl}`)

  const out = await runCommand(bin, [
    '-u', targetUrl,
    '--crawl',
    '--blind',
    '--timeout', '10',
    '--skip',           // skip confirmation prompts
  ], 180_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const vulnLines = evidence.split('\n').filter(l => /vulnerable|payload|parameter|XSS|Payload/i.test(l))
  const bypass    = evidence.split('\n').filter(l => /bypass|WAF|evasion/i.test(l))

  if (vulnLines.length > 0) {
    onFinding(makeFinding({
      title: `XSStrike: ${vulnLines.length} XSS vulnerability/vulnerabilities confirmed`,
      severity: 'high', cvss: 7.5, cweId: 'CWE-79',
      description: `XSStrike confirmed XSS with advanced payload generation: ${vulnLines.slice(0,3).join(' | ')}${bypass.length > 0 ? ` (WAF bypass techniques used)` : ''}`,
      remediation: 'Implement context-aware output encoding. Use a strict CSP. Sanitise all input at server and client side. Consider upgrading WAF signatures.',
      aiConfidence: 0.88, aiReasoning: 'XSStrike uses polyglot payloads and WAF bypass — confirmed findings are high confidence.',
      evidence: { type: 'raw', label: 'xsstrike output', data: cap(evidence) },
    }, targetUrl))
  } else if (/crawl|testing|checking/i.test(evidence)) {
    onLog('info', 'xsstrike: no XSS confirmed')
  }
}

// ---------------------------------------------------------------------------
// Tool: xsser — automated XSS detection framework
// ---------------------------------------------------------------------------
async function runXsser(targetUrl, onFinding, onLog) {
  onLog('info', `xsser: XSS framework scan on ${targetUrl}`)
  const out = await runCommand('xsser', ['--url', targetUrl, '--auto'], 180_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  if (/xss.*found|vulnerable|injection successful|payload successful/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'XSSer: Cross-Site Scripting vulnerability detected',
      severity: 'high', cvss: 7.2, cweId: 'CWE-79',
      description: 'XSSer output indicates at least one exploitable XSS vector.',
      remediation: 'Apply context-aware output encoding, strict CSP, and robust input validation on all reflected/stored inputs.',
      aiConfidence: 0.86,
      evidence: { type: 'raw', label: 'xsser output', data: cap(evidence) },
    }, targetUrl))
  } else if (/xss|injection|payload|parameter/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'XSSer: Potential XSS vectors identified',
      severity: 'medium', cvss: 5.5, cweId: 'CWE-79',
      description: 'XSSer found potential XSS vectors that need manual validation.',
      remediation: 'Manually verify reflected parameters and implement strict output encoding.',
      aiConfidence: 0.72,
      evidence: { type: 'raw', label: 'xsser findings', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: commix — command injection
// ---------------------------------------------------------------------------
async function runCommix(targetUrl, onFinding, onLog) {
  onLog('info', 'commix: OS command injection testing')
  const out = await runCommand('commix', [
    '--url', targetUrl, '--batch', '--level', '2',
    '--output-dir', '/tmp/commix_sentinelai', '--no-logging',
  ], 180_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  if (/vulnerable|injection point|command injection found|exploitable/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'Commix: OS command injection vulnerability confirmed',
      severity: 'critical', cvss: 9.8, cweId: 'CWE-78',
      description: `Commix confirmed command injection at ${targetUrl}. Arbitrary system commands can be executed.`,
      remediation: 'Never pass unsanitised user input to OS commands. Use allow-list validation. Apply WAF.',
      aiConfidence: 0.91,
      evidence: { type: 'raw', label: 'commix output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: nosqlmap — NoSQL injection testing
// ---------------------------------------------------------------------------
async function runNosqlmap(targetUrl, onFinding, onLog) {
  onLog('info', `nosqlmap: NoSQL injection testing on ${targetUrl}`)

  // Try common CLI pattern first; tool variants differ across distributions.
  let out = await runCommand('nosqlmap', ['-u', targetUrl, '--batch'], 180_000)
  let evidence = (out.stdout || out.stderr || '').trim()

  // Fallback run if the previous argument set is unsupported.
  if (/usage:|unrecognized arguments|error:/i.test(evidence) && !/vulnerable|injection/i.test(evidence)) {
    out = await runCommand('nosqlmap', [targetUrl], 120_000)
    evidence = (out.stdout || out.stderr || '').trim()
  }

  if (!evidence) return

  if (/vulnerable|injection point|authentication bypass|exploit/i.test(evidence) && !/not vulnerable/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'NoSQLMap: NoSQL injection vulnerability detected',
      severity: 'critical', cvss: 9.1, cweId: 'CWE-943',
      description: 'NoSQLMap indicates exploitable NoSQL injection behavior.',
      remediation: 'Use strict schema validation, typed queries, and server-side input sanitization. Avoid direct query object construction from user input.',
      aiConfidence: 0.83,
      evidence: { type: 'raw', label: 'nosqlmap output', data: cap(evidence) },
    }, targetUrl))
  } else if (!/usage:|help|examples?/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'NoSQLMap: Scan completed',
      severity: 'info', cvss: 0, cweId: 'CWE-943',
      description: 'NoSQLMap executed. Review raw output for endpoint-specific injection indicators.',
      remediation: 'Manually review API/database query paths even when no automated finding is flagged.',
      aiConfidence: 0.65,
      evidence: { type: 'raw', label: 'nosqlmap output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: ssrfmap — SSRF detection
// ---------------------------------------------------------------------------
async function runSsrfmap(targetUrl, onFinding, onLog) {
  const bin = isToolAvailable('ssrfmap') ? 'ssrfmap' : null
  if (!bin) { onLog('warn', 'ssrfmap: not found — install: pip3 install ssrfmap'); return }

  onLog('info', `ssrfmap: SSRF testing on ${targetUrl}`)

  // ssrfmap needs a request file; we create a minimal GET request
  const reqFile = `/tmp/ssrfmap_req_${Date.now()}.txt`
  try {
    const { writeFileSync } = await import('node:fs')
    const parsedUrl = new URL(targetUrl)
    writeFileSync(reqFile, `GET ${parsedUrl.pathname || '/'} HTTP/1.1\r\nHost: ${parsedUrl.hostname}\r\nUser-Agent: SentinelAI/1.0\r\n\r\n`)
  } catch { onLog('warn', 'ssrfmap: could not create request file'); return }

  const out = await runCommand(bin, [
    '-r', reqFile,
    '-p', 'url',          // test 'url' parameter
    '--level', '2',
  ], 120_000)

  // Cleanup
  try { (await import('node:fs')).unlinkSync(reqFile) } catch {}

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  if (/vulnerable|SSRF found|success|connection to/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'SSRFMap: Server-Side Request Forgery (SSRF) detected',
      severity: 'high', cvss: 8.6, cweId: 'CWE-918',
      description: `SSRFMap confirmed SSRF at ${targetUrl}. Attacker may be able to access internal services, cloud metadata, or internal network resources.`,
      remediation: 'Validate and whitelist allowed outbound URLs. Block cloud metadata IP (169.254.169.254). Restrict outbound network access from the application server.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'ssrfmap output', data: cap(evidence) },
    }, targetUrl))
  } else if (/testing|checking|scanning/i.test(evidence)) {
    onLog('info', 'ssrfmap: no SSRF confirmed')
  }
}

// ---------------------------------------------------------------------------
// Tool: jwt_tool — JWT security testing
// ---------------------------------------------------------------------------
async function runJwtTool(targetUrl, onFinding, onLog) {
  // JWT tool needs an actual token; we attempt to get one from the login endpoint
  // or check for JWT in cookies/headers via a probe request
  onLog('info', 'jwt_tool: probing for JWTs in responses')

  let jwt = null
  try {
    const probe = await fetch(targetUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'SentinelAI/1.0' },
      redirect: 'follow',
      signal: AbortSignal.timeout(10_000),
    })

    // Check Set-Cookie for JWT patterns
    const setCookie = probe.headers.get('set-cookie') || ''
    const authHeader = probe.headers.get('authorization') || ''
    const tokenRE = /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/

    const cookieMatch = setCookie.match(tokenRE)
    const authMatch   = authHeader.match(tokenRE)

    jwt = (cookieMatch || authMatch)?.[0] || null
  } catch { /* ignore */ }

  if (!jwt) {
    onLog('info', 'jwt_tool: no JWT found in HTTP response headers — skipping active tests')

    // Still check if the URL contains a JWT in query params (common mistake)
    const urlTokenMatch = targetUrl.match(/eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/)
    if (urlTokenMatch) {
      onFinding(makeFinding({
        title: 'JWT Token Exposed in URL',
        severity: 'high', cvss: 7.5, cweId: 'CWE-598',
        description: `A JWT token was found embedded in the URL: ${urlTokenMatch[0].substring(0, 50)}… Tokens in URLs are logged in server logs, browser history, and proxies.`,
        remediation: 'Never pass JWTs in URLs. Use Authorization header or secure cookies instead.',
        aiConfidence: 0.95,
        evidence: { type: 'http', label: 'JWT in URL', data: `Token found in: ${targetUrl}` },
      }, targetUrl))
    }
    return
  }

  onLog('info', `jwt_tool: JWT found, running security tests`)

  const bin = isToolAvailable('jwt_tool') ? 'jwt_tool' : null
  if (!bin) {
    // Even without the tool, we can do basic checks
    onFinding(makeFinding({
      title: 'JWT Token Present — Manual Testing Recommended',
      severity: 'info', cvss: 0, cweId: 'CWE-347',
      description: `A JWT was detected in HTTP responses. Manual testing recommended: check for none algorithm, weak secret, alg confusion.`,
      remediation: 'Install jwt_tool for automated JWT security testing. Review JWT configuration for: strong secret, appropriate expiry, alg restriction.',
      aiConfidence: 0.70,
      evidence: { type: 'raw', label: 'JWT detected', data: `Token (partial): ${jwt.substring(0, 80)}…` },
    }, targetUrl))
    return
  }

  // Run jwt_tool checks: none algorithm, JWKS injection, alg confusion
  const checks = [
    { args: [jwt, '-X', 'n'], label: 'None algorithm bypass',    finding: /SUCCESS|VALID|200/i },
    { args: [jwt, '-X', 'a'], label: 'Algorithm confusion (RSA)', finding: /SUCCESS|VALID|200/i },
    { args: [jwt, '-C', '-d', '/usr/share/wordlists/rockyou.txt'], label: 'Weak secret brute-force', finding: /key found|cracked/i },
  ]

  for (const check of checks) {
    const out = await runCommand(bin, check.args, 60_000)
    const evidence = (out.stdout || out.stderr || '').trim()

    if (check.finding.test(evidence)) {
      onFinding(makeFinding({
        title: `jwt_tool: JWT vulnerability — ${check.label}`,
        severity: check.label.includes('brute') ? 'critical' : 'high',
        cvss: check.label.includes('brute') ? 9.8 : 8.1,
        cweId: check.label.includes('brute') ? 'CWE-521' : 'CWE-347',
        description: `jwt_tool confirmed JWT vulnerability: ${check.label}. Attackers may forge arbitrary JWT tokens.`,
        remediation: 'Enforce specific algorithms (RS256/ES256). Never accept "none" algorithm. Use a strong, random secret (>256 bits). Set appropriate expiry (exp claim).',
        aiConfidence: 0.9,
        evidence: { type: 'raw', label: `jwt_tool ${check.label}`, data: cap(evidence) },
      }, targetUrl))
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: linkfinder — JavaScript endpoint discovery
// ---------------------------------------------------------------------------
async function runLinkfinder(targetUrl, onFinding, onLog) {
  // linkfinder.py may be installed as 'linkfinder' or called via python3
  const bin = isToolAvailable('linkfinder') ? 'linkfinder'
            : isToolAvailable('linkfinder.py') ? 'linkfinder.py' : null

  if (!bin) { onLog('warn', 'linkfinder: not found — install: pip3 install linkfinder'); return }

  onLog('info', `linkfinder: JS endpoint discovery on ${targetUrl}`)

  const out = await runCommand(bin, ['-i', targetUrl, '-o', 'cli', '--crawl', '1'], 120_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const endpoints = evidence.split('\n')
    .map(l => l.trim())
    .filter(l => l.startsWith('/') || l.startsWith('http'))

  const sensitiveEndpoints = endpoints.filter(e =>
    /admin|api\/v\d|\/auth|\/login|\/token|\/secret|\/config|\/debug|\/internal|graphql|swagger|openapi/i.test(e)
  )

  if (sensitiveEndpoints.length > 0) {
    onFinding(makeFinding({
      title: `Linkfinder: ${sensitiveEndpoints.length} sensitive endpoint(s) found in JavaScript`,
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: `JavaScript analysis revealed hidden/sensitive endpoints: ${sensitiveEndpoints.slice(0, 8).join(', ')}`,
      remediation: 'Review all discovered endpoints for authentication and authorisation. Remove debug/internal endpoints from production JS.',
      aiConfidence: 0.82,
      evidence: { type: 'list', label: 'linkfinder sensitive', data: sensitiveEndpoints.join('\n') },
    }, targetUrl))
  }

  if (endpoints.length > 0) {
    onFinding(makeFinding({
      title: `Linkfinder: ${endpoints.length} endpoint(s) extracted from JavaScript`,
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: `JavaScript source analysis found ${endpoints.length} API endpoints/paths.`,
      remediation: 'Audit all discovered endpoints. Ensure authentication on all API routes.',
      aiConfidence: 0.80,
      evidence: { type: 'list', label: 'linkfinder all', data: endpoints.slice(0, 100).join('\n') },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: corsy — CORS misconfiguration scanner
// ---------------------------------------------------------------------------
async function runCorsy(targetUrl, onFinding, onLog) {
  const bin = isToolAvailable('corsy') ? 'corsy' : null
  if (!bin) { onLog('warn', 'corsy: not found — install: pip3 install corsy'); return }

  onLog('info', `corsy: CORS misconfiguration scanning on ${targetUrl}`)

  const out = await runCommand(bin, ['-u', targetUrl, '-t', '10', '-d', '1'], 120_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  // Parse corsy output categories
  const categories = {
    'Reflect_Origin':      { t: 'CORS: Origin Reflection', s: 'high',     cvss: 7.5, cwe: 'CWE-942', rem: 'Validate Origin against whitelist.' },
    'Null_Origin':         { t: 'CORS: Null Origin Accepted', s: 'high',   cvss: 7.5, cwe: 'CWE-942', rem: 'Never trust null origin. Remove from CORS whitelist.' },
    'Prefix_Match':        { t: 'CORS: Prefix-matching Origin trusted', s: 'medium', cvss: 5.3, cwe: 'CWE-942', rem: 'Match full origin hostname, not prefix.' },
    'Suffix_Match':        { t: 'CORS: Suffix-matching Origin trusted', s: 'medium', cvss: 5.3, cwe: 'CWE-942', rem: 'Match full origin hostname, not suffix.' },
    'Wildcard_with_creds': { t: 'CORS: Wildcard + credentials (critical)', s: 'critical', cvss: 9.1, cwe: 'CWE-942', rem: 'Never combine wildcard ACAO with Allow-Credentials: true.' },
    'Arbitrary_Reflect':   { t: 'CORS: Arbitrary origin reflected', s: 'high', cvss: 8.0, cwe: 'CWE-942', rem: 'Validate all origins against a strict whitelist.' },
    'Http_trust':          { t: 'CORS: HTTP origins trusted over HTTPS', s: 'medium', cvss: 5.3, cwe: 'CWE-942', rem: 'Reject HTTP origins when site uses HTTPS.' },
  }

  let foundAny = false
  for (const [key, meta] of Object.entries(categories)) {
    if (evidence.includes(key) || new RegExp(key.replace('_', '\\s*'), 'i').test(evidence)) {
      foundAny = true
      onFinding(makeFinding({
        title: meta.t,
        severity: meta.s, cvss: meta.cvss, cweId: meta.cwe,
        description: `Corsy detected CORS misconfiguration: ${meta.t} on ${targetUrl}`,
        remediation: meta.rem + ' Also enforce HTTPS. Set Access-Control-Allow-Origin to specific trusted domains.',
        aiConfidence: 0.88,
        evidence: { type: 'raw', label: 'corsy output', data: cap(evidence) },
      }, targetUrl))
    }
  }

  if (!foundAny && /scanning|testing|checking/i.test(evidence)) {
    onLog('info', 'corsy: no CORS misconfigurations confirmed')
  } else if (!foundAny) {
    onFinding(makeFinding({
      title: 'Corsy: CORS configuration scanned',
      severity: 'info', cvss: 0, cweId: 'CWE-942',
      description: 'Corsy completed CORS misconfiguration scan.',
      remediation: 'Regularly audit CORS policy. Restrict to specific trusted origins.',
      aiConfidence: 0.70,
      evidence: { type: 'raw', label: 'corsy output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: dnsrecon
// ---------------------------------------------------------------------------
async function runDnsrecon(host, targetUrl, onFinding, onLog) {
  onLog('info', `dnsrecon: DNS reconnaissance on ${host}`)
  const out = await runCommand('dnsrecon', [
    '-d', host, '-t', 'std,brt,axfr',
    '-D', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-1000.txt',
  ], 120_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  if (/zone transfer|AXFR.*successful|Transfer succeeded/i.test(evidence)) {
    onFinding(makeFinding({
      title: `DNSRecon: DNS zone transfer (AXFR) possible on ${host}`,
      severity: 'high', cvss: 7.5, cweId: 'CWE-16',
      description: `Zone transfer reveals all DNS records, exposing internal subdomains and IPs.`,
      remediation: 'Restrict AXFR to authorised secondary name servers only.',
      aiConfidence: 0.95,
      evidence: { type: 'raw', label: 'dnsrecon axfr', data: cap(evidence) },
    }, targetUrl))
  }

  const aRecords = evidence.match(/A\s+[\w.\-]+\s+\d+\.\d+\.\d+\.\d+/g) || []
  const uniqueHosts = [...new Set(aRecords.map(r => r.split(/\s+/)[1]))]
  const sensitive   = uniqueHosts.filter(h => /dev\.|staging\.|test\.|internal\.|admin\.|jenkins\.|vpn\./.test(h))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `DNSRecon: ${sensitive.length} sensitive subdomain(s) exposed`,
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: `Sensitive subdomains found: ${sensitive.slice(0, 5).join(', ')}`,
      remediation: 'Remove internal subdomains from public DNS. Use split-horizon DNS.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'dnsrecon sensitive', data: sensitive.join('\n') },
    }, targetUrl))
  }
  if (uniqueHosts.length > 0) {
    onFinding(makeFinding({
      title: `DNSRecon: ${uniqueHosts.length} DNS record(s) enumerated`,
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: `DNS enumeration complete. ${uniqueHosts.length} hosts found.`,
      remediation: 'Review public DNS records. Remove decommissioned services.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'dnsrecon output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: fierce — DNS brute force
// ---------------------------------------------------------------------------
async function runFierce(host, targetUrl, onFinding, onLog) {
  onLog('info', `fierce: DNS brute force on ${host}`)
  const out = await runCommand('fierce', ['--domain', host, '--subdomains', '/usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt'], 90_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const found     = evidence.split('\n').filter(l => /Found:|IP:|Nearby/i.test(l))
  const sensitive = found.filter(l => /dev\.|staging\.|test\.|internal\.|admin\.|vpn\.|jenkins\./.test(l))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Fierce: ${sensitive.length} sensitive subdomain(s) brute-forced`,
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: `Fierce DNS brute-force found sensitive hosts: ${sensitive.slice(0,5).join(' | ')}`,
      remediation: 'Restrict internal subdomains from public DNS.',
      aiConfidence: 0.83,
      evidence: { type: 'raw', label: 'fierce findings', data: sensitive.join('\n') },
    }, targetUrl))
  } else if (found.length > 0) {
    onFinding(makeFinding({
      title: `Fierce: ${found.length} subdomain(s) discovered`,
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: `Fierce discovered ${found.length} DNS entries for ${host}.`,
      remediation: 'Review discovered subdomains for security exposure.',
      aiConfidence: 0.80,
      evidence: { type: 'raw', label: 'fierce output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: amass — OSINT subdomain enumeration
// ---------------------------------------------------------------------------
async function runAmass(host, targetUrl, onFinding, onLog) {
  onLog('info', `amass: OSINT subdomain enumeration for ${host}`)
  const out = await runCommand('amass', ['enum', '-passive', '-d', host, '-timeout', '5'], 360_000)
  const evidence = (out.stdout || '').trim()
  if (!evidence) return

  const subdomains = [...new Set(evidence.split('\n').map(l => l.trim()).filter(l => l && l.includes('.') && !l.startsWith('[')))]
  const sensitive  = subdomains.filter(s => /dev\.|staging\.|test\.|internal\.|admin\.|jenkins\.|db\.|vpn\.|kibana\./.test(s))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Amass: ${sensitive.length} sensitive subdomain(s) via OSINT`,
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: `Amass found sensitive subdomains: ${sensitive.slice(0,5).join(', ')}`,
      remediation: 'Review all subdomains. Harden or decommission unnecessary ones.',
      aiConfidence: 0.88,
      evidence: { type: 'raw', label: 'amass sensitive', data: sensitive.join('\n') },
    }, targetUrl))
  }
  if (subdomains.length > 0) {
    onFinding(makeFinding({
      title: `Amass: ${subdomains.length} subdomain(s) via OSINT`,
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: `Amass passive OSINT found ${subdomains.length} subdomains (CT logs, DNS datasets, APIs).`,
      remediation: 'Monitor CT logs. Audit full attack surface periodically.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'amass subdomains', data: subdomains.slice(0, 100).join('\n') },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: sublist3r — passive subdomain enumeration
// ---------------------------------------------------------------------------
async function runSublist3r(host, targetUrl, onFinding, onLog) {
  onLog('info', `sublist3r: passive subdomain enumeration for ${host}`)
  const out = await runCommand('sublist3r', ['-d', host, '-o', '/tmp/sublist3r_sentinelai.txt'], 180_000)

  let subdomains = []
  try {
    const { readFileSync } = await import('node:fs')
    subdomains = readFileSync('/tmp/sublist3r_sentinelai.txt', 'utf8').split('\n').map(l => l.trim()).filter(l => l && l.includes('.'))
  } catch {
    subdomains = (out.stdout || '').split('\n').map(l => l.trim()).filter(l => l.includes(host))
  }

  if (subdomains.length > 0) {
    const sensitive = subdomains.filter(s => /dev\.|staging\.|test\.|internal\.|admin\.|db\.|vpn\.|jenkins\./.test(s))
    onFinding(makeFinding({
      title: `Sublist3r: ${subdomains.length} subdomain(s) enumerated${sensitive.length > 0 ? ` (${sensitive.length} sensitive)` : ''}`,
      severity: sensitive.length > 0 ? 'medium' : 'info',
      cvss: sensitive.length > 0 ? 5.3 : 0, cweId: 'CWE-200',
      description: `Sublist3r passive enumeration found ${subdomains.length} subdomains${sensitive.length > 0 ? `. Sensitive: ${sensitive.slice(0,3).join(', ')}` : ''}.`,
      remediation: 'Review all subdomains. Remove DNS records for decommissioned services.',
      aiConfidence: 0.82,
      evidence: { type: 'raw', label: 'sublist3r results', data: subdomains.slice(0, 100).join('\n') },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: arjun — HTTP parameter discovery
// ---------------------------------------------------------------------------
async function runArjun(targetUrl, onFinding, onLog) {
  onLog('info', `arjun: HTTP parameter discovery on ${targetUrl}`)
  const out = await runCommand('arjun', ['-u', targetUrl, '--stable', '-t', '5', '-oJ', '/tmp/arjun_sentinelai.json'], 120_000)

  let params = []
  try {
    const { readFileSync } = await import('node:fs')
    const parsed = JSON.parse(readFileSync('/tmp/arjun_sentinelai.json', 'utf8'))
    params = Object.values(parsed).flat().filter(p => typeof p === 'string')
  } catch {
    const stdout = (out.stdout || '').trim()
    params = (stdout.match(/\[Parameter found\].*?:\s*([\w\-_]+)/gi) || []).map(s => s.replace(/.*:\s*/, '').trim())
  }

  if (!params.length) return

  const dangerous = params.filter(p => /redirect|url|target|file|path|include|cmd|exec|shell|eval|query|debug|pass|password|token|key|secret|callback|src|dest|destination/i.test(p))

  if (dangerous.length > 0) {
    onFinding(makeFinding({
      title: `Arjun: ${dangerous.length} high-risk HTTP parameter(s) found`,
      severity: 'medium', cvss: 5.5, cweId: 'CWE-20',
      description: `Arjun found parameters with injection/manipulation potential: ${dangerous.join(', ')}`,
      remediation: 'Validate and sanitise all discovered parameters. Test each for SSRF, open redirect, LFI, SQLi.',
      aiConfidence: 0.84,
      evidence: { type: 'list', label: 'arjun dangerous params', data: dangerous.join('\n') },
    }, targetUrl))
  }
  onFinding(makeFinding({
    title: `Arjun: ${params.length} HTTP parameter(s) discovered`,
    severity: 'info', cvss: 0, cweId: 'CWE-20',
    description: `Discovered ${params.length} parameters: ${params.slice(0, 10).join(', ')}`,
    remediation: 'Audit all parameters. Remove undocumented/debug ones from production.',
    aiConfidence: 0.80,
    evidence: { type: 'list', label: 'arjun all params', data: params.join('\n') },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: kiterunner (kr) — API endpoint discovery
// ---------------------------------------------------------------------------
async function runKiterunner(targetUrl, onFinding, onLog) {
  const cmd = isToolAvailable('kiterunner') ? 'kiterunner' : isToolAvailable('kr') ? 'kr' : null
  if (!cmd) return

  onLog('info', `kiterunner: API endpoint discovery on ${targetUrl}`)

  const { existsSync, readFileSync } = await import('node:fs')
  const wordlist = process.env.KITERUNNER_WORDLIST || '/usr/share/kiterunner/routes-large.kite'

  const args = ['scan', targetUrl, '-q', '-j', '-o', '/tmp/kr_sentinelai.jsonl']
  if (existsSync(wordlist)) {
    args.push('-w', wordlist)
  }

  const out = await runCommand(cmd, args, 240_000)
  const raw = (out.stdout || out.stderr || '').trim()

  let endpoints = []
  try {
    const lines = readFileSync('/tmp/kr_sentinelai.jsonl', 'utf8').split('\n').map(l => l.trim()).filter(Boolean)
    endpoints = lines
      .map(l => {
        try { return JSON.parse(l) } catch { return null }
      })
      .filter(Boolean)
  } catch {
    const lines = raw.split('\n').filter(l => /\b(200|201|202|204|301|302|307|401|403)\b/.test(l))
    endpoints = lines.map(l => ({ line: l }))
  }

  if (!endpoints.length) return

  const sensitive = endpoints.filter(e => /admin|internal|debug|graphql|swagger|openapi|token|auth|private/i.test(JSON.stringify(e)))
  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Kiterunner: ${sensitive.length} sensitive API route(s) discovered`,
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: 'Kiterunner discovered API routes that appear sensitive or administrative.',
      remediation: 'Apply authentication/authorization checks to all discovered API routes and disable debug endpoints in production.',
      aiConfidence: 0.82,
      evidence: { type: 'raw', label: 'kiterunner sensitive routes', data: sensitive.slice(0, 40).map(s => JSON.stringify(s)).join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `Kiterunner: ${endpoints.length} API route candidate(s) found`,
    severity: 'info', cvss: 0, cweId: 'CWE-200',
    description: 'Kiterunner completed API endpoint discovery.',
    remediation: 'Inventory and secure all discovered routes; remove deprecated endpoints.',
    aiConfidence: 0.79,
    evidence: { type: 'raw', label: 'kiterunner output', data: endpoints.slice(0, 80).map(s => JSON.stringify(s)).join('\n') || cap(raw) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: wapiti — web application vulnerability scanner
// ---------------------------------------------------------------------------
async function runWapiti(targetUrl, onFinding, onLog) {
  onLog('info', `wapiti: web vulnerability scan on ${targetUrl}`)
  const out = await runCommand('wapiti', [
    '-u', targetUrl,
    '--max-links-per-page', '50', '--max-scan-time', '5',
    '-f', 'txt', '-o', '/tmp/wapiti_report_sentinelai.txt', '--flush-session',
  ], 360_000)

  let reportText = ''
  try {
    const { readFileSync } = await import('node:fs')
    reportText = readFileSync('/tmp/wapiti_report_sentinelai.txt', 'utf8')
  } catch { reportText = (out.stdout || out.stderr || '').trim() }

  if (!reportText.trim()) return

  const checks = [
    { p: /SQL Injection/gi,         t: 'SQL Injection',          s: 'critical', cvss: 9.8, cwe: 'CWE-89',  rem: 'Use parameterised queries. Apply WAF.' },
    { p: /Cross Site Scripting/gi,  t: 'Cross-Site Scripting',   s: 'high',     cvss: 7.2, cwe: 'CWE-79',  rem: 'Output encoding. Strict CSP.' },
    { p: /File Handling/gi,         t: 'File Inclusion/Traversal',s: 'high',    cvss: 7.5, cwe: 'CWE-22',  rem: 'Validate file paths. Use allowlist.' },
    { p: /CRLF Injection/gi,        t: 'CRLF Injection',         s: 'medium',   cvss: 5.3, cwe: 'CWE-93',  rem: 'Sanitise all user input in HTTP headers.' },
    { p: /Command Execution/gi,     t: 'OS Command Injection',   s: 'critical', cvss: 9.8, cwe: 'CWE-78',  rem: 'Never use unsanitised input in OS commands.' },
    { p: /CSRF/gi,                  t: 'CSRF',                   s: 'medium',   cvss: 5.3, cwe: 'CWE-352', rem: 'Implement CSRF tokens. Use SameSite cookies.' },
    { p: /SSRF/gi,                  t: 'SSRF',                   s: 'high',     cvss: 7.5, cwe: 'CWE-918', rem: 'Whitelist outbound URLs. Block metadata IPs.' },
    { p: /Open Redirect/gi,         t: 'Open Redirect',          s: 'medium',   cvss: 5.4, cwe: 'CWE-601', rem: 'Validate redirect targets against allowlist.' },
  ]

  for (const check of checks) {
    if (check.p.test(reportText)) {
      onFinding(makeFinding({
        title: `Wapiti: ${check.t}`,
        severity: check.s, cvss: check.cvss, cweId: check.cwe,
        description: `Wapiti detected ${check.t} on ${targetUrl}.`,
        remediation: check.rem,
        aiConfidence: 0.85,
        evidence: { type: 'raw', label: `wapiti ${check.t}`, data: cap(reportText) },
      }, targetUrl))
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: joomscan — Joomla vulnerability scanner
// ---------------------------------------------------------------------------
async function runJoomscan(targetUrl, onFinding, onLog) {
  onLog('info', `joomscan: Joomla checks on ${targetUrl}`)
  const out = await runCommand('joomscan', ['--url', targetUrl, '--no-banner'], 180_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  if (/not a joomla|joomla not detected/i.test(evidence)) return

  if (/vulnerable|exploit|cve-|security issue/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'JoomScan: Joomla vulnerabilities detected',
      severity: 'high', cvss: 7.5, cweId: 'CWE-1104', cveIds: extractCVEs(evidence),
      description: 'JoomScan reported likely Joomla-specific vulnerabilities or weak components.',
      remediation: 'Update Joomla core/extensions and remove vulnerable or unmaintained plugins/templates.',
      aiConfidence: 0.84,
      evidence: { type: 'raw', label: 'joomscan output', data: cap(evidence) },
    }, targetUrl))
  } else {
    onFinding(makeFinding({
      title: 'JoomScan: Joomla fingerprint information gathered',
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: 'JoomScan identified Joomla-related metadata/components.',
      remediation: 'Harden Joomla installation and hide unnecessary version/component disclosure.',
      aiConfidence: 0.7,
      evidence: { type: 'raw', label: 'joomscan output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: droopescan — CMS scanner for Drupal/Joomla/etc.
// ---------------------------------------------------------------------------
async function runDroopescan(targetUrl, onFinding, onLog) {
  onLog('info', `droopescan: CMS checks on ${targetUrl}`)
  const modes = ['drupal', 'joomla', 'silverstripe']
  let allEvidence = ''

  for (const mode of modes) {
    const out = await runCommand('droopescan', ['scan', mode, '-u', targetUrl], 120_000)
    const evidence = (out.stdout || out.stderr || '').trim()
    if (!evidence) continue
    if (/target does not seem|not a .*site|not detected/i.test(evidence)) continue
    allEvidence += `\n--- ${mode.toUpperCase()} ---\n${evidence}\n`
  }

  if (!allEvidence.trim()) return

  if (/cve-|vulnerab|exploit|interesting finding/i.test(allEvidence)) {
    onFinding(makeFinding({
      title: 'Droopescan: CMS vulnerability indicators found',
      severity: 'high', cvss: 7.0, cweId: 'CWE-1104', cveIds: extractCVEs(allEvidence),
      description: 'Droopescan identified CMS-specific risk indicators and potentially vulnerable components.',
      remediation: 'Patch CMS core/modules and remove vulnerable extensions/themes.',
      aiConfidence: 0.8,
      evidence: { type: 'raw', label: 'droopescan output', data: cap(allEvidence) },
    }, targetUrl))
  } else {
    onFinding(makeFinding({
      title: 'Droopescan: CMS components enumerated',
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: 'Droopescan completed CMS enumeration for supported engines.',
      remediation: 'Review enumerated components and keep all versions up to date.',
      aiConfidence: 0.72,
      evidence: { type: 'raw', label: 'droopescan output', data: cap(allEvidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: cmsmap — CMS vulnerability scanner (WordPress/Joomla/Drupal/Moodle)
// ---------------------------------------------------------------------------
async function runCmsmap(targetUrl, onFinding, onLog) {
  onLog('info', `cmsmap: CMS security checks on ${targetUrl}`)
  const out = await runCommand('cmsmap', [targetUrl], 240_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  if (/vulnerab|exploit|default credentials|cve-/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'CMSmap: CMS vulnerabilities detected',
      severity: 'high', cvss: 7.5, cweId: 'CWE-1104', cveIds: extractCVEs(evidence),
      description: 'CMSmap reported CMS-level vulnerabilities, weak defaults, or exploitable components.',
      remediation: 'Update CMS core and plugins/themes; disable default accounts and remove obsolete modules.',
      aiConfidence: 0.82,
      evidence: { type: 'raw', label: 'cmsmap output', data: cap(evidence) },
    }, targetUrl))
  } else {
    onFinding(makeFinding({
      title: 'CMSmap: CMS fingerprinting complete',
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: 'CMSmap completed scanning and produced CMS fingerprint data.',
      remediation: 'Review CMS exposure and reduce publicly disclosed version/component details.',
      aiConfidence: 0.68,
      evidence: { type: 'raw', label: 'cmsmap output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: zap — OWASP ZAP quick scan
// ---------------------------------------------------------------------------
async function runZap(targetUrl, onFinding, onLog) {
  const cmd = isToolAvailable('zaproxy') ? 'zaproxy' : isToolAvailable('zap.sh') ? 'zap.sh' : null
  if (!cmd) return

  onLog('info', `zap: OWASP ZAP quick scan on ${targetUrl}`)
  const out = await runCommand(cmd, ['-cmd', '-quickurl', targetUrl, '-quickprogress'], 420_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const high = /FAIL-NEW|\bHigh\b|risk\s*:\s*high/i.test(evidence)
  const medium = /WARN-NEW|\bMedium\b|risk\s*:\s*medium/i.test(evidence)

  if (high || medium) {
    onFinding(makeFinding({
      title: `OWASP ZAP: ${high ? 'high' : 'medium'}-risk alert(s) detected`,
      severity: high ? 'high' : 'medium', cvss: high ? 8.0 : 5.3, cweId: 'CWE-16',
      description: 'OWASP ZAP quick scan reported actionable security alerts.',
      remediation: 'Review ZAP alerts in detail, fix root causes, and rerun scan to confirm remediation.',
      aiConfidence: 0.84,
      evidence: { type: 'raw', label: 'zaproxy output', data: cap(evidence) },
    }, targetUrl))
  } else {
    onFinding(makeFinding({
      title: 'OWASP ZAP: quick scan completed',
      severity: 'info', cvss: 0, cweId: 'CWE-16',
      description: 'OWASP ZAP quick scan completed with no high/medium alerts parsed from CLI output.',
      remediation: 'Run a full active scan for deeper coverage and manually review passive findings.',
      aiConfidence: 0.7,
      evidence: { type: 'raw', label: 'zaproxy output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: testssl — comprehensive SSL/TLS analysis
// ---------------------------------------------------------------------------
async function runTestssl(host, port, targetUrl, onFinding, onLog) {
  const cmd = isToolAvailable('testssl') ? 'testssl' : isToolAvailable('testssl.sh') ? 'testssl.sh' : null
  if (!cmd) return

  onLog('info', `testssl: SSL/TLS analysis on ${host}:${port}`)
  const out = await runCommand(cmd, ['--fast', '--color', '0', '--warnings', 'off', `${host}:${port}`], 180_000)
  const evidence = (out.stdout || '').trim()
  if (!evidence) return

  const checks = [
    { p: /SSLv2\s+offered|SSLv3\s+offered/i,        t: 'SSL v2/v3 offered', s: 'critical', cvss: 9.8, cwe: 'CWE-326', cves: ['CVE-2015-3197', 'CVE-2014-3566'] },
    { p: /TLS 1\.0\s+offered/i,                      t: 'TLS 1.0 (deprecated)', s: 'medium', cvss: 5.9, cwe: 'CWE-326', cves: [] },
    { p: /TLS 1\.1\s+offered/i,                      t: 'TLS 1.1 (deprecated)', s: 'medium', cvss: 5.3, cwe: 'CWE-326', cves: [] },
    { p: /VULNERABLE.*Heartbleed/i,                  t: 'Heartbleed (CVE-2014-0160)', s: 'critical', cvss: 9.8, cwe: 'CWE-125', cves: ['CVE-2014-0160'] },
    { p: /VULNERABLE.*POODLE/i,                      t: 'POODLE (CVE-2014-3566)', s: 'high', cvss: 7.5, cwe: 'CWE-310', cves: ['CVE-2014-3566'] },
    { p: /VULNERABLE.*DROWN/i,                       t: 'DROWN (CVE-2016-0800)', s: 'critical', cvss: 9.8, cwe: 'CWE-310', cves: ['CVE-2016-0800'] },
    { p: /VULNERABLE.*LOGJAM/i,                      t: 'LOGJAM DH weakness', s: 'high', cvss: 7.4, cwe: 'CWE-310', cves: ['CVE-2015-4000'] },
    { p: /VULNERABLE.*FREAK/i,                       t: 'FREAK EXPORT cipher', s: 'high', cvss: 7.4, cwe: 'CWE-326', cves: ['CVE-2015-0204'] },
    { p: /VULNERABLE.*SWEET32/i,                     t: 'SWEET32 (3DES/DES)', s: 'medium', cvss: 5.9, cwe: 'CWE-326', cves: ['CVE-2016-2183'] },
    { p: /no HSTS|HSTS.*not sent/i,                  t: 'HSTS not configured', s: 'medium', cvss: 5.3, cwe: 'CWE-16', cves: [] },
    { p: /Certificate is expired/i,                   t: 'TLS certificate expired', s: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [] },
    { p: /self.[Ss]igned/i,                           t: 'Self-signed certificate', s: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [] },
    { p: /RC4.*offered|EXPORT.*offered/i,             t: 'Weak ciphers (RC4/EXPORT)', s: 'high', cvss: 7.5, cwe: 'CWE-327', cves: ['CVE-2013-2566'] },
    { p: /NULL.*cipher.*offered/i,                    t: 'NULL cipher (no encryption)', s: 'critical', cvss: 9.1, cwe: 'CWE-312', cves: [] },
  ]

  for (const check of checks) {
    if (check.p.test(evidence)) {
      onFinding(makeFinding({
        title: `TestSSL: ${check.t}`,
        severity: check.s, cvss: check.cvss, cweId: check.cwe, cveIds: check.cves,
        description: `TestSSL detected: ${check.t} on ${host}:${port}`,
        remediation: 'Apply SSL/TLS hardening: disable weak protocols/ciphers, use TLS 1.2+, AES-GCM suites, enable HSTS.',
        aiConfidence: 0.92,
        evidence: { type: 'raw', label: 'testssl output', data: cap(evidence) },
      }, targetUrl))
    }
  }
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

const DEFAULT_ADVANCED_TOOLS = [
  'ffuf', 'wfuzz', 'feroxbuster', 'dalfox', 'xsstrike', 'xsser',
  'commix', 'nosqlmap', 'ssrfmap', 'jwt_tool', 'linkfinder', 'corsy',
  'dnsrecon', 'fierce', 'amass', 'sublist3r',
  'arjun', 'kiterunner', 'wapiti', 'joomscan', 'droopescan', 'cmsmap',
  'zap', 'testssl',
]

export async function scanKaliAdvanced(targetUrl, onFinding, onLog) {
  onLog?.('info', `Advanced Kali Tools starting for ${targetUrl}`)

  if (String(process.env.EXTERNAL_SCANNER_ENABLED || 'false').toLowerCase() !== 'true') {
    onLog?.('warn', 'Advanced Kali scanner disabled. Set EXTERNAL_SCANNER_ENABLED=true.')
    return { skipped: true, reason: 'disabled' }
  }

  let urlObj
  try { urlObj = new URL(targetUrl) } catch { return { skipped: true, reason: 'invalid-url' } }

  const host = urlObj.hostname
  const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')

  const envList  = (process.env.ADVANCED_TOOL_LIST || '').split(',').map(s => s.trim()).filter(Boolean)
  const wantList = envList.length > 0 ? envList : DEFAULT_ADVANCED_TOOLS

  const resolveAlias = (tool) => {
    const t = String(tool || '').trim()
    if (!t) return null

    if (t === 'testssl') return isToolAvailable('testssl') ? 'testssl' : isToolAvailable('testssl.sh') ? 'testssl.sh' : null
    if (t === 'kiterunner' || t === 'kr') return isToolAvailable('kiterunner') ? 'kiterunner' : isToolAvailable('kr') ? 'kr' : null
    if (t === 'zap' || t === 'zaproxy' || t === 'zap.sh') return isToolAvailable('zaproxy') ? 'zaproxy' : isToolAvailable('zap.sh') ? 'zap.sh' : null

    return isToolAvailable(t) ? t : null
  }

  const available = [...new Set(wantList.map(resolveAlias).filter(Boolean))]

  onLog?.('info', `Available advanced tools: [${available.join(', ')}]`)

  if (!available.length) {
    onLog?.('warn', 'No advanced tools found. Install local wrappers/binaries for: ffuf wfuzz feroxbuster dalfox xsstrike xsser commix nosqlmap ssrfmap jwt_tool linkfinder corsy dnsrecon fierce amass sublist3r arjun kiterunner wapiti joomscan droopescan cmsmap zap testssl')
    return { skipped: true, reason: 'no-tools-available' }
  }

  const findings = []
  const wrap = f => { findings.push(f); onFinding?.(f) }

  const handlers = {
    ffuf:         () => runFfuf(targetUrl, wrap, (l, m) => onLog?.(l, `[ffuf] ${m}`)),
    wfuzz:        () => runWfuzz(targetUrl, wrap, (l, m) => onLog?.(l, `[wfuzz] ${m}`)),
    feroxbuster:  () => runFeroxbuster(targetUrl, wrap, (l, m) => onLog?.(l, `[feroxbuster] ${m}`)),
    dalfox:       () => runDalfox(targetUrl, wrap, (l, m) => onLog?.(l, `[dalfox] ${m}`)),
    xsstrike:     () => runXsstrike(targetUrl, wrap, (l, m) => onLog?.(l, `[xsstrike] ${m}`)),
    xsser:        () => runXsser(targetUrl, wrap, (l, m) => onLog?.(l, `[xsser] ${m}`)),
    commix:       () => runCommix(targetUrl, wrap, (l, m) => onLog?.(l, `[commix] ${m}`)),
    nosqlmap:     () => runNosqlmap(targetUrl, wrap, (l, m) => onLog?.(l, `[nosqlmap] ${m}`)),
    ssrfmap:      () => runSsrfmap(targetUrl, wrap, (l, m) => onLog?.(l, `[ssrfmap] ${m}`)),
    jwt_tool:     () => runJwtTool(targetUrl, wrap, (l, m) => onLog?.(l, `[jwt_tool] ${m}`)),
    linkfinder:   () => runLinkfinder(targetUrl, wrap, (l, m) => onLog?.(l, `[linkfinder] ${m}`)),
    corsy:        () => runCorsy(targetUrl, wrap, (l, m) => onLog?.(l, `[corsy] ${m}`)),
    dnsrecon:     () => runDnsrecon(host, targetUrl, wrap, (l, m) => onLog?.(l, `[dnsrecon] ${m}`)),
    fierce:       () => runFierce(host, targetUrl, wrap, (l, m) => onLog?.(l, `[fierce] ${m}`)),
    amass:        () => runAmass(host, targetUrl, wrap, (l, m) => onLog?.(l, `[amass] ${m}`)),
    sublist3r:    () => runSublist3r(host, targetUrl, wrap, (l, m) => onLog?.(l, `[sublist3r] ${m}`)),
    arjun:        () => runArjun(targetUrl, wrap, (l, m) => onLog?.(l, `[arjun] ${m}`)),
    kiterunner:   () => runKiterunner(targetUrl, wrap, (l, m) => onLog?.(l, `[kiterunner] ${m}`)),
    kr:           () => runKiterunner(targetUrl, wrap, (l, m) => onLog?.(l, `[kiterunner] ${m}`)),
    wapiti:       () => runWapiti(targetUrl, wrap, (l, m) => onLog?.(l, `[wapiti] ${m}`)),
    joomscan:     () => runJoomscan(targetUrl, wrap, (l, m) => onLog?.(l, `[joomscan] ${m}`)),
    droopescan:   () => runDroopescan(targetUrl, wrap, (l, m) => onLog?.(l, `[droopescan] ${m}`)),
    cmsmap:       () => runCmsmap(targetUrl, wrap, (l, m) => onLog?.(l, `[cmsmap] ${m}`)),
    zaproxy:      () => runZap(targetUrl, wrap, (l, m) => onLog?.(l, `[zap] ${m}`)),
    'zap.sh':     () => runZap(targetUrl, wrap, (l, m) => onLog?.(l, `[zap] ${m}`)),
    testssl:      () => runTestssl(host, port, targetUrl, wrap, (l, m) => onLog?.(l, `[testssl] ${m}`)),
    'testssl.sh': () => runTestssl(host, port, targetUrl, wrap, (l, m) => onLog?.(l, `[testssl] ${m}`)),
  }

  for (const tool of available) {
    const handler = handlers[tool]
    if (!handler) { onLog?.('info', `[advanced] Unknown tool: ${tool}`); continue }
    try {
      onLog?.('info', `[advanced] Starting: ${tool}`)
      await handler()
      onLog?.('info', `[advanced] Finished: ${tool}`)
    } catch (err) {
      onLog?.('warn', `[advanced] ${tool} error: ${String(err.message || err)}`)
    }
  }

  onLog?.('info', `Advanced Kali Tools complete — ${findings.length} findings`)
  return findings
}
