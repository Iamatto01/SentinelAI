/**
 * kali_advanced.js – Advanced Kali Linux tool integrations
 *
 * Tools included:
 *  - ffuf          – Fast web fuzzer (endpoint/parameter discovery)
 *  - feroxbuster   – Recursive content discovery
 *  - dalfox        – XSS parameter scanner
 *  - commix        – Automated command injection
 *  - dnsrecon      – DNS reconnaissance & zone transfer
 *  - fierce        – DNS brute force
 *  - amass         – OSINT subdomain enumeration
 *  - sublist3r     – Passive subdomain enumeration
 *  - arjun         – HTTP parameter discovery
 *  - wapiti        – Web application vulnerability scanner
 *  - testssl       – Comprehensive SSL/TLS analysis
 *
 * Enable: EXTERNAL_SCANNER_ENABLED=true
 * Tool list override: ADVANCED_TOOL_LIST=ffuf,dalfox,...
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
    return r.status === 0 && r.stdout && r.stdout.trim().length > 0
  } catch {
    return false
  }
}

function runCommand(cmd, args, timeoutMs = 120_000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false })
    let stdout = ''
    let stderr = ''
    const to = setTimeout(() => {
      try { child.kill('SIGKILL') } catch (_) {}
      resolve({ timedOut: true, stdout, stderr, code: null })
    }, timeoutMs)

    child.stdout.on('data', (d) => { stdout += String(d) })
    child.stderr.on('data', (d) => { stderr += String(d) })
    child.on('close', (code) => { clearTimeout(to); resolve({ timedOut: false, stdout, stderr, code }) })
    child.on('error', (err) => { clearTimeout(to); resolve({ timedOut: false, stdout, stderr: String(err.message || err), code: null }) })
  })
}

function cap(str, bytes = 60_000) {
  if (!str) return ''
  return str.length > bytes ? str.substring(0, bytes) + '\n...[truncated]' : str
}

function extractCVEs(text = '') {
  const m = text.match(/CVE-\d{4}-\d{4,7}/gi) || []
  return [...new Set(m.map((c) => c.toUpperCase()))]
}

// ---------------------------------------------------------------------------
// Tool: ffuf – fast web fuzzer
// ---------------------------------------------------------------------------
async function runFfuf(targetUrl, onFinding, onLog) {
  const wordlist = process.env.FFUF_WORDLIST
    || '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt'
    || '/usr/share/wordlists/dirb/common.txt'

  onLog('info', `ffuf: directory/file fuzzing with wordlist ${wordlist}`)

  // Run ffuf with JSON output for parsing
  const out = await runCommand('ffuf', [
    '-u', `${targetUrl}/FUZZ`,
    '-w', wordlist,
    '-mc', '200,204,301,302,307,401,403,405',
    '-fc', '404',
    '-c',
    '-of', 'json',
    '-o', '/tmp/ffuf_sentinelai.json',
    '-t', '40',
    '-p', '0.1',
    '-recursion',
    '-recursion-depth', '2',
    '-e', '.php,.asp,.aspx,.jsp,.bak,.sql,.zip,.conf,.env,.txt,.xml,.json',
  ], 180_000)

  // Try to read JSON output
  let results = []
  try {
    const { readFileSync } = await import('node:fs')
    const raw = readFileSync('/tmp/ffuf_sentinelai.json', 'utf8')
    const parsed = JSON.parse(raw)
    results = parsed.results || []
  } catch (_) {
    // Fall back to stdout parsing
    const stdout = out.stdout || ''
    if (stdout) {
      const lines = stdout.split('\n').filter((l) => /\[Status:\s*\d+/.test(l))
      results = lines.slice(0, 100).map((l) => {
        const url = l.match(/[^\s]+(?:FUZZ[^\s]*)/) || []
        const status = l.match(/Status:\s*(\d+)/)
        return { url: url[0]?.replace('FUZZ', '') || '', status: status ? parseInt(status[1]) : 0 }
      })
    }
  }

  if (results.length === 0) {
    onLog('info', 'ffuf: no results found')
    return
  }

  const sensitive = results.filter((r) => {
    const u = String(r.url || r.input?.FUZZ || '')
    return /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|credential|private|\.htaccess|phpmyadmin|staging|dev\//i.test(u)
  })

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `FFUF: ${sensitive.length} sensitive path(s) discovered`,
      severity: 'high',
      cvss: 7.5,
      cweId: 'CWE-548',
      description: `FFuf fuzzing discovered sensitive accessible endpoints: ${sensitive.slice(0, 5).map((r) => r.url || r.input?.FUZZ || '').join(', ')}`,
      remediation: 'Remove or restrict access to sensitive files and directories. Configure web server to deny access to backup, config, and admin files.',
      aiConfidence: 0.88,
      evidence: { type: 'list', label: 'ffuf sensitive paths', data: sensitive.slice(0, 30).map((r) => JSON.stringify(r)).join('\n') },
    }, targetUrl))
  }

  // Summarise all findings
  const byStatus = results.reduce((acc, r) => {
    const s = String(r.status)
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})

  onFinding(makeFinding({
    title: `FFUF: ${results.length} endpoint(s) discovered (${Object.entries(byStatus).map(([s, n]) => `${n}×${s}`).join(', ')})`,
    severity: 'info',
    cvss: 0,
    cweId: 'CWE-548',
    description: `FFuf recursive fuzzing found ${results.length} accessible paths. Review all non-standard endpoints.`,
    remediation: 'Audit all discovered paths. Disable directory listing. Remove unused files and debug endpoints.',
    aiConfidence: 0.82,
    evidence: { type: 'raw', label: 'ffuf results', data: results.slice(0, 50).map((r) => JSON.stringify(r)).join('\n') },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: feroxbuster – recursive content discovery
// ---------------------------------------------------------------------------
async function runFeroxbuster(targetUrl, onFinding, onLog) {
  const wordlist = process.env.FEROX_WORDLIST
    || '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt'
    || '/usr/share/wordlists/dirb/common.txt'

  onLog('info', 'feroxbuster: recursive content discovery')

  const out = await runCommand('feroxbuster', [
    '-u', targetUrl,
    '-w', wordlist,
    '-d', '3',
    '-t', '30',
    '--status-codes', '200,204,301,302,307,401,403',
    '--filter-status', '404',
    '-q',
    '--no-state',
    '-x', 'php,asp,aspx,jsp,bak,sql,conf,env',
  ], 180_000)

  const stdout = out.stdout || ''
  if (!stdout.trim()) return

  const lines = stdout.split('\n').filter((l) => l.trim() && /http/i.test(l))
  if (lines.length === 0) return

  const sensitiveLines = lines.filter((l) =>
    /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|credentials|private|phpmyadmin|panel/i.test(l)
  )

  if (sensitiveLines.length > 0) {
    onFinding(makeFinding({
      title: `Feroxbuster: ${sensitiveLines.length} sensitive resource(s) found`,
      severity: 'high',
      cvss: 7.5,
      cweId: 'CWE-548',
      description: `Feroxbuster recursive scan discovered sensitive resources: ${sensitiveLines.slice(0, 5).join(' | ')}`,
      remediation: 'Remove or restrict access to sensitive resources. Audit web application structure for unnecessary file exposure.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'feroxbuster sensitive', data: sensitiveLines.slice(0, 50).join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `Feroxbuster: ${lines.length} URL(s) discovered via recursive enumeration`,
    severity: 'info',
    cvss: 0,
    cweId: 'CWE-548',
    description: `Feroxbuster recursive directory brute-force found ${lines.length} accessible URLs on the target.`,
    remediation: 'Review discovered URLs. Restrict unnecessary endpoints. Enable authentication on all admin/management interfaces.',
    aiConfidence: 0.83,
    evidence: { type: 'raw', label: 'feroxbuster output', data: cap(stdout) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: dalfox – XSS parameter scanner
// ---------------------------------------------------------------------------
async function runDalfox(targetUrl, onFinding, onLog) {
  onLog('info', 'dalfox: XSS parameter scanning')

  const out = await runCommand('dalfox', [
    'url', targetUrl,
    '--skip-bav',
    '--no-spinner',
    '--silence',
    '--format', 'plain',
  ], 120_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const xssLines = evidence.split('\n').filter((l) => /\[V\]|POC:|XSS|payload/i.test(l))
  const reflectLines = evidence.split('\n').filter((l) => /\[R\]|reflected/i.test(l))

  if (xssLines.length > 0) {
    for (const line of xssLines.slice(0, 5)) {
      onFinding(makeFinding({
        title: `Dalfox: XSS vulnerability confirmed – ${line.substring(0, 100)}`,
        severity: 'high',
        cvss: 7.2,
        cweId: 'CWE-79',
        description: `Dalfox confirmed an exploitable XSS payload: ${line}`,
        remediation: 'Implement context-aware output encoding. Apply Content-Security-Policy (CSP). Sanitise all user input.',
        aiConfidence: 0.9,
        aiReasoning: 'Dalfox verified XSS payload execution with [V] (verified) status.',
        evidence: { type: 'raw', label: 'dalfox XSS PoC', data: line },
      }, targetUrl))
    }
  } else if (reflectLines.length > 0) {
    onFinding(makeFinding({
      title: `Dalfox: ${reflectLines.length} reflected parameter(s) detected`,
      severity: 'medium',
      cvss: 5.5,
      cweId: 'CWE-79',
      description: `Dalfox found ${reflectLines.length} reflected parameters that are candidates for XSS. Further manual verification recommended.`,
      remediation: 'Sanitise and encode all reflected user input. Implement strict CSP headers.',
      aiConfidence: 0.75,
      aiReasoning: 'Dalfox identified reflected parameters (Reflection mode).',
      evidence: { type: 'raw', label: 'dalfox reflections', data: reflectLines.slice(0, 20).join('\n') },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: commix – command injection
// ---------------------------------------------------------------------------
async function runCommix(targetUrl, onFinding, onLog) {
  onLog('info', 'commix: testing for command injection')

  const out = await runCommand('commix', [
    '--url', targetUrl,
    '--batch',
    '--level', '2',
    '--output-dir', '/tmp/commix_sentinelai',
    '--no-logging',
  ], 180_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const isVulnerable = /vulnerable|injection point|command injection found|exploitable/i.test(evidence)

  if (isVulnerable) {
    onFinding(makeFinding({
      title: 'Commix: OS command injection vulnerability detected',
      severity: 'critical',
      cvss: 9.8,
      cweId: 'CWE-78',
      description: `Commix detected an OS command injection vulnerability at ${targetUrl}. An attacker could execute arbitrary system commands on the target server.`,
      remediation: 'Never pass unsanitised user input to system commands. Use allow-list validation. Apply WAF rules for command injection patterns.',
      aiConfidence: 0.91,
      aiReasoning: 'Commix confirmed injectable parameter with OS command execution.',
      evidence: { type: 'raw', label: 'commix output', data: cap(evidence) },
    }, targetUrl))
  } else if (/testing|checking/i.test(evidence)) {
    onLog('info', 'commix: no command injection confirmed')
  }
}

// ---------------------------------------------------------------------------
// Tool: dnsrecon – DNS reconnaissance
// ---------------------------------------------------------------------------
async function runDnsrecon(host, targetUrl, onFinding, onLog) {
  onLog('info', `dnsrecon: DNS reconnaissance on ${host}`)

  // Standard enumeration
  const out = await runCommand('dnsrecon', [
    '-d', host,
    '-t', 'std,brt,axfr',
    '-D', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-1000.txt',
  ], 120_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  // Check for zone transfer success
  if (/zone transfer|AXFR.*successful|Transfer succeeded/i.test(evidence)) {
    onFinding(makeFinding({
      title: `DNSRecon: DNS zone transfer (AXFR) possible on ${host}`,
      severity: 'high',
      cvss: 7.5,
      cweId: 'CWE-16',
      description: `DNSRecon successfully performed a DNS zone transfer on ${host}. This reveals the complete DNS zone contents, exposing all internal subdomains and IP addresses.`,
      remediation: 'Restrict zone transfers (AXFR) to authorised secondary name servers only. Configure your DNS server to deny zone transfer requests from arbitrary sources.',
      aiConfidence: 0.95,
      aiReasoning: 'Successful AXFR zone transfer returns full zone records.',
      evidence: { type: 'raw', label: 'dnsrecon axfr output', data: cap(evidence) },
    }, targetUrl))
  }

  // Count found subdomains
  const aRecords = evidence.match(/A\s+[\w\.\-]+\s+\d+\.\d+\.\d+\.\d+/g) || []
  const uniqueHosts = [...new Set(aRecords.map((r) => r.split(/\s+/)[1]))]
  const sensitiveHosts = uniqueHosts.filter((h) =>
    /dev\.|staging\.|test\.|internal\.|admin\.|api\.|jenkins\.|gitlab\.|ci\.|db\.|vpn\.|kibana\.|grafana\./i.test(h)
  )

  if (sensitiveHosts.length > 0) {
    onFinding(makeFinding({
      title: `DNSRecon: ${sensitiveHosts.length} sensitive subdomain(s) exposed`,
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-200',
      description: `DNSRecon discovered sensitive subdomains: ${sensitiveHosts.slice(0, 5).join(', ')}`,
      remediation: 'Remove or restrict internal/development subdomains from public DNS. Use split-horizon DNS to separate internal and external records.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'dnsrecon sensitive subdomains', data: sensitiveHosts.join('\n') },
    }, targetUrl))
  }

  if (uniqueHosts.length > 0) {
    onFinding(makeFinding({
      title: `DNSRecon: ${uniqueHosts.length} DNS record(s) enumerated for ${host}`,
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-200',
      description: `DNSRecon enumerated DNS records for ${host}. Exposed DNS records provide attackers with target structure information.`,
      remediation: 'Review all public DNS records. Remove records for decommissioned services.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'dnsrecon output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: fierce – DNS brute force
// ---------------------------------------------------------------------------
async function runFierce(host, targetUrl, onFinding, onLog) {
  onLog('info', `fierce: DNS brute force on ${host}`)

  const out = await runCommand('fierce', [
    '--domain', host,
    '--subdomains', '/usr/share/wordlists/seclists/Discovery/DNS/fierce-hostlist.txt',
  ], 90_000)

  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const found = evidence.split('\n').filter((l) => /Found:|IP:|Nearby/i.test(l))
  const sensitiveFound = found.filter((l) =>
    /dev\.|staging\.|test\.|internal\.|admin\.|vpn\.|jenkins\.|gitlab\.|ci\.|db\./i.test(l)
  )

  if (sensitiveFound.length > 0) {
    onFinding(makeFinding({
      title: `Fierce: ${sensitiveFound.length} sensitive subdomain(s) brute-forced`,
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-200',
      description: `Fierce DNS brute-force found sensitive subdomains: ${sensitiveFound.slice(0, 5).join(' | ')}`,
      remediation: 'Restrict internal subdomains from appearing in public DNS. Implement DNS security controls.',
      aiConfidence: 0.83,
      evidence: { type: 'raw', label: 'fierce findings', data: sensitiveFound.join('\n') },
    }, targetUrl))
  } else if (found.length > 0) {
    onFinding(makeFinding({
      title: `Fierce: ${found.length} subdomain(s) discovered via DNS brute-force`,
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-200',
      description: `Fierce discovered ${found.length} DNS entries for ${host}.`,
      remediation: 'Review all discovered subdomains for security exposure.',
      aiConfidence: 0.8,
      evidence: { type: 'raw', label: 'fierce output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: amass – OSINT subdomain enumeration
// ---------------------------------------------------------------------------
async function runAmass(host, targetUrl, onFinding, onLog) {
  onLog('info', `amass: OSINT subdomain enumeration for ${host}`)

  const out = await runCommand('amass', [
    'enum',
    '-passive',           // passive mode – no active probing
    '-d', host,
    '-timeout', '5',      // 5 minute timeout for passive enum
  ], 360_000)

  const evidence = (out.stdout || '').trim()
  if (!evidence) return

  const subdomains = [...new Set(
    evidence.split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && l.includes('.') && !l.startsWith('['))
  )]

  const sensitive = subdomains.filter((s) =>
    /dev\.|staging\.|test\.|internal\.|admin\.|api\.|jenkins\.|gitlab\.|ci\.|db\.|vpn\.|kibana\.|grafana\.|prod\.|uat\.|qa\./i.test(s)
  )

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Amass: ${sensitive.length} sensitive subdomain(s) discovered via OSINT`,
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-200',
      description: `Amass OSINT enumeration found sensitive subdomains from public sources: ${sensitive.slice(0, 5).join(', ')}`,
      remediation: 'Review all discovered subdomains. Harden or decommission unnecessary internal-facing subdomains exposed publicly.',
      aiConfidence: 0.88,
      evidence: { type: 'raw', label: 'amass sensitive subdomains', data: sensitive.join('\n') },
    }, targetUrl))
  }

  if (subdomains.length > 0) {
    onFinding(makeFinding({
      title: `Amass: ${subdomains.length} subdomain(s) found via OSINT for ${host}`,
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-200',
      description: `Amass discovered ${subdomains.length} subdomains using passive OSINT sources (certificate transparency, DNS datasets, APIs).`,
      remediation: 'Enumerate your full attack surface periodically. Monitor certificate transparency logs.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'amass discovered subdomains', data: subdomains.slice(0, 100).join('\n') },
    }, targetUrl))
  }

  onLog('info', `amass: discovered ${subdomains.length} subdomains (${sensitive.length} sensitive)`)
}

// ---------------------------------------------------------------------------
// Tool: sublist3r – passive subdomain enumeration
// ---------------------------------------------------------------------------
async function runSublist3r(host, targetUrl, onFinding, onLog) {
  onLog('info', `sublist3r: passive subdomain enumeration for ${host}`)

  const out = await runCommand('sublist3r', [
    '-d', host,
    '-o', '/tmp/sublist3r_sentinelai.txt',
  ], 180_000)

  // Read output file
  let subdomains = []
  try {
    const { readFileSync } = await import('node:fs')
    const raw = readFileSync('/tmp/sublist3r_sentinelai.txt', 'utf8')
    subdomains = raw.split('\n').map((l) => l.trim()).filter((l) => l.length > 0 && l.includes('.'))
  } catch (_) {
    const stdout = (out.stdout || '').trim()
    subdomains = stdout.split('\n').map((l) => l.trim()).filter((l) => l.includes(host))
  }

  const sensitive = subdomains.filter((s) =>
    /dev\.|staging\.|test\.|internal\.|admin\.|api\.|jenkins\.|gitlab\.|db\.|vpn\./i.test(s)
  )

  if (subdomains.length > 0) {
    onFinding(makeFinding({
      title: `Sublist3r: ${subdomains.length} subdomain(s) enumerated (${sensitive.length} sensitive)`,
      severity: sensitive.length > 0 ? 'medium' : 'info',
      cvss: sensitive.length > 0 ? 5.3 : 0,
      cweId: 'CWE-200',
      description: `Sublist3r passive enumeration found ${subdomains.length} subdomains${sensitive.length > 0 ? `, including ${sensitive.length} potentially sensitive: ${sensitive.slice(0, 3).join(', ')}` : ''}.`,
      remediation: 'Review all discovered subdomains for unnecessary exposure. Remove DNS records for decommissioned services.',
      aiConfidence: 0.82,
      evidence: { type: 'raw', label: 'sublist3r subdomains', data: subdomains.slice(0, 100).join('\n') },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: arjun – HTTP parameter discovery
// ---------------------------------------------------------------------------
async function runArjun(targetUrl, onFinding, onLog) {
  onLog('info', `arjun: discovering HTTP parameters on ${targetUrl}`)

  const out = await runCommand('arjun', [
    '-u', targetUrl,
    '--stable',
    '-t', '5',
    '-oJ', '/tmp/arjun_sentinelai.json',
  ], 120_000)

  let params = []
  try {
    const { readFileSync } = await import('node:fs')
    const raw = readFileSync('/tmp/arjun_sentinelai.json', 'utf8')
    const parsed = JSON.parse(raw)
    // arjun JSON: { "url": [...params...] }
    for (const v of Object.values(parsed)) {
      if (Array.isArray(v)) params.push(...v)
    }
  } catch (_) {
    const stdout = (out.stdout || '').trim()
    if (stdout) {
      const m = stdout.match(/\[Parameter found\].*?:\s*([\w\-_]+)/gi) || []
      params = m.map((s) => s.replace(/.*:\s*/, '').trim())
    }
  }

  if (params.length === 0) return

  const sensitiveParams = params.filter((p) =>
    /redirect|url|target|file|path|include|cmd|exec|shell|eval|query|debug|admin|pass|password|token|key|secret|callback|src|href|dest|destination/i.test(p)
  )

  if (sensitiveParams.length > 0) {
    onFinding(makeFinding({
      title: `Arjun: ${sensitiveParams.length} sensitive HTTP parameter(s) discovered`,
      severity: 'medium',
      cvss: 5.5,
      cweId: 'CWE-20',
      description: `Arjun found sensitive parameters that are potential injection/manipulation vectors: ${sensitiveParams.join(', ')}`,
      remediation: 'Validate and sanitise all discovered parameters. Implement strict input validation. Test each sensitive parameter for injection vulnerabilities.',
      aiConfidence: 0.84,
      aiReasoning: 'Parameters matching patterns associated with injection, redirect, or file inclusion vulnerabilities were found.',
      evidence: { type: 'list', label: 'arjun sensitive params', data: sensitiveParams.join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `Arjun: ${params.length} HTTP parameter(s) discovered`,
    severity: 'info',
    cvss: 0,
    cweId: 'CWE-20',
    description: `Arjun discovered ${params.length} HTTP parameters: ${params.slice(0, 10).join(', ')}. Hidden/undocumented parameters may represent unintended functionality.`,
    remediation: 'Audit all discovered parameters. Remove undocumented/debug parameters from production.',
    aiConfidence: 0.8,
    evidence: { type: 'list', label: 'arjun all params', data: params.join('\n') },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: wapiti – web application vulnerability scanner
// ---------------------------------------------------------------------------
async function runWapiti(targetUrl, onFinding, onLog) {
  onLog('info', `wapiti: web application vulnerability scan on ${targetUrl}`)

  const out = await runCommand('wapiti', [
    '-u', targetUrl,
    '--max-links-per-page', '50',
    '--max-scan-time', '5',
    '-f', 'txt',
    '-o', '/tmp/wapiti_report_sentinelai.txt',
    '--flush-session',
  ], 360_000)

  let reportText = ''
  try {
    const { readFileSync } = await import('node:fs')
    reportText = readFileSync('/tmp/wapiti_report_sentinelai.txt', 'utf8')
  } catch (_) {
    reportText = (out.stdout || out.stderr || '').trim()
  }

  if (!reportText.trim()) return

  const cves = extractCVEs(reportText)

  // Parse wapiti vulnerability categories
  const vulnCategories = [
    { pattern: /SQL Injection/gi,          title: 'SQL Injection',          severity: 'critical', cvss: 9.8, cwe: 'CWE-89'  },
    { pattern: /Blind SQL Injection/gi,    title: 'Blind SQL Injection',     severity: 'critical', cvss: 9.8, cwe: 'CWE-89'  },
    { pattern: /Cross Site Scripting/gi,   title: 'Cross-Site Scripting',    severity: 'high',     cvss: 7.2, cwe: 'CWE-79'  },
    { pattern: /File Handling/gi,          title: 'File Inclusion/Traversal',severity: 'high',     cvss: 7.5, cwe: 'CWE-22'  },
    { pattern: /CRLF Injection/gi,         title: 'CRLF Injection',          severity: 'medium',   cvss: 5.3, cwe: 'CWE-93'  },
    { pattern: /Command Execution/gi,      title: 'OS Command Injection',    severity: 'critical', cvss: 9.8, cwe: 'CWE-78'  },
    { pattern: /CSRF/gi,                   title: 'CSRF',                    severity: 'medium',   cvss: 5.3, cwe: 'CWE-352' },
    { pattern: /SSRF/gi,                   title: 'Server-Side Request Forgery', severity: 'high', cvss: 7.5, cwe: 'CWE-918' },
    { pattern: /XXSS/gi,                   title: 'XXE Injection',           severity: 'high',     cvss: 7.5, cwe: 'CWE-611' },
    { pattern: /Open Redirect/gi,          title: 'Open Redirect',           severity: 'medium',   cvss: 5.4, cwe: 'CWE-601' },
    { pattern: /Htaccess bypass/gi,        title: '.htaccess Bypass',        severity: 'high',     cvss: 7.5, cwe: 'CWE-284' },
  ]

  let foundAny = false
  for (const check of vulnCategories) {
    if (check.pattern.test(reportText)) {
      foundAny = true
      onFinding(makeFinding({
        title: `Wapiti: ${check.title} detected`,
        severity: check.severity,
        cvss: check.cvss,
        cweId: check.cwe,
        description: `Wapiti web scanner detected ${check.title} on ${targetUrl}. Review the full Wapiti report for affected parameters and proof-of-concept payloads.`,
        remediation: getWapitiRemediation(check.title),
        aiConfidence: 0.85,
        evidence: { type: 'raw', label: `wapiti ${check.title}`, data: cap(reportText) },
      }, targetUrl))
    }
  }

  // Summary finding
  onFinding(makeFinding({
    title: 'Wapiti: web application vulnerability scan completed',
    severity: foundAny ? 'info' : 'info',
    cvss: 0,
    cweId: 'CWE-200',
    cveIds: cves.slice(0, 5),
    description: `Wapiti crawled and tested ${targetUrl} for common web vulnerabilities.`,
    remediation: 'Review the full Wapiti report and remediate all identified issues.',
    aiConfidence: 0.87,
    evidence: { type: 'raw', label: 'wapiti report', data: cap(reportText) },
  }, targetUrl))
}

function getWapitiRemediation(vulnType) {
  const map = {
    'SQL Injection': 'Use parameterised queries. Implement input validation and a WAF.',
    'Blind SQL Injection': 'Use parameterised queries. Monitor for time-delay anomalies.',
    'Cross-Site Scripting': 'Implement output encoding and a strict CSP header.',
    'File Inclusion/Traversal': 'Validate all file path inputs. Use allow-list validation.',
    'CRLF Injection': 'Sanitise all user input included in HTTP headers.',
    'OS Command Injection': 'Never pass unsanitised input to OS commands.',
    'CSRF': 'Implement anti-CSRF tokens. Use SameSite cookie attribute.',
    'Server-Side Request Forgery': 'Validate and whitelist all outbound request targets.',
    'XXE Injection': 'Disable external entity processing in XML parsers.',
    'Open Redirect': 'Validate redirect targets against an allow-list.',
    '.htaccess Bypass': 'Audit .htaccess rules. Use web server-level access controls.',
  }
  return map[vulnType] || 'Apply appropriate security hardening based on the vulnerability type.'
}

// ---------------------------------------------------------------------------
// Tool: testssl – comprehensive SSL/TLS analysis
// ---------------------------------------------------------------------------
async function runTestssl(host, port, targetUrl, onFinding, onLog) {
  // testssl.sh may be available as 'testssl' or 'testssl.sh'
  const cmd = isToolAvailable('testssl') ? 'testssl' : isToolAvailable('testssl.sh') ? 'testssl.sh' : null
  if (!cmd) return

  onLog('info', `testssl: comprehensive SSL/TLS analysis on ${host}:${port}`)

  const out = await runCommand(cmd, [
    '--fast',
    '--color', '0',
    '--warnings', 'off',
    `${host}:${port}`,
  ], 180_000)

  const evidence = (out.stdout || '').trim()
  if (!evidence) return

  const checks = [
    { pattern: /SSLv2\s+offered|SSLv3\s+offered/i,       title: 'SSL v2/v3 offered', severity: 'critical', cvss: 9.8, cwe: 'CWE-326', cves: ['CVE-2015-3197', 'CVE-2014-3566'] },
    { pattern: /TLS 1\.0\s+offered/i,                     title: 'TLS 1.0 offered (deprecated)', severity: 'medium', cvss: 5.9, cwe: 'CWE-326', cves: [] },
    { pattern: /TLS 1\.1\s+offered/i,                     title: 'TLS 1.1 offered (deprecated)', severity: 'medium', cvss: 5.3, cwe: 'CWE-326', cves: [] },
    { pattern: /VULNERABLE.*BEAST|BEAST.*VULNERABLE/i,     title: 'BEAST attack vulnerability', severity: 'medium', cvss: 5.9, cwe: 'CWE-310', cves: ['CVE-2011-3389'] },
    { pattern: /VULNERABLE.*POODLE|POODLE.*VULNERABLE/i,   title: 'POODLE vulnerability', severity: 'high', cvss: 7.5, cwe: 'CWE-310', cves: ['CVE-2014-3566'] },
    { pattern: /VULNERABLE.*Heartbleed|Heartbleed.*VULNERABLE/i, title: 'Heartbleed vulnerability', severity: 'critical', cvss: 9.8, cwe: 'CWE-125', cves: ['CVE-2014-0160'] },
    { pattern: /VULNERABLE.*DROWN|DROWN.*VULNERABLE/i,     title: 'DROWN vulnerability', severity: 'critical', cvss: 9.8, cwe: 'CWE-310', cves: ['CVE-2016-0800'] },
    { pattern: /VULNERABLE.*LOGJAM|LOGJAM.*VULNERABLE/i,   title: 'LOGJAM DH vulnerability', severity: 'high', cvss: 7.4, cwe: 'CWE-310', cves: ['CVE-2015-4000'] },
    { pattern: /VULNERABLE.*FREAK|FREAK.*VULNERABLE/i,      title: 'FREAK EXPORT cipher vulnerability', severity: 'high', cvss: 7.4, cwe: 'CWE-326', cves: ['CVE-2015-0204'] },
    { pattern: /VULNERABLE.*LUCKY13|LUCKY13.*VULNERABLE/i,  title: 'LUCKY13 vulnerability', severity: 'medium', cvss: 5.9, cwe: 'CWE-310', cves: ['CVE-2013-0169'] },
    { pattern: /VULNERABLE.*CRIME|CRIME.*VULNERABLE/i,      title: 'CRIME compression vulnerability', severity: 'medium', cvss: 5.9, cwe: 'CWE-310', cves: ['CVE-2012-4929'] },
    { pattern: /VULNERABLE.*BREACH|BREACH.*VULNERABLE/i,    title: 'BREACH compression vulnerability', severity: 'medium', cvss: 5.9, cwe: 'CWE-310', cves: ['CVE-2013-3587'] },
    { pattern: /VULNERABLE.*SWEET32|SWEET32.*VULNERABLE/i,  title: 'SWEET32 birthday attack (3DES)', severity: 'medium', cvss: 5.9, cwe: 'CWE-326', cves: ['CVE-2016-2183'] },
    { pattern: /VULNERABLE.*TICKETBLEED|TICKETBLEED.*VULNERABLE/i, title: 'TICKETBLEED vulnerability', severity: 'high', cvss: 7.5, cwe: 'CWE-200', cves: ['CVE-2016-9244'] },
    { pattern: /no HSTS|HSTS.*not sent|HSTS.*missing/i,    title: 'HSTS not configured', severity: 'medium', cvss: 5.3, cwe: 'CWE-16', cves: [] },
    { pattern: /Certificate is expired/i,                   title: 'TLS certificate expired', severity: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [] },
    { pattern: /self.[Ss]igned/i,                           title: 'Self-signed certificate in use', severity: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [] },
    { pattern: /RC4.*offered|EXPORT.*offered/i,             title: 'Weak cipher suites (RC4/EXPORT) offered', severity: 'high', cvss: 7.5, cwe: 'CWE-327', cves: ['CVE-2013-2566'] },
    { pattern: /NULL.*cipher.*offered/i,                    title: 'NULL cipher suite offered (no encryption)', severity: 'critical', cvss: 9.1, cwe: 'CWE-312', cves: [] },
    { pattern: /not protected.*OCSP|no OCSP/i,             title: 'No OCSP stapling', severity: 'low', cvss: 3.7, cwe: 'CWE-295', cves: [] },
  ]

  let foundAny = false
  for (const check of checks) {
    if (check.pattern.test(evidence)) {
      foundAny = true
      onFinding(makeFinding({
        title: `TestSSL: ${check.title}`,
        severity: check.severity,
        cvss: check.cvss,
        cweId: check.cwe,
        cveIds: check.cves,
        description: `TestSSL detected: ${check.title} on ${host}:${port}.`,
        remediation: getTesssslRemediation(check.title),
        aiConfidence: 0.92,
        evidence: { type: 'raw', label: 'testssl output', data: cap(evidence) },
      }, targetUrl))
    }
  }

  if (!foundAny) {
    onLog('info', 'testssl: no critical SSL/TLS issues detected')
  }
}

function getTesssslRemediation(title) {
  if (/SSLv2|SSLv3/.test(title)) return 'Disable SSLv2 and SSLv3. Configure TLS 1.2 and TLS 1.3 only.'
  if (/TLS 1\.0|TLS 1\.1/.test(title)) return 'Disable TLS 1.0 and TLS 1.1. Use TLS 1.2 minimum.'
  if (/Heartbleed/.test(title)) return 'Upgrade OpenSSL immediately. Revoke and reissue certificates.'
  if (/POODLE/.test(title)) return 'Disable SSLv3. Use TLS_FALLBACK_SCSV to prevent downgrade attacks.'
  if (/DROWN/.test(title)) return 'Disable SSLv2 on all servers. Do not share private keys between servers.'
  if (/LOGJAM/.test(title)) return 'Use DH parameters of at least 2048 bits. Disable DHE_EXPORT cipher suites.'
  if (/FREAK/.test(title)) return 'Disable all EXPORT-grade cipher suites on the server.'
  if (/RC4|EXPORT/.test(title)) return 'Remove RC4 and EXPORT cipher suites from SSL configuration.'
  if (/NULL cipher/.test(title)) return 'Remove NULL cipher suites immediately. Any NULL cipher means no encryption.'
  if (/HSTS/.test(title)) return 'Add Strict-Transport-Security header with max-age >= 31536000.'
  if (/expired/.test(title)) return 'Renew the TLS certificate immediately.'
  if (/self.signed/.test(title)) return 'Replace self-signed cert with one from a trusted CA.'
  return 'Apply the relevant SSL/TLS hardening measures as indicated.'
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

const DEFAULT_ADVANCED_TOOLS = [
  'ffuf', 'feroxbuster', 'dalfox', 'commix',
  'dnsrecon', 'fierce', 'amass', 'sublist3r',
  'arjun', 'wapiti', 'testssl',
]

/**
 * scanKaliAdvanced – runs advanced Kali Linux tools for deep security assessment.
 * Enable via: EXTERNAL_SCANNER_ENABLED=true
 * Tool list override: ADVANCED_TOOL_LIST=ffuf,dalfox,...
 */
export async function scanKaliAdvanced(targetUrl, onFinding, onLog) {
  onLog?.('info', `Advanced Kali Tools starting for ${targetUrl}`)

  if (String(process.env.EXTERNAL_SCANNER_ENABLED || 'false').toLowerCase() !== 'true') {
    onLog?.('warn', 'Advanced Kali scanner disabled. Set EXTERNAL_SCANNER_ENABLED=true.')
    return { skipped: true, reason: 'disabled' }
  }

  let urlObj
  try {
    urlObj = new URL(targetUrl)
  } catch {
    return { skipped: true, reason: 'invalid-url' }
  }

  const host = urlObj.hostname
  const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')

  const envList = (process.env.ADVANCED_TOOL_LIST || '').split(',').map((s) => s.trim()).filter(Boolean)
  const toolsToRun = envList.length > 0 ? envList : DEFAULT_ADVANCED_TOOLS

  // testssl may be named testssl.sh
  const testSSLAvailable = isToolAvailable('testssl') || isToolAvailable('testssl.sh')
  const available = toolsToRun.filter((t) =>
    t === 'testssl' ? testSSLAvailable : isToolAvailable(t)
  )

  onLog?.('info', `Available advanced tools: [${available.join(', ')}]`)

  if (available.length === 0) {
    onLog?.('warn', 'No advanced tools found. Install via: apt install ffuf feroxbuster dalfox commix dnsrecon fierce amass sublist3r wapiti')
    return { skipped: true, reason: 'no-tools-available' }
  }

  const findings = []
  const wrappedOnFinding = (f) => {
    findings.push(f)
    onFinding?.(f)
  }

  const handlers = {
    ffuf:       () => runFfuf(targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[ffuf] ${m}`)),
    feroxbuster:() => runFeroxbuster(targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[feroxbuster] ${m}`)),
    dalfox:     () => runDalfox(targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[dalfox] ${m}`)),
    commix:     () => runCommix(targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[commix] ${m}`)),
    dnsrecon:   () => runDnsrecon(host, targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[dnsrecon] ${m}`)),
    fierce:     () => runFierce(host, targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[fierce] ${m}`)),
    amass:      () => runAmass(host, targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[amass] ${m}`)),
    sublist3r:  () => runSublist3r(host, targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[sublist3r] ${m}`)),
    arjun:      () => runArjun(targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[arjun] ${m}`)),
    wapiti:     () => runWapiti(targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[wapiti] ${m}`)),
    testssl:    () => runTestssl(host, port, targetUrl, wrappedOnFinding, (l, m) => onLog?.(l, `[testssl] ${m}`)),
  }

  for (const tool of available) {
    const handler = handlers[tool]
    if (!handler) {
      onLog?.('info', `[advanced] Skipping unknown tool: ${tool}`)
      continue
    }
    try {
      onLog?.('info', `[advanced] Starting: ${tool}`)
      await handler()
      onLog?.('info', `[advanced] Finished: ${tool}`)
    } catch (err) {
      onLog?.('warn', `[advanced] ${tool} error: ${String(err.message || err)}`)
    }
  }

  onLog?.('info', `Advanced Kali Tools complete – ${findings.length} findings generated`)
  return findings
}
