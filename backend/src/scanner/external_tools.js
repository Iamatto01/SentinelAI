/**
 * external_tools.js — Kali Linux Core Tool Integrations
 *
 * Tools: nmap, nikto, whatweb, sqlmap, sslscan, gobuster, wafw00f, wpscan,
 *        masscan, theHarvester, enum4linux-ng, dirb
 *
 * Enable: EXTERNAL_SCANNER_ENABLED=true
 * Select tools: EXTERNAL_TOOL_LIST=nmap,nikto,...  (CSV, default = all)
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
    module: 'External Tools (Kali)',
    aiConfidence: opts.aiConfidence ?? 0.75,
    aiReasoning: opts.aiReasoning || 'Derived from external tool output',
    evidence: opts.evidence || {},
  }
}

function isToolAvailable(tool) {
  try {
    const r = spawnSync('which', [tool], { encoding: 'utf8' })
    return r.status === 0 && Boolean(r.stdout?.trim())
  } catch { return false }
}

function runCommand(cmd, args, timeoutMs = 120_000, env = undefined) {
  return new Promise(resolve => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false, env: env || process.env })
    let stdout = '', stderr = ''
    const to = setTimeout(() => { try { child.kill('SIGKILL') } catch {} ; resolve({ timedOut: true, stdout, stderr, code: null }) }, timeoutMs)
    child.stdout.on('data', d => { stdout += String(d) })
    child.stderr.on('data', d => { stderr += String(d) })
    child.on('close', code => { clearTimeout(to); resolve({ timedOut: false, stdout, stderr, code }) })
    child.on('error', err => { clearTimeout(to); resolve({ timedOut: false, stdout, stderr: String(err.message), code: null }) })
  })
}

function extractCVEs(text) {
  const m = text?.match(/CVE-\d{4}-\d{4,7}/gi) || []
  return [...new Set(m.map(c => c.toUpperCase()))]
}

function cap(str, bytes = 60_000) {
  if (!str) return ''
  return str.length > bytes ? str.substring(0, bytes) + '\n…[truncated]' : str
}

// ---------------------------------------------------------------------------
// Tool: nmap (enhanced)
// ---------------------------------------------------------------------------
async function runNmap(host, port, targetUrl, onFinding, onLog) {
  const baseTimeout = Math.max(15_000, Number(process.env.NMAP_BASE_TIMEOUT_MS || 45_000))
  const vulnTimeout = Math.max(20_000, Number(process.env.NMAP_VULN_TIMEOUT_MS || 60_000))

  const ports = process.env.NMAP_PORTS || '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017'
  onLog('info', `nmap: port scan (${ports}) timeout=${Math.round(baseTimeout/1000)}s`)

  const baseOut = await runCommand('nmap', [
    '-Pn', '-n', '-T4', '--max-retries', '1',
    '--host-timeout', `${Math.max(15, Math.round(baseTimeout/1000))}s`,
    '--initial-rtt-timeout', '500ms', '--max-rtt-timeout', '1000ms',
    '--min-rate', '100', '-sV', '-sC', '--open', '-p', ports,
    '--script', 'http-headers,http-methods,http-auth-finder,http-security-headers,banner',
    host,
  ], baseTimeout)

  if (baseOut.timedOut) onLog('warn', 'nmap: base scan timed out')

  const evidence = baseOut.stdout || ''
  if (evidence.trim()) {
    const cves = extractCVEs(evidence)
    onFinding(makeFinding({
      title: 'Nmap: Port scan & service enumeration',
      severity: 'info', cvss: 0, cweId: 'CWE-200', cveIds: cves,
      description: `Nmap identified open ports/services on ${host}. Review each for unnecessary exposure.`,
      remediation: 'Close unneeded ports via firewall. Keep service versions patched.',
      aiConfidence: 0.92, aiReasoning: 'Direct nmap scan result.',
      evidence: { type: 'raw', label: 'nmap output', data: cap(evidence) },
    }, targetUrl))

    // Flag high-risk open ports
    const dangerous = {
      21:    { t: 'FTP port 21 open (cleartext)', s: 'medium', cvss: 5.3, cwe: 'CWE-319' },
      23:    { t: 'Telnet port 23 open (cleartext RCE risk)', s: 'high', cvss: 7.5, cwe: 'CWE-319' },
      3306:  { t: 'MySQL 3306 publicly exposed', s: 'high', cvss: 7.5, cwe: 'CWE-284' },
      5432:  { t: 'PostgreSQL 5432 publicly exposed', s: 'high', cvss: 7.5, cwe: 'CWE-284' },
      6379:  { t: 'Redis 6379 publicly exposed (no auth by default)', s: 'critical', cvss: 9.8, cwe: 'CWE-284' },
      9200:  { t: 'Elasticsearch 9200 publicly exposed (no auth by default)', s: 'critical', cvss: 9.8, cwe: 'CWE-284' },
      27017: { t: 'MongoDB 27017 publicly exposed', s: 'critical', cvss: 9.8, cwe: 'CWE-284' },
      445:   { t: 'SMB 445 publicly exposed', s: 'high', cvss: 8.1, cwe: 'CWE-284' },
      3389:  { t: 'RDP 3389 publicly exposed (brute-force target)', s: 'high', cvss: 7.5, cwe: 'CWE-284' },
      5900:  { t: 'VNC 5900 publicly exposed', s: 'high', cvss: 7.5, cwe: 'CWE-284' },
      22:    { t: 'SSH 22 publicly reachable', s: 'low', cvss: 3.7, cwe: 'CWE-284' },
      8888:  { t: 'Port 8888 open (possible Jupyter Notebook — no auth)', s: 'high', cvss: 8.1, cwe: 'CWE-284' },
    }
    for (const [p, meta] of Object.entries(dangerous)) {
      if (new RegExp(`${p}/tcp\\s+open`).test(evidence)) {
        onFinding(makeFinding({
          title: `Nmap: ${meta.t}`,
          severity: meta.s, cvss: meta.cvss, cweId: meta.cwe,
          description: `Port ${p}/tcp is open and reachable from the internet.`,
          remediation: `Restrict port ${p} via firewall rules. Only allow trusted source IPs.`,
          aiConfidence: 0.9,
          evidence: { type: 'raw', label: 'nmap port detail', data: cap(evidence) },
        }, targetUrl))
      }
    }
  }

  // Phase 2: vuln scripts
  onLog('info', `nmap: vuln scripts on web ports timeout=${Math.round(vulnTimeout/1000)}s`)
  const vulnOut = await runCommand('nmap', [
    '-Pn', '-n', '-T4', '--max-retries', '1',
    '--host-timeout', `${Math.max(20, Math.round(vulnTimeout/1000))}s`,
    '--initial-rtt-timeout', '500ms', '--max-rtt-timeout', '1000ms',
    '-p', '80,443,8080,8443',
    '--script', 'http-shellshock,http-slowloris-check,http-passwd,ssl-poodle,ssl-heartbleed,ssl-dh-params,http-csrf,http-open-redirect',
    '--script-timeout', '30s', host,
  ], vulnTimeout)

  if (vulnOut.timedOut) onLog('warn', 'nmap: vuln script phase timed out')

  const vEvidence = vulnOut.stdout || ''
  if (/VULNERABLE|shellshock|poodle|heartbleed/i.test(vEvidence)) {
    const cves = extractCVEs(vEvidence)
    if (/heartbleed/i.test(vEvidence)) {
      onFinding(makeFinding({ title: 'Nmap: Heartbleed (CVE-2014-0160)', severity: 'critical', cvss: 9.8, cweId: 'CWE-125', cveIds: ['CVE-2014-0160'], description: 'OpenSSL Heartbleed leaks server memory.', remediation: 'Upgrade OpenSSL immediately. Revoke and reissue all certificates.', aiConfidence: 0.95, evidence: { type: 'raw', label: 'nmap vuln', data: cap(vEvidence) } }, targetUrl))
    }
    if (/poodle/i.test(vEvidence)) {
      onFinding(makeFinding({ title: 'Nmap: POODLE (CVE-2014-3566)', severity: 'high', cvss: 7.5, cweId: 'CWE-310', cveIds: ['CVE-2014-3566'], description: 'POODLE allows MITM decryption via SSLv3.', remediation: 'Disable SSLv3. Enforce TLS 1.2+.', aiConfidence: 0.93, evidence: { type: 'raw', label: 'nmap vuln', data: cap(vEvidence) } }, targetUrl))
    }
    if (/shellshock/i.test(vEvidence)) {
      onFinding(makeFinding({ title: 'Nmap: Shellshock CGI (CVE-2014-6271)', severity: 'critical', cvss: 9.8, cweId: 'CWE-78', cveIds: ['CVE-2014-6271'], description: 'Bash Shellshock allows RCE via CGI.', remediation: 'Patch Bash. Disable CGI execution.', aiConfidence: 0.93, evidence: { type: 'raw', label: 'nmap vuln', data: cap(vEvidence) } }, targetUrl))
    }
    if (cves.length > 0 && !(/heartbleed|poodle|shellshock/i.test(vEvidence))) {
      onFinding(makeFinding({ title: `Nmap: CVEs detected (${cves.slice(0,3).join(', ')})`, severity: 'high', cvss: 7.0, cweId: 'CWE-693', cveIds: cves, description: 'Nmap vuln scripts found potential CVEs.', remediation: 'Apply vendor patches for each identified CVE.', aiConfidence: 0.82, evidence: { type: 'raw', label: 'nmap vuln', data: cap(vEvidence) } }, targetUrl))
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: masscan (fast full-range port scanner)
// ---------------------------------------------------------------------------
async function runMasscan(host, targetUrl, onFinding, onLog) {
  onLog('info', `masscan: fast port scan on ${host}`)

  const rate  = process.env.MASSCAN_RATE || '500'
  const ports = process.env.MASSCAN_PORTS || '1-65535'

  const out = await runCommand('masscan', [
    '-p', ports,
    '--rate', rate,
    '-oJ', '/tmp/masscan_sentinelai.json',
    host,
  ], 120_000)

  // Parse JSON output
  let results = []
  try {
    const { readFileSync } = await import('node:fs')
    const raw = readFileSync('/tmp/masscan_sentinelai.json', 'utf8').trim()
    // masscan JSON may have a trailing comma before ]
    const clean = raw.replace(/,\s*\]/g, ']')
    results = JSON.parse(clean)
  } catch {
    // Fall back to stdout parsing
    const stdout = out.stdout || ''
    const portMatches = stdout.matchAll(/Discovered open port (\d+)\/(\w+) on ([\d.]+)/g)
    for (const m of portMatches) {
      results.push({ ports: [{ port: Number(m[1]), proto: m[2] }], ip: m[3] })
    }
  }

  if (!results.length) {
    onLog('info', 'masscan: no open ports found in range')
    return
  }

  const openPorts = results.flatMap(r => r.ports || []).map(p => p.port).sort((a, b) => a - b)
  const uniquePorts = [...new Set(openPorts)]

  // Flag non-standard ports as potential security concern
  const stdPorts = new Set([21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995])
  const unusual  = uniquePorts.filter(p => !stdPorts.has(p))

  if (unusual.length > 0) {
    onFinding(makeFinding({
      title: `Masscan: ${unusual.length} non-standard port(s) open — ${unusual.slice(0,8).join(', ')}${unusual.length > 8 ? '…' : ''}`,
      severity: unusual.length > 5 ? 'medium' : 'low',
      cvss: unusual.length > 5 ? 5.3 : 3.7,
      cweId: 'CWE-284',
      description: `Full-range port scan found ${uniquePorts.length} total open port(s). Non-standard: ${unusual.join(', ')}`,
      remediation: 'Review each non-standard port. Close or firewall any unnecessary services.',
      aiConfidence: 0.9,
      evidence: { type: 'raw', label: 'masscan results', data: `Open ports: ${uniquePorts.join(', ')}\nRaw:\n${cap(out.stdout || JSON.stringify(results).substring(0, 2000))}` },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `Masscan: ${uniquePorts.length} port(s) open on ${host}`,
    severity: 'info', cvss: 0, cweId: 'CWE-200',
    description: `Masscan full-range scan found ${uniquePorts.length} open ports: ${uniquePorts.join(', ')}`,
    remediation: 'Audit all open ports. Ensure firewall blocks unnecessary services.',
    aiConfidence: 0.9,
    evidence: { type: 'raw', label: 'masscan port list', data: `Ports: ${uniquePorts.join(', ')}` },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: theHarvester (OSINT — emails, subdomains, hosts, IPs)
// ---------------------------------------------------------------------------
async function runTheharvester(host, targetUrl, onFinding, onLog) {
  // theHarvester binary may be 'theharvester' or 'theHarvester'
  const bin = isToolAvailable('theharvester') ? 'theharvester'
            : isToolAvailable('theHarvester')  ? 'theHarvester' : null
  if (!bin) { onLog('warn', 'theHarvester: not found, skipping'); return }

  onLog('info', `theHarvester: OSINT gathering for ${host}`)

  // Use passive sources that don't require API keys
  const out = await runCommand(bin, [
    '-d', host,
    '-b', 'bing,duckduckgo,certspotter,crtsh,dnsdumpster,hackertarget,rapiddns',
    '-l', '200',
    '-f', '/tmp/harvester_sentinelai',
  ], 90_000)

  const evidence = out.stdout || out.stderr || ''
  if (!evidence.trim()) return

  // Parse emails
  const emails = [...new Set((evidence.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []))]
  // Parse IPs
  const ips    = [...new Set((evidence.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(ip => !ip.startsWith('127.') && !ip.startsWith('0.')))]
  // Parse hostnames
  const hostnameRE = new RegExp(`[a-zA-Z0-9][-a-zA-Z0-9]*\\.${host.replace('.', '\\.')}`, 'gi')
  const hosts  = [...new Set((evidence.match(hostnameRE) || []).map(h => h.toLowerCase()))]

  if (emails.length > 0) {
    onFinding(makeFinding({
      title: `theHarvester: ${emails.length} email address(es) discovered`,
      severity: 'low', cvss: 3.7, cweId: 'CWE-200',
      description: `Email addresses found during OSINT: ${emails.slice(0, 10).join(', ')}. These can be used for phishing and social engineering attacks.`,
      remediation: 'Train staff on phishing awareness. Consider email obfuscation on public pages. Monitor for credential leaks.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'theHarvester emails', data: emails.join('\n') },
    }, targetUrl))
  }

  if (hosts.length > 0) {
    const sensitiveSubs = hosts.filter(h => /dev\.|staging\.|test\.|internal\.|admin\.|vpn\.|jenkins\.|git\.|db\./.test(h))
    if (sensitiveSubs.length > 0) {
      onFinding(makeFinding({
        title: `theHarvester: ${sensitiveSubs.length} sensitive subdomain(s) discovered via OSINT`,
        severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
        description: `OSINT revealed sensitive subdomains: ${sensitiveSubs.join(', ')}. These may expose internal infrastructure.`,
        remediation: 'Review exposed subdomains. Remove DNS records for unused services. Use split-horizon DNS.',
        aiConfidence: 0.87,
        evidence: { type: 'raw', label: 'theHarvester sensitive hosts', data: sensitiveSubs.join('\n') },
      }, targetUrl))
    }

    onFinding(makeFinding({
      title: `theHarvester: ${hosts.length} host(s) and ${ips.length} IP(s) found via OSINT`,
      severity: 'info', cvss: 0, cweId: 'CWE-200',
      description: `OSINT gathered ${hosts.length} hostnames and ${ips.length} IPs for ${host}.`,
      remediation: 'Review OSINT findings. Identify and secure any unexpected exposure.',
      aiConfidence: 0.82,
      evidence: { type: 'raw', label: 'theHarvester OSINT', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: enum4linux-ng (SMB/NetBIOS enumeration)
// ---------------------------------------------------------------------------
async function runEnum4linux(host, targetUrl, onFinding, onLog) {
  // Check 445/139 are even open first
  let smbOpen = false
  try {
    const { createConnection } = await import('node:net')
    for (const p of [445, 139]) {
      await new Promise((resolve, reject) => {
        const s = createConnection(p, host)
        s.setTimeout(3000)
        s.on('connect', () => { smbOpen = true; s.destroy(); resolve() })
        s.on('timeout', () => { s.destroy(); resolve() })
        s.on('error', () => resolve())
      })
      if (smbOpen) break
    }
  } catch { /* ignore */ }

  if (!smbOpen) { onLog('info', `enum4linux: SMB ports (445/139) not open on ${host} — skipping`); return }

  const bin = isToolAvailable('enum4linux-ng') ? 'enum4linux-ng'
            : isToolAvailable('enum4linux')     ? 'enum4linux' : null
  if (!bin) { onLog('warn', 'enum4linux: not found, skipping'); return }

  onLog('info', `enum4linux: SMB enumeration on ${host}`)

  const args = bin === 'enum4linux-ng'
    ? ['-A', '-R', host]          // -A: all checks, -R: RID cycling
    : ['-a', '-r', host]          // legacy enum4linux

  const out = await runCommand(bin, args, 90_000)
  const evidence = out.stdout || out.stderr || ''
  if (!evidence.trim()) return

  const cves = extractCVEs(evidence)

  // Check for null session (anonymous access)
  if (/null session|Session.*OK|IPC\$.*anonymous/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'Enum4linux: SMB null session (anonymous access) permitted',
      severity: 'high', cvss: 7.5, cweId: 'CWE-306',
      description: `${host} allows anonymous SMB connections. Attackers can enumerate users, shares, and password policies without credentials.`,
      remediation: 'Disable null sessions in Windows registry (RestrictAnonymous=2). Apply Group Policy to restrict anonymous enumeration.',
      aiConfidence: 0.92, aiReasoning: 'Null session confirmed by enum4linux.',
      evidence: { type: 'raw', label: 'enum4linux SMB', data: cap(evidence) },
    }, targetUrl))
  }

  // Check for usernames leaked
  const userLines = evidence.split('\n').filter(l => /user:|username:|account:/i.test(l)).slice(0, 10)
  if (userLines.length > 0) {
    onFinding(makeFinding({
      title: `Enum4linux: ${userLines.length} user account(s) enumerated via SMB`,
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: `User accounts discoverable via SMB enumeration: ${userLines.map(l => l.trim()).join(' | ')}`,
      remediation: 'Set RestrictAnonymous=2. Restrict SMB access to internal network only.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'enum4linux users', data: userLines.join('\n') },
    }, targetUrl))
  }

  // Check for shares
  const shareLines = evidence.split('\n').filter(l => /Sharename|share|mapping/i.test(l) && !/^\s*$/.test(l)).slice(0, 10)
  if (shareLines.length > 0) {
    const sensShares = shareLines.filter(l => /admin|c\$|ipc\$|sysvol|netlogon/i.test(l))
    if (sensShares.length > 0) {
      onFinding(makeFinding({
        title: `Enum4linux: Administrative shares exposed (${sensShares.length})`,
        severity: 'high', cvss: 7.5, cweId: 'CWE-284',
        description: `Sensitive SMB shares found: ${sensShares.map(l => l.trim()).join(' | ')}`,
        remediation: 'Restrict access to administrative shares. Disable IPC$ anonymous access.',
        aiConfidence: 0.88,
        evidence: { type: 'raw', label: 'enum4linux shares', data: sensShares.join('\n') },
      }, targetUrl))
    }
  }

  // Summary
  onFinding(makeFinding({
    title: `Enum4linux: SMB service enumeration completed on ${host}`,
    severity: 'info', cvss: 0, cweId: 'CWE-200', cveIds: cves,
    description: 'SMB enumeration completed. Review output for sensitive disclosures.',
    remediation: 'Restrict SMB to internal networks. Disable legacy SMBv1. Apply latest Windows patches.',
    aiConfidence: 0.85,
    evidence: { type: 'raw', label: 'enum4linux full output', data: cap(evidence) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: nikto (enhanced)
// ---------------------------------------------------------------------------
async function runNikto(targetUrl, onFinding, onLog) {
  onLog('info', 'nikto: web server vulnerability scan')
  const out = await runCommand('nikto', [
    '-host', targetUrl, '-maxtime', '90', '-nointeractive',
    '-Plugins', 'headers,shellshock,httpoptions,dictionary,auth,ssl',
    '-Format', 'txt',
  ], 120_000)

  const evidence = out.stdout || out.stderr || ''
  if (!evidence.trim()) return

  const cves = extractCVEs(evidence)
  const lines = evidence.split('\n').filter(l => /OSVDB-\d+|CVE-|vulnerability|Interesting|Warning/i.test(l))
  const unique = [...new Set(lines.map(l => l.trim()))].slice(0, 25)

  for (const line of unique) {
    const isHigh = /sql injection|xss|rce|remote code|traversal|include|lfi|rfi|cmd|shell|upload/i.test(line)
    const isMed  = /default|backup|config|exposed|info.*leak|password|credential|phpmyadmin|admin/i.test(line)
    const severity = isHigh ? 'high' : isMed ? 'medium' : 'low'
    onFinding(makeFinding({
      title: `Nikto: ${line.substring(0, 120)}`,
      severity, cvss: isHigh ? 7.5 : isMed ? 5.3 : 3.7,
      cweId: isHigh ? 'CWE-94' : 'CWE-200', cveIds: extractCVEs(line),
      description: `Nikto identified: ${line}`,
      remediation: 'Apply security patches and configuration hardening for identified issues.',
      aiConfidence: 0.70,
      evidence: { type: 'raw', label: 'nikto finding', data: line },
    }, targetUrl))
  }

  if (unique.length === 0 && /Server:|nikto|target/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'Nikto: Web server scan completed', severity: 'info', cvss: 0, cweId: 'CWE-16', cveIds: cves,
      description: 'Nikto completed scan. No high-severity findings automatically parsed; review raw output.',
      remediation: 'Review full nikto output for any flagged items.',
      aiConfidence: 0.65, evidence: { type: 'raw', label: 'nikto output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: whatweb
// ---------------------------------------------------------------------------
async function runWhatweb(targetUrl, onFinding, onLog) {
  onLog('info', 'whatweb: technology fingerprinting')
  const out = await runCommand('whatweb', ['--colour', 'never', '--log-verbose=-', targetUrl], 30_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const versionPattern = /(\w[\w\s]+)\[([^\]]*\d+\.\d+[^\]]*)\]/g
  const versions = []
  let m
  while ((m = versionPattern.exec(evidence)) !== null) versions.push(`${m[1].trim()}: ${m[2].trim()}`)

  if (versions.length > 0) {
    onFinding(makeFinding({
      title: 'WhatWeb: Technology version(s) disclosed',
      severity: 'low', cvss: 3.7, cweId: 'CWE-200',
      description: `WhatWeb detected version disclosure: ${versions.slice(0, 5).join('; ')}`,
      remediation: 'Suppress version info in HTTP headers and error pages. Keep software updated.',
      aiConfidence: 0.80,
      evidence: { type: 'raw', label: 'whatweb versions', data: versions.join('\n') },
    }, targetUrl))
  }
  onFinding(makeFinding({
    title: 'WhatWeb: Technology stack fingerprinted',
    severity: 'info', cvss: 0, cweId: 'CWE-200',
    description: 'WhatWeb identified the target tech stack.',
    remediation: 'Remove or obfuscate technology identifiers: Server header, X-Powered-By, meta generators.',
    aiConfidence: 0.85, evidence: { type: 'raw', label: 'whatweb output', data: cap(evidence) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: sqlmap
// ---------------------------------------------------------------------------
async function runSqlmap(targetUrl, onFinding, onLog) {
  onLog('info', 'sqlmap: SQL injection testing')
  const out = await runCommand('sqlmap', [
    '-u', targetUrl, '--batch', '--level=2', '--risk=2',
    '--forms', '--crawl=2', '--threads=3',
    '--output-dir=/tmp/sqlmap_sentinelai',
  ], 240_000)

  const evidence = out.stdout || out.stderr || ''
  if (!evidence) return

  const vulnerable = /is vulnerable|Parameter:|injectable|payload|sql injection found/i.test(evidence)
  const dbmsMatch  = /DBMS:\s*([\w\s]+)/i.exec(evidence)

  if (vulnerable) {
    const dbms = dbmsMatch ? dbmsMatch[1].trim() : 'unknown'
    onFinding(makeFinding({
      title: `SQLMap: SQL injection confirmed (DBMS: ${dbms})`,
      severity: 'critical', cvss: 9.8, cweId: 'CWE-89',
      description: `SQLMap confirmed SQL injection at ${targetUrl}. DB: ${dbms}. Full data extraction may be possible.`,
      remediation: 'Use parameterised queries. Implement WAF. Apply least-privilege DB accounts.',
      aiConfidence: 0.92, aiReasoning: 'SQLMap confirmed injectable parameter with working payload.',
      evidence: { type: 'raw', label: 'sqlmap output', data: cap(evidence) },
    }, targetUrl))
  } else {
    onLog('info', 'sqlmap: no SQL injection confirmed')
  }
}

// ---------------------------------------------------------------------------
// Tool: sslscan
// ---------------------------------------------------------------------------
async function runSslscan(host, port, targetUrl, onFinding, onLog) {
  onLog('info', `sslscan: SSL/TLS analysis on ${host}:${port}`)
  const out = await runCommand('sslscan', ['--no-colour', `${host}:${port}`], 60_000)
  const evidence = out.stdout || out.stderr || ''
  if (!evidence) return

  const checks = [
    { p: /SSLv2/i,          t: 'SSLv2 enabled',           s: 'critical', cvss: 9.8, cwe: 'CWE-326', cves: ['CVE-2016-0800'] },
    { p: /SSLv3/i,          t: 'SSLv3 enabled (POODLE)',   s: 'high',     cvss: 7.5, cwe: 'CWE-310', cves: ['CVE-2014-3566'] },
    { p: /TLSv1\.0/i,       t: 'TLS 1.0 enabled (deprecated)', s: 'medium', cvss: 5.9, cwe: 'CWE-326', cves: ['CVE-2011-3389'] },
    { p: /TLSv1\.1/i,       t: 'TLS 1.1 enabled (deprecated)', s: 'medium', cvss: 5.3, cwe: 'CWE-326', cves: [] },
    { p: /RC4/i,            t: 'RC4 cipher enabled',      s: 'high',     cvss: 7.5, cwe: 'CWE-327', cves: ['CVE-2013-2566'] },
    { p: /3DES|DES\b/i,     t: 'DES/3DES cipher enabled', s: 'medium',   cvss: 5.9, cwe: 'CWE-327', cves: ['CVE-2016-2183'] },
    { p: /NULL cipher/i,    t: 'NULL cipher — no encryption', s: 'critical', cvss: 9.1, cwe: 'CWE-312', cves: [] },
    { p: /Certificate is self.signed/i, t: 'Self-signed certificate', s: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [] },
    { p: /Certificate expired/i,        t: 'Certificate expired',     s: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [] },
  ]

  for (const check of checks) {
    if (check.p.test(evidence)) {
      onFinding(makeFinding({
        title: `SSLScan: ${check.t}`,
        severity: check.s, cvss: check.cvss, cweId: check.cwe, cveIds: check.cves,
        description: `SSLScan detected: ${check.t} on ${host}:${port}`,
        remediation: 'Disable weak protocols/ciphers. Use TLS 1.2+ with AES-GCM cipher suites.',
        aiConfidence: 0.9, evidence: { type: 'raw', label: 'sslscan output', data: cap(evidence) },
      }, targetUrl))
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: gobuster
// ---------------------------------------------------------------------------
async function runGobuster(host, targetUrl, onFinding, onLog) {
  const wordlist = process.env.GOBUSTER_WORDLIST || '/usr/share/wordlists/dirb/common.txt'
  onLog('info', `gobuster: directory brute-force (${wordlist})`)

  const dirOut = await runCommand('gobuster', [
    'dir', '-u', targetUrl, '-w', wordlist, '-q',
    '-s', '200,204,301,302,307,401,403',
    '-x', 'php,asp,aspx,jsp,txt,bak,zip,sql,conf,env',
    '--no-error',
  ], 90_000)

  const dirEvidence = dirOut.stdout || ''
  if (dirEvidence && /Found:|Status:/i.test(dirEvidence)) {
    const lines = dirEvidence.split('\n').filter(l => /Found:|Status:/i.test(l))
    const sensitive = lines.filter(l => /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|credential|private|\.htaccess|phpmyadmin/i.test(l))

    if (sensitive.length > 0) {
      onFinding(makeFinding({
        title: `Gobuster: ${sensitive.length} sensitive path(s) exposed`,
        severity: 'high', cvss: 7.5, cweId: 'CWE-548',
        description: `Gobuster found sensitive paths: ${sensitive.slice(0,5).map(l => l.trim()).join('; ')}`,
        remediation: 'Restrict access. Remove backup/temp files from web root. Use .htaccess or nginx deny rules.',
        aiConfidence: 0.88,
        evidence: { type: 'raw', label: 'gobuster sensitive paths', data: sensitive.slice(0, 50).join('\n') },
      }, targetUrl))
    }

    onFinding(makeFinding({
      title: `Gobuster: ${lines.length} path(s) discovered`,
      severity: 'info', cvss: 0, cweId: 'CWE-548',
      description: `Directory brute-force found ${lines.length} accessible endpoints.`,
      remediation: 'Audit all discovered paths. Remove unused endpoints.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'gobuster dir output', data: cap(dirEvidence) },
    }, targetUrl))
  }

  // DNS subdomain mode
  onLog('info', 'gobuster: DNS subdomain enumeration')
  const dnsWordlist = '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
  if (isToolAvailable('gobuster')) {
    const dnsOut = await runCommand('gobuster', [
      'dns', '-d', host, '-w', dnsWordlist, '-q', '--no-error',
    ], 60_000)

    const dnsEvidence = dnsOut.stdout || ''
    if (/Found:/i.test(dnsEvidence)) {
      const subs = dnsEvidence.split('\n').filter(l => /Found:/i.test(l))
      const sensitive = subs.filter(l => /dev\.|staging\.|test\.|internal\.|admin\.|api\.|jenkins\./i.test(l))

      if (sensitive.length > 0) {
        onFinding(makeFinding({
          title: `Gobuster DNS: ${sensitive.length} sensitive subdomain(s)`,
          severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
          description: `Gobuster DNS found: ${sensitive.slice(0,5).map(l => l.trim()).join('; ')}`,
          remediation: 'Restrict internal subdomains from public DNS. Use split-horizon DNS.',
          aiConfidence: 0.85,
          evidence: { type: 'raw', label: 'gobuster dns', data: sensitive.slice(0, 30).join('\n') },
        }, targetUrl))
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: dirb (alternative directory scanner)
// ---------------------------------------------------------------------------
async function runDirb(targetUrl, onFinding, onLog) {
  const wordlist = '/usr/share/wordlists/dirb/common.txt'
  onLog('info', `dirb: directory brute-force on ${targetUrl}`)

  const out = await runCommand('dirb', [
    targetUrl, wordlist,
    '-r',            // don't search recursively
    '-z', '100',     // 100ms delay to avoid DoS
    '-S',            // silent (suppress found items to stdout only)
    '-N', '404',     // ignore 404
  ], 120_000)

  const evidence = out.stdout || ''
  if (!evidence.trim()) return

  const found = evidence.split('\n').filter(l => /==>|FOUND/i.test(l) || /CODE:200/.test(l)).slice(0, 30)
  const sensitive = found.filter(l => /admin|\.git|\.env|backup|config|sql|zip|passwd|secret|private/i.test(l))

  if (sensitive.length > 0) {
    onFinding(makeFinding({
      title: `Dirb: ${sensitive.length} sensitive resource(s) found`,
      severity: 'high', cvss: 7.5, cweId: 'CWE-548',
      description: `Dirb discovered sensitive accessible paths: ${sensitive.slice(0,5).join(' | ')}`,
      remediation: 'Remove or block access to sensitive files/directories. Implement proper access controls.',
      aiConfidence: 0.83,
      evidence: { type: 'raw', label: 'dirb sensitive', data: sensitive.join('\n') },
    }, targetUrl))
  }

  if (found.length > 0) {
    onFinding(makeFinding({
      title: `Dirb: ${found.length} URL(s) found via directory brute-force`,
      severity: 'info', cvss: 0, cweId: 'CWE-548',
      description: `Dirb discovered ${found.length} accessible resources.`,
      remediation: 'Audit all discovered paths. Disable directory listing.',
      aiConfidence: 0.80,
      evidence: { type: 'raw', label: 'dirb output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: wafw00f
// ---------------------------------------------------------------------------
async function runWafw00f(targetUrl, onFinding, onLog) {
  onLog('info', 'wafw00f: WAF detection')
  const out = await runCommand('wafw00f', ['-a', targetUrl], 30_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const wafMatch = /(?:is behind|detected|protected by)\s+([\w\s\-.]+)/i.exec(evidence)
  const noWaf    = /no WAF|not behind|No WAF/i.test(evidence)

  if (wafMatch) {
    onFinding(makeFinding({
      title: `WAF Detected: ${wafMatch[1].trim()}`,
      severity: 'info', cvss: 0, cweId: 'CWE-16',
      description: `wafw00f detected a WAF: ${wafMatch[1].trim()}. This may affect scan effectiveness.`,
      remediation: 'WAF is a positive security layer. Keep WAF rules updated. Fix underlying vulnerabilities.',
      aiConfidence: 0.88, evidence: { type: 'raw', label: 'wafw00f', data: cap(evidence) },
    }, targetUrl))
  } else if (noWaf) {
    onFinding(makeFinding({
      title: 'No WAF detected — application directly exposed',
      severity: 'medium', cvss: 5.3, cweId: 'CWE-16',
      description: 'No WAF in front of the application.',
      remediation: 'Deploy a WAF (Cloudflare, AWS WAF, ModSecurity) for defence-in-depth.',
      aiConfidence: 0.75, evidence: { type: 'raw', label: 'wafw00f', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: wpscan
// ---------------------------------------------------------------------------
async function runWpscan(targetUrl, onFinding, onLog) {
  onLog('info', 'wpscan: WordPress detection')
  const detectOut = await runCommand('wpscan', [
    '--url', targetUrl, '--no-banner', '--disable-tls-checks',
    '--detection-mode', 'passive', '--format', 'cli-no-colour',
  ], 30_000)

  const detectEvidence = detectOut.stdout || detectOut.stderr || ''
  if (!/wordpress|wp-content|wp-includes/i.test(detectEvidence)) {
    onLog('info', 'wpscan: WordPress not detected, skipping')
    return
  }

  onLog('info', 'wpscan: WordPress found — running full scan')
  const fullOut = await runCommand('wpscan', [
    '--url', targetUrl, '--no-banner', '--disable-tls-checks',
    '--enumerate', 'u,vp,vt,tt,cb,dbe', '--format', 'cli-no-colour',
  ], 180_000)

  const evidence = fullOut.stdout || fullOut.stderr || ''
  if (!evidence) return

  const cves = extractCVEs(evidence)

  if (/Username:|user found/i.test(evidence)) {
    const userLines = evidence.split('\n').filter(l => /Username:|Found:/i.test(l)).slice(0, 5)
    onFinding(makeFinding({
      title: 'WPScan: WordPress user enumeration possible',
      severity: 'medium', cvss: 5.3, cweId: 'CWE-200',
      description: `Users discoverable: ${userLines.join(' | ')}`,
      remediation: 'Disable author archives. Use security plugin. Enforce strong passwords and 2FA.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'wpscan users', data: userLines.join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: `WPScan: WordPress installation found${cves.length > 0 ? ' — vulnerabilities detected' : ''}`,
    severity: cves.length > 0 ? 'high' : 'info', cvss: cves.length > 0 ? 7.0 : 0,
    cweId: 'CWE-1035', cveIds: cves.slice(0, 5),
    description: 'WordPress CMS detected. WPScan assessed core, plugins, and themes.',
    remediation: 'Keep WordPress/plugins/themes updated. Disable XML-RPC if unused. Use Wordfence.',
    aiConfidence: 0.9,
    evidence: { type: 'raw', label: 'wpscan full output', data: cap(evidence) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

const DEFAULT_TOOLS = ['nmap', 'masscan', 'nikto', 'whatweb', 'sqlmap', 'sslscan', 'gobuster', 'dirb', 'wafw00f', 'wpscan', 'theharvester', 'enum4linux']

export async function scanExternal(targetUrl, onFinding, onLog) {
  onLog?.('info', `External Tools (Kali) starting for ${targetUrl}`)

  if (String(process.env.EXTERNAL_SCANNER_ENABLED || 'false').toLowerCase() !== 'true') {
    onLog?.('warn', 'External scanner disabled. Set EXTERNAL_SCANNER_ENABLED=true to enable.')
    return { skipped: true, reason: 'disabled' }
  }

  let urlObj
  try { urlObj = new URL(targetUrl) } catch {
    onLog?.('error', `Invalid URL: ${targetUrl}`)
    return { skipped: true, reason: 'invalid-url' }
  }

  const host = urlObj.hostname
  const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')

  const envList  = (process.env.EXTERNAL_TOOL_LIST || '').split(',').map(s => s.trim()).filter(Boolean)
  const wantList = envList.length > 0 ? envList : DEFAULT_TOOLS

  // Resolve aliases (theHarvester / theharvester)
  const resolveAlias = t => {
    if (t === 'theharvester' || t === 'theHarvester') return isToolAvailable('theharvester') ? 'theharvester' : isToolAvailable('theHarvester') ? 'theHarvester' : null
    if (t === 'enum4linux')  return isToolAvailable('enum4linux-ng') ? 'enum4linux-ng' : isToolAvailable('enum4linux') ? 'enum4linux' : null
    return isToolAvailable(t) ? t : null
  }

  const available = wantList.map(resolveAlias).filter(Boolean)
  onLog?.('info', `Available tools: [${available.join(', ')}]`)

  if (available.length === 0) {
    onLog?.('warn', 'No external tools found. Install: apt install nmap masscan nikto whatweb sqlmap sslscan gobuster dirb wafw00f wpscan theharvester enum4linux-ng')
    return { skipped: true, reason: 'no-tools-available' }
  }

  const findings = []
  const wrap = f => { findings.push(f); onFinding?.(f) }

  const handlers = {
    nmap:           () => runNmap(host, port, targetUrl, wrap, (l, m) => onLog?.(l, `[nmap] ${m}`)),
    masscan:        () => runMasscan(host, targetUrl, wrap, (l, m) => onLog?.(l, `[masscan] ${m}`)),
    nikto:          () => runNikto(targetUrl, wrap, (l, m) => onLog?.(l, `[nikto] ${m}`)),
    whatweb:        () => runWhatweb(targetUrl, wrap, (l, m) => onLog?.(l, `[whatweb] ${m}`)),
    sqlmap:         () => runSqlmap(targetUrl, wrap, (l, m) => onLog?.(l, `[sqlmap] ${m}`)),
    sslscan:        () => runSslscan(host, port, targetUrl, wrap, (l, m) => onLog?.(l, `[sslscan] ${m}`)),
    gobuster:       () => runGobuster(host, targetUrl, wrap, (l, m) => onLog?.(l, `[gobuster] ${m}`)),
    dirb:           () => runDirb(targetUrl, wrap, (l, m) => onLog?.(l, `[dirb] ${m}`)),
    wafw00f:        () => runWafw00f(targetUrl, wrap, (l, m) => onLog?.(l, `[wafw00f] ${m}`)),
    wpscan:         () => runWpscan(targetUrl, wrap, (l, m) => onLog?.(l, `[wpscan] ${m}`)),
    theharvester:   () => runTheharvester(host, targetUrl, wrap, (l, m) => onLog?.(l, `[theHarvester] ${m}`)),
    theHarvester:   () => runTheharvester(host, targetUrl, wrap, (l, m) => onLog?.(l, `[theHarvester] ${m}`)),
    'enum4linux-ng':() => runEnum4linux(host, targetUrl, wrap, (l, m) => onLog?.(l, `[enum4linux] ${m}`)),
    enum4linux:     () => runEnum4linux(host, targetUrl, wrap, (l, m) => onLog?.(l, `[enum4linux] ${m}`)),
  }

  for (const tool of available) {
    const handler = handlers[tool]
    if (!handler) { onLog?.('info', `[external] Skipping unknown tool: ${tool}`); continue }
    try {
      onLog?.('info', `[external] Starting: ${tool}`)
      await handler()
      onLog?.('info', `[external] Finished: ${tool}`)
    } catch (err) {
      onLog?.('warn', `[external] ${tool} error: ${String(err.message || err)}`)
    }
  }

  onLog?.('info', `External Tools complete — ${findings.length} findings`)
  return findings
}
