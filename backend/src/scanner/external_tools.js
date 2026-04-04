import { randomUUID } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { URL } from 'node:url'

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity || 'info',
    cvss: opts.cvss || 0,
    cweId: opts.cweId || 'CWE-200',
    cveIds: opts.cveIds || [],
    status: 'open',
    asset: opts.asset || targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description || '',
    remediation: opts.remediation || '',
    module: 'External Tools (Kali)',
    aiConfidence: opts.aiConfidence || 0.75,
    aiReasoning: opts.aiReasoning || 'Derived from external tool output',
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

function runCommand(cmd, args, timeoutMs = 120000, env = undefined) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      env: env || process.env,
    })
    let stdout = ''
    let stderr = ''
    const to = setTimeout(() => {
      try { child.kill('SIGKILL') } catch (_) {}
      resolve({ timedOut: true, stdout, stderr, code: null })
    }, timeoutMs)

    child.stdout.on('data', (d) => { stdout += String(d) })
    child.stderr.on('data', (d) => { stderr += String(d) })
    child.on('close', (code) => {
      clearTimeout(to)
      resolve({ timedOut: false, stdout, stderr, code })
    })
    child.on('error', (err) => {
      clearTimeout(to)
      resolve({ timedOut: false, stdout, stderr: String(err.message || err), code: null })
    })
  })
}

/** Extract CVE IDs from any text blob */
function extractCVEs(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || []
  return [...new Set(matches.map((c) => c.toUpperCase()))]
}

/** Cap raw evidence output to avoid enormous DB entries */
function cap(str, bytes = 60_000) {
  if (!str) return ''
  return str.length > bytes ? str.substring(0, bytes) + '\n...[truncated]' : str
}

// ---------------------------------------------------------------------------
// Tool: nmap (enhanced)
// ---------------------------------------------------------------------------
async function runNmap(host, port, targetUrl, onFinding, onLog) {
  const nmapBaseTimeoutMs = Math.max(15_000, Number(process.env.NMAP_BASE_TIMEOUT_MS || 45_000))
  const nmapVulnTimeoutMs = Math.max(20_000, Number(process.env.NMAP_VULN_TIMEOUT_MS || 60_000))

  // Phase 1 – port scan + service/version detection on common web ports + extra
  const ports = process.env.NMAP_PORTS || '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,27017'
  onLog('info', `nmap: scanning ports ${ports} (timeout ${Math.round(nmapBaseTimeoutMs / 1000)}s)`)
  const baseOut = await runCommand('nmap', [
    '-Pn',
    '-n',
    '-T4',
    '--max-retries', '1',
    '--host-timeout', `${Math.max(15, Math.round(nmapBaseTimeoutMs / 1000))}s`,
    '--initial-rtt-timeout', '500ms',
    '--max-rtt-timeout', '1000ms',
    '--min-rate', '100',
    '-sV', '-sC', '--open', '-p', ports,
    '--script', 'http-headers,http-methods,http-auth-finder,http-security-headers',
    host,
  ], nmapBaseTimeoutMs)

  if (baseOut.timedOut) {
    onLog('warn', 'nmap: base scan timed out, continuing with partial/empty result')
  }

  const evidence = baseOut.stdout || ''
  if (evidence.trim()) {
    const cves = extractCVEs(evidence)
    onFinding(makeFinding({
      title: 'Nmap: port scan & service enumeration',
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-200',
      cveIds: cves,
      description: `Nmap identified open ports and running services on ${host}. Review each open port/service for unnecessary exposure.`,
      remediation: 'Close unneeded ports via firewall rules. Upgrade outdated service versions.',
      aiConfidence: 0.92,
      aiReasoning: 'Direct scan result from nmap service detection.',
      evidence: { type: 'raw', label: 'nmap output', data: cap(evidence) },
    }, targetUrl))

    // Flag dangerous open ports individually
    const dangerousPorts = {
      21: { title: 'FTP port 21 open', severity: 'medium', cvss: 5.3, cwe: 'CWE-319' },
      23: { title: 'Telnet port 23 open (cleartext protocol)', severity: 'high', cvss: 7.5, cwe: 'CWE-319' },
      3306: { title: 'MySQL port 3306 publicly exposed', severity: 'high', cvss: 7.5, cwe: 'CWE-284' },
      5432: { title: 'PostgreSQL port 5432 publicly exposed', severity: 'high', cvss: 7.5, cwe: 'CWE-284' },
      6379: { title: 'Redis port 6379 publicly exposed (no auth by default)', severity: 'critical', cvss: 9.8, cwe: 'CWE-284' },
      27017: { title: 'MongoDB port 27017 publicly exposed', severity: 'critical', cvss: 9.8, cwe: 'CWE-284' },
      445: { title: 'SMB port 445 publicly exposed', severity: 'high', cvss: 8.1, cwe: 'CWE-284' },
      3389: { title: 'RDP port 3389 publicly exposed', severity: 'high', cvss: 7.5, cwe: 'CWE-284' },
      22: { title: 'SSH port 22 publicly reachable', severity: 'low', cvss: 3.7, cwe: 'CWE-284' },
    }
    for (const [p, meta] of Object.entries(dangerousPorts)) {
      if (new RegExp(`${p}/tcp\\s+open`).test(evidence)) {
        onFinding(makeFinding({
          title: `Nmap: ${meta.title}`,
          severity: meta.severity,
          cvss: meta.cvss,
          cweId: meta.cwe,
          description: `Port ${p}/tcp is open and reachable. ${meta.title}.`,
          remediation: `Restrict access to port ${p} via firewall. Only allow trusted IPs if the service is required.`,
          aiConfidence: 0.9,
          evidence: { type: 'raw', label: 'nmap port detail', data: cap(evidence) },
        }, targetUrl))
      }
    }
  }

  // Phase 2 – lightweight vuln scripts on web ports only
  onLog('info', `nmap: running vuln scripts on web ports (timeout ${Math.round(nmapVulnTimeoutMs / 1000)}s)`)
  const vulnOut = await runCommand('nmap', [
    '-Pn',
    '-n',
    '-T4',
    '--max-retries', '1',
    '--host-timeout', `${Math.max(20, Math.round(nmapVulnTimeoutMs / 1000))}s`,
    '--initial-rtt-timeout', '500ms',
    '--max-rtt-timeout', '1000ms',
    '--min-rate', '100',
    '-p', '80,443,8080,8443',
    '--script', 'http-shellshock,http-slowloris-check,http-passwd,ssl-poodle,ssl-heartbleed,ssl-dh-params',
    '--script-timeout', '30s',
    host,
  ], nmapVulnTimeoutMs)

  if (vulnOut.timedOut) {
    onLog('warn', 'nmap: vuln script phase timed out, continuing scan')
  }

  const vEvidence = vulnOut.stdout || ''
  if (vEvidence.trim() && /VULNERABLE|shellshock|poodle|heartbleed/i.test(vEvidence)) {
    const cves = extractCVEs(vEvidence)
    const isHeartbleed = /heartbleed/i.test(vEvidence)
    const isPoodle = /poodle/i.test(vEvidence)
    const isShellshock = /shellshock/i.test(vEvidence)

    if (isHeartbleed) {
      onFinding(makeFinding({
        title: 'Nmap: Heartbleed vulnerability detected (CVE-2014-0160)',
        severity: 'critical',
        cvss: 9.8,
        cweId: 'CWE-125',
        cveIds: ['CVE-2014-0160'],
        description: 'The target appears vulnerable to Heartbleed, a critical OpenSSL bug that leaks server memory.',
        remediation: 'Upgrade OpenSSL to 1.0.1g or later immediately. Revoke and reissue all certificates.',
        aiConfidence: 0.95,
        evidence: { type: 'raw', label: 'nmap vuln output', data: cap(vEvidence) },
      }, targetUrl))
    }
    if (isPoodle) {
      onFinding(makeFinding({
        title: 'Nmap: POODLE vulnerability detected (CVE-2014-3566)',
        severity: 'high',
        cvss: 7.5,
        cweId: 'CWE-310',
        cveIds: ['CVE-2014-3566'],
        description: 'POODLE allows a man-in-the-middle attacker to decrypt encrypted connections using SSLv3 padding oracle.',
        remediation: 'Disable SSLv3 on all services. Enforce TLS 1.2 or later.',
        aiConfidence: 0.93,
        evidence: { type: 'raw', label: 'nmap vuln output', data: cap(vEvidence) },
      }, targetUrl))
    }
    if (isShellshock) {
      onFinding(makeFinding({
        title: 'Nmap: Shellshock CGI vulnerability detected (CVE-2014-6271)',
        severity: 'critical',
        cvss: 9.8,
        cweId: 'CWE-78',
        cveIds: ['CVE-2014-6271', 'CVE-2014-7169'],
        description: 'Bash Shellshock allows remote code execution via crafted environment variables in CGI scripts.',
        remediation: 'Update Bash to a patched version. Remove or disable CGI execution.',
        aiConfidence: 0.93,
        evidence: { type: 'raw', label: 'nmap vuln output', data: cap(vEvidence) },
      }, targetUrl))
    }
    if (!isHeartbleed && !isPoodle && !isShellshock && cves.length > 0) {
      onFinding(makeFinding({
        title: `Nmap: vulnerabilities detected (${cves.slice(0, 3).join(', ')})`,
        severity: 'high',
        cvss: 7.0,
        cweId: 'CWE-693',
        cveIds: cves,
        description: 'Nmap vulnerability scripts identified one or more potential CVEs on the target.',
        remediation: 'Review and patch each identified CVE. Apply vendor-supplied security updates.',
        aiConfidence: 0.82,
        evidence: { type: 'raw', label: 'nmap vuln output', data: cap(vEvidence) },
      }, targetUrl))
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: nikto (enhanced)
// ---------------------------------------------------------------------------
async function runNikto(targetUrl, onFinding, onLog) {
  onLog('info', 'nikto: starting web server scan')
  const out = await runCommand('nikto', [
    '-host', targetUrl,
    '-maxtime', '90',
    '-nointeractive',
    '-Format', 'txt',
  ], 120_000)

  const evidence = out.stdout || out.stderr || ''
  if (!evidence.trim()) return

  const cves = extractCVEs(evidence)

  // Parse individual OSVDB entries as separate findings
  const osvdbLines = evidence.split('\n').filter((l) => /OSVDB-\d+/i.test(l))
  const unique = [...new Set(osvdbLines.map((l) => l.trim()))].slice(0, 20)

  if (unique.length > 0) {
    for (const line of unique) {
      const isHighRisk = /sql injection|xss|rce|remote code|exec|eval|traversal|include|lfi|rfi|cmd|shell|upload/i.test(line)
      const isMedRisk = /default|backup|config|exposed|info\s*leak|password|credential|phpmyadmin|admin/i.test(line)
      const severity = isHighRisk ? 'high' : isMedRisk ? 'medium' : 'low'
      const cvss = isHighRisk ? 7.5 : isMedRisk ? 5.3 : 3.7

      onFinding(makeFinding({
        title: `Nikto: ${line.substring(0, 120)}`,
        severity,
        cvss,
        cweId: isHighRisk ? 'CWE-94' : 'CWE-200',
        cveIds: extractCVEs(line),
        description: `Nikto identified a potential issue: ${line}`,
        remediation: 'Review nikto findings and apply appropriate security patches or configuration hardening.',
        aiConfidence: 0.7,
        evidence: { type: 'raw', label: 'nikto finding', data: line },
      }, targetUrl))
    }
  } else if (/Server:|nikto|target/i.test(evidence)) {
    onFinding(makeFinding({
      title: 'Nikto: web server scan results',
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-16',
      cveIds: cves,
      description: 'Nikto web scanner found potential issues with the target web server.',
      remediation: 'Review full nikto output and address each flagged item.',
      aiConfidence: 0.7,
      evidence: { type: 'raw', label: 'nikto output', data: cap(evidence) },
    }, targetUrl))
  }
}

// ---------------------------------------------------------------------------
// Tool: whatweb (enhanced)
// ---------------------------------------------------------------------------
async function runWhatweb(targetUrl, onFinding, onLog) {
  onLog('info', 'whatweb: fingerprinting technologies')
  const out = await runCommand('whatweb', ['--colour', 'never', '--log-verbose=-', targetUrl], 30_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  // Detect version disclosures
  const versionPattern = /(\w[\w\s]+)\[([^\]]*\d+\.\d+[^\]]*)\]/g
  const versions = []
  let m
  while ((m = versionPattern.exec(evidence)) !== null) {
    versions.push(`${m[1].trim()}: ${m[2].trim()}`)
  }

  if (versions.length > 0) {
    onFinding(makeFinding({
      title: 'WhatWeb: technology versions disclosed',
      severity: 'low',
      cvss: 3.7,
      cweId: 'CWE-200',
      description: `WhatWeb detected version information being disclosed: ${versions.slice(0, 5).join('; ')}`,
      remediation: 'Suppress version information in HTTP headers and error pages. Keep software up to date.',
      aiConfidence: 0.8,
      evidence: { type: 'raw', label: 'whatweb versions', data: versions.join('\n') },
    }, targetUrl))
  }

  onFinding(makeFinding({
    title: 'WhatWeb: technology stack fingerprint',
    severity: 'info',
    cvss: 0,
    cweId: 'CWE-200',
    description: 'WhatWeb identified the target technology stack. Exposed version info can aid attacker reconnaissance.',
    remediation: 'Remove or obscure version headers and meta-tags. Apply security through obscurity as a defence-in-depth measure.',
    aiConfidence: 0.85,
    evidence: { type: 'raw', label: 'whatweb output', data: cap(evidence) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Tool: sqlmap (enhanced)
// ---------------------------------------------------------------------------
async function runSqlmap(targetUrl, onFinding, onLog) {
  onLog('info', 'sqlmap: testing for SQL injection')
  const out = await runCommand('sqlmap', [
    '-u', targetUrl,
    '--batch',
    '--level=2',
    '--risk=2',
    '--forms',
    '--crawl=2',
    '--threads=3',
    '--output-dir=/tmp/sqlmap_sentinelai',
  ], 240_000)

  const evidence = out.stdout || out.stderr || ''
  if (!evidence) return

  const isVulnerable = /is vulnerable|Parameter:|injectable|payload|sql injection found/i.test(evidence)
  const dbmsDetected = /DBMS:\s*([\w\s]+)/i.exec(evidence)

  if (isVulnerable) {
    const dbms = dbmsDetected ? dbmsDetected[1].trim() : 'unknown'
    onFinding(makeFinding({
      title: `SQLMap: SQL injection vulnerability detected (DBMS: ${dbms})`,
      severity: 'critical',
      cvss: 9.8,
      cweId: 'CWE-89',
      cveIds: [],
      description: `SQLMap confirmed SQL injection on ${targetUrl}. Database: ${dbms}. An attacker can extract, modify, or delete database contents.`,
      remediation: 'Use parameterised queries / prepared statements. Implement a WAF. Apply least-privilege DB accounts.',
      aiConfidence: 0.92,
      aiReasoning: 'SQLMap confirmed injectable parameter with working payload.',
      evidence: { type: 'raw', label: 'sqlmap output', data: cap(evidence) },
    }, targetUrl))
  } else if (/tested|checking/i.test(evidence)) {
    onLog('info', 'sqlmap: no SQL injection confirmed')
  }
}

// ---------------------------------------------------------------------------
// Tool: sslscan (enhanced)
// ---------------------------------------------------------------------------
async function runSslscan(host, port, targetUrl, onFinding, onLog) {
  onLog('info', 'sslscan: deep SSL/TLS analysis')
  const out = await runCommand('sslscan', [
    '--no-colour',
    `${host}:${port}`,
  ], 60_000)

  const evidence = out.stdout || out.stderr || ''
  if (!evidence) return

  const checks = [
    { pattern: /SSLv2/i, title: 'SSLv2 protocol enabled', severity: 'critical', cvss: 9.8, cwe: 'CWE-326', cves: ['CVE-2016-0800'], remediation: 'Disable SSLv2 immediately.' },
    { pattern: /SSLv3/i, title: 'SSLv3 protocol enabled (POODLE)', severity: 'high', cvss: 7.5, cwe: 'CWE-310', cves: ['CVE-2014-3566'], remediation: 'Disable SSLv3. Enforce TLS 1.2+.' },
    { pattern: /TLSv1\.0/i, title: 'TLS 1.0 enabled (deprecated)', severity: 'medium', cvss: 5.9, cwe: 'CWE-326', cves: ['CVE-2011-3389'], remediation: 'Disable TLS 1.0. Use TLS 1.2 or TLS 1.3 only.' },
    { pattern: /TLSv1\.1/i, title: 'TLS 1.1 enabled (deprecated)', severity: 'medium', cvss: 5.3, cwe: 'CWE-326', cves: [], remediation: 'Disable TLS 1.1. Use TLS 1.2 or TLS 1.3 only.' },
    { pattern: /RC4/i, title: 'RC4 cipher suite enabled (weak)', severity: 'high', cvss: 7.5, cwe: 'CWE-327', cves: ['CVE-2013-2566'], remediation: 'Disable all RC4 cipher suites.' },
    { pattern: /DES\b|3DES/i, title: 'DES/3DES cipher suite enabled (weak)', severity: 'medium', cvss: 5.9, cwe: 'CWE-327', cves: ['CVE-2016-2183'], remediation: 'Disable DES and 3DES ciphers. Use AES-GCM.' },
    { pattern: /NULL cipher/i, title: 'NULL cipher suite enabled (no encryption)', severity: 'critical', cvss: 9.1, cwe: 'CWE-312', cves: [], remediation: 'Remove NULL cipher suites from SSL configuration.' },
    { pattern: /EXPORT/i, title: 'EXPORT-grade cipher enabled (FREAK)', severity: 'high', cvss: 7.4, cwe: 'CWE-326', cves: ['CVE-2015-0204'], remediation: 'Disable all EXPORT-grade cipher suites.' },
    { pattern: /Certificate is self.signed/i, title: 'Self-signed certificate in use', severity: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [], remediation: 'Replace with a certificate issued by a trusted CA.' },
    { pattern: /Certificate expired/i, title: 'SSL certificate has expired', severity: 'high', cvss: 7.5, cwe: 'CWE-295', cves: [], remediation: 'Renew the certificate immediately.' },
  ]

  let foundAny = false
  for (const check of checks) {
    if (check.pattern.test(evidence)) {
      foundAny = true
      onFinding(makeFinding({
        title: `SSLScan: ${check.title}`,
        severity: check.severity,
        cvss: check.cvss,
        cweId: check.cwe,
        cveIds: check.cves,
        description: `SSLScan detected: ${check.title}. This weakens transport-layer security.`,
        remediation: check.remediation,
        aiConfidence: 0.9,
        evidence: { type: 'raw', label: 'sslscan output', data: cap(evidence) },
      }, targetUrl))
    }
  }

  if (!foundAny) {
    onLog('info', 'sslscan: no critical SSL issues detected')
  }
}

// ---------------------------------------------------------------------------
// Tool: gobuster (enhanced – dir + dns + vhost)
// ---------------------------------------------------------------------------
async function runGobuster(host, targetUrl, onFinding, onLog) {
  const wordlist = process.env.GOBUSTER_WORDLIST || '/usr/share/wordlists/dirb/common.txt'
  const medWordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

  // Mode 1: directory/file bruteforce
  onLog('info', `gobuster: directory brute-force (wordlist: ${wordlist})`)
  const dirOut = await runCommand('gobuster', [
    'dir', '-u', targetUrl, '-w', wordlist, '-q',
    '-s', '200,204,301,302,307,401,403',
    '-x', 'php,asp,aspx,jsp,txt,bak,zip,sql,conf,env',
    '--no-error',
  ], 90_000)

  const dirEvidence = dirOut.stdout || ''
  if (dirEvidence && /Found:|Status:/i.test(dirEvidence)) {
    const lines = dirEvidence.split('\n').filter((l) => /Found:|Status:/i.test(l))
    const sensitiveHits = lines.filter((l) =>
      /admin|\.env|\.git|backup|config|\.sql|\.zip|secret|passwd|credential|private|\.htaccess|phpmyadmin/i.test(l)
    )

    if (sensitiveHits.length > 0) {
      onFinding(makeFinding({
        title: `Gobuster: ${sensitiveHits.length} sensitive path(s) exposed`,
        severity: 'high',
        cvss: 7.5,
        cweId: 'CWE-548',
        description: `Gobuster discovered sensitive accessible paths: ${sensitiveHits.slice(0, 5).map((l) => l.trim()).join('; ')}`,
        remediation: 'Restrict access to sensitive files via web server configuration. Remove backup/temp files from public directories.',
        aiConfidence: 0.88,
        evidence: { type: 'raw', label: 'gobuster dir findings', data: sensitiveHits.slice(0, 50).join('\n') },
      }, targetUrl))
    }

    onFinding(makeFinding({
      title: `Gobuster: ${lines.length} path(s) discovered via brute-force`,
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-548',
      description: 'Directory brute-force revealed accessible endpoints. These may expose unintended functionality.',
      remediation: 'Audit all discovered paths. Remove or restrict unneeded endpoints.',
      aiConfidence: 0.85,
      evidence: { type: 'raw', label: 'gobuster dir output', data: cap(dirEvidence) },
    }, targetUrl))
  }

  // Mode 2: DNS subdomain enumeration
  const dnsList = '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
  if (isToolAvailable('gobuster')) {
    onLog('info', 'gobuster: DNS subdomain enumeration')
    const dnsOut = await runCommand('gobuster', [
      'dns', '-d', host, '-w',
      dnsList || '/usr/share/wordlists/dirb/common.txt',
      '-q', '--no-error',
    ], 60_000)

    const dnsEvidence = dnsOut.stdout || ''
    if (dnsEvidence && /Found:/i.test(dnsEvidence)) {
      const subdomains = dnsEvidence.split('\n').filter((l) => /Found:/i.test(l))
      const sensitive = subdomains.filter((l) =>
        /dev\.|staging\.|test\.|internal\.|admin\.|api\.|jenkins\.|gitlab\.|ci\.|db\.|vpn\.|dashboard\./i.test(l)
      )
      if (sensitive.length > 0) {
        onFinding(makeFinding({
          title: `Gobuster DNS: ${sensitive.length} sensitive subdomain(s) found`,
          severity: 'medium',
          cvss: 5.3,
          cweId: 'CWE-200',
          description: `Gobuster DNS mode discovered sensitive subdomains: ${sensitive.slice(0, 5).map((l) => l.trim()).join('; ')}`,
          remediation: 'Restrict public DNS exposure of internal/development subdomains. Implement split-horizon DNS.',
          aiConfidence: 0.85,
          evidence: { type: 'raw', label: 'gobuster dns findings', data: sensitive.slice(0, 30).join('\n') },
        }, targetUrl))
      }
      if (subdomains.length > 0) {
        onFinding(makeFinding({
          title: `Gobuster DNS: ${subdomains.length} subdomain(s) discovered`,
          severity: 'info',
          cvss: 0,
          cweId: 'CWE-200',
          description: `DNS enumeration discovered ${subdomains.length} active subdomains.`,
          remediation: 'Audit discovered subdomains for unnecessary exposure.',
          aiConfidence: 0.82,
          evidence: { type: 'raw', label: 'gobuster dns output', data: cap(dnsEvidence) },
        }, targetUrl))
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Tool: wafw00f – WAF detection
// ---------------------------------------------------------------------------
async function runWafw00f(targetUrl, onFinding, onLog) {
  onLog('info', 'wafw00f: detecting Web Application Firewall')
  const out = await runCommand('wafw00f', ['-a', targetUrl], 30_000)
  const evidence = (out.stdout || out.stderr || '').trim()
  if (!evidence) return

  const wafMatch = /(?:is behind|detected|protected by)\s+([\w\s\-\.]+)/i.exec(evidence)
  const noWaf = /no WAF|not behind|No WAF/i.test(evidence)

  if (wafMatch) {
    onFinding(makeFinding({
      title: `WAF Detected: ${wafMatch[1].trim()}`,
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-16',
      description: `wafw00f detected a WAF protecting the target: ${wafMatch[1].trim()}. This affects the effectiveness of automated scans and manual testing.`,
      remediation: 'WAF is a positive security control. Ensure WAF rules are regularly updated. Do not rely solely on WAF; fix underlying vulnerabilities.',
      aiConfidence: 0.88,
      evidence: { type: 'raw', label: 'wafw00f output', data: cap(evidence) },
    }, targetUrl))
  } else if (noWaf) {
    onFinding(makeFinding({
      title: 'No Web Application Firewall (WAF) detected',
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-16',
      description: 'No WAF was detected in front of the application. The application is directly exposed to web attacks.',
      remediation: 'Deploy a WAF (e.g., ModSecurity, Cloudflare WAF, AWS WAF) for defence-in-depth against common web attacks.',
      aiConfidence: 0.75,
      evidence: { type: 'raw', label: 'wafw00f output', data: cap(evidence) },
    }, targetUrl))
  } else if (evidence) {
    onLog('info', `wafw00f: ${evidence.slice(0, 200)}`)
  }
}

// ---------------------------------------------------------------------------
// Tool: wpscan – WordPress scanner
// ---------------------------------------------------------------------------
async function runWpscan(targetUrl, onFinding, onLog) {
  onLog('info', 'wpscan: checking for WordPress installation')
  // Quick detection first
  const detectOut = await runCommand('wpscan', [
    '--url', targetUrl,
    '--no-banner',
    '--disable-tls-checks',
    '--detection-mode', 'passive',
    '--format', 'cli-no-colour',
  ], 30_000)

  const detectEvidence = detectOut.stdout || detectOut.stderr || ''
  const isWordPress = /wordpress|wp-content|wp-includes/i.test(detectEvidence)

  if (!isWordPress) {
    onLog('info', 'wpscan: WordPress not detected, skipping full scan')
    return
  }

  onLog('info', 'wpscan: WordPress detected, running full vulnerability scan')
  const fullOut = await runCommand('wpscan', [
    '--url', targetUrl,
    '--no-banner',
    '--disable-tls-checks',
    '--enumerate', 'u,vp,vt,tt,cb,dbe',
    '--format', 'cli-no-colour',
  ], 180_000)

  const evidence = fullOut.stdout || fullOut.stderr || ''
  if (!evidence) return

  const cves = extractCVEs(evidence)

  // Parse critical findings
  const vulnBlocks = evidence.split(/\[!\]|\[+\]/).filter((b) => /vulnerability|vulnerabilit|CVE|outdated|insecure/i.test(b))

  for (const block of vulnBlocks.slice(0, 10)) {
    const blockCves = extractCVEs(block)
    const isHigh = /sql injection|rce|remote code|xss.*stored|authentication bypass/i.test(block)
    onFinding(makeFinding({
      title: `WPScan: WordPress vulnerability – ${block.trim().substring(0, 100)}`,
      severity: isHigh ? 'high' : 'medium',
      cvss: isHigh ? 7.5 : 5.3,
      cweId: 'CWE-1035',
      cveIds: blockCves,
      description: `WPScan identified a WordPress vulnerability: ${block.trim().substring(0, 500)}`,
      remediation: 'Update WordPress core, themes, and plugins to latest versions. Remove unused plugins/themes.',
      aiConfidence: 0.82,
      evidence: { type: 'raw', label: 'wpscan finding', data: block.trim().substring(0, 2000) },
    }, targetUrl))
  }

  // Check for user enumeration
  if (/Username:|user found/i.test(evidence)) {
    const userLines = evidence.split('\n').filter((l) => /Username:|Found: /i.test(l)).slice(0, 5)
    onFinding(makeFinding({
      title: 'WPScan: WordPress user enumeration possible',
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-200',
      description: `WPScan enumerated WordPress users: ${userLines.join(' | ')}. User enumeration facilitates brute-force attacks.`,
      remediation: 'Disable author archives. Use a security plugin to prevent user enumeration. Enforce strong passwords and 2FA.',
      aiConfidence: 0.87,
      evidence: { type: 'raw', label: 'wpscan user enumeration', data: userLines.join('\n') },
    }, targetUrl))
  }

  // General summary finding
  onFinding(makeFinding({
    title: 'WPScan: WordPress installation found and scanned',
    severity: cves.length > 0 ? 'high' : 'info',
    cvss: cves.length > 0 ? 7.0 : 0,
    cweId: 'CWE-1035',
    cveIds: cves.slice(0, 5),
    description: 'WordPress CMS detected. WPScan performed vulnerability assessment.',
    remediation: 'Keep WordPress, plugins, and themes updated. Disable XML-RPC if unused. Use security plugins like Wordfence.',
    aiConfidence: 0.9,
    evidence: { type: 'raw', label: 'wpscan full output', data: cap(evidence) },
  }, targetUrl))
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * scanExternal – runs a suite of Kali Linux tools against the target.
 * Enable via: EXTERNAL_SCANNER_ENABLED=true
 * Limit tools via: EXTERNAL_TOOL_LIST=nmap,nikto,...
 *
 * Enhanced tool list: nmap, nikto, whatweb, sqlmap, sslscan, gobuster,
 *                     wafw00f, wpscan
 */
export async function scanExternal(targetUrl, onFinding, onLog) {
  onLog?.('info', `External Tools (Kali) starting for ${targetUrl}`)

  if (String(process.env.EXTERNAL_SCANNER_ENABLED || 'false').toLowerCase() !== 'true') {
    onLog?.('warn', 'External scanner disabled. Set EXTERNAL_SCANNER_ENABLED=true to enable.')
    return { skipped: true, reason: 'disabled' }
  }

  let urlObj
  try {
    urlObj = new URL(targetUrl)
  } catch {
    onLog?.('error', `Invalid target URL: ${targetUrl}`)
    return { skipped: true, reason: 'invalid-url' }
  }

  const host = urlObj.hostname
  const port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80')

  const defaultTools = ['nmap', 'nikto', 'whatweb', 'sqlmap', 'sslscan', 'gobuster', 'wafw00f', 'wpscan']
  const envList = (process.env.EXTERNAL_TOOL_LIST || '').split(',').map((s) => s.trim()).filter(Boolean)
  const toolsToRun = envList.length > 0 ? envList : defaultTools

  const available = toolsToRun.filter(isToolAvailable)
  onLog?.('info', `Available tools: [${available.join(', ')}] (requested: [${toolsToRun.join(', ')}])`)

  if (available.length === 0) {
    onLog?.('warn', 'No external Kali tools found. Install them via: apt install nmap nikto whatweb sqlmap sslscan gobuster wafw00f wpscan')
    return { skipped: true, reason: 'no-tools-available' }
  }

  const findings = []
  const origOnFinding = onFinding

  const wrappedOnFinding = (f) => {
    findings.push(f)
    origOnFinding?.(f)
  }

  const toolHandlers = {
    nmap: () => runNmap(host, port, targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[nmap] ${msg}`)),
    nikto: () => runNikto(targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[nikto] ${msg}`)),
    whatweb: () => runWhatweb(targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[whatweb] ${msg}`)),
    sqlmap: () => runSqlmap(targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[sqlmap] ${msg}`)),
    sslscan: () => runSslscan(host, port, targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[sslscan] ${msg}`)),
    gobuster: () => runGobuster(host, targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[gobuster] ${msg}`)),
    wafw00f: () => runWafw00f(targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[wafw00f] ${msg}`)),
    wpscan: () => runWpscan(targetUrl, wrappedOnFinding, (lvl, msg) => onLog?.(lvl, `[wpscan] ${msg}`)),
  }

  for (const tool of available) {
    const handler = toolHandlers[tool]
    if (!handler) {
      onLog?.('info', `[external] Skipping unknown tool: ${tool}`)
      continue
    }
    try {
      onLog?.('info', `[external] Starting: ${tool}`)
      await handler()
      onLog?.('info', `[external] Finished: ${tool}`)
    } catch (err) {
      onLog?.('warn', `[external] ${tool} error: ${String(err.message || err)}`)
    }
  }

  onLog?.('info', `External Tools complete – ${findings.length} findings generated`)
  return findings
}
