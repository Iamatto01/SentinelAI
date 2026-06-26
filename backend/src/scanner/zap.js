/**
 * zap.js — OWASP ZAP Scanner Integration
 *
 * Runs OWASP ZAP baseline scan against a target URL.
 * Requires: zaproxy or zap-cli installed on the system.
 * Gracefully skips if unavailable.
 */

import { randomUUID } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'

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
    module: 'OWASP ZAP',
    aiConfidence: opts.aiConfidence ?? 0.75,
    aiReasoning: opts.aiReasoning || 'Derived from OWASP ZAP scan output',
    evidence: opts.evidence || {},
  }
}

function isToolAvailable(tool) {
  try {
    const r = spawnSync('which', [tool], { encoding: 'utf8' })
    return r.status === 0 && Boolean(r.stdout?.trim())
  } catch { return false }
}

function runCommand(cmd, args, timeoutMs = 300_000) {
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

function extractCVEs(text) {
  const m = text?.match(/CVE-\d{4}-\d{4,7}/gi) || []
  return [...new Set(m.map(c => c.toUpperCase()))]
}

/**
 * Parse ZAP text/JSON output into findings
 */
function parseZapOutput(output, targetUrl, onFinding) {
  // Try JSON format first
  try {
    const json = JSON.parse(output)
    const alerts = json.site?.[0]?.alerts || json.alerts || []
    for (const alert of alerts) {
      const riskMap = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' }
      const cvssMap = { '3': 7.5, '2': 5.3, '1': 3.7, '0': 0 }
      const severity = riskMap[String(alert.riskcode)] || 'info'
      const cvss = cvssMap[String(alert.riskcode)] || 0
      
      onFinding(makeFinding({
        title: `ZAP: ${alert.alert || alert.name || 'Finding'}`,
        severity,
        cvss,
        cweId: alert.cweid ? `CWE-${alert.cweid}` : 'CWE-200',
        cveIds: extractCVEs(alert.desc || ''),
        description: (alert.desc || '').replace(/<[^>]+>/g, '').substring(0, 500),
        remediation: (alert.solution || '').replace(/<[^>]+>/g, '').substring(0, 500),
        aiConfidence: 0.82,
        aiReasoning: `OWASP ZAP ${alert.confidence === '3' ? 'high' : alert.confidence === '2' ? 'medium' : 'low'} confidence finding`,
        evidence: {
          type: 'raw',
          label: 'ZAP alert',
          data: `URL: ${alert.url || ''}\nParameter: ${alert.param || ''}\nEvidence: ${alert.evidence || ''}`,
        },
      }, targetUrl))
    }
    return alerts.length
  } catch {
    // Fall back to text parsing
  }

  // Text output parsing (from baseline scan)
  const lines = output.split('\n')
  let count = 0
  for (const line of lines) {
    const alertMatch = line.match(/^(FAIL|WARN|INFO).*?:\s*(.+)/i)
    if (alertMatch) {
      const level = alertMatch[1].toUpperCase()
      const msg = alertMatch[2].trim()
      const severity = level === 'FAIL' ? 'high' : level === 'WARN' ? 'medium' : 'info'
      const cvss = level === 'FAIL' ? 7.5 : level === 'WARN' ? 5.3 : 0

      onFinding(makeFinding({
        title: `ZAP: ${msg.substring(0, 120)}`,
        severity,
        cvss,
        cweId: 'CWE-200',
        description: `OWASP ZAP baseline scan flagged: ${msg}`,
        remediation: 'Review ZAP recommendation. Apply security configuration and patch.',
        aiConfidence: 0.75,
        evidence: { type: 'raw', label: 'ZAP baseline', data: line },
      }, targetUrl))
      count++
    }
  }
  return count
}

export async function scanZap(targetUrl, onFinding, onLog) {
  onLog?.('info', `OWASP ZAP: starting scan for ${targetUrl}`)

  // Check for zap-baseline.py (Docker-based), zap-cli, or zaproxy
  const zapBin = isToolAvailable('zap-baseline.py') ? 'zap-baseline.py'
    : isToolAvailable('zap-cli') ? 'zap-cli'
    : isToolAvailable('zaproxy') ? 'zaproxy'
    : null

  if (!zapBin) {
    onLog?.('warn', 'OWASP ZAP: not found. Install zaproxy, zap-cli, or use ZAP Docker image.')
    return { skipped: true, reason: 'zap-not-installed' }
  }

  onLog?.('info', `OWASP ZAP: using ${zapBin}`)

  let out
  const timeoutMs = Math.max(60_000, Number(process.env.ZAP_TIMEOUT_MS || 300_000))

  if (zapBin === 'zap-baseline.py') {
    // Docker-based ZAP baseline scan
    out = await runCommand(zapBin, [
      '-t', targetUrl,
      '-J', '/tmp/zap_report.json',
      '-I', // don't fail on warnings
    ], timeoutMs)
  } else if (zapBin === 'zap-cli') {
    // zap-cli quick scan
    out = await runCommand('zap-cli', [
      'quick-scan', '--self-contained', '--start-options', '-config api.disablekey=true',
      targetUrl,
    ], timeoutMs)
  } else {
    // zaproxy command line
    out = await runCommand('zaproxy', [
      '-cmd', '-quickurl', targetUrl,
      '-quickout', '/tmp/zap_report.json',
      '-quickprogress',
    ], timeoutMs)
  }

  if (out.timedOut) {
    onLog?.('warn', `OWASP ZAP: scan timed out after ${Math.round(timeoutMs / 1000)}s`)
  }

  const evidence = out.stdout || out.stderr || ''
  if (!evidence.trim()) {
    // Try reading JSON report file
    try {
      const { readFileSync } = await import('node:fs')
      const jsonReport = readFileSync('/tmp/zap_report.json', 'utf8')
      const count = parseZapOutput(jsonReport, targetUrl, onFinding)
      onLog?.('info', `OWASP ZAP: ${count} findings from JSON report`)
      return
    } catch {
      onLog?.('info', 'OWASP ZAP: no output produced')
      return []
    }
  }

  const count = parseZapOutput(evidence, targetUrl, onFinding)
  onLog?.('info', `OWASP ZAP: scan completed with ${count} findings`)

  if (count === 0) {
    onFinding(makeFinding({
      title: 'OWASP ZAP: Baseline scan completed',
      severity: 'info',
      cvss: 0,
      cweId: 'CWE-16',
      description: 'OWASP ZAP baseline scan completed. No significant findings auto-parsed; review raw output.',
      remediation: 'Review full ZAP output for any flagged items.',
      aiConfidence: 0.65,
      evidence: { type: 'raw', label: 'ZAP output', data: cap(evidence) },
    }, targetUrl))
  }

  return []
}
