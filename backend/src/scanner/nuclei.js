/**
 * nuclei.js – ProjectDiscovery Nuclei template-based vulnerability scanner
 *
 * Nuclei runs thousands of community-maintained YAML templates covering:
 *  - CVEs (known vulnerabilities)
 *  - Exposed panels / admin interfaces
 *  - Default credentials
 *  - Misconfigurations
 *  - Exposed files / information disclosure
 *  - Technology-specific vulnerabilities
 *  - Subdomain takeover
 *  - SSRF / SSTI / IDOR / XSS / SQLi probes
 *
 * Requires: nuclei (install via: apt install nuclei  OR  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
 * Enable : EXTERNAL_SCANNER_ENABLED=true
 * Disable specific templates: set NUCLEI_EXCLUDE_TAGS=dos,fuzz  (CSV)
 * Restrict to templates:      set NUCLEI_TAGS=cve,exposure,misconfig  (CSV)
 * Custom templates dir:       set NUCLEI_TEMPLATES_DIR=/path/to/templates
 */

import { randomUUID } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { URL } from 'node:url'

// ---------------------------------------------------------------------------
// Severity / CVSS mappings
// ---------------------------------------------------------------------------
const NUCLEI_SEV_MAP = {
  critical: { severity: 'critical', cvss: 9.5 },
  high:     { severity: 'high',     cvss: 7.5 },
  medium:   { severity: 'medium',   cvss: 5.3 },
  low:      { severity: 'low',      cvss: 3.7 },
  info:     { severity: 'info',     cvss: 0   },
  unknown:  { severity: 'info',     cvss: 0   },
}

// CWE guessing from template tags / names
const TAG_CWE_MAP = {
  sqli:             'CWE-89',
  'sql-injection':  'CWE-89',
  xss:              'CWE-79',
  xxe:              'CWE-611',
  ssrf:             'CWE-918',
  ssti:             'CWE-94',
  rce:              'CWE-78',
  lfi:              'CWE-22',
  idor:             'CWE-284',
  redirect:         'CWE-601',
  cors:             'CWE-942',
  auth:             'CWE-287',
  'default-login':  'CWE-1392',
  'exposed-panel':  'CWE-538',
  exposure:         'CWE-200',
  misconfig:        'CWE-16',
  takeover:         'CWE-284',
  'cve':            'CWE-1035',
  ssl:              'CWE-326',
  tls:              'CWE-326',
  'info-disclosure':'CWE-200',
}

function guessCwe(tags = [], templateId = '') {
  for (const tag of tags) {
    const cwe = TAG_CWE_MAP[tag.toLowerCase()]
    if (cwe) return cwe
  }
  for (const [keyword, cwe] of Object.entries(TAG_CWE_MAP)) {
    if (templateId.toLowerCase().includes(keyword)) return cwe
  }
  return 'CWE-200'
}

function extractCVEs(text = '') {
  const m = text.match(/CVE-\d{4}-\d{4,7}/gi) || []
  return [...new Set(m.map((c) => c.toUpperCase()))]
}

function cap(str, bytes = 60_000) {
  if (!str) return ''
  return str.length > bytes ? str.substring(0, bytes) + '\n...[truncated]' : str
}

let templatesUpdatedForProcess = false

function isToolAvailable(tool) {
  try {
    const r = spawnSync('which', [tool], { encoding: 'utf8' })
    return r.status === 0 && r.stdout && r.stdout.trim().length > 0
  } catch {
    return false
  }
}

function runCommand(cmd, args, timeoutMs = 300_000) {
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
    module: 'Nuclei Template Scanning',
    aiConfidence: opts.aiConfidence ?? 0.87,
    aiReasoning: opts.aiReasoning || 'Nuclei template-matched finding with HTTP evidence.',
    evidence: opts.evidence || {},
  }
}

/**
 * Parse nuclei JSONL output (nuclei -j flag) into structured findings.
 * Each line is an independent JSON object.
 */
function parseNucleiJsonl(jsonlOutput, targetUrl, onFinding, onLog) {
  let count = 0
  const seenTemplates = new Set()

  const lines = jsonlOutput.split('\n').filter((l) => l.trim().startsWith('{'))
  for (const line of lines) {
    try {
      const entry = JSON.parse(line)
      const templateId   = entry['template-id'] || entry.templateID || 'unknown'
      const name         = entry.info?.name || entry.name || templateId
      const severity     = (entry.info?.severity || 'info').toLowerCase()
      const description  = entry.info?.description || entry.description || ''
      const remediation  = entry.info?.remediation || ''
      const tags         = entry.info?.tags ? (Array.isArray(entry.info.tags) ? entry.info.tags : String(entry.info.tags).split(',').map((t) => t.trim())) : []
      const matchedAt    = entry['matched-at'] || entry.host || targetUrl
      const reference    = Array.isArray(entry.info?.reference) ? entry.info.reference.join(', ') : (entry.info?.reference || '')
      const cves         = extractCVEs(`${name} ${description} ${reference} ${tags.join(' ')}`)
      const sevInfo      = NUCLEI_SEV_MAP[severity] || NUCLEI_SEV_MAP.info
      const cweId        = guessCwe(tags, templateId)

      // Deduplicate by template-id + host to avoid spam
      const dedupeKey = `${templateId}::${matchedAt}`
      if (seenTemplates.has(dedupeKey)) continue
      seenTemplates.add(dedupeKey)

      const extractedResults = entry['extracted-results'] || []
      const curl = entry['curl-command'] || ''
      const httpReq  = entry.request || ''
      const httpResp = entry.response || (entry.response ? cap(entry.response, 5000) : '')

      const evidenceData = [
        httpReq ? `--- REQUEST ---\n${httpReq}` : '',
        httpResp ? `--- RESPONSE (excerpt) ---\n${httpResp.substring(0, 3000)}` : '',
        extractedResults.length > 0 ? `--- EXTRACTED ---\n${extractedResults.join('\n')}` : '',
        curl ? `--- CURL ---\n${curl}` : '',
      ].filter(Boolean).join('\n\n')

      const remediationText = remediation || buildDefaultRemediation(templateId, tags, severity)

      const finding = makeFinding({
        title: `Nuclei: ${name}`,
        severity: sevInfo.severity,
        cvss: sevInfo.cvss,
        cweId,
        cveIds: cves,
        asset: matchedAt,
        description: [
          description,
          reference ? `References: ${reference.substring(0, 300)}` : '',
          `Template: ${templateId}`,
          tags.length > 0 ? `Tags: ${tags.join(', ')}` : '',
        ].filter(Boolean).join('\n\n'),
        remediation: remediationText,
        aiConfidence: confidence(sevInfo.severity),
        aiReasoning: `Nuclei template '${templateId}' matched at ${matchedAt}. Template severity: ${severity}.`,
        evidence: { type: 'http', label: `nuclei: ${templateId}`, data: evidenceData || line.substring(0, 5000) },
      }, targetUrl)

      onFinding(finding)
      count++
    } catch (_) {
      // malformed JSON line – skip
    }
  }
  return count
}

function confidence(severity) {
  const map = { critical: 0.95, high: 0.9, medium: 0.82, low: 0.75, info: 0.7 }
  return map[severity] ?? 0.72
}

function buildDefaultRemediation(templateId, tags, severity) {
  if (tags.includes('sqli') || templateId.includes('sqli') || templateId.includes('sql-injection')) {
    return 'Use parameterised queries/prepared statements. Implement input validation and a WAF.'
  }
  if (tags.includes('xss') || templateId.includes('xss')) {
    return 'Apply output encoding. Implement a strict Content-Security-Policy. Sanitise all user input.'
  }
  if (tags.includes('ssrf') || templateId.includes('ssrf')) {
    return 'Whitelist allowed outbound URLs. Block internal/cloud metadata IP ranges. Validate URL schemes.'
  }
  if (tags.includes('rce') || templateId.includes('rce') || templateId.includes('code-execution')) {
    return 'Patch the affected component immediately. Apply WAF rules. Restrict process execution permissions.'
  }
  if (tags.includes('lfi') || templateId.includes('lfi')) {
    return 'Validate and sanitise file path inputs. Use a whitelist of allowed files. Restrict directory traversal.'
  }
  if (tags.includes('default-login') || templateId.includes('default-login')) {
    return 'Change all default credentials immediately. Enforce strong password policies. Enable MFA.'
  }
  if (tags.includes('exposed-panel') || templateId.includes('exposed-panel')) {
    return 'Restrict admin panel access by IP. Place admin interfaces behind VPN. Implement strong authentication.'
  }
  if (tags.includes('takeover') || templateId.includes('takeover')) {
    return 'Remove or update orphaned DNS CNAME records pointing to unclaimed services.'
  }
  if (tags.includes('cve') || templateId.startsWith('CVE-')) {
    return 'Apply the vendor security patch for this CVE. Review your patch management process.'
  }
  if (severity === 'critical' || severity === 'high') {
    return 'Investigate immediately. Apply vendor patches or mitigating configuration changes.'
  }
  return 'Review the finding and apply appropriate security hardening measures.'
}

/**
 * Template categories to run (grouped for logical scan phases).
 * Can be overridden via NUCLEI_TAGS env var.
 */
const DEFAULT_TEMPLATE_TAGS = [
  'cve',
  'exposure',
  'misconfig',
  'default-login',
  'exposed-panel',
  'takeover',
  'token-spray',
  'xss',
  'sqli',
  'ssrf',
  'rce',
  'lfi',
]

export async function scanNuclei(targetUrl, onFinding, onLog) {
  onLog?.('info', `Nuclei scanner starting for ${targetUrl}`)

  if (String(process.env.EXTERNAL_SCANNER_ENABLED || 'false').toLowerCase() !== 'true') {
    onLog?.('warn', 'Nuclei scanner disabled. Set EXTERNAL_SCANNER_ENABLED=true to enable.')
    return { skipped: true, reason: 'disabled' }
  }

  if (!isToolAvailable('nuclei')) {
    onLog?.('warn', 'nuclei not found. Install: apt install nuclei  OR  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')
    return { skipped: true, reason: 'nuclei-not-installed' }
  }

  let urlObj
  try {
    urlObj = new URL(targetUrl)
  } catch {
    return { skipped: true, reason: 'invalid-url' }
  }

  const host = urlObj.hostname

  // Update templates before scan (silent)
  const skipTemplateUpdate = String(process.env.NUCLEI_SKIP_TEMPLATE_UPDATE || 'false').toLowerCase() === 'true'
  const updateTimeoutMs = Math.max(10_000, Number(process.env.NUCLEI_TEMPLATE_UPDATE_TIMEOUT_MS || 30_000))
  if (!skipTemplateUpdate && !templatesUpdatedForProcess) {
    onLog?.('info', `nuclei: updating templates (timeout ${Math.round(updateTimeoutMs / 1000)}s)...`)
    const updateOut = await runCommand('nuclei', ['-update-templates', '-silent'], updateTimeoutMs)
    if (updateOut.timedOut) {
      onLog?.('warn', 'nuclei: template update timed out, continuing with existing templates')
    } else if (updateOut.code === 0) {
      templatesUpdatedForProcess = true
      onLog?.('info', 'nuclei: templates updated')
    } else {
      onLog?.('warn', 'nuclei: template update failed, continuing with existing templates')
    }
  } else {
    onLog?.('info', 'nuclei: skipping template update for faster scan')
  }

  const envTags     = (process.env.NUCLEI_TAGS || '').split(',').map((t) => t.trim()).filter(Boolean)
  const excludeTags = (process.env.NUCLEI_EXCLUDE_TAGS || 'dos,fuzz,brute-force').split(',').map((t) => t.trim()).filter(Boolean)
  const templateDir = process.env.NUCLEI_TEMPLATES_DIR || ''

  const tags = envTags.length > 0 ? envTags : DEFAULT_TEMPLATE_TAGS
  onLog?.('info', `nuclei: running templates [${tags.join(', ')}] (excluding: [${excludeTags.join(', ')}])`)

  const args = [
    '-u', targetUrl,
    '-t', templateDir || 'http/',    // template directory
    '-tags', tags.join(','),
    '-exclude-tags', excludeTags.join(','),
    '-j',                            // JSONL output for machine parsing
    '-silent',
    '-no-color',
    '-timeout', String(Math.max(5, Number(process.env.NUCLEI_HTTP_TIMEOUT_SECONDS || 5))),
    '-retries', '1',
    '-rate-limit', String(Math.max(10, Number(process.env.NUCLEI_RATE_LIMIT || 20))),
    '-bulk-size', String(Math.max(5, Number(process.env.NUCLEI_BULK_SIZE || 10))),
    '-c', String(Math.max(1, Number(process.env.NUCLEI_CONCURRENCY || 5))),
  ]

  if (templateDir) {
    // replace default -t with custom dir
    args[args.indexOf('http/')] = templateDir
  }

  const findings = []
  const wrappedOnFinding = (f) => {
    findings.push(f)
    onFinding?.(f)
  }

  onLog?.('info', `nuclei: running (tags: ${tags.length} categories, target: ${host})`)
  const scanTimeoutMs = Math.max(30_000, Number(process.env.NUCLEI_SCAN_TIMEOUT_MS || 180_000))
  const out = await runCommand('nuclei', args, scanTimeoutMs)

  if (out.timedOut) {
    onLog?.('warn', 'nuclei: scan timed out – partial results may be available')
  }

  const jsonlOutput = out.stdout || ''
  if (jsonlOutput.trim()) {
    const count = parseNucleiJsonl(jsonlOutput, targetUrl, wrappedOnFinding, onLog)
    onLog?.('info', `nuclei: parsed ${count} findings from JSONL output`)
  } else {
    onLog?.('info', 'nuclei: no template matches found')
  }

  // Parse any stderr warnings
  if (out.stderr && /error|warn|fatal/i.test(out.stderr)) {
    onLog?.('warn', `nuclei stderr: ${out.stderr.substring(0, 500)}`)
  }

  // Summary finding
  if (findings.length > 0) {
    const sev = findings.some((f) => f.severity === 'critical') ? 'critical'
              : findings.some((f) => f.severity === 'high')     ? 'high'
              : findings.some((f) => f.severity === 'medium')   ? 'medium' : 'low'

    const bySev = findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1
      return acc
    }, {})

    onLog?.('info', `nuclei: summary – ${Object.entries(bySev).map(([s, n]) => `${n} ${s}`).join(', ')}`)
  }

  onLog?.('info', `Nuclei scan complete – ${findings.length} findings`)
  return findings
}
