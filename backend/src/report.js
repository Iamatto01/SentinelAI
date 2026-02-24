import PDFDocument from 'pdfkit'

// ── Constants ────────────────────────────────────────────────────────────────

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const MODULE_DESCRIPTIONS = {
  headers: {
    name: 'HTTP Headers Analysis',
    description:
      'Examines HTTP response headers for security misconfigurations including missing or misconfigured Content-Security-Policy (CSP), HTTP Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers. Additionally analyses cookie security attributes (Secure, HttpOnly, SameSite), Cross-Origin Resource Sharing (CORS) configurations, and information disclosure through Server and X-Powered-By headers.',
    standards: [
      'OWASP A05:2021 - Security Misconfiguration',
      'NIST SP 800-95 - Guide to Secure Web Services',
      'CWE-693: Protection Mechanism Failure',
    ],
  },
  ssl: {
    name: 'SSL/TLS Analysis',
    description:
      'Performs TLS handshake analysis to evaluate certificate validity, protocol versions, and cipher suite strength. Detects expired or soon-to-expire certificates, weak protocols (TLS 1.0/1.1), self-signed certificates, hostname mismatches, and weak cipher suites. Uses Node.js built-in TLS module for direct connection analysis.',
    standards: [
      'OWASP A02:2021 - Cryptographic Failures',
      'NIST SP 800-52 Rev 2 - Guidelines for TLS Implementations',
      'CWE-295: Improper Certificate Validation',
    ],
  },
  paths: {
    name: 'Exposed Paths Discovery',
    description:
      'Probes for commonly exposed sensitive files and directories that should not be publicly accessible. Checks for version control directories (.git), environment files (.env), backup archives, configuration files, admin panels, debug endpoints, and other paths that may leak credentials, source code, or internal system information.',
    standards: [
      'OWASP A01:2021 - Broken Access Control',
      'CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory',
      'CWE-548: Exposure of Information Through Directory Listing',
    ],
  },
  nmap: {
    name: 'Port Scanning (Nmap)',
    description:
      'Uses Nmap to perform TCP SYN port scanning and service/version detection across the target host. Identifies open ports, running services, and their versions. Helps detect unnecessary exposed services, outdated software, and potential attack vectors. Requires Nmap to be installed on the system; gracefully skips if unavailable.',
    standards: [
      'NIST SP 800-115 - Technical Guide to Information Security Testing',
      'OWASP Testing Guide v4.2 - Infrastructure Testing',
    ],
  },
  nuclei: {
    name: 'Vulnerability Scanning (Nuclei)',
    description:
      'Runs template-based vulnerability detection using ProjectDiscovery Nuclei. Checks for known CVEs, security misconfigurations, exposed administrative panels, default credentials, and technology-specific vulnerabilities using community-maintained detection templates. Requires Nuclei to be installed; gracefully skips if unavailable.',
    standards: [
      'OWASP A06:2021 - Vulnerable and Outdated Components',
      'CVE (Common Vulnerabilities and Exposures) Database',
      'NVD (National Vulnerability Database)',
    ],
  },
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function sevLabel(sev) {
  return (sev || 'info').charAt(0).toUpperCase() + (sev || 'info').slice(1)
}

function fmtDate(dt) {
  if (!dt) return 'N/A'
  try {
    return new Date(dt).toLocaleDateString('en-GB', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })
  } catch {
    return String(dt)
  }
}

function fmtDateTime(dt) {
  if (!dt) return 'N/A'
  try {
    return new Date(dt).toLocaleString('en-GB', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return String(dt)
  }
}

function riskRating(vulns) {
  const counts = {}
  for (const v of vulns) {
    const s = (v.severity || 'info').toLowerCase()
    counts[s] = (counts[s] || 0) + 1
  }
  if ((counts.critical || 0) > 0) return 'Critical'
  if ((counts.high || 0) >= 3) return 'High'
  if ((counts.high || 0) > 0 || (counts.medium || 0) >= 5) return 'Medium'
  if ((counts.medium || 0) > 0 || (counts.low || 0) > 0) return 'Low'
  return 'Informational'
}

function duration(start, end) {
  if (!start) return 'N/A'
  const s = new Date(start).getTime()
  const e = end ? new Date(end).getTime() : Date.now()
  const diff = e - s
  const h = Math.floor(diff / 3600000)
  const m = Math.floor((diff % 3600000) / 60000)
  const sec = Math.floor((diff % 60000) / 1000)
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
}

function usedModuleKeys(scans) {
  const keys = new Set()
  for (const s of scans) {
    for (const m of s.modules || []) {
      if ((m.status || '').toLowerCase() !== 'skipped') {
        keys.add((m.key || m.name || '').toLowerCase())
      }
    }
  }
  return keys
}

// ── Page-break guard ─────────────────────────────────────────────────────────

function ensureSpace(doc, needed) {
  if (doc.y + needed > doc.page.height - 80) {
    doc.addPage()
  }
}

// ── Section renderers ────────────────────────────────────────────────────────

function renderCoverPage(doc, { reportTitle, scans, project }) {
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right
  const cx = doc.page.margins.left + w / 2

  // Classification
  doc
    .fontSize(10)
    .font('Helvetica')
    .fillColor('#666666')
    .text('CONFIDENTIAL', doc.page.margins.left, 60, { width: w, align: 'center' })

  // Main title
  doc.moveDown(8)
  doc
    .fontSize(28)
    .font('Helvetica-Bold')
    .fillColor('#000000')
    .text(reportTitle, doc.page.margins.left, doc.y, { width: w, align: 'center' })

  // Horizontal rule
  doc.moveDown(1)
  const ruleY = doc.y
  doc
    .strokeColor('#000000')
    .lineWidth(2)
    .moveTo(cx - 100, ruleY)
    .lineTo(cx + 100, ruleY)
    .stroke()

  // Tool name
  doc.moveDown(2)
  doc
    .fontSize(14)
    .font('Helvetica')
    .fillColor('#333333')
    .text('SentinelAI - Automated Security Assessment Platform', doc.page.margins.left, doc.y, {
      width: w,
      align: 'center',
    })

  // Target / Project info
  doc.moveDown(3)
  doc.fontSize(11).font('Helvetica').fillColor('#444444')

  if (project) {
    doc.text(`Project: ${project.name}`, doc.page.margins.left, doc.y, { width: w, align: 'center' })
    doc.text(`Client: ${project.client || 'N/A'}`, doc.page.margins.left, doc.y, { width: w, align: 'center' })
  } else if (scans.length === 1) {
    doc.text(`Target: ${scans[0].target || 'N/A'}`, doc.page.margins.left, doc.y, { width: w, align: 'center' })
  } else if (scans.length > 1) {
    doc.text(`Targets: ${scans.length} scans`, doc.page.margins.left, doc.y, { width: w, align: 'center' })
  }

  doc.moveDown(4)
  doc
    .fontSize(11)
    .font('Helvetica')
    .fillColor('#555555')
    .text(`Date: ${fmtDate(new Date())}`, doc.page.margins.left, doc.y, { width: w, align: 'center' })
  doc.text('Prepared by: Security Analyst', doc.page.margins.left, doc.y, { width: w, align: 'center' })
  doc.text(`Scans Included: ${scans.length}`, doc.page.margins.left, doc.y, { width: w, align: 'center' })

  doc.addPage()
}

function renderTableOfContents(doc) {
  const x = doc.page.margins.left
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right

  doc.fontSize(20).font('Helvetica-Bold').fillColor('#000000').text('Table of Contents', x, doc.y)
  doc.moveDown(1.5)

  const sections = [
    '1.  Executive Summary',
    '2.  Methodology',
    '3.  Findings Summary',
    '4.  Detailed Findings',
    '5.  Appendix',
  ]

  for (const s of sections) {
    doc.fontSize(12).font('Helvetica').fillColor('#222222').text(s, x + 20, doc.y)
    doc.moveDown(0.6)
  }

  doc.addPage()
}

function renderExecutiveSummary(doc, { vulnerabilities, scans }) {
  const x = doc.page.margins.left
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right

  doc.fontSize(20).font('Helvetica-Bold').fillColor('#000000').text('1.  Executive Summary', x, doc.y)
  doc.moveDown(1)

  // Overview paragraph
  const targets = [...new Set(scans.map((s) => s.target).filter(Boolean))]
  doc.fontSize(11).font('Helvetica').fillColor('#222222')
  doc.text(
    `This report presents the results of an automated security assessment conducted using SentinelAI. ` +
      `A total of ${scans.length} scan${scans.length !== 1 ? 's' : ''} ${scans.length !== 1 ? 'were' : 'was'} performed against ${targets.length} unique target${targets.length !== 1 ? 's' : ''}, ` +
      `yielding ${vulnerabilities.length} finding${vulnerabilities.length !== 1 ? 's' : ''}. ` +
      `The overall risk rating for this assessment is: ${riskRating(vulnerabilities)}.`,
    x,
    doc.y,
    { width: w },
  )
  doc.moveDown(1.5)

  // Severity breakdown table
  doc.fontSize(13).font('Helvetica-Bold').text('Severity Breakdown', x, doc.y)
  doc.moveDown(0.7)

  const counts = {}
  for (const s of SEV_ORDER) counts[s] = 0
  for (const v of vulnerabilities) {
    const s = (v.severity || 'info').toLowerCase()
    if (counts[s] !== undefined) counts[s]++
  }

  // Table header
  const col1 = x
  const col2 = x + 200
  doc.fontSize(10).font('Helvetica-Bold').fillColor('#555555')
  doc.text('Severity', col1, doc.y)
  doc.text('Count', col2, doc.y - doc.currentLineHeight())
  doc.moveDown(0.3)

  // Divider
  doc.strokeColor('#cccccc').lineWidth(0.5).moveTo(col1, doc.y).lineTo(col2 + 60, doc.y).stroke()
  doc.moveDown(0.3)

  // Rows
  for (const s of SEV_ORDER) {
    doc.fontSize(10).font('Helvetica').fillColor('#222222')
    doc.text(sevLabel(s), col1, doc.y)
    doc.text(String(counts[s]), col2, doc.y - doc.currentLineHeight())
    doc.moveDown(0.2)
  }

  // Divider
  doc.moveDown(0.2)
  doc.strokeColor('#cccccc').lineWidth(0.5).moveTo(col1, doc.y).lineTo(col2 + 60, doc.y).stroke()
  doc.moveDown(0.1)
  doc.fontSize(10).font('Helvetica-Bold').fillColor('#222222')
  doc.text('Total', col1, doc.y)
  doc.text(String(vulnerabilities.length), col2, doc.y - doc.currentLineHeight())

  doc.moveDown(1.5)

  // Key statistics
  doc.fontSize(13).font('Helvetica-Bold').fillColor('#000000').text('Key Statistics', x, doc.y)
  doc.moveDown(0.7)

  const avgAi = vulnerabilities.length
    ? Math.round(
        (vulnerabilities.reduce((sum, v) => sum + (v.aiConfidence || 0), 0) / vulnerabilities.length) * 100,
      )
    : 0
  const uniqueAssets = new Set(vulnerabilities.map((v) => v.asset).filter(Boolean)).size
  const modules = usedModuleKeys(scans)

  const stats = [
    ['Unique Assets Scanned', String(uniqueAssets)],
    ['Modules Executed', String(modules.size)],
    ['Average AI Confidence', `${avgAi}%`],
    ['Overall Risk Rating', riskRating(vulnerabilities)],
  ]

  for (const [label, value] of stats) {
    doc.fontSize(10).font('Helvetica').fillColor('#222222')
    doc.text(`${label}: `, col1, doc.y, { continued: true })
    doc.font('Helvetica-Bold').text(value)
    doc.moveDown(0.15)
  }

  doc.addPage()
}

function renderMethodology(doc, { scans }) {
  const x = doc.page.margins.left
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right

  doc.fontSize(20).font('Helvetica-Bold').fillColor('#000000').text('2.  Methodology', x, doc.y)
  doc.moveDown(1)

  doc.fontSize(11).font('Helvetica').fillColor('#222222')
  doc.text(
    'The security assessment was performed using SentinelAI, an automated penetration testing orchestration platform. ' +
      'SentinelAI employs a modular architecture where each scanning module targets a specific security domain. ' +
      'The platform coordinates module execution, aggregates findings, and applies AI-assisted analysis to determine confidence levels and prioritise remediation efforts. ' +
      'The methodology follows industry-standard frameworks including the OWASP Testing Guide v4.2 and NIST SP 800-115.',
    x,
    doc.y,
    { width: w },
  )
  doc.moveDown(1.5)

  doc.fontSize(13).font('Helvetica-Bold').text('Scanning Modules', x, doc.y)
  doc.moveDown(0.7)

  const keys = usedModuleKeys(scans)

  for (const [key, info] of Object.entries(MODULE_DESCRIPTIONS)) {
    if (!keys.has(key)) continue
    ensureSpace(doc, 120)

    doc.fontSize(12).font('Helvetica-Bold').fillColor('#000000').text(`2.${Object.keys(MODULE_DESCRIPTIONS).indexOf(key) + 1}  ${info.name}`, x, doc.y)
    doc.moveDown(0.4)
    doc.fontSize(10).font('Helvetica').fillColor('#333333').text(info.description, x + 10, doc.y, { width: w - 10 })
    doc.moveDown(0.5)

    doc.fontSize(9).font('Helvetica-Bold').fillColor('#555555').text('Referenced Standards:', x + 10, doc.y)
    doc.moveDown(0.2)
    for (const std of info.standards) {
      doc.fontSize(9).font('Helvetica').fillColor('#555555').text(`  -  ${std}`, x + 15, doc.y, { width: w - 15 })
      doc.moveDown(0.15)
    }
    doc.moveDown(0.8)
  }

  // If no modules ran
  if (keys.size === 0) {
    doc.fontSize(10).font('Helvetica').fillColor('#666666').text('No scanning modules were executed.', x, doc.y)
  }

  doc.moveDown(1)
  doc.fontSize(13).font('Helvetica-Bold').fillColor('#000000').text('References', x, doc.y)
  doc.moveDown(0.5)

  const refs = [
    'OWASP Top 10 (2021) - https://owasp.org/Top10/',
    'OWASP Testing Guide v4.2 - https://owasp.org/www-project-web-security-testing-guide/',
    'NIST SP 800-115 - Technical Guide to Information Security Testing and Assessment',
    'NIST SP 800-52 Rev 2 - Guidelines for the Selection, Configuration, and Use of TLS Implementations',
    'CVE - Common Vulnerabilities and Exposures - https://cve.mitre.org',
    'CWE - Common Weakness Enumeration - https://cwe.mitre.org',
  ]

  for (const ref of refs) {
    doc.fontSize(9).font('Helvetica').fillColor('#444444').text(`  -  ${ref}`, x + 10, doc.y, { width: w - 10 })
    doc.moveDown(0.15)
  }

  doc.addPage()
}

function renderFindingsSummary(doc, { vulnerabilities }) {
  const x = doc.page.margins.left
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right

  doc.fontSize(20).font('Helvetica-Bold').fillColor('#000000').text('3.  Findings Summary', x, doc.y)
  doc.moveDown(1)

  if (vulnerabilities.length === 0) {
    doc.fontSize(11).font('Helvetica').fillColor('#666666').text('No vulnerabilities were discovered during this assessment.', x, doc.y, { width: w })
    doc.addPage()
    return
  }

  // Severity distribution
  doc.fontSize(13).font('Helvetica-Bold').text('Severity Distribution', x, doc.y)
  doc.moveDown(0.7)

  const sevCounts = {}
  for (const s of SEV_ORDER) sevCounts[s] = 0
  for (const v of vulnerabilities) {
    const s = (v.severity || 'info').toLowerCase()
    if (sevCounts[s] !== undefined) sevCounts[s]++
  }

  // Draw simple bar chart using rectangles
  const barX = x + 80
  const barMaxW = w - 120
  const maxCount = Math.max(1, ...Object.values(sevCounts))

  for (const s of SEV_ORDER) {
    const barW = Math.max(1, (sevCounts[s] / maxCount) * barMaxW)
    const barY = doc.y

    doc.fontSize(10).font('Helvetica').fillColor('#222222').text(sevLabel(s), x, barY)

    // Bar
    const fill = s === 'critical' ? '#000000' : s === 'high' ? '#333333' : s === 'medium' ? '#666666' : s === 'low' ? '#999999' : '#cccccc'
    doc.rect(barX, barY, barW, 12).fill(fill)

    // Count label
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#222222').text(` ${sevCounts[s]}`, barX + barW + 5, barY + 1)
    doc.moveDown(0.6)
  }

  doc.moveDown(1)

  // Findings by asset
  const assetCounts = {}
  for (const v of vulnerabilities) {
    const a = v.asset || 'Unknown'
    assetCounts[a] = (assetCounts[a] || 0) + 1
  }

  doc.fontSize(13).font('Helvetica-Bold').fillColor('#000000').text('Findings by Asset', x, doc.y)
  doc.moveDown(0.5)

  const colA1 = x
  const colA2 = x + 300
  doc.fontSize(10).font('Helvetica-Bold').fillColor('#555555')
  doc.text('Asset', colA1, doc.y)
  doc.text('Count', colA2, doc.y - doc.currentLineHeight())
  doc.moveDown(0.2)
  doc.strokeColor('#cccccc').lineWidth(0.5).moveTo(colA1, doc.y).lineTo(colA2 + 60, doc.y).stroke()
  doc.moveDown(0.3)

  for (const [asset, count] of Object.entries(assetCounts).sort((a, b) => b[1] - a[1])) {
    ensureSpace(doc, 20)
    doc.fontSize(9).font('Courier').fillColor('#333333')
    const displayAsset = asset.length > 60 ? asset.slice(0, 57) + '...' : asset
    doc.text(displayAsset, colA1, doc.y)
    doc.text(String(count), colA2, doc.y - doc.currentLineHeight())
    doc.moveDown(0.2)
  }

  doc.moveDown(1)
  ensureSpace(doc, 80)

  // Findings by module
  const moduleCounts = {}
  for (const v of vulnerabilities) {
    const m = v.module || 'Unknown'
    moduleCounts[m] = (moduleCounts[m] || 0) + 1
  }

  doc.fontSize(13).font('Helvetica-Bold').fillColor('#000000').text('Findings by Module', x, doc.y)
  doc.moveDown(0.5)

  doc.fontSize(10).font('Helvetica-Bold').fillColor('#555555')
  doc.text('Module', colA1, doc.y)
  doc.text('Count', colA2, doc.y - doc.currentLineHeight())
  doc.moveDown(0.2)
  doc.strokeColor('#cccccc').lineWidth(0.5).moveTo(colA1, doc.y).lineTo(colA2 + 60, doc.y).stroke()
  doc.moveDown(0.3)

  for (const [mod, count] of Object.entries(moduleCounts).sort((a, b) => b[1] - a[1])) {
    ensureSpace(doc, 20)
    doc.fontSize(9).font('Helvetica').fillColor('#333333').text(mod, colA1, doc.y)
    doc.text(String(count), colA2, doc.y - doc.currentLineHeight())
    doc.moveDown(0.2)
  }

  doc.moveDown(1)
  ensureSpace(doc, 60)

  // Status breakdown
  const statusCounts = { open: 0, 'in-progress': 0, closed: 0 }
  for (const v of vulnerabilities) {
    const st = (v.status || 'open').toLowerCase().replace(/ /g, '-')
    if (statusCounts[st] !== undefined) statusCounts[st]++
  }

  doc.fontSize(13).font('Helvetica-Bold').fillColor('#000000').text('Status Breakdown', x, doc.y)
  doc.moveDown(0.5)

  for (const [status, count] of Object.entries(statusCounts)) {
    doc.fontSize(10).font('Helvetica').fillColor('#222222')
    doc.text(`${status.charAt(0).toUpperCase() + status.slice(1)}: `, x, doc.y, { continued: true })
    doc.font('Helvetica-Bold').text(String(count))
    doc.moveDown(0.15)
  }

  doc.addPage()
}

function renderDetailedFindings(doc, { vulnerabilities }) {
  const x = doc.page.margins.left
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right

  doc.fontSize(20).font('Helvetica-Bold').fillColor('#000000').text('4.  Detailed Findings', x, doc.y)
  doc.moveDown(1)

  if (vulnerabilities.length === 0) {
    doc.fontSize(11).font('Helvetica').fillColor('#666666').text('No vulnerabilities to report.', x, doc.y, { width: w })
    doc.addPage()
    return
  }

  // Sort by severity
  const sorted = [...vulnerabilities].sort((a, b) => {
    const ai = SEV_ORDER.indexOf((a.severity || 'info').toLowerCase())
    const bi = SEV_ORDER.indexOf((b.severity || 'info').toLowerCase())
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
  })

  for (let i = 0; i < sorted.length; i++) {
    const v = sorted[i]
    const sev = (v.severity || 'info').toLowerCase()
    const num = `4.${i + 1}`

    // Estimate space needed for this finding
    ensureSpace(doc, 200)

    const boxTop = doc.y

    // Title line
    doc.fontSize(13).font('Helvetica-Bold').fillColor('#000000')
    doc.text(`${num}  ${v.title || 'Untitled Finding'}`, x + 5, doc.y, { width: w - 10 })
    doc.moveDown(0.5)

    // Meta fields
    const metaY = doc.y
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#555555')
    doc.text('Severity: ', x + 10, doc.y, { continued: true })
    doc.font('Helvetica').text(sevLabel(sev))

    doc.fontSize(9).font('Helvetica-Bold').text('CVSS: ', x + 10, doc.y, { continued: true })
    doc.font('Helvetica').text(v.cvss != null ? String(v.cvss) : 'N/A')

    doc.fontSize(9).font('Helvetica-Bold').text('Asset: ', x + 10, doc.y, { continued: true })
    doc.font('Courier').text(v.asset || 'N/A')

    doc.fontSize(9).font('Helvetica-Bold').fillColor('#555555').text('Module: ', x + 10, doc.y, { continued: true })
    doc.font('Helvetica').text(v.module || 'N/A')

    if (v.cweId) {
      doc.fontSize(9).font('Helvetica-Bold').text('CWE: ', x + 10, doc.y, { continued: true })
      doc.font('Courier').text(v.cweId)
    }

    if (v.cveIds && v.cveIds.length > 0) {
      doc.fontSize(9).font('Helvetica-Bold').text('CVE: ', x + 10, doc.y, { continued: true })
      doc.font('Courier').text(v.cveIds.join(', '))
    }

    doc.moveDown(0.5)

    // Separator
    doc.strokeColor('#dddddd').lineWidth(0.5).moveTo(x + 5, doc.y).lineTo(x + w - 5, doc.y).stroke()
    doc.moveDown(0.4)

    // Description
    if (v.description) {
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#333333').text('Description:', x + 10, doc.y)
      doc.moveDown(0.2)
      doc.fontSize(9).font('Helvetica').fillColor('#444444').text(v.description, x + 15, doc.y, { width: w - 30 })
      doc.moveDown(0.5)
    }

    // AI Analysis
    if (v.aiReasoning) {
      ensureSpace(doc, 60)
      const pct = Math.round((v.aiConfidence || 0) * 100)
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#333333').text(`AI Analysis (${pct}% confidence):`, x + 10, doc.y)
      doc.moveDown(0.2)
      doc.fontSize(9).font('Helvetica').fillColor('#444444').text(v.aiReasoning, x + 15, doc.y, { width: w - 30 })
      doc.moveDown(0.5)
    }

    // Remediation
    if (v.remediation) {
      ensureSpace(doc, 60)
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#333333').text('Remediation:', x + 10, doc.y)
      doc.moveDown(0.2)
      doc.fontSize(9).font('Helvetica').fillColor('#444444').text(v.remediation, x + 15, doc.y, { width: w - 30 })
      doc.moveDown(0.5)
    }

    // Draw border around the finding
    const boxBottom = doc.y + 5
    doc
      .strokeColor('#999999')
      .lineWidth(0.8)
      .rect(x, boxTop - 5, w, boxBottom - boxTop + 10)
      .stroke()

    doc.y = boxBottom + 15
  }

  doc.addPage()
}

function renderAppendix(doc, { scans, project }) {
  const x = doc.page.margins.left
  const w = doc.page.width - doc.page.margins.left - doc.page.margins.right

  doc.fontSize(20).font('Helvetica-Bold').fillColor('#000000').text('5.  Appendix', x, doc.y)
  doc.moveDown(1)

  // A. Scan Details
  doc.fontSize(14).font('Helvetica-Bold').text('A.  Scan Details', x, doc.y)
  doc.moveDown(0.7)

  if (scans.length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor('#666666').text('No scans were performed.', x, doc.y)
    doc.moveDown(1)
  }

  for (const s of scans) {
    ensureSpace(doc, 100)

    doc.fontSize(11).font('Helvetica-Bold').fillColor('#222222').text(`Scan: ${s.target || 'Unknown'}`, x + 10, doc.y)
    doc.moveDown(0.3)

    const details = [
      ['Scan ID', s.id || 'N/A'],
      ['Template', (s.template || 'N/A').charAt(0).toUpperCase() + (s.template || '').slice(1)],
      ['Status', (s.status || 'N/A').charAt(0).toUpperCase() + (s.status || '').slice(1)],
      ['Start Time', fmtDateTime(s.startTime)],
      ['End Time', fmtDateTime(s.endTime)],
      ['Duration', duration(s.startTime, s.endTime)],
      ['Findings', String(s.vulnerabilitiesFound ?? 0)],
    ]

    for (const [label, value] of details) {
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#555555').text(`${label}: `, x + 20, doc.y, { continued: true })
      doc.font('Helvetica').fillColor('#333333').text(value)
      doc.moveDown(0.1)
    }

    // Module results
    if (s.modules && s.modules.length > 0) {
      doc.moveDown(0.3)
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#555555').text('Modules:', x + 20, doc.y)
      doc.moveDown(0.2)
      for (const m of s.modules) {
        const st = (m.status || 'queued').toLowerCase()
        const label = st === 'completed' ? 'Completed' : st === 'skipped' ? 'Skipped' : st === 'failed' ? 'Failed' : st
        doc.fontSize(9).font('Helvetica').fillColor('#444444').text(`  -  ${m.name || m.key}: ${label}`, x + 25, doc.y)
        doc.moveDown(0.1)
      }
    }

    doc.moveDown(0.8)
  }

  // B. Tool Information
  ensureSpace(doc, 80)
  doc.moveDown(0.5)
  doc.fontSize(14).font('Helvetica-Bold').fillColor('#000000').text('B.  Tool Information', x, doc.y)
  doc.moveDown(0.5)

  const tools = [
    ['Platform', 'SentinelAI - Automated Security Assessment Platform v0.1.0'],
    ['PDF Engine', 'pdfkit for Node.js'],
    ['Runtime', `Node.js ${process.version}`],
    ['Report Generated', fmtDateTime(new Date())],
  ]

  for (const [label, value] of tools) {
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#555555').text(`${label}: `, x + 10, doc.y, { continued: true })
    doc.font('Helvetica').fillColor('#333333').text(value)
    doc.moveDown(0.15)
  }

  // C. Disclaimer
  ensureSpace(doc, 100)
  doc.moveDown(1)
  doc.fontSize(14).font('Helvetica-Bold').fillColor('#000000').text('C.  Disclaimer', x, doc.y)
  doc.moveDown(0.5)

  doc.fontSize(9).font('Helvetica').fillColor('#555555')
  doc.text(
    'This report reflects the security posture of the assessed target(s) at the time of testing. ' +
      'Security vulnerabilities may exist that were not identified during this assessment due to scope limitations, ' +
      'network conditions, or other factors. This report is intended for the authorised recipient only and should be ' +
      'treated as confidential. The findings and recommendations provided are based on automated analysis and should ' +
      'be validated by qualified security professionals before implementation. Neither the tool authors nor the ' +
      'assessor assume liability for actions taken based on this report.',
    x + 10,
    doc.y,
    { width: w - 20 },
  )
}

// ── Main export ──────────────────────────────────────────────────────────────

export async function generateReport(type, id, db) {
  // Gather data
  let vulnerabilities = []
  let scans = []
  let project = null
  let reportTitle = ''

  if (type === 'scan') {
    const scan = db.scans.find((s) => s.id === id)
    if (!scan) throw new Error('Scan not found')
    scans = [scan]
    vulnerabilities = db.vulnerabilitiesByScanId.get(id) || []
    reportTitle = `Scan Report: ${scan.target || 'Unknown Target'}`
  } else if (type === 'project') {
    project = db.projects.find((p) => p.id === id)
    if (!project) throw new Error('Project not found')
    scans = db.scans.filter((s) => s.projectId === id)
    for (const scan of scans) {
      const vulns = db.vulnerabilitiesByScanId.get(scan.id) || []
      vulnerabilities.push(...vulns.map((v) => ({ ...v, scanId: scan.id, scanTarget: scan.target })))
    }
    reportTitle = `Project Report: ${project.name}`
  } else {
    // full
    scans = [...db.scans]
    for (const [scanId, vulns] of db.vulnerabilitiesByScanId) {
      const scan = db.scans.find((s) => s.id === scanId)
      vulnerabilities.push(...vulns.map((v) => ({ ...v, scanId, scanTarget: scan?.target })))
    }
    reportTitle = 'Full System Security Assessment Report'
  }

  // Create PDF
  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: 60, bottom: 60, left: 50, right: 50 },
    info: {
      Title: reportTitle,
      Author: 'SentinelAI Security Platform',
      Subject: 'Security Assessment Report',
      Creator: 'SentinelAI v0.1.0',
    },
    bufferPages: true,
  })

  // Render sections
  renderCoverPage(doc, { reportTitle, scans, project })
  renderTableOfContents(doc)
  renderExecutiveSummary(doc, { vulnerabilities, scans })
  renderMethodology(doc, { scans })
  renderFindingsSummary(doc, { vulnerabilities })
  renderDetailedFindings(doc, { vulnerabilities })
  renderAppendix(doc, { scans, project })

  // Add page footers
  const range = doc.bufferedPageRange()
  const totalPages = range.count
  for (let i = range.start; i < range.start + totalPages; i++) {
    doc.switchToPage(i)
    // Save state to avoid affecting other content
    doc.save()
    doc
      .fontSize(8)
      .font('Helvetica')
      .fillColor('#999999')
      .text('SentinelAI - Confidential', 50, doc.page.height - 40, {
        lineBreak: false,
      })
    doc
      .fontSize(8)
      .font('Helvetica')
      .fillColor('#999999')
      .text(`Page ${i - range.start + 1} of ${totalPages}`, 0, doc.page.height - 40, {
        align: 'right',
        width: doc.page.width - 50,
        lineBreak: false,
      })
    doc.restore()
  }

  return doc
}
