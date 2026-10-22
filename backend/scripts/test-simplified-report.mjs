import fs from 'node:fs'
import path from 'node:path'
import PDFDocument from 'pdfkit'

function sanitizePdfText(str) {
  if (!str) return ''
  return String(str)
    .normalize('NFKD')
    .replace(/\r/g, '')
    .replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
    .replace(/[\u2013\u2014\u2015]/g, ' - ')
    .replace(/\u2026/g, '...')
    .replace(/[\u2022\u2023\u25E6\u2043\u2219]/g, '* ')
    .replace(/[\u2192\u21D2\u279C\u2794]/g, ' -> ')
    .replace(/[\u2713\u2714\u2611]/g, '[OK] ')
    .replace(/[\u2717\u2718\u2612]/g, '[X] ')
    .replace(/[\u26A0\u26A1]/g, '[!] ')
    .replace(/[\u2B50\u2605]/g, '* ')
    .replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, '')
    .replace(/[\u{10000}-\u{10FFFF}]/gu, '')
    .replace(/[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}]/gu, '')
    .replace(/[^\x20-\x7E\t\n]/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim()
}

const BRAND = {
  primary: '#0F172A',
  accent: '#0EA5E9',
  cardBg: '#F8FAFC',
  cardBorder: '#CBD5E1',
  textDark: '#0F172A',
  textMuted: '#64748B',
  borderLight: '#E2E8F0',
}

const SEV_COLORS = {
  critical: { bg: '#DC2626', text: '#FFFFFF', border: '#B91C1C', light: '#FEF2F2' },
  high:     { bg: '#EA580C', text: '#FFFFFF', border: '#C2410C', light: '#FFF7ED' },
  medium:   { bg: '#2563EB', text: '#FFFFFF', border: '#1D4ED8', light: '#EFF6FF' },
  low:      { bg: '#0D9488', text: '#FFFFFF', border: '#0F766E', light: '#F0FDFA' },
  info:     { bg: '#64748B', text: '#FFFFFF', border: '#475569', light: '#F8FAFC' },
  success:  { bg: '#16A34A', text: '#FFFFFF', border: '#15803D', light: '#F0FDF4' },
}

function drawRoundedBadge(doc, text, x, y, bgColor, textColor = '#FFFFFF', borderColor = null, radius = 3) {
  const fontSz = 7.5
  const paddingH = 6
  const h = 14
  const clean = sanitizePdfText(text)
  const w = Math.round(doc.fontSize(fontSz).font('Helvetica-Bold').widthOfString(clean) + paddingH * 2)
  if (borderColor) {
    doc.roundedRect(x, y, w, h, radius).fillAndStroke(bgColor, borderColor)
  } else {
    doc.roundedRect(x, y, w, h, radius).fill(bgColor)
  }
  doc.fontSize(fontSz).font('Helvetica-Bold').fillColor(textColor).text(clean, x, y + 3, { width: w, align: 'center' })
  return w
}

function drawSectionTitle(doc, titleText, subtitle = null) {
  const x = doc.page.margins.left
  const y = doc.y
  doc.rect(x, y, 4, 18).fill(BRAND.accent)
  doc.fontSize(16).font('Helvetica-Bold').fillColor(BRAND.primary).text(sanitizePdfText(titleText), x + 12, y + 1)
  if (subtitle) {
    doc.fontSize(9).font('Helvetica').fillColor(BRAND.textMuted).text(sanitizePdfText(subtitle), x + 12, y + 19)
    doc.y = y + 36
  } else {
    doc.y = y + 26
  }
}

function buildSimplifiedActionItem(v, index, detectedTech = []) {
  const title = sanitizePdfText(v.title || 'Security Finding')
  const sev = (v.severity || 'medium').toLowerCase()
  const lowerTitle = title.toLowerCase()

  let urgency = sev === 'critical' ? 'fix-today' : sev === 'high' ? 'this-week' : 'optional'
  let difficulty = 'medium'
  let estimatedMinutes = 30
  let symptom = sanitizePdfText(v.description || '')
  let risk = 'Presents security risk to web assets if left unmitigated.'
  let prescription = sanitizePdfText(v.remediation || '')
  let verification = 'Re-scan with SentinelAI after applying the remediation.'

  // Context-aware enrichment for common web and configuration findings
  if (lowerTitle.includes('content-security-policy') || lowerTitle.includes('csp')) {
    difficulty = 'medium'
    estimatedMinutes = 25
    symptom = 'The web application does not send a Content-Security-Policy (CSP) HTTP response header.'
    risk = 'Without CSP, malicious injected scripts can execute in visitors\' browsers, increasing XSS and data-theft risks.'
    prescription = "Configure your web server (Nginx/Apache/Cloudflare) to send: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
    verification = 'Run `curl -I https://<target>` and check that the Content-Security-Policy header is present in the response.'
  } else if (lowerTitle.includes('x-frame-options') || lowerTitle.includes('clickjacking')) {
    difficulty = 'easy'
    estimatedMinutes = 15
    symptom = 'The web server does not set an X-Frame-Options or frame-ancestors directive.'
    risk = 'Attackers can render this site inside an invisible iframe on a malicious website to deceive users into unintended clicks (Clickjacking).'
    prescription = 'Add the HTTP header: `X-Frame-Options: SAMEORIGIN` in your reverse proxy, Nginx configuration, or Cloudflare Transform Rules.'
    verification = 'Inspect HTTP response headers via `curl -I https://<target>` and verify `X-Frame-Options: SAMEORIGIN` is returned.'
  } else if (lowerTitle.includes('strict-transport-security') || lowerTitle.includes('hsts')) {
    difficulty = 'easy'
    estimatedMinutes = 15
    symptom = 'HTTP Strict Transport Security (HSTS) header is missing from HTTPS responses.'
    risk = 'Visitors may inadvertently establish unencrypted HTTP connections that attackers can intercept on untrusted networks.'
    prescription = 'Add HTTP header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses.'
    verification = 'Test HTTPS responses via `curl -sI https://<target> | grep -i strict-transport-security`.'
  } else if (lowerTitle.includes('x-content-type-options')) {
    difficulty = 'easy'
    estimatedMinutes = 10
    symptom = 'The X-Content-Type-Options: nosniff header is missing.'
    risk = 'Older browsers may MIME-sniff response content, potentially executing user-uploaded files as scripts.'
    prescription = 'Add HTTP header: `X-Content-Type-Options: nosniff` in web server configuration.'
    verification = 'Verify header presence using curl or browser Developer Tools Network tab.'
  } else if (lowerTitle.includes('server header') || lowerTitle.includes('banner') || lowerTitle.includes('disclosure')) {
    difficulty = 'easy'
    estimatedMinutes = 15
    symptom = 'The web server reveals its exact software version or underlying operating system in response headers.'
    risk = 'Attackers can use version information to pinpoint targeted CVE exploits without active brute-forcing.'
    prescription = 'Disable server signature tokens (e.g. Nginx: `server_tokens off;`, Apache: `ServerSignature Off` and `ServerTokens Prod`).'
    verification = 'Send a test HTTP request and confirm the Server header omits detailed version numbers.'
  } else if (lowerTitle.includes('sql') || lowerTitle.includes('injection')) {
    difficulty = 'hard'
    estimatedMinutes = 60
    urgency = sev === 'critical' ? 'fix-today' : 'this-week'
    symptom = 'User-supplied parameters are concatenated directly into database queries.'
    risk = 'Attackers can bypass authentication controls, extract confidential data, or alter database contents.'
    prescription = 'Rewrite dynamic queries using parameterized prepared statements or an established ORM. Never concatenate raw user input.'
    verification = 'Re-run SentinelAI targeted SQL injection probe to confirm parameterized query safety.'
  } else if (lowerTitle.includes('cross-site scripting') || lowerTitle.includes('xss')) {
    difficulty = 'medium'
    estimatedMinutes = 45
    urgency = sev === 'critical' ? 'fix-today' : 'this-week'
    symptom = 'Unsanitized user input is reflected or stored and rendered in HTML output.'
    risk = 'Enables session hijacking, keystroke logging, and unauthorized actions performed on behalf of authenticated users.'
    prescription = 'Apply contextual output encoding (HTML, JavaScript, URL encoding) before rendering data and enforce a strong CSP.'
    verification = 'Submit special character test strings (`<script>`, `"><img`) and ensure they are properly escaped.'
  } else if (lowerTitle.includes('open port') || lowerTitle.includes('service')) {
    difficulty = 'medium'
    estimatedMinutes = 20
    symptom = 'A network port is open and publicly accessible from the Internet.'
    risk = 'Exposes administrative services or internal daemons to external scanning and unauthorized brute-force attacks.'
    prescription = 'Apply firewall rules (UFW, iptables, AWS Security Groups) to restrict access to trusted IP ranges or VPN only.'
    verification = 'Run nmap or nc against the port from an external IP to confirm it is closed or filtered.'
  } else if (!prescription) {
    prescription = 'Review application configuration and apply the recommended vendor security patch or hardening directives.'
  }

  return {
    title,
    severity: sev,
    symptom: sanitizePdfText(symptom),
    risk: sanitizePdfText(risk),
    prescription: sanitizePdfText(prescription),
    urgency,
    difficulty,
    estimatedMinutes,
    verification: sanitizePdfText(verification),
  }
}

async function renderSimplifiedPdf({ file, reportTitle, scans = [], project = null, vulnerabilities = [], isWhitebox = false, aiNarrative = null, simplifiedGuide = null, custom = {}, detectedTech = [] }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 45, bottom: 45, left: 40, right: 40 },
      info: {
        Title: sanitizePdfText(reportTitle),
        Author: 'SentinelAI Autonomous Pentest Platform',
        Subject: 'Simplified IT Action Guide',
        Creator: 'SentinelAI v2.0',
      },
      bufferPages: true,
    })

    const stream = fs.createWriteStream(file)
    doc.pipe(stream)

    const w = doc.page.width - doc.page.margins.left - doc.page.margins.right
    const leftX = doc.page.margins.left
    const rightX = doc.page.width - doc.page.margins.right

    // Triage counts
    const criticalFindings = vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'critical')
    const highFindings = vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'high')
    const mediumFindings = vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'medium')
    const lowFindings = vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'low')
    const infoFindings = vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'info')

    const todayCount = simplifiedGuide?.taskCountToday !== undefined 
      ? Number(simplifiedGuide.taskCountToday) 
      : criticalFindings.length
    const weekCount = highFindings.length
    const laterCount = mediumFindings.length
    const actionableTotal = todayCount + weekCount + laterCount

    // Items list (from AI guide or enriched findings)
    let items = []
    if (simplifiedGuide?.actionItems && Array.isArray(simplifiedGuide.actionItems) && simplifiedGuide.actionItems.length > 0) {
      items = simplifiedGuide.actionItems.map((item, idx) => ({
        title: sanitizePdfText(item.title || `Action Item #${idx + 1}`),
        severity: (item.severity || 'medium').toLowerCase(),
        symptom: sanitizePdfText(item.symptom || 'Anomalous configuration identified on target system.'),
        risk: sanitizePdfText(item.risk || 'Presents security risks if left unaddressed.'),
        prescription: sanitizePdfText(item.prescription || 'Apply recommended vendor configuration hardening.'),
        urgency: item.urgency === 'fix-today' ? 'fix-today' : item.urgency === 'this-week' ? 'this-week' : 'optional',
        difficulty: item.difficulty === 'easy' ? 'easy' : item.difficulty === 'hard' ? 'hard' : 'medium',
        estimatedMinutes: parseInt(item.estimatedMinutes, 10) || 25,
        verification: sanitizePdfText(item.verification || 'Re-scan with SentinelAI after applying changes.'),
      }))
    } else {
      // Intelligently select actionable findings, or fall back to low/info hardening items if 0 critical/high/medium
      const sourceFindings = (actionableTotal > 0)
        ? [...criticalFindings, ...highFindings, ...mediumFindings]
        : [...lowFindings, ...infoFindings]

      items = sourceFindings.slice(0, 15).map((v, idx) => buildSimplifiedActionItem(v, idx, detectedTech))
    }

    // Determine target name
    const primaryScan = scans[0] || {}
    const targetName = sanitizePdfText(primaryScan.target || 'Target System')
    const projectName = sanitizePdfText(project?.name || 'Default Assessment')
    const reportDateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

    // =========================================================================
    // PAGE 1: EXECUTIVE COVER PAGE
    // =========================================================================
    
    // Top Navy Header Banner
    doc.rect(0, 0, doc.page.width, 135).fill(BRAND.primary)
    doc.rect(0, 135, doc.page.width, 4).fill(BRAND.accent)

    // Eyebrow Tag
    drawRoundedBadge(doc, 'EXECUTIVE & IT REMEDIATION PLAYBOOK', leftX, 35, '#0284C7', '#FFFFFF', null, 3)

    // Main Title & Subtitle
    doc.fontSize(22).font('Helvetica-Bold').fillColor('#FFFFFF')
      .text('Simplified IT Action Guide', leftX, 58, { width: w })
    doc.fontSize(10.5).font('Helvetica').fillColor('#38BDF8')
      .text('Plain-Language Remediation Playbook for IT & Operations Teams', leftX, 86, { width: w })
    doc.fontSize(8.5).font('Helvetica').fillColor('#94A3B8')
      .text('SentinelAI Autonomous Pentest & Vulnerability Management Platform', leftX, 105, { width: w })

    doc.y = 155

    // Overall Security Health & Posture Box
    const postureY = doc.y
    let postureColor = SEV_COLORS.medium
    let postureTitle = 'MODERATE RISK - SCHEDULED HARDENING REQUIRED'
    let postureDesc = 'No emergency critical issues detected today. Scheduled remediation recommended for configuration and defense hardening.'

    if (todayCount > 0) {
      postureColor = SEV_COLORS.critical
      postureTitle = 'CRITICAL ATTENTION REQUIRED - IMMEDIATE ACTION'
      postureDesc = `${todayCount} critical issue(s) require immediate same-day remediation to prevent potential compromise or breach.`
    } else if (weekCount > 0) {
      postureColor = SEV_COLORS.high
      postureTitle = 'ELEVATED RISK - ACTION REQUIRED THIS WEEK'
      postureDesc = `${weekCount} high-priority issue(s) identified. Remediate within 7 days to eliminate high-risk exposure pathways.`
    } else if (laterCount > 0) {
      postureColor = SEV_COLORS.medium
      postureTitle = 'MODERATE RISK - SCHEDULED HARDENING REQUIRED'
      postureDesc = `Perimeter is stable. ${laterCount} medium-priority hardening item(s) should be scheduled during routine maintenance.`
    } else if (vulnerabilities.length > 0) {
      postureColor = SEV_COLORS.low
      postureTitle = 'GOOD POSTURE - LOW-PRIORITY HARDENING OPPORTUNITIES'
      postureDesc = 'No critical, high, or medium threats detected. General security hygiene opportunities identified.'
    } else {
      postureColor = SEV_COLORS.success
      postureTitle = 'HEALTHY POSTURE - NO ACTIONABLE THREATS IDENTIFIED'
      postureDesc = 'All automated and AI security test suites passed. No vulnerabilities were detected on tested endpoints.'
    }

    doc.roundedRect(leftX, postureY, w, 70, 4).fillAndStroke(postureColor.light, postureColor.border)
    drawRoundedBadge(doc, 'OVERALL POSTURE', leftX + 16, postureY + 12, postureColor.bg, '#FFFFFF', null, 3)
    doc.fontSize(12).font('Helvetica-Bold').fillColor(postureColor.border).text(postureTitle, leftX + 110, postureY + 12, { width: w - 126 })
    doc.fontSize(9.5).font('Helvetica').fillColor(BRAND.textDark).text(postureDesc, leftX + 16, postureY + 34, { width: w - 32 })

    // Assessment Scope & Metadata Card
    doc.y = postureY + 85
    const metaY = doc.y
    const metaH = 135
    doc.roundedRect(leftX, metaY, w, metaH, 4).fillAndStroke(BRAND.cardBg, BRAND.cardBorder)

    doc.fontSize(11).font('Helvetica-Bold').fillColor(BRAND.primary).text('Assessment & Target Profile', leftX + 18, metaY + 14)
    doc.strokeColor(BRAND.borderLight).lineWidth(1).moveTo(leftX + 18, metaY + 30).lineTo(rightX - 18, metaY + 30).stroke()

    const col1X = leftX + 18
    const col2X = leftX + w / 2 + 10
    const colW = w / 2 - 28
    const rowGap = 30
    const rowStartY = metaY + 40

    const metaItems = [
      [
        { label: 'Target System / URL', val: targetName },
        { label: 'Assessment Date', val: reportDateStr },
      ],
      [
        { label: 'Assessment Mode', val: isWhitebox ? 'Whitebox (Static Source Code Audit)' : (primaryScan.mode ? primaryScan.mode.toUpperCase() + ' Dynamic Blackbox' : 'Blackbox Dynamic Pentest') },
        { label: 'Prepared By', val: 'SentinelAI Autonomous Security Engine v2.0' },
      ],
      [
        { label: 'Actionable Tasks', val: `${actionableTotal} Total (${todayCount} Today, ${weekCount} This Week, ${laterCount} Scheduled)` },
        { label: 'Project Context', val: projectName },
      ],
    ]

    for (let r = 0; r < metaItems.length; r++) {
      const curRowY = rowStartY + r * rowGap
      const [c1, c2] = metaItems[r]
      doc.fontSize(7.5).font('Helvetica-Bold').fillColor(BRAND.textMuted).text(c1.label.toUpperCase(), col1X, curRowY, { width: colW })
      doc.fontSize(9.5).font('Helvetica').fillColor(BRAND.textDark).text(String(c1.val).slice(0, 52), col1X, curRowY + 11, { width: colW })

      doc.fontSize(7.5).font('Helvetica-Bold').fillColor(BRAND.textMuted).text(c2.label.toUpperCase(), col2X, curRowY, { width: colW })
      doc.fontSize(9.5).font('Helvetica').fillColor(BRAND.textDark).text(String(c2.val).slice(0, 52), col2X, curRowY + 11, { width: colW })
    }

    // Detected Tech Stack Card
    doc.y = metaY + metaH + 15
    const techY = doc.y
    const techH = 55
    doc.roundedRect(leftX, techY, w, techH, 4).fillAndStroke('#FFFFFF', BRAND.cardBorder)
    doc.fontSize(8.5).font('Helvetica-Bold').fillColor(BRAND.primary).text('DETECTED TECHNOLOGY STACK', leftX + 16, techY + 10)
    const techText = detectedTech.length > 0 
      ? detectedTech.join(', ')
      : 'Standard Web Application Architecture (HTTP/HTTPS Reverse Proxy & Application Server)'
    doc.fontSize(9).font('Helvetica').fillColor(BRAND.textMuted).text(sanitizePdfText(techText), leftX + 16, techY + 24, { width: w - 32 })
    doc.fontSize(7.5).font('Helvetica').fillColor('#94A3B8').text('* Remediation steps in this guide reference settings and syntax for these technologies.', leftX + 16, techY + 38, { width: w - 32 })

    // Purpose & Guidance Callout
    doc.y = techY + techH + 15
    const guideY = doc.y
    const guideH = 80
    doc.roundedRect(leftX, guideY, w, guideH, 4).fillAndStroke(BRAND.cardBg, BRAND.cardBorder)
    doc.fontSize(9.5).font('Helvetica-Bold').fillColor(BRAND.primary).text('About This Simplified IT Action Guide', leftX + 16, guideY + 12)
    doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textDark).text(
      sanitizePdfText(custom.customSummary || 'This guide is designed for IT administrators, webmasters, and operations engineers. Rather than listing raw scanner vulnerabilities with academic CVSS ratings, it categorizes findings into plain-language tasks with clear business risks, step-by-step click-paths or configuration directives, and quick verification checks.'),
      leftX + 16, guideY + 28, { width: w - 32, lineGap: 2 },
    )

    // Cover Page Footer Note (temporarily zero bottom margin to prevent auto-addPage)
    const coverOrigBottom = doc.page.margins.bottom
    doc.page.margins.bottom = 0
    doc.fontSize(7.5).font('Helvetica').fillColor('#94A3B8').text(
      'CONFIDENTIAL - FOR AUTHORIZED IT OPERATIONS & ENGINEERING PERSONNEL ONLY',
      leftX, doc.page.height - 28, { width: w, align: 'center' },
    )
    doc.page.margins.bottom = coverOrigBottom

    // =========================================================================
    // PAGE 2: WHAT NEEDS YOUR ATTENTION (PRIORITIZATION & ATTENTION DASHBOARD)
    // =========================================================================
    doc.addPage()

    drawSectionTitle(doc, 'What Needs Your Attention', 'Urgency triage, remediation SLAs, and operational action matrix')

    // Top Posture Alert Banner
    const alertY = doc.y
    const alertH = 55
    let alertBg = '#EFF6FF'
    let alertBorder = '#2563EB'
    let alertTag = 'NO CRITICAL THREATS TODAY'
    let alertMessage = `Good news: 0 critical and 0 high-severity threats detected. You have ${laterCount} medium-priority hardening item(s) to schedule during upcoming maintenance cycles.`

    if (todayCount > 0) {
      alertBg = '#FEF2F2'
      alertBorder = '#DC2626'
      alertTag = 'IMMEDIATE ACTION REQUIRED'
      alertMessage = `You have ${todayCount} critical issue(s) that require immediate same-day intervention to protect services against active exploitability.`
    } else if (weekCount > 0) {
      alertBg = '#FFF7ED'
      alertBorder = '#EA580C'
      alertTag = 'URGENT ACTION THIS WEEK'
      alertMessage = `0 critical issues today. However, ${weekCount} high-priority issue(s) should be remediated within 7 days to eliminate high-risk exposure.`
    } else if (actionableTotal === 0) {
      alertBg = '#F0FDF4'
      alertBorder = '#16A34A'
      alertTag = 'TARGET SYSTEM HEALTHY'
      alertMessage = 'No critical, high, or medium severity vulnerabilities were detected on tested endpoints. All primary security baselines passed.'
    }

    doc.roundedRect(leftX, alertY, w, alertH, 4).fillAndStroke(alertBg, alertBorder)
    // Left colored accent line
    doc.rect(leftX, alertY, 4, alertH).fill(alertBorder)
    drawRoundedBadge(doc, alertTag, leftX + 16, alertY + 10, alertBorder, '#FFFFFF', null, 3)
    doc.fontSize(9.5).font('Helvetica-Bold').fillColor(BRAND.primary).text(alertMessage, leftX + 16, alertY + 28, { width: w - 32 })

    // 3 Side-by-Side KPI Metric Cards
    doc.y = alertY + alertH + 16
    const kpiY = doc.y
    const cardGap = 12
    const kpiCardW = (w - cardGap * 2) / 3
    const kpiCardH = 75

    const kpiData = [
      {
        title: 'Fix Today',
        count: todayCount,
        color: SEV_COLORS.critical,
        sla: 'SLA: < 24 Hours',
        note: todayCount > 0 ? 'Critical Severity' : 'Zero Emergency Items',
      },
      {
        title: 'This Week',
        count: weekCount,
        color: SEV_COLORS.high,
        sla: 'SLA: Within 7 Days',
        note: weekCount > 0 ? 'High Severity' : 'Zero High Items',
      },
      {
        title: 'When Convenient',
        count: laterCount,
        color: SEV_COLORS.medium,
        sla: 'SLA: Next 30 Days',
        note: laterCount > 0 ? 'Medium / Hardening' : 'Zero Medium Items',
      },
    ]

    for (let k = 0; k < 3; k++) {
      const cardX = leftX + k * (kpiCardW + cardGap)
      const data = kpiData[k]

      // Card container
      doc.roundedRect(cardX, kpiY, kpiCardW, kpiCardH, 4).fillAndStroke('#FFFFFF', BRAND.cardBorder)
      // Top colored bar
      doc.rect(cardX, kpiY, kpiCardW, 4).fill(data.color.bg)

      // Header row
      doc.fontSize(8.5).font('Helvetica-Bold').fillColor(BRAND.textMuted).text(data.title.toUpperCase(), cardX + 12, kpiY + 12)
      
      // Giant Number
      doc.fontSize(24).font('Helvetica-Bold').fillColor(data.color.bg).text(String(data.count), cardX + 12, kpiY + 24)

      // Subtitle / SLA
      doc.fontSize(8).font('Helvetica-Bold').fillColor(BRAND.primary).text(data.sla, cardX + 50, kpiY + 28)
      doc.fontSize(7.5).font('Helvetica').fillColor(BRAND.textMuted).text(data.note, cardX + 50, kpiY + 40)
    }

    // Remediation SLA & Priority Breakdown Table
    doc.y = kpiY + kpiCardH + 18
    const tblY = doc.y
    const tblH = 105
    doc.roundedRect(leftX, tblY, w, tblH, 4).fillAndStroke('#FFFFFF', BRAND.cardBorder)

    // Table Header
    doc.rect(leftX, tblY, w, 22).fill('#F1F5F9')
    doc.strokeColor(BRAND.borderLight).lineWidth(1).moveTo(leftX, tblY + 22).lineTo(rightX, tblY + 22).stroke()

    doc.fontSize(8).font('Helvetica-Bold').fillColor(BRAND.textMuted)
    doc.text('PRIORITY LEVEL', leftX + 12, tblY + 7, { width: 110 })
    doc.text('ACTIVE TASKS', leftX + 125, tblY + 7, { width: 75 })
    doc.text('TARGET SLA', leftX + 205, tblY + 7, { width: 95 })
    doc.text('RECOMMENDED OPERATIONAL ACTION', leftX + 305, tblY + 7, { width: w - 315 })

    const tableRows = [
      {
        badge: 'CRITICAL',
        color: SEV_COLORS.critical,
        tasks: `${todayCount} task${todayCount === 1 ? '' : 's'}`,
        sla: 'Immediate (< 24h)',
        action: 'Emergency hotfix - isolate and patch immediately to block exploit paths.',
      },
      {
        badge: 'HIGH',
        color: SEV_COLORS.high,
        tasks: `${weekCount} task${weekCount === 1 ? '' : 's'}`,
        sla: 'Within 7 Days',
        action: 'Urgent sprint item - resolve during current cycle to protect data integrity.',
      },
      {
        badge: 'MEDIUM',
        color: SEV_COLORS.medium,
        tasks: `${laterCount} task${laterCount === 1 ? '' : 's'}`,
        sla: 'Within 30 Days',
        action: 'Defense-in-depth - apply web server and security header hardening.',
      },
    ]

    for (let r = 0; r < tableRows.length; r++) {
      const rowY = tblY + 23 + r * 27
      const tr = tableRows[r]

      if (r > 0) {
        doc.strokeColor('#F1F5F9').lineWidth(0.8).moveTo(leftX + 8, rowY).lineTo(rightX - 8, rowY).stroke()
      }

      drawRoundedBadge(doc, tr.badge, leftX + 12, rowY + 5, tr.color.bg, '#FFFFFF', null, 2)
      doc.fontSize(8.5).font('Helvetica-Bold').fillColor(BRAND.textDark).text(tr.tasks, leftX + 125, rowY + 7, { width: 75 })
      doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textMuted).text(tr.sla, leftX + 205, rowY + 7, { width: 95 })
      doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textDark).text(tr.action, leftX + 305, rowY + 7, { width: w - 315 })
    }

    // Top Priority Recommendation Callout
    doc.y = tblY + tblH + 16
    const calloutY = doc.y
    const calloutH = 55
    doc.roundedRect(leftX, calloutY, w, calloutH, 4).fillAndStroke('#F8FAFC', BRAND.cardBorder)
    doc.rect(leftX, calloutY, 4, calloutH).fill(BRAND.accent)

    drawRoundedBadge(doc, 'RECOMMENDED PRIORITY FOCUS', leftX + 14, calloutY + 8, BRAND.accent, '#FFFFFF', null, 3)
    
    let focusText = simplifiedGuide?.topPriority
    if (!focusText) {
      if (todayCount > 0) {
        focusText = 'Focus immediately on resolving critical findings. Patch vulnerable code paths and restrict external exposure.'
      } else if (weekCount > 0) {
        focusText = 'Prioritize high-severity access control and authentication hardening within the next 7 business days.'
      } else if (laterCount > 0) {
        focusText = `Schedule remediation for the ${laterCount} medium-priority configuration and security header directives during your next regular deployment window.`
      } else {
        focusText = 'No immediate threats detected. Maintain routine automated scanning cadence and follow security baseline best practices.'
      }
    }
    doc.fontSize(9.5).font('Helvetica').fillColor(BRAND.textDark).text(sanitizePdfText(focusText), leftX + 14, calloutY + 27, { width: w - 28 })

    // Remediation Resources & Operational Workflow
    doc.y = calloutY + calloutH + 14
    const workY = doc.y
    const workH = 75
    doc.roundedRect(leftX, workY, w, workH, 4).fillAndStroke('#FFFFFF', BRAND.cardBorder)

    doc.fontSize(9).font('Helvetica-Bold').fillColor(BRAND.primary).text('OPERATIONAL EXECUTION WORKFLOW', leftX + 14, workY + 10)
    
    const stepW = (w - 28 - 16) / 3
    const steps = [
      {
        num: '1',
        title: 'Review Fix Cards',
        desc: 'Consult the step-by-step instructions on the following pages for exact configuration directives.',
      },
      {
        num: '2',
        title: 'Deploy Directives',
        desc: 'Apply changes in staging, verify non-disruption to web assets, and deploy to production.',
      },
      {
        num: '3',
        title: 'Verify & Sign Off',
        desc: 'Re-run SentinelAI security scan to confirm vulnerability mitigation and record sign-off.',
      },
    ]

    for (let s = 0; s < 3; s++) {
      const stepX = leftX + 14 + s * (stepW + 8)
      const st = steps[s]

      doc.rect(stepX, workY + 28, 16, 16).fill(BRAND.primary)
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#FFFFFF').text(st.num, stepX, workY + 31, { width: 16, align: 'center' })

      doc.fontSize(8.5).font('Helvetica-Bold').fillColor(BRAND.primary).text(st.title, stepX + 22, workY + 28)
      doc.fontSize(7.5).font('Helvetica').fillColor(BRAND.textMuted).text(st.desc, stepX + 22, workY + 40, { width: stepW - 22, lineGap: 1 })
    }

    // =========================================================================
    // PAGE 3+: ACTIONABLE REMEDIATION CARDS ("YOUR FIX CARDS")
    // =========================================================================
    doc.addPage()

    drawSectionTitle(doc, 'Your Fix Cards', 'Step-by-step remediation instructions with symptoms, business risks, and verification steps')

    const urgencyBadgeColors = {
      'fix-today': { bg: '#DC2626', label: 'FIX TODAY - IMMEDIATE' },
      'this-week': { bg: '#EA580C', label: 'THIS WEEK - URGENT' },
      'optional':  { bg: '#2563EB', label: 'SCHEDULED - SPRINT' },
    }

    const difficultyBadgeColors = {
      easy:   { bg: '#16A34A', label: 'EASY FIX' },
      medium: { bg: '#D97706', label: 'MODERATE' },
      hard:   { bg: '#9333EA', label: 'COMPLEX' },
    }

    if (items.length === 0) {
      // Empty state
      const emptyH = 120
      doc.roundedRect(leftX, doc.y, w, emptyH, 4).fillAndStroke('#F0FDF4', '#BBF7D0')
      doc.rect(leftX, doc.y, 4, emptyH).fill('#16A34A')
      drawRoundedBadge(doc, 'ALL CLEAR', leftX + 16, doc.y + 14, '#16A34A', '#FFFFFF', null, 3)
      doc.fontSize(12).font('Helvetica-Bold').fillColor(BRAND.primary).text('No Actionable Fix Cards Required', leftX + 90, doc.y + 14)
      doc.fontSize(9.5).font('Helvetica').fillColor(BRAND.textDark).text(
        'The security assessment identified zero critical, high, or medium severity vulnerabilities on the target host. No emergency configurations or code modifications are required at this time.',
        leftX + 16, doc.y + 40, { width: w - 32, lineGap: 3 },
      )
    } else {
      items.forEach((item, idx) => {
        // Calculate estimated height
        const symptomH = doc.fontSize(8.5).font('Helvetica').heightOfString(item.symptom || 'N/A', { width: w - 130 })
        const riskH = doc.fontSize(8.5).font('Helvetica').heightOfString(item.risk || 'N/A', { width: w - 130 })
        const prescH = doc.fontSize(8.5).font('Helvetica').heightOfString(item.prescription || 'N/A', { width: w - 36 })
        const verifH = doc.fontSize(8.5).font('Helvetica').heightOfString(item.verification || 'N/A', { width: w - 130 })

        const totalCardH = 40 + Math.max(16, symptomH) + 8 + Math.max(16, riskH) + 12 + Math.max(28, prescH + 18) + 8 + Math.max(16, verifH) + 16

        // Page break if needed
        if (doc.y + totalCardH > doc.page.height - 55) {
          doc.addPage()
        }

        const cardY = doc.y
        const uMeta = urgencyBadgeColors[item.urgency] || urgencyBadgeColors.optional
        const dMeta = difficultyBadgeColors[item.difficulty] || difficultyBadgeColors.medium

        // Card container
        doc.roundedRect(leftX, cardY, w, totalCardH, 4).fillAndStroke('#FFFFFF', BRAND.cardBorder)
        // Top colored accent bar
        doc.rect(leftX, cardY, w, 4).fill(uMeta.bg)

        // Title row
        doc.fontSize(11).font('Helvetica-Bold').fillColor(BRAND.primary)
          .text(`${idx + 1}. ${item.title}`, leftX + 14, cardY + 12, { width: w - 210 })

        // Badges on top right
        let curBadgeX = rightX - 14
        const timeBadgeW = drawRoundedBadge(doc, `~${item.estimatedMinutes || 25} MIN`, curBadgeX - 55, cardY + 10, '#64748B', '#FFFFFF', null, 2)
        curBadgeX -= (timeBadgeW + 6)
        const diffBadgeW = drawRoundedBadge(doc, dMeta.label, curBadgeX - 65, cardY + 10, dMeta.bg, '#FFFFFF', null, 2)
        curBadgeX -= (diffBadgeW + 6)
        drawRoundedBadge(doc, uMeta.label, curBadgeX - 95, cardY + 10, uMeta.bg, '#FFFFFF', null, 2)

        let contentY = cardY + 36

        // Row 1: Symptom
        doc.fontSize(8).font('Helvetica-Bold').fillColor(BRAND.textMuted).text('WHAT WAS FOUND:', leftX + 14, contentY, { width: 110 })
        doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textDark).text(item.symptom || 'N/A', leftX + 130, contentY, { width: w - 144 })
        contentY += Math.max(16, symptomH) + 6

        // Row 2: Risk
        doc.fontSize(8).font('Helvetica-Bold').fillColor('#DC2626').text('WHY IT MATTERS:', leftX + 14, contentY, { width: 110 })
        doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textDark).text(item.risk || 'N/A', leftX + 130, contentY, { width: w - 144 })
        contentY += Math.max(16, riskH) + 8

        // Row 3: Prescription Box
        const prescBoxH = Math.max(30, prescH + 18)
        doc.roundedRect(leftX + 14, contentY, w - 28, prescBoxH, 3).fillAndStroke('#F8FAFC', BRAND.borderLight)
        doc.rect(leftX + 14, contentY, 3, prescBoxH).fill('#16A34A')
        doc.fontSize(8).font('Helvetica-Bold').fillColor('#16A34A').text('HOW TO FIX (RECOMMENDED REMEDIATION):', leftX + 24, contentY + 6)
        doc.fontSize(8.5).font('Courier').fillColor(BRAND.primary).text(item.prescription || 'N/A', leftX + 24, contentY + 18, { width: w - 48 })
        contentY += prescBoxH + 8

        // Row 4: Verification
        doc.fontSize(8).font('Helvetica-Bold').fillColor(BRAND.accent).text('CHECK IT WORKED:', leftX + 14, contentY, { width: 110 })
        doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textMuted).text(item.verification || 'Re-scan with SentinelAI after applying changes.', leftX + 130, contentY, { width: w - 144 })

        doc.y = cardY + totalCardH + 12
      })
    }

    // =========================================================================
    // PAGE 4 (or Final Page): IT OPERATIONS CHECKLIST & SIGN-OFF
    // =========================================================================
    if (doc.y > doc.page.height - 240) {
      doc.addPage()
    } else {
      doc.moveDown(1.5)
    }

    drawSectionTitle(doc, 'Remediation Tracking Checklist', 'Record task assignment, implementation status, and verification sign-off')

    const checkY = doc.y
    const checkRowH = 22
    const checkRowCount = Math.max(3, Math.min(items.length, 8))
    const checkTableH = 22 + checkRowCount * checkRowH

    doc.roundedRect(leftX, checkY, w, checkTableH, 4).fillAndStroke('#FFFFFF', BRAND.cardBorder)
    doc.rect(leftX, checkY, w, 22).fill('#F1F5F9')

    doc.fontSize(7.5).font('Helvetica-Bold').fillColor(BRAND.textMuted)
    doc.text('#', leftX + 10, checkY + 7, { width: 20 })
    doc.text('ACTION ITEM / DIRECTIVE', leftX + 35, checkY + 7, { width: 230 })
    doc.text('PRIORITY', leftX + 270, checkY + 7, { width: 70 })
    doc.text('ASSIGNED TO', leftX + 345, checkY + 7, { width: 85 })
    doc.text('COMPLETED', leftX + 435, checkY + 7, { width: 75 })

    for (let c = 0; c < checkRowCount; c++) {
      const rowY = checkY + 22 + c * checkRowH
      const itm = items[c]
      doc.strokeColor('#F1F5F9').lineWidth(0.8).moveTo(leftX, rowY).lineTo(rightX, rowY).stroke()

      doc.fontSize(8).font('Helvetica-Bold').fillColor(BRAND.primary).text(String(c + 1), leftX + 10, rowY + 6, { width: 20 })
      doc.fontSize(8).font('Helvetica').fillColor(BRAND.textDark).text(
        itm ? String(itm.title).slice(0, 42) : 'General Security Maintenance',
        leftX + 35, rowY + 6, { width: 230 },
      )
      
      const sevLabel = itm ? itm.severity.toUpperCase() : 'MEDIUM'
      const sevColor = SEV_COLORS[itm?.severity] || SEV_COLORS.medium
      drawRoundedBadge(doc, sevLabel, leftX + 270, rowY + 4, sevColor.bg, '#FFFFFF', null, 2)

      // Signature lines
      doc.strokeColor('#CBD5E1').lineWidth(0.5).moveTo(leftX + 345, rowY + 16).lineTo(leftX + 420, rowY + 16).stroke()
      doc.rect(leftX + 445, rowY + 5, 10, 10).strokeColor('#94A3B8').lineWidth(1).stroke()
      doc.fontSize(7.5).font('Helvetica').fillColor(BRAND.textMuted).text('Verified', leftX + 460, rowY + 6)
    }

    doc.y = checkY + checkTableH + 16

    // Sign-Off Container
    const signY = doc.y
    const signH = 65
    doc.roundedRect(leftX, signY, w, signH, 4).fillAndStroke(BRAND.cardBg, BRAND.cardBorder)
    doc.fontSize(8.5).font('Helvetica-Bold').fillColor(BRAND.primary).text('REMEDIATION COMPLETION SIGN-OFF', leftX + 16, signY + 10)

    doc.fontSize(8).font('Helvetica').fillColor(BRAND.textMuted).text('Remediation Lead / IT Manager:', leftX + 16, signY + 28)
    doc.strokeColor('#CBD5E1').lineWidth(0.8).moveTo(leftX + 145, signY + 38).lineTo(leftX + 270, signY + 38).stroke()

    doc.fontSize(8).font('Helvetica').fillColor(BRAND.textMuted).text('Date Completed:', leftX + 300, signY + 28)
    doc.strokeColor('#CBD5E1').lineWidth(0.8).moveTo(leftX + 375, signY + 38).lineTo(leftX + 480, signY + 38).stroke()

    doc.fontSize(7.5).font('Helvetica').fillColor('#94A3B8').text(
      '* After implementing all fixes, re-trigger a SentinelAI verification scan to ensure 100% compliance closure.',
      leftX + 16, signY + 48, { width: w - 32 },
    )

    // Custom Conclusion if specified
    if (custom.customConclusion) {
      doc.y = signY + signH + 14
      doc.fontSize(9.5).font('Helvetica-Bold').fillColor(BRAND.primary).text('Operational Notes', leftX, doc.y)
      doc.moveDown(0.3)
      doc.fontSize(8.5).font('Helvetica').fillColor(BRAND.textDark).text(sanitizePdfText(custom.customConclusion), leftX, doc.y, { width: w })
    }

    // =========================================================================
    // RUNNING HEADERS & FOOTERS (All pages except Cover)
    // =========================================================================
    const range = doc.bufferedPageRange()
    const totalPages = range.count

    for (let p = range.start; p < range.start + totalPages; p++) {
      if (p === 0) continue // Skip cover page running header/footer
      doc.switchToPage(p)

      const origBottom = doc.page.margins.bottom
      doc.page.margins.bottom = 0
      doc.save()

      // Header Top Accent Stripe
      doc.rect(0, 0, doc.page.width, 4).fill(BRAND.accent)

      // Header Text
      doc.fontSize(8).font('Helvetica-Bold').fillColor('#94A3B8')
        .text('SENTINELAI - SIMPLIFIED IT ACTION GUIDE', leftX, 22, { lineBreak: false })
      doc.fontSize(8).font('Helvetica').fillColor('#94A3B8')
        .text(targetName, rightX - 180, 22, { width: 180, align: 'right', lineBreak: false })

      // Header Divider Line
      doc.strokeColor('#E2E8F0').lineWidth(0.5).moveTo(leftX, 34).lineTo(rightX, 34).stroke()

      // Footer Divider Line
      doc.strokeColor('#E2E8F0').lineWidth(0.5).moveTo(leftX, doc.page.height - 38).lineTo(rightX, doc.page.height - 38).stroke()

      // Footer Text
      doc.fontSize(8).font('Helvetica-Bold').fillColor('#94A3B8')
        .text('CONFIDENTIAL - AUTHORIZED IT & OPERATIONS DISTRIBUTION ONLY', leftX, doc.page.height - 28, { lineBreak: false })
      doc.fontSize(8).font('Helvetica').fillColor('#94A3B8')
        .text(`Page ${p + 1} of ${totalPages}`, rightX - 100, doc.page.height - 28, { width: 100, align: 'right', lineBreak: false })

      doc.restore()
      doc.page.margins.bottom = origBottom
    }

    doc.end()
    stream.on('finish', resolve)
    stream.on('error', reject)
  })
}

const mockVulnerabilities = [
  {
    title: 'Missing Content-Security-Policy (CSP) Header',
    severity: 'medium',
    description: 'The target web application does not implement a Content-Security-Policy HTTP header.',
    remediation: 'Implement a strict CSP restricting script sources to self and trusted domains.',
  },
  {
    title: 'Missing X-Frame-Options Header (Clickjacking Risk)',
    severity: 'medium',
    description: 'The response lacks the X-Frame-Options HTTP header, allowing framing by third parties.',
    remediation: 'Add X-Frame-Options: SAMEORIGIN header to prevent unauthorized framing.',
  },
  {
    title: 'Missing Strict-Transport-Security (HSTS) Header',
    severity: 'medium',
    description: 'HSTS is not configured on the domain, allowing potential SSL stripping attacks.',
    remediation: 'Enable HSTS with max-age=31536000 and includeSubDomains.',
  },
  {
    title: 'Server Banner Information Disclosure',
    severity: 'medium',
    description: 'Web server returns detailed software version in Server header.',
    remediation: 'Configure web server (Nginx/Apache) to suppress server version details.',
  },
]

const outputPath = path.resolve('./output/test-simplified-redesign.pdf')
console.log('Rendering test PDF to:', outputPath)

renderSimplifiedPdf({
  file: outputPath,
  reportTitle: 'Simplified IT Action Guide: https://example.com',
  scans: [{ target: 'https://example.com', mode: 'blackbox' }],
  project: { name: 'Production Web Perimeter' },
  vulnerabilities: mockVulnerabilities,
  isWhitebox: false,
  detectedTech: ['Cloudflare', 'Nginx', 'Ubuntu Linux'],
}).then(() => {
  const stat = fs.statSync(outputPath)
  console.log('Successfully generated test PDF! File size:', stat.size, 'bytes')
}).catch(err => {
  console.error('Error rendering PDF:', err)
})
