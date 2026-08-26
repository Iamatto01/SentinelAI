import nodemailer from 'nodemailer'

const DEFAULT_NOTIFY_EMAIL = 'muhammadsaifudinmj@gmail.com'

export async function sendScanRequestNotification({ clientUser, project, target, scanType, notes }) {
  const recipient = process.env.NOTIFICATION_EMAIL || DEFAULT_NOTIFY_EMAIL

  const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com'
  const smtpPort = Number(process.env.SMTP_PORT || 587)
  const smtpUser = process.env.SMTP_USER || ''
  const smtpPass = process.env.SMTP_PASS || ''

  let transporter
  if (smtpUser && smtpPass) {
    transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    })
  } else {
    // Fallback transporter (JSON transport for dev/testing when SMTP env vars are not set)
    transporter = nodemailer.createTransport({
      jsonTransport: true,
    })
  }

  const clientName = clientUser?.username || clientUser?.email || 'Client'
  const clientEmail = clientUser?.email || 'Not provided'
  const projectName = project?.name || 'Unassigned Project'
  const clientCompany = project?.client || 'Client Organization'

  const subject = `[SentinelAI] New Scan Request from ${clientName} (${clientCompany})`

  const htmlContent = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #09090b; color: #f4f4f5; border: 1px solid rgba(255,255,255,0.15); border-radius: 12px; padding: 24px;">
      <div style="display: flex; align-items: center; justify-content: space-between; border-b: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px; margin-bottom: 20px;">
        <h2 style="color: #00f2fe; margin: 0; font-size: 20px;">🛡️ SentinelAI — New Scan Request</h2>
      </div>

      <p style="color: #a1a1aa; font-size: 14px; margin-bottom: 20px;">
        A new penetration test scan request has been submitted by a client user. Details below:
      </p>

      <table style="width: 100%; border-collapse: collapse; background-color: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; overflow: hidden; margin-bottom: 24px;">
        <tbody>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600; width: 140px;">Client User</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #ffffff; font-size: 14px; font-weight: 600;">
              ${clientName} <span style="color: #a1a1aa; font-size: 12px; font-weight: normal;">(${clientEmail})</span>
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600;">Project</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #ffffff; font-size: 14px;">
              ${projectName} <span style="color: #00f2fe; font-size: 12px;">[${clientCompany}]</span>
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600;">Target Scope</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #00f2fe; font-family: monospace; font-size: 14px; font-weight: bold;">
              ${target}
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600;">Scan Profile</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #ffffff; font-size: 14px;">
              ${scanType || 'Full Security Assessment'}
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; color: #71717a; font-size: 13px; font-weight: 600;">Notes</td>
            <td style="padding: 12px 16px; color: #d4d4d8; font-size: 14px; white-space: pre-wrap;">${notes || 'No additional notes.'}</td>
          </tr>
        </tbody>
      </table>

      <div style="background-color: rgba(0, 242, 254, 0.1); border: 1px solid rgba(0, 242, 254, 0.3); border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 13px; color: #38bdf8;">
        <strong>Action Required:</strong> Log in to SentinelAI Pentest Suite to review and execute this scan.
      </div>

      <div style="border-t: 1px solid rgba(255,255,255,0.1); padding-top: 16px; font-size: 12px; color: #71717a; text-align: center;">
        Sent via SentinelAI Platform &bull; ${new Date().toUTCString()}
      </div>
    </div>
  `

  try {
    const info = await transporter.sendMail({
      from: `"SentinelAI Security Portal" <${smtpUser || 'no-reply@sentinelai.studio'}>`,
      to: recipient,
      subject,
      html: htmlContent,
    })

    console.log(`[email] Scan request notification sent to ${recipient}:`, info.messageId || JSON.stringify(info))
    return { success: true, recipient, messageId: info.messageId }
  } catch (err) {
    console.error(`[email] Delivery failed to ${recipient}:`, err.message)
    return { success: false, recipient, error: err.message }
  }
}

/**
 * Send Anonymous Community Feedback & Bug Report to developer email
 */
export async function sendAnonymousFeedbackNotification({ category = 'General Feedback', message, rating, userContext = 'Anonymous Community User' }) {
  const recipient = DEFAULT_NOTIFY_EMAIL

  const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com'
  const smtpPort = Number(process.env.SMTP_PORT || 587)
  const smtpUser = process.env.SMTP_USER || ''
  const smtpPass = process.env.SMTP_PASS || ''

  let transporter
  if (smtpUser && smtpPass) {
    transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
    })
  } else {
    transporter = nodemailer.createTransport({ jsonTransport: true })
  }

  const ratingStars = rating ? '⭐'.repeat(Number(rating)) : 'Not provided'
  const subject = `[SentinelAI Feedback] [${category}] Community Feedback (${ratingStars})`

  const htmlContent = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; background-color: #09090b; color: #f4f4f5; border: 1px solid rgba(255,255,255,0.15); border-radius: 12px; padding: 24px;">
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px; margin-bottom: 20px;">
        <h2 style="color: #00f2fe; margin: 0; font-size: 20px;">💬 SentinelAI — Anonymous Community Feedback</h2>
      </div>

      <p style="color: #a1a1aa; font-size: 14px; margin-bottom: 20px;">
        A user has submitted anonymous feedback / bug report from the platform Settings:
      </p>

      <table style="width: 100%; border-collapse: collapse; background-color: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; overflow: hidden; margin-bottom: 24px;">
        <tbody>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600; width: 130px;">Category</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #00f2fe; font-size: 14px; font-weight: bold;">
              ${category}
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600;">Rating</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #fbbf24; font-size: 14px;">
              ${ratingStars} (${rating || 0}/5)
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #71717a; font-size: 13px; font-weight: 600;">Sender Context</td>
            <td style="padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.08); color: #a1a1aa; font-size: 13px;">
              ${userContext} (Anonymous)
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 16px; color: #71717a; font-size: 13px; font-weight: 600; vertical-align: top;">Feedback Content</td>
            <td style="padding: 12px 16px; color: #ffffff; font-size: 14px; line-height: 1.6; white-space: pre-wrap; font-family: monospace; background: rgba(0,0,0,0.3); border-radius: 6px;">${message || '(No message provided)'}</td>
          </tr>
        </tbody>
      </table>

      <div style="border-top: 1px solid rgba(255,255,255,0.1); padding-top: 16px; font-size: 12px; color: #71717a; text-align: center;">
        Directly sent to muhammadsaifudinmj@gmail.com via SentinelAI Platform &bull; ${new Date().toUTCString()}
      </div>
    </div>
  `

  try {
    const info = await transporter.sendMail({
      from: `"SentinelAI Feedback" <${smtpUser || 'no-reply@sentinelai.studio'}>`,
      to: recipient,
      subject,
      html: htmlContent,
    })

    console.log(`[email] Anonymous feedback delivered to ${recipient}:`, info.messageId || JSON.stringify(info))
    return { success: true, recipient, messageId: info.messageId }
  } catch (err) {
    console.error(`[email] Feedback delivery error:`, err.message)
    return { success: false, recipient, error: err.message }
  }
}

/**
 * Send automated Security Audit Report Email with PDF attachment to subscriber/user
 */
export async function sendScanAuditReportEmail({ userEmail, scan, findings = [], pdfPath, repoName, triggerSource, commitHash }) {
  const recipient = userEmail || process.env.NOTIFICATION_EMAIL || DEFAULT_NOTIFY_EMAIL

  const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com'
  const smtpPort = Number(process.env.SMTP_PORT || 587)
  const smtpUser = process.env.SMTP_USER || ''
  const smtpPass = process.env.SMTP_PASS || ''

  let transporter
  if (smtpUser && smtpPass) {
    transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
    })
  } else {
    transporter = nodemailer.createTransport({ jsonTransport: true })
  }

  // Calculate severity stats
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach(f => {
    const s = (f.severity || 'info').toLowerCase()
    if (sevCounts[s] !== undefined) sevCounts[s]++
  })

  const totalFindings = findings.length
  const riskScore = scan.risk_score != null ? Number(scan.risk_score).toFixed(1) : 'N/A'
  
  // Grade calculation
  let grade = 'A+'
  let gradeColor = '#10B981'
  if (sevCounts.critical > 0 || Number(riskScore) > 75) {
    grade = 'F (Critical Risk)'
    gradeColor = '#EF4444'
  } else if (sevCounts.high > 0 || Number(riskScore) > 50) {
    grade = 'C (Elevated Risk)'
    gradeColor = '#F97316'
  } else if (sevCounts.medium > 0 || Number(riskScore) > 25) {
    grade = 'B (Moderate Risk)'
    gradeColor = '#EAB308'
  }

  const targetDisplay = repoName || scan.target || 'Source Code'
  const subject = `[SentinelAI Audit] ${targetDisplay} Security Report (${grade})`

  // Top 3 findings
  const topFindings = findings.slice(0, 3)
  const findingsHtml = topFindings.length > 0
    ? topFindings.map(f => `
      <div style="background-color: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px; margin-bottom: 10px;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
          <strong style="color: #ffffff; font-size: 14px;">${f.title}</strong>
          <span style="font-size: 11px; font-weight: bold; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background-color: ${f.severity === 'critical' ? '#dc2626' : f.severity === 'high' ? '#ea580c' : '#d97706'}; color: #ffffff;">
            ${f.severity || 'info'}
          </span>
        </div>
        <p style="color: #a1a1aa; font-size: 12px; margin: 4px 0 8px 0; line-height: 1.4;">${f.description ? f.description.slice(0, 160) + '...' : 'No description provided.'}</p>
        ${f.remediation ? `<div style="font-size: 11px; color: #38bdf8; background-color: rgba(56, 189, 248, 0.08); padding: 6px 10px; border-radius: 6px;"><strong>Fix:</strong> ${f.remediation.slice(0, 140)}...</div>` : ''}
      </div>
    `).join('')
    : '<p style="color: #10B981; font-size: 13px;">No security vulnerabilities were identified in this repository.</p>'

  const htmlContent = `
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 620px; margin: 0 auto; background-color: #0B0F19; color: #F1F5F9; border: 1px solid rgba(255,255,255,0.12); border-radius: 14px; padding: 28px;">
      <!-- Header -->
      <div style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 18px; margin-bottom: 22px;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <h2 style="color: #00F2FE; margin: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.5px;">🛡️ SentinelAI Code Audit Report</h2>
          <span style="font-size: 11px; padding: 3px 10px; border-radius: 9999px; background-color: rgba(0, 242, 254, 0.15); color: #00F2FE; border: 1px solid rgba(0, 242, 254, 0.3); text-transform: uppercase; font-weight: bold;">Automated Scan</span>
        </div>
        <p style="color: #94A3B8; font-size: 13px; margin: 6px 0 0 0;">Continuous DevSecOps & AI Code Review summary for your repository.</p>
      </div>

      <!-- Overview Card -->
      <div style="background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.7) 100%); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 18px; margin-bottom: 22px;">
        <div style="margin-bottom: 12px;">
          <span style="color: #64748B; font-size: 11px; text-transform: uppercase; font-weight: bold;">Repository / Target</span>
          <div style="color: #38BDF8; font-family: monospace; font-size: 15px; font-weight: bold; margin-top: 2px;">${targetDisplay}</div>
          ${commitHash ? `<div style="color: #64748B; font-size: 11px; font-family: monospace; margin-top: 2px;">Commit: ${commitHash.slice(0, 8)} (${triggerSource || 'push'})</div>` : ''}
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 12px;">
          <div>
            <span style="color: #64748B; font-size: 11px; text-transform: uppercase; font-weight: bold;">Security Grade</span>
            <div style="color: ${gradeColor}; font-size: 18px; font-weight: 800; margin-top: 2px;">${grade}</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 11px; text-transform: uppercase; font-weight: bold;">Total Findings</span>
            <div style="color: #FFFFFF; font-size: 18px; font-weight: 800; margin-top: 2px;">${totalFindings} issues</div>
          </div>
        </div>
      </div>

      <!-- Severity Badges -->
      <div style="display: flex; gap: 8px; margin-bottom: 22px;">
        <div style="flex: 1; background: rgba(220, 38, 38, 0.15); border: 1px solid rgba(220, 38, 38, 0.3); border-radius: 8px; padding: 10px; text-align: center;">
          <div style="font-size: 16px; font-weight: bold; color: #F87171;">${sevCounts.critical}</div>
          <div style="font-size: 10px; color: #94A3B8; text-transform: uppercase; font-weight: bold;">Critical</div>
        </div>
        <div style="flex: 1; background: rgba(234, 88, 12, 0.15); border: 1px solid rgba(234, 88, 12, 0.3); border-radius: 8px; padding: 10px; text-align: center;">
          <div style="font-size: 16px; font-weight: bold; color: #FB923C;">${sevCounts.high}</div>
          <div style="font-size: 10px; color: #94A3B8; text-transform: uppercase; font-weight: bold;">High</div>
        </div>
        <div style="flex: 1; background: rgba(217, 119, 6, 0.15); border: 1px solid rgba(217, 119, 6, 0.3); border-radius: 8px; padding: 10px; text-align: center;">
          <div style="font-size: 16px; font-weight: bold; color: #FBBF24;">${sevCounts.medium}</div>
          <div style="font-size: 10px; color: #94A3B8; text-transform: uppercase; font-weight: bold;">Medium</div>
        </div>
        <div style="flex: 1; background: rgba(37, 99, 235, 0.15); border: 1px solid rgba(37, 99, 235, 0.3); border-radius: 8px; padding: 10px; text-align: center;">
          <div style="font-size: 16px; font-weight: bold; color: #60A5FA;">${sevCounts.low}</div>
          <div style="font-size: 10px; color: #94A3B8; text-transform: uppercase; font-weight: bold;">Low</div>
        </div>
      </div>

      <!-- Top Findings Section -->
      <h3 style="color: #FFFFFF; font-size: 14px; margin: 0 0 12px 0; text-transform: uppercase; letter-spacing: 0.5px;">Key Security Findings</h3>
      ${findingsHtml}

      <!-- PDF Attachment Notice -->
      <div style="background-color: rgba(0, 242, 254, 0.08); border: 1px solid rgba(0, 242, 254, 0.25); border-radius: 8px; padding: 14px 16px; margin: 24px 0; display: flex; align-items: center; gap: 12px;">
        <span style="font-size: 20px;">📄</span>
        <div>
          <strong style="color: #38BDF8; font-size: 13px;">Full Audit PDF Report Attached</strong>
          <p style="color: #94A3B8; font-size: 11px; margin: 2px 0 0 0;">Download the attached PDF file for comprehensive vulnerability PoCs, code traces, and remediation diffs.</p>
        </div>
      </div>

      <!-- Footer -->
      <div style="border-top: 1px solid rgba(255,255,255,0.1); padding-top: 16px; font-size: 11px; color: #64748B; text-align: center;">
        Sent via SentinelAI Platform &bull; Automated AI DevSecOps Engine &bull; ${new Date().toUTCString()}
      </div>
    </div>
  `

  const attachments = []
  if (pdfPath && fs.existsSync(pdfPath)) {
    attachments.push({
      filename: `SentinelAI-Audit-${(repoName || 'Scan').replace(/[^a-zA-Z0-9-_]/g, '_')}.pdf`,
      path: pdfPath,
      contentType: 'application/pdf',
    })
  }

  try {
    const info = await transporter.sendMail({
      from: `"SentinelAI DevSecOps" <${smtpUser || 'no-reply@sentinelai.studio'}>`,
      to: recipient,
      subject,
      html: htmlContent,
      attachments,
    })

    console.log(`[email] Audit report successfully sent to ${recipient} (Attachments: ${attachments.length}):`, info.messageId || 'OK')
    return { success: true, recipient, messageId: info.messageId, attachedPdf: attachments.length > 0 }
  } catch (err) {
    console.error(`[email] Failed to send audit report to ${recipient}:`, err.message)
    return { success: false, recipient, error: err.message }
  }
}

