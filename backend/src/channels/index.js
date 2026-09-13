import { config } from '../config.js'
import * as db from '../db.js'
import { telegramBot } from './telegram.js'
import { discordBot } from './discord.js'
import { randomUUID } from 'node:crypto'
import { llm } from '../ai/llm-client.js'
import { nativeToolsStatus } from '../integrations/native-tools.js'
import { EXPLOIT_REGISTRY, matchExploits } from '../exploits/registry.js'

const COPILOT_SYSTEM_PROMPT = `You are SentinelAI Security Copilot, an elite offensive and defensive cybersecurity AI specialist integrated with the SentinelAI autonomous penetration testing platform (https://sentinelai.studio).
Your role:
1. Provide accurate, technical, and actionable penetration testing & defensive security advice.
2. Outline risk implications, attack vectors, and concrete remediation steps.
3. Include real CLI examples (nmap, curl, openssl, sqlmap, kali tools) or hardened code snippets where helpful.
4. Keep answers concise, highly readable, and formatted with clean markdown bullet points and code blocks (keep under 350 words so it reads great in Telegram & Discord chat).
5. If the user asks in Malay, answer in professional Malay; if in English, answer in English.`

class ChannelGateway {
  constructor() {
    this.io = null
    this.pipeline = null
    this.orchestrator = null
    this.agentRegistry = null
    this.channels = []
    this.started = false
  }

  attach({ io, pipeline, orchestrator, agentRegistry }) {
    this.io = io
    this.pipeline = pipeline
    this.orchestrator = orchestrator
    this.agentRegistry = agentRegistry
  }

  getApprovedPairing(platform, chatId) {
    try {
      return db.get(
        "SELECT * FROM telegram_pairings WHERE platform = ? AND chat_id = ? AND status = 'approved' ORDER BY approved_at DESC LIMIT 1",
        String(platform),
        String(chatId)
      )
    } catch {
      return null
    }
  }

  isApproved(platform, chatId) {
    return !!this.getApprovedPairing(platform, chatId)
  }

  listApproved() {
    try {
      const rows = db.all("SELECT * FROM telegram_pairings WHERE status = 'approved'")
      return rows.map(r => ({
        id: `${r.platform}:${r.chat_id}`,
        platform: r.platform,
        chatId: r.chat_id,
        userId: r.user_id,
        username: r.username,
        senderName: r.sender_name,
        approvedAt: r.approved_at
      }))
    } catch {
      return []
    }
  }

  broadcast(message, opts = {}) {
    for (const ch of this.channels) {
      if (typeof ch.send === 'function') {
        try { ch.send(message, opts) } catch { }
      }
    }
  }

  async broadcastAlert(message, opts = {}) {
    this.broadcast(message, opts)
  }

  /**
   * Relay scan completion alerts directly to paired Telegram and Discord users!
   */
  async notifyScanCompleted(scan, counts = {}, riskScore = 0) {
    if (!scan) return
    try {
      const pairings = db.all(
        "SELECT platform, chat_id FROM telegram_pairings WHERE (user_id = ? OR username = ?) AND status = 'approved'",
        scan.user_id, scan.client
      )
      if (!pairings || !pairings.length) return

      const critical = counts.critical || 0
      const high = counts.high || 0
      const medium = counts.medium || 0
      const low = (counts.low || 0) + (counts.info || 0)
      const scoreNum = Number(riskScore || 0).toFixed(1)
      const portalUrl = `https://sentinelai.studio/app/scans/${scan.id}`

      for (const p of pairings) {
        if (p.platform === 'telegram') {
          const text =
            `✅ *Imbasan Pentest Selesai!*\n\n` +
            `• *Sasaran:* \`${scan.target || 'Unknown'}\`\n` +
            `• *Skor Risiko:* *${scoreNum} / 10*\n` +
            `• *Penemuan Keselamatan:*\n` +
            `  🔴 Critical: *${critical}*\n` +
            `  🟠 High: *${high}*\n` +
            `  🟡 Medium: *${medium}*\n` +
            `  🔵 Low/Info: *${low}*\n\n` +
            `🔗 Lihat laporan & analitik penuh di:\n${portalUrl}`

          const inlineKeyboard = [
            [
              { text: '⚠️ Lihat Findings', callback_data: `cmd:/findings ${scan.id}` },
              { text: '🌐 Buka Web Portal', url: portalUrl },
            ]
          ]
          telegramBot.sendTo(p.chat_id, text, { inlineKeyboard }).catch(() => {})
        } else if (p.platform === 'discord') {
          const embed = {
            title: `✅ Imbasan Pentest Selesai — ${scan.target || 'Sasaran'}`,
            color: critical > 0 ? 0xf43f5e : (high > 0 ? 0xf59e0b : 0x10b981),
            fields: [
              { name: '🎯 Sasaran', value: `\`${scan.target || 'Unknown'}\``, inline: true },
              { name: '📈 Skor Risiko', value: `**${scoreNum} / 10**`, inline: true },
              { name: '🔴 Critical', value: `**${critical}**`, inline: true },
              { name: '🟠 High', value: `**${high}**`, inline: true },
              { name: '🟡 Medium', value: `**${medium}**`, inline: true },
              { name: '🔵 Low & Info', value: `**${low}**`, inline: true },
              { name: '📄 Laporan Penuh', value: `[Buka Analisis di Portal](${portalUrl})`, inline: false },
            ],
            footer: { text: 'SentinelAI Autonomous Security Operations' },
            timestamp: new Date().toISOString(),
          }
          discordBot.sendTo(p.chat_id, '', { embed }).catch(() => {})
        }
      }
    } catch (e) {
      console.warn(`[Channels] Failed to notify scan completion: ${e.message}`)
    }
  }

  async handleAICopilot(platform, pairedUser, query, reply, chatId) {
    if (platform === 'telegram') telegramBot.sendChatAction(chatId, 'typing')
    if (platform === 'discord') discordBot.sendTyping(chatId)

    try {
      const answer = await llm.analyze(query, {
        system: COPILOT_SYSTEM_PROMPT,
        maxTokens: 1200,
        useFast: true,
      })

      if (platform === 'discord') {
        const embed = {
          title: '🤖 SentinelAI Security Copilot',
          color: 0x8b5cf6, // Purple
          description: (answer || '').slice(0, 4000),
          footer: { text: 'Powered by SentinelAI Multi-LLM Engine (DeepSeek V4 Pro / Groq)' },
          timestamp: new Date().toISOString(),
        }
        reply('', { embed })
      } else {
        const text =
          `🤖 *SentinelAI Security Copilot*\n\n` +
          `${answer}\n\n` +
          `_💡 Enjin Multi-LLM (DeepSeek V4 Pro / Groq / OpenRouter)_`

        const inlineKeyboard = [
          [
            { text: '🛡️ Status Sistem', callback_data: 'cmd:/status' },
            { text: '📊 Imbasan Saya', callback_data: 'cmd:/scans' },
          ]
        ]
        reply(text, { inlineKeyboard })
      }
    } catch (e) {
      reply(`❌ AI Security Copilot tidak dapat membalas buat masa ini: ${e.message}`)
    }
  }

  async handleCommand(platform, chatId, text, reply, senderInfo = {}) {
    const raw = String(text || '').trim()
    if (!raw) return

    const pairing = this.getApprovedPairing(platform, chatId)
    const pairedUser = pairing?.user_id
      ? db.get("SELECT id, username, email, role FROM users WHERE id = ?", pairing.user_id)
      : null

    let cmd = raw
    if (cmd.startsWith('!')) cmd = `/${cmd.slice(1)}`

    const isSlash = cmd.startsWith('/')
    const cleanCmd = isSlash ? cmd.slice(1) : cmd
    const [rawName, ...args] = cleanCmd.split(/\s+/)
    const name = (rawName || '').toLowerCase()

    // ── NOT PAIRED FLOW ──────────────────────────────────────────────────────
    if (!pairing || !pairedUser) {
      let pending = db.get(
        "SELECT * FROM telegram_pairings WHERE platform = ? AND chat_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
        String(platform),
        String(chatId)
      )

      let code = pending?.pairing_code
      if (!code) {
        let h = 0
        const s = `${platform}:${chatId}:${Date.now()}`
        for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0
        code = String((h % 900000) + 100000)

        db.run(
          "DELETE FROM telegram_pairings WHERE platform = ? AND chat_id = ? AND status = 'pending'",
          String(platform),
          String(chatId)
        )
        db.run(
          "INSERT INTO telegram_pairings (id, platform, chat_id, sender_name, pairing_code, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
          `pair_${randomUUID()}`,
          String(platform),
          String(chatId),
          senderInfo.senderName || 'Channel User',
          code,
          new Date().toISOString()
        )
      }

      if (platform === 'discord') {
        const embed = {
          title: '🔒 SentinelAI Account Pairing',
          description: `Kod pengesahan 6-digit akaun anda:\n# \`${code}\``,
          color: 0x00f2fe,
          fields: [
            {
              name: 'Cara Sambungkan ke Akaun SentinelAI:',
              value:
                '1. Log masuk ke akaun anda di [sentinelai.studio](https://sentinelai.studio)\n' +
                '2. Buka menu **Settings** ➡️ **Telegram & Discord Pairing**\n' +
                `3. Masukkan kod \`${code}\` dan klik **Approve & Connect**.\n\n` +
                '_Selepas akaun disambungkan, anda boleh jalankan imbasan pentest, semak findings, dan bersembang dengan AI Security Copilot!_',
              inline: false,
            }
          ],
          footer: { text: 'SentinelAI Autonomous Security Engine' },
        }
        reply('', { embed })
      } else {
        const inlineKeyboard = [
          [{ text: '🌐 Buka Pairing Settings', url: 'https://sentinelai.studio/app/settings' }]
        ]
        reply(
          `🔒 *SentinelAI Account Pairing*\n\n` +
          `Kod sambungan akaun 6-digit anda:\n` +
          `👉 \`${code}\`\n\n` +
          `*Cara sambungkan ke akaun SentinelAI anda:*\n` +
          `1. Log masuk ke akaun anda di https://sentinelai.studio\n` +
          `2. Buka menu **Settings** ➡️ **Telegram & Discord Pairing**\n` +
          `3. Masukkan kod \`${code}\` dan klik **Approve & Connect**.\n\n` +
          `_Selepas akaun disambungkan, anda boleh jalankan imbasan pentest, semak findings, dan bersembang dengan AI Security Copilot!_`,
          { inlineKeyboard }
        )
      }
      return
    }

    // ── PAIRED USER COMMANDS ────────────────────────────────────────────────
    switch (name) {
      case 'start':
      case 'help':
      case 'menu':
      case 'yo':
      case 'hai':
      case 'hello':
      case 'hi': {
        if (platform === 'discord') {
          const embed = {
            title: '🛡️ SentinelAI Security Operations Core',
            description: `Selamat datang, **${pairedUser.username || pairedUser.email}** (\`${pairedUser.role?.toUpperCase() || 'CLIENT'}\`).\nBot ini disambungkan ke enjin pentest autonomi SentinelAI pada Kali Linux.`,
            color: 0x00f2fe,
            fields: [
              {
                name: '⚡ Arahan Tersedia (Commands)',
                value: [
                  '`/status` — Status masa nyata sistem & enjin pentest',
                  '`/scans` — Senarai imbasan terkini akaun anda',
                  '`/findings` — Senarai penemuan kerentanan (CVE/CWE)',
                  '`/quickscan <url>` — Imbasan pantas sasaran baharu',
                  '`/quota` — Semak baki kredit & pelan langganan',
                  '`/tools` — Status toolchain keselamatan Kali Linux',
                  '`/cve <id>` — Carian exploit registry & CVE',
                  '`/stop <scan_id>` — Hentikan imbasan aktif',
                  '`/ask <soalan>` — Rujuk AI Security Copilot',
                ].join('\n'),
                inline: false,
              },
              {
                name: '🤖 Conversational AI Security Copilot',
                value: 'Anda boleh taip apa sahaja soalan pentesting, analisis kod, atau teknik eksploit secara bebas di dalam chat. Multi-LLM Copilot akan menjawab secara langsung!',
                inline: false,
              },
              {
                name: '🌐 Web Dashboard',
                value: '[sentinelai.studio](https://sentinelai.studio)',
                inline: true,
              },
              {
                name: '⚙️ Enjin',
                value: 'Kali Native 2026.1',
                inline: true,
              },
            ],
            footer: { text: 'SentinelAI Autonomous Security Engine' },
            timestamp: new Date().toISOString(),
          }
          reply('', { embed })
        } else {
          const text =
            `🛡️ *SentinelAI Autonomous Security Operations*\n\n` +
            `👤 Pengguna: *${pairedUser.username || pairedUser.email}* (\`${pairedUser.role?.toUpperCase() || 'CLIENT'}\`)\n` +
            `⚙️ Enjin: *Native Kali Toolchain (ONLINE)*\n` +
            `🤖 AI Specialist: *DeepSeek V4 Pro / Groq (ONLINE)*\n\n` +
            `💡 *Pilih arahan di bawah atau taip terus soalan anda untuk berbual dengan AI Pentest Copilot:*\n\n` +
            `• \`/status\` — Status masa nyata sistem & imbasan\n` +
            `• \`/scans\` — Senarai imbasan terkini & skor risiko\n` +
            `• \`/findings\` — Senarai penemuan kerentanan (CVE/CWE)\n` +
            `• \`/quickscan <url>\` — Lancarkan imbasan pantas sasaran\n` +
            `• \`/quota\` — Semak baki kuota imbasan & pelan\n` +
            `• \`/tools\` — Semakan status 14 tool Kali Linux\n` +
            `• \`/cve <id>\` — Carian pangkalan data CVE & eksploit\n` +
            `• \`/ask <soalan>\` — Rujuk pakar AI Pentest Copilot\n` +
            `• \`/unlink\` — Putuskan sambungan bot ini`

          const inlineKeyboard = [
            [
              { text: '🛡️ Status Sistem', callback_data: 'cmd:/status' },
              { text: '📊 Imbasan Saya', callback_data: 'cmd:/scans' },
            ],
            [
              { text: '⚠️ Penemuan (Findings)', callback_data: 'cmd:/findings' },
              { text: '💳 Pelan & Kuota', callback_data: 'cmd:/quota' },
            ],
            [
              { text: '🛠️ Toolchain Kali', callback_data: 'cmd:/tools' },
              { text: '👥 50 AI Personas', callback_data: 'cmd:/agents' },
            ],
            [
              { text: '🌐 Buka Web Portal', url: 'https://sentinelai.studio' },
            ],
          ]
          reply(text, { inlineKeyboard })
        }
        break
      }

      case 'status': {
        const scans = pairedUser.role === 'admin'
          ? db.all(`SELECT status, COUNT(*) c FROM scans GROUP BY status`)
          : db.all(`SELECT status, COUNT(*) c FROM scans WHERE user_id = ? OR client = ? GROUP BY status`, pairedUser.id, pairedUser.username)
        const running = scans.find(s => s.status === 'running')?.c || 0
        const completed = scans.find(s => s.status === 'completed')?.c || 0
        const total = scans.reduce((a, s) => a + s.c, 0)

        const fRows = pairedUser.role === 'admin'
          ? db.all(`SELECT severity, COUNT(*) c FROM findings GROUP BY severity`)
          : db.all(`SELECT f.severity, COUNT(*) c FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = ? OR s.client = ? GROUP BY f.severity`, pairedUser.id, pairedUser.username)
        const critical = fRows.find(r => r.severity === 'critical')?.c || 0
        const high = fRows.find(r => r.severity === 'high')?.c || 0
        const medium = fRows.find(r => r.severity === 'medium')?.c || 0
        const low = (fRows.find(r => r.severity === 'low')?.c || 0) + (fRows.find(r => r.severity === 'info')?.c || 0)

        const sub = db.get("SELECT * FROM subscriptions WHERE user_id = ?", pairedUser.id)
        const quotaUsed = sub?.scan_quota_used ?? 0
        const quotaTotal = sub?.scan_quota_total ?? 3
        const planName = sub?.plan_name || 'Free Trial'

        let onlineTools = 0, totalTools = 0
        try {
          const ts = await nativeToolsStatus()
          const vals = Object.values(ts)
          totalTools = vals.length
          onlineTools = vals.filter(Boolean).length
        } catch {}

        if (platform === 'discord') {
          const embed = {
            title: `🛡️ SentinelAI Core Status — ${pairedUser.username || pairedUser.email}`,
            color: critical > 0 ? 0xf43f5e : (running > 0 ? 0x00f2fe : 0x10b981),
            fields: [
              { name: '📊 Imbasan Pentest', value: `Sedang Berjalan: **${running}**\nJumlah: **${total}**\nSelesai: **${completed}**`, inline: true },
              { name: '⚠️ Kerentanan', value: `🔴 Critical: **${critical}**\n🟠 High: **${high}**\n🟡 Medium: **${medium}**`, inline: true },
              { name: '💳 Pelan & Kuota', value: `Pelan: **${planName}**\nDigunakan: **${quotaUsed} / ${quotaTotal}**`, inline: true },
              { name: '🛠️ Kali Toolchain', value: `🟢 **${onlineTools}/${totalTools || 14} Online**`, inline: true },
              { name: '🤖 AI Specialist', value: `⚡ **DeepSeek V4 Pro**\n👥 **50 Personas Active**`, inline: true },
              { name: '🌐 Web Portal', value: `[Buka Dashboard](https://sentinelai.studio/app/dashboard)`, inline: true },
            ],
            footer: { text: 'SentinelAI Autonomous Security Operations' },
            timestamp: new Date().toISOString(),
          }
          reply('', { embed })
        } else {
          const text =
            `🛡️ *SentinelAI Core Status (${pairedUser.username || 'Client'})*\n\n` +
            `• *Imbasan:* ${running > 0 ? `🟡 *${running} Aktif*` : '⚪ 0 Aktif'} | 📁 *${total} Jumlah* (${completed} Selesai)\n` +
            `• *Penemuan Kerentanan:*\n` +
            `  🔴 Critical: *${critical}* | 🟠 High: *${high}*\n` +
            `  🟡 Medium: *${medium}* | 🔵 Low/Info: *${low}*\n` +
            `• *Pelan & Kuota:* *${planName}* (${quotaUsed}/${quotaTotal} digunakan)\n` +
            `• *Kali Toolchain:* 🟢 *${onlineTools}/${totalTools || 14} Tools Online*\n` +
            `• *AI Copilot:* ⚡ *DeepSeek V4 Pro / Groq (ONLINE)*\n` +
            `• *Specialist Agents:* 👥 *50 Personas Active*\n\n` +
            `🌐 Portal: https://sentinelai.studio`

          const inlineKeyboard = [
            [
              { text: '📊 Imbasan Terkini', callback_data: 'cmd:/scans' },
              { text: '⚠️ Lihat Findings', callback_data: 'cmd:/findings' },
            ],
            [
              { text: '🛠️ Semak Tools', callback_data: 'cmd:/tools' },
              { text: '💳 Semak Kuota', callback_data: 'cmd:/quota' },
            ],
          ]
          reply(text, { inlineKeyboard })
        }
        break
      }

      case 'scans': {
        const scans = pairedUser.role === 'admin'
          ? db.all(`SELECT id, target, status, risk_score, created_at FROM scans ORDER BY created_at DESC LIMIT 6`)
          : db.all(`SELECT id, target, status, risk_score, created_at FROM scans WHERE user_id = ? OR client = ? ORDER BY created_at DESC LIMIT 6`, pairedUser.id, pairedUser.username)

        if (!scans || !scans.length) {
          const msg = 'Tiada imbasan ditemui untuk akaun anda. Taip `/quickscan https://example.com` untuk memulakan imbasan.'
          if (platform === 'telegram') {
            reply(msg, {
              inlineKeyboard: [[{ text: '⚡ Imbasan Pantas', callback_data: 'cmd:/quickscan' }]]
            })
          } else {
            reply(msg)
          }
          break
        }

        if (platform === 'discord') {
          const fields = scans.map((s, idx) => {
            const icon = s.status === 'running' ? '🟡' : (s.status === 'completed' ? '🟢' : '🔴')
            return {
              name: `${idx + 1}. ${icon} ${s.target || 'Sasaran'}`,
              value: `Status: \`${s.status}\` | Skor Risiko: **${(s.risk_score ?? 0).toFixed(1)}/10**\n[Lihat Laporan](https://sentinelai.studio/app/scans/${s.id})`,
              inline: false,
            }
          })

          const embed = {
            title: `📊 Imbasan Terkini Akaun — ${pairedUser.username || pairedUser.email}`,
            color: 0x00f2fe,
            fields,
            footer: { text: 'Klik pautan untuk melihat penemuan lengkap di web portal' },
            timestamp: new Date().toISOString(),
          }
          reply('', { embed })
        } else {
          const list = scans.map((s, idx) => {
            const icon = s.status === 'running' ? '🟡' : (s.status === 'completed' ? '🟢' : '🔴')
            return `${idx + 1}. ${icon} *${s.target || '?'}*\n   Status: \`${s.status}\` | Risk: *${(s.risk_score ?? 0).toFixed(1)} / 10*\n   🔗 https://sentinelai.studio/app/scans/${s.id}`
          }).join('\n\n')

          const inlineKeyboard = [
            [
              { text: '⚠️ Lihat Findings', callback_data: 'cmd:/findings' },
              { text: '⚡ Quick Scan Sasaran', callback_data: 'cmd:/quickscan' },
            ]
          ]
          reply(`📊 *Imbasan Terkini Akaun Anda:*\n\n${list}`, { inlineKeyboard })
        }
        break
      }

      case 'findings': {
        const scanIdArg = args[0]
        let findings = []
        if (scanIdArg) {
          findings = db.all(
            `SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT 6`,
            scanIdArg
          )
        } else {
          findings = pairedUser.role === 'admin'
            ? db.all(`SELECT f.*, s.target FROM findings f JOIN scans s ON f.scan_id = s.id ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC LIMIT 6`)
            : db.all(`SELECT f.*, s.target FROM findings f JOIN scans s ON f.scan_id = s.id WHERE s.user_id = ? OR s.client = ? ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC LIMIT 6`, pairedUser.id, pairedUser.username)
        }

        if (!findings || !findings.length) {
          reply('✅ *Tiada kerentanan aktif ditemui!* Sistem anda berada dalam keadaan selamat atau belum diimbas.')
          break
        }

        const sevIcon = (sev) => {
          switch ((sev || '').toLowerCase()) {
            case 'critical': return '🔴'
            case 'high': return '🟠'
            case 'medium': return '🟡'
            default: return '🔵'
          }
        }

        if (platform === 'discord') {
          const fields = findings.map((f, idx) => ({
            name: `${idx + 1}. ${sevIcon(f.severity)} [${(f.severity || 'INFO').toUpperCase()}] ${f.title}`,
            value: `**Sasaran:** \`${f.target || 'N/A'}\`${f.cve_id ? ` | **CVE:** \`${f.cve_id}\`` : ''}\n${f.layman_impact || f.description || 'Tiada huraian lanjut.'}`.slice(0, 1024),
            inline: false,
          }))

          const hasCritical = findings.some(f => f.severity === 'critical')
          const embed = {
            title: `⚠️ Penemuan Kerentanan Terkini (${findings.length})`,
            color: hasCritical ? 0xf43f5e : 0xf59e0b,
            fields,
            footer: { text: 'Rujuk portal untuk langkah remediate terperinci' },
            timestamp: new Date().toISOString(),
          }
          reply('', { embed })
        } else {
          const list = findings.map((f, idx) => {
            const cveStr = f.cve_id ? ` (${f.cve_id})` : (f.cwe_id ? ` (${f.cwe_id})` : '')
            return `${idx + 1}. ${sevIcon(f.severity)} *[${(f.severity || 'INFO').toUpperCase()}]* ${f.title}${cveStr}\n   🎯 Sasaran: \`${f.target || 'N/A'}\`\n   📝 Remediate: _${(f.remediation || f.layman_impact || 'Sila kemas kini perisian ke versi terkini').slice(0, 120)}..._`
          }).join('\n\n')

          const inlineKeyboard = [
            [
              { text: '🌐 Buka Analisis di Portal', url: 'https://sentinelai.studio/app/findings' }
            ]
          ]
          reply(`⚠️ *Penemuan Kerentanan Terkini:*\n\n${list}`, { inlineKeyboard })
        }
        break
      }

      case 'quota':
      case 'plan': {
        const sub = db.get("SELECT * FROM subscriptions WHERE user_id = ?", pairedUser.id)
        const used = sub?.scan_quota_used ?? 0
        const total = sub?.scan_quota_total ?? 3
        const remaining = Math.max(0, total - used)
        const pct = Math.min(100, Math.round((used / total) * 100))
        const filled = Math.min(10, Math.round(pct / 10))
        const bar = '█'.repeat(filled) + '░'.repeat(10 - filled)
        const planName = sub?.plan_name || 'Free Trial'
        const expDate = sub?.current_period_end ? sub.current_period_end.slice(0, 10) : 'Sepanjang Hayat'

        if (platform === 'discord') {
          const embed = {
            title: '💳 Langganan & Kuota Imbasan SentinelAI',
            color: 0x8b5cf6,
            fields: [
              { name: '📦 Pelan Semasa', value: `**${planName}** (\`${sub?.status?.toUpperCase() || 'ACTIVE'}\`)`, inline: true },
              { name: '🎯 Baki Imbasan', value: `**${remaining} / ${total}** imbasan`, inline: true },
              { name: '⏳ Sah Sehingga', value: `**${expDate}**`, inline: true },
              { name: '📊 Penggunaan Kuota', value: `\`[${bar}] ${pct}%\` (${used} digunakan)`, inline: false },
              { name: '🚀 Naik Taraf', value: '[Buka Halaman Langganan](https://sentinelai.studio/app/billing)', inline: false },
            ],
            footer: { text: 'SentinelAI Subscription Management' },
          }
          reply('', { embed })
        } else {
          const text =
            `💳 *Pelan & Kuota Imbasan SentinelAI*\n\n` +
            `• *Pelan Semasa:* *${planName}* (\`${sub?.status?.toUpperCase() || 'ACTIVE'}\`)\n` +
            `• *Baki Kuota:* *${remaining} / ${total} imbasan*\n` +
            `• *Penggunaan:* \`[${bar}] ${pct}%\` (${used} telah digunakan)\n` +
            `• *Tamat Tempoh:* *${expDate}*\n\n` +
            `_Perlukan lebih banyak imbasan tanpa had? Naik taraf pelan akaun anda di portal billing._`

          const inlineKeyboard = [
            [
              { text: '💳 Naik Taraf Pelan', url: 'https://sentinelai.studio/app/billing' },
              { text: '⚡ Imbasan Pantas', callback_data: 'cmd:/quickscan' },
            ]
          ]
          reply(text, { inlineKeyboard })
        }
        break
      }

      case 'tools': {
        let ts = {}
        try { ts = await nativeToolsStatus() } catch {}
        const toolList = [
          { name: 'nmap', desc: 'Port scanner & service fingerprinter' },
          { name: 'nuclei', desc: 'Template-based vulnerability scanner' },
          { name: 'nikto', desc: 'Web server security assessment' },
          { name: 'httpx', desc: 'Multi-purpose HTTP probing engine' },
          { name: 'whatweb', desc: 'Web technology stack fingerprinting' },
          { name: 'subfinder', desc: 'Fast passive subdomain enumeration' },
          { name: 'amass', desc: 'In-depth OSINT attack surface mapping' },
          { name: 'gobuster', desc: 'URI & DNS directory brute-forcer' },
          { name: 'sqlmap', desc: 'Automatic SQL injection exploitation' },
          { name: 'feroxbuster', desc: 'Recursive directory brute-force' },
          { name: 'searchsploit', desc: 'Local Exploit-DB vulnerability search' },
          { name: 'sslscan', desc: 'TLS/SSL cipher suite & cert audit' },
          { name: 'masscan', desc: 'High-speed TCP port scanner' },
        ]

        if (platform === 'discord') {
          const fields = toolList.map(t => {
            const online = Boolean(ts[t.name])
            return {
              name: `${online ? '🟢' : '⚪'} ${t.name}`,
              value: `${t.desc} (${online ? 'ONLINE' : 'NOT INSTALLED'})`,
              inline: true,
            }
          })
          const embed = {
            title: '🛠️ Kali Linux Security Toolchain Health',
            color: 0x00f2fe,
            fields,
            footer: { text: 'Enjin imbasan dijalankan secara natif pada Kali Linux' },
            timestamp: new Date().toISOString(),
          }
          reply('', { embed })
        } else {
          const list = toolList.map(t => {
            const online = Boolean(ts[t.name])
            return `${online ? '🟢' : '⚪'} \`${t.name}\` — ${t.desc} (${online ? '*ONLINE*' : '_OFFLINE_'})`
          }).join('\n')

          reply(`🛠️ *Status Toolchain Kali Linux:*\n\n${list}\n\n_Semua imbasan menggunakan subprocess natif secara terus pada kernel Kali._`)
        }
        break
      }

      case 'cve': {
        const query = args.join(' ').trim()
        if (!query) {
          reply('⚠️ Sila berikan kata kunci atau CVE ID sasaran.\nContoh: `/cve log4j` atau `/cve CVE-2021-44228` atau `/cve sqlmap`')
          break
        }

        const matched = matchExploits({ title: query, description: query, cveId: query, cweId: query })
        let dbCves = []
        try {
          const rows = db.all(
            `SELECT id, data FROM cve_cache WHERE id LIKE ? OR data LIKE ? LIMIT 3`,
            `%${query}%`, `%${query}%`
          )
          dbCves = rows.map(r => {
            let parsed = {}
            try { parsed = JSON.parse(r.data || '{}') } catch {}
            return {
              id: r.id,
              description: parsed.description || parsed.summary || 'Recorded CVE vulnerability entry',
              cvss: parsed.cvss || parsed.score || null,
            }
          })
        } catch {}

        if (!matched.length && !dbCves.length) {
          reply(`🔍 Tiada modul eksploit atau cache CVE ditemui untuk: \`${query}\`.\nCuba guna \`/ask ${query}\` untuk bertanya kepada AI Security Copilot.`)
          break
        }

        if (platform === 'discord') {
          const fields = []
          for (const m of matched.slice(0, 3)) {
            fields.push({
              name: `🎯 Modul Eksploit: ${m.id}`,
              value: `Tahap Risiko: **${(m.risk || 'medium').toUpperCase()}**\nTeknik: ${m.techniques?.map(t => `\`${t.step}\` (${t.tool})`).join(', ') || 'Standard'}\nPost-Exploit: ${m.postExploit?.join(', ') || 'None'}`,
              inline: false,
            })
          }
          for (const c of dbCves) {
            fields.push({
              name: `📋 ${c.id} (CVSS: ${c.cvss || 'N/A'})`,
              value: (c.description || 'Tiada penerangan ringkas.').slice(0, 250),
              inline: false,
            })
          }

          const embed = {
            title: `🔍 Hasil Carian CVE & Modul Eksploit: "${query}"`,
            color: 0x00f2fe,
            fields,
            footer: { text: 'Autonomous Exploitation Engine (AEE) Registry' },
          }
          reply('', { embed })
        } else {
          let text = `🔍 *Hasil Carian CVE & Eksploit:* \`${query}\`\n\n`
          if (matched.length) {
            text += `*Modul Eksploit Berdaftar:*\n`
            for (const m of matched.slice(0, 3)) {
              text += `• *${m.id}* (Risiko: \`${(m.risk || 'medium').toUpperCase()}\`)\n  Tool: ${m.techniques?.map(t => `\`${t.tool}\``).join(', ') || 'N/A'}\n`
            }
            text += '\n'
          }
          if (dbCves.length) {
            text += `*Padanan CVE:*\n`
            for (const c of dbCves) {
              text += `• *${c.id}* (CVSS: ${c.cvss || 'N/A'})\n  _${(c.description || '').slice(0, 100)}..._\n`
            }
          }
          reply(text)
        }
        break
      }

      case 'quickscan':
      case 'scan': {
        const target = args[0]
        if (!target) {
          reply('⚠️ Sila masukkan URL atau IP sasaran.\nContoh: `/quickscan https://example.com` atau `/scan 192.168.1.1`')
          break
        }

        // Check user scan quota
        const sub = db.get("SELECT * FROM subscriptions WHERE user_id = ?", pairedUser.id)
        if (sub && sub.scan_quota_used >= sub.scan_quota_total) {
          const quotaMsg =
            `⚠️ *Kuota Imbasan Telah Habis!*\n\n` +
            `Akaun anda telah menggunakan *${sub.scan_quota_used}/${sub.scan_quota_total}* imbasan yang diperuntukkan.\n` +
            `Sila naik taraf pelan langganan anda di https://sentinelai.studio/app/billing untuk mendapatkan imbasan seterusnya.`
          if (platform === 'telegram') {
            reply(quotaMsg, {
              inlineKeyboard: [[{ text: '💳 Naik Taraf Pelan', url: 'https://sentinelai.studio/app/billing' }]]
            })
          } else {
            reply(quotaMsg)
          }
          break
        }

        try {
          // Deduct quota
          db.run("UPDATE subscriptions SET scan_quota_used = scan_quota_used + 1, updated_at = ? WHERE user_id = ?", new Date().toISOString(), pairedUser.id)

          const scanId = `scan_${randomUUID()}`
          const now = new Date().toISOString()
          db.run(
            `INSERT INTO scans (id, user_id, target, target_type, mode, status, template, modules, progress, created_at, started_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
            scanId, pairedUser.id, target.trim(), 'url', 'blackbox', 'running', 'standard',
            JSON.stringify(['nmap', 'httpx', 'whatweb', 'nuclei', 'nikto']), 0, now, now
          )

          const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
          if (this.pipeline?.runBlackbox) {
            setImmediate(async () => {
              try {
                await this.pipeline.runBlackbox(scan, {
                  modules: ['nmap', 'httpx', 'whatweb', 'nuclei', 'nikto'],
                  objective: 'standard',
                  maxTools: 6,
                  verify: true,
                  depth: 'standard'
                })
              } catch (e) {
                console.error(`[Scan] Error running background scan ${scanId}:`, e)
              }
            })
          }

          const portalUrl = `https://sentinelai.studio/app/scans/${scanId}`
          if (platform === 'discord') {
            const embed = {
              title: '🚀 Imbasan Keselamatan Dilancarkan!',
              color: 0x00f2fe,
              fields: [
                { name: '🎯 Sasaran', value: `\`${target}\``, inline: true },
                { name: '🆔 Scan ID', value: `\`${scanId.slice(0, 12)}\``, inline: true },
                { name: '⚙️ Toolchain', value: '`nmap`, `httpx`, `whatweb`, `nuclei`, `nikto`', inline: false },
                { name: '💳 Baki Kuota', value: `**${Math.max(0, (sub?.scan_quota_total || 3) - (sub?.scan_quota_used || 0) - 1)} imbasan**`, inline: true },
                { name: '📡 Pemantauan Langsung', value: `[Buka Analisis Masa Nyata](${portalUrl})`, inline: false },
              ],
              footer: { text: 'Anda akan menerima notifikasi sebaik sahaja imbasan selesai!' },
              timestamp: new Date().toISOString(),
            }
            reply('', { embed })
          } else {
            const text =
              `🚀 *Imbasan Keselamatan Dilancarkan!*\n\n` +
              `• *Sasaran:* \`${target}\`\n` +
              `• *Scan ID:* \`${scanId.slice(0, 12)}\`\n` +
              `• *Toolchain:* \`nmap\`, \`httpx\`, \`whatweb\`, \`nuclei\`, \`nikto\`\n` +
              `• *Baki Kuota:* *${Math.max(0, (sub?.scan_quota_total || 3) - (sub?.scan_quota_used || 0) - 1)} imbasan*\n\n` +
              `🔗 Pantau secara langsung di:\n${portalUrl}\n\n` +
              `_💡 Bot akan menghantar ringkasan penemuan sebaik sahaja imbasan ini selesai._`

            const inlineKeyboard = [
              [
                { text: '🌐 Pantau Imbasan Masa Nyata', url: portalUrl }
              ]
            ]
            reply(text, { inlineKeyboard })
          }
        } catch (e) {
          reply(`❌ Gagal melancarkan imbasan: ${e.message}`)
        }
        break
      }

      case 'stop': {
        const scanIdArg = args[0]
        if (!scanIdArg) {
          reply('⚠️ Sila nyatakan Scan ID yang ingin dihentikan.\nContoh: `/stop scan_abc123`')
          break
        }
        const scan = db.get(
          "SELECT * FROM scans WHERE (id = ? OR id LIKE ?) AND (user_id = ? OR client = ?)",
          scanIdArg, `${scanIdArg}%`, pairedUser.id, pairedUser.username
        )
        if (!scan) {
          reply(`❌ Imbasan dengan ID \`${scanIdArg}\` tidak dijumpai atau bukan milik anda.`)
          break
        }
        if (scan.status !== 'running') {
          reply(`ℹ️ Imbasan tersebut sudah berstatus: \`${scan.status}\`.`)
          break
        }

        try {
          this.pipeline?.stopScan?.(scan.id)
          db.run("UPDATE scans SET status = 'stopped', finished_at = ? WHERE id = ?", new Date().toISOString(), scan.id)
          reply(`⏹️ *Imbasan ${scan.id.slice(0, 12)} telah dihentikan.*`)
        } catch (e) {
          reply(`❌ Gagal menghentikan imbasan: ${e.message}`)
        }
        break
      }

      case 'agents': {
        const agents = (this.agentRegistry?.list?.() || []).slice(0, 50)
        if (!agents.length) { reply('Tiada persona agent dimuatkan.'); break }
        reply(`🤖 *50 Specialist AI Personas Active:*\n\n` + agents.map(a => `• \`${a.name || a.id}\``).join('\n'))
        break
      }

      case 'unlink': {
        db.run("DELETE FROM telegram_pairings WHERE platform = ? AND chat_id = ?", String(platform), String(chatId))
        reply(`🔓 *Sambungan Diputuskan.*\n\nAkaun anda telah dinyahpaut daripada SentinelAI. Taip /start pada bila-bila masa untuk menyambung semula.`)
        break
      }

      case 'ask': {
        const query = args.join(' ').trim()
        if (!query) {
          reply('⚠️ Sila sertakan soalan keselamatan anda. Contoh:\n`/ask Bagaimanakah cara untuk menyekat SQL injection dalam Express.js?`')
          break
        }
        await this.handleAICopilot(platform, pairedUser, query, reply, chatId)
        break
      }

      // ── CONVERSATIONAL AI COPILOT FALLBACK ─────────────────────────────────
      // If user sends any free-form message, don't say "Arahan tidak dikenali" —
      // answer intelligently with SentinelAI Security Copilot!
      default: {
        const query = raw.startsWith('/') ? raw.slice(1).trim() : raw.trim()
        if (query.length > 2) {
          await this.handleAICopilot(platform, pairedUser, query, reply, chatId)
        } else {
          reply(`Taip /help untuk senarai arahan atau tanya terus apa-apa soalan keselamatan.`)
        }
        break
      }
    }
  }

  async start() {
    if (this.started) return
    this.started = true

    if (config.channels?.telegram?.token) {
      try {
        await telegramBot.start(this)
        this.channels.push(telegramBot)
        console.log(`[Channels] Telegram bot @${telegramBot.me?.username || 'unknown'} started`)
      } catch (e) {
        console.warn(`[Channels] Telegram failed to start: ${e.message}`)
      }
    }

    if (config.channels?.discord?.token) {
      try {
        await discordBot.start(this)
        this.channels.push(discordBot)
        console.log(`[Channels] Discord bot @${discordBot.clientUsername || 'Sentinel AI'} started`)
      } catch (e) {
        console.warn(`[Channels] Discord failed to start: ${e.message}`)
      }
    }
  }

  stop() {
    for (const ch of this.channels) {
      try { ch.stop?.() } catch { }
    }
    this.channels = []
    this.started = false
  }
}

export const channelGateway = new ChannelGateway()
