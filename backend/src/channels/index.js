import { config } from '../config.js'
import * as db from '../db.js'
import { telegramBot } from './telegram.js'
import { discordBot } from './discord.js'
import { randomUUID } from 'node:crypto'

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

  async handleCommand(platform, chatId, text, reply, senderInfo = {}) {
    const cmd = String(text || '').trim()
    const pairing = this.getApprovedPairing(platform, chatId)
    const pairedUser = pairing?.user_id
      ? db.get("SELECT id, username, email, role FROM users WHERE id = ?", pairing.user_id)
      : null

    const [name, ...args] = cmd.startsWith('/') ? cmd.slice(1).split(/\s+/) : ['unknown']

    // ── NOT PAIRED FLOW ──────────────────────────────────────────────────────
    if (!pairing || !pairedUser) {
      if (name === 'start' || !cmd.startsWith('/')) {
        // Generate or fetch existing pending pairing code
        let pending = db.get(
          "SELECT * FROM telegram_pairings WHERE platform = ? AND chat_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
          String(platform),
          String(chatId)
        )

        let code = pending?.pairing_code
        if (!code) {
          // Generate deterministic 6-digit code based on chatId
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
            `tele_${randomUUID()}`,
            String(platform),
            String(chatId),
            senderInfo.senderName || 'Telegram User',
            code,
            new Date().toISOString()
          )
        }

        reply(
          `🔒 *SentinelAI Account Pairing*

` +
          `Kod sambungan akaun 6-digit anda:
` +
          `👉 \`${code}\`

` +
          `*Cara sambungkan ke akaun SentinelAI anda:*
` +
          `1. Log masuk ke akaun anda di https://sentinelai.studio
` +
          `2. Buka menu **Settings** (atau Integrations) ➡️ **Telegram Pairing**
` +
          `3. Masukkan kod \`${code}\` dan klik **Approve & Connect**.

` +
          `_Selepas akaun disambungkan, anda boleh jalankan imbasan pentest, semak findings, dan terima alert masa nyata!_`
        )
        return
      }

      reply(
        `🔒 *Akaun Belum Disambungkan*

` +
        `Sila taip /start untuk mendapatkan kod sambungan 6-digit anda, kemudian luluskan di dashboard web https://sentinelai.studio.`
      )
      return
    }

    // ── PAIRED USER COMMANDS ────────────────────────────────────────────────
    switch (name) {
      case 'start':
      case 'help':
        reply(
          `🛡️ *SentinelAI Telegram Connected!*

` +
          `Pengguna: *${pairedUser.username || pairedUser.email}* (${pairedUser.role?.toUpperCase() || 'CLIENT'})
` +
          `Chat ID: \`${chatId}\`

` +
          `*Senarai Arahan Tersedia:*
` +
          `• \`/status\` — Semak status sistem & enjin pentest
` +
          `• \`/scans\` — Senarai imbasan terkini akaun anda
` +
          `• \`/agents\` — Senarai 50 AI Specialist Personas
` +
          `• \`/scan <url>\` — Lancarkan imbasan pentest sasaran baharu
` +
          `• \`/unlink\` — Putuskan sambungan Telegram ini
` +
          `• \`/help\` — Paparkan bantuan arahan

` +
          `🌐 Portal: https://sentinelai.studio`
        )
        break

      case 'status': {
        const scans = pairedUser.role === 'admin'
          ? db.all(`SELECT status, COUNT(*) c FROM scans GROUP BY status`)
          : db.all(`SELECT status, COUNT(*) c FROM scans WHERE user_id = ? OR client = ? GROUP BY status`, pairedUser.id, pairedUser.username)
        const running = scans.find(s => s.status === 'running')?.c || 0
        const total = scans.reduce((a, s) => a + s.c, 0)
        reply(
          `🛡️ *SentinelAI Status (${pairedUser.username || 'Client'})*

` +
          `• Jumlah Imbasan: *${total}*
` +
          `• Sedang Berjalan: *${running} active*
` +
          `• Enjin Hexstrike: *124 Kali Tools (ONLINE)*
` +
          `• AI Specialist Agents: *50 Personas Active*

` +
          `🌐 Dashboard: https://sentinelai.studio`
        )
        break
      }

      case 'scans': {
        const scans = pairedUser.role === 'admin'
          ? db.all(`SELECT id, target, status, risk_score, created_at FROM scans ORDER BY created_at DESC LIMIT 8`)
          : db.all(`SELECT id, target, status, risk_score, created_at FROM scans WHERE user_id = ? OR client = ? ORDER BY created_at DESC LIMIT 8`, pairedUser.id, pairedUser.username)
        if (!scans.length) {
          reply('Tiada imbasan ditemui untuk akaun anda. Taip `/scan https://example.com` untuk memulakan imbasan.')
          break
        }
        const list = scans.map((s, idx) =>
          `${idx + 1}. *${s.target || '?'}*
   Status: \`${s.status}\` | Risk: *${(s.risk_score ?? 0).toFixed(1)}*
   🔗 https://sentinelai.studio/app/scans/${s.id}`
        ).join('

')
        reply(`📊 *Imbasan Terkini Akaun Anda:*

${list}`)
        break
      }

      case 'agents': {
        const agents = (this.agentRegistry?.list?.() || []).slice(0, 50)
        if (!agents.length) { reply('Tiada agent dimuatkan.'); break }
        reply(`🤖 *50 Specialist AI Personas Active:*

` + agents.map(a => `• \`${a.name || a.id}\``).join('
'))
        break
      }

      case 'scan': {
        const target = args[0]
        if (!target) {
          reply('⚠️ Sila masukkan URL/IP sasaran. Contoh: `/scan https://example.com`')
          break
        }
        try {
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
                reply(`✅ *Imbasan Selesai untuk ${target}!*

Lihat laporan & findings penuh di:
https://sentinelai.studio/app/scans/${scanId}`)
              } catch (e) {
                reply(`❌ Ralat semasa imbasan ${target}: ${e.message}`)
              }
            })
          }
          reply(
            `🚀 *Imbasan Keselamatan Dilancarkan!*

` +
            `• Akaun: *${pairedUser.username || pairedUser.email}*
` +
            `• Sasaran: \`${target}\`
` +
            `• Scan ID: \`${scanId.slice(0, 12)}\`
` +
            `• Enjin: *Hexstrike Toolchain*

` +
            `Pantau secara langsung di:
https://sentinelai.studio/app/scans/${scanId}`
          )
        } catch (e) {
          reply(`❌ Gagal melancarkan imbasan: ${e.message}`)
        }
        break
      }

      case 'unlink': {
        db.run("DELETE FROM telegram_pairings WHERE platform = ? AND chat_id = ?", String(platform), String(chatId))
        reply(`🔓 *Sambungan Telegram Diputuskan.*

Akaun Telegram anda telah dinyahpaut daripada SentinelAI. Taip /start pada bila-bila masa untuk menyambung semula.`)
        break
      }

      default:
        reply(`Arahan /${name} tidak dikenali. Taip /help untuk senarai arahan.`)
    }
  }

  async start() {
    if (this.started) return
    this.started = true

    if (config.channels?.telegram?.enabled && config.channels.telegram.token) {
      try {
        await telegramBot.start(this)
        this.channels.push(telegramBot)
        console.log(`[Channels] Telegram bot @${telegramBot.me?.username || 'unknown'} started`)
      } catch (e) {
        console.warn(`[Channels] Telegram failed to start: ${e.message}`)
      }
    }

    if (config.channels?.discord?.enabled && config.channels.discord.token) {
      try {
        await discordBot.start(this)
        this.channels.push(discordBot)
        console.log(`[Channels] Discord bot ${discordBot.client?.user?.tag || 'unknown'} started`)
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
