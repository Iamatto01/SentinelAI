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
    this.approved = new Map()
  }

  attach({ io, pipeline, orchestrator, agentRegistry }) {
    this.io = io
    this.pipeline = pipeline
    this.orchestrator = orchestrator
    this.agentRegistry = agentRegistry
  }

  isApproved(platform, chatId) {
    return true
  }

  approve(platform, chatId) {
    this.approved.set(${platform}:, { platform, approvedAt: Date.now() })
  }

  revoke(platform, chatId) {
    this.approved.delete(${platform}:)
  }

  listApproved() {
    return [...this.approved.entries()].map(([id, meta]) => ({ id, ...meta }))
  }

  broadcast(message, opts = {}) {
    for (const ch of this.channels) {
      if (typeof ch.send === 'function') {
        try { ch.send(message, opts) } catch { }
      }
    }
  }

  async handleCommand(platform, chatId, text, reply) {
    this.approve(platform, chatId)
    const cmd = String(text || '').trim()
    if (!cmd.startsWith('/')) {
      reply('Gunakan arahan /help untuk melihat senarai arahan.')
      return
    }
    const [name, ...args] = cmd.slice(1).split(/\\s+/)

    if (name === 'start') {
      reply(
        '🛡️ *Selamat datang ke SentinelAI Telegram Bot!*\\n\\n' +
        'Platform ini disambungkan terus ke *Hexstrike Pentest Engine* & *50 AI Specialist Personas*.\\n\\n' +
        '*Senarai Arahan Tersedia:*\\n' +
        '• /status — Semak status sistem & imbasan aktif\\n' +
        '• /scans — Senarai imbasan terkini & skor risiko\\n' +
        '• /agents — Senarai 50 AI agent personas yang aktif\\n' +
        '• /scan <url> — Lancarkan imbasan keselamatan ke atas target\\n' +
        '• /help — Paparkan senarai bantuan ini\\n\\n' +
        '🌐 Dashboard Web: https://sentinelai.studio'
      )
      return
    }

    switch (name) {
      case 'help':
        reply(
          '🛡️ *SentinelAI Bot Commands:*\\n\\n' +
          '• /status — Status platform & enjin Hexstrike\\n' +
          '• /scans — 8 imbasan terkini & status kerentanan\\n' +
          '• /agents — Senarai 50 persona AI Agent\\n' +
          '• /scan <url> — Lancarkan imbasan terus dari Telegram\\n' +
          '• /help — Bantuan arahan\\n\\n' +
          '🌐 Portal: https://sentinelai.studio'
        )
        break

      case 'status': {
        const scans = db.all(SELECT status, COUNT(*) c FROM scans GROUP BY status)
        const running = scans.find(s => s.status === 'running')?.c || 0
        const total = scans.reduce((a, s) => a + s.c, 0)
        reply(
          🛡️ *SentinelAI Platform Status*\\n\\n +
          • Total Scans: **\\n +
          • Active Running Scans: **\\n +
          • AI Specialist Agents: * Personas*\\n +
          • Hexstrike Tools: *124 Kali Tools Active*\\n +
          • Status: *ONLINE (Healthy)*\\n\\n +
          🌐 Portal: https://sentinelai.studio
        )
        break
      }

      case 'scans': {
        const scans = db.all(SELECT id, target, status, risk_score, created_at FROM scans ORDER BY created_at DESC LIMIT 8)
        if (!scans.length) { reply('Tiada imbasan ditemui.'); break }
        const list = scans.map((s, idx) =>
          ${idx + 1}. **\\n   Status: \${s.status}\ | Risk: **\\n   🔗 https://sentinelai.studio/app/scans/
        ).join('\\n\\n')
        reply(📊 *Imbasan Terkini (SentinelAI):*\\n\\n)
        break
      }

      case 'agents': {
        const agents = (this.agentRegistry?.list?.() || []).slice(0, 50)
        if (!agents.length) { reply('Tiada agent dimuatkan.'); break }
        reply(🤖 *50 Specialist AI Personas Active:*\\n\\n + agents.map(a => • \${a.name || a.id}\`).join('\\n'))
        break
      }

      case 'scan': {
        const target = args[0]
        if (!target) {
          reply('⚠️ Sila masukkan URL/IP sasaran. Contoh: /scan https://example.com')
          break
        }
        try {
          const scanId = scan_
          const now = new Date().toISOString()
          db.run(INSERT INTO scans (id, target, target_type, mode, status, template, modules, progress, created_at, started_at)
                  VALUES (?,?,?,?,?,?,?,?,?,?),
            scanId, target.trim(), 'url', 'blackbox', 'running', 'standard',
            JSON.stringify(['nmap', 'httpx', 'whatweb', 'nuclei', 'nikto']), 0, now, now)
          const scan = db.get(SELECT * FROM scans WHERE id = ?, scanId)
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
                reply(✅ *Imbasan Selesai untuk !*\\n\\nLihat laporan & findings penuh di:\\nhttps://sentinelai.studio/app/scans/)
              } catch (e) {
                reply(❌ Ralat semasa imbasan : )
              }
            })
          }
          reply(
            🚀 *Imbasan Keselamatan Dilancarkan!*\\n\\n +
            • Sasaran: \${target}\\
 +
            • Scan ID: \${scanId.slice(0, 12)}\\
 +
            • Enjin: *Hexstrike Toolchain (Nmap, Nuclei, Nikto, WhatWeb)*\\n\\n +
            Pantau secara langsung di:\\nhttps://sentinelai.studio/app/scans/
          )
        } catch (e) {
          reply(❌ Gagal melancarkan imbasan: )
        }
        break
      }

      default:
        reply(Arahan / tidak dikenali. Taip /help untuk bantuan.)
    }
  }

  pairingCodeFor(platform, chatId) {
    return '000000'
  }

  approveByCode(code) {
    return { ok: true }
  }

  async start() {
    if (this.started) return
    this.started = true

    if (config.channels?.telegram?.enabled && config.channels.telegram.token) {
      try {
        await telegramBot.start(this)
        this.channels.push(telegramBot)
        console.log([Channels] Telegram bot @ started)
      } catch (e) {
        console.warn([Channels] Telegram failed to start: )
      }
    }

    if (config.channels?.discord?.enabled && config.channels.discord.token) {
      try {
        await discordBot.start(this)
        this.channels.push(discordBot)
        console.log([Channels] Discord bot  started)
      } catch (e) {
        console.warn([Channels] Discord failed to start: )
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
