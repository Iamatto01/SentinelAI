import { config } from '../config.js'

/**
 * Telegram bot — zero-dependency (raw Bot API via fetch, long-polling).
 * Supports rich Markdown, Inline Keyboards, Callback Queries, and Auto-complete commands.
 */

const API = (token, method) => `https://api.telegram.org/bot${token}/${method}`

class TelegramBot {
  constructor() {
    this.platform = 'telegram'
    this.gateway = null
    this.running = false
    this.offset = 0
    this.pending = []
    this.me = null
  }

  async start(gateway) {
    this.gateway = gateway
    const token = config.channels?.telegram?.token
    if (!token) return
    const res = await fetch(API(token, 'getMe'))
    const j = await res.json()
    if (!j.ok) throw new Error(`getMe failed: ${j.description || res.status}`)
    this.me = j.result
    this.running = true

    // Register autocomplete command menu with Telegram
    this.registerCommands().catch(() => {})

    this.loop()
  }

  async registerCommands() {
    const token = config.channels?.telegram?.token
    if (!token) return
    const commands = [
      { command: 'status', description: '🛡️ Enjin pentest & status sistem' },
      { command: 'scans', description: '📊 Senarai imbasan terkini akaun' },
      { command: 'findings', description: '⚠️ Penemuan kerentanan & CVE' },
      { command: 'quickscan', description: '⚡ Imbasan pantas sasaran (url)' },
      { command: 'ask', description: '🤖 Tanya AI Pentest Copilot' },
      { command: 'quota', description: '💳 Semak baki kuota imbasan' },
      { command: 'cve', description: '🔍 Carian CVE & teknik eksploit' },
      { command: 'tools', description: '🛠️ Semakan toolchain Kali Linux' },
      { command: 'agents', description: '👥 50 AI Specialist Personas' },
      { command: 'help', description: '❓ Menu bantuan & arahan' },
    ]
    await fetch(API(token, 'setMyCommands'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ commands }),
    }).catch(() => {})
  }

  sendChatAction(chatId, action = 'typing') {
    const token = config.channels?.telegram?.token
    if (!token) return Promise.resolve()
    return fetch(API(token, 'sendChatAction'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, action }),
    }).catch(() => {})
  }

  async loop() {
    const token = config.channels?.telegram?.token
    while (this.running) {
      try {
        const res = await fetch(`${API(token, 'getUpdates')}?timeout=25&offset=${this.offset + 1}`)
        const j = await res.json()
        if (!j.ok) { await sleep(3000); continue }
        for (const u of j.result || []) {
          this.offset = Math.max(this.offset, u.update_id)
          this.onUpdate(u).catch(() => { })
        }
      } catch {
        await sleep(5000)
      }
    }
  }

  onUpdate(u) {
    // 1. Handle interactive inline button clicks (Callback Queries)
    if (u.callback_query) {
      const cq = u.callback_query
      const token = config.channels?.telegram?.token
      if (token && cq.id) {
        fetch(API(token, 'answerCallbackQuery'), {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ callback_query_id: cq.id }),
        }).catch(() => {})
      }
      const chatId = cq.message?.chat?.id
      const data = String(cq.data || '').trim()
      if (!chatId || !data) return Promise.resolve()
      const senderInfo = {
        senderName: [cq.from?.first_name, cq.from?.last_name].filter(Boolean).join(' ') || cq.from?.username || 'Telegram User',
        username: cq.from?.username || ''
      }
      const cmdText = data.startsWith('cmd:') ? data.slice(4) : data
      return this.gateway.handleCommand('telegram', chatId, cmdText, (reply, opts) => this.sendTo(chatId, reply, opts), senderInfo)
    }

    // 2. Handle normal user chat messages
    const msg = u.message || u.edited_message
    if (!msg?.text) return Promise.resolve()
    const chatId = msg.chat.id
    const senderInfo = {
      senderName: [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(' ') || msg.from?.username || 'Telegram User',
      username: msg.from?.username || ''
    }
    return this.gateway.handleCommand('telegram', chatId, msg.text, (reply, opts) => this.sendTo(chatId, reply, opts), senderInfo)
  }

  async sendTo(chatId, text, opts = {}) {
    const token = config.channels?.telegram?.token
    if (!token) return Promise.resolve()
    const str = String(text || '')
    const chunks = str.length > 3900 ? str.match(/[\s\S]{1,3900}(\s|$)/g) || [str] : [str]

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]
      const body = {
        chat_id: chatId,
        text: chunk,
        parse_mode: opts.parseMode ?? 'Markdown',
      }
      // Attach interactive buttons only to the final chunk
      if (i === chunks.length - 1) {
        if (opts.inlineKeyboard) {
          body.reply_markup = { inline_keyboard: opts.inlineKeyboard }
        } else if (opts.replyMarkup) {
          body.reply_markup = opts.replyMarkup
        }
      }

      try {
        const res = await fetch(API(token, 'sendMessage'), {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        })
        const j = await res.json()
        // If Markdown parsing fails due to unescaped characters in AI responses, retry as plain text
        if (!j.ok && (j.description?.includes('can\'t parse entities') || j.error_code === 400)) {
          delete body.parse_mode
          await fetch(API(token, 'sendMessage'), {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          })
        }
      } catch (e) {
        console.warn(`[Telegram] send failed: ${e.message}`)
      }
    }
  }

  send(text, opts = {}) {
    const targets = this.gateway.listApproved().filter(a => a.platform === 'telegram').map(a => a.id.split(':')[1])
    return Promise.all(targets.map(id => this.sendTo(id, text, opts)))
  }

  stop() { this.running = false }
}

const sleep = ms => new Promise(r => setTimeout(r, ms))

export const telegramBot = new TelegramBot()
