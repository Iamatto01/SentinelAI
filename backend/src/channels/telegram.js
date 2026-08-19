import { config } from '../config.js'

/**
 * Telegram bot — zero-dependency (raw Bot API via fetch, long-polling).
 * No webhook/public URL needed, works behind NAT — good for local dev.
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
    this.loop()
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
    const msg = u.message || u.edited_message
    if (!msg?.text) return Promise.resolve()
    const chatId = msg.chat.id
    const senderInfo = {
      senderName: [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(' ') || msg.from?.username || 'Telegram User',
      username: msg.from?.username || ''
    }
    return this.gateway.handleCommand('telegram', chatId, msg.text, (reply) => this.sendTo(chatId, reply), senderInfo)
  }

  sendTo(chatId, text) {
    const token = config.channels?.telegram?.token
    if (!token) return Promise.resolve()
    return fetch(API(token, 'sendMessage'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
    }).catch(e => console.warn(`[Telegram] send failed: ${e.message}`))
  }

  send(text) {
    const targets = this.gateway.listApproved().filter(a => a.platform === 'telegram').map(a => a.id.split(':')[1])
    return Promise.all(targets.map(id => this.sendTo(id, text)))
  }

  stop() { this.running = false }
}

const sleep = ms => new Promise(r => setTimeout(r, ms))

export const telegramBot = new TelegramBot()
