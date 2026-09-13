import { config } from '../config.js'

/**
 * Discord bot — zero-dependency implementation using Discord's official
 * REST API + Gateway WebSocket (no discord.js needed).
 */

const API_BASE = 'https://discord.com/api/v10'

class DiscordBot {
  constructor() {
    this.platform = 'discord'
    this.gateway = null
    this.running = false
    this.ws = null
    this.applicationId = null
    this.clientUsername = null
    this.heartbeatTimer = null
    this.lastSeq = null
    this.sessionId = null
    this.resumeUrl = null
  }

  async start(gateway) {
    this.gateway = gateway
    const token = config.channels?.discord?.token
    if (!token) {
      console.warn('[Channels] Discord bot skipped: DISCORD_BOT_TOKEN not provided')
      return
    }
    const [meRes, gwRes] = await Promise.all([
      fetch(`${API_BASE}/users/@me`, { headers: { authorization: `Bot ${token}` } }),
      fetch(`${API_BASE}/gateway/bot`, { headers: { authorization: `Bot ${token}` } }),
    ])
    if (!meRes.ok) throw new Error(`Discord auth failed (${meRes.status}) — check DISCORD_BOT_TOKEN`)
    const me = await meRes.json()
    if (!gwRes.ok) throw new Error(`Discord gateway fetch failed (${gwRes.status})`)
    const gw = await gwRes.json()
    this.applicationId = me.id
    this.clientUsername = me.username
    this.running = true
    this.connectWs(gw.url)
  }

  connectWs(url) {
    this.ws = new WebSocket(url)
    this.ws.onmessage = (ev) => this.onGatewayMessage(JSON.parse(ev.data))
    this.ws.onclose = () => {
      this.stopHeartbeat()
      if (this.running) setTimeout(() => this.connectWs(this.resumeUrl || url), 3000)
    }
  }

  onGatewayMessage(msg) {
    const { op, t, d, s } = msg
    if (s) this.lastSeq = s

    if (op === 10) {
      const interval = d.heartbeat_interval
      this.startHeartbeat(interval)
      if (this.sessionId) {
        this.sendWs({ op: 6, d: { token: config.channels.discord.token, session_id: this.sessionId, seq: this.lastSeq } })
      } else {
        this.sendWs({
          op: 2,
          d: {
            token: config.channels.discord.token,
            intents: (1 << 9) | (1 << 15) | (1 << 0), // GUILDS | MESSAGE_CONTENT | GUILD_MESSAGES
            properties: { os: 'linux', browser: 'sentinelai', device: 'sentinelai' },
          },
        })
      }
    } else if (op === 0 && t === 'READY') {
      this.sessionId = d.session_id
      this.resumeUrl = d.resume_gateway_url
      console.log(`[Channels] Discord gateway ready as @${d.user.username} (ID: ${this.applicationId})`)
    } else if (op === 0 && t === 'MESSAGE_CREATE') {
      // 1. Ignore messages from ANY bot (including Sentinel MLBB, GitHub bot, or itself)
      if (d.author?.bot || d.author?.id === this.applicationId || !d.content) return

      const rawContent = String(d.content || '').trim()
      const botMention = `<@${this.applicationId}>`
      const botMentionNick = `<@!${this.applicationId}>`
      const isMentioned = rawContent.includes(botMention) || rawContent.includes(botMentionNick)
      const isDirectCommand = rawContent.startsWith('/') || rawContent.startsWith('!')

      // 2. In server/guild channels, ONLY respond if the message starts with / or explicitly mentions THIS bot.
      // If user is chatting normally or mentioning another bot (@Sentinel MLBB), ignore it completely!
      if (!isDirectCommand && !isMentioned && d.guild_id) {
        return
      }

      let cleanText = rawContent
      if (isMentioned) {
        cleanText = cleanText.replace(new RegExp(`<@!?${this.applicationId}>`, 'g'), '').trim()
      }
      if (!cleanText) cleanText = '/start'

      const channelId = d.channel_id
      const senderInfo = {
        senderName: d.author?.global_name || d.author?.username || 'Discord User',
        username: d.author?.username || ''
      }

      this.gateway.handleCommand('discord', channelId, cleanText, (reply, opts) => this.sendTo(channelId, reply, opts), senderInfo).catch(() => { })
    } else if (op === 7) {
      this.ws?.close()
    } else if (op === 9) {
      this.sessionId = null
      setTimeout(() => this.ws?.close(), 2000)
    }
  }

  sendTyping(channelId) {
    const token = config.channels?.discord?.token
    if (!token) return Promise.resolve()
    return fetch(`${API_BASE}/channels/${channelId}/typing`, {
      method: 'POST',
      headers: { authorization: `Bot ${token}` },
    }).catch(() => {})
  }

  startHeartbeat(interval) {
    this.stopHeartbeat()
    this.heartbeatTimer = setInterval(() => this.sendWs({ op: 1, d: this.lastSeq }), interval)
  }

  stopHeartbeat() { if (this.heartbeatTimer) clearInterval(this.heartbeatTimer) }

  sendWs(obj) {
    try {
      if (this.ws?.readyState === 1) {
        this.ws.send(JSON.stringify(obj))
      }
    } catch { }
  }

  async sendTo(channelId, textOrPayload, opts = {}) {
    const token = config.channels?.discord?.token
    if (!token) return

    const embeds = opts.embeds || (opts.embed ? [opts.embed] : null) || (textOrPayload && typeof textOrPayload === 'object' && textOrPayload.embeds ? textOrPayload.embeds : null)
    const rawContent = typeof textOrPayload === 'string' ? textOrPayload : (textOrPayload?.content || '')

    // 1. Rich Embed delivery (styled cybersecurity cards)
    if (embeds && embeds.length > 0) {
      const body = {
        content: rawContent || undefined,
        embeds,
      }
      if (opts.components) body.components = opts.components

      return fetch(`${API_BASE}/channels/${channelId}/messages`, {
        method: 'POST',
        headers: { authorization: `Bot ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }).catch(e => console.warn(`[Discord] send embed failed: ${e.message}`))
    }

    // 2. Standard message chunking for plain text
    for (const chunk of String(rawContent).match(/[\s\S]{1,1900}(\s|$)/g) || [String(rawContent)]) {
      await fetch(`${API_BASE}/channels/${channelId}/messages`, {
        method: 'POST',
        headers: { authorization: `Bot ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ content: chunk }),
      }).catch(e => console.warn(`[Discord] send failed: ${e.message}`))
    }
  }

  send(text, opts = {}) {
    const targets = this.gateway.listApproved().filter(a => a.platform === 'discord').map(a => a.id.split(':')[1])
    return Promise.all(targets.map(id => this.sendTo(id, text, opts)))
  }

  stop() {
    this.running = false
    this.stopHeartbeat()
    this.ws?.close()
  }
}

export const discordBot = new DiscordBot()
