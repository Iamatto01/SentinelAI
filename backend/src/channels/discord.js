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
    if (!token) return
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

      const channelId = d.channel_id
      const senderInfo = {
        senderName: d.author?.global_name || d.author?.username || 'Discord User',
        username: d.author?.username || ''
      }

      this.gateway.handleCommand('discord', channelId, cleanText, (reply) => this.sendTo(channelId, reply), senderInfo).catch(() => { })
    } else if (op === 7) {
      this.ws?.close()
    } else if (op === 9) {
      this.sessionId = null
      setTimeout(() => this.ws?.close(), 2000)
    }
  }

  startHeartbeat(interval) {
    this.stopHeartbeat()
    this.heartbeatTimer = setInterval(() => this.sendWs({ op: 1, d: this.lastSeq }), interval)
  }

  stopHeartbeat() { if (this.heartbeatTimer) clearInterval(this.heartbeatTimer) }

  sendWs(obj) { try { this.ws?.send(JSON.stringify(obj)) } catch { } }

  async sendTo(channelId, text) {
    for (const chunk of String(text).match(/[\s\S]{1,1900}(\s|$)/g) || [String(text)]) {
      await fetch(`${API_BASE}/channels/${channelId}/messages`, {
        method: 'POST',
        headers: { authorization: `Bot ${config.channels?.discord?.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ content: chunk }),
      }).catch(e => console.warn(`[Discord] send failed: ${e.message}`))
    }
  }

  send(text) {
    const targets = this.gateway.listApproved().filter(a => a.platform === 'discord').map(a => a.id.split(':')[1])
    return Promise.all(targets.map(id => this.sendTo(id, text)))
  }

  stop() {
    this.running = false
    this.stopHeartbeat()
    this.ws?.close()
  }
}

export const discordBot = new DiscordBot()
