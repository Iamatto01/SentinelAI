import { config } from '../config.js'

/**
 * Discord bot — zero-dependency implementation using Discord's official
 * REST API + Gateway WebSocket (no discord.js needed).
 *
 * Setup (Discord Developer Portal):
 *   1. New Application → Bot → Reset Token → put in .env DISCORD_BOT_TOKEN
 *   2. Enable "Message Content Intent" under Bot → Privileged Gateway Intents
 *   3. OAuth2 → URL Generator: scopes=bot, permissions=Send Messages,
 *      Read Message History → open the URL to invite the bot to a server.
 */

const API_BASE = 'https://discord.com/api/v10'

class DiscordBot {
  constructor() {
    this.platform = 'discord'
    this.gateway = null
    this.running = false
    this.ws = null
    this.applicationId = null
    /** channelIds that sent /start and await approval */
    this.pending = []
    this.heartbeatTimer = null
    this.lastSeq = null
    this.sessionId = null
    this.resumeUrl = null
  }

  async start(gateway) {
    this.gateway = gateway
    const token = config.channels.discord.token
    // Fetch bot user + gateway URL in parallel.
    const [meRes, gwRes] = await Promise.all([
      fetch(`${API_BASE}/users/@me`, { headers: { authorization: `Bot ${token}` } }),
      fetch(`${API_BASE}/gateway/bot`, { headers: { authorization: `Bot ${token}` } }),
    ])
    if (!meRes.ok) throw new Error(`Discord auth failed (${meRes.status}) — check DISCORD_BOT_TOKEN`)
    const me = await meRes.json()
    if (!gwRes.ok) throw new Error(`Discord gateway fetch failed (${gwRes.status})`)
    const gw = await gwRes.json()
    this.applicationId = me.id
    this.running = true
    this.connectWs(gw.url)
  }

  connectWs(url) {
    this.ws = new WebSocket(url)
    this.ws.onmessage = (ev) => this.onGatewayMessage(JSON.parse(ev.data))
    this.ws.onclose = () => {
      this.stopHeartbeat()
      if (this.running) setTimeout(() => this.connectWs(this.resumeUrl || url), 3000) // reconnect/resume
    }
  }

  onGatewayMessage(msg) {
    const { op, t, d, s } = msg
    if (s) this.lastSeq = s

    if (op === 10) { // HELLO — start heartbeating, then IDENTIFY/RESUME
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
      console.log(`[Channels] Discord gateway ready as @${d.user.username}`)
    } else if (op === 0 && t === 'MESSAGE_CREATE') {
      // Ignore own messages and non-command text.
      if (d.author?.id === this.applicationId || !d.content) return
      const channelId = d.channel_id
      if (!this.pending.includes(channelId)) this.pending.push(channelId)
      this.gateway.handleCommand('discord', channelId, d.content, (reply) => this.sendTo(channelId, reply)).catch(() => { })
    } else if (op === 7) { // RECONNECT requested
      this.ws?.close()
    } else if (op === 9) { // Invalid session — fresh IDENTIFY
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
    // Discord message limit is 2000 chars — split if needed.
    for (const chunk of String(text).match(/[\s\S]{1,1900}(\s|$)/g) || [String(text)]) {
      await fetch(`${API_BASE}/channels/${channelId}/messages`, {
        method: 'POST',
        headers: { authorization: `Bot ${config.channels.discord.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ content: chunk }),
      }).catch(e => console.warn(`[Discord] send failed: ${e.message}`))
    }
  }

  /** Gateway broadcast — send to every approved channel. */
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
