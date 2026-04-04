import fs from 'node:fs/promises'
import path from 'node:path'
import { randomUUID } from 'node:crypto'

export class AISessionLogger {
  constructor() {
    this.baseDir = path.resolve(process.cwd(), '../logs/ai_sessions')
  }

  async ensureDir() {
    await fs.mkdir(this.baseDir, { recursive: true })
  }

  async startSession({ type, user, projectId = null, target = null, metadata = {} }) {
    await this.ensureDir()
    const sessionId = `ais_${randomUUID()}`
    const now = new Date().toISOString()

    const meta = {
      sessionId,
      type,
      user,
      projectId,
      target,
      startedAt: now,
      endedAt: null,
      metadata,
    }

    await fs.writeFile(this.getMetaPath(sessionId), JSON.stringify(meta, null, 2), 'utf8')
    await fs.writeFile(this.getTranscriptPath(sessionId), '', 'utf8')

    await this.appendTranscript(sessionId, {
      event: 'session_started',
      timestamp: now,
      payload: { type, user, projectId, target },
    })

    return sessionId
  }

  async appendTranscript(sessionId, entry) {
    await this.ensureDir()
    const line = JSON.stringify(entry)
    await fs.appendFile(this.getTranscriptPath(sessionId), `${line}\n`, 'utf8')
  }

  async endSession(sessionId, status = 'completed', summary = {}) {
    const metaPath = this.getMetaPath(sessionId)
    let meta = null

    try {
      const raw = await fs.readFile(metaPath, 'utf8')
      meta = JSON.parse(raw)
    } catch (_) {
      return
    }

    meta.endedAt = new Date().toISOString()
    meta.status = status
    meta.summary = summary

    await fs.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8')
    await this.appendTranscript(sessionId, {
      event: 'session_ended',
      timestamp: meta.endedAt,
      payload: { status, summary },
    })
  }

  getMetaPath(sessionId) {
    return path.join(this.baseDir, `${sessionId}.meta.json`)
  }

  getTranscriptPath(sessionId) {
    return path.join(this.baseDir, `${sessionId}.transcript.jsonl`)
  }
}
