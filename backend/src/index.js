import http from 'node:http'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import { Server as SocketIOServer } from 'socket.io'
import { randomUUID } from 'node:crypto'
import bcrypt from 'bcryptjs'
import fs from 'node:fs'

import { config } from './config.js'
import * as db from './db.js'
import { authMiddleware, requireAuth, signToken, getUser } from './auth.js'
import { UnifiedPipeline } from './pipeline.js'
import { hexstrike, payloadsRag } from './integrations/index.js'
import { agentRegistry } from './ai/agent-registry.js'
import { aiEngine } from './ai/ai-engine.js'
import { generateReport } from './report.js'
import { getCve, findVersionVulnerabilities } from './cve.js'
import * as monitors from './monitor-scheduler.js'
import swaggerUi from 'swagger-ui-express'
import { openapiSpec } from './openapi.js'
import { walkProjects, DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES } from './folder-walker.js'
import { ExploitOrchestrator } from './exploits/orchestrator.js'
import * as msf from './exploits/msf-client.js'
import { matchExploits, classifyRisk } from './exploits/registry.js'
import { sendScanRequestNotification } from './email.js'
import { GitHubClient, parseGitHubWebhook } from './integrations/github.js'
import { PLANS, getUserSubscription, consumeScanQuota, activateSubscription, getPaymentHistory } from './billing.js'

// CORS: only whitelisted origins (config.corsOrigins from CLIENT_ORIGIN).
// Non-browser clients (curl, server-to-server) carry no Origin header → allowed.
// Local frontend on any localhost/127.0.0.1 port (vite dev 517x, preview 417x) is always allowed —
// the backend itself binds to localhost, so this never widens remote attack surface.
const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/
const corsOptions = {
  origin(origin, cb) {
    if (!origin || config.corsOrigins.includes(origin) || config.corsOrigins.includes('*') || origin.endsWith('sentinelai.studio') || LOCAL_ORIGIN_RE.test(origin)) return cb(null, true)
    return cb(new Error(`CORS blocked: ${origin}`))
  },
  credentials: true,
}

const app = express()
app.disable('x-powered-by')
app.use(express.json({ limit: '10mb' }))
app.use(cors(corsOptions))
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  next()
})
app.use(authMiddleware)

const server = http.createServer(app)
const io = new SocketIOServer(server, { cors: corsOptions })

// Authenticate WebSocket connections via the JWT (sent in handshake auth).
io.use((socket, next) => {
  const token = socket.handshake.auth?.token
  if (!token) return next(new Error('authentication required'))
  try {
    socket.user = jwt.verify(token, config.jwt.secret, { issuer: config.jwt.issuer })
    return next()
  } catch { return next(new Error('invalid token')) }
})

const pipeline = new UnifiedPipeline({ io })

// ── Autonomous Exploitation Engine ────────────────────────────────────────────
const exploitEngine = new ExploitOrchestrator({ io, pipeline })

// Wire the singleton exploit engine into the pipeline for auto-exploit
pipeline._exploitEngine = exploitEngine

// ── bootstrap ────────────────────────────────────────────────────────────────
db.getDb()
const armedMonitors = monitors.bootstrap(pipeline)
if (armedMonitors) console.log(`[bootstrap] ${armedMonitors} monitor(s) re-armed`)

// Mark scans interrupted by server restart as 'interrupted' (NOT 'failed').
// Findings are preserved in the DB — only in-memory pipeline state is lost.
// The user can resume from the UI to pick up where it left off.
try {
  const interruptedScans = db.all(`SELECT * FROM scans WHERE status IN ('running','paused','queued')`)
  if (interruptedScans.length > 0) {
    console.log(`[bootstrap] Found ${interruptedScans.length} interrupted scan(s). Marking as interrupted (findings preserved)...`)
    const ts = new Date().toISOString()
    for (const scan of interruptedScans) {
      db.run(`UPDATE scans SET status = 'interrupted', finished_at = NULL WHERE id = ?`, scan.id)
      db.run(`INSERT INTO logs (scan_id, level, message, ts) VALUES (?,?,?,?)`,
        scan.id, 'warn', '⏸ Scan interrupted by server restart. All findings are preserved. Click Resume to continue.', ts)
    }
  }
} catch (e) { console.warn('[bootstrap] Interrupted scan recovery notice:', e.message) }

// seed admin
let adminUser = getUser('muhammadsaifudinmj@gmail.com') || getUser('admin')
if (!adminUser) {
  db.run(`INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?)`,
    `usr_${randomUUID()}`, 'admin', 'muhammadsaifudinmj@gmail.com', bcrypt.hashSync(config.defaultAdminPassword, 10), 'admin', new Date().toISOString())
  console.log('[bootstrap] default admin user created')
} else {
  // Always ensure email and password match requested credentials
  db.run(`UPDATE users SET email = ?, password_hash = ? WHERE id = ?`,
    'muhammadsaifudinmj@gmail.com', bcrypt.hashSync('kali', 10), adminUser.id)
}
// build payload index if empty
try {
  const st = payloadsRag.payloadsIndexStatus()
  if (st.installed && st.docs === 0) {
    console.log('[bootstrap] building PayloadsAllTheThings RAG index...')
    const r = payloadsRag.buildPayloadIndex((lvl, msg) => console.log(`[rag] ${msg}`))
    console.log(`[bootstrap] RAG index ready: ${r.indexed} docs`)
  }
} catch (e) { console.warn('[bootstrap] RAG index build skipped:', e.message) }

const audit = (actor, action, detail) =>
  db.run(`INSERT INTO audit (actor, action, detail, ts) VALUES (?,?,?,?)`, actor || 'system', action, detail || '', new Date().toISOString())

/** Persist the exact launch configuration of a scan so it can be re-run later. */
const saveScanConfig = (scanId, cfg) => {
  try {
    db.run(`INSERT OR REPLACE INTO scan_configs (scan_id, config) VALUES (?,?)`, scanId, JSON.stringify(cfg || {}))
  } catch { /* non-fatal — re-run falls back to defaults */ }
}

// ── API docs (Swagger UI) — public, no auth so teams can browse the spec ────
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(openapiSpec, {
  customSiteTitle: 'FYP2 API Docs',
  customCss: '.topbar{display:none} .swagger-ui{color-scheme:dark}',
}))
app.get('/api/openapi.json', (req, res) => res.json(openapiSpec))

// ── Health & status ──────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }))

app.get('/api/status', requireAuth, async (req, res) => {
  const engine = await hexstrike.engineStatus()
  const rag = payloadsRag.payloadsIndexStatus()
  let msfStatus = { available: false, error: 'not checked' }
  try { msfStatus = await msf.status() } catch (e) { msfStatus = { available: false, error: e.message } }
  res.json({
    engine,
    rag,
    msf: msfStatus,
    agents: { count: agentRegistry.list().length, dir: config.agentsDir },
    ai: { configured: aiEngine.llm.isConfigured(), provider: config.ai.provider },
  })
})

// ── Auth ─────────────────────────────────────────────────────────────────────
// Brute-force protection: 10 attempts / 15 min per IP on login.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts — try again later' },
})

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {}
  const identifier = (username || '').trim()
  
  // 1. Check primary admin/analyst users
  let user = getUser(identifier)
  if (user && bcrypt.compareSync(password || '', user.password_hash)) {
    db.run(`UPDATE users SET last_login = ? WHERE id = ?`, new Date().toISOString(), user.id)
    audit(user.username, 'login', 'user logged in')
    return res.json({ token: signToken(user), user: { id: user.id, username: user.username, role: user.role, email: user.email } })
  }

  // 2. Check client portal credentials (added under projects)
  const clientCred = db.get(`SELECT * FROM client_credentials WHERE email = ?`, identifier)
  if (clientCred && (password === clientCred.password || bcrypt.compareSync(password || '', clientCred.password))) {
    const clientUser = {
      id: clientCred.id,
      username: clientCred.email.split('@')[0] || 'client',
      role: 'client',
      email: clientCred.email,
      projectId: clientCred.project_id
    }
    audit(clientCred.email, 'login', `client portal login for project ${clientCred.project_id}`)
    return res.json({ token: signToken(clientUser), user: clientUser })
  }

  return res.status(401).json({ error: 'invalid credentials' })
})

app.get('/api/users/me', requireAuth, (req, res) => {
  const u = getUser(req.user.username)
  if (!u) return res.json({ id: req.user.sub, username: req.user.username, role: req.user.role, email: req.user.email || null, lastLogin: null })
  res.json({ id: u.id, username: u.username, role: u.role, email: u.email, lastLogin: u.last_login })
})

app.put('/api/users/me', requireAuth, (req, res) => {
  const { email } = req.body || {}
  db.run(`UPDATE users SET email = ? WHERE id = ?`, email ?? null, req.user.sub)
  audit(req.user.username, 'user:update', 'profile updated')
  const u = db.get(`SELECT * FROM users WHERE id = ?`, req.user.sub)
  res.json({ id: u.id, username: u.username, role: u.role, email: u.email, lastLogin: u.last_login })
})

app.post('/api/users/me/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {}
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'new password must be ≥ 6 chars' })
  const u = db.get(`SELECT * FROM users WHERE id = ?`, req.user.sub)
  if (!u || !bcrypt.compareSync(currentPassword || '', u.password_hash))
    return res.status(401).json({ error: 'current password incorrect' })
  db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, bcrypt.hashSync(newPassword, 10), u.id)
  audit(req.user.username, 'user:password', 'password changed')
  res.json({ ok: true })
})

// ── Projects ─────────────────────────────────────────────────────────────────
app.get('/api/projects', requireAuth, (req, res) => {
  if (req.user?.role === 'client') {
    if (req.user.projectId) {
      const proj = db.get(`SELECT * FROM projects WHERE id = ?`, req.user.projectId)
      return res.json(proj ? [proj] : [])
    }
    const userEmail = (req.user.email || '').toLowerCase()
    const username = (req.user.username || '').toLowerCase()
    const allProjs = db.all(`SELECT * FROM projects ORDER BY created_at DESC`)
    const filtered = allProjs.filter((p) => {
      const clientName = (p.client || '').toLowerCase()
      const projName = (p.name || '').toLowerCase()
      return (
        (userEmail && clientName.includes(userEmail)) ||
        (username && clientName.includes(username)) ||
        (clientName.includes('myces') || projName.includes('fms'))
      )
    })
    if (filtered.length > 0) return res.json(filtered)
    return res.json(allProjs.slice(0, 1))
  }
  return res.json(db.all(`SELECT * FROM projects ORDER BY created_at DESC`))
})

app.post('/api/projects', requireAuth, (req, res) => {
  if (req.user?.role === 'client') {
    return res.status(403).json({ error: 'Client users cannot create projects' })
  }
  const { name, client = '', description = '', scope = '', cover = '', riskLevel = 'medium' } = req.body || {}
  if (!name) return res.status(400).json({ error: 'name required' })
  const id = `proj_${randomUUID()}`
  const now = new Date().toISOString()
  db.run(`INSERT INTO projects (id, name, client, description, scope, cover, risk_level, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
    id, name, client, description, scope, cover, riskLevel, 'active', now, now)
  audit(req.user.username, 'project:create', name)
  res.status(201).json(db.get(`SELECT * FROM projects WHERE id = ?`, id))
})

app.put('/api/projects/:id', requireAuth, (req, res) => {
  if (req.user?.role === 'client') {
    return res.status(403).json({ error: 'Client users cannot modify projects' })
  }
  const { name, client = '', description = '', scope = '', cover = '', riskLevel = 'medium' } = req.body || {}
  if (!name) return res.status(400).json({ error: 'name required' })
  const now = new Date().toISOString()
  db.run(`UPDATE projects SET name = ?, client = ?, description = ?, scope = ?, cover = ?, risk_level = ?, updated_at = ? WHERE id = ?`,
    name, client, description, scope, cover, riskLevel, now, req.params.id)
  audit(req.user.username, 'project:update', req.params.id)
  res.json(db.get(`SELECT * FROM projects WHERE id = ?`, req.params.id))
})

app.delete('/api/projects/:id', requireAuth, (req, res) => {
  if (req.user?.role === 'client') {
    return res.status(403).json({ error: 'Client users cannot delete projects' })
  }
  db.run(`DELETE FROM client_credentials WHERE project_id = ?`, req.params.id)
  db.run(`DELETE FROM projects WHERE id = ?`, req.params.id)
  audit(req.user.username, 'project:delete', req.params.id)
  res.json({ ok: true })
})

// ── Client Credentials for Project Portals ────────────────────────────────────
app.get('/api/projects/:id/credentials', requireAuth, (req, res) => {
  res.json(db.all(`SELECT * FROM client_credentials WHERE project_id = ? ORDER BY created_at DESC`, req.params.id))
})

app.post('/api/projects/:id/credentials', requireAuth, (req, res) => {
  const { email, password, note = '' } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'email and password required' })
  const id = `cred_${randomUUID()}`
  const now = new Date().toISOString()
  const hashedPassword = bcrypt.hashSync(password, 10)
  db.run(`INSERT INTO client_credentials (id, project_id, email, password, note, created_at) VALUES (?,?,?,?,?,?)`,
    id, req.params.id, email.trim(), hashedPassword, note.trim(), now)
  audit(req.user.username, 'project:cred_create', `${email} on ${req.params.id}`)
  res.status(201).json(db.get(`SELECT * FROM client_credentials WHERE id = ?`, id))
})

app.put('/api/projects/:id/credentials/:credId', requireAuth, (req, res) => {
  const { email, password, note = '' } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'email and password required' })
  const hashedPassword = bcrypt.hashSync(password, 10)
  db.run(`UPDATE client_credentials SET email = ?, password = ?, note = ? WHERE id = ? AND project_id = ?`,
    email.trim(), hashedPassword, note.trim(), req.params.credId, req.params.id)
  audit(req.user.username, 'project:cred_update', `${req.params.credId}`)
  res.json(db.get(`SELECT * FROM client_credentials WHERE id = ?`, req.params.credId))
})

app.delete('/api/projects/:id/credentials/:credId', requireAuth, (req, res) => {
  db.run(`DELETE FROM client_credentials WHERE id = ? AND project_id = ?`, req.params.credId, req.params.id)
  audit(req.user.username, 'project:cred_delete', `${req.params.credId}`)
  res.json({ ok: true })
})

// ── Scans ────────────────────────────────────────────────────────────────────
app.get('/api/scans', requireAuth, (req, res) => {
  try {
    if (req.user?.role === 'client') {
      if (req.user.projectId) {
        const scans = db.all(`
          SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_count
          FROM scans s WHERE s.project_id = ? ORDER BY s.created_at DESC LIMIT 200
        `, req.user.projectId)
        return res.json(scans || [])
      }
      const userEmail = (req.user.email || '').toLowerCase()
      const username = (req.user.username || '').toLowerCase()
      const allProjs = db.all(`SELECT * FROM projects`)
      const matchProjs = allProjs.filter((p) => {
        const c = (p.client || '').toLowerCase()
        const n = (p.name || '').toLowerCase()
        return (userEmail && c.includes(userEmail)) || (username && c.includes(username)) || c.includes('myces') || n.includes('fms')
      })
      const projIds = matchProjs.map(p => p.id)
      if (projIds.length > 0) {
        const placeholders = projIds.map(() => '?').join(',')
        const scans = db.all(`
          SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_count
          FROM scans s WHERE s.project_id IN (${placeholders}) ORDER BY s.created_at DESC LIMIT 200
        `, ...projIds)
        return res.json(scans || [])
      }
    }
    const allScans = db.all(`
      SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_count
      FROM scans s ORDER BY s.created_at DESC LIMIT 200
    `)
    return res.json(allScans || [])
  } catch (err) {
    console.error('Failed to fetch scans:', err)
    return res.status(500).json({ error: 'Failed to fetch scans' })
  }
})
app.get('/api/scans/:id', requireAuth, (req, res) => {
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, req.params.id)
  if (!scan) return res.status(404).json({ error: 'not found' })
  const findings = db.all(`SELECT * FROM findings WHERE scan_id = ?`, scan.id)
  const logs = db.all(`SELECT level, message, ts FROM logs WHERE scan_id = ? ORDER BY id DESC LIMIT 100`, scan.id).reverse()
  // Parse whitebox metadata for the Audit Details section
  let whiteboxMeta = null
  if (scan.whitebox_meta) {
    try { whiteboxMeta = JSON.parse(scan.whitebox_meta) } catch { /* ignore */ }
  }
  // Parse blackbox metadata for the URL tracking section
  let blackboxMeta = null
  if (scan.blackbox_meta) {
    try { blackboxMeta = JSON.parse(scan.blackbox_meta) } catch { /* ignore */ }
  }
  res.json({ scan, findings, logs, whiteboxMeta, blackboxMeta })
})

// Client scan request endpoint (notifies admin via email)
app.post('/api/scans/request', requireAuth, async (req, res) => {
  try {
    const { target, projectId, scanType, notes } = req.body || {}
    if (!target || !target.trim()) {
      return res.status(400).json({ error: 'Target URL or scope is required' })
    }

    const project = projectId ? db.get(`SELECT * FROM projects WHERE id = ?`, projectId) : null
    const requestId = `req_${randomUUID()}`

    audit(req.user.username, 'scan:request', `Target: ${target.trim()} (Project: ${project?.name || 'N/A'})`)

    const emailResult = await sendScanRequestNotification({
      clientUser: req.user,
      project,
      target: target.trim(),
      scanType,
      notes,
    })

    return res.json({
      success: true,
      requestId,
      message: 'Scan request submitted successfully! Notification sent to muhammadsaifudinmj@gmail.com.',
      emailResult,
    })
  } catch (err) {
    console.error('[scans/request] error:', err)
    return res.status(500).json({ error: 'Failed to submit scan request: ' + (err.message || err) })
  }
})

// Alias kept for backwards-compat — delegates to the real handler above
app.post('/api/scan-requests', requireAuth, async (req, res) => {
  // Simply call the same scan-request logic inline
  const { target, projectId, scanType, notes } = req.body || {}
  if (!target || !target.trim()) return res.status(400).json({ error: 'Target URL or scope is required' })
  const project = projectId ? db.get(`SELECT * FROM projects WHERE id = ?`, projectId) : null
  audit(req.user.username, 'scan:request', `Target: ${target.trim()} (Project: ${project?.name || 'N/A'})`)
  const { sendScanRequestNotification: notify } = await import('./email.js').catch(() => ({ sendScanRequestNotification: null }))
  const emailResult = notify ? await notify({ clientUser: req.user, project, target: target.trim(), scanType, notes }).catch(e => ({ error: e.message })) : { error: 'email module unavailable' }
  return res.json({ success: true, requestId: `req_${randomUUID()}`, message: 'Scan request submitted.', emailResult })
})

app.post('/api/scans', requireAuth, async (req, res) => {
  if (req.user?.role === 'client') {
    return res.status(403).json({ error: 'Client users cannot launch scans directly. Please use Ask for New Scan.' })
  }
  const {
    target, projectId = null, mode = 'blackbox', targetType = 'url',
    template = 'standard', modules = [], objective = 'comprehensive', maxTools = 6,
    files = [], language = '', focus = '', verify = true, depth = 'standard',
    dynamicTarget = '', dynamicModules = [],
  } = req.body || {}

  if (mode === 'blackbox' && !target) return res.status(400).json({ error: 'target required for blackbox' })
  if (mode === 'whitebox' && (!files || !files.length)) return res.status(400).json({ error: 'files required for whitebox' })

  const id = `scan_${randomUUID()}`
  const now = new Date().toISOString()
  db.run(`INSERT INTO scans (id, project_id, target, target_type, mode, status, template, modules, progress, created_at, started_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    id, projectId, target || '(whitebox)', targetType, mode, 'running', template,
    JSON.stringify(modules), 0, now, now)
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, id)
  audit(req.user.username, 'scan:start', `${mode} → ${target || 'codebase'}`)
  saveScanConfig(id, { target, targetType, mode, template, modules, objective, maxTools, files, language, focus, verify, depth, dynamicTarget, dynamicModules })

  // Run async (non-blocking)
  setImmediate(async () => {
    try {
      if (mode === 'whitebox') await pipeline.runWhitebox(scan, { files, language, focus, verify, depth, dynamicTarget, dynamicModules })
      else await pipeline.runBlackbox(scan, { modules, objective, maxTools, verify, depth })
    } catch (e) {
      if (e.message === 'SCAN_STOPPED') return // already set to 'stopped' by the /stop endpoint
      pipeline.log(id, 'error', `Pipeline error: ${e.message}`)
      pipeline.finish(id, 'failed')
    }
  })

  res.status(201).json({ scan })
})

app.post('/api/scans/:id/stop', requireAuth, (req, res) => {
  pipeline.stopScan(req.params.id) // set stopped flag so loops abort
  db.run(`UPDATE scans SET status = 'stopped', finished_at = ? WHERE id = ?`, new Date().toISOString(), req.params.id)
  audit(req.user.username, 'scan:stop', req.params.id)
  res.json({ ok: true })
})

app.delete('/api/scans/:id', requireAuth, (req, res) => {
  const { id } = req.params
  pipeline.stopScan(id) // abort any running scan
  db.run(`DELETE FROM logs WHERE scan_id = ?`, id)
  db.run(`DELETE FROM scan_configs WHERE scan_id = ?`, id)
  db.run(`DELETE FROM findings WHERE scan_id = ?`, id)
  db.run(`DELETE FROM scans WHERE id = ?`, id)
  audit(req.user.username, 'scan:delete', id)
  res.json({ ok: true })
})

app.post('/api/scans/:id/re-run', requireAuth, async (req, res) => {
  const old = db.get(`SELECT * FROM scans WHERE id = ?`, req.params.id)
  if (!old) return res.status(404).json({ error: 'Scan not found' })

  // Restore the original launch configuration (persisted at scan creation).
  let cfg = {}
  try { cfg = JSON.parse(db.get(`SELECT config FROM scan_configs WHERE scan_id = ?`, old.id)?.config || '{}') } catch { }

  const mode = cfg.mode || old.mode || 'blackbox'
  const modules = Array.isArray(cfg.modules) ? cfg.modules : (() => { try { return JSON.parse(old.modules || '[]') } catch { return [] } })()
  const baseOpts = {
    modules,
    objective: cfg.objective || 'comprehensive',
    maxTools: cfg.maxTools || 6,
    verify: cfg.verify !== false,
    depth: cfg.depth || 'standard',
    language: cfg.language || '',
    focus: cfg.focus || '',
  }

  // Whitebox needs its source material: either the inline files or the folder list.
  let whiteboxFiles = null
  if (mode === 'whitebox') {
    if (Array.isArray(cfg.files) && cfg.files.length) {
      whiteboxFiles = cfg.files
    } else if (Array.isArray(cfg.folders) && cfg.folders.length) {
      try {
        // Re-runs always use the unlimited default so a stored low cap
        // (e.g. maxFiles: 1000 from an older scan) never truncates the source set.
        const { files, stats } = walkProjects(cfg.folders, {
          maxFiles: DEFAULT_MAX_FILES,
          maxBytes: DEFAULT_MAX_BYTES,
        })
        if (files.length) {
          whiteboxFiles = files
          pipeline.log(req.params.id, 'info', `🔁 Re-run: re-walked folders → ${files.length} files`)
        } else {
          return res.status(400).json({ error: 're-run failed: original folders no longer contain scannable files', stats })
        }
      } catch (e) {
        return res.status(400).json({ error: `re-run failed: cannot re-walk folders (${e.message})` })
      }
    } else {
      return res.status(400).json({ error: 're-run not possible: original whitebox source (files/folders) was not stored for this scan' })
    }
  }

  const id = 'scan_' + randomUUID()
  const now = new Date().toISOString()

  db.run(`INSERT INTO scans (id, project_id, target, target_type, mode, status, template, modules, progress, risk_score, created_at, started_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    id, old.project_id, old.target, old.target_type, mode, 'running', old.template,
    JSON.stringify(modules), 0, 0, now, now)

  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, id)
  audit(req.user.username, 'scan:re-run', `${scan.target} (${id})`)
  // Carry the config forward so the new scan is itself re-runnable.
  saveScanConfig(id, { ...cfg, mode, modules })

  setImmediate(async () => {
    try {
      if (mode === 'whitebox') await pipeline.runWhitebox(scan, { ...baseOpts, files: whiteboxFiles, dynamicTarget: cfg.dynamicTarget || '', dynamicModules: cfg.dynamicModules || [] })
      else await pipeline.runBlackbox(scan, baseOpts)
    } catch (e) {
      if (e.message === 'SCAN_STOPPED') return
      pipeline.log(id, 'error', `Pipeline error: ${e.message}`)
      pipeline.finish(id, 'failed')
    }
  })

  res.status(201).json({ scan })
})

/**
 * Retry only the FAILED parts of a scan (whitebox AI passes or blackbox tools).
 * Does NOT create a new scan — re-runs in-place on the same scan ID.
 */
app.post('/api/scans/:id/retry-failed', requireAuth, async (req, res) => {
  const old = db.get(`SELECT * FROM scans WHERE id = ?`, req.params.id)
  if (!old) return res.status(404).json({ error: 'Scan not found' })

  // Restore the original launch configuration
  let cfg = {}
  try { cfg = JSON.parse(db.get(`SELECT config FROM scan_configs WHERE scan_id = ?`, old.id)?.config || '{}') } catch { }

  const mode = cfg.mode || old.mode || 'blackbox'
  const modules = Array.isArray(cfg.modules) ? cfg.modules : (() => { try { return JSON.parse(old.modules || '[]') } catch { return [] } })()
  const baseOpts = {
    modules,
    verify: cfg.verify !== false,
    language: cfg.language || '',
    focus: cfg.focus || '',
  }

  // Reset the scan to running so the UI shows progress
  db.run(`UPDATE scans SET status = 'running', progress = 0 WHERE id = ?`, old.id)
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, old.id)
  audit(req.user.username, 'scan:retry-failed', `${scan.target} (${scan.id})`)

  setImmediate(async () => {
    try {
      if (mode === 'whitebox') {
        // Load source files from config
        let whiteboxFiles = []
        if (Array.isArray(cfg.files) && cfg.files.length) {
          whiteboxFiles = cfg.files
        } else if (Array.isArray(cfg.folders) && cfg.folders.length) {
          try {
            const { files } = walkProjects(cfg.folders, {
              maxFiles: DEFAULT_MAX_FILES,
              maxBytes: DEFAULT_MAX_BYTES,
            })
            whiteboxFiles = files
          } catch { /* will fail below */ }
        }
        if (!whiteboxFiles.length) {
          pipeline.log(old.id, 'error', 'Retry failed: cannot re-load source files')
          pipeline.finish(old.id, 'failed')
          return
        }
        await pipeline.retryFailedWhitebox(scan, { ...baseOpts, files: whiteboxFiles })
      } else {
        await pipeline.retryFailedBlackbox(scan, baseOpts)
      }
    } catch (e) {
      if (e.message === 'SCAN_STOPPED') return
      pipeline.log(old.id, 'error', `Retry failed error: ${e.message}`)
      pipeline.finish(old.id, 'failed')
    }
  })

  res.json({ scan })
})

/**
 * Whitebox folder scan — the server walks one or more LOCAL project folders
 * (frontend + backend), skipping node_modules/.git/.env/dist/build/lockfiles,
 * and feeds the collected source into the whitebox pipeline.
 *
 * Body: { folders: [{dir, prefix?}] | string[], projectId?, language?, focus?, verify?, maxFiles? }
 * Only folders under config.whiteboxRoots (default: project root + $HOME) are allowed.
 */
/**
 * Browse server filesystem for whitebox folder selection.
 * Returns directories only, within allowed roots.
 */
app.get('/api/filesystem/browse', requireAuth, async (req, res) => {
  const pathMod = await import('node:path')
  const osMod = await import('node:os')
  const roots = (config.whiteboxRoots || [process.cwd(), osMod.default.homedir()]).map(r => pathMod.default.resolve(r))

  let rel = (req.query.path || '').trim()
  let baseDir
  if (!rel) {
    // No path = list allowed roots
    return res.json({
      roots: roots.map(r => ({ path: r, name: pathMod.default.basename(r) || r })),
      current: null,
      parent: null,
      directories: [],
    })
  }

  const resolved = pathMod.default.resolve(rel)
  if (!roots.some(r => resolved === r || resolved.startsWith(r + pathMod.default.sep))) {
    return res.status(403).json({ error: `path outside allowed roots: ${resolved}`, allowedRoots: roots })
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    return res.status(400).json({ error: `not a directory: ${resolved}` })
  }

  const entries = fs.readdirSync(resolved, { withFileTypes: true })
  const directories = entries
    .filter(e => e.isDirectory() && !e.name.startsWith('.') && !['node_modules', 'dist', 'build', 'out', '__pycache__', '.git', '.svn', 'venv', '.venv', 'target', 'bin', 'obj', 'tmp', 'temp', 'cache', '.cache', '.turbo', '.next', '.nuxt', 'coverage', 'uploads', 'storage', 'migrations', 'fixtures', 'logs'].includes(e.name))
    .map(e => ({
      name: e.name,
      path: pathMod.default.join(resolved, e.name),
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
    .slice(0, 100)

  const parent = pathMod.default.dirname(resolved)
  const parentAllowed = roots.some(r => parent === r || parent.startsWith(r + pathMod.default.sep))

  res.json({
    roots: roots.map(r => ({ path: r, name: pathMod.default.basename(r) || r })),
    current: resolved,
    parent: parentAllowed ? parent : null,
    directories,
  })
})

app.post('/api/scans/whitebox-folder', requireAuth, async (req, res) => {
  const {
    folders = [], projectId = null, language = '', focus = '', verify = true,
    maxFiles = 10000, maxBytes = 50_000_000, depth = 'standard',
    dynamicTarget = '', dynamicModules = [],
  } = req.body || {}
  const list = Array.isArray(folders) ? folders : [folders]
  if (!list.length) return res.status(400).json({ error: 'folders required (array of {dir, prefix?} or paths)' })

  // Security: only allow folders under whitelisted roots
  const pathMod = await import('node:path')
  const osMod = await import('node:os')
  const roots = (config.whiteboxRoots || [process.cwd(), osMod.default.homedir()]).map(r => pathMod.default.resolve(r))
  const normalized = list.map((f) => {
    const dir = typeof f === 'string' ? f : f.dir
    const prefix = typeof f === 'string' ? pathMod.default.basename(f) : (f.prefix || pathMod.default.basename(f.dir))
    const resolved = pathMod.default.resolve(dir)
    return { dir: resolved, prefix }
  })
  for (const f of normalized) {
    if (!roots.some(r => f.dir === r || f.dir.startsWith(r + pathMod.default.sep))) {
      return res.status(403).json({ error: `folder outside allowed roots: ${f.dir}`, allowedRoots: roots })
    }
    if (!fs.existsSync(f.dir)) {
      return res.status(400).json({ error: `folder not found: ${f.dir}` })
    }
  }

  const { files, stats } = walkProjects(normalized, {
    maxFiles: Number(maxFiles) || DEFAULT_MAX_FILES,
    maxBytes: Number(maxBytes) || DEFAULT_MAX_BYTES,
  })
  if (!files.length) return res.status(400).json({ error: 'no source files collected', stats })

  const id = `scan_${randomUUID()}`
  const now = new Date().toISOString()
  const targetLabel = normalized.map(f => f.prefix).join(' + ')
  db.run(`INSERT INTO scans (id, project_id, target, target_type, mode, status, template, modules, progress, created_at, started_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    id, projectId, targetLabel, 'code', 'whitebox', 'running', 'folder',
    JSON.stringify(['folder-walker']), 0, now, now)
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, id)
  audit(req.user.username, 'scan:start', `whitebox-folder → ${targetLabel} (${files.length} files)`)
  saveScanConfig(id, { mode: 'whitebox', source: 'folder', folders: normalized, language, focus, verify, depth, maxFiles, maxBytes, dynamicTarget, dynamicModules })

  pipeline.log(id, 'info', `📂 Folder walker collected ${files.length} files (${JSON.stringify(stats.collected || files.length)} used, stats: ${JSON.stringify(stats).slice(0, 300)})`)

  setImmediate(async () => {
    try {
      await pipeline.runWhitebox(scan, { files, language, focus, verify, depth, dynamicTarget, dynamicModules })
    } catch (e) {
      if (e.message === 'SCAN_STOPPED') return
      pipeline.log(id, 'error', `Pipeline error: ${e.message}`)
      pipeline.finish(id, 'failed')
    }
  })

  res.status(201).json({ scan, stats })
})

app.post('/api/scans/:id/pause', requireAuth, (req, res) => {
  pipeline.pauseScan(req.params.id)
  db.run(`UPDATE scans SET status = 'paused' WHERE id = ?`, req.params.id)
  pipeline.log(req.params.id, 'warn', '⏸ Scan paused by user')
  audit(req.user.username, 'scan:pause', req.params.id)
  res.json({ ok: true, status: 'paused' })
})

app.post('/api/scans/:id/resume', requireAuth, (req, res) => {
  pipeline.resumeScan(req.params.id)
  db.run(`UPDATE scans SET status = 'running' WHERE id = ?`, req.params.id)
  pipeline.log(req.params.id, 'info', '▶ Scan resumed by user')
  audit(req.user.username, 'scan:resume', req.params.id)
  res.json({ ok: true, status: 'running' })
})

// ── Findings ─────────────────────────────────────────────────────────────────
app.get('/api/findings', requireAuth, (req, res) => {
  const { status, scan_id, project_id, severity } = req.query
  let sql = `
    SELECT f.*, s.target, s.project_id, p.name AS project_name
    FROM findings f
    LEFT JOIN scans s ON s.id = f.scan_id
    LEFT JOIN projects p ON p.id = s.project_id
    WHERE 1=1
  `
  const params = []
  if (status) { sql += ' AND f.status = ?'; params.push(status) }
  if (scan_id) { sql += ' AND f.scan_id = ?'; params.push(scan_id) }
  if (project_id) { sql += ' AND s.project_id = ?'; params.push(project_id) }
  if (severity) { sql += ' AND f.severity = ?'; params.push(severity) }
  sql += ' ORDER BY f.created_at DESC LIMIT 1000'
  res.json(db.all(sql, ...params))
})
app.delete('/api/findings/:id', requireAuth, (req, res) => {
  const f = db.get(`SELECT id FROM findings WHERE id = ?`, req.params.id)
  if (!f) return res.status(404).json({ error: 'finding not found' })
  db.run(`DELETE FROM finding_notes WHERE finding_id = ?`, req.params.id)
  db.run(`DELETE FROM findings WHERE id = ?`, req.params.id)
  audit(req.user.username, 'finding:delete', req.params.id)
  res.json({ ok: true })
})

app.put('/api/findings/:id/status', requireAuth, (req, res) => {
  db.run(`UPDATE findings SET status = ? WHERE id = ?`, req.body.status || 'open', req.params.id)
  res.json(db.get(`SELECT * FROM findings WHERE id = ?`, req.params.id))
})

app.put('/api/findings/:id/severity', requireAuth, (req, res) => {
  const valid = ['critical', 'high', 'medium', 'low', 'info']
  const sev = (req.body.severity || '').toLowerCase()
  if (!valid.includes(sev)) return res.status(400).json({ error: `Invalid severity. Must be one of: ${valid.join(', ')}` })
  const f = db.get(`SELECT id FROM findings WHERE id = ?`, req.params.id)
  if (!f) return res.status(404).json({ error: 'finding not found' })
  db.run(`UPDATE findings SET severity = ? WHERE id = ?`, sev, req.params.id)
  audit(req.user.username, 'finding:severity-override', `${req.params.id} → ${sev}`)
  res.json(db.get(`SELECT * FROM findings WHERE id = ?`, req.params.id))
})

// ── Console / Terminal ───────────────────────────────────────────────────────
app.post('/api/console/exec', requireAuth, async (req, res) => {
  const { command, timeout = 120000 } = req.body || {}
  if (!command || typeof command !== 'string') return res.status(400).json({ error: 'command required' })
  if (command.length > 8000) return res.status(400).json({ error: 'command too long (max 8000 chars)' })
  audit(req.user.username, 'console:exec', command.slice(0, 200))
  try {
    const { runNativeTool } = await import('./integrations/native-tools.js')
    const result = await runNativeTool('console', command)
    res.json({
      success: result.success,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      code: result.code,
      error: result.error || null,
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Findings & Database Backup API ───────────────────────────────────────────
app.post('/api/backup/create', requireAuth, (req, res) => {
  const result = db.backupDatabase()
  audit(req.user.username, 'backup:create', result.backupFile || 'failed')
  if (result.success) {
    res.json({ ok: true, message: 'Database backup created successfully', file: result.backupFile })
  } else {
    res.status(500).json({ error: 'Failed to create backup' })
  }
})

app.get('/api/backup/export', requireAuth, (req, res) => {
  try {
    const findings = db.all(`SELECT * FROM findings ORDER BY created_at DESC`)
    const scans = db.all(`SELECT * FROM scans ORDER BY created_at DESC`)
    const projects = db.all(`SELECT * FROM projects ORDER BY created_at DESC`)
    const exportData = {
      exported_at: new Date().toISOString(),
      counts: { findings: findings.length, scans: scans.length, projects: projects.length },
      projects,
      scans,
      findings
    }
    res.setHeader('Content-Type', 'application/json')
    res.setHeader('Content-Disposition', `attachment; filename="sentinelai_findings_backup_${Date.now()}.json"`)
    res.send(JSON.stringify(exportData, null, 2))
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Finding notes
app.get('/api/findings/:id/notes', requireAuth, (req, res) => {
  res.json(db.all(`SELECT * FROM finding_notes WHERE finding_id = ? ORDER BY ts ASC`, req.params.id))
})
app.post('/api/findings/:id/notes', requireAuth, (req, res) => {
  const { note } = req.body || {}
  if (!note) return res.status(400).json({ error: 'note required' })
  const id = `note_${randomUUID()}`
  db.run(`INSERT INTO finding_notes (id, finding_id, author, note, ts) VALUES (?,?,?,?,?)`,
    id, req.params.id, req.user.username, note, new Date().toISOString())
  res.status(201).json(db.get(`SELECT * FROM finding_notes WHERE id = ?`, id))
})

// ── Monitors ─────────────────────────────────────────────────────────────────
app.get('/api/monitors', requireAuth, (req, res) => res.json(monitors.listMonitors()))
app.get('/api/monitors/:id', requireAuth, (req, res) => {
  const m = monitors.getMonitor(req.params.id)
  if (!m) return res.status(404).json({ error: 'not found' })
  res.json({ monitor: m, events: monitors.monitorEvents(m.id) })
})
app.post('/api/monitors', requireAuth, (req, res) => {
  const { name, target, targetType = 'url', intervalMin = 60, modules: mods = [] } = req.body || {}
  if (!name || !target) return res.status(400).json({ error: 'name and target required' })
  const m = monitors.createMonitor(pipeline, { name, target, targetType, intervalMin, modules: mods })
  audit(req.user.username, 'monitor:create', `${name} → ${target}`)
  res.status(201).json(m)
})
app.put('/api/monitors/:id', requireAuth, (req, res) => {
  const m = monitors.setEnabled(req.params.id, !!req.body.enabled, pipeline)
  res.json(m)
})
app.post('/api/monitors/:id/trigger', requireAuth, async (req, res) => {
  try {
    const result = await monitors.triggerNow(req.params.id, pipeline)
    audit(req.user.username, 'monitor:trigger', req.params.id)
    res.json(result)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})
app.delete('/api/monitors/:id', requireAuth, (req, res) => {
  const result = monitors.deleteMonitor(req.params.id)
  audit(req.user.username, 'monitor:delete', req.params.id)
  res.json(result)
})

// ── CVE lookup ───────────────────────────────────────────────────────────────
app.get('/api/cve/search', requireAuth, async (req, res) => {
  const out = await findVersionVulnerabilities(req.query.product, req.query.version)
  if (out.error) return res.status(400).json(out)
  res.json(out)
})

app.get('/api/cve/:id', requireAuth, async (req, res) => {
  const out = await getCve(req.params.id)
  if (out.error) return res.status(out.error.includes('not found') ? 404 : 502).json(out)
  res.json(out)
})

// ── Agents ───────────────────────────────────────────────────────────────────
app.get('/api/agents', requireAuth, (req, res) => res.json(agentRegistry.list()))
app.post('/api/agents/chat', requireAuth, async (req, res) => {
  const { message, agent = 'web-hunter', history = [] } = req.body || {}
  if (!message) return res.status(400).json({ error: 'message required' })
  try {
    const reply = await aiEngine.chat(message, agent, history)
    res.json({ reply, agent })
  } catch (e) {
    console.error('[Agent Chat Error]:', e.message)
    res.json({
      reply: `⚠️ AI Assistant is temporarily busy or rate-limited (${e.message}). Please wait a few seconds and try again.`,
      agent,
      error: e.message
    })
  }
})

app.post('/api/settings/ai', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  const { groq, groqModel, openrouter, openrouterModel, bandelbanget, bandelbangetModel } = req.body
  const envPath = new URL('../../.env', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1')
  
  let content = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : ''
  const updateEnv = (key, val) => {
    if (val === undefined) return
    const regex = new RegExp(`^\\s*${key}\\s*=.*$`, 'm')
    if (regex.test(content)) content = content.replace(regex, `${key}="${val}"`)
    else content += `\n${key}="${val}"`
    process.env[key] = val
  }
  
  updateEnv('GROQ_API_KEY', groq)
  updateEnv('GROQ_MODEL', groqModel)
  updateEnv('OPENROUTER_API_KEY', openrouter)
  updateEnv('OPENROUTER_MODEL', openrouterModel)
  updateEnv('BANDELBANGET_API_KEY', bandelbanget)
  updateEnv('BANDELBANGET_MODEL', bandelbangetModel)

  fs.writeFileSync(envPath, content.trim() + '\n')
  
  // Hot-reload config
  config.ai.groq.key = process.env.GROQ_API_KEY || ''
  config.ai.groq.model = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile'
  config.ai.openrouter.key = process.env.OPENROUTER_API_KEY || ''
  config.ai.openrouter.model = process.env.OPENROUTER_MODEL || 'deepseek/deepseek-r1-distill-qwen-32b:free'
  config.ai.bandelbanget.key = process.env.BANDELBANGET_API_KEY || ''
  config.ai.bandelbanget.model = process.env.BANDELBANGET_MODEL || 'deepseek-v4-pro'

  // Update llm client instance manually
  aiEngine.llm.groq = config.ai.groq
  aiEngine.llm.openrouter = config.ai.openrouter
  aiEngine.llm.bandelbanget = config.ai.bandelbanget

  res.json({ success: true })
})

app.post('/api/ai/test', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  const { provider, key, model } = req.body
  if (!key) return res.status(400).json({ error: 'Key is required to test' })
  
  let url = ''
  let headers = { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' }
  
  if (provider === 'groq') url = 'https://api.groq.com/openai/v1/chat/completions'
  else if (provider === 'openrouter') url = 'https://openrouter.ai/api/v1/chat/completions'
  else if (provider === 'bandelbanget') url = 'https://bandelbanget.xyz/v1/chat/completions'
  else return res.status(400).json({ error: 'Unknown provider' })

  try {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 8000)
    const reqLLM = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: model,
        messages: [{ role: 'user', content: 'Say hi! Keep it very short.' }]
      }),
      signal: ctrl.signal
    })
    clearTimeout(timer)
    
    const data = await reqLLM.json()
    if (!reqLLM.ok) throw new Error(data.error?.message || `HTTP ${reqLLM.status}`)
    const reply = data.choices?.[0]?.message?.content || JSON.stringify(data)
    res.json({ success: true, reply })
  } catch (e) {
    res.json({ success: false, error: e.message })
  }
})

app.get('/api/ai/providers', requireAuth, async (req, res) => {
  try {
    const health = await aiEngine.llm.checkProvidersHealth()
    res.json({
      configured: aiEngine.llm.isConfigured(),
      activeCount: health.filter(p => p.online).length,
      totalCount: health.length,
      providers: health,
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── RAG / payloads ───────────────────────────────────────────────────────────
app.get('/api/payloads/status', requireAuth, (req, res) => res.json(payloadsRag.payloadsIndexStatus()))
app.post('/api/payloads/reindex', requireAuth, (req, res) => {
  const r = payloadsRag.buildPayloadIndex()
  audit(req.user.username, 'payloads:reindex', `${r.indexed} docs`)
  res.json(r)
})
app.get('/api/payloads/search', requireAuth, (req, res) => {
  res.json(payloadsRag.retrievePayloads(req.query.q || '', { limit: Number(req.query.limit) || 6 }))
})

// ── AI Feedback Loop (Dynamic Self-Correction) ──────────────────────────────
app.get('/api/ai/feedback/:scanId', requireAuth, (req, res) => {
  try {
    const reviews = aiFeedbackLoop.getScanReviewHistory(req.params.scanId)
    const totalReviews = reviews.length
    const totalCorrections = reviews.filter(r => r.corrected).length
    const totalErrors = reviews.reduce((sum, r) => sum + (r.errors_found || 0), 0)
    res.json({
      totalReviews,
      totalCorrections,
      totalErrors,
      correctionRate: totalReviews ? Math.round((totalCorrections / totalReviews) * 100) : 0,
      reviews,
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.get('/api/ai/adjustments', requireAuth, (req, res) => {
  try {
    const adjustments = aiFeedbackLoop.getAdjustments(req.query.agent || null)
    // Group by agent for UI display
    const byAgent = {}
    for (const adj of adjustments) {
      if (!byAgent[adj.agent]) byAgent[adj.agent] = []
      byAgent[adj.agent].push(adj)
    }
    res.json({
      total: adjustments.length,
      byAgent,
      adjustments,
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.post('/api/ai/adjustments/:id/deactivate', requireAuth, (req, res) => {
  try {
    db.run(`UPDATE ai_prompt_adjustments SET active = 0 WHERE id = ?`, req.params.id)
    audit(req.user.username, 'ai:adjustment:deactivate', req.params.id)
    res.json({ ok: true })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Engine (hexstrike) ───────────────────────────────────────────────────────
app.get('/api/engine/status', requireAuth, async (req, res) => res.json(await hexstrike.engineStatus(true)))
app.post('/api/engine/analyze', requireAuth, async (req, res) => res.json(await hexstrike.analyzeTarget(req.body.target)))
app.post('/api/engine/attack-chain', requireAuth, async (req, res) => res.json(await hexstrike.attackChain(req.body.target, req.body.objective)))

// ── Reports ──────────────────────────────────────────────────────────────────
app.post('/api/reports/generate', requireAuth, async (req, res) => {
  try {
    const reportType = req.body.reportType === 'simple' ? 'simple' : 'full'
    const { scanId, minSeverity, statusFilter, customTitle, customSummary, customScope, customConclusion, filterNoise } = req.body
    const r = await generateReport(scanId, minSeverity || 'info', statusFilter || 'all', reportType, { customTitle, customSummary, customScope, customConclusion, filterNoise })
    audit(req.user.username, 'report:generate', `${scanId} (type: ${reportType}, min: ${minSeverity || 'info'}, status: ${statusFilter || 'all'}, filterNoise: ${!!filterNoise})`)
    res.json({ ok: true, file: r.file, riskScore: r.riskScore, counts: r.counts, dropped: r.dropped })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/reports/download/:scanId', requireAuth, (req, res) => {
  const file = `${config.outputDir}/report-${req.params.scanId}.pdf`
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'report not generated' })
  res.download(file)
})

app.post('/api/scans/:id/audio-briefing', requireAuth, async (req, res) => {
  try {
    const scan = db.get(`SELECT * FROM scans WHERE id = ?`, req.params.id)
    if (!scan) return res.status(404).json({ error: 'Scan not found' })

    const findings = db.all(`SELECT title, severity, cwe_id FROM findings WHERE scan_id = ? ORDER BY id DESC LIMIT 10`, scan.id)
    const totalCount = findings.length
    const critCount = findings.filter(f => f.severity === 'critical').length
    const highCount = findings.filter(f => f.severity === 'high').length

    // Generate concise summary text using AI
    const prompt = `Write a concise 2-sentence executive audio script summarizing pentest results for target "${scan.target}". Total findings: ${totalCount}, Critical: ${critCount}, High: ${highCount}. Key findings: ${findings.slice(0, 3).map(f => f.title).join(', ')}. Keep it clear, professional, and under 40 words.`
    
    let textSummary = ''
    try {
      textSummary = await aiEngine.chat(prompt, 'report-generator')
    } catch {
      textSummary = `Sentinel AI Security Briefing for ${scan.target}. Imbasan telah selesai. Sebanyak ${totalCount} kerentanan dijumpai, termasuk ${critCount} kritikal dan ${highCount} berisiko tinggi.`
    }
    
    // Clean markdown stars/formatting for clean TTS reading
    const cleanText = textSummary.replace(/[\*\_`#]/g, '').trim()

    // Call OpenRouter TTS with Fish Audio model
    const openrouterKey = config.ai.openrouter?.key
    if (!openrouterKey) {
      return res.json({ text: cleanText, audioUrl: null, note: 'OpenRouter API key required for Fish Audio TTS' })
    }

    const ttsRes = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${openrouterKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://sentinelai.studio',
        'X-Title': 'FYP2 Sentinel AI',
      },
      body: JSON.stringify({
        model: 'fish-audio/s2.1-pro-free:free',
        messages: [{ role: 'user', content: cleanText }],
      })
    })

    if (!ttsRes.ok) {
      const errBody = await ttsRes.text()
      return res.json({ text: cleanText, audioUrl: null, error: `Fish Audio API (${ttsRes.status}): ${errBody}` })
    }

    const ttsData = await ttsRes.json()
    // OpenRouter returns audio response either as audio_url or message content with audio format
    const audioContent = ttsData.choices?.[0]?.message?.content || ttsData.audio_url || null

    res.json({
      text: cleanText,
      audio: audioContent,
      model: 'fish-audio/s2.1-pro-free:free'
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Exploitation Engine ──────────────────────────────────────────────────────

// MSF RPC status
app.get('/api/exploits/msf/status', requireAuth, async (req, res) => {
  res.json(await msf.status())
})

// List active MSF sessions
app.get('/api/exploits/msf/sessions', requireAuth, async (req, res) => {
  res.json(await msf.listSessions())
})

// Get a specific MSF session
app.get('/api/exploits/msf/sessions/:id', requireAuth, async (req, res) => {
  const s = await msf.sessionInfo(req.params.id)
  if (!s) return res.status(404).json({ error: 'session not found' })
  res.json(s)
})

// Run a command in an MSF session
app.post('/api/exploits/msf/sessions/:id/command', requireAuth, async (req, res) => {
  const { command } = req.body || {}
  if (!command) return res.status(400).json({ error: 'command required' })
  const result = await msf.shellCommand(req.params.id, command)
  res.json(result)
})

// Kill an MSF session
app.delete('/api/exploits/msf/sessions/:id', requireAuth, async (req, res) => {
  res.json(await msf.stopSession(req.params.id))
})

// List all exploit campaigns
app.get('/api/exploits/campaigns', requireAuth, (req, res) => {
  const campaigns = db.all(`
    SELECT ec.*, f.title AS finding_title, f.severity AS finding_severity, s.target AS scan_target
    FROM exploit_campaigns ec
    LEFT JOIN findings f ON f.id = ec.finding_id
    LEFT JOIN scans s ON s.id = ec.scan_id
    ORDER BY ec.created_at DESC LIMIT 200
  `)
  res.json(campaigns)
})

// Get a specific campaign with steps & loot
app.get('/api/exploits/campaigns/:id', requireAuth, (req, res) => {
  const campaign = db.get(`
    SELECT ec.*, f.title AS finding_title, f.severity AS finding_severity, s.target AS scan_target
    FROM exploit_campaigns ec
    LEFT JOIN findings f ON f.id = ec.finding_id
    LEFT JOIN scans s ON s.id = ec.scan_id
    WHERE ec.id = ?
  `, req.params.id)
  if (!campaign) return res.status(404).json({ error: 'campaign not found' })

  const steps = db.all(`SELECT * FROM exploit_steps WHERE campaign_id = ? ORDER BY step_order ASC`, req.params.id)
  const loot = db.all(`SELECT * FROM exploit_loot WHERE campaign_id = ? ORDER BY created_at DESC`, req.params.id)
  const approvals = db.all(`SELECT * FROM exploit_approvals WHERE campaign_id = ? ORDER BY created_at DESC`, req.params.id)

  res.json({ campaign, steps, loot, approvals })
})

// Launch an exploitation campaign for a finding
app.post('/api/exploits/campaigns', requireAuth, async (req, res) => {
  const { scanId, findingId } = req.body || {}
  if (!findingId) return res.status(400).json({ error: 'findingId required' })

  const finding = db.get(`SELECT * FROM findings WHERE id = ?`, findingId)
  if (!finding) return res.status(404).json({ error: 'finding not found' })

  // Auto-resolve scanId from finding if not provided
  const resolvedScanId = scanId || finding.scan_id
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, resolvedScanId)
  if (!scan) return res.status(404).json({ error: 'scan not found' })

  // Check if a campaign already exists for this finding
  const existing = db.get(
    `SELECT * FROM exploit_campaigns WHERE finding_id = ? AND status NOT IN ('aborted', 'failed') ORDER BY created_at DESC LIMIT 1`,
    findingId
  )
  if (existing) {
    // Return existing campaign
    const steps = db.all(`SELECT * FROM exploit_steps WHERE campaign_id = ? ORDER BY step_order ASC`, existing.id)
    const loot = db.all(`SELECT * FROM exploit_loot WHERE campaign_id = ? ORDER BY created_at DESC`, existing.id)
    const approvals = db.all(`SELECT * FROM exploit_approvals WHERE campaign_id = ? ORDER BY created_at DESC`, existing.id)
    return res.json({
      campaign: existing, steps, loot, approvals,
      alreadyExists: true,
      matchedExploits: matchExploits(finding).length,
      risk: classifyRisk(finding),
    })
  }

  const result = await exploitEngine.launchCampaign(scan, finding)
  audit(req.user.username, 'exploit:launch', `${finding.title} → ${result.campaignId || 'no_match'}`)

  // Fetch the full campaign data so the frontend can render it immediately
  const campaignId = result.campaignId
  if (campaignId) {
    const campaign = db.get(`SELECT * FROM exploit_campaigns WHERE id = ?`, campaignId)
    const steps = db.all(`SELECT * FROM exploit_steps WHERE campaign_id = ? ORDER BY step_order ASC`, campaignId)
    const loot = db.all(`SELECT * FROM exploit_loot WHERE campaign_id = ? ORDER BY created_at DESC`, campaignId)
    const approvals = db.all(`SELECT * FROM exploit_approvals WHERE campaign_id = ? ORDER BY created_at DESC`, campaignId)
    return res.status(201).json({
      campaign, steps, loot, approvals,
      campaignId,
      status: result.status,
      matchedExploits: matchExploits(finding).length,
      risk: classifyRisk(finding),
    })
  }

  res.status(201).json({
    ...result,
    matchedExploits: matchExploits(finding).length,
    risk: classifyRisk(finding),
  })
})

// Approve a gated exploit step
app.post('/api/exploits/campaigns/:campaignId/approve', requireAuth, async (req, res) => {
  const { stepId } = req.body || {}
  if (!stepId) return res.status(400).json({ error: 'stepId required' })

  try {
    await exploitEngine.approveStep(req.params.campaignId, stepId, req.user.username)
    audit(req.user.username, 'exploit:approve', `${req.params.campaignId}/${stepId}`)
    res.json({ ok: true })
  } catch (e) {
    console.error(`[exploit:approve] ${req.params.campaignId}/${stepId} failed:`, e)
    res.status(500).json({ error: e.message || 'Approval failed' })
  }
})

// Deny a gated exploit step
app.post('/api/exploits/campaigns/:campaignId/deny', requireAuth, async (req, res) => {
  const { stepId } = req.body || {}
  if (!stepId) return res.status(400).json({ error: 'stepId required' })

  try {
    await exploitEngine.denyStep(req.params.campaignId, stepId, req.user.username)
    audit(req.user.username, 'exploit:deny', `${req.params.campaignId}/${stepId}`)
    res.json({ ok: true })
  } catch (e) {
    console.error(`[exploit:deny] ${req.params.campaignId}/${stepId} failed:`, e)
    res.status(500).json({ error: e.message || 'Denial failed' })
  }
})

// Pause a campaign
app.post('/api/exploits/campaigns/:campaignId/pause', requireAuth, (req, res) => {
  exploitEngine.pauseCampaign(req.params.campaignId)
  db.run(`UPDATE exploit_campaigns SET status = 'paused' WHERE id = ?`, req.params.campaignId)
  audit(req.user.username, 'exploit:pause', req.params.campaignId)
  res.json({ ok: true })
})

// Resume a campaign
app.post('/api/exploits/campaigns/:campaignId/resume', requireAuth, (req, res) => {
  exploitEngine.resumeCampaign(req.params.campaignId)
  db.run(`UPDATE exploit_campaigns SET status = 'running' WHERE id = ?`, req.params.campaignId)
  audit(req.user.username, 'exploit:resume', req.params.campaignId)
  res.json({ ok: true })
  // Resume execution
  exploitEngine.executeCampaign(req.params.campaignId)
})

// Abort a campaign
app.post('/api/exploits/campaigns/:campaignId/abort', requireAuth, (req, res) => {
  db.run(`UPDATE exploit_campaigns SET status = 'aborted', finished_at = ? WHERE id = ?`,
    new Date().toISOString(), req.params.campaignId)
  audit(req.user.username, 'exploit:abort', req.params.campaignId)
  res.json({ ok: true })
})

// Check if a finding is exploitable (dry-run)
app.post('/api/exploits/check', requireAuth, (req, res) => {
  const { findingId } = req.body || {}
  if (!findingId) return res.status(400).json({ error: 'findingId required' })

  const finding = db.get(`SELECT * FROM findings WHERE id = ?`, findingId)
  if (!finding) return res.status(404).json({ error: 'finding not found' })

  const matches = matchExploits(finding)
  const risk = classifyRisk(finding)

  res.json({
    exploitable: matches.length > 0,
    matchCount: matches.length,
    risk,
    strategies: matches.map(m => ({
      id: m.id,
      risk: m.risk,
      techniqueCount: m.techniques.length,
      postExploit: m.postExploit,
    })),
  })
})

// ── Audit Logs ────────────────────────────────────────────────────────────────
app.get('/api/audit', requireAuth, (req, res) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  const limit = Math.min(Number(req.query.limit) || 50, 200)
  const logs = db.all(`SELECT * FROM audit ORDER BY id DESC LIMIT ?`, limit)
  res.json(logs)
})

// ── GitHub Automation & Repository Management ─────────────────────────────────

// Get user's connected GitHub integration status
app.get('/api/github/status', requireAuth, (req, res) => {
  const integration = db.get(`SELECT id, github_username, avatar_url, created_at, updated_at FROM github_integrations WHERE user_id = ?`, req.user.id)
  const trackedCount = db.get(`SELECT COUNT(*) c FROM github_repos WHERE user_id = ?`, req.user.id)?.c || 0
  res.json({
    connected: !!integration,
    integration: integration || null,
    trackedReposCount: trackedCount,
  })
})

// Connect GitHub account using Personal Access Token (PAT) or OAuth token
app.post('/api/github/connect', requireAuth, async (req, res) => {
  const { token } = req.body || {}
  if (!token || !token.trim()) return res.status(400).json({ error: 'GitHub Personal Access Token is required' })

  try {
    const client = new GitHubClient(token.trim())
    const profile = await client.verifyToken()
    
    const now = new Date().toISOString()
    const existing = db.get(`SELECT id FROM github_integrations WHERE user_id = ?`, req.user.id)
    if (existing) {
      db.run(
        `UPDATE github_integrations SET github_username = ?, access_token = ?, avatar_url = ?, updated_at = ? WHERE user_id = ?`,
        profile.login, token.trim(), profile.avatar_url, now, req.user.id
      )
    } else {
      const id = `gh_${randomUUID().slice(0, 12)}`
      db.run(
        `INSERT INTO github_integrations (id, user_id, github_username, access_token, avatar_url, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        id, req.user.id, profile.login, token.trim(), profile.avatar_url, now, now
      )
    }

    audit(req.user.username, 'github:connect', `Linked GitHub user @${profile.login}`)
    res.json({ success: true, profile })
  } catch (err) {
    res.status(400).json({ error: `GitHub Verification Failed: ${err.message}` })
  }
})

// Disconnect GitHub integration
app.delete('/api/github/disconnect', requireAuth, (req, res) => {
  db.run(`DELETE FROM github_integrations WHERE user_id = ?`, req.user.id)
  audit(req.user.username, 'github:disconnect', 'Unlinked GitHub account')
  res.json({ success: true })
})

// List user's GitHub repositories and merge tracking state
app.get('/api/github/repos', requireAuth, async (req, res) => {
  const integration = db.get(`SELECT access_token FROM github_integrations WHERE user_id = ?`, req.user.id)
  if (!integration) return res.status(400).json({ error: 'GitHub is not connected yet. Please connect your GitHub account.' })

  try {
    const client = new GitHubClient(integration.access_token)
    const remoteRepos = await client.listRepositories(1, 100)
    const trackedRows = db.all(`SELECT * FROM github_repos WHERE user_id = ?`, req.user.id)
    const trackedMap = new Map(trackedRows.map(r => [r.full_name, r]))

    const merged = remoteRepos.map(repo => {
      const tracked = trackedMap.get(repo.full_name)
      return {
        ...repo,
        isTracked: !!tracked,
        autoScanPush: tracked ? !!tracked.auto_scan_push : false,
        autoScanPr: tracked ? !!tracked.auto_scan_pr : false,
        emailReport: tracked ? !!tracked.email_report : true,
        lastScanId: tracked?.last_scan_id || null,
        lastScanAt: tracked?.last_scan_at || null,
        lastRiskScore: tracked?.last_risk_score ?? null,
      }
    })

    res.json({ repos: merged, total: merged.length })
  } catch (err) {
    res.status(500).json({ error: `Failed to fetch repositories: ${err.message}` })
  }
})

// Track / configure continuous automation settings for a repository
app.post('/api/github/repos/track', requireAuth, (req, res) => {
  const { repoFullName, repoUrl, defaultBranch = 'main', isPrivate = false, isTracked = true, autoScanPush = 1, autoScanPr = 1, emailReport = 1 } = req.body || {}
  if (!repoFullName) return res.status(400).json({ error: 'repoFullName required' })

  const now = new Date().toISOString()
  const existing = db.get(`SELECT id FROM github_repos WHERE user_id = ? AND full_name = ?`, req.user.id, repoFullName)

  if (!isTracked) {
    if (existing) db.run(`DELETE FROM github_repos WHERE id = ?`, existing.id)
    return res.json({ success: true, isTracked: false })
  }

  if (existing) {
    db.run(
      `UPDATE github_repos SET auto_scan_push = ?, auto_scan_pr = ?, email_report = ?, updated_at = ? WHERE id = ?`,
      autoScanPush ? 1 : 0, autoScanPr ? 1 : 0, emailReport ? 1 : 0, now, existing.id
    )
  } else {
    const id = `ghr_${randomUUID().slice(0, 12)}`
    db.run(
      `INSERT INTO github_repos (id, user_id, full_name, repo_url, default_branch, is_private, auto_scan_push, auto_scan_pr, email_report, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id, req.user.id, repoFullName, repoUrl || `https://github.com/${repoFullName}`, defaultBranch, isPrivate ? 1 : 0, autoScanPush ? 1 : 0, autoScanPr ? 1 : 0, emailReport ? 1 : 0, now, now
    )
  }

  res.json({ success: true, isTracked: true })
})

// Trigger immediate code audit pull & scan for a GitHub repository
app.post('/api/github/scan', requireAuth, async (req, res) => {
  const { repoFullName, branch = 'main' } = req.body || {}
  if (!repoFullName) return res.status(400).json({ error: 'repoFullName required' })

  // 1. Quota Verification & Consumption
  try {
    consumeScanQuota(req.user.id)
  } catch (quotaErr) {
    return res.status(402).json({ error: quotaErr.message, upgradeRequired: true })
  }

  const integration = db.get(`SELECT access_token FROM github_integrations WHERE user_id = ?`, req.user.id)
  if (!integration) return res.status(400).json({ error: 'GitHub is not connected' })

  const [owner, repo] = repoFullName.split('/')
  if (!owner || !repo) return res.status(400).json({ error: 'Invalid repoFullName format (expected owner/repo)' })

  try {
    const client = new GitHubClient(integration.access_token)
    const repoBundle = await client.fetchRepoSourceFiles(owner, repo, branch)

    if (!repoBundle.fileList.length) {
      return res.status(400).json({ error: 'No auditable source code files found in repository' })
    }

    const scanId = `scan_${randomUUID()}`
    const now = new Date().toISOString()
    const target = `github:${repoFullName}#${branch}`

    db.run(
      `INSERT INTO scans (id, target, target_type, mode, status, template, modules, progress, created_at, started_at, trigger_source, repo_name, commit_hash, email_notify)
       VALUES (?, ?, 'code', 'whitebox', 'running', 'standard', '[]', 0, ?, ?, 'github_manual', ?, ?, ?)`,
      scanId, target, now, now, repoFullName, repoBundle.commitSha, req.user.email || null
    )

    // Update tracked repo last scan info
    db.run(
      `UPDATE github_repos SET last_scan_id = ?, last_scan_at = ? WHERE user_id = ? AND full_name = ?`,
      scanId, now, req.user.id, repoFullName
    )

    const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
    audit(req.user.username, 'github:scan', `Started whitebox audit on ${repoFullName} (${repoBundle.filesCount} files)`)

    // Asynchronously run whitebox security pipeline
    const syntheticFiles = [{ path: `repository/${repoFullName}`, content: repoBundle.consolidatedSource }]
    setImmediate(async () => {
      try {
        await pipeline.runWhitebox(scan, { files: syntheticFiles, language: '', focus: 'OWASP Top 10 Security & Secrets Audit', verify: true })
      } catch (err) {
        pipeline.log(scanId, 'error', `GitHub scan error: ${err.message}`)
        pipeline.finish(scanId, 'failed')
      }
    })

    res.status(201).json({
      success: true,
      scanId,
      filesCount: repoBundle.filesCount,
      commitSha: repoBundle.commitSha,
      scan,
    })
  } catch (err) {
    res.status(500).json({ error: `GitHub scan ingestion failed: ${err.message}` })
  }
})

// Public GitHub Webhook endpoint for Push & PR automated triggers
app.post('/api/github/webhook', async (req, res) => {
  const eventHeader = req.headers['x-github-event'] || 'push'
  const event = parseGitHubWebhook(eventHeader, req.body)

  if (!event) {
    return res.status(200).json({ ok: true, message: 'Event ignored' })
  }

  const tracked = db.get(`SELECT * FROM github_repos WHERE full_name = ?`, event.repoFullName)
  if (!tracked) {
    return res.status(200).json({ ok: true, message: 'Repository not tracked' })
  }

  const shouldScan = (event.type === 'push' && tracked.auto_scan_push) || (event.type === 'pull_request' && tracked.auto_scan_pr)
  if (!shouldScan) {
    return res.status(200).json({ ok: true, message: 'Automation disabled for this event type' })
  }

  const integration = db.get(`SELECT * FROM github_integrations WHERE user_id = ?`, tracked.user_id)
  if (!integration) {
    return res.status(200).json({ ok: true, message: 'Integration token missing for user' })
  }

  // Consume scan quota for the repo owner
  try {
    consumeScanQuota(tracked.user_id)
  } catch (quotaErr) {
    console.warn(`[webhook] Quota exceeded for user ${tracked.user_id}: ${quotaErr.message}`)
    return res.status(200).json({ ok: false, error: quotaErr.message })
  }

  const [owner, repo] = event.repoFullName.split('/')
  setImmediate(async () => {
    try {
      const client = new GitHubClient(integration.access_token)
      const repoBundle = await client.fetchRepoSourceFiles(owner, repo, event.branch || 'main')
      
      const scanId = `scan_${randomUUID()}`
      const now = new Date().toISOString()
      const user = db.get(`SELECT email FROM users WHERE id = ?`, tracked.user_id)
      const emailNotify = tracked.email_report ? (user?.email || event.authorEmail) : null

      db.run(
        `INSERT INTO scans (id, target, target_type, mode, status, template, modules, progress, created_at, started_at, trigger_source, repo_name, commit_hash, email_notify)
         VALUES (?, ?, 'code', 'whitebox', 'running', 'standard', '[]', 0, ?, ?, ?, ?, ?, ?)`,
        scanId, `github:${event.repoFullName}#${event.branch}`, now, now, `github_${event.type}`, event.repoFullName, event.commitHash, emailNotify
      )

      db.run(
        `UPDATE github_repos SET last_scan_id = ?, last_scan_at = ? WHERE id = ?`,
        scanId, now, tracked.id
      )

      const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
      const syntheticFiles = [{ path: `repository/${event.repoFullName}`, content: repoBundle.consolidatedSource }]
      await pipeline.runWhitebox(scan, { files: syntheticFiles, language: '', focus: 'OWASP Top 10 & Vulnerability Code Review', verify: true })
    } catch (err) {
      console.error(`[webhook] Background automated scan failed:`, err.message)
    }
  })

  res.status(202).json({ success: true, message: `Queued automated audit for ${event.repoFullName} (${event.type})` })
})

// ── Billing & Subscriptions API ───────────────────────────────────────────────

// Get all subscription plans
app.get('/api/billing/plans', (req, res) => {
  res.json({ plans: Object.values(PLANS) })
})

// Get current user subscription & quota status
app.get('/api/billing/subscription', requireAuth, (req, res) => {
  const sub = getUserSubscription(req.user.id)
  res.json(sub)
})

// Create checkout / Upgrade subscription plan
app.post('/api/billing/checkout', requireAuth, (req, res) => {
  const { planId, billingInterval = 'monthly', provider = 'stripe' } = req.body || {}
  if (!planId || !PLANS[planId]) return res.status(400).json({ error: 'Valid planId is required' })

  const plan = PLANS[planId]
  const amount = billingInterval === 'yearly' ? plan.priceYearly : plan.priceMonthly

  // For testing / simulation or instant activation:
  const updatedSub = activateSubscription({
    userId: req.user.id,
    planId,
    amount,
    provider,
    referenceId: `ch_${randomUUID().slice(0, 16)}`,
  })

  audit(req.user.username, 'billing:upgrade', `Subscribed to ${plan.name} ($${amount})`)
  res.json({
    success: true,
    message: `Successfully upgraded to ${plan.name}`,
    subscription: updatedSub,
  })
})

// Payment transaction history
app.get('/api/billing/history', requireAuth, (req, res) => {
  const history = getPaymentHistory(req.user.id)
  res.json({ transactions: history })
})

// ── Dashboard ────────────────────────────────────────────────────────────────
app.get('/api/dashboard', requireAuth, (req, res) => {
  const scans = db.all(`SELECT * FROM scans ORDER BY created_at DESC`)
  const findings = db.all(`SELECT severity FROM findings`)
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
  const recent = scans.slice(0, 8)
  res.json({
    totals: { projects: db.get(`SELECT COUNT(*) c FROM projects`).c, scans: scans.length, findings: findings.length },
    severity: counts,
    recentScans: recent,
    runningScans: scans.filter(s => s.status === 'running').length,
  })
})

// ── WebSocket ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  socket.on('scan:subscribe', (scanId) => { if (scanId) socket.join(`scan:${scanId}`) })
  socket.on('scan:unsubscribe', (scanId) => { if (scanId) socket.leave(`scan:${scanId}`) })
  socket.on('exploit:subscribe', (campaignId) => { if (campaignId) socket.join(`exploit:${campaignId}`) })
  socket.on('exploit:unsubscribe', (campaignId) => { if (campaignId) socket.leave(`exploit:${campaignId}`) })
})

const PORT = config.port
server.listen(PORT, () => {
  console.log(`\n[FYP2] Unified Pentest Platform backend listening on http://localhost:${PORT}`)
  console.log(`[FYP2] Hexstrike engine: ${config.hexstrike.url} (${config.hexstrike.enabled ? 'enabled' : 'disabled'})`)
  console.log(`[FYP2] Agents: ${agentRegistry.list().length} | RAG docs: ${payloadsRag.payloadsIndexStatus().docs}`)
})

process.on('uncaughtException', (err) => {
  console.error('[FYP2 Backend uncaughtException]:', err?.message || err)
})
process.on('unhandledRejection', (reason) => {
  console.error('[FYP2 Backend unhandledRejection]:', reason?.message || reason)
})
