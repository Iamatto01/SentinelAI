import http from 'node:http'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import { Server as SocketIOServer } from 'socket.io'
import { randomUUID, createHmac, timingSafeEqual } from 'node:crypto'
import bcrypt from 'bcryptjs'
import fs from 'node:fs'

import { config } from './config.js'
import * as db from './db.js'
import { authMiddleware, requireAuth, signToken, getUser } from './auth.js'
import { requireRole } from './auth.js'
import * as kaliControl from './kali-control.js'
import { UnifiedPipeline } from './pipeline.js'
import { getOwaspToolMapList, blackboxModulesForCategories, whiteboxPassesForCategories } from './owasp-tools.js'
import { getAllScripts, getScript, createScript, updateScript, deleteScript, runCustomScript } from './custom-scripts.js'
import { payloadsRag, skillsRag } from './integrations/index.js'
import { nativeToolsStatus } from './integrations/native-tools.js'
import { agentRegistry } from './ai/agent-registry.js'
import { aiEngine } from './ai/ai-engine.js'
import { generateReport } from './report.js'
import { getCve, findVersionVulnerabilities } from './cve.js'
import * as monitors from './monitor-scheduler.js'
import swaggerUi from 'swagger-ui-express'
import { openapiSpec } from './openapi.js'
import { walkProjects } from './folder-walker.js'
import { ExploitOrchestrator } from './exploits/orchestrator.js'
import * as msf from './exploits/msf-client.js'
import { matchExploits, classifyRisk } from './exploits/registry.js'
import { sendScanRequestNotification, sendAnonymousFeedbackNotification, sendConsultationBookingNotification } from './email.js'
import { GitHubClient, parseGitHubWebhook } from './integrations/github.js'
import {
  PLANS,
  getAllPlans,
  getPlan,
  createPlan,
  updatePlan,
  togglePlanStatus,
  deletePlan,
  getAllPromoCodes,
  getPromoCode,
  createPromoCode,
  updatePromoCode,
  togglePromoCodeStatus,
  deletePromoCode,
  validatePromoCode,
  getUserSubscription,
  consumeScanQuota,
  activateSubscription,
  getPaymentHistory
} from './billing.js'
import { createStripeCheckoutSession, verifyAndFulfillSession, getStripe } from './stripe.js'
import { channelGateway } from './channels/index.js'

// CORS: only whitelisted origins (config.corsOrigins from CLIENT_ORIGIN).
// Non-browser clients (curl, server-to-server) carry no Origin header → allowed.
// Local frontend on any localhost/127.0.0.1 port (vite dev 517x, preview 417x) is always allowed —
// the backend itself binds to localhost, so this never widens remote attack surface.
// Private LAN origins (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are allowed so the
// Kali box can be accessed from any machine on the home/lab network.
const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/
const LAN_ORIGIN_RE = /^https?:\/\/(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?$/
const corsOptions = {
  origin(origin, cb) {
    // Exact-suffix match on the apex domain or any subdomain — anchored so
    // "evilsentinelai.studio" cannot pass as sentinelai.studio.
    const isSentinelHost = /^https?:\/\/([a-z0-9-]+\.)*sentinelai\.studio(:\d+)?$/i.test(origin)
    if (!origin || config.corsOrigins.includes(origin) || isSentinelHost || LOCAL_ORIGIN_RE.test(origin) || LAN_ORIGIN_RE.test(origin)) return cb(null, true)
    return cb(new Error(`CORS blocked: ${origin}`))
  },
  credentials: true,
}

const app = express()
app.set('trust proxy', 1)
app.disable('x-powered-by')
// CORS note: LAN origins allowed via LAN_ORIGIN_RE above.
app.use(express.json({ limit: '10mb', verify: (req, res, buf) => { req.rawBody = buf } }))
app.use(cors(corsOptions))
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; font-src 'self' https: data:; connect-src 'self' https: wss: ws:; frame-ancestors 'none';")
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

// Mark scans interrupted by server restart as failed (do NOT auto-resume).
// Auto-resume corrupts state: pipeline holds in-memory per-scan state (collected URLs,
// progress, pause/stop control flags) that is lost on restart. Re-running from scratch with
// the same scanId duplicates findings and confuses the UI. Instead, mark as 'interrupted'
// with a clear log entry so the user can manually re-launch.
try {
  const interruptedScans = db.all(`SELECT * FROM scans WHERE status IN ('running','paused','queued')`)
  if (interruptedScans.length > 0) {
    console.log(`[bootstrap] Found ${interruptedScans.length} interrupted scan(s). Marking as failed (manual restart required)...`)
    const ts = new Date().toISOString()
    for (const scan of interruptedScans) {
      db.run(`UPDATE scans SET status = 'failed', finished_at = ? WHERE id = ?`, ts, scan.id)
      db.run(`INSERT INTO logs (scan_id, level, message, ts) VALUES (?,?,?,?)`,
        scan.id, 'warn', '⏸ Scan interrupted by server restart. Please start a new scan — state was not preserved.', ts)
    }
  }
} catch (e) { console.warn('[bootstrap] Interrupted scan recovery notice:', e.message) }

// seed admin — create kali@sentinelai.com if no admin user exists
// NEVER reset passwords on restart: that would silently revert every password change.
const adminUser = db.get(`SELECT * FROM users WHERE role = 'admin' LIMIT 1`)
if (!adminUser) {
  db.run(`INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?)`,
    `usr_${randomUUID()}`, 'kali', 'kali@sentinelai.com', bcrypt.hashSync(config.defaultAdminPassword, 10), 'admin', new Date().toISOString())
  console.log('[bootstrap] default admin user created (kali@sentinelai.com)')
} else {
  console.log(`[bootstrap] admin user already exists: ${adminUser.email}`)
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

// build cybersecurity skills index if empty
try {
  const st = skillsRag.skillsIndexStatus()
  if (st.installed && st.skills === 0) {
    console.log('[bootstrap] building Cybersecurity Skills index (817-skill corpus)...')
    const r = skillsRag.buildSkillsIndex((lvl, msg) => console.log(`[skills-rag] ${msg}`))
    console.log(`[bootstrap] skills index ready: ${r.indexed} skills`)
    const cat = skillsRag.writeSkillsCatalog()
    if (cat.written) console.log(`[bootstrap] skills catalog written: ${cat.count} entries -> ${cat.path}`)
  }
} catch (e) { console.warn('[bootstrap] skills index build skipped:', e.message) }

const audit = (actor, action, detail) =>
  db.run(`INSERT INTO audit (actor, action, detail, ts) VALUES (?,?,?,?)`, actor || 'system', action, detail || '', new Date().toISOString())

/** Client-portal users may only touch their own project's data. */
const requireStaff = (req, res, next) => {
  if (req.user?.role === 'client') return res.status(403).json({ error: 'client accounts cannot access this resource' })
  next()
}

/** Resolve the project IDs a client-portal user may see; null = unrestricted (staff). */
function visibleProjectIds(user) {
  if (user?.role !== 'client') return null
  if (user.projectId) return [user.projectId]
  const userEmail = (user.email || '').toLowerCase().trim()
  const username = (user.username || '').toLowerCase().trim()
  // STRICT matching only: exact email/username equality against the project's
  // client field, or direct ownership. Substring matching was spoofable — a user
  // could set their email to any substring of another project's client string.
  const allProjs = db.all(`SELECT id, client, name, user_id, client_id FROM projects`)
  const ids = allProjs
    .filter((p) => {
      if (p.user_id && p.user_id === user.id) return true
      if (p.client_id && p.client_id === user.id) return true
      const c = (p.client || '').toLowerCase().trim()
      return (userEmail && c === userEmail) || (username && c === username)
    })
    .map((p) => p.id)

  if (userEmail) {
    const creds = db.all(`SELECT project_id FROM client_credentials WHERE LOWER(email) = ?`, userEmail)
    for (const cr of creds) {
      if (cr.project_id && !ids.includes(cr.project_id)) ids.push(cr.project_id)
    }
  }
  return ids.length ? ids : []
}

/** Guard a single existing project row: staff always pass; clients must own it. */
function canAccessProject(user, project) {
  if (!project) return false
  if (user?.role !== 'client') return true
  if (user.projectId && user.projectId === project.id) return true
  if (project.user_id && project.user_id === user.id) return true
  if (project.client_id && project.client_id === user.id) return true
  const userEmail = (user.email || '').toLowerCase().trim()
  const username = (user.username || '').toLowerCase().trim()
  const c = (project.client || '').toLowerCase().trim()
  return Boolean((userEmail && c === userEmail) || (username && c === username))
}

/** Guard a scan-scoped request: 404 unless the scan belongs to the client or their project. */
function requireScanAccess(req, res, next) {
  if (req.user?.role !== 'client') return next()
  const scanId = req.params.id || req.params.scanId || req.body?.scanId
  const scan = db.get(`SELECT id, project_id, user_id, client FROM scans WHERE id = ?`, scanId)
  if (!scan) return res.status(404).json({ error: 'not found' })
  
  // 1. If scan was created directly by this client
  if (scan.user_id && scan.user_id === req.user.id) return next()
  if (scan.client && (scan.client.toLowerCase() === (req.user.username || '').toLowerCase() || scan.client.toLowerCase() === (req.user.email || '').toLowerCase())) return next()

  // 2. If scan belongs to an authorized client project
  const allowed = visibleProjectIds(req.user)
  if (allowed && scan.project_id && allowed.includes(scan.project_id)) return next()

  return res.status(404).json({ error: 'not found' })
}

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
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString(), agentsCount: agentRegistry.list().length }))
app.get('/api/public/stats', (req, res) => {
  res.json({
    agentsCount: agentRegistry.list().length,
    toolsCount: 150,
    ragDocsCount: payloadsRag.payloadsIndexStatus().docs || 10000,
  })
})
app.get('/api/public/agents', (req, res) => {
  res.json(agentRegistry.list())
})

app.get('/api/status', requireAuth, async (req, res) => {
  const tools = await nativeToolsStatus()
  const available = Object.values(tools).filter(Boolean).length
  const total = Object.keys(tools).length
  const engine = {
    ok: available > 0,
    available: available > 0,
    engine: 'native',
    toolsAvailable: available,
    totalToolsAvailable: available,
    totalTools: total,
    tools,
  }
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
// Enterprise Brute-force protection: 10 attempts / 15 min per real client IP.
// Uses the library's DEFAULT keying (= req.ip, with IPv6 subnet bucketing).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts — please wait 15 minutes before trying again.' },
})

// Strict RFC 5322 standard regex for email validation
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

// Enterprise password validation: min 4 chars
function validatePasswordComplexity(pass) {
  if (!pass || typeof pass !== 'string') return 'Password is required'
  if (pass.length < 4) return 'Password must be at least 4 characters long'
  return null
}

// The feedback endpoint is public and sends a real email on every call, so it
// needs its own (much tighter) budget to prevent mailbox flooding.
const feedbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many feedback submissions — please try again later' },
})

const FEEDBACK_CATEGORIES = new Set([
  'General Feedback',
  'Bug Report',
  'Feature Request',
  'Scan Tool Suggestion',
  'UI & UX Improvement',
])
const FEEDBACK_MAX_LENGTH = 5000

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {}
  const identifier = (username || '').trim()
  
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Username or password is required' })
  }

  // 1. Check primary admin/analyst users strictly via bcrypt hash (no hardcoded bypasses)
  let user = getUser(identifier)
  if (user && bcrypt.compareSync(password || '', user.password_hash)) {
    db.run(`UPDATE users SET last_login = ? WHERE id = ?`, new Date().toISOString(), user.id)
    audit(user.username, 'login', 'user logged in')
    return res.json({ token: signToken(user), user: { id: user.id, username: user.username, role: user.role, email: user.email } })
  }

  // 2. Check client portal credentials (added under projects).
  // Stored as bcrypt hashes; legacy plaintext rows are verified then upgraded in-place.
  const clientCred = db.get(`SELECT * FROM client_credentials WHERE email = ?`, identifier)
  if (clientCred) {
    const isPlaintext = !clientCred.password.startsWith('$2')
    const inputPass = password || ''
    const storedPass = clientCred.password
    const lengthMatch = isPlaintext ? inputPass.length === storedPass.length : true
    const ok = isPlaintext
      ? lengthMatch && timingSafeEqual(Buffer.from(inputPass), Buffer.from(storedPass))
      : bcrypt.compareSync(inputPass, storedPass)
    if (ok) {
      if (isPlaintext) {
        db.run(`UPDATE client_credentials SET password = ? WHERE id = ?`, bcrypt.hashSync(password, 12), clientCred.id)
      }
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
  }

  return res.status(401).json({ error: 'Username or password is invalid' })
})

// Registration with plan selection & instant subscription
app.post('/api/auth/register', loginLimiter, (req, res) => {
  try {
    const { username, email, password, planId = 'pro', billingInterval = 'monthly', paymentProvider = 'stripe' } = req.body || {}
    const uName = (username || '').trim()
    const uEmail = (email || '').trim().toLowerCase()

    if (!uName || !uEmail || !password) {
      return res.status(400).json({ error: 'Username, email and password are required' })
    }
    if (!/^[a-zA-Z0-9_\-\.]{3,32}$/.test(uName)) {
      return res.status(400).json({ error: 'Username must be 3-32 alphanumeric characters, dashes, or underscores' })
    }
    if (!EMAIL_REGEX.test(uEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address' })
    }
    const passwordError = validatePasswordComplexity(password)
    if (passwordError) {
      return res.status(400).json({ error: passwordError })
    }

    // Check if username or email exists
    const existingUser = db.get(`SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?`, uName.toLowerCase(), uEmail)
    if (existingUser) {
      return res.status(409).json({ error: 'Username or email is already registered' })
    }

    const userId = `usr_${randomUUID()}`
    const passHash = bcrypt.hashSync(password, 12)
    const now = new Date().toISOString()

    db.run(
      `INSERT INTO users (id, username, email, password_hash, role, created_at, last_login) VALUES (?, ?, ?, ?, 'client', ?, ?)`,
      userId, uName, uEmail, passHash, now, now
    )

    // Always start newly registered users on the Free Trial plan
    try {
      activateSubscription({
        userId,
        planId: 'trial',
        interval: 'monthly',
        provider: 'system'
      })
    } catch (subErr) {
      console.warn('Subscription activation warning during register:', subErr.message)
    }

    const newUser = {
      id: userId,
      username: uName,
      email: uEmail,
      role: 'client'
    }

    audit(uName, 'register', `new account registered (requested plan: ${planId || 'trial'})`)

    return res.json({
      token: signToken(newUser),
      user: newUser,
      requestedPlanId: planId && planId !== 'trial' ? planId : undefined,
      message: 'Account created successfully'
    })
  } catch (err) {
    console.error('Registration error:', err)
    return res.status(500).json({ error: err.message || 'Registration failed' })
  }
})

app.get('/api/users/me', requireAuth, (req, res) => {
  const u = getUser(req.user.username)
  if (!u) return res.json({ id: req.user.sub, username: req.user.username, role: req.user.role, email: req.user.email || null, lastLogin: null })
  res.json({ id: u.id, username: u.username, role: u.role, email: u.email, lastLogin: u.last_login })
})

app.put('/api/users/me', requireAuth, (req, res) => {
  const { email } = req.body || {}
  // Validate + uniqueness-check email; clients cannot change it freely
  // (their email is the key that links them to their project).
  if (email != null) {
    if (typeof email !== 'string' || !EMAIL_REGEX.test(email.trim()))
      return res.status(400).json({ error: 'Please enter a valid email address' })
    const normalized = email.trim().toLowerCase()
    if (req.user?.role === 'client') {
      const current = db.get(`SELECT email FROM users WHERE id = ?`, req.user.sub)
      if (!current || (current.email || '').toLowerCase() !== normalized)
        return res.status(403).json({ error: 'client accounts cannot change their email' })
    }
    const dupe = db.get(`SELECT id FROM users WHERE LOWER(email) = ? AND id != ?`, normalized, req.user.sub)
    if (dupe) return res.status(409).json({ error: 'email already in use by another account' })
  }
  db.run(`UPDATE users SET email = ? WHERE id = ?`, email ? email.trim().toLowerCase() : null, req.user.sub)
  audit(req.user.username, 'user:update', 'profile updated')
  const u = db.get(`SELECT * FROM users WHERE id = ?`, req.user.sub)
  res.json({ id: u.id, username: u.username, role: u.role, email: u.email, lastLogin: u.last_login })
})

app.post('/api/users/me/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {}
  if (!currentPassword) {
    return res.status(400).json({ error: 'Please enter your current password' })
  }
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters long' })
  }
  const u = db.get(`SELECT * FROM users WHERE id = ?`, req.user.sub)
  if (!u || !bcrypt.compareSync(currentPassword || '', u.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' })
  }
  db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, bcrypt.hashSync(newPassword, 12), u.id)
  audit(req.user.username, 'user:password', 'password changed')
  res.json({ ok: true, message: 'Password updated successfully!' })
})

// ── Admin Panel ──────────────────────────────────────────────────────────────

// GET /api/admin/overview — dashboard stats for admin panel
app.get('/api/admin/overview', requireAuth, requireRole('admin'), (req, res) => {
  const totalClients = db.get(`SELECT COUNT(*) as c FROM users WHERE role != 'admin'`)
  const activeSubs = db.get(`SELECT COUNT(*) as c FROM subscriptions WHERE status = 'active'`)
  const expiredSubs = db.get(`SELECT COUNT(*) as c FROM subscriptions WHERE status != 'active'`)
  const totalScans = db.get(`SELECT COUNT(*) as c FROM scans`)
  res.json({
    totalClients: totalClients?.c || 0,
    activeSubscriptions: activeSubs?.c || 0,
    expiredInactive: expiredSubs?.c || 0,
    totalScansExecuted: totalScans?.c || 0,
  })
})

// GET /api/admin/clients — list all users with their subscription info
app.get('/api/admin/clients', requireAuth, requireRole('admin'), (req, res) => {
  const users = db.all(`
    SELECT u.id, u.username, u.email, u.role, u.created_at, u.last_login,
           s.plan_id, s.plan_name, s.status as sub_status,
           s.scan_quota_total, s.scan_quota_used, s.current_period_end,
           (SELECT COUNT(*) FROM scans WHERE user_id = u.id) as scans_run,
           (SELECT github_username FROM github_integrations WHERE user_id = u.id LIMIT 1) as github_username
    FROM users u
    LEFT JOIN subscriptions s ON s.user_id = u.id
    WHERE u.role != 'admin'
    ORDER BY u.created_at DESC
  `)

  const clients = users.map(u => {
    const quotaTotal = u.scan_quota_total || 0
    const quotaUsed = u.scan_quota_used || 0
    const expiresAt = u.current_period_end || null
    const isUnlimited = quotaTotal >= 9000

    // Determine effective status (expired if past period end)
    let effectiveStatus = u.sub_status || 'inactive'
    if (effectiveStatus === 'active' && expiresAt && new Date(expiresAt) < new Date()) {
      effectiveStatus = 'expired'
    }

    return {
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      created_at: u.created_at,
      last_login: u.last_login,
      github_username: u.github_username || null,
      plan_id: u.plan_id || 'none',
      plan_name: u.plan_name || 'No Plan',
      sub_status: u.sub_status || 'inactive',
      effective_status: effectiveStatus,
      scan_quota_total: quotaTotal,
      scan_quota_used: quotaUsed,
      remaining_quota: isUnlimited ? '∞' : Math.max(0, quotaTotal - quotaUsed),
      current_period_end: expiresAt,
      total_scans: u.scans_run || 0,
    }
  })

  // Summary counts
  const totalClients = clients.length
  const activeSubscriptions = clients.filter(c => c.effective_status === 'active').length
  const expiredInactive = clients.filter(c => c.effective_status !== 'active').length
  const totalScansExecuted = clients.reduce((sum, c) => sum + (c.total_scans || 0), 0)

  res.json({ clients, totalClients, activeSubscriptions, expiredInactive, totalScansExecuted })
})

// GET /api/admin/clients/:id/details — full workspace details for one user
app.get('/api/admin/clients/:id/details', requireAuth, requireRole('admin'), (req, res) => {
  const u = db.get(`SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?`, req.params.id)
  if (!u) return res.status(404).json({ error: 'User not found' })

  const sub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, u.id)
  const projects = db.all(`
    SELECT p.*,
           (SELECT COUNT(*) FROM scans sc WHERE sc.project_id = p.id) as scan_count,
           (SELECT COUNT(*) FROM findings f WHERE f.scan_id IN (SELECT id FROM scans WHERE project_id = p.id)) as finding_count
    FROM projects p
    WHERE p.user_id = ? 
       OR p.client_id = ? 
       OR p.client = ? 
       OR p.client = ? 
       OR p.id IN (SELECT project_id FROM client_credentials WHERE LOWER(email) = LOWER(?))
    ORDER BY p.created_at DESC
  `, u.id, u.id, u.username, u.email, u.email)

  const scans = db.all(`
    SELECT s.id, s.target, s.status, s.created_at, s.risk_score, p.name as project_name
    FROM scans s
    LEFT JOIN projects p ON p.id = s.project_id
    WHERE s.user_id = ? 
       OR s.project_id IN (SELECT id FROM projects WHERE user_id = ? OR client_id = ? OR client = ? OR client = ?)
    ORDER BY s.created_at DESC LIMIT 50
  `, u.id, u.id, u.id, u.username, u.email)
  const github = db.get(`SELECT github_username, avatar_url, created_at FROM github_integrations WHERE user_id = ?`, u.id)

  res.json({
    user: { id: u.id, username: u.username, email: u.email, role: u.role, createdAt: u.created_at, lastLogin: u.last_login },
    subscription: sub || null,
    projects,
    recentScans: scans,
    github: github || null,
  })
})

// POST /api/admin/clients/:id/projects — create a project for a client
app.post('/api/admin/clients/:id/projects', requireAuth, requireRole('admin'), (req, res) => {
  const u = db.get(`SELECT id FROM users WHERE id = ?`, req.params.id)
  if (!u) return res.status(404).json({ error: 'User not found' })

  const { name, scope, description } = req.body || {}
  if (!name?.trim()) return res.status(400).json({ error: 'Project name is required' })

  const pid = `proj_${randomUUID()}`
  const now = new Date().toISOString()

  db.run(
    `INSERT INTO projects (id, name, scope, description, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    pid, name.trim(), scope || '', description || '', u.id, now, now
  )
  audit(req.user.username, 'admin:create-project', `created project ${name} for user ${u.id}`)
  const project = db.get(`SELECT * FROM projects WHERE id = ?`, pid)
  res.json({ ok: true, project })
})

// POST /api/admin/clients/:id/subscription — update a client's subscription/quota
app.post('/api/admin/clients/:id/subscription', requireAuth, requireRole('admin'), (req, res) => {
  const u = db.get(`SELECT id, username FROM users WHERE id = ?`, req.params.id)
  if (!u) return res.status(404).json({ error: 'User not found' })

  const { planId, quotaTotal, status, daysFromNow = 30 } = req.body || {}
  const expiresAt = new Date(Date.now() + daysFromNow * 86400 * 1000).toISOString()
  const now = new Date().toISOString()

  const plan = PLANS[planId] || PLANS['pro']
  const existing = db.get(`SELECT id FROM subscriptions WHERE user_id = ?`, u.id)

  if (existing) {
    db.run(
      `UPDATE subscriptions SET plan_id=?, plan_name=?, status=?, scan_quota_total=?, current_period_end=?, updated_at=? WHERE user_id=?`,
      planId || 'pro', plan.name, status || 'active',
      quotaTotal ?? plan.quotaScans, expiresAt, now, u.id
    )
  } else {
    db.run(
      `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
      `sub_${randomUUID()}`, u.id, planId || 'pro', plan.name, status || 'active',
      quotaTotal ?? plan.quotaScans, expiresAt, now, now
    )
  }

  audit(req.user.username, 'admin:update-sub', `updated subscription for ${u.username} → plan=${planId}, quota=${quotaTotal}`)
  const updatedSub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, u.id)
  res.json({ ok: true, subscription: updatedSub })
})

// ── Admin Subscription Plans Management ─────────────────────────────────────
app.get('/api/admin/plans', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const plans = getAllPlans({ onlyOpen: false })
    res.json({ plans })
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch plans' })
  }
})

app.post('/api/admin/plans', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const newPlan = createPlan(req.body)
    audit(req.user.username, 'admin:create-plan', `created plan ${newPlan.id} (${newPlan.name})`)
    res.status(201).json({ plan: newPlan })
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to create plan' })
  }
})

app.put('/api/admin/plans/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const updated = updatePlan(req.params.id, req.body)
    audit(req.user.username, 'admin:update-plan', `updated plan ${req.params.id}`)
    res.json({ plan: updated })
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to update plan' })
  }
})

app.patch('/api/admin/plans/:id/toggle-status', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { isOpen } = req.body || {}
    const updated = togglePlanStatus(req.params.id, Boolean(isOpen))
    audit(req.user.username, 'admin:toggle-plan', `toggled plan ${req.params.id} -> isOpen=${isOpen}`)
    res.json({ plan: updated })
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to toggle plan status' })
  }
})

app.delete('/api/admin/plans/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const result = deletePlan(req.params.id)
    audit(req.user.username, 'admin:delete-plan', `deleted plan ${req.params.id}`)
    res.json(result)
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to delete plan' })
  }
})

// ── Admin Promo Codes Management ────────────────────────────────────────────
app.get('/api/admin/promo-codes', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const codes = getAllPromoCodes()
    res.json({ promoCodes: codes })
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to fetch promo codes' })
  }
})

app.post('/api/admin/promo-codes', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const created = createPromoCode(req.body)
    audit(req.user.username, 'admin:create-promo', `created promo code ${created.code}`)
    res.status(201).json({ promoCode: created })
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to create promo code' })
  }
})

app.put('/api/admin/promo-codes/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const updated = updatePromoCode(req.params.id, req.body)
    audit(req.user.username, 'admin:update-promo', `updated promo code ${req.params.id}`)
    res.json({ promoCode: updated })
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to update promo code' })
  }
})

app.patch('/api/admin/promo-codes/:id/toggle-status', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { isActive } = req.body || {}
    const updated = togglePromoCodeStatus(req.params.id, Boolean(isActive))
    audit(req.user.username, 'admin:toggle-promo', `toggled promo code ${req.params.id} -> isActive=${isActive}`)
    res.json({ promoCode: updated })
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to toggle promo code' })
  }
})

app.delete('/api/admin/promo-codes/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const result = deletePromoCode(req.params.id)
    audit(req.user.username, 'admin:delete-promo', `deleted promo code ${req.params.id}`)
    res.json(result)
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to delete promo code' })
  }
})

// ── Admin Custom Subscription Override ──────────────────────────────────────
app.post('/api/admin/subscriptions/custom-override', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { userId, planId, planName, quotaTotal, status, customNotes, extendDays = 30 } = req.body || {}
    if (!userId) return res.status(400).json({ error: 'userId is required' })

    const user = db.get(`SELECT id, username FROM users WHERE id = ?`, userId)
    if (!user) return res.status(404).json({ error: 'User not found' })

    const expiresAt = new Date(Date.now() + (Number(extendDays) || 30) * 86400 * 1000).toISOString()
    const now = new Date().toISOString()
    const targetPlan = getPlan(planId) || PLANS[planId] || { name: planName || 'Custom Plan', quotaScans: 50 }

    const existing = db.get(`SELECT id FROM subscriptions WHERE user_id = ?`, user.id)
    if (existing) {
      db.run(
        `UPDATE subscriptions SET plan_id=?, plan_name=?, status=?, scan_quota_total=?, current_period_end=?, updated_at=? WHERE user_id=?`,
        planId || 'custom', planName || targetPlan.name, status || 'active',
        quotaTotal ?? targetPlan.scanQuota ?? targetPlan.quotaScans ?? 50,
        expiresAt, now, user.id
      )
    } else {
      db.run(
        `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
        `sub_${randomUUID()}`, user.id, planId || 'custom', planName || targetPlan.name, status || 'active',
        quotaTotal ?? targetPlan.scanQuota ?? targetPlan.quotaScans ?? 50,
        expiresAt, now, now
      )
    }

    audit(req.user.username, 'admin:custom-override', `custom override for ${user.username} -> plan=${planId}, quota=${quotaTotal}, notes=${customNotes || ''}`)
    const updatedSub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, user.id)
    res.json({ ok: true, subscription: updatedSub })
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to apply custom override' })
  }
})

// ── Projects ─────────────────────────────────────────────────────────────────
app.get('/api/projects', requireAuth, (req, res) => {
  const allowed = visibleProjectIds(req.user)
  if (allowed === null) return res.json(db.all(`SELECT * FROM projects ORDER BY created_at DESC`))
  if (!allowed.length) return res.json([])
  const placeholders = allowed.map(() => '?').join(',')
  return res.json(db.all(`SELECT * FROM projects WHERE id IN (${placeholders}) ORDER BY created_at DESC`, ...allowed))
})

app.post('/api/projects', requireAuth, (req, res) => {
  const { name, client = '', description = '', scope = '', cover = '', riskLevel = 'medium' } = req.body || {}
  if (!name) return res.status(400).json({ error: 'name required' })
  const assignedClient = client || req.user?.email || req.user?.username || 'client'
  const id = `proj_${randomUUID()}`
  const now = new Date().toISOString()
  db.run(`INSERT INTO projects (id, name, client, description, scope, cover, risk_level, status, created_at, updated_at, user_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    id, name.trim(), assignedClient, description.trim(), scope.trim(), cover, riskLevel, 'active', now, now, req.user?.id)
  audit(req.user.username, 'project:create', name)
  res.status(201).json(db.get(`SELECT * FROM projects WHERE id = ?`, id))
})

app.put('/api/projects/:id', requireAuth, (req, res) => {
  const existing = db.get(`SELECT * FROM projects WHERE id = ?`, req.params.id)
  if (!existing) return res.status(404).json({ error: 'Project not found' })
  if (!canAccessProject(req.user, existing)) {
    return res.status(403).json({ error: 'Cannot modify this project' })
  }
  const { name = existing.name, client = existing.client, description = existing.description, scope = existing.scope, cover = existing.cover, riskLevel = existing.risk_level } = req.body || {}
  const now = new Date().toISOString()
  db.run(`UPDATE projects SET name = ?, client = ?, description = ?, scope = ?, cover = ?, risk_level = ?, updated_at = ? WHERE id = ?`,
    name, client, description, scope, cover, riskLevel, now, req.params.id)
  audit(req.user.username, 'project:update', req.params.id)
  res.json(db.get(`SELECT * FROM projects WHERE id = ?`, req.params.id))
})

app.delete('/api/projects/:id', requireAuth, (req, res) => {
  const existing = db.get(`SELECT * FROM projects WHERE id = ?`, req.params.id)
  if (!existing) return res.status(404).json({ error: 'Project not found' })
  if (!canAccessProject(req.user, existing)) {
    return res.status(403).json({ error: 'Cannot delete this project' })
  }
  db.transaction(() => {
    db.run(`DELETE FROM client_credentials WHERE project_id = ?`, req.params.id)
    db.run(`DELETE FROM projects WHERE id = ?`, req.params.id)
  })()
  audit(req.user.username, 'project:delete', req.params.id)
  res.json({ ok: true })
})

// ── Client Credentials for Project Portals ────────────────────────────────────
// Staff-only: these endpoints read/write portal login passwords.
app.get('/api/projects/:id/credentials', requireAuth, requireStaff, (req, res) => {
  res.json(db.all(`SELECT id, project_id, email, note, created_at FROM client_credentials WHERE project_id = ? ORDER BY created_at DESC`, req.params.id))
})

app.post('/api/projects/:id/credentials', requireAuth, requireStaff, (req, res) => {
  const { email, password, note = '' } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'email and password required' })
  const id = `cred_${randomUUID()}`
  const now = new Date().toISOString()
  db.run(`INSERT INTO client_credentials (id, project_id, email, password, note, created_at) VALUES (?,?,?,?,?,?)`,
    id, req.params.id, email.trim(), bcrypt.hashSync(password, 10), note.trim(), now)
  audit(req.user.username, 'project:cred_create', `${email} on ${req.params.id}`)
  res.status(201).json(db.get(`SELECT id, project_id, email, note, created_at FROM client_credentials WHERE id = ?`, id))
})

app.put('/api/projects/:id/credentials/:credId', requireAuth, requireStaff, (req, res) => {
  const { email, password, note = '' } = req.body || {}
  if (!email) return res.status(400).json({ error: 'email required' })
  // Empty password = keep the existing one (GET no longer returns passwords)
  if (password) {
    db.run(`UPDATE client_credentials SET email = ?, password = ?, note = ? WHERE id = ? AND project_id = ?`,
      email.trim(), bcrypt.hashSync(password, 10), note.trim(), req.params.credId, req.params.id)
  } else {
    db.run(`UPDATE client_credentials SET email = ?, note = ? WHERE id = ? AND project_id = ?`,
      email.trim(), note.trim(), req.params.credId, req.params.id)
  }
  audit(req.user.username, 'project:cred_update', `${req.params.credId}`)
  res.json(db.get(`SELECT id, project_id, email, note, created_at FROM client_credentials WHERE id = ?`, req.params.credId))
})

app.delete('/api/projects/:id/credentials/:credId', requireAuth, requireStaff, (req, res) => {
  db.run(`DELETE FROM client_credentials WHERE id = ? AND project_id = ?`, req.params.credId, req.params.id)
  audit(req.user.username, 'project:cred_delete', `${req.params.credId}`)
  res.json({ ok: true })
})

// ── Scans ────────────────────────────────────────────────────────────────────
app.get('/api/scans', requireAuth, (req, res) => {
  try {
    if (req.user?.role === 'client') {
      const userEmail = (req.user.email || '').toLowerCase()
      const username = (req.user.username || '').toLowerCase()
      const userId = req.user.id

      const allProjs = db.all(`SELECT * FROM projects`)
      const matchProjs = allProjs.filter((p) => canAccessProject(req.user, p))
      const projIds = matchProjs.map(p => p.id)

      let scans = []
      if (projIds.length > 0) {
        const placeholders = projIds.map(() => '?').join(',')
        scans = db.all(`
          SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_count
          FROM scans s 
          WHERE s.project_id IN (${placeholders}) 
             OR (s.user_id IS NOT NULL AND s.user_id = ?) 
             OR (s.client IS NOT NULL AND (LOWER(s.client) = ? OR LOWER(s.client) = ?))
          ORDER BY s.created_at DESC LIMIT 200
        `, ...projIds, userId, username, userEmail)
      } else {
        scans = db.all(`
          SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS findings_count
          FROM scans s 
          WHERE (s.user_id IS NOT NULL AND s.user_id = ?) 
             OR (s.client IS NOT NULL AND (LOWER(s.client) = ? OR LOWER(s.client) = ?))
          ORDER BY s.created_at DESC LIMIT 200
        `, userId, username, userEmail)
      }
      return res.json(scans || [])
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
app.get('/api/scans/:id', requireAuth, requireScanAccess, (req, res) => {
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, req.params.id)
  if (!scan) return res.status(404).json({ error: 'not found' })
  const findings = db.all(`SELECT * FROM findings WHERE scan_id = ?`, scan.id)
  const logs = db.all(`SELECT level, message, ts FROM logs WHERE scan_id = ? ORDER BY id DESC LIMIT 100`, scan.id).reverse()
  // Parse whitebox metadata for the Audit Details section
  let whiteboxMeta = null
  if (scan.whitebox_meta) {
    try { whiteboxMeta = JSON.parse(scan.whitebox_meta) } catch { /* ignore */ }
  }
  res.json({ scan, findings, logs, whiteboxMeta })
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

// Anonymous Community Feedback & Bug Reports
app.post('/api/feedback', feedbackLimiter, async (req, res) => {
  try {
    const { category, message, rating } = req.body || {}

    const text = typeof message === 'string' ? message.trim() : ''
    if (!text) {
      return res.status(400).json({ error: 'Feedback message is required' })
    }
    if (text.length > FEEDBACK_MAX_LENGTH) {
      return res.status(413).json({ error: `Feedback message must be ${FEEDBACK_MAX_LENGTH} characters or fewer` })
    }

    // Never let client-supplied text reach the mailer unvalidated: `category`
    // lands in the SMTP subject line and `message` in the HTML body.
    const safeCategory = FEEDBACK_CATEGORIES.has(category) ? category : 'General Feedback'
    const parsedRating = Number.parseInt(rating, 10)
    const safeRating = Number.isInteger(parsedRating) && parsedRating >= 1 && parsedRating <= 5 ? parsedRating : 5

    const senderContext = req.user ? `${req.user.role} user (${req.user.username || 'client'})` : 'Anonymous Visitor'
    const result = await sendAnonymousFeedbackNotification({
      category: safeCategory,
      message: text,
      rating: safeRating,
      userContext: senderContext,
    })

    audit(req.user?.username || 'anonymous', 'feedback:submit', `Category: ${safeCategory}`)

    return res.json({
      success: true,
      message: 'Thank you! Your feedback has been sent anonymously to muhammadsaifudinmj@gmail.com.',
      result,
    })
  } catch (err) {
    console.error('[feedback] error:', err)
    return res.status(500).json({ error: 'Failed to send feedback: ' + (err.message || err) })
  }
})

app.post('/api/scans', requireAuth, async (req, res) => {
  const {
    target, projectId = null, mode = 'blackbox', targetType = 'url',
    template = 'standard', modules = [], objective = 'comprehensive', maxTools = 6,
    files = [], language = '', focus = '', verify = true, depth = 'standard',
    owaspCategories = [],
  } = req.body || {}

  if (mode === 'blackbox' && !target) return res.status(400).json({ error: 'target required for blackbox' })
  if (mode === 'whitebox' && (!files || !files.length)) return res.status(400).json({ error: 'files required for whitebox' })

  // Quota enforcement — applies to ALL scan launches (manual, whitebox-folder),
  // not just GitHub-triggered ones. Admins are exempt.
  if (req.user?.role !== 'admin') {
    try {
      consumeScanQuota(req.user.id)
    } catch (quotaErr) {
      return res.status(402).json({ error: quotaErr.message, upgradeRequired: true })
    }
  }

  const id = `scan_${randomUUID()}`
  const now = new Date().toISOString()
  db.run(`INSERT INTO scans (id, project_id, target, target_type, mode, status, template, modules, progress, created_at, started_at, user_id, client)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    id, projectId, target || '(whitebox)', targetType, mode, 'running', template,
    JSON.stringify(modules), 0, now, now, req.user?.id || null, req.user?.username || req.user?.email || null)
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, id)
  audit(req.user.username, 'scan:start', `${mode} → ${target || 'codebase'}`)
  saveScanConfig(id, { target, targetType, mode, template, modules, objective, maxTools, files, language, focus, verify, depth, owaspCategories })

  // Derive modules from OWASP categories if provided (blackbox),
  // or derive AI pass filter (whitebox)
  const effectiveModules = owaspCategories.length ? blackboxModulesForCategories(owaspCategories) : modules
  const whiteboxPasses = owaspCategories.length ? whiteboxPassesForCategories(owaspCategories) : null

  // Run async (non-blocking)
  setImmediate(async () => {
    try {
      if (mode === 'whitebox') await pipeline.runWhitebox(scan, { files, language, focus, verify, depth, owaspCategories, whiteboxPasses })
      else await pipeline.runBlackbox(scan, { modules: effectiveModules, objective, maxTools, verify, depth, owaspCategories })
    } catch (e) {
      if (e.message === 'SCAN_STOPPED') return // already set to 'stopped' by the /stop endpoint
      pipeline.log(id, 'error', `Pipeline error: ${e.message}`)
      pipeline.finish(id, 'failed')
    }
  })

  res.status(201).json({ scan })
})

app.post('/api/scans/:id/stop', requireAuth, requireStaff, (req, res) => {
  pipeline.stopScan(req.params.id) // set stopped flag so loops abort
  db.run(`UPDATE scans SET status = 'stopped', finished_at = ? WHERE id = ?`, new Date().toISOString(), req.params.id)
  audit(req.user.username, 'scan:stop', req.params.id)
  res.json({ ok: true })
})

app.delete('/api/scans/:id', requireAuth, requireStaff, (req, res) => {
  const { id } = req.params
  pipeline.stopScan(id) // abort any running scan
  db.transaction(() => {
    db.run(`DELETE FROM logs WHERE scan_id = ?`, id)
    db.run(`DELETE FROM scan_configs WHERE scan_id = ?`, id)
    db.run(`DELETE FROM findings WHERE scan_id = ?`, id)
    db.run(`DELETE FROM scans WHERE id = ?`, id)
  })()
  audit(req.user.username, 'scan:delete', id)
  res.json({ ok: true })
})

app.post('/api/scans/:id/re-run', requireAuth, requireStaff, async (req, res) => {
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
        const { files, stats } = walkProjects(cfg.folders, {
          maxFiles: Math.min(Number(cfg.maxFiles) || 300, 1000),
          maxBytes: Math.min(Number(cfg.maxBytes) || 10_000_000, 50_000_000),
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
      if (mode === 'whitebox') await pipeline.runWhitebox(scan, { ...baseOpts, files: whiteboxFiles })
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
app.post('/api/scans/:id/retry-failed', requireAuth, requireStaff, async (req, res) => {
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
              maxFiles: Math.min(Number(cfg.maxFiles) || 300, 1000),
              maxBytes: Math.min(Number(cfg.maxBytes) || 10_000_000, 50_000_000),
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
    folders = [], projectId = null, targetUserId: targetClientId = null, deductQuota = true,
    language = '', focus = '', verify = true, dynamicTarget = '', dynamicModules = [],
    maxFiles = 300, maxBytes = 10_000_000, depth = 'standard',
    owaspCategories = [],
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
    maxFiles: Math.min(Number(maxFiles) || 300, 1000),
    maxBytes: Math.min(Number(maxBytes) || 10_000_000, 50_000_000),
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
  saveScanConfig(id, { mode: 'whitebox', source: 'folder', folders: normalized, language, focus, verify, depth, maxFiles, maxBytes, owaspCategories })

  const whiteboxPasses = owaspCategories.length ? whiteboxPassesForCategories(owaspCategories) : null

  pipeline.log(id, 'info', `📂 Folder walker collected ${files.length} files (${JSON.stringify(stats.collected || files.length)} used, stats: ${JSON.stringify(stats).slice(0, 300)})`)

  setImmediate(async () => {
    try {
      await pipeline.runWhitebox(scan, { files, language, focus, verify, depth, owaspCategories, whiteboxPasses })
    } catch (e) {
      if (e.message === 'SCAN_STOPPED') return
      pipeline.log(id, 'error', `Pipeline error: ${e.message}`)
      pipeline.finish(id, 'failed')
    }
  })

  res.status(201).json({ scan, stats })
})

app.post('/api/scans/:id/pause', requireAuth, requireStaff, (req, res) => {
  pipeline.pauseScan(req.params.id)
  db.run(`UPDATE scans SET status = 'paused' WHERE id = ?`, req.params.id)
  pipeline.log(req.params.id, 'warn', '⏸ Scan paused by user')
  audit(req.user.username, 'scan:pause', req.params.id)
  res.json({ ok: true, status: 'paused' })
})

app.post('/api/scans/:id/resume', requireAuth, requireStaff, (req, res) => {
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
  // Client-portal users see findings from their own projects or direct scans
  if (req.user?.role === 'client') {
    const userEmail = (req.user.email || '').toLowerCase().trim()
    const username = (req.user.username || '').toLowerCase().trim()
    const userId = req.user.id

    const allProjs = db.all(`SELECT id, client, name, user_id, client_id FROM projects`)
    const matchProjs = allProjs.filter((p) => canAccessProject(req.user, p))
    const projIds = matchProjs.map(p => p.id)

    if (projIds.length > 0) {
      const placeholders = projIds.map(() => '?').join(',')
      sql += ` AND (s.project_id IN (${placeholders}) OR (s.user_id IS NOT NULL AND s.user_id = ?) OR (s.client IS NOT NULL AND (LOWER(s.client) = ? OR LOWER(s.client) = ?)))`
      params.push(...projIds, userId, username, userEmail)
    } else {
      sql += ` AND ((s.user_id IS NOT NULL AND s.user_id = ?) OR (s.client IS NOT NULL AND (LOWER(s.client) = ? OR LOWER(s.client) = ?)))`
      params.push(userId, username, userEmail)
    }
  }
  if (status && status !== 'all') { sql += ' AND f.status = ?'; params.push(status) }
  if (scan_id && scan_id !== 'all') { sql += ' AND f.scan_id = ?'; params.push(scan_id) }
  if (project_id && project_id !== 'all') { sql += ' AND s.project_id = ?'; params.push(project_id) }
  if (severity && severity !== 'all') { sql += ' AND f.severity = ?'; params.push(severity) }
  sql += ' ORDER BY f.created_at DESC LIMIT 1000'
  res.json(db.all(sql, ...params))
})
app.delete('/api/findings/:id', requireAuth, requireStaff, (req, res) => {
  const f = db.get(`SELECT id FROM findings WHERE id = ?`, req.params.id)
  if (!f) return res.status(404).json({ error: 'finding not found' })
  db.run(`DELETE FROM finding_notes WHERE finding_id = ?`, req.params.id)
  db.run(`DELETE FROM findings WHERE id = ?`, req.params.id)
  audit(req.user.username, 'finding:delete', req.params.id)
  res.json({ ok: true })
})

const FINDING_STATUSES = ['open', 'confirmed', 'in-progress', 'fixed', 'accepted', 'false-positive']
app.put('/api/findings/:id/status', requireAuth, requireStaff, (req, res) => {
  const status = FINDING_STATUSES.includes(req.body.status) ? req.body.status : 'open'
  db.run(`UPDATE findings SET status = ? WHERE id = ?`, status, req.params.id)
  res.json(db.get(`SELECT * FROM findings WHERE id = ?`, req.params.id))
})

const FINDING_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
app.put('/api/findings/:id/severity', requireAuth, requireStaff, (req, res) => {
  const { severity } = req.body || {}
  if (!FINDING_SEVERITIES.includes(severity)) return res.status(400).json({ error: `severity must be one of: ${FINDING_SEVERITIES.join(', ')}` })
  const existing = db.get(`SELECT id FROM findings WHERE id = ?`, req.params.id)
  if (!existing) return res.status(404).json({ error: 'Finding not found' })
  db.run(`UPDATE findings SET severity = ? WHERE id = ?`, severity, req.params.id)
  audit(req.user.username, 'finding:severity', `${req.params.id} → ${severity}`)
  res.json(db.get(`SELECT * FROM findings WHERE id = ?`, req.params.id))
})

// ── Findings & Database Backup API — staff only (full DB export)
app.post('/api/backup/create', requireAuth, requireStaff, async (req, res) => {
  try {
    const result = await db.backupDatabase()
    audit(req.user.username, 'backup:create', result.backupFile || 'failed')
    if (result.success) {
      res.json({ ok: true, message: 'Database backup created successfully', file: result.backupFile })
    } else {
      res.status(500).json({ error: 'Failed to create backup' })
    }
  } catch (err) {
    console.error('[backup:create] error:', err)
    res.status(500).json({ error: err.message || 'Failed to create backup' })
  }
})

app.get('/api/backup/raw', requireAuth, requireStaff, (req, res) => {
  try {
    const backupDir = path.join(config.outputDir, 'backups')
    const latestPath = path.join(backupDir, 'fyp2_latest_backup.db')
    if (fs.existsSync(latestPath)) {
      return res.download(latestPath, `sentinelai_backup_${Date.now()}.db`)
    }
    if (fs.existsSync(config.dbPath)) {
      return res.download(config.dbPath, `sentinelai_active_${Date.now()}.db`)
    }
    res.status(404).json({ error: 'No backup database file found' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/backup/export', requireAuth, requireStaff, (req, res) => {
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
app.get('/api/findings/:id/notes', requireAuth, requireStaff, (req, res) => {
  res.json(db.all(`SELECT * FROM finding_notes WHERE finding_id = ? ORDER BY ts ASC`, req.params.id))
})
app.post('/api/findings/:id/notes', requireAuth, requireStaff, (req, res) => {
  const { note } = req.body || {}
  if (!note) return res.status(400).json({ error: 'note required' })
  const id = `note_${randomUUID()}`
  db.run(`INSERT INTO finding_notes (id, finding_id, author, note, ts) VALUES (?,?,?,?,?)`,
    id, req.params.id, req.user.username, note, new Date().toISOString())
  res.status(201).json(db.get(`SELECT * FROM finding_notes WHERE id = ?`, id))
})

// ── Monitors ─────────────────────────────────────────────────────────────────
// ── Monitors — staff only (they launch scans against arbitrary targets)
app.get('/api/monitors', requireAuth, requireStaff, (req, res) => res.json(monitors.listMonitors()))
app.get('/api/monitors/:id', requireAuth, requireStaff, (req, res) => {
  const m = monitors.getMonitor(req.params.id)
  if (!m) return res.status(404).json({ error: 'not found' })
  res.json({ monitor: m, events: monitors.monitorEvents(m.id) })
})
app.post('/api/monitors', requireAuth, requireStaff, (req, res) => {
  const { name, target, targetType = 'url', intervalMin = 60, modules: mods = [] } = req.body || {}
  if (!name || !target) return res.status(400).json({ error: 'name and target required' })
  const m = monitors.createMonitor(pipeline, { name, target, targetType, intervalMin, modules: mods })
  audit(req.user.username, 'monitor:create', `${name} → ${target}`)
  res.status(201).json(m)
})
app.put('/api/monitors/:id', requireAuth, requireStaff, (req, res) => {
  const m = monitors.setEnabled(req.params.id, !!req.body.enabled, pipeline)
  res.json(m)
})
app.post('/api/monitors/:id/trigger', requireAuth, requireStaff, async (req, res) => {
  try {
    const result = await monitors.triggerNow(req.params.id, pipeline)
    audit(req.user.username, 'monitor:trigger', req.params.id)
    res.json(result)
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})
app.delete('/api/monitors/:id', requireAuth, requireStaff, (req, res) => {
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
  const { provider, key, model, prompt } = req.body || {}
  
  let apiKey = key
  let targetModel = model
  let url = ''

  if (provider === 'groq') {
    url = 'https://api.groq.com/openai/v1/chat/completions'
    apiKey = apiKey || config.ai.groq.key
    targetModel = targetModel || config.ai.groq.model
  } else if (provider === 'openrouter') {
    url = 'https://openrouter.ai/api/v1/chat/completions'
    apiKey = apiKey || config.ai.openrouter.key
    targetModel = targetModel || config.ai.openrouter.model
  } else if (provider === 'bandelbanget') {
    url = 'https://bandelbanget.xyz/v1/chat/completions'
    apiKey = apiKey || config.ai.bandelbanget.key
    targetModel = targetModel || config.ai.bandelbanget.model
  } else {
    return res.status(400).json({ error: 'Unknown provider' })
  }

  if (!apiKey) {
    return res.status(400).json({ success: false, error: `No API key configured for ${provider}` })
  }

  const t0 = Date.now()
  try {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 12000)
    const testPrompt = prompt || 'Say OK if you can read this.'
    const headers = { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' }
    
    const reqLLM = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: targetModel,
        messages: [{ role: 'user', content: testPrompt }],
        max_tokens: 150
      }),
      signal: ctrl.signal
    })
    clearTimeout(timer)

    const latencyMs = Date.now() - t0
    const data = await reqLLM.json()
    if (!reqLLM.ok) {
      const errMsg = data.error?.message || (typeof data.error === 'string' ? data.error : `HTTP ${reqLLM.status}`)
      return res.json({ success: false, error: errMsg, latencyMs, model: targetModel, provider })
    }

    const rawChoice = data.choices?.[0]?.message
    const reply = (rawChoice?.content && rawChoice.content.trim())
      || (rawChoice?.reasoning && rawChoice.reasoning.trim())
      || (typeof data === 'string' ? data : JSON.stringify(data))

    res.json({ success: true, reply: (reply || 'OK').trim(), latencyMs, model: targetModel, provider })
  } catch (e) {
    const latencyMs = Date.now() - t0
    res.json({ success: false, error: e.name === 'AbortError' ? 'Timeout (12s)' : e.message, latencyMs, model: targetModel, provider })
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

// ── Skills RAG (cybersecurity playbooks) ─────────────────────────────────────
app.get('/api/skills/status', requireAuth, (req, res) => res.json(skillsRag.skillsIndexStatus()))
app.post('/api/skills/reindex', requireAuth, (req, res) => {
  const r = skillsRag.buildSkillsIndex()
  const cat = skillsRag.writeSkillsCatalog()
  audit(req.user.username, 'skills:reindex', `${r.indexed} skills`)
  res.json({ ...r, catalog: cat })
})
app.get('/api/skills/search', requireAuth, (req, res) => {
  res.json(skillsRag.retrieveSkills(req.query.q || '', { limit: Number(req.query.limit) || 2, includeBody: req.query.body === 'true' }))
})

// ── Kali Linux Remote Control ────────────────────────────────────────────────
// NOTE: these run shell commands on the host the backend runs on. They are
// admin-only and intended for the dedicated Kali deployment where the backend
// itself binds to localhost.
app.get('/api/kali/system-info', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
    res.setHeader('Pragma', 'no-cache')
    res.setHeader('Expires', '0')
    res.json(await kaliControl.getSystemInfo())
  } catch (e) {
    console.error('[kali:system-info] failed:', e.message)
    res.status(500).json({ error: e.message })
  }
})

app.post('/api/kali/exec', requireAuth, requireRole('admin'), async (req, res) => {
  const { command, timeout } = req.body || {}
  try {
    const result = await kaliControl.executeCommand(command, Number(timeout) || 30000)
    audit(req.user.username, 'kali:exec', String(command).slice(0, 200))
    res.json(result)
  } catch (e) {
    console.error('[kali:exec] failed:', e.message)
    res.status(400).json({ error: e.message })
  }
})

// AI chatbox: translate natural language into a Kali command for review
app.post('/api/kali/suggest', requireAuth, requireRole('admin'), async (req, res) => {
  const { message, history } = req.body || {}
  try {
    const suggestion = await kaliControl.suggestKaliCommand(message, Array.isArray(history) ? history : [])
    audit(req.user.username, 'kali:suggest', String(message).slice(0, 200))
    res.json(suggestion)
  } catch (e) {
    console.error('[kali:suggest] failed:', e.message)
    res.status(400).json({ error: e.message })
  }
})

app.post('/api/kali/service', requireAuth, requireRole('admin'), async (req, res) => {
  const { service, action } = req.body || {}
  try {
    const result = await kaliControl.manageService(service, action)
    audit(req.user.username, `kali:service:${action}`, service)
    res.json(result)
  } catch (e) {
    console.error('[kali:service] failed:', e.message)
    res.status(400).json({ error: e.message })
  }
})

app.get('/api/kali/tools', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    res.json(await kaliControl.auditTools())
  } catch (e) {
    console.error('[kali:tools] failed:', e.message)
    res.status(500).json({ error: e.message })
  }
})

app.post('/api/kali/tools/install', requireAuth, requireRole('admin'), (req, res) => {
  const result = kaliControl.triggerToolsInstall()
  audit(req.user.username, 'kali:tools:install', 'all 22 tools')
  res.json(result)
})

// ── Engine (native toolchain) ───────────────────────────────────────────────
app.get('/api/engine/status', requireAuth, requireStaff, async (req, res) => {
  const tools = await nativeToolsStatus()
  const available = Object.values(tools).filter(Boolean).length
  res.json({
    ok: available > 0,
    enabled: true,
    available: available > 0,
    engine: 'native',
    totalTools: Object.keys(tools).length,
    totalToolsAvailable: available,
    tools,
  })
})
app.post('/api/engine/analyze', requireAuth, requireStaff, async (req, res) => res.json({ success: false, error: 'not supported by native engine' }))
app.post('/api/engine/attack-chain', requireAuth, requireStaff, async (req, res) => res.json({ success: false, error: 'not supported by native engine' }))

// ── OWASP Tool Map ──────────────────────────────────────────────────────
app.get('/api/owasp-tools', requireAuth, (req, res) => {
  res.json({ categories: getOwaspToolMapList() })
})

// ── Custom Scripts Engine ───────────────────────────────────────────────
// Admin-defined scanning scripts that run as pipeline stages.
app.get('/api/scripts', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ scripts: getAllScripts() })
})

app.post('/api/scripts/seed-defaults', requireAuth, requireRole('admin'), (req, res) => {
  const result = typeof db.seedDefaultScripts === 'function' ? db.seedDefaultScripts() : { count: 0 }
  audit(req.user.username, 'scripts:seed-defaults', `Restored ${result.count || 0} scripts`)
  res.json({ ok: true, count: result.count, scripts: getAllScripts() })
})

app.post('/api/scripts', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const s = createScript(req.body || {})
    audit(req.user.username, 'script:create', `${s.id} "${s.name}" (${s.language}/${s.trigger_point})`)
    res.json({ ok: true, script: s })
  } catch (e) { res.status(400).json({ error: e.message }) }
})

app.put('/api/scripts/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const s = updateScript(req.params.id, req.body || {})
    audit(req.user.username, 'script:update', `${s.id} "${s.name}"`)
    res.json({ ok: true, script: s })
  } catch (e) { res.status(400).json({ error: e.message }) }
})

app.delete('/api/scripts/:id', requireAuth, requireRole('admin'), (req, res) => {
  const ok = deleteScript(req.params.id)
  if (ok) audit(req.user.username, 'script:delete', req.params.id)
  res.json({ ok })
})

// Test-run a script against a target without creating a scan.
app.post('/api/scripts/:id/test', requireAuth, requireRole('admin'), async (req, res) => {
  const script = getScript(req.params.id)
  if (!script) return res.status(404).json({ error: 'script not found' })
  const target = String(req.body?.target || '').trim()
  if (!/^https?:\/\//i.test(target)) return res.status(400).json({ error: 'target must be an http(s) URL' })
  try {
    const { result, findings } = await runCustomScript(script, { target, scanId: `test_${Date.now()}` })
    audit(req.user.username, 'script:test', `${script.id} → ${target} (${findings.length} findings)`)
    res.json({
      ok: true,
      exitCode: result.code,
      success: result.success,
      durationMs: result.durationMs,
      findings,
      stdout: String(result.stdout || '').slice(0, 20000),
      stderr: String(result.stderr || '').slice(0, 5000),
    })
  } catch (e) { res.status(500).json({ error: e.message }) }
})


// ── Reports ──────────────────────────────────────────────────────────────────
app.post('/api/reports/generate', requireAuth, requireScanAccess, async (req, res) => {
  try {
    const r = await generateReport(req.body.scanId, req.body.minSeverity || 'info', req.body.statusFilter || 'all')
    audit(req.user.username, 'report:generate', `${req.body.scanId} (min: ${req.body.minSeverity || 'info'}, status: ${req.body.statusFilter || 'all'})`)
    res.json({ ok: true, file: r.file, riskScore: r.riskScore, counts: r.counts })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/reports/download/:scanId', requireAuth, requireScanAccess, (req, res) => {
  // scanId is server-generated (scan_<uuid>) — strip path separators defensively
  const safeId = String(req.params.scanId).replace(/[^a-zA-Z0-9_-]/g, '')
  const file = `${config.outputDir}/report-${safeId}.pdf`
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'report not generated' })
  res.download(file)
})

app.post('/api/scans/:id/audio-briefing', requireAuth, requireScanAccess, async (req, res) => {
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
// ── Exploitation (MSF + campaigns) — staff only; MSF session commands are
// remote shell execution and must never be reachable by client-portal users.
app.get('/api/exploits/msf/status', requireAuth, requireStaff, async (req, res) => {
  try { res.json(await msf.status()) }
  catch (e) { console.error('[msf:status]', e.message); res.status(502).json({ error: e.message || 'MSF RPC unavailable' }) }
})

// List active MSF sessions
app.get('/api/exploits/msf/sessions', requireAuth, requireStaff, async (req, res) => {
  try { res.json(await msf.listSessions()) }
  catch (e) { console.error('[msf:sessions]', e.message); res.status(502).json({ error: e.message || 'MSF RPC unavailable' }) }
})

// Get a specific MSF session
app.get('/api/exploits/msf/sessions/:id', requireAuth, requireStaff, async (req, res) => {
  try {
    const s = await msf.sessionInfo(req.params.id)
    if (!s) return res.status(404).json({ error: 'session not found' })
    res.json(s)
  } catch (e) { console.error('[msf:sessionInfo]', e.message); res.status(502).json({ error: e.message || 'MSF RPC unavailable' }) }
})

// Run a command in an MSF session
app.post('/api/exploits/msf/sessions/:id/command', requireAuth, requireStaff, async (req, res) => {
  const { command } = req.body || {}
  if (!command) return res.status(400).json({ error: 'command required' })
  try {
    const result = await msf.shellCommand(req.params.id, command)
    res.json(result)
  } catch (e) { console.error('[msf:shellCommand]', e.message); res.status(502).json({ error: e.message || 'MSF RPC unavailable' }) }
})

// Kill an MSF session
app.delete('/api/exploits/msf/sessions/:id', requireAuth, requireStaff, async (req, res) => {
  try { res.json(await msf.stopSession(req.params.id)) }
  catch (e) { console.error('[msf:stopSession]', e.message); res.status(502).json({ error: e.message || 'MSF RPC unavailable' }) }
})

// List all exploit campaigns
app.get('/api/exploits/campaigns', requireAuth, requireStaff, (req, res) => {
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
app.get('/api/exploits/campaigns/:id', requireAuth, requireStaff, (req, res) => {
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
app.post('/api/exploits/campaigns', requireAuth, requireStaff, async (req, res) => {
  const { scanId, findingId } = req.body || {}
  if (!findingId) return res.status(400).json({ error: 'findingId required' })

  const finding = db.get(`SELECT * FROM findings WHERE id = ?`, findingId)
  if (!finding) return res.status(404).json({ error: 'finding not found' })

  // Auto-resolve scanId from finding if not provided
  const resolvedScanId = scanId || finding.scan_id
  let scan = resolvedScanId ? db.get(`SELECT * FROM scans WHERE id = ?`, resolvedScanId) : null
  if (!scan) {
    // If finding has no associated scan in DB (e.g. repo audits or imported findings), create placeholder
    const fallbackScanId = resolvedScanId || `scan_${randomUUID()}`
    const now = new Date().toISOString()
    const target = finding.target || 'target'
    db.run(
      `INSERT OR IGNORE INTO scans (id, target, target_type, mode, status, template, modules, progress, created_at, started_at)
       VALUES (?, ?, 'url', 'blackbox', 'completed', 'standard', '[]', 100, ?, ?)`,
      fallbackScanId, target, now, now
    )
    scan = db.get(`SELECT * FROM scans WHERE id = ?`, fallbackScanId)
  }
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

  try {
    const result = await exploitEngine.launchCampaign(scan, finding)
    audit(req.user.username, 'exploit:launch', `${finding.title} → ${result.campaignId || 'no_match'}`)

    res.status(201).json({
      ...result,
      matchedExploits: matchExploits(finding).length,
      risk: classifyRisk(finding),
    })
  } catch (e) {
    console.error('[exploit:launch]', e)
    res.status(500).json({ error: e.message || 'Campaign launch failed' })
  }
})

// Approve a gated exploit step
app.post('/api/exploits/campaigns/:campaignId/approve', requireAuth, requireStaff, async (req, res) => {
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
app.post('/api/exploits/campaigns/:campaignId/deny', requireAuth, requireStaff, async (req, res) => {
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
app.post('/api/exploits/campaigns/:campaignId/pause', requireAuth, requireStaff, (req, res) => {
  exploitEngine.pauseCampaign(req.params.campaignId)
  db.run(`UPDATE exploit_campaigns SET status = 'paused' WHERE id = ?`, req.params.campaignId)
  audit(req.user.username, 'exploit:pause', req.params.campaignId)
  res.json({ ok: true })
})

// Resume a campaign
app.post('/api/exploits/campaigns/:campaignId/resume', requireAuth, requireStaff, (req, res) => {
  exploitEngine.resumeCampaign(req.params.campaignId)
  db.run(`UPDATE exploit_campaigns SET status = 'running' WHERE id = ?`, req.params.campaignId)
  audit(req.user.username, 'exploit:resume', req.params.campaignId)
  // Resume execution — schedule after response so the client is unblocked
  setImmediate(() => exploitEngine.executeCampaign(req.params.campaignId))
  res.json({ ok: true })
})

// Abort a campaign
app.post('/api/exploits/campaigns/:campaignId/abort', requireAuth, requireStaff, (req, res) => {
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

    // Asynchronously run whitebox security pipeline with all audited source files
    const filesToAudit = (repoBundle.files && repoBundle.files.length > 0)
      ? repoBundle.files
      : (repoBundle.fileContents && repoBundle.fileContents.length > 0)
        ? repoBundle.fileContents
        : [{ path: `repository/${repoFullName}`, content: repoBundle.consolidatedSource }]

    setImmediate(async () => {
      try {
        await pipeline.runWhitebox(scan, { files: filesToAudit, language: '', focus: 'OWASP Top 10 Security & Secrets Audit', verify: true })
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

// Public GitHub Webhook endpoint for Push & PR automated triggers.
// Signature-verified when GITHUB_WEBHOOK_SECRET is set; without a secret only
// loopback/LAN callers are accepted (unauthenticated remote scan triggering
// would let anyone burn scan quota and exfiltrate repo source).
app.post('/api/github/webhook', (req, res) => {
  const secret = config.github.webhookSecret
  if (secret) {
    const sig = req.headers['x-hub-signature-256'] || ''
    const expected = 'sha256=' + createHmac('sha256', secret).update(req.rawBody || Buffer.from(JSON.stringify(req.body || {}))).digest('hex')
    const a = Buffer.from(sig)
    const b = Buffer.from(expected)
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'invalid webhook signature' })
    }
  } else {
    // No secret configured — restrict to private networks
    const ip = req.socket.remoteAddress || ''
    const isLocal = ip === '::1' || ip === '::ffff:127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')
    if (!isLocal) return res.status(401).json({ error: 'webhook secret not configured; remote requests rejected' })
  }

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
      const filesToAudit = (repoBundle.files && repoBundle.files.length > 0)
        ? repoBundle.files
        : (repoBundle.fileContents && repoBundle.fileContents.length > 0)
          ? repoBundle.fileContents
          : [{ path: `repository/${event.repoFullName}`, content: repoBundle.consolidatedSource }]
      await pipeline.runWhitebox(scan, { files: filesToAudit, language: '', focus: 'OWASP Top 10 & Vulnerability Code Review', verify: true })
    } catch (err) {
      console.error(`[webhook] Background automated scan failed:`, err.message)
    }
  })

  res.status(202).json({ success: true, message: `Queued automated audit for ${event.repoFullName} (${event.type})` })
})

// ── Billing & Subscriptions API ───────────────────────────────────────────────

// Get all subscription plans (dynamically fetched from database with fallback)
app.get('/api/billing/plans', (req, res) => {
  try {
    const plans = getAllPlans({ onlyOpen: true })
    if (plans && plans.length > 0) {
      return res.json({ plans })
    }
  } catch (e) {
    console.warn('[billing] error fetching open plans:', e.message)
  }
  res.json({ plans: Object.values(PLANS) })
})

// Get billing & payment gateway public config
app.get('/api/billing/config', (req, res) => {
  res.json({
    stripeEnabled: Boolean(config.stripe?.publishableKey && config.stripe?.secretKey),
    publishableKey: config.stripe?.publishableKey || '',
    currency: (config.stripe?.currency || 'MYR').toUpperCase(),
    duitnow: {
      enabled: true,
      merchantName: config.duitnow?.merchantName || 'MUHAMMAD SAIFUDIN BIN MO',
      merchantAccount: config.duitnow?.merchantAccount || 'MDN1782300742811690',
      qrPayload: config.duitnow?.qrPayload || '',
      qrImage: config.duitnow?.qrImage || '/duitnow-card.png',
      qrPrompt: 'Scan with ShopeePay, Touch n Go eWallet, Maybank MAE, CIMB OCTO, or any Malaysian banking app',
    },
  })
})

// Get current user subscription & quota status
app.get('/api/billing/subscription', requireAuth, (req, res) => {
  const sub = getUserSubscription(req.user.id)
  res.json(sub)
})

// Create checkout / Upgrade subscription plan (Stripe Live Checkout or DuitNow QR)
app.post('/api/billing/checkout', requireAuth, async (req, res) => {
  const { planId, billingInterval = 'monthly', provider = 'stripe', promoCode = '', referenceNumber = '' } = req.body || {}
  if (!planId || !PLANS[planId]) return res.status(400).json({ error: 'Valid planId is required' })

  const plan = PLANS[planId]
  let amount = billingInterval === 'yearly' ? plan.priceYearly : plan.priceMonthly
  if (planId === 'pay_per_scan') {
    amount = plan.priceMonthly || 3.0
  }

  // Calculate promo discount if applicable
  let discountAmount = 0
  let appliedPromo = ''
  if (promoCode && promoCode.trim()) {
    try {
      const val = validatePromoCode(promoCode.trim(), planId, billingInterval)
      if (val?.valid) {
        discountAmount = val.discountAmount
        appliedPromo = val.code
      }
    } catch { /* ignore */ }
  }
  const finalAmount = Math.max(0, amount - discountAmount)

  // If provider is Stripe, create real Stripe Checkout Session
  if (provider === 'stripe') {
    if (!config.stripe?.secretKey) {
      return res.status(400).json({ error: 'Stripe gateway is currently unavailable on this server. Please use DuitNow QR or contact support.' })
    }
    try {
      const origin = req.headers.origin || req.headers.referer ? new URL(req.headers.referer || req.headers.origin).origin : 'https://sentinelai.studio'
      const session = await createStripeCheckoutSession({
        userId: req.user.id,
        userEmail: req.user.email || `${req.user.username}@sentinelai.studio`,
        planId,
        billingInterval,
        promoCode: appliedPromo,
        origin,
      })

      audit(req.user.username, 'billing:stripe_checkout', `Initiated Stripe Checkout for ${plan.name} (${session.sessionId})`)
      return res.json({
        success: true,
        provider: 'stripe',
        url: session.url,
        sessionId: session.sessionId,
      })
    } catch (err) {
      console.error('[stripe] Checkout session creation failed:', err.message)
      return res.status(500).json({ error: `Stripe checkout initialization failed: ${err.message}` })
    }
  }

  // DuitNow QR payment fulfillment
  if (provider === 'duitnow_qr' || provider === 'local_fpx') {
    const txRef = referenceNumber?.trim()
    if (!txRef || txRef.length < 5) {
      return res.status(400).json({ error: 'Sila masukkan nombor rujukan transaksi DuitNow / slip bayaran yang sah (minimum 5 aksara).' })
    }
    const now = new Date().toISOString()

    if (planId === 'pay_per_scan') {
      const currentSub = getUserSubscription(req.user.id)
      const currentQuotaTotal = Number(currentSub.scan_quota_total || currentSub.scanQuotaTotal || 3)
      const newQuotaTotal = currentQuotaTotal + 1
      const txId = `tx_${Date.now().toString(36)}_${randomUUID().slice(0, 6)}`

      db.run(
        `UPDATE subscriptions SET scan_quota_total = ?, updated_at = ? WHERE user_id = ?`,
        newQuotaTotal,
        now,
        req.user.id
      )

      db.run(
        `INSERT INTO payment_transactions (id, user_id, amount, currency, status, provider, reference_id, plan_id, discount_amount, promo_code, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        txId,
        req.user.id,
        finalAmount,
        'MYR',
        'completed',
        provider,
        txRef,
        'pay_per_scan',
        discountAmount,
        appliedPromo,
        now
      )

      audit(req.user.username, `billing:${provider}`, `Topped up 1 Scan Credit via ${provider} (RM${finalAmount}) Ref: ${txRef}`)
      return res.json({
        success: true,
        provider,
        referenceId: txRef,
        message: `DuitNow QR payment confirmed! 1 Scan Credit added to your account.`,
        subscription: getUserSubscription(req.user.id),
      })
    }

    // Pro or Enterprise upgrade via DuitNow QR
    const updatedSub = activateSubscription({
      userId: req.user.id,
      planId,
      amount: finalAmount,
      provider,
      referenceId: txRef,
      interval: billingInterval,
      promoCode: appliedPromo,
    })

    audit(req.user.username, `billing:${provider}`, `Upgraded to ${plan.name} via ${provider} (RM${finalAmount}) Ref: ${txRef}`)
    return res.json({
      success: true,
      provider,
      referenceId: txRef,
      message: `🎉 DuitNow QR payment verified! Successfully upgraded to ${plan.name}.`,
      subscription: updatedSub,
    })
  }

  // Reject any unsupported or unverified provider — never bypass payment
  return res.status(400).json({ error: 'Kaedah pembayaran tidak sah atau tidak disokong. Sila pilih Stripe atau DuitNow QR.' })
})

// Verify Stripe Checkout Session and activate subscription
app.post('/api/billing/verify-session', requireAuth, async (req, res) => {
  const { sessionId } = req.body || {}
  if (!sessionId) return res.status(400).json({ error: 'sessionId is required' })

  try {
    const result = await verifyAndFulfillSession(sessionId)
    if (!result.success) {
      return res.status(400).json({ error: result.message || 'Payment not completed' })
    }

    audit(req.user.username, 'billing:verified', `Stripe payment verified for session ${sessionId}`)
    res.json({
      success: true,
      subscription: result.subscription,
      planId: result.planId,
    })
  } catch (err) {
    console.error('[stripe] Session verification failed:', err.message)
    res.status(500).json({ error: `Verification failed: ${err.message}` })
  }
})

// Stripe Webhook listener for asynchronous confirmation
app.post('/api/billing/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature']
  const stripe = getStripe()

  if (!stripe) return res.status(400).send('Stripe not configured')

  // Fail closed. Without signature verification anyone could POST a forged
  // `checkout.session.completed` event and drive server-side fulfilment, so we
  // only ever process events that Stripe itself signed.
  if (!config.stripe?.webhookSecret) {
    console.error('[stripe] Webhook rejected: STRIPE_WEBHOOK_SECRET is not configured')
    return res.status(503).send('Webhook endpoint not configured')
  }
  if (!sig || !req.rawBody) {
    return res.status(400).send('Webhook Error: missing stripe-signature header')
  }

  let event
  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, config.stripe.webhookSecret)
  } catch (err) {
    console.warn('[stripe] Webhook signature verification failed:', err.message)
    return res.status(400).send(`Webhook Error: ${err.message}`)
  }

  if (event?.type === 'checkout.session.completed') {
    const session = event?.data?.object
    if (session?.id) {
      try {
        await verifyAndFulfillSession(session.id)
        console.log(`[stripe] Checkout session fulfilled via webhook: ${session.id}`)
      } catch (err) {
        console.error(`[stripe] Webhook fulfillment error: ${err.message}`)
      }
    }
  }

  res.json({ received: true })
})

// Payment transaction history
app.get('/api/billing/history', requireAuth, (req, res) => {
  const history = getPaymentHistory(req.user.id)
  res.json({ transactions: history })
})

// ── Dashboard ────────────────────────────────────────────────────────────────
app.get('/api/dashboard', requireAuth, (req, res) => {
  let scans = []
  let projsCount = 0

  if (req.user?.role === 'client') {
    const userEmail = (req.user.email || '').toLowerCase()
    const username = (req.user.username || '').toLowerCase()
    const userId = req.user.id

    const allProjs = db.all(`SELECT * FROM projects`)
    const matchProjs = allProjs.filter((p) => canAccessProject(req.user, p))
    projsCount = matchProjs.length
    const projIds = matchProjs.map(p => p.id)

    if (projIds.length > 0) {
      const placeholders = projIds.map(() => '?').join(',')
      scans = db.all(`
        SELECT * FROM scans 
        WHERE project_id IN (${placeholders}) 
           OR (user_id IS NOT NULL AND user_id = ?) 
           OR (client IS NOT NULL AND (LOWER(client) = ? OR LOWER(client) = ?))
        ORDER BY created_at DESC
      `, ...projIds, userId, username, userEmail)
    } else {
      scans = db.all(`
        SELECT * FROM scans 
        WHERE (user_id IS NOT NULL AND user_id = ?) 
           OR (client IS NOT NULL AND (LOWER(client) = ? OR LOWER(client) = ?))
        ORDER BY created_at DESC
      `, userId, username, userEmail)
    }
  } else {
    scans = db.all(`SELECT * FROM scans ORDER BY created_at DESC`)
    projsCount = db.get(`SELECT COUNT(*) c FROM projects`)?.c || 0
  }

  const scanIds = scans.map(s => s.id)
  let findings = []
  if (scanIds.length > 0) {
    const placeholders = scanIds.map(() => '?').join(',')
    findings = db.all(`SELECT severity FROM findings WHERE scan_id IN (${placeholders})`, ...scanIds)
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
  const recent = scans.slice(0, 8)
  res.json({
    totals: { projects: projsCount, scans: scans.length, findings: findings.length },
    severity: counts,
    recentScans: recent,
    runningScans: scans.filter(s => s.status === 'running').length,
    agentsCount: agentRegistry.list().length,
  })
})

// ── Professional Security Consultation & Advisory ──────────────────────────
app.get('/api/consultations', requireAuth, (req, res) => {
  try {
    const isStaff = req.user?.role !== 'client'
    const requests = isStaff
      ? db.all(`SELECT * FROM consultation_requests ORDER BY created_at DESC`)
      : db.all(`SELECT * FROM consultation_requests WHERE user_id = ? ORDER BY created_at DESC`, req.user.id)
    res.json({ consultations: requests || [] })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/consultations', requireAuth, (req, res) => {
  try {
    const {
      serviceType,
      consultantName = 'Any Specialist',
      scanId = null,
      preferredDate,
      preferredTime,
      channel = 'Google Meet',
      notes = ''
    } = req.body || {}

    if (!serviceType || !serviceType.trim()) {
      return res.status(400).json({ error: 'Service type is required' })
    }

    const sub = getUserSubscription(req.user.id)
    const planTier = sub?.plan_id || 'none'
    const id = `cons_${randomUUID().slice(0, 16)}`
    const now = new Date().toISOString()

    db.run(
      `INSERT INTO consultation_requests (
        id, user_id, username, email, service_type, consultant_name, scan_id,
        preferred_date, preferred_time, channel, notes, plan_tier, status,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      id,
      req.user.id,
      req.user.username || 'client',
      req.user.email || '',
      serviceType.trim(),
      consultantName.trim(),
      scanId || null,
      preferredDate || null,
      preferredTime || null,
      channel || 'Google Meet',
      notes.trim(),
      planTier,
      now,
      now
    )

    audit(req.user.username, 'consultation:request', `${serviceType} with ${consultantName}`)
    const created = db.get(`SELECT * FROM consultation_requests WHERE id = ?`, id)

    // Trigger email notification to muhammadsaifudinmj@gmail.com
    sendConsultationBookingNotification({
      consultation: created,
      user: req.user
    }).catch(err => console.error('[email] Consultation notification delivery error:', err.message))

    // Broadcast alert to Telegram channel gateway if configured
    try {
      const teleMsg = `📅 *New Consultation Booking Request!*\n\n` +
        `👤 *Client:* ${req.user.username} (${req.user.email || 'N/A'})\n` +
        `📦 *Package:* ${serviceType}\n` +
        `👨‍💼 *Advisor:* ${consultantName}\n` +
        `🗓️ *Schedule:* ${preferredDate || 'Flexible'} ${preferredTime || ''}\n` +
        `💻 *Platform:* ${channel}\n` +
        `📝 *Notes:* ${notes.trim() || 'None'}`
      import('./channels/index.js').then(({ channelGateway }) => {
        channelGateway.broadcastAlert(teleMsg).catch(() => {})
      }).catch(() => {})
    } catch {}

    return res.status(201).json({
      success: true,
      consultation: created,
      message: 'Permintaan tempahan konsultasi anda telah berjaya dihantar ke muhammadsaifudinmj@gmail.com!'
    })
  } catch (err) {
    console.error('Consultation creation error:', err)
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/consultations/:id', requireAuth, requireStaff, (req, res) => {
  try {
    const existing = db.get(`SELECT * FROM consultation_requests WHERE id = ?`, req.params.id)
    if (!existing) return res.status(404).json({ error: 'Consultation request not found' })

    const { status = existing.status, meetingLink = existing.meeting_link, adminNotes = existing.admin_notes } = req.body || {}
    const now = new Date().toISOString()

    db.run(
      `UPDATE consultation_requests SET status = ?, meeting_link = ?, admin_notes = ?, updated_at = ? WHERE id = ?`,
      status,
      meetingLink,
      adminNotes,
      now,
      req.params.id
    )

    audit(req.user.username, 'consultation:update', `${req.params.id} -> ${status}`)
    const updated = db.get(`SELECT * FROM consultation_requests WHERE id = ?`, req.params.id)
    res.json({ success: true, consultation: updated })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ── Channel gateway (Telegram/Discord bots) ─────────────────────────────────
app.get('/api/channels/me', requireAuth, (req, res) => {
  try {
    const telePairing = db.get("SELECT * FROM telegram_pairings WHERE user_id = ? AND platform = 'telegram' AND status = 'approved' ORDER BY approved_at DESC LIMIT 1", req.user.id)
    const discordPairing = db.get("SELECT * FROM telegram_pairings WHERE user_id = ? AND platform = 'discord' AND status = 'approved' ORDER BY approved_at DESC LIMIT 1", req.user.id)
    res.json({
      telegram: {
        paired: !!telePairing,
        chatId: telePairing?.chat_id,
        senderName: telePairing?.sender_name,
        approvedAt: telePairing?.approved_at,
        botUsername: 'sentinelai_telebot'
      },
      discord: {
        paired: !!discordPairing,
        chatId: discordPairing?.chat_id,
        senderName: discordPairing?.sender_name,
        approvedAt: discordPairing?.approved_at,
        botName: 'Sentinel AI'
      }
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.post('/api/channels/pair', requireAuth, (req, res) => {
  try {
    const { code } = req.body || {}
    if (!code) return res.status(400).json({ error: 'Sila masukkan kod 6-digit dari Telegram atau Discord' })
    const trimmedCode = String(code).trim()
    const pending = db.get("SELECT * FROM telegram_pairings WHERE pairing_code = ? AND status = 'pending'", trimmedCode)
    if (!pending) {
      return res.status(404).json({ error: 'Kod pairing tidak sah atau telah tamat. Sila taip /start di Telegram (@sentinelai_telebot) atau di Discord (@Sentinel AI /start) untuk mendapatkan kod baharu.' })
    }
    const now = new Date().toISOString()
    const platform = pending.platform || 'telegram'
    const platformLabel = platform === 'discord' ? 'Discord' : 'Telegram'

    // Unlink old pairing of this user on this specific platform
    db.run("DELETE FROM telegram_pairings WHERE user_id = ? AND platform = ?", req.user.id, platform)
    db.run("UPDATE telegram_pairings SET user_id = ?, username = ?, status = 'approved', approved_at = ? WHERE id = ?",
      req.user.id, req.user.username || req.user.email, now, pending.id)
    
    const confirmMsg = `🎉 *Akaun Berjaya Disambungkan!*\n\n` +
      `Disambungkan ke akaun SentinelAI: *${req.user.username || req.user.email}* (${req.user.role?.toUpperCase() || 'CLIENT'})\n\n` +
      `Anda kini boleh menggunakan arahan berikut secara terus:\n` +
      `• \`/scans\` — Senarai imbasan akaun anda\n` +
      `• \`/status\` — Semak status semasa sistem\n` +
      `• \`/scan <url>\` — Lancarkan imbasan pentest baharu\n` +
      `• \`/help\` — Senarai semua arahan\n\n` +
      `🌐 Portal: https://sentinelai.studio`

    if (platform === 'discord') {
      import('./channels/discord.js').then(({ discordBot }) => {
        discordBot.sendTo(pending.chat_id, confirmMsg).catch(err => console.error('Discord notification failed:', err.message))
      }).catch(err => console.error('Discord pairing failed:', err.message))
    } else {
      import('./channels/telegram.js').then(({ telegramBot }) => {
        telegramBot.sendTo(pending.chat_id, confirmMsg).catch(err => console.error('Telegram notification failed:', err.message))
      }).catch(err => console.error('Telegram pairing failed:', err.message))
    }

    res.json({
      ok: true,
      message: `Akaun ${platformLabel} berjaya dipautkan!`,
      platform,
      chatId: pending.chat_id,
      senderName: pending.sender_name
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.post('/api/channels/unpair', requireAuth, (req, res) => {
  try {
    const { platform } = req.body || {}
    if (platform) {
      db.run("DELETE FROM telegram_pairings WHERE user_id = ? AND platform = ?", req.user.id, String(platform))
    } else {
      db.run("DELETE FROM telegram_pairings WHERE user_id = ?", req.user.id)
    }
    res.json({ ok: true, message: 'Sambungan telah diputuskan.' })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.get('/api/channels', requireAuth, requireStaff, (req, res) => {
  res.json({
    connected: channelGateway.channels.map(c => ({ platform: c.platform, identity: c.me?.username || null })),
    approved: channelGateway.listApproved(),
  })
})

// ── Centralized Production-Safe Error Handler ──────────────────────────────
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500
  const isProd = process.env.NODE_ENV === 'production'
  // Redact any sensitive tokens or secrets before logging
  const safeMessage = (err?.message || 'Internal server error')
    .replace(/(bearer\s+)[a-zA-Z0-9_\-\.]+/gi, '$1[REDACTED]')
    .replace(/(password["':\s]+)[^"'\s,}]+/gi, '$1[REDACTED]')
  console.error(`[API Error ${status}]:`, safeMessage)
  res.status(status).json({
    error: isProd && status === 500 ? 'An internal error occurred. Please contact the security administrator.' : safeMessage,
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
server.listen(PORT, async () => {
  console.log(`\n[FYP2] Unified Pentest Platform backend listening on http://localhost:${PORT}`)
  console.log(`[FYP2] Native scanner engine: direct subprocess execution (hexstrike removed)`)
  console.log(`[FYP2] Agents: ${agentRegistry.list().length} | RAG docs: ${payloadsRag.payloadsIndexStatus().docs}`)

  // Channel gateway (Telegram/Discord bots) — non-fatal if tokens missing.
  try {
    channelGateway.attach({ io, pipeline, orchestrator: exploitEngine, agentRegistry })
    await channelGateway.start()
  } catch (e) {
    console.warn(`[FYP2] Channel gateway failed to start: ${e.message}`)
  }
})

process.on('uncaughtException', (err) => {
  console.error('[FYP2 Backend uncaughtException]:', err?.message || err)
})
process.on('unhandledRejection', (reason) => {
  console.error('[FYP2 Backend unhandledRejection]:', reason?.message || reason)
})
