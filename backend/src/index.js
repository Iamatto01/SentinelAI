import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import express from 'express'
import cors from 'cors'
import { Server as SocketIOServer } from 'socket.io'
import { randomUUID } from 'node:crypto'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

import { authMiddleware, requireAuth, requireRole } from './auth.js'
import {
  db, seedIfEmpty,
  addProject, saveProject, removeProject,
  addScan, saveScan,
  initVulns, addVuln, saveVulnStatus,
  initLogs, addLog,
  addAudit,
} from './data.js'
import { dbGetUserByUsername, dbUpdateUserLastLogin } from './database.js'
import { getCveById, searchCve } from './cve.js'
import { runScan, buildModules, getModuleSelection } from './scanner/orchestrator.js'
import { generateReport } from './report.js'

const PORT = Number(process.env.PORT || 5000)
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173'
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const JWT_ISSUER = process.env.JWT_ISSUER || 'vlolv-backend'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

// Remove technology fingerprinting headers
app.disable('x-powered-by')

// Security headers middleware
app.use((req, res, next) => {
  // Only set HSTS on HTTPS connections (including behind reverse proxies)
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
  }
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:")
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  next()
})

app.use(express.json({ limit: '1mb' }))
app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  }),
)
app.use(authMiddleware)

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() })
})

// ── Auth ──────────────────────────────────────────────────────────────────────

// Simple in-memory rate limiter for login: max 10 attempts per IP per 15 minutes
const loginAttempts = new Map()
const LOGIN_WINDOW_MS = 15 * 60 * 1000
const LOGIN_MAX_ATTEMPTS = 10

function loginRateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown'
  const now = Date.now()
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + LOGIN_WINDOW_MS }
  if (now > entry.resetAt) {
    entry.count = 0
    entry.resetAt = now + LOGIN_WINDOW_MS
  }
  entry.count += 1
  loginAttempts.set(ip, entry)
  if (entry.count > LOGIN_MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000)
    res.setHeader('Retry-After', String(retryAfter))
    return res.status(429).json({ error: 'Too many login attempts. Please try again later.' })
  }
  next()
}

app.post('/api/auth/login', loginRateLimiter, (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' })
  }

  void (async () => {
    const record = await dbGetUserByUsername(username)
    if (!record) {
      return res.status(401).json({ error: 'Invalid username or password' })
    }

    const ok = bcrypt.compareSync(password, record.passwordHash)
    if (!ok) {
      return res.status(401).json({ error: 'Invalid username or password' })
    }

    const role = record.role || 'analyst'
    const permissions =
      role === 'admin' ? ['all'] : role === 'client' ? ['read'] : ['read', 'scan', 'report']

    const email = record.email || (role === 'client' ? String(username).toLowerCase() : `${username}@company.com`)
    const lastLogin = new Date().toISOString()
    await dbUpdateUserLastLogin(record.id, lastLogin)

    const user = {
      id: record.id,
      username: record.username,
      email,
      role,
      permissions,
      assignedProjectIds: role === 'client' ? getClientProjectIds({ role: 'client', email }) || [] : [],
      lastLogin,
    }

    const token = jwt.sign(
      {
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
        lastLogin: user.lastLogin,
      },
      JWT_SECRET,
      { issuer: JWT_ISSUER, subject: user.id, expiresIn: '12h' },
    )

    addAudit({
      user: user.username,
      action: 'LOGIN',
      resource: user.id,
      details: `User logged in (role: ${role})`,
    })

    return res.json({ success: true, token, user })
  })().catch((e) => {
    console.error('[auth] login error:', e)
    return res.status(500).json({ error: 'Login failed' })
  })
})

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user })
})

// ── Projects ──────────────────────────────────────────────────────────────────

app.get('/api/projects', requireAuth, (req, res) => {
  const clientPids = getClientProjectIds(req.user)
  const projects = clientPids ? db.projects.filter((p) => clientPids.includes(p.id)) : db.projects
  res.json({ projects })
})

app.get('/api/projects/:id', requireAuth, (req, res) => {
  const project = db.projects.find((p) => p.id === req.params.id)
  if (!project) return res.status(404).json({ error: 'Project not found' })
  const clientPids = getClientProjectIds(req.user)
  if (clientPids && !clientPids.includes(project.id)) return res.status(403).json({ error: 'Forbidden' })
  const scans = db.scans.filter((s) => s.projectId === project.id)
  res.json({ project, scans })
})

app.post('/api/projects', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const data = req.body || {}
  if (!data.name || !data.client || !data.owner) {
    return res.status(400).json({ error: 'name, client, and owner required' })
  }

  const now = new Date().toISOString()
  const project = {
    id: 'proj_' + randomUUID(),
    ...data,
    clientEmails: Array.isArray(data.clientEmails) ? data.clientEmails : [],
    createdAt: now,
    updatedAt: now,
    scanCount: 0,
    vulnerabilityCount: 0,
    status: 'active',
  }

  addProject(project)
  addAudit({
    user: req.user.username,
    action: 'PROJECT_CREATED',
    resource: project.id,
    details: `Project created: ${project.name}`,
  })

  res.status(201).json({ project })
})

app.put('/api/projects/:id', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const project = db.projects.find((p) => p.id === req.params.id)
  if (!project) return res.status(404).json({ error: 'Project not found' })
  const data = req.body || {}
  const safe = ['name', 'client', 'owner', 'description', 'status', 'riskLevel', 'startDate', 'endDate', 'scope', 'clientEmails']
  for (const key of safe) {
    if (data[key] !== undefined) project[key] = data[key]
  }
  project.updatedAt = new Date().toISOString()
  saveProject(project)
  addAudit({
    user: req.user.username,
    action: 'PROJECT_UPDATED',
    resource: project.id,
    details: `Project updated: ${project.name}`,
  })
  res.json({ project })
})

app.delete('/api/projects/:id', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const removed = removeProject(req.params.id)
  if (!removed) return res.status(404).json({ error: 'Project not found' })
  addAudit({
    user: req.user.username,
    action: 'PROJECT_DELETED',
    resource: removed.id,
    details: `Project deleted: ${removed.name}`,
  })
  res.json({ success: true })
})

// ── Scans ─────────────────────────────────────────────────────────────────────

app.get('/api/scans', requireAuth, (req, res) => {
  const clientPids = getClientProjectIds(req.user)
  const scans = clientPids ? db.scans.filter((s) => clientPids.includes(s.projectId)) : db.scans
  res.json({ scans })
})

app.post('/api/scan/start', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const data = req.body || {}
  if (!data.target) {
    return res.status(400).json({ error: 'target is required' })
  }

  // Validate URL
  try {
    new URL(data.target)
  } catch {
    return res.status(400).json({ error: 'target must be a valid URL (e.g. https://example.com)' })
  }

  const template = data.template || 'standard'
  const moduleSelection = getModuleSelection(template, data.modules)
  const modules = buildModules(moduleSelection)

  const now = new Date().toISOString()
  const scan = {
    id: 'scan_' + randomUUID(),
    target: data.target,
    template,
    projectId: data.projectId || null,
    status: 'running',
    progress: 0,
    startTime: now,
    modules,
    vulnerabilitiesFound: 0,
    assetsScanned: 0,
  }

  addScan(scan)
  initLogs(scan.id)
  initVulns(scan.id)
  pushLog(scan.id, 'info', `Scan initiated for ${scan.target} (template: ${template})`)

  addAudit({
    user: req.user.username,
    action: 'SCAN_STARTED',
    resource: scan.id,
    details: `Scan started for target ${scan.target}`,
  })

  // Run scan asynchronously
  runScan(scan.id, data.target, { template, modules: moduleSelection }, { db, io, pushLog, addAudit, saveScan, saveProject, addVuln })

  res.status(201).json({ scan })
})

app.post('/api/scan/pause', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const { scanId } = req.body || {}
  const scan = db.scans.find((s) => s.id === scanId) || null
  if (!scan) return res.status(404).json({ error: 'Scan not found' })
  scan.status = 'paused'
  saveScan(scan)
  pushLog(scan.id, 'warn', 'Scan paused by user')
  addAudit({
    user: req.user.username,
    action: 'SCAN_PAUSED',
    resource: scan.id,
    details: `Scan paused for target ${scan.target}`,
  })
  emitScanUpdate(scan.id)
  res.json({ scan })
})

app.post('/api/scan/stop', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const { scanId } = req.body || {}
  const scan = db.scans.find((s) => s.id === scanId) || null
  if (!scan) return res.status(404).json({ error: 'Scan not found' })
  scan.status = 'stopped'
  scan.progress = Math.min(100, scan.progress || 0)
  saveScan(scan)
  pushLog(scan.id, 'error', 'Scan stopped by user')
  addAudit({
    user: req.user.username,
    action: 'SCAN_STOPPED',
    resource: scan.id,
    details: `Scan stopped for target ${scan.target}`,
  })
  emitScanUpdate(scan.id)
  res.json({ scan })
})

app.get('/api/scan/status', requireAuth, (req, res) => {
  const scanId = req.query.scanId
  const scan = db.scans.find((s) => s.id === scanId) || null
  if (!scan) return res.status(404).json({ error: 'Scan not found' })
  const clientPids = getClientProjectIds(req.user)
  if (clientPids && !clientPids.includes(scan.projectId)) return res.status(403).json({ error: 'Forbidden' })
  res.json({ scan })
})

app.get('/api/scan/logs', requireAuth, (req, res) => {
  const scanId = req.query.scanId
  const scan = db.scans.find((s) => s.id === scanId)
  const clientPids = getClientProjectIds(req.user)
  if (scan && clientPids && !clientPids.includes(scan.projectId)) return res.status(403).json({ error: 'Forbidden' })
  const logs = db.scanLogsByScanId.get(scanId) || []
  res.json({ logs })
})

app.get('/api/scan/results', requireAuth, (req, res) => {
  const scanId = req.query.scanId
  const scan = db.scans.find((s) => s.id === scanId)
  const clientPids = getClientProjectIds(req.user)
  if (scan && clientPids && !clientPids.includes(scan.projectId)) return res.status(403).json({ error: 'Forbidden' })
  const vulnerabilities = db.vulnerabilitiesByScanId.get(scanId) || []
  res.json({ vulnerabilities })
})

// ── Vulnerability Status Update ─────────────────────────────────────────────

app.put('/api/scan/results/:vulnId/status', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const { vulnId } = req.params
  const { status } = req.body || {}
  const validStatuses = ['open', 'in-progress', 'closed']
  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${validStatuses.join(', ')}` })
  }

  // Search across all scans
  for (const [, vulns] of db.vulnerabilitiesByScanId) {
    const vuln = vulns.find((v) => v.id === vulnId)
    if (vuln) {
      saveVulnStatus(vulnId, status)
      addAudit({
        user: req.user.username,
        action: 'VULN_STATUS_UPDATED',
        resource: vulnId,
        details: `Vulnerability status changed to ${status}`,
      })
      return res.json({ vulnerability: vuln })
    }
  }

  return res.status(404).json({ error: 'Vulnerability not found' })
})

// ── All Vulnerabilities (aggregated) ─────────────────────────────────────────

app.get('/api/vulnerabilities', requireAuth, (req, res) => {
  const clientPids = getClientProjectIds(req.user)
  const all = []
  for (const [scanId, vulns] of db.vulnerabilitiesByScanId) {
    const scan = db.scans.find((s) => s.id === scanId)
    if (clientPids && (!scan || !clientPids.includes(scan.projectId))) continue
    for (const v of vulns) {
      all.push({ ...v, scanId, scanTarget: scan?.target })
    }
  }
  res.json({ vulnerabilities: all })
})

// ── Reports ──────────────────────────────────────────────────────────────────

app.get('/api/reports/generate', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const { type, id } = req.query

  if (!type || !['scan', 'project', 'full'].includes(type)) {
    return res.status(400).json({ error: 'type must be scan, project, or full' })
  }
  if ((type === 'scan' || type === 'project') && !id) {
    return res.status(400).json({ error: 'id is required for scan/project reports' })
  }

  try {
    const pdfStream = await generateReport(type, id || null, db)

    const filename = `security-report-${type}-${new Date().toISOString().slice(0, 10)}.pdf`
    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)

    pdfStream.pipe(res)
    pdfStream.end()

    addAudit({
      user: req.user.username,
      action: 'REPORT_GENERATED',
      resource: id || 'full',
      details: `Generated ${type} report`,
    })
  } catch (err) {
    res.status(500).json({ error: err.message || 'Report generation failed' })
  }
})

// ── Settings & Audit ──────────────────────────────────────────────────────────

app.get('/api/settings', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  res.json({ settings: db.settings })
})

app.get('/api/audit/logs', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  res.json({ logs: db.auditLogs.slice(0, 200), total: db.auditLogs.length })
})

// ── CVE Database (reads from local cvelistV5-main) ────────────────────────────

app.get('/api/cve/search', requireAuth, async (req, res) => {
  const { q, year } = req.query
  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'q parameter required (min 2 chars)' })
  }
  const years = year ? [String(year)] : ['2025', '2024', '2023']
  const cves = await searchCve(q.trim(), { years, limit: 20 })
  addAudit({
    user: req.user.username,
    action: 'CVE_SEARCH',
    resource: 'cvelistV5',
    details: `Searched CVEs for: "${q}"`,
  })
  res.json({ cves, total: cves.length })
})

app.get('/api/cve/:cveId', requireAuth, async (req, res) => {
  const cveId = req.params.cveId.toUpperCase()
  if (!/^CVE-\d{4}-\d+$/.test(cveId)) {
    return res.status(400).json({ error: 'Invalid CVE ID format (expected CVE-YYYY-NNNN)' })
  }
  const cve = await getCveById(cveId)
  if (!cve) return res.status(404).json({ error: `${cveId} not found in local CVE database` })
  addAudit({
    user: req.user.username,
    action: 'CVE_LOOKUP',
    resource: cveId,
    details: `Looked up ${cveId}`,
  })
  res.json({ cve })
})

// ── Socket.io ─────────────────────────────────────────────────────────────────

const httpServer = http.createServer(app)
const io = new SocketIOServer(httpServer, {
  cors: {
    origin: CLIENT_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST'],
  },
})

io.on('connection', (socket) => {
  socket.on('scan:join', (scanId) => {
    if (!scanId) return
    socket.join(`scan:${scanId}`)
  })

  socket.on('scan:leave', (scanId) => {
    if (!scanId) return
    socket.leave(`scan:${scanId}`)
  })
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function pushLog(scanId, level, message, module = 'core') {
  const entry = { timestamp: new Date().toISOString(), level, message, module }
  return addLog(scanId, entry)
}

function emitScanUpdate(scanId) {
  const scan = db.scans.find((s) => s.id === scanId)
  if (!scan) return
  const logs = db.scanLogsByScanId.get(scanId) || []
  io.to(`scan:${scanId}`).emit('scan:update', { scan, logs: logs.slice(-50) })
}

// ── Client access helper ────────────────────────────────────────────────────

function getClientProjectIds(user) {
  if (!user || user.role !== 'client') return null
  const email = (user.email || '').toLowerCase()
  return db.projects
    .filter((p) => Array.isArray(p.clientEmails) && p.clientEmails.some((e) => e.toLowerCase() === email))
    .map((p) => p.id)
}

// ── Serve frontend build ──────────────────────────────────────────────────────

// Block access to sensitive file paths before serving static files
const BLOCKED_EXACT_PATHS = new Set([
  '/.env', '/.ds_store', '/.htaccess',
  '/backup.zip', '/backup.sql', '/database.sql',
  '/config.php', '/web.config', '/crossdomain.xml',
  '/wp-login.php', '/phpinfo.php', '/server-status',
])
const BLOCKED_PATH_PREFIXES = ['/.git', '/wp-admin']

app.use((req, res, next) => {
  const p = req.path.toLowerCase()
  if (
    BLOCKED_EXACT_PATHS.has(p) ||
    BLOCKED_PATH_PREFIXES.some((prefix) => p === prefix || p.startsWith(prefix + '/'))
  ) {
    return res.status(404).end()
  }
  next()
})

const distPath = path.join(__dirname, '../../frontend/dist')
app.use(express.static(distPath))
app.get('*', (req, res) => {
  res.sendFile(path.join(distPath, 'index.html'))
})

// ── Start ─────────────────────────────────────────────────────────────────────

async function start() {
  if (JWT_SECRET === 'dev-secret-change-me') {
    console.warn('[backend] WARNING: JWT_SECRET is using the insecure default value. Set the JWT_SECRET environment variable in production.')
  }
  await seedIfEmpty()
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`[backend] listening on http://0.0.0.0:${PORT}`)
    console.log(`[backend] allow origin: ${CLIENT_ORIGIN}`)
  })
}

start().catch((err) => {
  console.error('[backend] Failed to start:', err)
  process.exit(1)
})
