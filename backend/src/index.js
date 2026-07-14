// ── Global error handlers (prevent crashes from transient DB/network errors) ──
process.on('unhandledRejection', (reason) => {
  console.error('[backend] Unhandled rejection (non-fatal):', reason?.message || reason)
})
process.on('uncaughtException', (err) => {
  // Only crash on truly fatal errors, not network hiccups
  if (err.code === 'EAI_AGAIN' || err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT') {
    console.error('[backend] Network error (non-fatal):', err.message)
    return
  }
  console.error('[backend] Fatal uncaught exception:', err)
  process.exit(1)
})

import http from 'node:http'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import fs from 'node:fs/promises'
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
  db, seedIfEmpty, ensureClientUsersFromProjects,
  addProject, saveProject, removeProject,
  addScan, saveScan,
  initVulns, addVuln, saveVulnStatus,
  initLogs, addLog,
  addAudit,
} from './data.js'
import { dbGetUserByUsername, dbUpdateUserLastLogin, dbGetUserByEmail, dbUpdateUser } from './database.js'
import { getCveById, searchCve } from './cve.js'
import { runScan, buildModules, getModuleSelection } from './scanner/orchestrator.js'
import { generateReport } from './report.js'
import { AIAgentController } from './ai/agent-controller.js'
import { AISessionLogger } from './ai/session-logger.js'
import { AICostTracker } from './ai/cost-tracker.js'
import { generateVulnSummary, generateProjectSummary } from './ai/voice-summary.js'
import { AIWorker } from './ai/ai-worker.js'
import { MonitorScheduler } from './ai/monitor-scheduler.js'
import { LogAnalyzer } from './ai/log-analyzer.js'
import {
  dbGetAllMonitors, dbGetMonitorById, dbGetMonitorsByProject,
  dbInsertMonitor, dbUpdateMonitor, dbDeleteMonitor,
  dbGetEventsByMonitor, dbGetAlertsByMonitor, dbGetUnacknowledgedAlerts,
  dbAcknowledgeAlert, dbGetReportsByMonitor,
  dbInsertIngestedLogs, dbGetIngestedLogs, dbGetIngestedLogsStats,
  dbDeleteScan
} from './database.js'

const PORT = Number(process.env.PORT || 5000)
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173'
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const JWT_ISSUER = process.env.JWT_ISSUER || 'vlolv-backend'
const HTTPS_KEY_PATH = process.env.HTTPS_KEY_PATH || ''
const HTTPS_CERT_PATH = process.env.HTTPS_CERT_PATH || ''
const HTTPS_CA_PATH = process.env.HTTPS_CA_PATH || ''

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const WORKSPACE_ROOT = path.resolve(__dirname, '../..')
const BLOCKED_WORKSPACE_NAMES = new Set(['.env', '.env.local', '.env.production', '.git', 'node_modules', 'dist', 'build', 'coverage'])

function resolveWorkspacePath(requestedPath) {
  if (!requestedPath || typeof requestedPath !== 'string') return null

  const cleaned = requestedPath
    .trim()
    .replace(/^file:\/\//i, '')
    .replace(/^['"`]|['"`]$/g, '')

  if (!cleaned) return null

  const resolved = path.resolve(WORKSPACE_ROOT, cleaned)
  const relative = path.relative(WORKSPACE_ROOT, resolved)

  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return null

  const segments = relative.split(path.sep).map((segment) => segment.toLowerCase())
  if (segments.some((segment) => BLOCKED_WORKSPACE_NAMES.has(segment))) return null

  return resolved
}

function looksLikeFileEditRequest(message = '') {
  return /\b(modify|edit|update|fix|rewrite|patch|replace)\b/i.test(message)
}

// Initialize AI services
const aiSessionLogger = new AISessionLogger()
const aiCostTracker = new AICostTracker()
const aiController = new AIAgentController({
  sessionLogger: aiSessionLogger,
  costTracker: aiCostTracker,
})
const aiWorker = new AIWorker()
const logAnalyzer = new LogAnalyzer({ aiWorker })
let monitorScheduler = null

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
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()')
  next()
})

app.use(express.json({ limit: '1mb' }))

// Dynamic CORS: allow localhost, 127.0.0.1, and local network IPs (for development)
const isDev = process.env.NODE_ENV !== 'production'
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests without origin (like mobile apps)
      if (!origin) return callback(null, true)
      
      // Always allow configured CLIENT_ORIGIN
      if (origin === CLIENT_ORIGIN) return callback(null, true)
      
      // In development, allow any localhost/127.0.0.1/local IP on port 5173
      if (isDev && /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)(:\d+)?$/.test(origin)) {
        return callback(null, true)
      }
      
      callback(new Error('CORS not allowed'))
    },
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

app.post('/api/auth/login', loginRateLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {}
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' })
    }

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

    await addAudit({
      user: user.username,
      action: 'LOGIN',
      resource: user.id,
      details: `User logged in (role: ${role})`,
    })

    return res.json({ success: true, token, user })
  } catch (e) {
    console.error('[auth] login error:', e)
    return res.status(500).json({ error: 'Login failed' })
  }
})

// ── Client email-only login ──────────────────────────────────────────────────

app.post('/api/auth/client-login', loginRateLimiter, async (req, res) => {
  try {
    const { email } = req.body || {}
    if (!email || !email.trim()) {
      return res.status(400).json({ error: 'Email is required' })
    }

    const normalizedEmail = email.trim().toLowerCase()

    // Look up client user by email
    const record = await dbGetUserByEmail(normalizedEmail)
    if (!record || record.role !== 'client') {
      return res.status(401).json({ error: 'No client account found for this email. Contact your security analyst.' })
    }

    const lastLogin = new Date().toISOString()
    await dbUpdateUserLastLogin(record.id, lastLogin)

    const user = {
      id: record.id,
      username: record.username,
      email: record.email,
      role: 'client',
      permissions: ['read'],
      assignedProjectIds: getClientProjectIds({ role: 'client', email: normalizedEmail }) || [],
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

    await addAudit({
      user: user.username,
      action: 'CLIENT_LOGIN',
      resource: user.id,
      details: `Client logged in via email: ${normalizedEmail}`,
    })

    return res.json({ success: true, token, user })
  } catch (e) {
    console.error('[auth] client-login error:', e)
    return res.status(500).json({ error: 'Login failed' })
  }
})

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user })
})

app.put('/api/users/me', requireAuth, async (req, res) => {
  try {
    const { email, password } = req.body || {}
    let passwordHash = null;
    if (password && password.trim().length >= 6) {
      passwordHash = bcrypt.hashSync(password, 10);
    }
    
    await dbUpdateUser(req.user.id, email || req.user.email, passwordHash);

    await addAudit({
      user: req.user.username,
      action: 'USER_PROFILE_UPDATED',
      resource: req.user.id,
      details: `User updated profile.`,
    })

    res.json({ success: true, message: 'Profile updated successfully' })
  } catch (error) {
    res.status(500).json({ error: error.message || 'Update failed' })
  }
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

app.post('/api/projects', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
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

  await addProject(project)

  // Create client user accounts for any new client emails
  await ensureClientUsersFromProjects()

  await addAudit({
    user: req.user.username,
    action: 'PROJECT_CREATED',
    resource: project.id,
    details: `Project created: ${project.name}`,
  })

  res.status(201).json({ project })
})

app.put('/api/projects/:id', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const project = db.projects.find((p) => p.id === req.params.id)
  if (!project) return res.status(404).json({ error: 'Project not found' })
  const data = req.body || {}
  const safe = ['name', 'client', 'owner', 'description', 'status', 'riskLevel', 'startDate', 'endDate', 'scope', 'clientEmails']
  for (const key of safe) {
    if (data[key] !== undefined) project[key] = data[key]
  }
  project.updatedAt = new Date().toISOString()
  await saveProject(project)

  // Create client user accounts for any new client emails
  await ensureClientUsersFromProjects()

  await addAudit({
    user: req.user.username,
    action: 'PROJECT_UPDATED',
    resource: project.id,
    details: `Project updated: ${project.name}`,
  })
  res.json({ project })
})

app.delete('/api/projects/:id', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const removed = await removeProject(req.params.id)
  if (!removed) return res.status(404).json({ error: 'Project not found' })
  await addAudit({
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

app.post('/api/scan/start', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
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

  await addScan(scan)
  initLogs(scan.id)
  initVulns(scan.id)
  await pushLog(scan.id, 'info', `Scan initiated for ${scan.target} (template: ${template})`)

  await addAudit({
    user: req.user.username,
    action: 'SCAN_STARTED',
    resource: scan.id,
    details: `Scan started for target ${scan.target}`,
  })

  // Run scan asynchronously
  runScan(scan.id, data.target, { template, modules: moduleSelection }, { db, io, pushLog, addAudit, saveScan, saveProject, addVuln })

  res.status(201).json({ scan })
})

app.post('/api/scan/pause', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const { scanId } = req.body || {}
  const scan = db.scans.find((s) => s.id === scanId) || null
  if (!scan) return res.status(404).json({ error: 'Scan not found' })
  scan.status = 'paused'
  await saveScan(scan)
  await pushLog(scan.id, 'warn', 'Scan paused by user')
  await addAudit({
    user: req.user.username,
    action: 'SCAN_PAUSED',
    resource: scan.id,
    details: `Scan paused for target ${scan.target}`,
  })
  emitScanUpdate(scan.id)
  res.json({ scan })
})

app.post('/api/scan/resume', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const { scanId } = req.body || {}
  const scan = db.scans.find((s) => s.id === scanId) || null
  if (!scan) return res.status(404).json({ error: 'Scan not found' })
  if (scan.status !== 'paused') {
    return res.status(400).json({ error: `Cannot resume a scan with status '${scan.status}'. Only paused scans can be resumed.` })
  }
  scan.status = 'running'
  await saveScan(scan)
  await pushLog(scan.id, 'info', 'Scan resumed by user')
  await addAudit({
    user: req.user.username,
    action: 'SCAN_RESUMED',
    resource: scan.id,
    details: `Scan resumed for target ${scan.target}`,
  })
  emitScanUpdate(scan.id)
  res.json({ scan })
})


app.post('/api/scan/stop', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const { scanId } = req.body || {}
  const scan = db.scans.find((s) => s.id === scanId) || null
  if (!scan) return res.status(404).json({ error: 'Scan not found' })
  scan.status = 'stopped'
  scan.progress = Math.min(100, scan.progress || 0)
  await saveScan(scan)
  await pushLog(scan.id, 'error', 'Scan stopped by user')
  await addAudit({
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

app.delete('/api/scans/:id', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const scan = db.scans.find(s => s.id === req.params.id)
  if (!scan) return res.status(404).json({ error: 'Scan not found' })

  try {
    await dbDeleteScan(req.params.id)
    
    // Clean up memory state
    db.scans = db.scans.filter(s => s.id !== req.params.id)
    db.scanLogsByScanId.delete(req.params.id)
    db.vulnerabilitiesByScanId.delete(req.params.id)
    
    await addAudit({
      user: req.user.username,
      action: 'SCAN_DELETED',
      resource: req.params.id,
      details: `Scan deleted for target ${scan.target}`,
    })

    res.json({ success: true })
  } catch (err) {
    console.error('Delete scan error:', err)
    res.status(500).json({ error: 'Failed to delete scan' })
  }
})

// ── Vulnerability Status Update ─────────────────────────────────────────────

app.put('/api/scan/results/:vulnId/status', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
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
      await saveVulnStatus(vulnId, status)
      await addAudit({
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
  const { scanId: filterScanId, projectId: filterProjectId } = req.query
  
  const all = []
  for (const [scanId, vulns] of db.vulnerabilitiesByScanId) {
    // Filter by scanId if provided
    if (filterScanId && scanId !== filterScanId) continue
    
    const scan = db.scans.find((s) => s.id === scanId)
    
    // Filter by projectId if provided
    if (filterProjectId && (!scan || scan.projectId !== filterProjectId)) continue
    
    if (clientPids && (!scan || !clientPids.includes(scan.projectId))) continue
    for (const v of vulns) {
      all.push({ ...v, scanId, scanTarget: scan?.target })
    }
  }
  res.json({ vulnerabilities: all })
})

// ── Reports ──────────────────────────────────────────────────────────────────

app.get('/api/reports/generate', requireAuth, async (req, res) => {
  const { type, id } = req.query

  if (!type || !['scan', 'project', 'full'].includes(type)) {
    return res.status(400).json({ error: 'type must be scan, project, or full' })
  }
  if ((type === 'scan' || type === 'project') && !id) {
    return res.status(400).json({ error: 'id is required for scan/project reports' })
  }

  // Allow clients to download reports for their own projects
  if (req.user.role === 'client') {
    if (type === 'project') {
      const clientPids = getClientProjectIds(req.user)
      if (!clientPids || !clientPids.includes(id)) {
        return res.status(403).json({ error: 'Forbidden' })
      }
    } else if (type === 'scan') {
      const scan = db.scans.find((s) => s.id === id)
      const clientPids = getClientProjectIds(req.user)
      if (!scan || !clientPids || !clientPids.includes(scan.projectId)) {
        return res.status(403).json({ error: 'Forbidden' })
      }
    } else {
      return res.status(403).json({ error: 'Forbidden' })
    }
  }

  try {
    const pdfStream = await generateReport(type, id || null, db)

    const filename = `security-report-${type}-${new Date().toISOString().slice(0, 10)}.pdf`
    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)

    pdfStream.pipe(res)
    pdfStream.end()

    await addAudit({
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

app.put('/api/settings', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const data = req.body || {}
    if (data.aiMode) db.settings.aiMode = data.aiMode
    if (data.rateLimit) db.settings.rateLimit = Number(data.rateLimit)
    if (data.concurrency) db.settings.concurrency = Number(data.concurrency)
    if (data.apiEndpoint) db.settings.apiEndpoint = data.apiEndpoint
    if (data.modules) db.settings.modules = { ...db.settings.modules, ...data.modules }

    await addAudit({
      user: req.user.username,
      action: 'SETTINGS_UPDATED',
      resource: 'global',
      details: `Global system settings updated.`,
    })

    res.json({ success: true, settings: db.settings })
  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings' })
  }
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
  await addAudit({
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
  await addAudit({
    user: req.user.username,
    action: 'CVE_LOOKUP',
    resource: cveId,
    details: `Looked up ${cveId}`,
  })
  res.json({ cve })
})

// ── Monitoring / SIEM Endpoints ──────────────────────────────────────────────

// Create a new monitor
app.post('/api/monitors', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  const data = req.body || {}
  if (!data.target) {
    return res.status(400).json({ error: 'target URL is required' })
  }

  try { new URL(data.target) } catch {
    return res.status(400).json({ error: 'target must be a valid URL' })
  }

  const validSchedules = ['5m', '15m', '30m', '1h', '6h', '12h', '24h']
  const schedule = validSchedules.includes(data.schedule) ? data.schedule : '1h'
  const defaultModules = ['headers', 'ssl', 'paths', 'cors']
  const modules = Array.isArray(data.modules) && data.modules.length > 0 ? data.modules : defaultModules

  const now = new Date().toISOString()
  const monitor = {
    id: 'mon_' + randomUUID(),
    projectId: data.projectId || null,
    target: data.target,
    schedule,
    modules,
    status: 'active',
    healthStatus: 'unknown',
    lastCheckAt: null,
    nextCheckAt: now,
    totalChecks: 0,
    createdBy: req.user.username,
    createdAt: now,
    updatedAt: now,
  }

  await dbInsertMonitor(monitor)
  await addAudit({
    user: req.user.username,
    action: 'MONITOR_CREATED',
    resource: monitor.id,
    details: `Monitor created for ${monitor.target} (schedule: ${schedule})`,
  })

  res.status(201).json({ monitor })
})

// List all monitors (admin sees all, client sees their projects)
app.get('/api/monitors', requireAuth, async (req, res) => {
  try {
    const clientPids = getClientProjectIds(req.user)
    let monitors = await dbGetAllMonitors()
    if (clientPids) {
      monitors = monitors.filter(m => m.projectId && clientPids.includes(m.projectId))
    }
    res.json({ monitors })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Get single monitor details
app.get('/api/monitors/:id', requireAuth, async (req, res) => {
  try {
    const monitor = await dbGetMonitorById(req.params.id)
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' })

    const clientPids = getClientProjectIds(req.user)
    if (clientPids && (!monitor.projectId || !clientPids.includes(monitor.projectId))) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    res.json({ monitor })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Update monitor (schedule, modules, pause/resume)
app.put('/api/monitors/:id', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const monitor = await dbGetMonitorById(req.params.id)
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' })

    const data = req.body || {}
    const validSchedules = ['5m', '15m', '30m', '1h', '6h', '12h', '24h']
    if (data.schedule && validSchedules.includes(data.schedule)) monitor.schedule = data.schedule
    if (Array.isArray(data.modules)) monitor.modules = data.modules
    if (data.status && ['active', 'paused'].includes(data.status)) monitor.status = data.status
    if (data.projectId !== undefined) monitor.projectId = data.projectId
    monitor.updatedAt = new Date().toISOString()

    await dbUpdateMonitor(monitor)
    await addAudit({
      user: req.user.username,
      action: 'MONITOR_UPDATED',
      resource: monitor.id,
      details: `Monitor updated for ${monitor.target}`,
    })

    res.json({ monitor })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Delete monitor
app.delete('/api/monitors/:id', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const monitor = await dbGetMonitorById(req.params.id)
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' })

    await dbDeleteMonitor(monitor.id)
    await addAudit({
      user: req.user.username,
      action: 'MONITOR_DELETED',
      resource: monitor.id,
      details: `Monitor deleted for ${monitor.target}`,
    })

    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Get monitor events (timeline)
app.get('/api/monitors/:id/events', requireAuth, async (req, res) => {
  try {
    const monitor = await dbGetMonitorById(req.params.id)
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' })

    const clientPids = getClientProjectIds(req.user)
    if (clientPids && (!monitor.projectId || !clientPids.includes(monitor.projectId))) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    const limit = Math.min(Number(req.query.limit) || 100, 500)
    const events = await dbGetEventsByMonitor(monitor.id, limit)
    res.json({ events })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Get monitor alerts
app.get('/api/monitors/:id/alerts', requireAuth, async (req, res) => {
  try {
    const monitor = await dbGetMonitorById(req.params.id)
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' })

    const clientPids = getClientProjectIds(req.user)
    if (clientPids && (!monitor.projectId || !clientPids.includes(monitor.projectId))) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    const alerts = await dbGetAlertsByMonitor(monitor.id)
    res.json({ alerts })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Acknowledge an alert
app.post('/api/monitors/:id/alerts/:alertId/ack', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    await dbAcknowledgeAlert(req.params.alertId, req.user.username)
    await addAudit({
      user: req.user.username,
      action: 'ALERT_ACKNOWLEDGED',
      resource: req.params.alertId,
      details: `Alert acknowledged`,
    })
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Get monitor reports
app.get('/api/monitors/:id/reports', requireAuth, async (req, res) => {
  try {
    const monitor = await dbGetMonitorById(req.params.id)
    if (!monitor) return res.status(404).json({ error: 'Monitor not found' })

    const clientPids = getClientProjectIds(req.user)
    if (clientPids && (!monitor.projectId || !clientPids.includes(monitor.projectId))) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    const reports = await dbGetReportsByMonitor(monitor.id)
    res.json({ reports })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Fleet overview (admin only)
app.get('/api/fleet/overview', requireAuth, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const monitors = await dbGetAllMonitors()
    const alerts = await dbGetUnacknowledgedAlerts(50)

    const healthCounts = { healthy: 0, degraded: 0, critical: 0, down: 0, unknown: 0 }
    for (const m of monitors) {
      healthCounts[m.healthStatus] = (healthCounts[m.healthStatus] || 0) + 1
    }

    res.json({
      totalMonitors: monitors.length,
      activeMonitors: monitors.filter(m => m.status === 'active').length,
      healthCounts,
      unacknowledgedAlerts: alerts.length,
      recentAlerts: alerts.slice(0, 20),
      monitors: monitors.map(m => ({
        id: m.id,
        target: m.target,
        projectId: m.projectId,
        status: m.status,
        healthStatus: m.healthStatus,
        schedule: m.schedule,
        lastCheckAt: m.lastCheckAt,
        nextCheckAt: m.nextCheckAt,
        totalChecks: m.totalChecks,
      })),
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ── Log Ingestion (Splunk-like) ──────────────────────────────────────────────

// Ingest logs (can be called by external agents/servers)
app.post('/api/logs/ingest', async (req, res) => {
  // Support both single object and array of logs
  const logs = Array.isArray(req.body) ? req.body : [req.body]
  
  if (!logs.length) {
    return res.status(400).json({ error: 'No logs provided' })
  }

  const processedLogs = logs.map(l => ({
    id: 'log_' + randomUUID(),
    projectId: l.projectId || null,
    source: l.source || 'unknown',
    level: (l.level || 'info').toLowerCase(),
    message: l.message || '',
    metadata: l.metadata || {},
    timestamp: l.timestamp || new Date().toISOString()
  }))

  try {
    await dbInsertIngestedLogs(processedLogs)
    res.status(201).json({ success: true, count: processedLogs.length })
  } catch (err) {
    console.error('Log ingestion error:', err)
    res.status(500).json({ error: 'Failed to ingest logs' })
  }
})

// Query logs (The Log Explorer API)
app.get('/api/logs', requireAuth, async (req, res) => {
  try {
    const { source, level, search, minAnomalyScore, projectId, analyzed, limit, offset } = req.query
    const options = {
      source,
      level,
      search,
      minAnomalyScore: minAnomalyScore ? Number(minAnomalyScore) : undefined,
      projectId,
      analyzed: analyzed !== undefined ? (analyzed === 'true') : undefined,
      limit: limit ? Number(limit) : 100,
      offset: offset ? Number(offset) : 0
    }

    const clientPids = getClientProjectIds(req.user)
    if (clientPids && clientPids.length > 0) {
      if (!options.projectId || !clientPids.includes(options.projectId)) {
        return res.status(403).json({ error: 'Forbidden' })
      }
    }

    const logs = await dbGetIngestedLogs(options)
    res.json({ logs })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Log Statistics (for charts)
app.get('/api/logs/stats', requireAuth, async (req, res) => {
  try {
    const { projectId } = req.query
    const clientPids = getClientProjectIds(req.user)
    if (clientPids && clientPids.length > 0) {
      if (!projectId || !clientPids.includes(projectId)) {
        return res.status(403).json({ error: 'Forbidden' })
      }
    }

    const stats = await dbGetIngestedLogsStats(projectId)
    res.json({ stats })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ── AI System Status ─────────────────────────────────────────────────────────
app.get('/api/ai/status', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  const status = aiController.getStatus()
  const workerStatus = aiWorker.getStatus()
  res.json({
    ai: status,
    worker: workerStatus,
    groqConfigured: !!process.env.GROQ_API_KEY,
    version: '2.0.0',
  })
})

app.get('/api/ai/costs', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  res.json({ projects: aiCostTracker.getAllProjectSummaries() })
})

app.get('/api/ai/costs/:projectId', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
  res.json({ project: aiCostTracker.getProjectSummary(req.params.projectId) })
})

app.put('/api/ai/budgets/:projectId', requireAuth, requireRole('admin'), (req, res) => {
  const { budgetUsd } = req.body || {}
  const ok = aiCostTracker.setProjectBudget(req.params.projectId, budgetUsd)
  if (!ok) {
    return res.status(400).json({ error: 'budgetUsd must be a non-negative number' })
  }
  res.json({
    project: aiCostTracker.getProjectSummary(req.params.projectId),
  })
})

app.get('/api/ai/files', requireAuth, async (req, res) => {
  try {
    const requestedPath = String(req.query.path || '')
    const resolvedPath = resolveWorkspacePath(requestedPath)
    if (!resolvedPath) {
      return res.status(400).json({ error: 'Invalid or blocked file path' })
    }

    const stats = await fs.stat(resolvedPath)
    if (!stats.isFile()) {
      return res.status(400).json({ error: 'Path is not a file' })
    }

    const content = await fs.readFile(resolvedPath, 'utf8')
    await addAudit({
      user: req.user.username,
      action: 'AI_FILE_READ',
      resource: requestedPath,
      details: `Read workspace file: ${requestedPath}`,
    })

    res.json({
      path: requestedPath,
      content,
      size: stats.size,
      modifiedAt: stats.mtime.toISOString(),
    })
  } catch (error) {
    console.error('[AI File Read] Error:', error.message)
    res.status(500).json({ error: 'Failed to read file: ' + error.message })
  }
})

app.put('/api/ai/files', requireAuth, async (req, res) => {
  try {
    const { path: requestedPath, content } = req.body || {}
    const resolvedPath = resolveWorkspacePath(requestedPath)
    if (!resolvedPath) {
      return res.status(400).json({ error: 'Invalid or blocked file path' })
    }
    if (typeof content !== 'string') {
      return res.status(400).json({ error: 'content must be a string' })
    }

    await fs.mkdir(path.dirname(resolvedPath), { recursive: true })
    await fs.writeFile(resolvedPath, content, 'utf8')

    const stats = await fs.stat(resolvedPath)
    await addAudit({
      user: req.user.username,
      action: 'AI_FILE_WRITE',
      resource: requestedPath,
      details: `Updated workspace file: ${requestedPath}`,
    })

    res.json({
      success: true,
      path: requestedPath,
      size: stats.size,
      modifiedAt: stats.mtime.toISOString(),
    })
  } catch (error) {
    console.error('[AI File Write] Error:', error.message)
    res.status(500).json({ error: 'Failed to write file: ' + error.message })
  }
})

// ── AI Chat Endpoint ─────────────────────────────────────────────────────────

app.post('/api/ai/chat', requireAuth, async (req, res) => {
  const { message, history, context, attachments } = req.body || {}
  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'message is required' })
  }

  const aiStatus = aiController.getStatus()
  if (!aiStatus.isActive) {
    return res.status(503).json({ error: 'AI features are not available. Please configure GROQ_API_KEY in your environment.' })
  }

  try {
    // Build system context
    let systemPrompt = `You are SentinelAI Assistant — an expert security analyst AI embedded in a penetration testing platform called SentinelAI.

Your role:
- Help security analysts and clients understand vulnerabilities, assess risk, and plan remediation
- Provide clear, actionable security advice
- Explain complex security concepts in an accessible way
- Reference relevant CVEs, CWEs, OWASP categories, and industry standards when appropriate
- Be concise but thorough

Important guidelines:
- Always provide specific, actionable remediation steps when asked about fixes
- Include severity context when discussing risks
- Mention relevant compliance frameworks when applicable
- If uncertain, clearly state so and recommend manual review
- Format responses with clear structure using bullet points and headers when helpful`

    // If vulnerability context is provided, add it to the prompt
    if (context?.type === 'vulnerability' && context.vulnerability) {
      const v = context.vulnerability
      systemPrompt += `\n\nYou are currently being asked about a specific vulnerability:\n`
      systemPrompt += `- Title: ${v.title || 'Unknown'}\n`
      systemPrompt += `- Severity: ${v.severity || 'Unknown'}\n`
      systemPrompt += `- CVSS Score: ${v.cvss ?? 'N/A'}\n`
      systemPrompt += `- CWE: ${v.cweId || 'N/A'}\n`
      systemPrompt += `- Status: ${v.status || 'open'}\n`
      systemPrompt += `- Affected Asset: ${v.asset || 'Unknown'}\n`
      systemPrompt += `- Module: ${v.module || 'Unknown'}\n`
      if (v.description) systemPrompt += `- Description: ${v.description}\n`
      if (v.remediation) systemPrompt += `- Current Remediation Notes: ${v.remediation}\n`
      systemPrompt += `\nProvide answers specifically about this vulnerability. Be detailed and practical.`
    }

    const fileAttachments = Array.isArray(attachments)
      ? attachments
          .filter((item) => item && typeof item.content === 'string')
          .slice(0, 5)
      : []

    if (fileAttachments.length > 0) {
      systemPrompt += `\n\nAttached file context:\n`
      for (const file of fileAttachments) {
        const fileLabel = file.path || file.name || 'attached-file'
        const preview = file.content.length > 12_000
          ? `${file.content.slice(0, 12_000)}\n\n[Truncated after 12,000 characters]`
          : file.content
        systemPrompt += `\nFile: ${fileLabel}\n\`\`\`text\n${preview}\n\`\`\`\n`
      }

      if (looksLikeFileEditRequest(message)) {
        systemPrompt += `\nWhen the user asks to modify an attached file, return the full updated file content only, or a clear unified diff if the full file is too large. Avoid extra commentary so the result can be written back to disk.`
      } else {
        systemPrompt += `\nUse the attached file context when answering and reference the file path if it matters.`
      }
    }

    // Build messages array for the Groq API
    const messages = [{ role: 'system', content: systemPrompt }]

    // Add conversation history (limited to last 10 messages)
    if (Array.isArray(history)) {
      for (const h of history.slice(-10)) {
        if (h.role && h.content) {
          messages.push({ role: h.role === 'assistant' ? 'assistant' : 'user', content: h.content })
        }
      }
    }

    // Add the current user message
    messages.push({ role: 'user', content: message.trim() })

    // Call Groq directly for multi-turn chat (bypasses the single-prompt .analyze() method)
    const groqClient = aiController.groq
    if (!groqClient?.client) {
      return res.status(503).json({ error: 'AI client not initialized' })
    }

    const completion = await groqClient.client.chat.completions.create({
      messages,
      model: groqClient.defaultModel,
      temperature: 0.3,
      max_tokens: 1024,
      top_p: 0.9,
    })

    const response = completion.choices[0]?.message?.content || ''

    await addAudit({
      user: req.user.username,
      action: 'AI_CHAT',
      resource: context?.vulnerability?.id || 'general',
      details: `AI chat: "${message.slice(0, 80)}${message.length > 80 ? '...' : ''}"`,
    })

    res.json({ response })
  } catch (error) {
    console.error('[AI Chat] Error:', error.message)
    res.status(500).json({ error: 'AI chat failed: ' + error.message })
  }
})

// ── Voice Summary Endpoints ──────────────────────────────────────────────────

app.post('/api/ai/voice/summarize-vuln', requireAuth, async (req, res) => {
  const { vulnerability } = req.body || {}
  if (!vulnerability) {
    return res.status(400).json({ error: 'vulnerability object is required' })
  }

  const aiStatus = aiController.getStatus()
  if (!aiStatus.isActive) {
    return res.status(503).json({ error: 'AI features are not available. Please configure GROQ_API_KEY.' })
  }

  try {
    const summary = await generateVulnSummary(vulnerability)

    await addAudit({
      user: req.user.username,
      action: 'AI_VOICE_SUMMARY',
      resource: vulnerability.id || 'unknown',
      details: `Voice summary generated for: ${vulnerability.title || 'Unknown vulnerability'}`,
    })

    res.json({ summary })
  } catch (error) {
    console.error('[Voice Summary] Vuln error:', error.message)
    res.status(500).json({ error: 'Failed to generate vulnerability summary: ' + error.message })
  }
})

app.post('/api/ai/voice/summarize-project', requireAuth, async (req, res) => {
  const { projectId } = req.body || {}
  if (!projectId) {
    return res.status(400).json({ error: 'projectId is required' })
  }

  const aiStatus = aiController.getStatus()
  if (!aiStatus.isActive) {
    return res.status(503).json({ error: 'AI features are not available. Please configure GROQ_API_KEY.' })
  }

  try {
    const summary = await generateProjectSummary(projectId)

    await addAudit({
      user: req.user.username,
      action: 'AI_VOICE_PROJECT_SUMMARY',
      resource: `project:${projectId}`,
      details: 'Executive voice summary generated',
    })

    res.json({ summary })
  } catch (error) {
    console.error('[Voice Summary] Project error:', error.message)
    res.status(500).json({ error: 'Failed to generate project summary: ' + error.message })
  }
})

// ── Socket.io ─────────────────────────────────────────────────────────────────

const httpServer = http.createServer(app)
const io = new SocketIOServer({
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

  // Monitor real-time updates
  socket.on('monitor:join', (monitorId) => {
    if (!monitorId) return
    socket.join(`monitor:${monitorId}`)
  })

  socket.on('monitor:leave', (monitorId) => {
    if (!monitorId) return
    socket.leave(`monitor:${monitorId}`)
  })
})

// ── Helpers ───────────────────────────────────────────────────────────────────

async function pushLog(scanId, level, message, module = 'core') {
  const entry = { timestamp: new Date().toISOString(), level, message, module }
  return await addLog(scanId, entry)
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

  // Initialize database and seed data
  await seedIfEmpty()

  // Initialize AI Agent Controller
  const aiInitialized = await aiController.initialize()
  if (aiInitialized) {
    console.log('🤖 [AI] Agent controller initialized successfully')
  } else {
    console.log('⚠️  [AI] Agent controller disabled (no GROQ_API_KEY)')
  }

  // Initialize AI Worker + Monitor Scheduler + Log Analyzer
  await aiWorker.initialize()
  monitorScheduler = new MonitorScheduler({ aiWorker, io })
  monitorScheduler.start()
  logAnalyzer.start()
  console.log('⏱️  [SIEM] Monitor scheduler initialized')
  console.log('📝 [SIEM] Log analyzer initialized')

  const useHttps = Boolean(HTTPS_KEY_PATH && HTTPS_CERT_PATH)
  const server = useHttps
    ? https.createServer(
        {
          key: readFileSync(HTTPS_KEY_PATH),
          cert: readFileSync(HTTPS_CERT_PATH),
          ca: HTTPS_CA_PATH ? readFileSync(HTTPS_CA_PATH) : undefined,
        },
        app,
      )
    : httpServer

  io.attach(server)

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n❌ [backend] Port ${PORT} is already in use!`)
      console.error(`   Another SentinelAI instance is already running.`)
      console.error(`   Run this command to fix it:\n`)
      console.error(`   npx kill-port ${PORT}\n`)
      process.exit(1)
    } else {
      throw err
    }
  })

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[backend] listening on ${useHttps ? 'https' : 'http'}://0.0.0.0:${PORT}`)
    console.log(`[backend] allow origin: ${CLIENT_ORIGIN}`)
    if (useHttps) {
      console.log(`[backend] TLS enabled with cert: ${HTTPS_CERT_PATH}`)
    }
    if (aiInitialized) {
      console.log('🔥 [AI] Enhanced scanning features are available!')
    }
    console.log('🛡️  [SIEM] Continuous monitoring system is active!')
  })
}

start().catch((err) => {
  console.error('[backend] Failed to start:', err)
  process.exit(1)
})
