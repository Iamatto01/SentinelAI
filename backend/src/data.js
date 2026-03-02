import { randomUUID } from 'node:crypto'
import bcrypt from 'bcryptjs'
import {
  initDatabase,
  dbHasProjects,
  dbGetAllProjects, dbInsertProject, dbUpdateProject, dbDeleteProject,
  dbGetAllScans, dbInsertScan, dbUpdateScan,
  dbGetVulnsByScan, dbInsertVuln, dbUpdateVulnStatus,
  dbGetLogsByScan, dbInsertLog,
  dbInsertAudit, dbGetAuditLogs,
  dbGetUserByUsername, dbInsertUser,
} from './database.js'

// ── In-memory db object (backward compat with orchestrator) ─────────────────

export const db = {
  projects: [],
  scans: [],
  scanLogsByScanId: new Map(),
  vulnerabilitiesByScanId: new Map(),
  auditLogs: [],
  settings: {
    modules: {
      reconnaissance: true,
      portScanning: true,
      serviceDetection: true,
      vulnerabilityScanning: true,
      webTesting: true,
    },
    aiMode: 'assist',
    rateLimit: 100,
    concurrency: 10,
    apiEndpoint: 'http://localhost:5000/api',
  },
}

// ── Load from database on startup ───────────────────────────────────────────

async function loadFromDb() {
  db.projects = await dbGetAllProjects()
  db.scans = await dbGetAllScans()
  db.auditLogs = await dbGetAuditLogs(500)

  db.vulnerabilitiesByScanId.clear()
  for (const scan of db.scans) {
    db.vulnerabilitiesByScanId.set(scan.id, await dbGetVulnsByScan(scan.id))
  }

  db.scanLogsByScanId.clear()
  for (const scan of db.scans) {
    db.scanLogsByScanId.set(scan.id, await dbGetLogsByScan(scan.id))
  }
}

// ── Seed data ───────────────────────────────────────────────────────────────

export async function seedIfEmpty() {
  await initDatabase()

  await ensureCoreUsers()

  if (await dbHasProjects()) {
    await loadFromDb()
    await ensureClientUsersFromProjects()
    return
  }

  const seeds = [
    {
      id: 'proj_1',
      name: 'Corporate Network Assessment',
      client: 'TechCorp Inc.',
      clientEmails: ['john@techcorp.com'],
      owner: 'John Smith',
      description: '',
      scope: '',
      startDate: '2025-01-15',
      endDate: '2025-01-29',
      riskLevel: 'high',
      scanCount: 12,
      vulnerabilityCount: 45,
      status: 'active',
      createdAt: '2025-01-10T10:00:00Z',
      updatedAt: '2025-01-22T14:30:00Z',
    },
    {
      id: 'proj_2',
      name: 'Web Application Security Review',
      client: 'E-Commerce Solutions',
      clientEmails: ['bob@ecommerce.com'],
      owner: 'Sarah Johnson',
      description: '',
      scope: '',
      startDate: '2025-02-01',
      endDate: '2025-02-15',
      riskLevel: 'medium',
      scanCount: 8,
      vulnerabilityCount: 23,
      status: 'active',
      createdAt: '2025-01-28T09:15:00Z',
      updatedAt: '2025-02-05T16:45:00Z',
    },
  ]

  for (const p of seeds) {
    await dbInsertProject(p)
  }

  await loadFromDb()

  await ensureClientUsersFromProjects()
}

async function ensureCoreUsers() {
  const now = new Date().toISOString()
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin'
  const analystPassword = process.env.DEFAULT_ANALYST_PASSWORD || 'analyst'

  await ensureUser({
    username: 'admin',
    email: 'admin@company.com',
    role: 'admin',
    password: adminPassword,
    createdAt: now,
  })

  await ensureUser({
    username: 'analyst',
    email: 'analyst@company.com',
    role: 'analyst',
    password: analystPassword,
    createdAt: now,
  })
}

export async function ensureClientUsersFromProjects() {
  const now = new Date().toISOString()
  const clientPassword = process.env.DEFAULT_CLIENT_PASSWORD || 'client'
  const emails = new Set()

  for (const p of db.projects) {
    if (!Array.isArray(p.clientEmails)) continue
    for (const e of p.clientEmails) {
      if (typeof e === 'string' && e.trim()) emails.add(e.trim().toLowerCase())
    }
  }

  for (const email of emails) {
    await ensureUser({
      username: email,
      email,
      role: 'client',
      password: clientPassword,
      createdAt: now,
    })
  }
}

async function ensureUser({ username, email, role, password, createdAt }) {
  const existing = await dbGetUserByUsername(username)
  if (existing) return
  const passwordHash = bcrypt.hashSync(password, 10)
  await dbInsertUser({
    id: 'usr_' + randomUUID(),
    username,
    email,
    passwordHash,
    role,
    createdAt,
    lastLogin: null,
  })
}

// ── CRUD helpers (update in-memory + await DB write) ────────────────────────

// Projects
export async function addProject(project) {
  db.projects.unshift(project)
  try {
    await dbInsertProject(project)
  } catch (e) {
    console.error('dbInsertProject error:', e.message)
  }
}

export async function saveProject(project) {
  try {
    await dbUpdateProject(project)
  } catch (e) {
    console.error('dbUpdateProject error:', e.message)
  }
}

export async function removeProject(id) {
  const idx = db.projects.findIndex((p) => p.id === id)
  if (idx === -1) return null
  const [removed] = db.projects.splice(idx, 1)
  try {
    await dbDeleteProject(id)
  } catch (e) {
    console.error('dbDeleteProject error:', e.message)
  }
  return removed
}

// Scans
export async function addScan(scan) {
  db.scans.unshift(scan)
  try {
    await dbInsertScan(scan)
  } catch (e) {
    console.error('dbInsertScan error:', e.message)
  }
}

export async function saveScan(scan) {
  try {
    await dbUpdateScan(scan)
  } catch (e) {
    console.error('dbUpdateScan error:', e.message)
  }
}

// Vulnerabilities
export function initVulns(scanId) {
  if (!db.vulnerabilitiesByScanId.has(scanId)) {
    db.vulnerabilitiesByScanId.set(scanId, [])
  }
}

export async function addVuln(scanId, vuln) {
  const vulns = db.vulnerabilitiesByScanId.get(scanId) || []
  vulns.push(vuln)
  db.vulnerabilitiesByScanId.set(scanId, vulns)
  try {
    await dbInsertVuln({ ...vuln, scanId })
  } catch (e) {
    console.error('dbInsertVuln error:', e.message)
  }
}

export async function saveVulnStatus(vulnId, status) {
  for (const [, vulns] of db.vulnerabilitiesByScanId) {
    const vuln = vulns.find((v) => v.id === vulnId)
    if (vuln) {
      vuln.status = status
      break
    }
  }
  try {
    await dbUpdateVulnStatus(vulnId, status)
  } catch (e) {
    console.error('dbUpdateVulnStatus error:', e.message)
  }
}

// Scan logs
export function initLogs(scanId) {
  if (!db.scanLogsByScanId.has(scanId)) {
    db.scanLogsByScanId.set(scanId, [])
  }
  return db.scanLogsByScanId.get(scanId)
}

export async function addLog(scanId, entry) {
  const logs = initLogs(scanId)
  logs.push(entry)
  try {
    await dbInsertLog({ scanId, ...entry })
  } catch (e) {
    console.error('dbInsertLog error:', e.message)
  }
  return entry
}

// Audit logs
export async function addAudit({ user, action, resource, details }) {
  const entry = {
    id: 'log_' + randomUUID(),
    timestamp: new Date().toISOString(),
    user,
    action,
    resource,
    details,
  }
  db.auditLogs.unshift(entry)
  try {
    await dbInsertAudit(entry)
  } catch (e) {
    console.error('dbInsertAudit error:', e.message)
  }
}
