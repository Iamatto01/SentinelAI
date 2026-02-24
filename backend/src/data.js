import { randomUUID } from 'node:crypto'
import {
  initDatabase,
  dbHasProjects,
  dbGetAllProjects, dbInsertProject, dbUpdateProject, dbDeleteProject,
  dbGetAllScans, dbInsertScan, dbUpdateScan,
  dbGetVulnsByScan, dbInsertVuln, dbUpdateVulnStatus,
  dbGetLogsByScan, dbInsertLog,
  dbInsertAudit, dbGetAuditLogs,
} from './database.js'

// ── In-memory db object (backward compat with orchestrator) ─────────────────

export const db = {
  usersByToken: new Map(),
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

  if (await dbHasProjects()) {
    await loadFromDb()
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
}

// ── CRUD helpers (update in-memory immediately, fire-and-forget to DB) ──────

// Projects
export function addProject(project) {
  db.projects.unshift(project)
  dbInsertProject(project).catch((e) => console.error('dbInsertProject error:', e.message))
}

export function saveProject(project) {
  dbUpdateProject(project).catch((e) => console.error('dbUpdateProject error:', e.message))
}

export function removeProject(id) {
  const idx = db.projects.findIndex((p) => p.id === id)
  if (idx === -1) return null
  const [removed] = db.projects.splice(idx, 1)
  dbDeleteProject(id).catch((e) => console.error('dbDeleteProject error:', e.message))
  return removed
}

// Scans
export function addScan(scan) {
  db.scans.unshift(scan)
  dbInsertScan(scan).catch((e) => console.error('dbInsertScan error:', e.message))
}

export function saveScan(scan) {
  dbUpdateScan(scan).catch((e) => console.error('dbUpdateScan error:', e.message))
}

// Vulnerabilities
export function initVulns(scanId) {
  if (!db.vulnerabilitiesByScanId.has(scanId)) {
    db.vulnerabilitiesByScanId.set(scanId, [])
  }
}

export function addVuln(scanId, vuln) {
  const vulns = db.vulnerabilitiesByScanId.get(scanId) || []
  vulns.push(vuln)
  db.vulnerabilitiesByScanId.set(scanId, vulns)
  dbInsertVuln({ ...vuln, scanId }).catch((e) => console.error('dbInsertVuln error:', e.message))
}

export function saveVulnStatus(vulnId, status) {
  for (const [, vulns] of db.vulnerabilitiesByScanId) {
    const vuln = vulns.find((v) => v.id === vulnId)
    if (vuln) {
      vuln.status = status
      break
    }
  }
  dbUpdateVulnStatus(vulnId, status).catch((e) => console.error('dbUpdateVulnStatus error:', e.message))
}

// Scan logs
export function initLogs(scanId) {
  if (!db.scanLogsByScanId.has(scanId)) {
    db.scanLogsByScanId.set(scanId, [])
  }
  return db.scanLogsByScanId.get(scanId)
}

export function addLog(scanId, entry) {
  const logs = initLogs(scanId)
  logs.push(entry)
  dbInsertLog({ scanId, ...entry }).catch((e) => console.error('dbInsertLog error:', e.message))
  return entry
}

// Audit logs
export function addAudit({ user, action, resource, details }) {
  const entry = {
    id: 'log_' + randomUUID(),
    timestamp: new Date().toISOString(),
    user,
    action,
    resource,
    details,
  }
  db.auditLogs.unshift(entry)
  dbInsertAudit(entry).catch((e) => console.error('dbInsertAudit error:', e.message))
}
