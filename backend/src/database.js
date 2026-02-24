import { createClient } from '@libsql/client'

// ── Connect to Turso (remote) or local SQLite file ─────────────────────────

const dbUrl = process.env.TURSO_DATABASE_URL || 'file:sentinelai.db'
const authToken = process.env.TURSO_AUTH_TOKEN || undefined

const client = createClient({ url: dbUrl, authToken })

// ── Create tables ────────────────────────────────────────────────────────────

export async function initDatabase() {
  await client.execute(`
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      client TEXT,
      clientEmails TEXT DEFAULT '[]',
      owner TEXT,
      description TEXT,
      scope TEXT,
      startDate TEXT,
      endDate TEXT,
      riskLevel TEXT DEFAULT 'medium',
      scanCount INTEGER DEFAULT 0,
      vulnerabilityCount INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      createdAt TEXT,
      updatedAt TEXT
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target TEXT,
      template TEXT,
      projectId TEXT,
      status TEXT DEFAULT 'running',
      progress REAL DEFAULT 0,
      startTime TEXT,
      endTime TEXT,
      modules TEXT DEFAULT '[]',
      vulnerabilitiesFound INTEGER DEFAULT 0,
      assetsScanned INTEGER DEFAULT 0
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      scanId TEXT NOT NULL,
      title TEXT,
      severity TEXT DEFAULT 'info',
      cvss REAL,
      asset TEXT,
      module TEXT,
      status TEXT DEFAULT 'open',
      description TEXT,
      aiReasoning TEXT,
      aiConfidence REAL DEFAULT 0,
      remediation TEXT,
      cweId TEXT,
      cveIds TEXT DEFAULT '[]',
      evidence TEXT DEFAULT '{}',
      discovered TEXT
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scanId TEXT NOT NULL,
      timestamp TEXT,
      level TEXT,
      message TEXT,
      module TEXT DEFAULT 'core'
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT,
      user TEXT,
      action TEXT,
      resource TEXT,
      details TEXT
    )
  `)

  // Migration: add evidence column if missing
  try {
    await client.execute(`ALTER TABLE vulnerabilities ADD COLUMN evidence TEXT DEFAULT '{}'`)
  } catch (_) { /* column already exists */ }
}

// ── Helper: parse/serialize JSON columns ─────────────────────────────────────

function parseProject(row) {
  if (!row) return null
  return { ...row, clientEmails: JSON.parse(row.clientEmails || '[]') }
}

function serializeProject(p) {
  return { ...p, clientEmails: JSON.stringify(p.clientEmails || []) }
}

function parseScan(row) {
  if (!row) return null
  return { ...row, modules: JSON.parse(row.modules || '[]') }
}

function serializeScan(s) {
  return {
    ...s,
    modules: JSON.stringify(s.modules || []),
    endTime: s.endTime || null,
  }
}

function parseVuln(row) {
  if (!row) return null
  return {
    ...row,
    cveIds: JSON.parse(row.cveIds || '[]'),
    evidence: JSON.parse(row.evidence || '{}'),
  }
}

function serializeVuln(v) {
  return {
    ...v,
    cveIds: JSON.stringify(v.cveIds || []),
    evidence: JSON.stringify(v.evidence || {}),
  }
}

// ── Async database operations ────────────────────────────────────────────────

export async function dbHasProjects() {
  const result = await client.execute('SELECT COUNT(*) as cnt FROM projects')
  return result.rows[0].cnt > 0
}

// Projects
export async function dbGetAllProjects() {
  const result = await client.execute('SELECT * FROM projects ORDER BY createdAt DESC')
  return result.rows.map(parseProject)
}

export async function dbInsertProject(p) {
  const s = serializeProject(p)
  await client.execute({
    sql: `INSERT INTO projects (id, name, client, clientEmails, owner, description, scope, startDate, endDate, riskLevel, scanCount, vulnerabilityCount, status, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [s.id, s.name, s.client, s.clientEmails, s.owner, s.description, s.scope, s.startDate, s.endDate, s.riskLevel, s.scanCount, s.vulnerabilityCount, s.status, s.createdAt, s.updatedAt],
  })
}

export async function dbUpdateProject(p) {
  const s = serializeProject(p)
  await client.execute({
    sql: `UPDATE projects SET name=?, client=?, clientEmails=?, owner=?, description=?, scope=?, startDate=?, endDate=?, riskLevel=?, scanCount=?, vulnerabilityCount=?, status=?, updatedAt=? WHERE id=?`,
    args: [s.name, s.client, s.clientEmails, s.owner, s.description, s.scope, s.startDate, s.endDate, s.riskLevel, s.scanCount, s.vulnerabilityCount, s.status, s.updatedAt, s.id],
  })
}

export async function dbDeleteProject(id) {
  await client.execute({ sql: 'DELETE FROM projects WHERE id = ?', args: [id] })
}

// Scans
export async function dbGetAllScans() {
  const result = await client.execute('SELECT * FROM scans ORDER BY startTime DESC')
  return result.rows.map(parseScan)
}

export async function dbInsertScan(s) {
  const d = serializeScan(s)
  await client.execute({
    sql: `INSERT INTO scans (id, target, template, projectId, status, progress, startTime, endTime, modules, vulnerabilitiesFound, assetsScanned)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [d.id, d.target, d.template, d.projectId, d.status, d.progress, d.startTime, d.endTime, d.modules, d.vulnerabilitiesFound, d.assetsScanned],
  })
}

export async function dbUpdateScan(s) {
  const d = serializeScan(s)
  await client.execute({
    sql: `UPDATE scans SET target=?, template=?, projectId=?, status=?, progress=?, startTime=?, endTime=?, modules=?, vulnerabilitiesFound=?, assetsScanned=? WHERE id=?`,
    args: [d.target, d.template, d.projectId, d.status, d.progress, d.startTime, d.endTime, d.modules, d.vulnerabilitiesFound, d.assetsScanned, d.id],
  })
}

// Vulnerabilities
export async function dbGetVulnsByScan(scanId) {
  const result = await client.execute({ sql: 'SELECT * FROM vulnerabilities WHERE scanId = ?', args: [scanId] })
  return result.rows.map(parseVuln)
}

export async function dbInsertVuln(v) {
  const d = serializeVuln(v)
  await client.execute({
    sql: `INSERT INTO vulnerabilities (id, scanId, title, severity, cvss, asset, module, status, description, aiReasoning, aiConfidence, remediation, cweId, cveIds, evidence, discovered)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [d.id, d.scanId, d.title, d.severity, d.cvss, d.asset, d.module, d.status, d.description, d.aiReasoning, d.aiConfidence, d.remediation, d.cweId, d.cveIds, d.evidence, d.discovered],
  })
}

export async function dbUpdateVulnStatus(id, status) {
  await client.execute({ sql: 'UPDATE vulnerabilities SET status = ? WHERE id = ?', args: [status, id] })
}

// Scan logs
export async function dbGetLogsByScan(scanId) {
  const result = await client.execute({ sql: 'SELECT * FROM scan_logs WHERE scanId = ? ORDER BY id ASC', args: [scanId] })
  return result.rows
}

export async function dbInsertLog(entry) {
  await client.execute({
    sql: `INSERT INTO scan_logs (scanId, timestamp, level, message, module) VALUES (?, ?, ?, ?, ?)`,
    args: [entry.scanId, entry.timestamp, entry.level, entry.message, entry.module],
  })
}

// Audit logs
export async function dbGetAuditLogs(limit = 200) {
  const result = await client.execute({ sql: 'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?', args: [limit] })
  return result.rows
}

export async function dbInsertAudit(entry) {
  await client.execute({
    sql: `INSERT INTO audit_logs (id, timestamp, user, action, resource, details) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [entry.id, entry.timestamp, entry.user, entry.action, entry.resource, entry.details],
  })
}
