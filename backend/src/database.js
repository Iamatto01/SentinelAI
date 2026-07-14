import { createClient } from '@libsql/client'

// ── Connect to Turso (remote) or local SQLite file ─────────────────────────

const dbUrl = process.env.TURSO_DATABASE_URL || 'file:sentinelai.db'
const authToken = process.env.TURSO_AUTH_TOKEN || undefined

const client = createClient({ url: dbUrl, authToken })

// ── Create tables ────────────────────────────────────────────────────────────

export async function initDatabase() {
  await client.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT,
      passwordHash TEXT NOT NULL,
      role TEXT DEFAULT 'analyst',
      createdAt TEXT,
      lastLogin TEXT
    )
  `)

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

  // ── Monitoring / SIEM tables ───────────────────────────────────────────────

  await client.execute(`
    CREATE TABLE IF NOT EXISTS monitors (
      id TEXT PRIMARY KEY,
      projectId TEXT,
      target TEXT NOT NULL,
      schedule TEXT DEFAULT '1h',
      modules TEXT DEFAULT '["headers","ssl","paths","cors"]',
      status TEXT DEFAULT 'active',
      healthStatus TEXT DEFAULT 'unknown',
      lastCheckAt TEXT,
      nextCheckAt TEXT,
      totalChecks INTEGER DEFAULT 0,
      createdBy TEXT,
      createdAt TEXT,
      updatedAt TEXT
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS monitor_events (
      id TEXT PRIMARY KEY,
      monitorId TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT DEFAULT 'info',
      title TEXT,
      details TEXT,
      aiSummary TEXT,
      createdAt TEXT
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS monitor_alerts (
      id TEXT PRIMARY KEY,
      monitorId TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT,
      details TEXT,
      acknowledged INTEGER DEFAULT 0,
      acknowledgedBy TEXT,
      acknowledgedAt TEXT,
      createdAt TEXT
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS monitor_reports (
      id TEXT PRIMARY KEY,
      monitorId TEXT NOT NULL,
      projectId TEXT,
      type TEXT,
      period TEXT,
      summary TEXT,
      data TEXT DEFAULT '{}',
      createdAt TEXT
    )
  `)

  await client.execute(`
    CREATE TABLE IF NOT EXISTS ingested_logs (
      id TEXT PRIMARY KEY,
      projectId TEXT,
      source TEXT NOT NULL,
      level TEXT NOT NULL,
      message TEXT NOT NULL,
      metadata TEXT DEFAULT '{}',
      timestamp TEXT NOT NULL,
      aiAnalysis TEXT,
      anomalyScore REAL DEFAULT 0,
      analyzed INTEGER DEFAULT 0
    )
  `)

  console.log('✅ Database initialized (Turso/SQLite)')

  // Migration: add evidence column if missing
  try {
    await client.execute(`ALTER TABLE vulnerabilities ADD COLUMN evidence TEXT DEFAULT '{}'`)
  } catch (_) { /* column already exists */ }
}

// ── Users ───────────────────────────────────────────────────────────────────

export async function dbGetUserByUsername(username) {
  const result = await client.execute({
    sql: 'SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1',
    args: [username],
  })
  return result.rows[0] || null
}

export async function dbGetUserById(id) {
  const result = await client.execute({ sql: 'SELECT * FROM users WHERE id = ? LIMIT 1', args: [id] })
  return result.rows[0] || null
}

export async function dbGetUserByEmail(email) {
  const result = await client.execute({
    sql: 'SELECT * FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1',
    args: [email],
  })
  return result.rows[0] || null
}

export async function dbInsertUser(user) {
  await client.execute({
    sql: `INSERT INTO users (id, username, email, passwordHash, role, createdAt, lastLogin)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [user.id, user.username, user.email, user.passwordHash, user.role, user.createdAt, user.lastLogin],
  })
}

export async function dbUpdateUserLastLogin(id, lastLogin) {
  await client.execute({
    sql: 'UPDATE users SET lastLogin = ? WHERE id = ?',
    args: [lastLogin, id],
  })
}

export async function dbUpdateUser(id, email, passwordHash) {
  if (passwordHash) {
    await client.execute({
      sql: 'UPDATE users SET email = ?, passwordHash = ? WHERE id = ?',
      args: [email, passwordHash, id],
    })
  } else {
    await client.execute({
      sql: 'UPDATE users SET email = ? WHERE id = ?',
      args: [email, id],
    })
  }
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

export async function dbDeleteScan(id) {
  await client.execute({ sql: 'DELETE FROM scans WHERE id = ?', args: [id] })
  await client.execute({ sql: 'DELETE FROM vulnerabilities WHERE scanId = ?', args: [id] })
  await client.execute({ sql: 'DELETE FROM scan_logs WHERE scanId = ?', args: [id] })
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

// ── Monitors ─────────────────────────────────────────────────────────────────

function parseMonitor(row) {
  if (!row) return null
  return { ...row, modules: JSON.parse(row.modules || '[]') }
}

export async function dbGetAllMonitors() {
  const result = await client.execute('SELECT * FROM monitors ORDER BY createdAt DESC')
  return result.rows.map(parseMonitor)
}

export async function dbGetMonitorById(id) {
  const result = await client.execute({ sql: 'SELECT * FROM monitors WHERE id = ? LIMIT 1', args: [id] })
  return parseMonitor(result.rows[0] || null)
}

export async function dbGetMonitorsByProject(projectId) {
  const result = await client.execute({ sql: 'SELECT * FROM monitors WHERE projectId = ? ORDER BY createdAt DESC', args: [projectId] })
  return result.rows.map(parseMonitor)
}

export async function dbGetActiveMonitors() {
  const result = await client.execute("SELECT * FROM monitors WHERE status = 'active' ORDER BY nextCheckAt ASC")
  return result.rows.map(parseMonitor)
}

export async function dbInsertMonitor(m) {
  await client.execute({
    sql: `INSERT INTO monitors (id, projectId, target, schedule, modules, status, healthStatus, lastCheckAt, nextCheckAt, totalChecks, createdBy, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [m.id, m.projectId, m.target, m.schedule, JSON.stringify(m.modules || []), m.status, m.healthStatus || 'unknown', m.lastCheckAt, m.nextCheckAt, m.totalChecks || 0, m.createdBy, m.createdAt, m.updatedAt],
  })
}

export async function dbUpdateMonitor(m) {
  await client.execute({
    sql: `UPDATE monitors SET projectId=?, target=?, schedule=?, modules=?, status=?, healthStatus=?, lastCheckAt=?, nextCheckAt=?, totalChecks=?, updatedAt=? WHERE id=?`,
    args: [m.projectId, m.target, m.schedule, JSON.stringify(m.modules || []), m.status, m.healthStatus, m.lastCheckAt, m.nextCheckAt, m.totalChecks, m.updatedAt, m.id],
  })
}

export async function dbDeleteMonitor(id) {
  await client.execute({ sql: 'DELETE FROM monitors WHERE id = ?', args: [id] })
  await client.execute({ sql: 'DELETE FROM monitor_events WHERE monitorId = ?', args: [id] })
  await client.execute({ sql: 'DELETE FROM monitor_alerts WHERE monitorId = ?', args: [id] })
  await client.execute({ sql: 'DELETE FROM monitor_reports WHERE monitorId = ?', args: [id] })
}

// ── Monitor Events ───────────────────────────────────────────────────────────

export async function dbGetEventsByMonitor(monitorId, limit = 100) {
  const result = await client.execute({ sql: 'SELECT * FROM monitor_events WHERE monitorId = ? ORDER BY createdAt DESC LIMIT ?', args: [monitorId, limit] })
  return result.rows.map(r => ({ ...r, details: r.details ? JSON.parse(r.details) : null }))
}

export async function dbInsertEvent(e) {
  await client.execute({
    sql: `INSERT INTO monitor_events (id, monitorId, type, severity, title, details, aiSummary, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [e.id, e.monitorId, e.type, e.severity, e.title, typeof e.details === 'string' ? e.details : JSON.stringify(e.details || {}), e.aiSummary, e.createdAt],
  })
}

// ── Monitor Alerts ───────────────────────────────────────────────────────────

export async function dbGetAlertsByMonitor(monitorId, limit = 50) {
  const result = await client.execute({ sql: 'SELECT * FROM monitor_alerts WHERE monitorId = ? ORDER BY createdAt DESC LIMIT ?', args: [monitorId, limit] })
  return result.rows.map(r => ({ ...r, details: r.details ? JSON.parse(r.details) : null }))
}

export async function dbGetUnacknowledgedAlerts(limit = 100) {
  const result = await client.execute({ sql: 'SELECT * FROM monitor_alerts WHERE acknowledged = 0 ORDER BY createdAt DESC LIMIT ?', args: [limit] })
  return result.rows.map(r => ({ ...r, details: r.details ? JSON.parse(r.details) : null }))
}

export async function dbInsertAlert(a) {
  await client.execute({
    sql: `INSERT INTO monitor_alerts (id, monitorId, type, severity, title, details, acknowledged, createdAt) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
    args: [a.id, a.monitorId, a.type, a.severity, a.title, typeof a.details === 'string' ? a.details : JSON.stringify(a.details || {}), a.createdAt],
  })
}

export async function dbAcknowledgeAlert(id, username) {
  await client.execute({
    sql: 'UPDATE monitor_alerts SET acknowledged = 1, acknowledgedBy = ?, acknowledgedAt = ? WHERE id = ?',
    args: [username, new Date().toISOString(), id],
  })
}

// ── Monitor Reports ──────────────────────────────────────────────────────────

export async function dbGetReportsByMonitor(monitorId) {
  const result = await client.execute({
    sql: 'SELECT * FROM monitor_reports WHERE monitorId = ? ORDER BY createdAt DESC',
    args: [monitorId]
  })
  return result.rows.map(row => ({
    ...row,
    data: JSON.parse(row.data)
  }))
}

// ── Ingested Logs (Splunk-like) ──────────────────────────────────────────────

export async function dbInsertIngestedLogs(logsArray) {
  if (!logsArray || logsArray.length === 0) return

  // Batch insert logs
  const statements = logsArray.map(log => ({
    sql: `INSERT INTO ingested_logs (id, projectId, source, level, message, metadata, timestamp, analyzed) 
          VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
    args: [
      log.id,
      log.projectId || null,
      log.source || 'unknown',
      log.level || 'info',
      log.message || '',
      JSON.stringify(log.metadata || {}),
      log.timestamp || new Date().toISOString()
    ]
  }))

  await client.batch(statements, 'write')
}

export async function dbGetIngestedLogs(options = {}) {
  let sql = 'SELECT * FROM ingested_logs WHERE 1=1'
  const args = []

  if (options.projectId) {
    sql += ' AND projectId = ?'
    args.push(options.projectId)
  }
  if (options.source) {
    sql += ' AND source = ?'
    args.push(options.source)
  }
  if (options.level) {
    sql += ' AND level = ?'
    args.push(options.level)
  }
  if (options.search) {
    sql += ' AND message LIKE ?'
    args.push(`%${options.search}%`)
  }
  if (options.minAnomalyScore !== undefined) {
    sql += ' AND anomalyScore >= ?'
    args.push(options.minAnomalyScore)
  }
  if (options.analyzed !== undefined) {
    sql += ' AND analyzed = ?'
    args.push(options.analyzed ? 1 : 0)
  }

  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
  args.push(options.limit || 100, options.offset || 0)

  const result = await client.execute({ sql, args })
  return result.rows.map(row => ({
    ...row,
    metadata: JSON.parse(row.metadata)
  }))
}

export async function dbUpdateIngestedLogsAnalysis(logsUpdates) {
  if (!logsUpdates || logsUpdates.length === 0) return

  const statements = logsUpdates.map(u => ({
    sql: 'UPDATE ingested_logs SET aiAnalysis = ?, anomalyScore = ?, analyzed = 1 WHERE id = ?',
    args: [u.aiAnalysis, u.anomalyScore || 0, u.id]
  }))

  await client.batch(statements, 'write')
}

export async function dbGetIngestedLogsStats(projectId = null) {
  // Aggregate log counts by level over the last 24 hours
  const sql = `
    SELECT level, COUNT(*) as count 
    FROM ingested_logs 
    WHERE timestamp >= datetime('now', '-24 hours')
    ${projectId ? 'AND projectId = ?' : ''}
    GROUP BY level
  `
  const args = projectId ? [projectId] : []
  const result = await client.execute({ sql, args })
  return result.rows
}

export async function dbInsertReport(r) {
  await client.execute({
    sql: `INSERT INTO monitor_reports (id, monitorId, projectId, type, period, summary, data, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [r.id, r.monitorId, r.projectId, r.type, r.period, r.summary, typeof r.data === 'string' ? r.data : JSON.stringify(r.data || {}), r.createdAt],
  })
}

