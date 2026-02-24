import Database from 'better-sqlite3'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const dbPath = path.join(__dirname, '..', 'sentinelai.db')
const sqlite = new Database(dbPath)

sqlite.pragma('journal_mode = WAL')
sqlite.pragma('foreign_keys = ON')

// ── Create tables ────────────────────────────────────────────────────────────

sqlite.exec(`
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
  );

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
  );

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
  );

  CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanId TEXT NOT NULL,
    timestamp TEXT,
    level TEXT,
    message TEXT,
    module TEXT DEFAULT 'core'
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    user TEXT,
    action TEXT,
    resource TEXT,
    details TEXT
  );
`)

// Migration: add evidence column if missing (for existing databases)
try {
  sqlite.exec(`ALTER TABLE vulnerabilities ADD COLUMN evidence TEXT DEFAULT '{}'`)
} catch (_) { /* column already exists */ }

// ── Prepared statements ──────────────────────────────────────────────────────

// Projects
const stmts = {
  // Projects
  getAllProjects: sqlite.prepare('SELECT * FROM projects ORDER BY createdAt DESC'),
  getProject: sqlite.prepare('SELECT * FROM projects WHERE id = ?'),
  insertProject: sqlite.prepare(`
    INSERT INTO projects (id, name, client, clientEmails, owner, description, scope, startDate, endDate, riskLevel, scanCount, vulnerabilityCount, status, createdAt, updatedAt)
    VALUES (@id, @name, @client, @clientEmails, @owner, @description, @scope, @startDate, @endDate, @riskLevel, @scanCount, @vulnerabilityCount, @status, @createdAt, @updatedAt)
  `),
  updateProject: sqlite.prepare(`
    UPDATE projects SET name=@name, client=@client, clientEmails=@clientEmails, owner=@owner,
    description=@description, scope=@scope, startDate=@startDate, endDate=@endDate,
    riskLevel=@riskLevel, scanCount=@scanCount, vulnerabilityCount=@vulnerabilityCount,
    status=@status, updatedAt=@updatedAt WHERE id=@id
  `),
  deleteProject: sqlite.prepare('DELETE FROM projects WHERE id = ?'),

  // Scans
  getAllScans: sqlite.prepare('SELECT * FROM scans ORDER BY startTime DESC'),
  getScan: sqlite.prepare('SELECT * FROM scans WHERE id = ?'),
  getScansByProject: sqlite.prepare('SELECT * FROM scans WHERE projectId = ?'),
  insertScan: sqlite.prepare(`
    INSERT INTO scans (id, target, template, projectId, status, progress, startTime, endTime, modules, vulnerabilitiesFound, assetsScanned)
    VALUES (@id, @target, @template, @projectId, @status, @progress, @startTime, @endTime, @modules, @vulnerabilitiesFound, @assetsScanned)
  `),
  updateScan: sqlite.prepare(`
    UPDATE scans SET target=@target, template=@template, projectId=@projectId, status=@status,
    progress=@progress, startTime=@startTime, endTime=@endTime, modules=@modules,
    vulnerabilitiesFound=@vulnerabilitiesFound, assetsScanned=@assetsScanned WHERE id=@id
  `),

  // Vulnerabilities
  getVulnsByScan: sqlite.prepare('SELECT * FROM vulnerabilities WHERE scanId = ?'),
  getVuln: sqlite.prepare('SELECT * FROM vulnerabilities WHERE id = ?'),
  insertVuln: sqlite.prepare(`
    INSERT INTO vulnerabilities (id, scanId, title, severity, cvss, asset, module, status, description, aiReasoning, aiConfidence, remediation, cweId, cveIds, evidence, discovered)
    VALUES (@id, @scanId, @title, @severity, @cvss, @asset, @module, @status, @description, @aiReasoning, @aiConfidence, @remediation, @cweId, @cveIds, @evidence, @discovered)
  `),
  updateVulnStatus: sqlite.prepare('UPDATE vulnerabilities SET status = ? WHERE id = ?'),

  // Scan logs
  getLogsByScan: sqlite.prepare('SELECT * FROM scan_logs WHERE scanId = ? ORDER BY id ASC'),
  insertLog: sqlite.prepare(`
    INSERT INTO scan_logs (scanId, timestamp, level, message, module)
    VALUES (@scanId, @timestamp, @level, @message, @module)
  `),

  // Audit logs
  getAuditLogs: sqlite.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?'),
  countAuditLogs: sqlite.prepare('SELECT COUNT(*) as cnt FROM audit_logs'),
  insertAudit: sqlite.prepare(`
    INSERT INTO audit_logs (id, timestamp, user, action, resource, details)
    VALUES (@id, @timestamp, @user, @action, @resource, @details)
  `),

  // Count helpers
  countProjects: sqlite.prepare('SELECT COUNT(*) as cnt FROM projects'),
}

// ── Helper: parse JSON columns ──────────────────────────────────────────────

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

// ── Exports ──────────────────────────────────────────────────────────────────

export function dbHasProjects() {
  return stmts.countProjects.get().cnt > 0
}

// Projects
export function dbGetAllProjects() {
  return stmts.getAllProjects.all().map(parseProject)
}
export function dbGetProject(id) {
  return parseProject(stmts.getProject.get(id))
}
export function dbInsertProject(p) {
  stmts.insertProject.run(serializeProject(p))
}
export function dbUpdateProject(p) {
  stmts.updateProject.run(serializeProject(p))
}
export function dbDeleteProject(id) {
  stmts.deleteProject.run(id)
}

// Scans
export function dbGetAllScans() {
  return stmts.getAllScans.all().map(parseScan)
}
export function dbGetScan(id) {
  return parseScan(stmts.getScan.get(id))
}
export function dbInsertScan(s) {
  stmts.insertScan.run(serializeScan(s))
}
export function dbUpdateScan(s) {
  stmts.updateScan.run(serializeScan(s))
}

// Vulnerabilities
export function dbGetVulnsByScan(scanId) {
  return stmts.getVulnsByScan.all(scanId).map(parseVuln)
}
export function dbInsertVuln(v) {
  stmts.insertVuln.run(serializeVuln(v))
}
export function dbUpdateVulnStatus(id, status) {
  stmts.updateVulnStatus.run(status, id)
}

// Scan logs
export function dbGetLogsByScan(scanId) {
  return stmts.getLogsByScan.all(scanId)
}
export function dbInsertLog(entry) {
  stmts.insertLog.run(entry)
}

// Audit logs
export function dbGetAuditLogs(limit = 200) {
  return stmts.getAuditLogs.all(limit)
}
export function dbCountAuditLogs() {
  return stmts.countAuditLogs.get().cnt
}
export function dbInsertAudit(entry) {
  stmts.insertAudit.run(entry)
}
