import fs from 'node:fs'
import path from 'node:path'
import Database from 'better-sqlite3'

const HDD_BASE = '/mnt/external_hdd/SentinelAI_Data'
const TARGET_DB_PATH = process.env.DB_PATH || (fs.existsSync('/mnt/external_hdd') ? path.join(HDD_BASE, 'fyp2.db') : path.resolve('output', 'fyp2.db'))
const BACKUP_DIR = path.join(path.dirname(TARGET_DB_PATH), 'backups')
const REPORTS_DIR = path.join(path.dirname(TARGET_DB_PATH), 'reports')

console.log('=====================================================')
console.log('🛡️  SentinelAI Data Revival & External HDD Migration')
console.log(`📁 Target Master DB: ${TARGET_DB_PATH}`)
console.log(`📁 Target Backup Dir: ${BACKUP_DIR}`)
console.log('=====================================================\n')

// Ensure target directories exist
fs.mkdirSync(path.dirname(TARGET_DB_PATH), { recursive: true })
fs.mkdirSync(BACKUP_DIR, { recursive: true })
fs.mkdirSync(REPORTS_DIR, { recursive: true })

// Discover all .db files in project and backups
function findDbFiles(dir) {
  const results = []
  if (!fs.existsSync(dir)) return results
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  for (const e of entries) {
    const full = path.join(dir, e.name)
    if (e.isDirectory()) {
      results.push(...findDbFiles(full))
    } else if (e.isFile() && e.name.endsWith('.db') && !e.name.includes('pre_reset') && !e.name.includes('-shm') && !e.name.includes('-wal')) {
      results.push(full)
    }
  }
  return results
}

const searchDirs = [
  '/home/kali/SentinelAI/output',
  '/home/kali/SentinelAI',
  '/home/kali/SentinelAI/backend',
  path.resolve('output'),
  path.resolve('.'),
  HDD_BASE,
]

const candidateFiles = new Set()
for (const d of searchDirs) {
  for (const f of findDbFiles(d)) {
    if (path.resolve(f) !== path.resolve(TARGET_DB_PATH)) {
      candidateFiles.add(f)
    }
  }
}

console.log(`🔍 Found ${candidateFiles.size} candidate database files for data revival:\n`)

const allScans = new Map()
const allFindings = new Map()
const allProjects = new Map()
const allUsers = new Map()
const allConfigs = new Map()
const allMonitors = new Map()
const allAudit = []

for (const dbFile of candidateFiles) {
  try {
    const db = new Database(dbFile, { readonly: true, fileMustExist: true })
    
    // Check tables
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name)
    
    let sCount = 0
    let fCount = 0
    
    if (tables.includes('users')) {
      const users = db.prepare('SELECT * FROM users').all()
      for (const u of users) {
        if (!allUsers.has(u.id)) allUsers.set(u.id, u)
      }
    }

    if (tables.includes('projects')) {
      const projs = db.prepare('SELECT * FROM projects').all()
      for (const p of projs) {
        if (!allProjects.has(p.id)) allProjects.set(p.id, p)
      }
    }

    if (tables.includes('scans')) {
      const scans = db.prepare('SELECT * FROM scans').all()
      sCount = scans.length
      for (const s of scans) {
        const existing = allScans.get(s.id)
        if (!existing || (s.finished_at && !existing.finished_at) || (s.status === 'completed' && existing.status !== 'completed')) {
          allScans.set(s.id, s)
        }
      }
    }

    if (tables.includes('findings')) {
      const findings = db.prepare('SELECT * FROM findings').all()
      fCount = findings.length
      for (const f of findings) {
        if (!allFindings.has(f.id)) allFindings.set(f.id, f)
      }
    }

    if (tables.includes('scan_configs')) {
      const configs = db.prepare('SELECT * FROM scan_configs').all()
      for (const c of configs) {
        if (!allConfigs.has(c.scan_id)) allConfigs.set(c.scan_id, c)
      }
    }

    if (tables.includes('monitors')) {
      const monitors = db.prepare('SELECT * FROM monitors').all()
      for (const m of monitors) {
        if (!allMonitors.has(m.id)) allMonitors.set(m.id, m)
      }
    }

    console.log(`   📂 ${dbFile}: ${sCount} scans, ${fCount} findings`)
    db.close()
  } catch (err) {
    console.warn(`   ⚠️  Skipping ${dbFile}: ${err.message}`)
  }
}

console.log('\n-----------------------------------------------------')
console.log(`📊 TOTAL REVIVED ASSETS ACROSS ALL BACKUPS:`)
console.log(`   - Users:     ${allUsers.size}`)
console.log(`   - Projects:  ${allProjects.size}`)
console.log(`   - Scans:     ${allScans.size}`)
console.log(`   - Findings:  ${allFindings.size}`)
console.log(`   - Configs:   ${allConfigs.size}`)
console.log(`   - Monitors:  ${allMonitors.size}`)
console.log('-----------------------------------------------------\n')

// Create / Initialize Target Master DB using schema
import { getDb } from '../src/db.js'
// Temporarily set process.env.DB_PATH for getDb
process.env.DB_PATH = TARGET_DB_PATH
const targetDb = getDb()

// Migrate data in a single transaction
const tx = targetDb.transaction(() => {
  // Users
  const insUser = targetDb.prepare(`
    INSERT INTO users (id, username, email, password_hash, role, created_at, last_login)
    VALUES (@id, @username, @email, @password_hash, @role, @created_at, @last_login)
    ON CONFLICT(id) DO UPDATE SET
      username = excluded.username,
      email = excluded.email,
      role = excluded.role
  `)
  for (const u of allUsers.values()) {
    insUser.run({
      id: u.id,
      username: u.username,
      email: u.email || null,
      password_hash: u.password_hash,
      role: u.role || 'analyst',
      created_at: u.created_at || new Date().toISOString(),
      last_login: u.last_login || null,
    })
  }

  // Projects
  const insProject = targetDb.prepare(`
    INSERT INTO projects (id, name, client, description, scope, risk_level, status, created_at, updated_at, cover, client_id, user_id)
    VALUES (@id, @name, @client, @description, @scope, @risk_level, @status, @created_at, @updated_at, @cover, @client_id, @user_id)
    ON CONFLICT(id) DO NOTHING
  `)
  for (const p of allProjects.values()) {
    insProject.run({
      id: p.id,
      name: p.name,
      client: p.client || null,
      description: p.description || '',
      scope: p.scope || '',
      risk_level: p.risk_level || 'medium',
      status: p.status || 'active',
      created_at: p.created_at || new Date().toISOString(),
      updated_at: p.updated_at || new Date().toISOString(),
      cover: p.cover || null,
      client_id: p.client_id || null,
      user_id: p.user_id || null,
    })
  }

  // Scans
  const insScan = targetDb.prepare(`
    INSERT INTO scans (
      id, project_id, target, target_type, mode, status, template, modules,
      progress, risk_score, created_at, started_at, finished_at, whitebox_meta,
      blackbox_meta, token_usage, trigger_source, repo_name, commit_hash,
      email_notify, user_id, client
    ) VALUES (
      @id, @project_id, @target, @target_type, @mode, @status, @template, @modules,
      @progress, @risk_score, @created_at, @started_at, @finished_at, @whitebox_meta,
      @blackbox_meta, @token_usage, @trigger_source, @repo_name, @commit_hash,
      @email_notify, @user_id, @client
    )
    ON CONFLICT(id) DO UPDATE SET
      status = excluded.status,
      progress = excluded.progress,
      risk_score = excluded.risk_score,
      finished_at = excluded.finished_at
  `)
  for (const s of allScans.values()) {
    insScan.run({
      id: s.id,
      project_id: s.project_id || null,
      target: s.target || '(unknown)',
      target_type: s.target_type || 'url',
      mode: s.mode || 'blackbox',
      status: s.status || 'completed',
      template: s.template || 'standard',
      modules: s.modules || '[]',
      progress: s.progress ?? 100,
      risk_score: s.risk_score ?? 0,
      created_at: s.created_at || new Date().toISOString(),
      started_at: s.started_at || null,
      finished_at: s.finished_at || null,
      whitebox_meta: s.whitebox_meta || null,
      blackbox_meta: s.blackbox_meta || null,
      token_usage: s.token_usage || '{}',
      trigger_source: s.trigger_source || 'manual',
      repo_name: s.repo_name || null,
      commit_hash: s.commit_hash || null,
      email_notify: s.email_notify || null,
      user_id: s.user_id || null,
      client: s.client || null,
    })
  }

  // Findings
  const insFinding = targetDb.prepare(`
    INSERT INTO findings (
      id, scan_id, title, severity, cvss, cwe_id, cve_id, owasp_category,
      description, layman_impact, remediation, module, status, evidence, poc,
      agent_verdict, created_at, fingerprint
    ) VALUES (
      @id, @scan_id, @title, @severity, @cvss, @cwe_id, @cve_id, @owasp_category,
      @description, @layman_impact, @remediation, @module, @status, @evidence, @poc,
      @agent_verdict, @created_at, @fingerprint
    )
    ON CONFLICT(id) DO NOTHING
  `)
  for (const f of allFindings.values()) {
    // Only insert if the scan exists
    if (allScans.has(f.scan_id)) {
      insFinding.run({
        id: f.id,
        scan_id: f.scan_id,
        title: f.title,
        severity: f.severity || 'info',
        cvss: f.cvss ?? null,
        cwe_id: f.cwe_id || null,
        cve_id: f.cve_id || null,
        owasp_category: f.owasp_category || null,
        description: f.description || '',
        layman_impact: f.layman_impact || null,
        remediation: f.remediation || '',
        module: f.module || 'general',
        status: f.status || 'open',
        evidence: f.evidence || '{}',
        poc: f.poc || '{}',
        agent_verdict: f.agent_verdict || null,
        created_at: f.created_at || new Date().toISOString(),
        fingerprint: f.fingerprint || null,
      })
    }
  }

  // Scan Configs
  const insConfig = targetDb.prepare(`
    INSERT INTO scan_configs (scan_id, config)
    VALUES (@scan_id, @config)
    ON CONFLICT(scan_id) DO UPDATE SET config = excluded.config
  `)
  for (const c of allConfigs.values()) {
    if (allScans.has(c.scan_id)) {
      insConfig.run({
        scan_id: c.scan_id,
        config: typeof c.config === 'string' ? c.config : JSON.stringify(c.config || {}),
      })
    }
  }

  // Monitors
  const insMonitor = targetDb.prepare(`
    INSERT INTO monitors (id, name, target, target_type, interval_min, modules, enabled, status, last_run, last_status, last_risk, next_run, created_at)
    VALUES (@id, @name, @target, @target_type, @interval_min, @modules, @enabled, @status, @last_run, @last_status, @last_risk, @next_run, @created_at)
    ON CONFLICT(id) DO NOTHING
  `)
  for (const m of allMonitors.values()) {
    insMonitor.run({
      id: m.id,
      name: m.name,
      target: m.target,
      target_type: m.target_type || 'url',
      interval_min: m.interval_min || 60,
      modules: m.modules || '[]',
      enabled: m.enabled ?? 1,
      status: m.status || 'idle',
      last_run: m.last_run || null,
      last_status: m.last_status || null,
      last_risk: m.last_risk ?? null,
      next_run: m.next_run || null,
      created_at: m.created_at || new Date().toISOString(),
    })
  }
})

tx()

// Create an immutable snapshot backup on the external HDD
const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
const backupFile = path.join(BACKUP_DIR, `fyp2_permanent_revival_${timestamp}.db`)
targetDb.backup(backupFile)
  .then(() => {
    console.log(`✅ Revived Master Database successfully written to: ${TARGET_DB_PATH}`)
    console.log(`💾 Immutable Snapshot Backup saved to: ${backupFile}`)
    console.log(`🎉 Revival Complete! Total Scans in Master DB: ${allScans.size} | Total Findings: ${allFindings.size}`)
  })
  .catch((err) => {
    console.error('Backup error:', err)
  })
