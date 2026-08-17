import Database from 'better-sqlite3'
import { config } from './config.js'

/**
 * Persistent store (better-sqlite3 — synchronous, embedded, zero external deps).
 * Replaces SentinelAI's cloud-Turso dependency with a local-first design.
 */

import path from 'node:path'
import fs from 'node:fs'

let db

export function backupDatabase() {
  try {
    const backupDir = path.join(config.outputDir, 'backups')
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true })
    }
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const targetPath = path.join(backupDir, `fyp2_backup_${timestamp}.db`)
    const latestPath = path.join(backupDir, `fyp2_latest_backup.db`)

    if (fs.existsSync(config.dbPath)) {
      fs.copyFileSync(config.dbPath, targetPath)
      fs.copyFileSync(config.dbPath, latestPath)
      // Retain maximum of 10 recent backups
      const files = fs.readdirSync(backupDir)
        .filter(f => f.startsWith('fyp2_backup_') && f.endsWith('.db'))
        .map(f => ({ name: f, path: path.join(backupDir, f), time: fs.statSync(path.join(backupDir, f)).mtimeMs }))
        .sort((a, b) => b.time - a.time)

      if (files.length > 10) {
        for (const oldFile of files.slice(10)) {
          try { fs.unlinkSync(oldFile.path) } catch {}
        }
      }
      return { success: true, backupFile: targetPath }
    }
  } catch (err) {
    console.error('Backup database failed:', err)
  }
  return { success: false }
}

export function getDb() {
  if (db) return db
  db = new Database(config.dbPath)
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')
  migrate(db)
  backupDatabase()
  return db
}

function migrate(d) {
  try { d.exec("ALTER TABLE projects ADD COLUMN cover TEXT") } catch {}
  try { d.exec("ALTER TABLE projects ADD COLUMN client_id TEXT") } catch {}
  try { d.exec("ALTER TABLE projects ADD COLUMN user_id TEXT") } catch {}
  try { d.exec("ALTER TABLE scans ADD COLUMN token_usage TEXT DEFAULT '{}'") } catch {}

  d.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL,
    last_login TEXT
  );

  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT,
    description TEXT,
    scope TEXT,
    cover TEXT,
    risk_level TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS client_credentials (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    target TEXT NOT NULL,
    target_type TEXT DEFAULT 'url',
    mode TEXT DEFAULT 'blackbox',
    status TEXT DEFAULT 'queued',
    template TEXT DEFAULT 'standard',
    modules TEXT DEFAULT '[]',
    progress INTEGER DEFAULT 0,
    risk_score REAL,
    token_usage TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    cvss REAL,
    cwe_id TEXT,
    cve_id TEXT,
    owasp_category TEXT,
    description TEXT,
    layman_impact TEXT,
    remediation TEXT,
    module TEXT,
    status TEXT DEFAULT 'open',
    evidence TEXT DEFAULT '{}',
    poc TEXT DEFAULT '{}',
    agent_verdict TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
  CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    level TEXT DEFAULT 'info',
    message TEXT,
    ts TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_logs_scan ON logs(scan_id);

  CREATE TABLE IF NOT EXISTS payload_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    file TEXT NOT NULL,
    title TEXT,
    content TEXT,
    keywords TEXT,
    UNIQUE(category, file)
  );
  CREATE INDEX IF NOT EXISTS idx_payload_cat ON payload_index(category);

  CREATE TABLE IF NOT EXISTS skills_index (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    subdomain TEXT,
    description TEXT,
    tags TEXT,
    frameworks TEXT,
    file TEXT NOT NULL,
    body TEXT,
    UNIQUE(name)
  );
  CREATE INDEX IF NOT EXISTS idx_skills_sub ON skills_index(subdomain);

  CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT,
    detail TEXT,
    ts TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS monitors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT DEFAULT 'url',
    interval_min INTEGER DEFAULT 60,
    modules TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1,
    status TEXT DEFAULT 'idle',
    last_run TEXT,
    last_status TEXT,
    last_risk REAL,
    next_run TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS monitor_events (
    id TEXT PRIMARY KEY,
    monitor_id TEXT NOT NULL,
    scan_id TEXT,
    kind TEXT DEFAULT 'info',
    message TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_mon_events ON monitor_events(monitor_id);

  CREATE TABLE IF NOT EXISTS finding_notes (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    author TEXT,
    note TEXT,
    ts TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_notes_finding ON finding_notes(finding_id);

  CREATE TABLE IF NOT EXISTS cve_cache (
    id TEXT PRIMARY KEY,
    data TEXT,
    fetched_at TEXT NOT NULL
  );

  -- Full scan configuration snapshot (JSON) so a scan can be re-run with its
  -- exact original parameters. Added 2026-07; nullable for legacy rows.
  CREATE TABLE IF NOT EXISTS scan_configs (
    scan_id TEXT PRIMARY KEY,
    config TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
  );

  -- ============ AUTONOMOUS EXPLOITATION ENGINE (AEE) ============

  -- Exploit campaigns: one per scan, tracks the full attack lifecycle.
  CREATE TABLE IF NOT EXISTS exploit_campaigns (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    status TEXT DEFAULT 'queued',  -- queued|running|paused|awaiting_approval|completed|failed|aborted
    risk_level TEXT DEFAULT 'medium',  -- low|medium|high|critical
    strategy TEXT DEFAULT '{}',  -- JSON: attack chain, selected tools, payload plan
    target_host TEXT,
    target_port INTEGER,
    target_service TEXT,
    session_id TEXT,  -- Metasploit session UUID
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_campaigns_scan ON exploit_campaigns(scan_id);
  CREATE INDEX IF NOT EXISTS idx_campaigns_status ON exploit_campaigns(status);

  -- Individual exploit steps within a campaign.
  CREATE TABLE IF NOT EXISTS exploit_steps (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    step_order INTEGER NOT NULL,
    step_type TEXT NOT NULL,  -- recon|lateral_movement|exploit|post_exploit|persist|exfil|loot|cleanup
    tool_name TEXT,  -- metasploit/nmap/hydra/custom module name
    command TEXT,
    payload TEXT,
    status TEXT DEFAULT 'pending',  -- pending|approved|running|success|failed|skipped
    needs_approval INTEGER DEFAULT 0,  -- 0=auto, 1=gate
    output TEXT,
    session_ref TEXT,  -- Metasploit session ID
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES exploit_campaigns(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_steps_campaign ON exploit_steps(campaign_id);

  -- Loot/exfiltrated data captured during exploitation.
  CREATE TABLE IF NOT EXISTS exploit_loot (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    step_id TEXT,
    loot_type TEXT DEFAULT 'raw',  -- credential|hash|session_token|private_key|screenshot|db_dump|file|raw
    label TEXT,
    data TEXT,  -- redacted/sanitized content
    file_path TEXT,  -- path to stored artifact on disk
    created_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES exploit_campaigns(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_loot_campaign ON exploit_loot(campaign_id);

  -- Approval queue for gated exploit steps.
  CREATE TABLE IF NOT EXISTS exploit_approvals (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    reason TEXT,
    status TEXT DEFAULT 'pending',  -- pending|approved|denied
    approved_by TEXT,
    approved_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES exploit_campaigns(id) ON DELETE CASCADE
  );

  -- ============ GITHUB AUTOMATION & REPO SYNC ============
  CREATE TABLE IF NOT EXISTS github_integrations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    github_username TEXT NOT NULL,
    access_token TEXT NOT NULL,
    avatar_url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_gh_user ON github_integrations(user_id);

  CREATE TABLE IF NOT EXISTS github_repos (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    repo_id TEXT,
    full_name TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    is_private INTEGER DEFAULT 0,
    auto_scan_push INTEGER DEFAULT 1,
    auto_scan_pr INTEGER DEFAULT 1,
    email_report INTEGER DEFAULT 1,
    last_scan_id TEXT,
    last_scan_at TEXT,
    last_risk_score REAL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_gh_repos_user ON github_repos(user_id);
  CREATE INDEX IF NOT EXISTS idx_gh_repos_name ON github_repos(full_name);

  -- ============ SUBSCRIPTIONS & BILLING ============
  CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT UNIQUE NOT NULL,
    plan_id TEXT NOT NULL DEFAULT 'starter',
    plan_name TEXT NOT NULL DEFAULT 'Starter Free',
    status TEXT NOT NULL DEFAULT 'active', -- active, past_due, canceled
    scan_quota_total INTEGER DEFAULT 5,
    scan_quota_used INTEGER DEFAULT 0,
    current_period_end TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_sub_user ON subscriptions(user_id);

  CREATE TABLE IF NOT EXISTS payment_transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'succeeded', -- succeeded, pending, failed
    provider TEXT NOT NULL DEFAULT 'stripe', -- stripe, lemonsqueezy, toyyibpay, manual
    reference_id TEXT,
    plan_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_pay_user ON payment_transactions(user_id);

  -- ============ AI FEEDBACK LOOP (Dynamic Self-Correction) ============

  -- Prompt adjustments learned from AI errors (persists across restarts)
  CREATE TABLE IF NOT EXISTS ai_prompt_adjustments (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    adjustment TEXT NOT NULL,
    error_type TEXT,
    finding_title TEXT,
    created_at TEXT NOT NULL,
    active INTEGER DEFAULT 1
  );
  CREATE INDEX IF NOT EXISTS idx_ai_adj_agent ON ai_prompt_adjustments(agent);

  -- Review history: every time the feedback loop reviews a finding
  CREATE TABLE IF NOT EXISTS ai_feedback_reviews (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    finding_id TEXT,
    attempts INTEGER DEFAULT 0,
    errors_found INTEGER DEFAULT 0,
    corrected INTEGER DEFAULT 0,
    review_log TEXT DEFAULT '[]',
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_ai_rev_scan ON ai_feedback_reviews(scan_id);
  CREATE INDEX IF NOT EXISTS idx_ai_rev_finding ON ai_feedback_reviews(finding_id);
  `)

  // Migration: add layman_impact column for existing databases
  try { d.exec(`ALTER TABLE findings ADD COLUMN layman_impact TEXT`) } catch { /* already exists */ }
  // Migration: store structured whitebox audit metadata (files checked, tool passes, timing)
  try { d.exec(`ALTER TABLE scans ADD COLUMN whitebox_meta TEXT`) } catch { /* already exists */ }
  // Migration: store structured blackbox audit metadata (URLs scanned, tools run, endpoints found)
  try { d.exec(`ALTER TABLE scans ADD COLUMN blackbox_meta TEXT`) } catch { /* already exists */ }
  // Migration: store scan trigger source, repo name, commit hash, and notification flags
  try { d.exec(`ALTER TABLE scans ADD COLUMN trigger_source TEXT DEFAULT 'manual'`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN repo_name TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN commit_hash TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN email_notify TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN user_id TEXT`) } catch { /* already exists */ }
}

// ── generic helpers ──────────────────────────────────────────────────────────
export function run(sql, ...args) { return getDb().prepare(sql).run(...args) }
export function get(sql, ...args) { return getDb().prepare(sql).get(...args) }
export function all(sql, ...args) { return getDb().prepare(sql).all(...args) }

export default { getDb, run, get, all }
