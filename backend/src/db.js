import Database from 'better-sqlite3'
import { config } from './config.js'

/**
 * Persistent store (better-sqlite3 — synchronous, embedded, zero external deps).
 * Replaces SentinelAI's cloud-Turso dependency with a local-first design.
 */

import path from 'node:path'
import fs from 'node:fs'

let db

export async function backupDatabase() {
  try {
    const backupDir = path.join(config.outputDir, 'backups')
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true })
    }
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const targetPath = path.join(backupDir, `fyp2_backup_${timestamp}.db`)
    const latestPath = path.join(backupDir, `fyp2_latest_backup.db`)

    const activeDb = getDb()
    await activeDb.backup(targetPath)
    try { fs.copyFileSync(targetPath, latestPath) } catch {}

    // Retain up to 50 historical snapshots
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('fyp2_backup_') && f.endsWith('.db'))
      .map(f => ({ name: f, path: path.join(backupDir, f), time: fs.statSync(path.join(backupDir, f)).mtimeMs }))
      .sort((a, b) => b.time - a.time)

    if (files.length > 50) {
      for (const oldFile of files.slice(50)) {
        try { fs.unlinkSync(oldFile.path) } catch {}
      }
    }
    return { success: true, backupFile: targetPath }
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
  return db
}

function migrate(d) {
  try { d.exec("ALTER TABLE projects ADD COLUMN cover TEXT") } catch {}

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
    user_id TEXT,
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
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    whitebox_meta TEXT,
    blackbox_meta TEXT,
    token_usage TEXT DEFAULT '{}',
    trigger_source TEXT DEFAULT 'manual',
    repo_name TEXT,
    commit_hash TEXT,
    email_notify TEXT,
    user_id TEXT,
    client TEXT,
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

  CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL DEFAULT 'trial',
    plan_name TEXT NOT NULL DEFAULT 'Free Trial',
    status TEXT NOT NULL DEFAULT 'active',
    scan_quota_total INTEGER NOT NULL DEFAULT 3,
    scan_quota_used INTEGER NOT NULL DEFAULT 0,
    current_period_end TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_name TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    interval TEXT NOT NULL DEFAULT 'monthly',
    provider TEXT NOT NULL DEFAULT 'stripe',
    status TEXT NOT NULL DEFAULT 'completed',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS consultation_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    service_type TEXT NOT NULL,
    consultant_name TEXT NOT NULL DEFAULT 'Any Specialist',
    scan_id TEXT,
    preferred_date TEXT,
    preferred_time TEXT,
    channel TEXT NOT NULL DEFAULT 'Google Meet',
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    price_monthly REAL NOT NULL DEFAULT 0,
    price_yearly REAL NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'MYR',
    scan_quota INTEGER NOT NULL DEFAULT 10,
    max_repos INTEGER NOT NULL DEFAULT 1,
    features TEXT NOT NULL DEFAULT '[]',
    is_popular INTEGER NOT NULL DEFAULT 0,
    is_open INTEGER NOT NULL DEFAULT 1,
    is_custom INTEGER NOT NULL DEFAULT 0,
    badge TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS payment_transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'MYR',
    status TEXT NOT NULL DEFAULT 'completed',
    provider TEXT NOT NULL DEFAULT 'stripe',
    reference_id TEXT,
    plan_id TEXT,
    discount_amount REAL DEFAULT 0,
    promo_code TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  `)

  // Migration: add layman_impact column for existing databases
  try { d.exec(`ALTER TABLE findings ADD COLUMN target TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE findings ADD COLUMN layman_impact TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE findings ADD COLUMN fingerprint TEXT`) } catch { /* already exists */ }
  try { d.exec(`CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(scan_id, fingerprint)`) } catch { /* already exists */ }
  // Migration: store structured whitebox & blackbox metadata and user/client columns
  try { d.exec(`ALTER TABLE scans ADD COLUMN whitebox_meta TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN blackbox_meta TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN token_usage TEXT DEFAULT '{}'`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN trigger_source TEXT DEFAULT 'manual'`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN repo_name TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN commit_hash TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN email_notify TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN user_id TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN client TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE scans ADD COLUMN owasp_categories TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE projects ADD COLUMN user_id TEXT`) } catch { /* already exists */ }

  // Ensure default plans exist with MYR pricing
  try {
    const now = new Date().toISOString()
    const defaultPlans = [
      ['trial', 'Free Trial', 'Explore the full power of SentinelAI autonomous scanning with 3 trial credits.', 0, 0, 'MYR', 3, 1, JSON.stringify(["3 Free Autonomous Security Scans","150+ Kali Toolchain (DAST + SAST)","Multi-LLM Consensus AI Verification","Executive Summary & Remediation Diff"]), 0, 1, 0, 'Starter', 1, now, now],
      ['pay_per_scan', 'Pay-Per-Scan Credit', 'Top-up single scan credits on-demand with zero monthly commitments.', 3, 30, 'MYR', 1, 1, JSON.stringify(["RM 3 per single full autonomous scan","Full 150+ Toolchain DAST / SAST execution","Live stdout terminal & real-time telemetry","Instant downloadable PDF Audit Report","No recurring monthly subscription"]), 0, 1, 0, 'On-Demand', 2, now, now],
      ['pro', 'SentinelAI Pro', 'Designed for engineering teams, pentesting consultants, and continuous security audits.', 20, 200, 'MYR', 50, 5, JSON.stringify(["5 Linked GitHub Repositories","50 AI Autonomous Scans / month","Continuous Webhooks (Push & PR)","Automated Email PDF Delivery","AI Auto-Fix & Remediation Diffs","Priority Security Agent Analysis"]), 1, 1, 0, 'Most Popular', 3, now, now],
      ['enterprise', 'SentinelAI Enterprise', 'Dedicated capacity, unlimited scans, bespoke AI personas, and Metasploit RPC for elite red teams.', 80, 800, 'MYR', 9999, 99, JSON.stringify(["Unlimited Repositories & Scans","Metasploit RPC Bridge & Automated Exploits","Dedicated Kali Linux Engine Worker Node","Custom AI Agent Persona Fine-Tuning","24/7 Automated Scheduled Monitoring","Direct Slack/Discord/Telegram Alert Relays"]), 0, 1, 0, 'Elite Security', 4, now, now]
    ]
    const stmt = d.prepare(`
      INSERT INTO plans (id, name, description, price_monthly, price_yearly, currency, scan_quota, max_repos, features, is_popular, is_open, is_custom, badge, sort_order, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        price_monthly = excluded.price_monthly,
        price_yearly = excluded.price_yearly,
        currency = excluded.currency,
        updated_at = excluded.updated_at
    `)
    for (const p of defaultPlans) {
      stmt.run(...p)
    }
  } catch (e) {
    console.warn('[db] plans seed/update note:', e.message)
  }

  // ============ CUSTOM SCRIPTS ENGINE ============
  // Operator-defined scanning scripts that run as pipeline stages.
  CREATE: try {
    d.exec(`
  CREATE TABLE IF NOT EXISTS custom_scripts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    language TEXT NOT NULL DEFAULT 'bash',        -- bash|python|node
    command TEXT NOT NULL,                        -- script body; TARGET/SCAN_ID/DEPTH env vars injected
    trigger_point TEXT NOT NULL DEFAULT 'post-recon', -- post-recon|post-scan|manual-only
    enabled INTEGER DEFAULT 1,
    severity_floor TEXT DEFAULT 'info',           -- suppress findings below this severity
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_custom_scripts_trigger ON custom_scripts(trigger_point, enabled);
    `)
  } catch (e) { if (!/already exists/i.test(String(e))) throw e }
}

// ── generic helpers ──────────────────────────────────────────────────────────
export function run(sql, ...args) { return getDb().prepare(sql).run(...args) }
export function get(sql, ...args) { return getDb().prepare(sql).get(...args) }
export function all(sql, ...args) { return getDb().prepare(sql).all(...args) }

export default { getDb, run, get, all }
