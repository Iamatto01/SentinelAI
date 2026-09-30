import Database from 'better-sqlite3'
import { config } from './config.js'

/**
 * Persistent store (better-sqlite3 — synchronous, embedded, zero external deps).
 * Replaces SentinelAI's cloud-Turso dependency with a local-first design.
 */

import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

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
    client_id TEXT,
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
    username TEXT,
    email TEXT,
    service_type TEXT NOT NULL,
    consultant_name TEXT NOT NULL DEFAULT 'Any Specialist',
    scan_id TEXT,
    preferred_date TEXT,
    preferred_time TEXT,
    channel TEXT NOT NULL DEFAULT 'Google Meet',
    notes TEXT,
    plan_tier TEXT DEFAULT 'starter',
    meeting_link TEXT,
    admin_notes TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT,
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

  CREATE TABLE IF NOT EXISTS promo_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    discount_type TEXT NOT NULL DEFAULT 'percentage',
    discount_value REAL NOT NULL DEFAULT 0,
    applicable_plans TEXT DEFAULT 'all',
    max_uses INTEGER DEFAULT 0,
    used_count INTEGER DEFAULT 0,
    min_purchase_amount REAL DEFAULT 0,
    expires_at TEXT,
    is_active INTEGER DEFAULT 1,
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS telegram_pairings (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL DEFAULT 'telegram',
    chat_id TEXT NOT NULL,
    sender_name TEXT,
    pairing_code TEXT,
    user_id TEXT,
    username TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    approved_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_tele_platform_chat ON telegram_pairings(platform, chat_id);
  CREATE INDEX IF NOT EXISTS idx_tele_user_id ON telegram_pairings(user_id);

  CREATE TABLE IF NOT EXISTS github_integrations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    github_username TEXT,
    access_token TEXT,
    avatar_url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS github_repos (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    full_name TEXT NOT NULL,
    repo_url TEXT,
    default_branch TEXT DEFAULT 'main',
    is_private INTEGER DEFAULT 0,
    auto_scan_push INTEGER DEFAULT 1,
    auto_scan_pr INTEGER DEFAULT 1,
    email_report INTEGER DEFAULT 1,
    last_scan_id TEXT,
    last_scan_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_gh_repos_user ON github_repos(user_id);
  `)

  // Migration: add layman_impact column for existing databases
  try { d.exec(`ALTER TABLE findings ADD COLUMN target TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE findings ADD COLUMN layman_impact TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE findings ADD COLUMN fingerprint TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(scan_id, fingerprint)`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  // Migration: store structured whitebox & blackbox metadata and user/client columns
  try { d.exec(`ALTER TABLE scans ADD COLUMN whitebox_meta TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN blackbox_meta TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN token_usage TEXT DEFAULT '{}'`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN trigger_source TEXT DEFAULT 'manual'`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN repo_name TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN commit_hash TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN email_notify TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN user_id TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN client TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE scans ADD COLUMN owasp_categories TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE projects ADD COLUMN user_id TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE projects ADD COLUMN client_id TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE projects ADD COLUMN cover TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }

  // Migration: ensure github_repos has all required columns
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN full_name TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN repo_url TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN is_private INTEGER DEFAULT 0`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN auto_scan_push INTEGER DEFAULT 1`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN auto_scan_pr INTEGER DEFAULT 1`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN email_report INTEGER DEFAULT 1`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN last_scan_id TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN last_scan_at TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE github_repos ADD COLUMN updated_at TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`CREATE INDEX IF NOT EXISTS idx_gh_repos_name ON github_repos(full_name)`) } catch (e) { if (!/already exists/i.test(String(e))) throw e }

  // Migration: ensure consultation_requests has all required columns
  try { d.exec(`ALTER TABLE consultation_requests ADD COLUMN username TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE consultation_requests ADD COLUMN email TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE consultation_requests ADD COLUMN plan_tier TEXT DEFAULT 'starter'`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE consultation_requests ADD COLUMN meeting_link TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE consultation_requests ADD COLUMN admin_notes TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }
  try { d.exec(`ALTER TABLE consultation_requests ADD COLUMN updated_at TEXT`) } catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }

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

  // Seed default promo codes
  try {
    const promoCount = d.prepare('SELECT COUNT(*) as c FROM promo_codes').get()
    if (!promoCount || promoCount.c === 0) {
      const now = new Date().toISOString()
      const defaultPromos = [
        ['promo_launch20', 'LAUNCH20', 'percentage', 20, 'all', 100, 0, 0, null, 1, 'Launch celebration 20% discount', now, now],
        ['promo_student50', 'STUDENT50', 'percentage', 50, 'all', 50, 0, 0, null, 1, '50% discount for educational & research use', now, now],
      ]
      const stmtPromo = d.prepare(`
        INSERT OR IGNORE INTO promo_codes (id, code, discount_type, discount_value, applicable_plans, max_uses, used_count, min_purchase_amount, expires_at, is_active, note, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      for (const pr of defaultPromos) {
        stmtPromo.run(...pr)
      }
    }
  } catch (e) {
    console.warn('[db] promo_codes seed error:', e.message)
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

  // Seed default custom scripts if table is empty
  try {
    seedDefaultScripts(d)
  } catch (e) {
    console.warn('[db] custom_scripts seed notice:', e.message)
  }
}

export function seedDefaultScripts(d = getDb()) {
  try {
    const existingCount = d.prepare('SELECT count(*) as c FROM custom_scripts').get()?.c || 0
    if (existingCount > 0) {
      return { seeded: false, count: existingCount, message: 'Custom scripts already present' }
    }
    const seedPath = path.join(__dirname, 'data', 'default-custom-scripts.json')
    if (!fs.existsSync(seedPath)) {
      return { seeded: false, count: 0, message: 'Seed file not found' }
    }
    const defaultScripts = JSON.parse(fs.readFileSync(seedPath, 'utf8'))
    const insertStmt = d.prepare(`
      INSERT OR IGNORE INTO custom_scripts (id, name, description, language, command, trigger_point, enabled, severity_floor, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    const tx = d.transaction((scripts) => {
      for (const s of scripts) {
        insertStmt.run(
          s.id,
          s.name,
          s.description || '',
          s.language || 'bash',
          s.command,
          s.trigger_point || 'post-scan',
          s.enabled != null ? s.enabled : 1,
          s.severity_floor || 'info',
          s.created_at || new Date().toISOString(),
          s.updated_at || new Date().toISOString()
        )
      }
    })
    tx(defaultScripts)
    const newCount = d.prepare('SELECT count(*) as c FROM custom_scripts').get()?.c || 0
    console.log(`[db] Seeded ${newCount} built-in custom security scripts into database`)
    return { seeded: true, count: newCount }
  } catch (err) {
    console.error('[db] seedDefaultScripts error:', err.message)
    return { seeded: false, error: err.message }
  }
}

// ── generic helpers ──────────────────────────────────────────────────────────
export function run(sql, ...args) { return getDb().prepare(sql).run(...args) }
export function get(sql, ...args) { return getDb().prepare(sql).get(...args) }
export function all(sql, ...args) { return getDb().prepare(sql).all(...args) }

export default { getDb, run, get, all }
