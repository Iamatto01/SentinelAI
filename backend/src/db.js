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
  backupDatabase()
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

  CREATE TABLE IF NOT EXISTS payment_transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'completed',
    provider TEXT NOT NULL DEFAULT 'stripe',
    reference_id TEXT,
    plan_id TEXT NOT NULL,
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
    repo_name TEXT NOT NULL,
    repo_full_name TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    webhook_id TEXT,
    webhook_active INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    price_monthly REAL NOT NULL DEFAULT 0,
    price_yearly REAL NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
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

  CREATE TABLE IF NOT EXISTS promo_codes (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    discount_type TEXT NOT NULL DEFAULT 'percentage',
    discount_value REAL NOT NULL,
    applicable_plans TEXT DEFAULT 'all',
    max_uses INTEGER DEFAULT 0,
    used_count INTEGER NOT NULL DEFAULT 0,
    min_purchase_amount REAL DEFAULT 0,
    expires_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  `)

  // Migration: add layman_impact column for existing databases
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
  try { d.exec(`ALTER TABLE projects ADD COLUMN user_id TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE subscriptions ADD COLUMN discount_percent REAL DEFAULT 0`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE subscriptions ADD COLUMN custom_notes TEXT`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE payment_transactions ADD COLUMN discount_amount REAL DEFAULT 0`) } catch { /* already exists */ }
  try { d.exec(`ALTER TABLE payment_transactions ADD COLUMN promo_code TEXT`) } catch { /* already exists */ }

  // Seed default plans if empty
  try {
    const count = d.prepare('SELECT COUNT(*) as c FROM plans').get()?.c || 0
    if (count === 0) {
      const now = new Date().toISOString()
      const seedPlans = [
        {
          id: 'trial',
          name: 'Free Trial',
          description: 'Explore the full power of SentinelAI autonomous scanning with 3 trial credits.',
          price_monthly: 0,
          price_yearly: 0,
          currency: 'USD',
          scan_quota: 3,
          max_repos: 1,
          features: JSON.stringify([
            '3 Free Autonomous Security Scans',
            'Hexstrike 150+ Kali Toolchain (DAST + SAST)',
            'Multi-LLM Consensus AI Verification',
            'Executive Summary & Remediation Diff',
          ]),
          is_popular: 0,
          is_open: 1,
          is_custom: 0,
          badge: 'Starter',
          sort_order: 1,
        },
        {
          id: 'pro',
          name: 'SentinelAI Pro',
          description: 'Designed for engineering teams, pentesting consultants, and continuous security audits.',
          price_monthly: 19,
          price_yearly: 190,
          currency: 'USD',
          scan_quota: 50,
          max_repos: 5,
          features: JSON.stringify([
            '5 Linked GitHub Repositories',
            '50 AI Code Audits / month',
            'Continuous Webhooks (Push & PR)',
            'Automated Email PDF Delivery',
            'AI Auto-Fix & Remediation Diffs',
            'Priority Security Agent Analysis',
          ]),
          is_popular: 1,
          is_open: 1,
          is_custom: 0,
          badge: 'Most Popular',
          sort_order: 2,
        },
        {
          id: 'enterprise',
          name: 'SentinelAI Enterprise',
          description: 'Unlimited security power with dedicated 1-on-1 virtual CISO advisory and customized workflows.',
          price_monthly: 79,
          price_yearly: 790,
          currency: 'USD',
          scan_quota: 9999,
          max_repos: 999,
          features: JSON.stringify([
            'Unlimited GitHub Repositories',
            'Unlimited AI Code Audits',
            '👨‍💼 1-on-1 Certified Security Consultant & Advisory (Guided Remediation & Virtual CISO)',
            'GitHub PR Bot Inline Review',
            'Real-time Slack / Discord Webhooks',
            'Executive White-label PDF Reports',
            'Dedicated SLA & 24/7 VIP Support',
          ]),
          is_popular: 0,
          is_open: 1,
          is_custom: 0,
          badge: 'Full Power',
          sort_order: 3,
        },
      ]

      for (const p of seedPlans) {
        d.prepare(`
          INSERT INTO plans (id, name, description, price_monthly, price_yearly, currency, scan_quota, max_repos, features, is_popular, is_open, is_custom, badge, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(p.id, p.name, p.description, p.price_monthly, p.price_yearly, p.currency, p.scan_quota, p.max_repos, p.features, p.is_popular, p.is_open, p.is_custom, p.badge, p.sort_order, now, now)
      }
    }
  } catch (e) {
    console.warn('[db] plans seed warning:', e.message)
  }

  // Seed default promo codes if empty
  try {
    const promoCount = d.prepare('SELECT COUNT(*) as c FROM promo_codes').get()?.c || 0
    if (promoCount === 0) {
      const now = new Date().toISOString()
      d.prepare(`
        INSERT INTO promo_codes (id, code, discount_type, discount_value, applicable_plans, max_uses, used_count, min_purchase_amount, expires_at, is_active, note, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run('promo_sentinel50', 'SENTINEL50', 'percentage', 50, 'all', 0, 0, 0, null, 1, 'Launch Celebration 50% Off Discount', now, now)

      d.prepare(`
        INSERT INTO promo_codes (id, code, discount_type, discount_value, applicable_plans, max_uses, used_count, min_purchase_amount, expires_at, is_active, note, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run('promo_fyp2026', 'FYP2026', 'fixed', 10, 'all', 0, 0, 0, null, 1, 'Academic & FYP Special Voucher ($10 off)', now, now)
    }
  } catch (e) {
    console.warn('[db] promo seed warning:', e.message)
  }
}

// ── generic helpers ──────────────────────────────────────────────────────────
export function run(sql, ...args) { return getDb().prepare(sql).run(...args) }
export function get(sql, ...args) { return getDb().prepare(sql).get(...args) }
export function all(sql, ...args) { return getDb().prepare(sql).all(...args) }
export function transaction(fn) { return getDb().transaction(fn) }
export function exec(sql) { return getDb().exec(sql) }
export function prepare(sql) { return getDb().prepare(sql) }

export default { getDb, run, get, all, transaction, exec, prepare, backupDatabase }
