import { runNativeCommand } from './integrations/native-tools.js'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { config } from './config.js'

/**
 * CUSTOM SCRIPTS ENGINE
 * =====================
 * Lets operators register their own scanning scripts (bash/python/node)
 * that run as a stage inside the blackbox pipeline. Scripts receive the
 * target via env var TARGET and emit findings as JSON lines on stdout.
 *
 * CONTRACT (per script):
 *   - Executed via: bash -c "<command>"  (or python3/node if shebang-style)
 *   - Env: TARGET=<url>, SCAN_ID=<id>, DEPTH=<standard|deep|full>
 *   - Output: zero or more JSON objects, one per line (JSONL):
 *       {
 *         "title": "...",            (required)
 *         "severity": "critical|high|medium|low|info",  (default info)
 *         "description": "...",
 *         "remediation": "...",
 *         "cweId": "CWE-79",
 *         "owaspCategory": "A05:2025-Injection",
 *         "evidence": { ... }        (arbitrary JSON)
 *       }
 *   - Exit code 0 = ran OK (even with zero findings)
 *   - Non-JSON stdout lines are ignored (tool chatter tolerated)
 *
 * SECURITY: commands run as the backend user on the Kali box — same trust
 * level as the existing native tool runner (runNativeCommand). Only admin
 * users can create/edit scripts (enforced at the API layer).
 */

const SCRIPT_TIMEOUT_MS = 300000 // 5 min per script

/** Load all enabled scripts for a given trigger point. */
export function getScriptsForTrigger(trigger) {
  // Lazy import to avoid circular dependency at module load
  const db = require_db()
  return db.all(
    `SELECT * FROM custom_scripts WHERE enabled = 1 AND trigger_point = ? ORDER BY created_at ASC`,
    trigger
  )
}

export function getAllScripts() {
  const db = require_db()
  let rows = db.all(`SELECT * FROM custom_scripts ORDER BY created_at ASC`)
  if (!rows || rows.length === 0) {
    if (typeof db.seedDefaultScripts === 'function') {
      db.seedDefaultScripts()
      rows = db.all(`SELECT * FROM custom_scripts ORDER BY created_at ASC`)
    }
  }
  return rows || []
}

export function getScript(id) {
  const db = require_db()
  return db.get(`SELECT * FROM custom_scripts WHERE id = ?`, id)
}

export function createScript({ name, description = '', language = 'bash', command, trigger_point = 'post-recon', enabled = 1, severity_floor = 'info' }) {
  const db = require_db()
  validateScript({ name, language, command, trigger_point })
  const id = `cscript_${randomUUID()}`
  const now = new Date().toISOString()
  db.run(
    `INSERT INTO custom_scripts (id, name, description, language, command, trigger_point, enabled, severity_floor, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
    id, name, description, language, command, trigger_point, enabled ? 1 : 0, severity_floor, now, now
  )
  return db.get(`SELECT * FROM custom_scripts WHERE id = ?`, id)
}

export function updateScript(id, patch) {
  const db = require_db()
  const existing = db.get(`SELECT * FROM custom_scripts WHERE id = ?`, id)
  if (!existing) throw new Error('script not found')
  const next = { ...existing, ...patch }
  validateScript(next)
  db.run(
    `UPDATE custom_scripts SET name=?, description=?, language=?, command=?, trigger_point=?, enabled=?, severity_floor=?, updated_at=? WHERE id=?`,
    next.name, next.description || '', next.language, next.command, next.trigger_point,
    next.enabled ? 1 : 0, next.severity_floor || 'info', new Date().toISOString(), id
  )
  return db.get(`SELECT * FROM custom_scripts WHERE id = ?`, id)
}

export function deleteScript(id) {
  const db = require_db()
  const r = db.run(`DELETE FROM custom_scripts WHERE id = ?`, id)
  return r.changes > 0
}

const TRIGGERS = ['post-recon', 'post-scan', 'manual-only']
const LANGS = ['bash', 'python', 'node']

function validateScript({ name, language, command, trigger_point }) {
  if (!name || typeof name !== 'string' || name.length > 120) throw new Error('name required (max 120 chars)')
  if (!command || typeof command !== 'string') throw new Error('command required')
  if (command.length > 50000) throw new Error('command too large (max 50KB)')
  if (!LANGS.includes(language)) throw new Error(`language must be one of: ${LANGS.join(', ')}`)
  if (!TRIGGERS.includes(trigger_point)) throw new Error(`trigger_point must be one of: ${TRIGGERS.join(', ')}`)
  // Block obviously catastrophic commands — defense in depth (API layer is admin-only anyway)
  if (/\brm\s+-rf\s+\/(?:\s|$)|\bmkfs\b|\bshutdown\b|\breboot\b|\bdd\s+if=\/dev\/(zero|random)\s+of=\/dev\/[sh]d/i.test(command)) {
    throw new Error('command blocked: destructive system-level operation detected')
  }
}

/** Build the actual invocation for a script. */
function buildInvocation(language, command) {
  if (language === 'bash') return command
  if (language === 'python') return `python3 - <<'PYEOF'\n${command}\nPYEOF`
  if (language === 'node') return `node - <<'NODEEOF'\n${command}\nNODEEOF`
  return command
}

/**
 * Parse JSONL findings from script stdout. Tolerates tool chatter:
 * any line that doesn't parse as a JSON object with a title is skipped.
 */
export function parseScriptFindings(stdout, severityFloor = 'info') {
  const findings = []
  const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
  for (const line of String(stdout || '').split('\n')) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) continue
    let obj
    try { obj = JSON.parse(trimmed) } catch { continue }
    if (!obj || typeof obj !== 'object' || !obj.title) continue
    const sev = String(obj.severity || 'info').toLowerCase()
    if (!RANK.hasOwnProperty(sev)) continue
    // severity floor: script author can suppress noisy low/info output
    if (RANK[sev] < RANK[severityFloor]) continue
    findings.push({
      title: String(obj.title).slice(0, 300),
      severity: sev,
      description: obj.description ? String(obj.description).slice(0, 8000) : '',
      remediation: obj.remediation ? String(obj.remediation).slice(0, 4000) : '',
      cweId: obj.cweId ? String(obj.cweId).slice(0, 20) : undefined,
      owaspCategory: obj.owaspCategory ? String(obj.owaspCategory).slice(0, 60) : undefined,
      evidence: obj.evidence && typeof obj.evidence === 'object' ? obj.evidence : { raw: trimmed.slice(0, 2000) },
    })
  }
  return findings
}

/**
 * Run one script against a target. Returns { result, findings }.
 * Used by both the pipeline stage and the API test-run endpoint.
 */
export async function runCustomScript(script, { target, scanId = 'test', depth = 'standard' } = {}) {
  const invocation = buildInvocation(script.language, script.command)
  const envPrefix = `TARGET=${JSON.stringify(target)} SCAN_ID=${JSON.stringify(scanId)} DEPTH=${JSON.stringify(depth)}`
  const full = `${envPrefix} ${invocation}`

  const result = await runNativeCommand(full, { timeout: SCRIPT_TIMEOUT_MS })
  const findings = parseScriptFindings(result.stdout, script.severity_floor || 'info')

  // Persist raw output for audit/debug (best-effort)
  try {
    const outDir = path.join(config.outputDir, 'custom-scripts')
    fs.mkdirSync(outDir, { recursive: true })
    fs.writeFileSync(
      path.join(outDir, `${script.id}_${scanId}.log`),
      `# ${new Date().toISOString()} — ${script.name}\n# CMD: ${full}\n# exit=${result.code} success=${result.success}\n\n${result.stdout}\n\n--- stderr ---\n${result.stderr}\n`,
      'utf-8'
    )
  } catch { /* non-fatal */ }

  return { result, findings }
}

// db.js exports a synchronous getDb via default; avoid circular import by
// requiring lazily through the default export's namespace.
import * as dbModule from './db.js'
function require_db() { return dbModule }
