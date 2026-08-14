import { randomUUID } from 'node:crypto'
import * as db from './db.js'

/**
 * Monitor scheduler — runs recurring light scans against registered targets.
 * Simplified port of SentinelAI's monitor-scheduler: instead of a bespoke
 * health-check, each tick launches a normal FYP2 scan via the UnifiedPipeline
 * and records a monitor event with the resulting risk / new finding count.
 */

const timers = new Map() // monitorId -> Timeout

function addEvent(monitorId, scanId, kind, message) {
  db.run(
    `INSERT INTO monitor_events (id, monitor_id, scan_id, kind, message, created_at) VALUES (?,?,?,?,?,?)`,
    `evt_${randomUUID()}`, monitorId, scanId, kind, message, new Date().toISOString()
  )
}

export function listMonitors() {
  return db.all(`SELECT * FROM monitors ORDER BY created_at DESC`)
}
export function getMonitor(id) {
  return db.get(`SELECT * FROM monitors WHERE id = ?`, id)
}
export function monitorEvents(id, limit = 100) {
  return db.all(`SELECT * FROM monitor_events WHERE monitor_id = ? ORDER BY created_at DESC LIMIT ?`, id, limit)
}

const cleanTarget = (t) => t ? String(t).trim().replace(/#.*$/, '').replace(/\/+$/, '') : ''

export function createMonitor(pipeline, { name, target, targetType = 'url', intervalMin = 60, modules = [] }) {
  const id = `mon_${randomUUID()}`
  const now = new Date().toISOString()
  const cleaned = cleanTarget(target)
  db.run(
    `INSERT INTO monitors (id, name, target, target_type, interval_min, modules, enabled, status, created_at, next_run)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
    id, name, cleaned, targetType, Math.max(5, intervalMin | 0), JSON.stringify(modules), 1, 'idle', now,
    new Date(Date.now() + Math.max(5, intervalMin | 0) * 60000).toISOString()
  )
  addEvent(id, null, 'info', `Monitor created for ${cleaned} (every ${intervalMin}m)`)
  schedule(id, pipeline)
  return getMonitor(id)
}

export function deleteMonitor(id) {
  clear(id)
  db.run(`DELETE FROM monitor_events WHERE monitor_id = ?`, id)
  db.run(`DELETE FROM monitors WHERE id = ?`, id)
  return { ok: true }
}

export function setEnabled(id, enabled, pipeline) {
  db.run(`UPDATE monitors SET enabled = ?, status = ? WHERE id = ?`, enabled ? 1 : 0, enabled ? 'idle' : 'disabled', id)
  if (enabled) { addEvent(id, null, 'info', 'Monitor enabled'); schedule(id, pipeline) }
  else { addEvent(id, null, 'info', 'Monitor disabled'); clear(id) }
  return getMonitor(id)
}

export async function triggerNow(id, pipeline) {
  const m = getMonitor(id)
  if (!m) throw new Error('Monitor not found')
  // Ensure enabled and set status to idle so tick executes properly
  db.run(`UPDATE monitors SET enabled = 1, status = 'idle' WHERE id = ?`, id)
  tick(id, pipeline) // Run asynchronously
  return { ok: true, message: 'Monitor scan triggered' }
}

function clear(id) {
  if (timers.has(id)) { clearTimeout(timers.get(id)); timers.delete(id) }
}

function schedule(id, pipeline) {
  clear(id)
  const m = getMonitor(id)
  if (!m || !m.enabled) return
  const intervalMs = Math.max(5, m.interval_min | 0) * 60000
  const timer = setTimeout(() => tick(id, pipeline), intervalMs)
  timers.set(id, timer)
}

async function tick(id, pipeline) {
  const m = getMonitor(id)
  if (!m || !m.enabled) return
  const now = new Date().toISOString()
  const target = cleanTarget(m.target)
  db.run(`UPDATE monitors SET status = 'running', last_run = ? WHERE id = ?`, now, id)

  // Launch a normal scan through the unified pipeline
  const scanId = `scan_${randomUUID()}`
  const modules = JSON.parse(m.modules || '[]')
  db.run(
    `INSERT INTO scans (id, project_id, target, target_type, mode, status, template, modules, progress, created_at, started_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    scanId, null, target, m.target_type, 'blackbox', 'running', 'monitor', JSON.stringify(modules), 0, now, now
  )
  const scan = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
  addEvent(id, scanId, 'info', `Scheduled scan started (${scanId})`)

  try {
    await pipeline.runBlackbox(scan, { modules, objective: 'monitoring', maxTools: 4, verify: true })
    const done = db.get(`SELECT * FROM scans WHERE id = ?`, scanId)
    const count = db.get(`SELECT COUNT(*) c FROM findings WHERE scan_id = ?`, scanId).c
    const finalStatus = done?.status || 'completed'
    db.run(`UPDATE monitors SET status = 'idle', last_status = ?, last_risk = ?, next_run = ? WHERE id = ?`,
      finalStatus, done?.risk_score ?? 0, new Date(Date.now() + Math.max(5, m.interval_min | 0) * 60000).toISOString(), id)
    addEvent(id, scanId, count > 0 ? 'alert' : 'ok', `Scan ${finalStatus}: ${count} findings detected, risk ${(done?.risk_score ?? 0).toFixed(1)}/10`)
  } catch (e) {
    db.run(`UPDATE monitors SET status = 'idle', last_status = 'error' WHERE id = ?`, id)
    addEvent(id, scanId, 'error', `Scheduled scan failed: ${e.message}`)
  }
  schedule(id, pipeline)
}

/** Re-arm timers for all enabled monitors (call on boot). */
export function bootstrap(pipeline) {
  const mons = db.all(`SELECT id FROM monitors WHERE enabled = 1`)
  for (const m of mons) schedule(m.id, pipeline)
  return mons.length
}

export default { listMonitors, getMonitor, monitorEvents, createMonitor, deleteMonitor, setEnabled, triggerNow, bootstrap }
