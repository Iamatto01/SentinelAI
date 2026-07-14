import { randomUUID } from 'node:crypto'
import {
  dbGetActiveMonitors, dbGetMonitorById, dbUpdateMonitor,
  dbInsertEvent, dbInsertAlert, dbInsertReport,
  dbGetEventsByMonitor, dbGetAlertsByMonitor,
} from '../database.js'
import { buildModules, getModuleSelection } from '../scanner/orchestrator.js'

/**
 * Monitor Scheduler — SIEM-like cron engine.
 *
 * Every TICK_INTERVAL_MS it checks which monitors are due for their next
 * check. When a monitor is due, it spawns a lightweight scan using the
 * existing scanner modules, passes the results to the AIWorker for analysis,
 * stores events, and fires alerts.
 */
const TICK_INTERVAL_MS = 30_000 // check every 30 seconds
const SCHEDULE_MAP = {
  '5m':  5 * 60_000,
  '15m': 15 * 60_000,
  '30m': 30 * 60_000,
  '1h':  60 * 60_000,
  '6h':  6 * 60 * 60_000,
  '12h': 12 * 60 * 60_000,
  '24h': 24 * 60 * 60_000,
}

export class MonitorScheduler {
  /**
   * @param {object} opts
   * @param {import('./ai-worker.js').AIWorker} opts.aiWorker
   * @param {import('socket.io').Server} [opts.io]
   */
  constructor({ aiWorker, io = null }) {
    this.aiWorker = aiWorker
    this.io = io
    this.timer = null
    this.running = new Set() // monitorIds currently being checked
    this.previousFindings = new Map() // monitorId -> last findings array
    this.maxConcurrent = Number(process.env.MAX_MONITOR_CONCURRENCY || 3)
  }

  start() {
    if (this.timer) return
    console.log('⏱️  Monitor Scheduler started (tick every 30s)')
    this.timer = setInterval(() => this._tick(), TICK_INTERVAL_MS)
    // Run first tick immediately
    this._tick()
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
      console.log('⏱️  Monitor Scheduler stopped')
    }
  }

  // ── Main tick ──────────────────────────────────────────────────────────────

  async _tick() {
    try {
      const monitors = await dbGetActiveMonitors()
      const now = Date.now()

      for (const monitor of monitors) {
        // Skip if already running
        if (this.running.has(monitor.id)) continue

        // Skip if not yet due
        if (monitor.nextCheckAt && new Date(monitor.nextCheckAt).getTime() > now) continue

        // Respect concurrency limit
        if (this.running.size >= this.maxConcurrent) break

        // Spawn the check (fire and forget — errors are handled internally)
        this._runCheck(monitor)
      }
    } catch (err) {
      console.error('[Scheduler] Tick error:', err.message)
    }
  }

  // ── Execute a monitoring check ─────────────────────────────────────────────

  async _runCheck(monitor) {
    this.running.add(monitor.id)
    const checkStart = new Date().toISOString()
    console.log(`🔍 [Monitor] Checking ${monitor.target} (${monitor.id})`)

    try {
      // 1. Run lightweight scans using existing scanner modules
      const findings = await this._executeScanModules(monitor)

      // 2. Get previous findings for diff analysis
      const previous = this.previousFindings.get(monitor.id) || null

      // 3. AI analysis
      const analysis = await this.aiWorker.analyzeCheck(monitor, findings, previous)

      // 4. Store the findings for next diff
      this.previousFindings.set(monitor.id, findings)

      // 5. Update monitor record
      const intervalMs = SCHEDULE_MAP[monitor.schedule] || SCHEDULE_MAP['1h']
      const now = new Date()
      monitor.lastCheckAt = now.toISOString()
      monitor.nextCheckAt = new Date(now.getTime() + intervalMs).toISOString()
      monitor.totalChecks = (monitor.totalChecks || 0) + 1
      monitor.healthStatus = analysis.healthStatus
      monitor.updatedAt = now.toISOString()
      await dbUpdateMonitor(monitor)

      // 6. Store event
      await dbInsertEvent({
        id: 'evt_' + randomUUID(),
        monitorId: monitor.id,
        type: 'check',
        severity: analysis.healthStatus === 'critical' ? 'critical' : analysis.healthStatus === 'degraded' ? 'medium' : 'info',
        title: `Check #${monitor.totalChecks}: ${findings.length} finding(s)`,
        details: {
          findingsCount: findings.length,
          newCount: analysis.changes.newFindings.length,
          resolvedCount: analysis.changes.resolvedFindings.length,
          healthStatus: analysis.healthStatus,
          findings: findings.slice(0, 30).map(f => ({ title: f.title, severity: f.severity })),
        },
        aiSummary: analysis.aiSummary,
        createdAt: now.toISOString(),
      })

      // 7. Store alerts
      for (const alert of analysis.alerts) {
        await dbInsertAlert({
          id: 'alert_' + randomUUID(),
          monitorId: monitor.id,
          type: alert.type,
          severity: alert.severity,
          title: alert.title,
          details: { target: monitor.target, checkNumber: monitor.totalChecks },
          createdAt: now.toISOString(),
        })
      }

      // 8. Emit real-time update via WebSocket
      this._emitMonitorUpdate(monitor, analysis)

      // 9. Auto-generate daily report if needed
      await this._maybeGenerateReport(monitor)

      console.log(`✅ [Monitor] ${monitor.target}: ${analysis.healthStatus} (${findings.length} findings, ${analysis.alerts.length} alerts)`)
    } catch (err) {
      console.error(`❌ [Monitor] Check failed for ${monitor.target}:`, err.message)

      // Record failure event
      const now = new Date()
      const intervalMs = SCHEDULE_MAP[monitor.schedule] || SCHEDULE_MAP['1h']
      monitor.lastCheckAt = now.toISOString()
      monitor.nextCheckAt = new Date(now.getTime() + intervalMs).toISOString()
      monitor.healthStatus = 'down'
      monitor.totalChecks = (monitor.totalChecks || 0) + 1
      monitor.updatedAt = now.toISOString()
      await dbUpdateMonitor(monitor)

      await dbInsertEvent({
        id: 'evt_' + randomUUID(),
        monitorId: monitor.id,
        type: 'check',
        severity: 'critical',
        title: `Check #${monitor.totalChecks}: FAILED`,
        details: { error: err.message },
        aiSummary: `Monitoring check failed: ${err.message}`,
        createdAt: now.toISOString(),
      })

      await dbInsertAlert({
        id: 'alert_' + randomUUID(),
        monitorId: monitor.id,
        type: 'downtime',
        severity: 'critical',
        title: `Monitor check failed: ${err.message}`,
        details: { target: monitor.target, error: err.message },
        createdAt: now.toISOString(),
      })
    } finally {
      this.running.delete(monitor.id)
    }
  }

  // ── Run scanner modules (lightweight) ──────────────────────────────────────

  async _executeScanModules(monitor) {
    // Dynamically import scanner functions based on monitor's configured modules
    const moduleMap = {
      headers: () => import('../scanner/headers.js').then(m => m.scanHeaders),
      ssl: () => import('../scanner/ssl.js').then(m => m.scanSsl),
      paths: () => import('../scanner/paths.js').then(m => m.scanPaths),
      dns: () => import('../scanner/dns.js').then(m => m.scanDns),
      cors: () => import('../scanner/cors.js').then(m => m.scanCors),
      tech: () => import('../scanner/tech.js').then(m => m.scanTech),
      info: () => import('../scanner/info.js').then(m => m.scanInfo),
      api: () => import('../scanner/api.js').then(m => m.scanApi),
      secrets: () => import('../scanner/secrets.js').then(m => m.scanSecrets),
    }

    const findings = []
    const enabledModules = monitor.modules || ['headers', 'ssl', 'paths', 'cors']
    const timeoutMs = 60_000 // 60s per module for monitoring (lightweight)

    for (const key of enabledModules) {
      if (!moduleMap[key]) continue

      try {
        const scanFn = await moduleMap[key]()
        const onFinding = (finding) => findings.push(finding)
        const onLog = () => {} // silent during monitoring

        const result = await Promise.race([
          scanFn(monitor.target, onFinding, onLog),
          new Promise((_, reject) => setTimeout(() => reject(new Error(`${key} timed out`)), timeoutMs)),
        ])
      } catch (err) {
        // Module failure is non-fatal — just log and continue
        console.warn(`[Monitor] Module ${key} failed for ${monitor.target}: ${err.message}`)
      }
    }

    return findings
  }

  // ── Auto report generation ─────────────────────────────────────────────────

  async _maybeGenerateReport(monitor) {
    // Generate a daily report every 24 checks or if it's been 24h since last report
    if (monitor.totalChecks % 24 !== 0 && monitor.totalChecks !== 1) return

    try {
      const events = await dbGetEventsByMonitor(monitor.id, 50)
      const alerts = await dbGetAlertsByMonitor(monitor.id, 20)
      const period = new Date().toISOString().slice(0, 10) // YYYY-MM-DD

      const summary = await this.aiWorker.generateReportSummary(monitor, events, alerts, period)

      await dbInsertReport({
        id: 'rpt_' + randomUUID(),
        monitorId: monitor.id,
        projectId: monitor.projectId,
        type: 'daily',
        period,
        summary,
        data: {
          target: monitor.target,
          healthStatus: monitor.healthStatus,
          totalChecks: monitor.totalChecks,
          eventsCount: events.length,
          alertsCount: alerts.length,
          recentAlerts: alerts.slice(0, 10),
        },
        createdAt: new Date().toISOString(),
      })

      console.log(`📊 [Monitor] Auto-report generated for ${monitor.target}`)
    } catch (err) {
      console.error(`[Monitor] Report generation failed:`, err.message)
    }
  }

  // ── WebSocket emit ─────────────────────────────────────────────────────────

  _emitMonitorUpdate(monitor, analysis) {
    if (!this.io) return
    this.io.emit('monitor:update', {
      monitorId: monitor.id,
      target: monitor.target,
      healthStatus: monitor.healthStatus,
      lastCheckAt: monitor.lastCheckAt,
      nextCheckAt: monitor.nextCheckAt,
      totalChecks: monitor.totalChecks,
      aiSummary: analysis.aiSummary,
      alertCount: analysis.alerts.length,
    })
  }
}
