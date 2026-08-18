import * as db from './db.js'

/**
 * ScanQueueManager — Offline Long-Running Scan Job Queue & Concurrency Worker Pool.
 *
 * Industry-grade architecture:
 * 1. Enforces max concurrent active scans (default: 2) to protect CPU/RAM from spiking.
 * 2. Excess scans transition into 'queued' state with deterministic FIFO ordering.
 * 3. Automatically dequeues and executes the next pending scan when active jobs finish.
 * 4. Persists job configurations in SQLite for crash resilience & seamless execution.
 */
export class ScanQueueManager {
  constructor({ maxConcurrency = 2 } = {}) {
    this.maxConcurrency = parseInt(process.env.MAX_CONCURRENT_SCANS || String(maxConcurrency), 10)
    this._isProcessing = false
  }

  /** Get count of currently running scans */
  getRunningCount() {
    try {
      const row = db.get(`SELECT COUNT(*) as count FROM scans WHERE status = 'running'`)
      return row?.count || 0
    } catch {
      return 0
    }
  }

  /** Get queue depth */
  getQueueDepth() {
    try {
      const row = db.get(`SELECT COUNT(*) as count FROM scans WHERE status = 'queued'`)
      return row?.count || 0
    } catch {
      return 0
    }
  }

  /** Get queue position for a specific scan */
  getQueuePosition(scanId, createdAt) {
    try {
      const row = db.get(
        `SELECT COUNT(*) as pos FROM scans WHERE status = 'queued' AND created_at <= (SELECT created_at FROM scans WHERE id = ?)`,
        scanId
      )
      return row?.pos || 1
    } catch {
      return 1
    }
  }

  /**
   * Enqueue or immediately dispatch a scan job.
   *
   * @param {Object} scan - Scan record from DB
   * @param {Object} config - Scan configuration options
   * @param {UnifiedPipeline} pipeline - Pipeline instance
   * @returns {Promise<{ status: string, queued: boolean, position: number }>}
   */
  async enqueue(scan, config, pipeline) {
    const running = this.getRunningCount()

    if (running < this.maxConcurrency) {
      // Slot available -> Start immediately
      db.run(`UPDATE scans SET status = 'running', started_at = ? WHERE id = ?`, new Date().toISOString(), scan.id)
      pipeline.log(scan.id, 'info', `🚀 Worker slot acquired (${running + 1}/${this.maxConcurrency}). Initializing scan pipeline...`)

      setImmediate(async () => {
        try {
          if (scan.mode === 'whitebox' && config.folders?.length) {
            await pipeline.runWhiteboxFolder(scan, config)
          } else if (scan.mode === 'whitebox') {
            await pipeline.runWhitebox(scan, config)
          } else {
            await pipeline.runBlackbox(scan, config)
          }
        } catch (e) {
          if (e.message === 'SCAN_STOPPED') return
          pipeline.log(scan.id, 'error', `Pipeline error: ${e.message}`)
          pipeline.finish(scan.id, 'failed')
        }
      })

      return { status: 'running', queued: false, position: 0 }
    } else {
      // Concurrency limit reached -> Queue job
      db.run(`UPDATE scans SET status = 'queued', progress = 0 WHERE id = ?`, scan.id)
      const position = this.getQueuePosition(scan.id, scan.created_at)

      pipeline.log(
        scan.id,
        'info',
        `⏳ Server worker pool busy (${running}/${this.maxConcurrency} active). Assessment queued at position #${position}. Will start automatically once a worker slot frees up.`
      )
      pipeline.emit(scan.id, 'scan:queued', { scanId: scan.id, position, totalQueued: this.getQueueDepth() })

      return { status: 'queued', queued: true, position }
    }
  }

  /**
   * Dequeue and dispatch the next queued scan job in FIFO order.
   * Called automatically upon scan completion or stoppage.
   *
   * @param {UnifiedPipeline} pipeline - Pipeline instance
   */
  async dequeueNext(pipeline) {
    if (this._isProcessing) return
    this._isProcessing = true

    try {
      const running = this.getRunningCount()
      if (running >= this.maxConcurrency) {
        return
      }

      // Find oldest pending queued scan
      const nextScan = db.get(`SELECT * FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1`)
      if (!nextScan) return

      // Retrieve saved configuration
      let config = {}
      const cfgRow = db.get(`SELECT config FROM scan_configs WHERE scan_id = ?`, nextScan.id)
      if (cfgRow?.config) {
        try {
          config = JSON.parse(cfgRow.config)
        } catch {
          config = {}
        }
      }

      // Mark as running
      const now = new Date().toISOString()
      db.run(`UPDATE scans SET status = 'running', started_at = ? WHERE id = ?`, now, nextScan.id)

      pipeline.log(
        nextScan.id,
        'info',
        `🚀 Worker slot released! Dequeued job for ${nextScan.target}. Launching assessment now...`
      )
      pipeline.emit(nextScan.id, 'scan:started', { scanId: nextScan.id, scan: nextScan })

      setImmediate(async () => {
        try {
          if (nextScan.mode === 'whitebox' && config.folders?.length) {
            await pipeline.runWhiteboxFolder(nextScan, config)
          } else if (nextScan.mode === 'whitebox') {
            await pipeline.runWhitebox(nextScan, config)
          } else {
            await pipeline.runBlackbox(nextScan, config)
          }
        } catch (e) {
          if (e.message === 'SCAN_STOPPED') return
          pipeline.log(nextScan.id, 'error', `Pipeline error: ${e.message}`)
          pipeline.finish(nextScan.id, 'failed')
        }
      })

      // Check if more slots are open
      if (this.getRunningCount() < this.maxConcurrency && this.getQueueDepth() > 0) {
        setImmediate(() => this.dequeueNext(pipeline))
      }
    } catch (err) {
      console.error('[queue] Dequeue error:', err)
    } finally {
      this._isProcessing = false
    }
  }
}

export const queueManager = new ScanQueueManager()
