/**
 * SentinelAI Honeypot & Anti-Reverse Engineering Canary Traps
 *
 * Exposes enticing decoy endpoints designed to detect, trap, and record
 * unauthorized reverse-engineering attempts, automated fuzzers, and crawlers
 * seeking administrative backdoors or internal data leaks.
 */

import * as db from './db.js'

const TRAPPED_IPS = new Map() // ip -> { count, lastSeen, userAgent }

export function isIpTrapped(ip) {
  if (!ip) return false
  const entry = TRAPPED_IPS.get(ip)
  return Boolean(entry && entry.count >= 3)
}

export function setupHoneypot(app) {
  const DECOY_ROUTES = [
    { method: 'all', path: '/api/v1/system/master-dump', desc: 'Simulated master database dump' },
    { method: 'all', path: '/api/admin/backdoor-eval', desc: 'Simulated backdoor evaluation interface' },
    { method: 'all', path: '/api/v1/internal/config-secrets', desc: 'Simulated internal configuration disclosure' },
    { method: 'all', path: '/api/v1/debug/heap-dump', desc: 'Simulated memory heap dump leak' },
    { method: 'all', path: '/api/admin/backup-tar', desc: 'Simulated system archive backup' },
    { method: 'all', path: '/.sentinel-backdoor', desc: 'Simulated hidden dotfile entrypoint' },
  ]

  const handleTrap = (req, res, decoy) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'
    const ua = req.headers['user-agent'] || 'unknown'
    const now = new Date().toISOString()

    const existing = TRAPPED_IPS.get(ip) || { count: 0, firstSeen: now }
    existing.count += 1
    existing.lastSeen = now
    existing.userAgent = ua
    existing.lastDecoy = decoy.path
    TRAPPED_IPS.set(ip, existing)

    console.warn(
      `[HONEYPOT ALERT] 🚨 Unauthorized probing detected on decoy route: ${req.method} ${req.originalUrl || req.path} from IP ${ip} (Hits: ${existing.count}, UA: ${ua})`
    )

    // Persist to audit log
    try {
      db.run(
        `INSERT INTO audit (actor, action, detail, ts) VALUES (?,?,?,?)`,
        'honeypot_canary',
        'honeypot:triggered',
        `Hit decoy "${decoy.path}" via ${req.method} from ${ip} (UA: ${ua.slice(0, 120)})`,
        now
      )
    } catch {
      // non-critical
    }

    // Artificial deceptive latency to waste attacker / scanner time (700ms - 1500ms)
    setTimeout(() => {
      res.status(403).json({
        error: 'Forbidden',
        message: 'Security Violation: Decoy boundary breached. IP address logged under Anti-Reverse Engineering protocol.',
        incidentId: `sec_${Date.now().toString(36)}`,
        timestamp: now,
      })
    }, 750)
  }

  for (const decoy of DECOY_ROUTES) {
    if (decoy.method === 'all') {
      app.all(decoy.path, (req, res) => handleTrap(req, res, decoy))
    }
  }

  // Middleware: block severely flagged trapped IPs from normal API endpoints
  app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'
    if (isIpTrapped(ip)) {
      return res.status(429).json({
        error: 'Too Many Requests',
        message: 'Access restricted due to suspicious intrusion detection activity.',
      })
    }
    next()
  })

  console.log(`[security] Anti-RE Honeypot initialized with ${DECOY_ROUTES.length} decoy canary endpoints`)
}
