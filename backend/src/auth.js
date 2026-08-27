import jwt from 'jsonwebtoken'
import { config } from './config.js'
import * as db from './db.js'

/** JWT auth middleware (populates req.user if a valid Bearer token present). */
export function authMiddleware(req, res, next) {
  const h = req.headers.authorization || ''
  // Authorization header only — tokens in query strings leak into logs/history
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  if (token) {
    try {
      const payload = jwt.verify(token, config.jwt.secret, { issuer: config.jwt.issuer })
      req.user = {
        ...payload,
        id: payload.id || payload.sub,
      }
    } catch { /* invalid token — leave req.user undefined */ }
  }
  next()
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' })
  next()
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'authentication required' })
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'insufficient role' })
    next()
  }
}

export function signToken(user) {
  return jwt.sign(
    { sub: user.id, id: user.id, username: user.username, role: user.role, email: user.email || null, projectId: user.projectId || user.project_id || null },
    config.jwt.secret,
    { issuer: config.jwt.issuer, expiresIn: '12h' }
  )
}

export function getUser(identifier) {
  const norm = (identifier || '').toLowerCase().trim()
  if (norm === 'admin@sentinelai.com' || norm === 'admin@sentinelai.studio' || norm === 'admin') {
    const adminUser = db.get(`SELECT * FROM users WHERE role = 'admin' OR LOWER(username) = 'admin' LIMIT 1`)
    if (adminUser) return adminUser
  }
  return db.get(`SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?`, norm, norm)
}

export default { authMiddleware, requireAuth, requireRole, signToken, getUser }
