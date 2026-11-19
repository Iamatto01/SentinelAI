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
      const payload = jwt.verify(token, config.jwt.secret, {
        issuer: [config.jwt.issuer, 'fyp2-backend', 'sentinelai-auth'],
        algorithms: ['HS256'],
      })
      // Verify token generation — tokens issued before a password change are rejected
      const dbUser = db.get(`SELECT token_generation, password_must_change FROM users WHERE id = ?`, payload.id || payload.sub)
      if (dbUser && typeof payload.tgen === 'number' && payload.tgen < (dbUser.token_generation || 0)) {
        return next() // stale token — leave req.user undefined
      }
      req.user = {
        ...payload,
        id: payload.id || payload.sub,
        passwordMustChange: !!(dbUser && dbUser.password_must_change),
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
    { sub: user.id, id: user.id, username: user.username, role: user.role, email: user.email || null, projectId: user.projectId || user.project_id || null, tgen: user.token_generation || 0 },
    config.jwt.secret,
    { issuer: config.jwt.issuer, expiresIn: '12h' }
  )
}

export function getUser(identifier) {
  const norm = (identifier || '').toLowerCase().trim()
  if (!norm) return null
  return db.get(`SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?`, norm, norm)
}

export default { authMiddleware, requireAuth, requireRole, signToken, getUser }
