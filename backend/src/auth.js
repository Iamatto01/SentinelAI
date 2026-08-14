import jwt from 'jsonwebtoken'
import { config } from './config.js'
import * as db from './db.js'

/** JWT auth middleware (populates req.user if a valid Bearer token present). */
export function authMiddleware(req, res, next) {
  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : (req.query?.token || null)
  if (token) {
    try {
      const payload = jwt.verify(token, config.jwt.secret, { issuer: config.jwt.issuer })
      req.user = payload
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
    { sub: user.id, username: user.username, role: user.role, email: user.email || null, projectId: user.projectId || user.project_id || null },
    config.jwt.secret,
    { issuer: config.jwt.issuer, expiresIn: '12h' }
  )
}

export function getUser(identifier) {
  return db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, identifier, identifier)
}

export default { authMiddleware, requireAuth, requireRole, signToken, getUser }
