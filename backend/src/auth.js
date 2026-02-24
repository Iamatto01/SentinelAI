import { db } from './data.js'

export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const match = authHeader.match(/^Bearer\s+(.+)$/i)
  if (!match) {
    req.user = null
    return next()
  }

  const token = match[1]
  const user = db.usersByToken.get(token) || null
  req.user = user
  req.token = token
  return next()
}

export function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  return next()
}

export function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' })
    if (!allowed.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' })
    return next()
  }
}
