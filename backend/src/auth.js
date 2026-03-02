import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto'
import { db } from './data.js'

export function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':')
    const hashBuffer = Buffer.from(hash, 'hex')
    const derivedBuffer = scryptSync(password, salt, 64)
    return timingSafeEqual(hashBuffer, derivedBuffer)
  } catch {
    return false
  }
}

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
