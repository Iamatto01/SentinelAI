import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'
const JWT_ISSUER = process.env.JWT_ISSUER || 'vlolv-backend'

export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const match = authHeader.match(/^Bearer\s+(.+)$/i)
  if (!match) {
    req.user = null
    return next()
  }

  const token = match[1]
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: JWT_ISSUER })
    req.user = {
      id: decoded.sub,
      username: decoded.username,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions,
      lastLogin: decoded.lastLogin,
    }
    req.token = token
  } catch {
    req.user = null
    req.token = null
  }
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
