import assert from 'node:assert/strict'
import jwt from 'jsonwebtoken'

process.env.JWT_SECRET ||= 'test-only-jwt-secret'
const { config } = await import('./config.js')
const { requireAuth, requireRole, signToken } = await import('./auth.js')

const token = signToken({ id: 'user-1', username: 'analyst', role: 'analyst' })
const payload = jwt.verify(token, config.jwt.secret, { issuer: config.jwt.issuer })
assert.equal(payload.id, 'user-1')
assert.equal(payload.role, 'analyst')
assert.ok(payload.exp > payload.iat)
assert.throws(() => jwt.verify(token, 'wrong-secret'))
const expired = jwt.sign({ id: 'expired' }, config.jwt.secret, { issuer: config.jwt.issuer, expiresIn: -1 })
assert.throws(() => jwt.verify(expired, config.jwt.secret, { issuer: config.jwt.issuer }), /jwt expired/)

const next = () => { next.called = true }
const unauthenticated = { user: null }
let response = { statusCode: null, body: null, status(code) { this.statusCode = code; return this }, json(body) { this.body = body } }
requireAuth(unauthenticated, response, next)
assert.equal(response.statusCode, 401)

response = { statusCode: null, body: null, status(code) { this.statusCode = code; return this }, json(body) { this.body = body } }
requireRole('admin')({ user: { role: 'analyst' } }, response, next)
assert.equal(response.statusCode, 403)

next.called = false
requireRole('analyst')({ user: { role: 'analyst' } }, response, next)
assert.equal(next.called, true)

console.log('auth tests: all pass')
