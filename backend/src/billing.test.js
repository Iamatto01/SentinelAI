import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'

process.env.JWT_SECRET ||= 'test-only-jwt-secret'
process.env.COMMUNITY_FREE_ACCESS_MODE = 'false'
process.env.DB_PATH = process.env.BILLING_TEST_DB_PATH || `./output/billing-test-${process.pid}.db`

const db = await import('./db.js')
const { consumeScanQuota, formatPlanRow } = await import('./billing.js')
const userId = `billing-test-${randomUUID()}`
const now = new Date().toISOString()

db.run(
  `INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
  userId, userId, `${userId}@example.test`, 'not-a-real-password', 'analyst', now
)
db.run(
  `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  randomUUID(), userId, 'test', 'Test', 'active', 2, 0, now, now
)

try {
  assert.equal(formatPlanRow({ id: 'pro', name: 'Pro', scan_quota: 25, features: '["reports"]', is_open: 1 }).scanQuota, 25)
  assert.deepEqual(consumeScanQuota(userId), { success: true, quotaUsed: 1, quotaTotal: 2 })
  assert.deepEqual(consumeScanQuota(userId), { success: true, quotaUsed: 2, quotaTotal: 2 })
  assert.throws(() => consumeScanQuota(userId), /quota reached/)
  console.log('billing tests: all pass')
} finally {
  db.run('DELETE FROM subscriptions WHERE user_id = ?', userId)
  db.run('DELETE FROM users WHERE id = ?', userId)
}
