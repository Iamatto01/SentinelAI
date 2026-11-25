import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-billing-test-'))
process.env.JWT_SECRET ||= 'test-only-jwt-secret'
process.env.COMMUNITY_FREE_ACCESS_MODE = 'false'
process.env.STRIPE_SECRET_KEY = 'unit_test_mock_stripe_key'
process.env.DB_PATH = path.join(tmpDir, 'billing-test.db')
process.env.OUTPUT_DIR = tmpDir

const db = await import('./db.js')
const {
  consumeScanQuota,
  formatPlanRow,
  createPromoCode,
  deletePromoCode,
  validatePromoCode,
  activateSubscription,
  getPlan,
  updatePlan,
  getPromoCode,
} = await import('./billing.js')
const { createStripeCheckoutSession } = await import('./stripe.js')

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

const createdPromos = []
try {
  // 1. Existing quota & formatPlanRow checks + zero-quota preservation (High #4)
  assert.equal(formatPlanRow({ id: 'pro', name: 'Pro', scan_quota: 25, features: '["reports"]', is_open: 1 }).scanQuota, 25)
  assert.equal(formatPlanRow({ id: 'free0', name: 'ZeroQuota', scan_quota: 0, max_repos: 0, features: '[]', is_open: 1 }).scanQuota, 0)
  assert.equal(formatPlanRow({ id: 'free0', name: 'ZeroQuota', scan_quota: 0, max_repos: 0, features: '[]', is_open: 1 }).maxRepos, 0)
  assert.deepEqual(consumeScanQuota(userId), { success: true, quotaUsed: 1, quotaTotal: 2 })
  assert.deepEqual(consumeScanQuota(userId), { success: true, quotaUsed: 2, quotaTotal: 2 })
  assert.throws(() => consumeScanQuota(userId), /quota reached/)

  // 2. Plan updates & MYR currency formatting on promos
  const updatedPro = updatePlan('pro', { priceMonthly: 35, currency: 'MYR' })
  assert.equal(updatedPro.priceMonthly, 35)

  const minPromo = createPromoCode({
    code: 'MIN100MYR',
    discountType: 'fixed',
    discountValue: 10,
    applicablePlans: 'pro',
    maxUses: 5,
    minPurchaseAmount: 100,
  })
  createdPromos.push(minPromo.id)
  assert.throws(() => validatePromoCode('MIN100MYR', 'pro', 'monthly'), /Minimum purchase of RM 100/)

  const fixedPromo = createPromoCode({
    code: 'SAVE5RM',
    discountType: 'fixed',
    discountValue: 5,
    applicablePlans: 'pro',
    maxUses: 5,
    minPurchaseAmount: 0,
  })
  createdPromos.push(fixedPromo.id)
  const valFixed = validatePromoCode('SAVE5RM', 'pro', 'monthly')
  assert.equal(valFixed.formattedDiscount, 'RM 5 OFF')
  assert.equal(valFixed.finalPrice, 30)

  // 3. 100%-discount promo still writes completed payment_transactions row (amount = 0) and updates used_count atomically
  const freePromo = createPromoCode({
    code: 'FREE100PRO',
    discountType: 'percentage',
    discountValue: 100,
    applicablePlans: 'pro',
    maxUses: 2,
  })
  createdPromos.push(freePromo.id)
  activateSubscription({
    userId,
    planId: 'pro',
    amount: 0,
    provider: 'stripe',
    referenceId: 'cs_test_zero_total',
    interval: 'monthly',
    promoCode: 'FREE100PRO',
  })
  const txRow = db.get(`SELECT * FROM payment_transactions WHERE reference_id = ?`, 'cs_test_zero_total')
  assert.ok(txRow, 'Expected RM 0 transaction row to be recorded')
  assert.equal(txRow.amount, 0)
  assert.equal(txRow.status, 'completed')
  assert.equal(getPromoCode('FREE100PRO').usedCount, 1)

  // 4. Stripe checkout rejects expired / maxed / wrong-plan promo codes upfront
  const expiredPromo = createPromoCode({
    code: 'OLDEXP',
    discountType: 'percentage',
    discountValue: 10,
    applicablePlans: 'all',
    expiresAt: '2020-01-01T00:00:00.000Z',
  })
  createdPromos.push(expiredPromo.id)
  await assert.rejects(
    () => createStripeCheckoutSession({ userId, userEmail: 'u@example.test', planId: 'pro', promoCode: 'OLDEXP' }),
    /expired/i
  )

  const entOnlyPromo = createPromoCode({
    code: 'ENTONLY',
    discountType: 'percentage',
    discountValue: 10,
    applicablePlans: 'enterprise',
  })
  createdPromos.push(entOnlyPromo.id)
  await assert.rejects(
    () => createStripeCheckoutSession({ userId, userEmail: 'u@example.test', planId: 'pro', promoCode: 'ENTONLY' }),
    /cannot be applied/i
  )

  assert.equal(getPlan('pro').priceMonthly, 35)
  console.log('billing tests: all pass')
} finally {
  for (const id of createdPromos) {
    try { deletePromoCode(id) } catch { /* ignore */ }
  }
  try { db.run('DELETE FROM payment_transactions WHERE user_id = ?', userId) } catch { /* ignore */ }
  try { db.run('DELETE FROM subscriptions WHERE user_id = ?', userId) } catch { /* ignore */ }
  try { db.run('DELETE FROM users WHERE id = ?', userId) } catch { /* ignore */ }
  try { db.getDb().close() } catch { /* ignore */ }
  fs.rmSync(tmpDir, { recursive: true, force: true })
}
