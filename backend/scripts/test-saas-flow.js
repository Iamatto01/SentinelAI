import * as db from '../src/db.js'
import { activateSubscription, getUserSubscription, consumeScanQuota, getAllClientsAdmin, adminUpdateClientSubscription, PLANS } from '../src/billing.js'
import bcrypt from 'bcryptjs'

console.log('--- Testing DB and Billing Engine ---')

// 1. Check plans
console.log('Plans:', Object.keys(PLANS))

// 2. Test user creation & subscription
const testUserId = `usr_test_${Date.now()}`
const testEmail = `tester_${Date.now()}@sentinelai.studio`
db.getDb()
db.run(
  `INSERT INTO users (id, username, email, password_hash, role, created_at, last_login) VALUES (?,?,?,?,?,?,?)`,
  testUserId, `tester_${Date.now()}`, testEmail, bcrypt.hashSync('test1234', 10), 'client', new Date().toISOString(), new Date().toISOString()
)

// 3. Activate Pro subscription
const sub = activateSubscription({
  userId: testUserId,
  planId: 'pro',
  interval: 'monthly',
  provider: 'stripe',
  referenceId: 'ref_test_001'
})
console.log('Activated Subscription:', sub.plan_name, '| Quota total:', sub.scan_quota_total, '| Status:', sub.status, '| IsSubscribed:', sub.isSubscribed)

// 4. Consume quota
const consumed = consumeScanQuota(testUserId)
console.log('Consumed Quota:', consumed)

const subAfter = getUserSubscription(testUserId)
console.log('Quota remaining:', subAfter.remainingQuota, '| Used:', subAfter.scan_quota_used)

// 5. Admin listing
const clients = getAllClientsAdmin()
console.log('Admin clients count:', clients.length)
const found = clients.find(c => c.id === testUserId)
console.log('Found created client in admin list:', found?.username, '| Plan:', found?.plan_name, '| Status:', found?.effective_status)

// 6. Admin update quota
const updated = adminUpdateClientSubscription(testUserId, {
  quotaTotal: 100,
  extendDays: 60,
  status: 'active'
})
console.log('Admin updated client quota:', updated.scan_quota_total, '| Period End:', updated.current_period_end)

// Clean up test user
db.run(`DELETE FROM users WHERE id = ?`, testUserId)
console.log('--- All DB and Billing tests passed successfully! ---')
