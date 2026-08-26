import { getUserSubscription, consumeScanQuota, activateSubscription, PLANS } from '../src/billing.js'
import * as db from '../src/db.js'
import { randomUUID } from 'node:crypto'

console.log('🧪 Testing SentinelAI 3-Free-Scan Trial System...')

const testUserId = `user_test_trial_${Date.now()}`
const now = new Date().toISOString()

// Create test user first to satisfy foreign key
db.run(
  `INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, 'client', ?)`,
  testUserId, testUserId, `${testUserId}@example.com`, 'hash_placeholder', now
)

// 1. New user gets trial with 3 scan credits
const sub1 = getUserSubscription(testUserId)
console.log('✓ Initial Sub:', {
  plan_id: sub1.plan_id,
  plan_name: sub1.plan_name,
  quotaTotal: sub1.scan_quota_total,
  quotaUsed: sub1.scan_quota_used,
  remaining: sub1.remainingQuota,
  isSubscribed: sub1.isSubscribed,
  isTrial: sub1.isTrial,
})

if (sub1.plan_id !== 'trial' || sub1.scan_quota_total !== 3 || sub1.remainingQuota !== 3) {
  throw new Error('Trial initialization failed!')
}

// 2. Consume 1st scan
const scan1 = consumeScanQuota(testUserId)
console.log('✓ Scan 1 Consumed:', scan1)

// 3. Consume 2nd scan
const scan2 = consumeScanQuota(testUserId)
console.log('✓ Scan 2 Consumed:', scan2)

// 4. Consume 3rd scan
const scan3 = consumeScanQuota(testUserId)
console.log('✓ Scan 3 Consumed:', scan3)

// 5. 4th scan must be rejected with trial upgrade error
let rejected = false
try {
  consumeScanQuota(testUserId)
} catch (err) {
  rejected = true
  console.log('✓ 4th Scan Correctly Blocked with Message:', err.message)
}

if (!rejected) {
  throw new Error('Expected 4th trial scan to be blocked, but it passed!')
}

// 6. Upgrading to Pro unlocks 50 scans
activateSubscription({ userId: testUserId, planId: 'pro', amount: 19 })
const subPro = getUserSubscription(testUserId)
console.log('✓ Upgraded to Pro:', {
  plan_id: subPro.plan_id,
  plan_name: subPro.plan_name,
  quotaTotal: subPro.scan_quota_total,
  quotaUsed: subPro.scan_quota_used,
  remaining: subPro.remainingQuota,
})

if (subPro.plan_id !== 'pro' || subPro.scan_quota_total !== 50) {
  throw new Error('Pro upgrade verification failed!')
}

console.log('\n🎉 ALL TRIAL QUOTA TESTS PASSED SUCCESSFULLY!')
