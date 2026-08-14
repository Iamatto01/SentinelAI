/**
 * Billing & Subscription Management Module
 * Supports Tiered Plans, Quota Enforcement, Checkout Sessions, and Payment Webhooks.
 */

import { randomUUID } from 'node:crypto'
import * as db from './db.js'

export const PLANS = {
  pro: {
    id: 'pro',
    name: 'SentinelAI Pro',
    priceMonthly: 19,
    priceYearly: 190,
    currency: 'USD',
    scanQuota: 50,
    maxRepos: 5,
    features: [
      '5 Linked GitHub Repositories',
      '50 AI Code Audits / month',
      'Continuous Webhooks (Push & PR)',
      'Automated Email PDF Delivery',
      'AI Auto-Fix & Remediation Diffs',
      'Priority Security Agent Analysis'
    ],
    popular: true,
  },
  enterprise: {
    id: 'enterprise',
    name: 'SentinelAI Enterprise',
    priceMonthly: 79,
    priceYearly: 790,
    currency: 'USD',
    scanQuota: 9999,
    maxRepos: 999,
    features: [
      'Unlimited GitHub Repositories',
      'Unlimited AI Code Audits',
      'GitHub PR Bot Inline Review',
      'Real-time Slack / Discord Webhooks',
      'Executive White-label PDF Reports',
      'Dedicated SLA & 24/7 Support'
    ],
    popular: false,
  },
}

/**
 * Get or initialize user subscription (paid-only system, default is inactive)
 */
export function getUserSubscription(userId) {
  let sub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, userId)
  if (!sub) {
    const id = `sub_${randomUUID().slice(0, 12)}`
    const now = new Date().toISOString()
    db.run(
      `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
       VALUES (?, ?, 'none', 'No Active Subscription', 'inactive', 0, 0, NULL, ?, ?)`,
      id, userId, now, now
    )
    sub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, userId)
  }

  const plan = PLANS[sub.plan_id] || null
  const remainingQuota = Math.max(0, (sub.scan_quota_total || 0) - (sub.scan_quota_used || 0))
  const isUnlimited = (sub.scan_quota_total || 0) >= 9000
  const isSubscribed = sub.status === 'active' && sub.plan_id !== 'none'

  return {
    ...sub,
    plan,
    isSubscribed,
    remainingQuota,
    isUnlimited,
  }
}

/**
 * Verify paid subscription & quota before running scan
 */
export function consumeScanQuota(userId) {
  const sub = getUserSubscription(userId)
  
  if (!sub.isSubscribed || sub.status !== 'active') {
    throw new Error(`An active SentinelAI paid subscription is required to run code audits. Please subscribe to Pro or Enterprise in Billing.`)
  }

  if (!sub.isUnlimited && sub.scan_quota_used >= sub.scan_quota_total) {
    throw new Error(`Monthly scan quota reached (${sub.scan_quota_used}/${sub.scan_quota_total}). Please upgrade your SentinelAI subscription in Billing.`)
  }

  db.run(
    `UPDATE subscriptions SET scan_quota_used = scan_quota_used + 1, updated_at = ? WHERE user_id = ?`,
    new Date().toISOString(), userId
  )

  return {
    success: true,
    quotaUsed: sub.scan_quota_used + 1,
    quotaTotal: sub.scan_quota_total,
  }
}

/**
 * Process successful payment and activate upgraded plan
 */
export function activateSubscription({ userId, planId, amount, provider = 'stripe', referenceId = '' }) {
  const plan = PLANS[planId]
  if (!plan) throw new Error(`Invalid plan: ${planId}`)

  const now = new Date().toISOString()
  const periodEnd = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()

  // Update or insert subscription
  const existing = db.get(`SELECT id FROM subscriptions WHERE user_id = ?`, userId)
  if (existing) {
    db.run(
      `UPDATE subscriptions 
       SET plan_id = ?, plan_name = ?, status = 'active', scan_quota_total = ?, scan_quota_used = 0, current_period_end = ?, updated_at = ?
       WHERE user_id = ?`,
      plan.id, plan.name, plan.scanQuota, periodEnd, now, userId
    )
  } else {
    const subId = `sub_${randomUUID().slice(0, 12)}`
    db.run(
      `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
      subId, userId, plan.id, plan.name, 'active', plan.scanQuota, periodEnd, now, now
    )
  }

  // Record transaction in database
  const txId = `tx_${randomUUID().slice(0, 12)}`
  db.run(
    `INSERT INTO payment_transactions (id, user_id, amount, currency, status, provider, reference_id, plan_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    txId, userId, amount || plan.priceMonthly, plan.currency, 'succeeded', provider, referenceId || `ref_${Date.now()}`, plan.id, now
  )

  return getUserSubscription(userId)
}

/**
 * Get payment transaction history
 */
export function getPaymentHistory(userId) {
  return db.all(`SELECT * FROM payment_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`, userId)
}
