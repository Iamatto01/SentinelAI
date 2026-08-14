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

  // Check period expiry
  let isExpired = false
  if (sub.current_period_end && new Date(sub.current_period_end) < new Date()) {
    isExpired = true
    if (sub.status === 'active') {
      db.run(`UPDATE subscriptions SET status = 'expired', updated_at = ? WHERE id = ?`, new Date().toISOString(), sub.id)
      sub.status = 'expired'
    }
  }

  const plan = PLANS[sub.plan_id] || null
  const remainingQuota = Math.max(0, (sub.scan_quota_total || 0) - (sub.scan_quota_used || 0))
  const isUnlimited = (sub.scan_quota_total || 0) >= 9000
  const isSubscribed = sub.status === 'active' && sub.plan_id !== 'none' && !isExpired

  return {
    ...sub,
    plan,
    isSubscribed,
    isExpired,
    remainingQuota,
    isUnlimited,
  }
}

/**
 * Verify paid subscription & quota before running scan
 */
export function consumeScanQuota(userId) {
  const sub = getUserSubscription(userId)
  
  if (sub.isExpired) {
    throw new Error(`Your SentinelAI subscription has expired. Please renew your plan in Billing to continue scanning.`)
  }

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
export function activateSubscription({ userId, planId, amount, provider = 'stripe', referenceId = '', interval = 'monthly' }) {
  const plan = PLANS[planId]
  if (!plan) throw new Error(`Invalid plan: ${planId}`)

  const now = new Date().toISOString()
  const days = interval === 'yearly' ? 365 : 30
  const periodEnd = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()
  const price = interval === 'yearly' ? plan.priceYearly : plan.priceMonthly

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
    txId, userId, amount || price, plan.currency, 'succeeded', provider, referenceId || `ref_${Date.now()}`, plan.id, now
  )

  return getUserSubscription(userId)
}

/**
 * Admin helper to manually update/extend a client's subscription
 */
export function adminUpdateClientSubscription(userId, { planId, quotaTotal, quotaUsed, status, extendDays = 30 }) {
  const plan = planId ? PLANS[planId] : null
  const now = new Date().toISOString()
  const periodEnd = new Date(Date.now() + (Number(extendDays) || 30) * 24 * 60 * 60 * 1000).toISOString()

  const existing = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, userId)
  if (existing) {
    db.run(
      `UPDATE subscriptions 
       SET plan_id = COALESCE(?, plan_id),
           plan_name = COALESCE(?, plan_name),
           status = COALESCE(?, status),
           scan_quota_total = COALESCE(?, scan_quota_total),
           scan_quota_used = COALESCE(?, scan_quota_used),
           current_period_end = COALESCE(?, current_period_end),
           updated_at = ?
       WHERE user_id = ?`,
      plan ? plan.id : null,
      plan ? plan.name : null,
      status || null,
      quotaTotal !== undefined ? quotaTotal : null,
      quotaUsed !== undefined ? quotaUsed : null,
      periodEnd,
      now,
      userId
    )
  } else {
    const subId = `sub_${randomUUID().slice(0, 12)}`
    db.run(
      `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      subId, userId, plan ? plan.id : 'pro', plan ? plan.name : 'SentinelAI Pro', status || 'active', quotaTotal || 50, quotaUsed || 0, periodEnd, now, now
    )
  }

  return getUserSubscription(userId)
}

/**
 * Get all registered clients with subscription details for Admin Panel
 */
export function getAllClientsAdmin() {
  const clients = db.all(`
    SELECT u.id, u.username, u.email, u.role, u.created_at as joined_at, u.last_login,
           s.plan_id, s.plan_name, s.status as sub_status, s.scan_quota_total, s.scan_quota_used, s.current_period_end,
           gh.github_username,
           (SELECT COUNT(*) FROM scans sc WHERE sc.user_id = u.id) as total_scans
    FROM users u
    LEFT JOIN subscriptions s ON s.user_id = u.id
    LEFT JOIN github_integrations gh ON gh.user_id = u.id
    ORDER BY u.created_at DESC
  `)

  return clients.map(c => {
    const isExpired = c.current_period_end && new Date(c.current_period_end) < new Date()
    return {
      ...c,
      isExpired,
      effective_status: isExpired ? 'expired' : (c.sub_status || 'inactive'),
      remaining_quota: Math.max(0, (c.scan_quota_total || 0) - (c.scan_quota_used || 0)),
    }
  })
}

/**
 * Get payment transaction history
 */
export function getPaymentHistory(userId) {
  if (userId) {
    return db.all(`SELECT * FROM payment_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`, userId)
  }
  return db.all(`SELECT p.*, u.username, u.email FROM payment_transactions p LEFT JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 100`)
}
