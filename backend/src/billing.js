/**
 * Billing & Subscription Management Module
 * Supports Tiered Plans, Quota Enforcement, Checkout Sessions, and Payment Webhooks.
 */

import { randomUUID } from 'node:crypto'
import * as db from './db.js'

export const PLANS = {
  trial: {
    id: 'trial',
    name: 'Free Trial',
    priceMonthly: 0,
    priceYearly: 0,
    currency: 'USD',
    scanQuota: 3,
    maxRepos: 1,
    features: [
      '3 Free Autonomous Security Scans',
      'Hexstrike 150+ Kali Toolchain (DAST + SAST)',
      'Multi-LLM Consensus AI Verification',
      'Executive Summary & Remediation Diff'
    ],
    popular: false,
  },
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
    consultationIncluded: true,
    consultationHours: 4,
    features: [
      'Unlimited GitHub Repositories',
      'Unlimited AI Code Audits',
      '👨‍💼 1-on-1 Certified Security Consultant & Advisory (Guided Remediation & Virtual CISO)',
      'GitHub PR Bot Inline Review',
      'Real-time Slack / Discord Webhooks',
      'Executive White-label PDF Reports',
      'Dedicated SLA & 24/7 VIP Support'
    ],
    popular: false,
  },
}

export const COMMUNITY_FREE_ACCESS_MODE = process.env.COMMUNITY_FREE_ACCESS_MODE !== 'false'

/**
 * Get or initialize user subscription (defaults to Free Trial with 3 scans)
 */
export function getUserSubscription(userId) {
  if (!userId) return null
  let sub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, userId)
  if (!sub) {
    const userExists = db.get(`SELECT id FROM users WHERE id = ?`, userId)
    if (!userExists) return null
    const id = `sub_${randomUUID().slice(0, 12)}`
    const now = new Date().toISOString()
    try {
      db.run(
        `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
         VALUES (?, ?, 'trial', 'Free Trial', 'active', 3, 0, NULL, ?, ?)`,
        id, userId, now, now
      )
      sub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, userId)
    } catch (e) {
      console.warn('[billing] subscription init warning:', e.message)
      return null
    }
  } else if (sub.plan_id === 'none' && sub.status === 'inactive') {
    // Upgrade existing inactive empty accounts to Free Trial with 3 credits
    db.run(
      `UPDATE subscriptions SET plan_id = 'trial', plan_name = 'Free Trial', status = 'active', scan_quota_total = 3, updated_at = ? WHERE id = ?`,
      new Date().toISOString(), sub.id
    )
    sub = db.get(`SELECT * FROM subscriptions WHERE user_id = ?`, userId)
  }

  if (!sub) return null

  // Check period expiry (only for paid plans with set expiration)
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
  const isTrial = sub.plan_id === 'trial'
  const isSubscribed = sub.status === 'active' && !isExpired

  return {
    ...sub,
    plan,
    isSubscribed,
    isExpired,
    isTrial,
    remainingQuota,
    isUnlimited,
  }
}

/**
 * Toggle for community open-access trial mode.
 * When true, paywalls/hard locks are temporarily relaxed for community testing.
 */
export const COMMUNITY_FREE_ACCESS_MODE = true

/**
 * Verify subscription & quota before running scan
 */
export function consumeScanQuota(userId) {
  const sub = getUserSubscription(userId)
  
  if (!COMMUNITY_FREE_ACCESS_MODE) {
    if (sub.isExpired) {
      throw new Error(`Your SentinelAI subscription has expired. Please renew your plan in Billing to continue scanning.`)
    }

    if (!sub.isSubscribed || sub.status !== 'active') {
      throw new Error(`An active subscription is required to run security audits. Please subscribe to Pro or Enterprise in Billing.`)
    }

    if (!sub.isUnlimited && sub.scan_quota_used >= sub.scan_quota_total) {
      if (sub.plan_id === 'trial') {
        throw new Error(`Free trial scan limit reached (${sub.scan_quota_used}/${sub.scan_quota_total} scans used). Please upgrade to SentinelAI Pro or Enterprise in Billing to continue scanning.`)
      }
      throw new Error(`Monthly scan quota reached (${sub.scan_quota_used}/${sub.scan_quota_total}). Please upgrade your SentinelAI subscription in Billing.`)
    }
  }

  // Increment usage count for analytics/tracking
  db.run(
    `UPDATE subscriptions SET scan_quota_used = scan_quota_used + 1, updated_at = ? WHERE user_id = ?`,
    new Date().toISOString(), userId
  )

  return {
    success: true,
    quotaUsed: (sub.scan_quota_used || 0) + 1,
    quotaTotal: sub.scan_quota_total || 3,
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
 * Get detailed customer folder data for Admin Panel inspection
 */
export function getClientDetailsAdmin(userId) {
  const user = db.get(`SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?`, userId)
  if (!user) throw new Error('Client user not found')

  const subscription = getUserSubscription(userId)
  const github = db.get(`SELECT github_username, created_at as connected_at FROM github_integrations WHERE user_id = ?`, userId)
  const repos = db.all(`SELECT * FROM github_repos WHERE user_id = ? ORDER BY created_at DESC`, userId)

  // Client Projects
  const projects = db.all(`
    SELECT p.*,
           (SELECT COUNT(*) FROM scans sc WHERE sc.project_id = p.id) as scan_count,
           (SELECT COUNT(*) FROM findings f WHERE f.scan_id IN (SELECT id FROM scans WHERE project_id = p.id)) as finding_count
    FROM projects p
    WHERE p.client_id = ? OR p.client = ? OR p.client = ? OR p.id IN (SELECT project_id FROM scans WHERE user_id = ?)
    ORDER BY p.updated_at DESC
  `, userId, user.username, user.email, userId)

  // Client Scans
  const scans = db.all(`
    SELECT s.*,
           p.name as project_name,
           (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as findings_count,
           (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'critical') as critical_count,
           (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'high') as high_count
    FROM scans s
    LEFT JOIN projects p ON p.id = s.project_id
    WHERE s.user_id = ? OR s.project_id IN (SELECT id FROM projects WHERE client_id = ? OR client = ? OR client = ?)
    ORDER BY s.created_at DESC
  `, userId, userId, user.username, user.email)

  // Severity summary across all client scans
  const findings = db.all(`
    SELECT f.severity, COUNT(*) as count
    FROM findings f
    WHERE f.scan_id IN (
      SELECT id FROM scans WHERE user_id = ? OR project_id IN (SELECT id FROM projects WHERE client_id = ? OR client = ? OR client = ?)
    )
    GROUP BY f.severity
  `, userId, userId, user.username, user.email)

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  findings.forEach(row => {
    if (severityCounts[row.severity] !== undefined) {
      severityCounts[row.severity] = row.count
    }
  })

  return {
    user,
    subscription,
    github: github ? { ...github, repos } : null,
    projects,
    scans,
    severityCounts,
    totalFindings: Object.values(severityCounts).reduce((a, b) => a + b, 0),
  }
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

