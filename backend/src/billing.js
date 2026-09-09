/**
 * Billing & Subscription Management Module
 * Supports Tiered Plans, Promo Codes, Dynamic Discounts, Quota Enforcement, and Custom Enterprise Overrides.
 */

import { randomUUID } from 'node:crypto'
import * as db from './db.js'

/**
 * Format plan row from database into a consistent JS object
 */
export function formatPlanRow(row) {
  if (!row) return null
  let features = []
  try {
    features = typeof row.features === 'string' ? JSON.parse(row.features) : (row.features || [])
  } catch {
    features = row.features ? [row.features] : []
  }

  return {
    id: row.id,
    name: row.name,
    description: row.description || '',
    priceMonthly: Number(row.price_monthly) || 0,
    priceYearly: Number(row.price_yearly) || 0,
    price_monthly: Number(row.price_monthly) || 0,
    price_yearly: Number(row.price_yearly) || 0,
    currency: row.currency || 'USD',
    scanQuota: Number(row.scan_quota) || 10,
    scan_quota: Number(row.scan_quota) || 10,
    maxRepos: Number(row.max_repos) || 1,
    max_repos: Number(row.max_repos) || 1,
    features,
    popular: Boolean(row.is_popular),
    is_popular: Boolean(row.is_popular),
    isOpen: Boolean(row.is_open),
    is_open: Boolean(row.is_open),
    isCustom: Boolean(row.is_custom),
    is_custom: Boolean(row.is_custom),
    badge: row.badge || '',
    sortOrder: Number(row.sort_order) || 0,
    sort_order: Number(row.sort_order) || 0,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

/**
 * Get all plans from database (dynamically configurable)
 */
export function getAllPlans({ onlyOpen = false } = {}) {
  try {
    const query = onlyOpen 
      ? `SELECT * FROM plans WHERE is_open = 1 ORDER BY sort_order ASC, created_at ASC`
      : `SELECT * FROM plans ORDER BY sort_order ASC, created_at ASC`
    const rows = db.all(query)
    return rows.map(formatPlanRow)
  } catch (e) {
    console.warn('[billing] getAllPlans error:', e.message)
    return []
  }
}

/**
 * Get single plan by ID
 */
export function getPlan(planId) {
  if (!planId) return null
  try {
    const row = db.get(`SELECT * FROM plans WHERE id = ?`, planId)
    if (row) return formatPlanRow(row)
  } catch (e) {
    console.warn('[billing] getPlan error:', e.message)
  }
  return null
}

/**
 * Legacy proxy object to maintain backward compatibility with PLANS[planId]
 */
export const PLANS = new Proxy({}, {
  get(target, prop) {
    if (typeof prop !== 'string') return target[prop]
    return getPlan(prop)
  },
  ownKeys() {
    return getAllPlans().map(p => p.id)
  },
  getOwnPropertyDescriptor(target, prop) {
    return {
      enumerable: true,
      configurable: true,
      value: getPlan(prop)
    }
  }
})

export const COMMUNITY_FREE_ACCESS_MODE = process.env.COMMUNITY_FREE_ACCESS_MODE !== 'false'

/**
 * Create a new subscription plan (Admin)
 */
export function createPlan(data) {
  let {
    id,
    name,
    description = '',
    priceMonthly = 0,
    priceYearly = 0,
    currency = 'USD',
    scanQuota = 10,
    maxRepos = 1,
    features = [],
    isPopular = false,
    isOpen = true,
    isCustom = false,
    badge = '',
    sortOrder = 0,
  } = data

  if (!name || !name.trim()) throw new Error('Plan name is required')
  const cleanId = (id && id.trim()) 
    ? id.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-')
    : name.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 30)

  const existing = getPlan(cleanId)
  if (existing) throw new Error(`Plan ID '${cleanId}' already exists. Please choose a different ID or name.`)

  const featuresStr = Array.isArray(features) ? JSON.stringify(features) : JSON.stringify([features])
  const now = new Date().toISOString()

  db.run(`
    INSERT INTO plans (id, name, description, price_monthly, price_yearly, currency, scan_quota, max_repos, features, is_popular, is_open, is_custom, badge, sort_order, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `,
    cleanId,
    name.trim(),
    description.trim(),
    Number(priceMonthly) || 0,
    Number(priceYearly) || 0,
    currency.toUpperCase(),
    Number(scanQuota) || 0,
    Number(maxRepos) || 1,
    featuresStr,
    isPopular ? 1 : 0,
    isOpen ? 1 : 0,
    isCustom ? 1 : 0,
    badge.trim(),
    Number(sortOrder) || 0,
    now,
    now
  )

  return getPlan(cleanId)
}

/**
 * Edit an existing plan (Admin)
 */
export function updatePlan(id, data) {
  const existing = getPlan(id)
  if (!existing) throw new Error(`Plan '${id}' not found`)

  const featuresStr = data.features !== undefined
    ? (Array.isArray(data.features) ? JSON.stringify(data.features) : JSON.stringify([data.features]))
    : JSON.stringify(existing.features)

  const now = new Date().toISOString()

  db.run(`
    UPDATE plans
    SET name = COALESCE(?, name),
        description = COALESCE(?, description),
        price_monthly = COALESCE(?, price_monthly),
        price_yearly = COALESCE(?, price_yearly),
        currency = COALESCE(?, currency),
        scan_quota = COALESCE(?, scan_quota),
        max_repos = COALESCE(?, max_repos),
        features = ?,
        is_popular = COALESCE(?, is_popular),
        is_open = COALESCE(?, is_open),
        is_custom = COALESCE(?, is_custom),
        badge = COALESCE(?, badge),
        sort_order = COALESCE(?, sort_order),
        updated_at = ?
    WHERE id = ?
  `,
    data.name ? data.name.trim() : null,
    data.description !== undefined ? data.description.trim() : null,
    data.priceMonthly !== undefined ? Number(data.priceMonthly) : (data.price_monthly !== undefined ? Number(data.price_monthly) : null),
    data.priceYearly !== undefined ? Number(data.priceYearly) : (data.price_yearly !== undefined ? Number(data.price_yearly) : null),
    data.currency ? data.currency.toUpperCase() : null,
    data.scanQuota !== undefined ? Number(data.scanQuota) : (data.scan_quota !== undefined ? Number(data.scan_quota) : null),
    data.maxRepos !== undefined ? Number(data.maxRepos) : (data.max_repos !== undefined ? Number(data.max_repos) : null),
    featuresStr,
    data.isPopular !== undefined ? (data.isPopular ? 1 : 0) : (data.is_popular !== undefined ? (data.is_popular ? 1 : 0) : null),
    data.isOpen !== undefined ? (data.isOpen ? 1 : 0) : (data.is_open !== undefined ? (data.is_open ? 1 : 0) : null),
    data.isCustom !== undefined ? (data.isCustom ? 1 : 0) : (data.is_custom !== undefined ? (data.is_custom ? 1 : 0) : null),
    data.badge !== undefined ? data.badge.trim() : null,
    data.sortOrder !== undefined ? Number(data.sortOrder) : (data.sort_order !== undefined ? Number(data.sort_order) : null),
    now,
    id
  )

  return getPlan(id)
}

/**
 * Open or Close a plan for public signups (Admin)
 */
export function togglePlanStatus(id, isOpen) {
  const existing = getPlan(id)
  if (!existing) throw new Error(`Plan '${id}' not found`)
  const now = new Date().toISOString()
  db.run(`UPDATE plans SET is_open = ?, updated_at = ? WHERE id = ?`, isOpen ? 1 : 0, now, id)
  return getPlan(id)
}

/**
 * Delete a plan (Admin)
 */
export function deletePlan(id) {
  const existing = getPlan(id)
  if (!existing) throw new Error(`Plan '${id}' not found`)
  db.run(`DELETE FROM plans WHERE id = ?`, id)
  return { success: true, message: `Plan '${id}' deleted successfully` }
}

// ── PROMO CODES ENGINE ─────────────────────────────────────────────────────────

/**
 * Get all promo codes with usage stats (Admin)
 */
export function getAllPromoCodes() {
  try {
    const rows = db.all(`SELECT * FROM promo_codes ORDER BY created_at DESC`)
    return rows.map(r => ({
      id: r.id,
      code: r.code,
      discountType: r.discount_type,
      discount_type: r.discount_type,
      discountValue: Number(r.discount_value) || 0,
      discount_value: Number(r.discount_value) || 0,
      applicablePlans: r.applicable_plans || 'all',
      applicable_plans: r.applicable_plans || 'all',
      maxUses: Number(r.max_uses) || 0,
      max_uses: Number(r.max_uses) || 0,
      usedCount: Number(r.used_count) || 0,
      used_count: Number(r.used_count) || 0,
      minPurchaseAmount: Number(r.min_purchase_amount) || 0,
      min_purchase_amount: Number(r.min_purchase_amount) || 0,
      expiresAt: r.expires_at,
      expires_at: r.expires_at,
      isActive: Boolean(r.is_active),
      is_active: Boolean(r.is_active),
      note: r.note || '',
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }))
  } catch (e) {
    console.warn('[billing] getAllPromoCodes error:', e.message)
    return []
  }
}

/**
 * Get single promo code
 */
export function getPromoCode(codeOrId) {
  if (!codeOrId) return null
  const row = db.get(`SELECT * FROM promo_codes WHERE id = ? OR UPPER(code) = UPPER(?)`, codeOrId, codeOrId.trim())
  if (!row) return null
  return {
    id: row.id,
    code: row.code,
    discountType: row.discount_type,
    discount_type: row.discount_type,
    discountValue: Number(row.discount_value) || 0,
    discount_value: Number(row.discount_value) || 0,
    applicablePlans: row.applicable_plans || 'all',
    applicable_plans: row.applicable_plans || 'all',
    maxUses: Number(row.max_uses) || 0,
    max_uses: Number(row.max_uses) || 0,
    usedCount: Number(row.used_count) || 0,
    used_count: Number(row.used_count) || 0,
    minPurchaseAmount: Number(row.min_purchase_amount) || 0,
    min_purchase_amount: Number(row.min_purchase_amount) || 0,
    expiresAt: row.expires_at,
    expires_at: row.expires_at,
    isActive: Boolean(row.is_active),
    is_active: Boolean(row.is_active),
    note: row.note || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

/**
 * Create a new Promo Code (Admin)
 */
export function createPromoCode(data) {
  let {
    code,
    discountType = 'percentage',
    discountValue = 10,
    applicablePlans = 'all',
    maxUses = 0,
    minPurchaseAmount = 0,
    expiresAt = null,
    isActive = true,
    note = '',
  } = data

  if (!code || !code.trim()) throw new Error('Promo code string is required')
  const cleanCode = code.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '')
  if (cleanCode.length < 3) throw new Error('Promo code must be at least 3 characters long')

  const existing = getPromoCode(cleanCode)
  if (existing) throw new Error(`Promo code '${cleanCode}' already exists`)

  const id = `promo_${randomUUID().slice(0, 12)}`
  const now = new Date().toISOString()

  db.run(`
    INSERT INTO promo_codes (id, code, discount_type, discount_value, applicable_plans, max_uses, used_count, min_purchase_amount, expires_at, is_active, note, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
  `,
    id,
    cleanCode,
    discountType === 'fixed' ? 'fixed' : 'percentage',
    Number(discountValue) || 0,
    typeof applicablePlans === 'string' ? applicablePlans : JSON.stringify(applicablePlans),
    Number(maxUses) || 0,
    Number(minPurchaseAmount) || 0,
    expiresAt ? new Date(expiresAt).toISOString() : null,
    isActive ? 1 : 0,
    note ? note.trim() : '',
    now,
    now
  )

  return getPromoCode(id)
}

/**
 * Update a Promo Code (Admin)
 */
export function updatePromoCode(id, data) {
  const existing = getPromoCode(id)
  if (!existing) throw new Error(`Promo code '${id}' not found`)

  const now = new Date().toISOString()
  db.run(`
    UPDATE promo_codes
    SET code = COALESCE(?, code),
        discount_type = COALESCE(?, discount_type),
        discount_value = COALESCE(?, discount_value),
        applicable_plans = COALESCE(?, applicable_plans),
        max_uses = COALESCE(?, max_uses),
        min_purchase_amount = COALESCE(?, min_purchase_amount),
        expires_at = ?,
        is_active = COALESCE(?, is_active),
        note = COALESCE(?, note),
        updated_at = ?
    WHERE id = ?
  `,
    data.code ? data.code.trim().toUpperCase() : null,
    data.discountType || data.discount_type || null,
    data.discountValue !== undefined ? Number(data.discountValue) : (data.discount_value !== undefined ? Number(data.discount_value) : null),
    data.applicablePlans !== undefined ? (typeof data.applicablePlans === 'string' ? data.applicablePlans : JSON.stringify(data.applicablePlans)) : null,
    data.maxUses !== undefined ? Number(data.maxUses) : null,
    data.minPurchaseAmount !== undefined ? Number(data.minPurchaseAmount) : null,
    data.expiresAt !== undefined ? (data.expiresAt ? new Date(data.expiresAt).toISOString() : null) : existing.expiresAt,
    data.isActive !== undefined ? (data.isActive ? 1 : 0) : (data.is_active !== undefined ? (data.is_active ? 1 : 0) : null),
    data.note !== undefined ? data.note.trim() : null,
    now,
    id
  )

  return getPromoCode(id)
}

/**
 * Toggle Promo Code active status
 */
export function togglePromoCodeStatus(id, isActive) {
  const existing = getPromoCode(id)
  if (!existing) throw new Error(`Promo code '${id}' not found`)
  const now = new Date().toISOString()
  db.run(`UPDATE promo_codes SET is_active = ?, updated_at = ? WHERE id = ?`, isActive ? 1 : 0, now, id)
  return getPromoCode(id)
}

/**
 * Delete a Promo Code
 */
export function deletePromoCode(id) {
  const existing = getPromoCode(id)
  if (!existing) throw new Error(`Promo code '${id}' not found`)
  db.run(`DELETE FROM promo_codes WHERE id = ?`, id)
  return { success: true, message: `Promo code '${existing.code}' deleted successfully` }
}

/**
 * Validate a promo code against a specific plan and compute final discount
 */
export function validatePromoCode(code, planId, billingInterval = 'monthly') {
  if (!code || !code.trim()) throw new Error('Please enter a promo code')
  const promo = getPromoCode(code)
  if (!promo) throw new Error(`Promo code '${code.trim().toUpperCase()}' is invalid or does not exist`)
  if (!promo.isActive) throw new Error(`Promo code '${promo.code}' is currently inactive`)

  if (promo.expiresAt && new Date(promo.expiresAt) < new Date()) {
    throw new Error(`Promo code '${promo.code}' expired on ${new Date(promo.expiresAt).toLocaleDateString()}`)
  }

  if (promo.maxUses > 0 && promo.usedCount >= promo.maxUses) {
    throw new Error(`Promo code '${promo.code}' has reached its maximum redemption limit`)
  }

  const plan = getPlan(planId)
  if (!plan) throw new Error(`Invalid plan '${planId}'`)

  if (promo.applicablePlans && promo.applicablePlans !== 'all') {
    const allowed = promo.applicablePlans.split(',').map(s => s.trim().toLowerCase())
    if (!allowed.includes(planId.toLowerCase())) {
      throw new Error(`Promo code '${promo.code}' cannot be applied to the ${plan.name} plan`)
    }
  }

  const originalPrice = billingInterval === 'yearly' ? plan.priceYearly : plan.priceMonthly
  if (promo.minPurchaseAmount > 0 && originalPrice < promo.minPurchaseAmount) {
    throw new Error(`Minimum purchase of $${promo.minPurchaseAmount} is required for code '${promo.code}'`)
  }

  let discountAmount = 0
  if (promo.discountType === 'percentage') {
    discountAmount = Math.round((originalPrice * (promo.discountValue / 100)) * 100) / 100
  } else {
    discountAmount = Math.min(originalPrice, promo.discountValue)
  }

  const finalPrice = Math.max(0, Math.round((originalPrice - discountAmount) * 100) / 100)

  return {
    valid: true,
    code: promo.code,
    discountType: promo.discountType,
    discountValue: promo.discountValue,
    discountAmount,
    originalPrice,
    finalPrice,
    formattedDiscount: promo.discountType === 'percentage' ? `${promo.discountValue}% OFF` : `$${promo.discountValue} OFF`,
    note: promo.note || '',
  }
}

// ── USER SUBSCRIPTIONS & CHECKOUT ──────────────────────────────────────────────

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

  const plan = getPlan(sub.plan_id) || null
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
 * Process successful payment and activate upgraded plan (supports Promo Codes & Discounts)
 */
export function activateSubscription({ userId, planId, amount, provider = 'stripe', referenceId = '', interval = 'monthly', promoCode = '' }) {
  const plan = getPlan(planId)
  if (!plan) throw new Error(`Invalid plan: ${planId}`)

  let discountAmount = 0
  let appliedPromo = null
  if (promoCode) {
    try {
      const val = validatePromoCode(promoCode, planId, interval)
      if (val.valid) {
        discountAmount = val.discountAmount
        appliedPromo = val.code
        // Increment redemption counter in database
        db.run(`UPDATE promo_codes SET used_count = used_count + 1, updated_at = ? WHERE UPPER(code) = UPPER(?)`, new Date().toISOString(), appliedPromo)
      }
    } catch (e) {
      console.warn('[billing] promo validation warning on checkout:', e.message)
    }
  }

  const now = new Date().toISOString()
  const days = interval === 'yearly' ? 365 : 30
  const periodEnd = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()
  const basePrice = interval === 'yearly' ? plan.priceYearly : plan.priceMonthly
  const finalPaidAmount = amount !== undefined ? amount : Math.max(0, basePrice - discountAmount)

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

  // Record transaction in database only if actual payment occurred for a paid plan
  if (plan.id !== 'trial' && finalPaidAmount > 0 && provider !== 'system') {
    const txId = `tx_${randomUUID().slice(0, 12)}`
    db.run(
      `INSERT INTO payment_transactions (id, user_id, amount, currency, status, provider, reference_id, plan_id, discount_amount, promo_code, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      txId, userId, finalPaidAmount, plan.currency, 'completed', provider, referenceId || `ref_${Date.now()}`, plan.id, discountAmount, appliedPromo, now
    )
  }

  return getUserSubscription(userId)
}

/**
 * Admin helper to manually update/extend or grant custom bespoke overrides to a client's subscription
 */
export function adminUpdateClientSubscription(userId, { planId, planName, quotaTotal, quotaUsed, status, discountPercent, customNotes, extendDays = 30 }) {
  const plan = planId ? getPlan(planId) : null
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
           discount_percent = COALESCE(?, discount_percent),
           custom_notes = COALESCE(?, custom_notes),
           updated_at = ?
       WHERE user_id = ?`,
      plan ? plan.id : (planId || null),
      plan ? plan.name : (planName || null),
      status || null,
      quotaTotal !== undefined ? quotaTotal : null,
      quotaUsed !== undefined ? quotaUsed : null,
      extendDays ? periodEnd : null,
      discountPercent !== undefined ? Number(discountPercent) : null,
      customNotes !== undefined ? customNotes : null,
      now,
      userId
    )
  } else {
    const subId = `sub_${randomUUID().slice(0, 12)}`
    db.run(
      `INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, discount_percent, custom_notes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      subId, userId, plan ? plan.id : (planId || 'pro'), plan ? plan.name : (planName || 'SentinelAI Pro'), status || 'active', quotaTotal || 50, quotaUsed || 0, periodEnd, Number(discountPercent) || 0, customNotes || '', now, now
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
           s.plan_id, s.plan_name, s.status as sub_status, s.scan_quota_total, s.scan_quota_used, s.current_period_end, s.discount_percent, s.custom_notes,
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
