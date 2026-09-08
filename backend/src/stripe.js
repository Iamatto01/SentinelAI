/**
 * Stripe Payment Gateway Integration Module
 * Handles Checkout Sessions, Webhook Verification, and Subscription/Credit Activation.
 */

import Stripe from 'stripe'
import config from './config.js'
import { getPlan, activateSubscription, getUserSubscription } from './billing.js'
import * as db from './db.js'

let stripeInstance = null

export function getStripe() {
  if (!stripeInstance) {
    if (!config.stripe?.secretKey) {
      console.warn('[stripe] STRIPE_SECRET_KEY not configured in environment')
      return null
    }
    stripeInstance = new Stripe(config.stripe.secretKey, {
      apiVersion: '2024-06-20',
    })
  }
  return stripeInstance
}

/**
 * Create a Stripe Checkout Session for a plan upgrade or pay-per-scan top-up
 */
export async function createStripeCheckoutSession({
  userId,
  userEmail,
  planId,
  billingInterval = 'monthly',
  promoCode = '',
  origin,
}) {
  const stripe = getStripe()
  if (!stripe) {
    throw new Error('Stripe payment gateway is not configured on the server. Please check STRIPE_SECRET_KEY.')
  }

  const plan = getPlan(planId)
  if (!plan) {
    throw new Error(`Invalid plan '${planId}'`)
  }

  // Calculate price based on interval
  let amount = billingInterval === 'yearly' ? plan.priceYearly : plan.priceMonthly
  if (planId === 'pay_per_scan') {
    amount = plan.priceMonthly || 3.0
  }

  // Check discount promo code if provided
  let discountAmount = 0
  let appliedPromo = ''
  if (promoCode && promoCode.trim()) {
    const promo = db.get(
      `SELECT * FROM promo_codes WHERE code = ? AND is_active = 1`,
      promoCode.trim().toUpperCase()
    )
    if (promo) {
      if (promo.valid_until && new Date(promo.valid_until) < new Date()) {
        // Expired promo, ignore
      } else if (promo.max_uses && promo.times_used >= promo.max_uses) {
        // Max uses reached, ignore
      } else {
        appliedPromo = promo.code
        if (promo.discount_type === 'percent') {
          discountAmount = (amount * Number(promo.discount_value)) / 100
        } else {
          discountAmount = Number(promo.discount_value)
        }
      }
    }
  }

  const finalAmount = Math.max(1.0, amount - discountAmount) // Stripe MYR minimum amount is RM 1.00
  const unitAmountInSen = Math.round(finalAmount * 100) // Convert to sen/cents (integer)

  const clientBase = origin || (config.corsOrigins && config.corsOrigins[0]) || 'https://sentinelai.studio'
  const successUrl = `${clientBase}/app/billing?session_id={CHECKOUT_SESSION_ID}&success=true`
  const cancelUrl = `${clientBase}/app/billing?canceled=true`

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    payment_method_types: ['card'], // Card is universally supported (Credit/Debit/Apple Pay/Google Pay)
    line_items: [
      {
        price_data: {
          currency: (config.stripe.currency || 'myr').toLowerCase(),
          product_data: {
            name: `${plan.name} (${planId === 'pay_per_scan' ? '1 On-Demand Scan Credit' : billingInterval === 'yearly' ? 'Yearly' : 'Monthly'})`,
            description: plan.description || 'SentinelAI Autonomous Security Testing Plan',
          },
          unit_amount: unitAmountInSen,
        },
        quantity: 1,
      },
    ],
    customer_email: userEmail || undefined,
    client_reference_id: userId,
    metadata: {
      userId,
      planId: plan.id,
      planName: plan.name,
      billingInterval,
      promoCode: appliedPromo,
      scanQuota: String(plan.scanQuota || 1),
    },
    success_url: successUrl,
    cancel_url: cancelUrl,
  })

  return {
    sessionId: session.id,
    url: session.url,
  }
}

/**
 * Verify checkout session and fulfill the subscription or top-up credit
 */
export async function verifyAndFulfillSession(sessionId) {
  if (!sessionId) throw new Error('sessionId is required')

  const stripe = getStripe()
  if (!stripe) throw new Error('Stripe not configured')

  const session = await stripe.checkout.sessions.retrieve(sessionId)
  if (!session) throw new Error('Checkout session not found on Stripe')

  if (session.payment_status !== 'paid') {
    return {
      success: false,
      status: session.payment_status,
      message: 'Payment has not been completed yet.',
    }
  }

  const { userId, planId, billingInterval = 'monthly', promoCode = '', scanQuota = '10' } = session.metadata || {}
  if (!userId || !planId) {
    throw new Error('Session metadata missing userId or planId')
  }

  // Idempotency: Check if transaction has already been recorded and fulfilled
  const existingTx = db.get(
    `SELECT * FROM payment_transactions WHERE reference_id = ? OR reference_id = ?`,
    session.id,
    session.payment_intent || session.id
  )

  if (existingTx) {
    return {
      success: true,
      alreadyFulfilled: true,
      subscription: getUserSubscription(userId),
    }
  }

  const amountPaid = (session.amount_total || 0) / 100
  const currency = (session.currency || 'myr').toUpperCase()

  if (planId === 'pay_per_scan') {
    // Top-up on-demand credit to existing quota
    const quotaToAdd = parseInt(scanQuota, 10) || 1
    const currentSub = getUserSubscription(userId)
    const newQuotaTotal = (currentSub.scanQuotaTotal || 3) + quotaToAdd

    db.run(
      `UPDATE subscriptions SET scan_quota_total = ?, updated_at = ? WHERE user_id = ?`,
      newQuotaTotal,
      new Date().toISOString(),
      userId
    )

    const txId = `tx_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`
    db.run(
      `INSERT INTO payment_transactions (id, user_id, amount, currency, status, provider, reference_id, plan_id, discount_amount, promo_code, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      txId,
      userId,
      amountPaid,
      currency,
      'completed',
      'stripe',
      session.id,
      'pay_per_scan',
      0,
      promoCode || '',
      new Date().toISOString()
    )

    return {
      success: true,
      planId: 'pay_per_scan',
      addedQuota: quotaToAdd,
      subscription: getUserSubscription(userId),
    }
  }

  // Standard subscription activation (Pro, Enterprise)
  const updatedSub = activateSubscription({
    userId,
    planId,
    amount: amountPaid,
    provider: 'stripe',
    referenceId: session.id,
    interval: billingInterval,
    promoCode,
  })

  return {
    success: true,
    planId,
    subscription: updatedSub,
  }
}

