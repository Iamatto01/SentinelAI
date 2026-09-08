import React, { useState, useEffect } from 'react'
import {
  CreditCard, Sparkles, Check, Zap, Shield, ArrowRight, CheckCircle2,
  Calendar, Layers, FileText, AlertCircle, RefreshCw, Loader2, Star,
  Lock, TrendingUp, HelpCircle, BadgeCheck, QrCode, Smartphone, Copy,
  ExternalLink, Building2
} from 'lucide-react'
import QRCode from 'qrcode'
import { api } from '../lib/api.js'
import { BillingSkeleton } from '../components/SkeletonLoader.jsx'

export default function Billing() {
  const [loading, setLoading] = useState(true)
  const [plans, setPlans] = useState([])
  const [subscription, setSubscription] = useState(null)
  const [history, setHistory] = useState([])
  const [interval, setInterval] = useState('monthly') // monthly | yearly
  const [upgradingPlan, setUpgradingPlan] = useState(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedPlan, setSelectedPlan] = useState(null)
  const [paymentProvider, setPaymentProvider] = useState('duitnow_qr') // 'duitnow_qr' | 'stripe' | 'local_fpx'
  const [processingPayment, setProcessingPayment] = useState(false)
  const [successMsg, setSuccessMsg] = useState('')
  const [error, setError] = useState('')

  // QR Code payment states
  const [duitnowQrUrl, setDuitnowQrUrl] = useState('')
  const [stripeQrUrl, setStripeQrUrl] = useState('')
  const [generatingStripeQr, setGeneratingStripeQr] = useState(false)
  const [copiedRef, setCopiedRef] = useState(false)
  const [duitnowRef, setDuitnowRef] = useState('')
  const [userEnteredRef, setUserEnteredRef] = useState('')

  const [promoCodeInput, setPromoCodeInput] = useState('')
  const [appliedPromo, setAppliedPromo] = useState(null)
  const [validatingPromo, setValidatingPromo] = useState(false)
  const [promoError, setPromoError] = useState('')

  const loadData = async () => {
    setLoading(true)
    setError('')
    try {
      const [plansRes, subRes, histRes] = await Promise.all([
        api.billingPlans().catch(() => ({ plans: [] })),
        api.billingSubscription().catch(() => null),
        api.billingHistory().catch(() => ({ transactions: [] })),
      ])
      setPlans(plansRes.plans || [])
      setSubscription(subRes)
      setHistory(histRes.transactions || [])
    } catch (err) {
      setError(err.message || 'Failed to load billing details')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()

    // Handle return from Stripe Checkout
    const params = new URLSearchParams(window.location.search)
    const sessionId = params.get('session_id')
    const isSuccess = params.get('success')
    const isCanceled = params.get('canceled')

    if (sessionId && isSuccess) {
      setProcessingPayment(true)
      api.billingVerifySession(sessionId)
        .then((res) => {
          setSuccessMsg(`🎉 Payment completed successfully via Stripe! Your account is now active on ${res.subscription?.plan_name || 'your upgraded tier'}.`)
          window.history.replaceState({}, document.title, window.location.pathname)
          loadData()
        })
        .catch((err) => {
          setError(err.message || 'Failed to verify Stripe payment session')
        })
        .finally(() => setProcessingPayment(false))
    } else if (isCanceled) {
      setError('Stripe checkout was canceled. No charges were made to your account.')
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [])

  const calculateTotalDue = () => {
    if (!selectedPlan) return 0
    if (appliedPromo) return Number(appliedPromo.finalPrice) || 0
    if (selectedPlan.id === 'pay_per_scan') return Number(selectedPlan.priceMonthly) || 3.0
    return interval === 'yearly' ? Number(selectedPlan.priceYearly) || 200.0 : Number(selectedPlan.priceMonthly) || 20.0
  }

  // Generate DuitNow QR Data URL whenever plan, interval, promo, or ref changes
  useEffect(() => {
    if (!selectedPlan || !modalOpen) return
    const total = calculateTotalDue()
    const ref = duitnowRef || ('SN' + Math.random().toString(36).substring(2, 8).toUpperCase())
    if (!duitnowRef) setDuitnowRef(ref)

    // Format DuitNow QR payload (Standard Malaysian DuitNow dynamic transfer format)
    const payload = `duitnow://pay?merchant=SENTINELAI_CYBERTECH&account=162263884920&amount=${total.toFixed(2)}&currency=MYR&ref=${ref}`
    QRCode.toDataURL(payload, {
      width: 280,
      margin: 2,
      color: {
        dark: '#090d16',
        light: '#ffffff',
      },
    })
      .then((url) => setDuitnowQrUrl(url))
      .catch((e) => console.warn('QR gen error:', e))
  }, [selectedPlan, modalOpen, interval, appliedPromo, duitnowRef])

  const handleOpenCheckout = (plan) => {
    setSelectedPlan(plan)
    setPromoCodeInput('')
    setAppliedPromo(null)
    setPromoError('')
    setPaymentProvider('duitnow_qr')
    setDuitnowRef('SN' + Math.random().toString(36).substring(2, 8).toUpperCase())
    setUserEnteredRef('')
    setStripeQrUrl('')
    setCopiedRef(false)
    setModalOpen(true)
  }

  const handleCopyRef = (text) => {
    if (!navigator.clipboard) return
    navigator.clipboard.writeText(text)
    setCopiedRef(true)
    setTimeout(() => setCopiedRef(false), 2000)
  }

  const handleGenerateStripeQr = async () => {
    if (!selectedPlan) return
    setGeneratingStripeQr(true)
    setError('')
    try {
      const promoToSend = appliedPromo ? appliedPromo.code : ''
      const res = await api.billingCheckout(selectedPlan.id, interval, promoToSend, 'stripe')
      if (res.url) {
        const qr = await QRCode.toDataURL(res.url, {
          width: 260,
          margin: 2,
          color: {
            dark: '#0369a1',
            light: '#ffffff',
          },
        })
        setStripeQrUrl(qr)
      }
    } catch (e) {
      setError('Failed to generate Stripe QR: ' + e.message)
    } finally {
      setGeneratingStripeQr(false)
    }
  }

  const handleApplyPromo = async () => {
    if (!promoCodeInput.trim() || !selectedPlan) return
    setValidatingPromo(true)
    setPromoError('')
    try {
      const res = await api.billingValidatePromo(promoCodeInput.trim(), selectedPlan.id, interval)
      if (res.valid) {
        setAppliedPromo(res)
      }
    } catch (e) {
      setAppliedPromo(null)
      setPromoError(e.message || 'Invalid promo code')
    } finally {
      setValidatingPromo(false)
    }
  }

  const handleConfirmCheckout = async () => {
    if (!selectedPlan) return
    setProcessingPayment(true)
    setError('')
    setSuccessMsg('')

    try {
      const promoToSend = appliedPromo ? appliedPromo.code : ''
      const refToSend = userEnteredRef.trim() || duitnowRef
      const res = await api.billingCheckout(selectedPlan.id, interval, promoToSend, paymentProvider, refToSend)
      
      // If Stripe Checkout session URL returned, redirect directly to Stripe!
      if (res.url) {
        window.location.href = res.url
        return
      }

      setSuccessMsg(res.message || `🎉 Success! Upgraded to ${selectedPlan.name}. Your quota has been updated.`)
      setModalOpen(false)
      await loadData()
    } catch (err) {
      setError(err.message || 'Checkout failed')
    } finally {
      setProcessingPayment(false)
    }
  }

  const currentPlanId = subscription?.plan_id || 'starter'
  const isUnlimited = subscription?.isUnlimited || false
  const quotaTotal = subscription?.scan_quota_total || 5
  const quotaUsed = subscription?.scan_quota_used || 0
  const quotaPct = isUnlimited ? 100 : Math.min(100, Math.round((quotaUsed / quotaTotal) * 100))

  if (loading && !subscription) return <BillingSkeleton />

  return (
    <div className="space-y-8 animate-in fade-in duration-300 pb-16 content-fade">
      {/* Header Banner */}
      <div className="card p-6 border-white/[0.07] relative overflow-hidden bg-[#161616]">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <CreditCard size={160} className="text-cyan-400" />
        </div>

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <CreditCard size={22} />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Subscriptions & Usage Billing</h1>
              <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30 uppercase tracking-wide">
                Flexible Plans
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Scale your automated code audits, security scans, and continuous CI/CD GitHub webhooks. Upgrade or change your subscription anytime with zero lock-in.
            </p>
          </div>

          {subscription && (
            <button
              onClick={loadData}
              disabled={loading}
              className="btn-primary text-xs py-2.5 px-4 font-extrabold shadow-glow flex items-center gap-2 self-start md:self-auto hover:scale-105 transition-transform"
            >
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
              <span>Refresh Plan</span>
            </button>
          )}
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 flex items-center gap-3 text-sm animate-in fade-in">
          <AlertCircle size={18} className="shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-3 text-sm animate-in fade-in">
          <CheckCircle2 size={18} className="shrink-0 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Current Subscription Status Card */}
      {subscription && (
        <div className={`card p-6 border space-y-5 shadow-xl ${
          subscription.isSubscribed
            ? 'border-cyan-500/30 bg-gradient-to-b from-slate-900/90 to-slate-950/90 shadow-cyan-950/20'
            : 'border-amber-500/30 bg-gradient-to-b from-slate-900/90 to-amber-950/20 shadow-amber-950/10'
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-4">
            <div className="space-y-1">
              <div className="text-xs uppercase font-bold tracking-wider text-cyan-400 flex items-center gap-1.5">
                <BadgeCheck size={14} /> SentinelAI Subscription Status
              </div>
              <div className="text-2xl font-extrabold text-white flex items-center gap-2">
                {subscription.plan?.name || (subscription.isSubscribed ? subscription.plan_name : 'No Active Plan')}
                <span className={`text-xs px-2.5 py-0.5 rounded-full border font-semibold uppercase ${
                  subscription.isSubscribed
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                }`}>
                  {subscription.isSubscribed ? 'Active' : 'Subscription Required'}
                </span>
              </div>
            </div>

            {subscription.isSubscribed && subscription.current_period_end ? (
              <div className="text-xs text-slate-400 flex items-center gap-2">
                <Calendar size={14} className="text-slate-500" />
                <span>Next billing date: <strong>{new Date(subscription.current_period_end).toLocaleDateString()}</strong></span>
              </div>
            ) : subscription.plan_id === 'trial' ? (
              <div className={`text-xs px-3 py-1.5 rounded-xl flex items-center gap-1.5 ${
                subscription.remainingQuota > 0
                  ? 'text-cyan-300 bg-cyan-500/10 border border-cyan-500/20'
                  : 'text-amber-300 bg-amber-500/10 border border-amber-500/20'
              }`}>
                {subscription.remainingQuota > 0 ? (
                  <>
                    <Sparkles size={14} className="text-cyan-400" />
                    <span>Free Trial: <strong>{subscription.remainingQuota} of 3 scans</strong> remaining</span>
                  </>
                ) : (
                  <>
                    <AlertCircle size={14} className="text-amber-400" />
                    <span>Free Trial Completed (3/3 used) &mdash; Upgrade below</span>
                  </>
                )}
              </div>
            ) : (
              <div className="text-xs text-amber-300/90 bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-xl flex items-center gap-1.5">
                <AlertCircle size={14} className="text-amber-400" />
                Choose a plan below to activate code audits
              </div>
            )}
          </div>

          {/* Quota Meter */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-slate-400 font-semibold">Monthly AI Code Scan Usage</span>
              <span className="font-mono font-bold text-white">
                {isUnlimited ? 'Unlimited Access' : `${quotaUsed} / ${quotaTotal} scans (${subscription.remainingQuota} remaining)`}
              </span>
            </div>
            <div className="h-3 bg-slate-950 rounded-full border border-white/10 overflow-hidden p-0.5">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  !subscription.isSubscribed
                    ? 'bg-slate-700'
                    : quotaPct > 85 ? 'bg-red-500 shadow-red-500/50' : quotaPct > 60 ? 'bg-amber-500' : 'bg-gradient-to-r from-cyan-400 to-emerald-400'
                }`}
                style={{ width: `${subscription.isSubscribed ? quotaPct : 0}%` }}
              />
            </div>
            {!subscription.isSubscribed && (
              <p className="text-xs text-slate-400 mt-1">
                You currently do not have an active subscription. Subscribe to <strong>SentinelAI Pro</strong> or <strong>Enterprise</strong> to run automated code audits and receive PDF email reports.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Interval Switch (Monthly / Yearly) */}
      <div className="flex items-center justify-center gap-3 pt-4">
        <span className={`text-xs font-semibold ${interval === 'monthly' ? 'text-white' : 'text-slate-500'}`}>Monthly Billing</span>
        <button
          onClick={() => setInterval(interval === 'monthly' ? 'yearly' : 'monthly')}
          className="w-12 h-6 rounded-full bg-slate-900 border border-white/20 p-0.5 relative transition-colors"
        >
          <div
            className={`w-5 h-5 rounded-full bg-cyan-400 transition-transform duration-200 ${
              interval === 'yearly' ? 'translate-x-6' : 'translate-x-0'
            }`}
          />
        </button>
        <span className={`text-xs font-semibold flex items-center gap-1.5 ${interval === 'yearly' ? 'text-white' : 'text-slate-500'}`}>
          Yearly Billing
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
            Save 17%
          </span>
        </span>
      </div>

      {/* Pricing Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto">
        {plans.filter(p => p.id !== 'trial').map((plan) => {
          const isCurrent = subscription?.isSubscribed && subscription?.plan_id === plan.id
          const isPayPerScan = plan.id === 'pay_per_scan'
          const price = isPayPerScan ? plan.priceMonthly : (interval === 'yearly' ? plan.priceYearly : plan.priceMonthly)
          const periodText = isPayPerScan ? ' / scan' : (interval === 'yearly' ? ' / year' : ' / month')

          return (
            <div
              key={plan.id}
              className={`card p-7 flex flex-col justify-between relative transition-all duration-300 border ${
                plan.popular
                  ? 'border-cyan-500/50 bg-gradient-to-b from-slate-900/90 via-slate-900/80 to-cyan-950/30 shadow-2xl shadow-cyan-950/40 ring-1 ring-cyan-400/40'
                  : 'border-cyan-500/30 bg-slate-950/80 hover:border-cyan-400/50 shadow-xl'
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 text-slate-950 font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-cyan-500/30 flex items-center gap-1">
                  <Star size={10} className="fill-slate-950" /> Most Popular
                </div>
              )}
              {plan.id === 'enterprise' && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-amber-500 via-purple-500 to-pink-500 text-slate-950 font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-amber-500/30 flex items-center gap-1">
                  <Sparkles size={10} className="fill-slate-950 text-slate-950" /> VIP Red Team Advisory
                </div>
              )}
              {isPayPerScan && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-emerald-500 to-teal-500 text-slate-950 font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-emerald-500/30 flex items-center gap-1">
                  <Zap size={10} className="fill-slate-950" /> Instant Top-Up
                </div>
              )}

              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-extrabold text-white">{plan.name}</h3>
                  <div className="mt-3 flex items-baseline gap-1">
                    <span className="text-4xl font-black text-white">RM {price}</span>
                    <span className="text-xs text-slate-400 font-medium">{periodText}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    {isPayPerScan && 'Top-up single autonomous scans on demand. No recurring monthly commitment.'}
                    {plan.id === 'pro' && 'Ideal for active developers and software teams needing continuous audit automation.'}
                    {plan.id === 'enterprise' && 'Full continuous DevSecOps pipeline for organizations requiring unlimited audits & compliance.'}
                  </p>
                </div>

                <div className="h-px bg-white/10" />

                {/* Features List */}
                <div className="space-y-3">
                  <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Included Features:</div>
                  <ul className="space-y-2.5">
                    {plan.features.map((feat, idx) => (
                      <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-300">
                        <CheckCircle2 size={15} className="text-cyan-400 shrink-0 mt-0.5" />
                        <span>{feat}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Action Button */}
              <div className="pt-8">
                {isCurrent && !isPayPerScan ? (
                  <div className="w-full py-3 rounded-xl bg-white/5 border border-white/10 text-center text-xs font-bold text-slate-400 cursor-default">
                    Current Active Plan
                  </div>
                ) : (
                  <div>
                    <button
                      onClick={() => handleOpenCheckout(plan)}
                      className="btn-primary w-full py-3 rounded-xl font-extrabold text-xs flex items-center justify-center gap-2 shadow-glow hover:scale-[1.02] transition-all bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 text-slate-950 cursor-pointer"
                    >
                      <Zap size={15} className="fill-slate-950" /> {isPayPerScan ? 'Top-Up Scan (RM 3)' : `Upgrade to ${plan.name}`}
                    </button>
                    <div className="mt-2.5 text-center text-[10px] text-slate-400 flex items-center justify-center gap-2">
                      <span className="flex items-center gap-1 text-pink-400 font-bold"><QrCode size={11} /> DuitNow QR</span>
                      <span className="text-slate-600">&bull;</span>
                      <span className="flex items-center gap-1 text-cyan-400 font-semibold"><CreditCard size={11} /> Stripe Cards / Pay</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Transaction History Table */}
      <div className="card p-6 border-white/10 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText size={18} className="text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Payment & Billing History</h3>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="p-8 text-center border border-dashed border-white/10 rounded-xl space-y-1">
            <CreditCard size={28} className="text-slate-600 mx-auto" />
            <div className="text-xs text-slate-400">No payment transactions recorded yet.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-slate-500 font-semibold">
                  <th className="pb-3 px-2">Transaction ID</th>
                  <th className="pb-3 px-2">Date</th>
                  <th className="pb-3 px-2">Plan</th>
                  <th className="pb-3 px-2">Amount</th>
                  <th className="pb-3 px-2">Provider</th>
                  <th className="pb-3 px-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {history.map((tx) => (
                  <tr key={tx.id} className="hover:bg-white/5 transition-colors">
                    <td className="py-3 px-2 font-mono text-slate-300">{tx.id}</td>
                    <td className="py-3 px-2 text-slate-400">{new Date(tx.created_at).toLocaleDateString()}</td>
                    <td className="py-3 px-2 font-semibold text-white uppercase">{tx.plan_id}</td>
                    <td className="py-3 px-2 font-mono text-cyan-300">RM {Number(tx.amount).toFixed(2)}</td>
                    <td className="py-3 px-2 text-slate-400 capitalize">{tx.provider}</td>
                    <td className="py-3 px-2">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                        {tx.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Checkout Modal */}
      {modalOpen && selectedPlan && (
        <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-md z-50 grid place-items-center p-4 animate-in fade-in">
          <div className="card p-6 max-w-lg w-full max-h-[92vh] overflow-y-auto border-cyan-500/30 bg-slate-900 shadow-2xl space-y-5 animate-in zoom-in-95 custom-scrollbar">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 font-bold text-white text-base">
                <Sparkles size={18} className="text-cyan-400" />
                {selectedPlan.id === 'pay_per_scan' ? 'Top-Up Scan Credit' : `Upgrade to ${selectedPlan.name}`}
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-bold p-1"
              >
                ✕
              </button>
            </div>

            {/* Summary Box */}
            <div className="bg-slate-950 p-4 rounded-xl border border-white/10 space-y-2">
              <div className="flex justify-between text-xs text-slate-400">
                <span>Selected Plan:</span>
                <span className="font-bold text-white">{selectedPlan.name}</span>
              </div>
              {selectedPlan.id !== 'pay_per_scan' && (
                <div className="flex justify-between text-xs text-slate-400">
                  <span>Billing Interval:</span>
                  <span className="font-semibold text-cyan-300 capitalize">{interval}</span>
                </div>
              )}
              <div className="flex justify-between text-xs text-slate-400">
                <span>Scan Quota:</span>
                <span className="font-bold text-white">
                  {selectedPlan.id === 'pay_per_scan' ? '+1 Instant Scan Credit' : selectedPlan.scanQuota >= 9000 ? 'Unlimited' : `${selectedPlan.scanQuota} scans/mo`}
                </span>
              </div>
              
              {/* Promo Code Discount Line */}
              {appliedPromo && (
                <div className="flex justify-between text-xs text-emerald-400 font-semibold pt-1 border-t border-white/5">
                  <span>Promo ({appliedPromo.code}):</span>
                  <span>-RM {appliedPromo.discountAmount} ({appliedPromo.formattedDiscount})</span>
                </div>
              )}

              <div className="h-px bg-white/10 my-2" />
              <div className="flex justify-between text-sm font-bold text-white">
                <span>Total Due:</span>
                <span className="text-cyan-400 font-mono text-base">
                  RM {calculateTotalDue().toFixed(2)} MYR
                </span>
              </div>
            </div>

            {/* Promo Code Voucher Input */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-300">
                <label>Have a Promo Code?</label>
                {appliedPromo && (
                  <span className="text-[11px] text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 size={12} /> Applied
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="e.g. SENTINEL50"
                  value={promoCodeInput}
                  onChange={(e) => {
                    setPromoCodeInput(e.target.value.toUpperCase())
                    setPromoError('')
                  }}
                  className="input font-mono text-xs uppercase flex-1"
                  disabled={validatingPromo || !!appliedPromo}
                />
                {appliedPromo ? (
                  <button
                    type="button"
                    onClick={() => {
                      setAppliedPromo(null)
                      setPromoCodeInput('')
                    }}
                    className="btn-ghost text-xs text-rose-400 hover:text-rose-300 px-3"
                  >
                    Remove
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={handleApplyPromo}
                    disabled={validatingPromo || !promoCodeInput.trim()}
                    className="btn-secondary text-xs px-3.5 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10"
                  >
                    {validatingPromo ? <Loader2 size={12} className="animate-spin" /> : 'Apply'}
                  </button>
                )}
              </div>
              {promoError && (
                <p className="text-[11px] text-rose-400 font-semibold">{promoError}</p>
              )}
            </div>

            {/* Payment Method Selector Tabs */}
            <div className="space-y-2.5">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Select Payment Method</span>
                <span className="text-[10px] text-slate-400">All methods in MYR</span>
              </label>

              <div className="grid grid-cols-3 gap-2">
                {/* DuitNow QR Tab */}
                <button
                  type="button"
                  onClick={() => setPaymentProvider('duitnow_qr')}
                  className={`p-2.5 rounded-xl border text-xs font-bold flex flex-col items-center justify-center gap-1 transition-all ${
                    paymentProvider === 'duitnow_qr'
                      ? 'border-pink-500 bg-pink-500/10 text-pink-300 shadow-md shadow-pink-950/30'
                      : 'border-white/10 bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  <QrCode size={18} className={paymentProvider === 'duitnow_qr' ? 'text-pink-400' : 'text-slate-400'} />
                  <span>DuitNow QR</span>
                </button>

                {/* Stripe Live Tab */}
                <button
                  type="button"
                  onClick={() => setPaymentProvider('stripe')}
                  className={`p-2.5 rounded-xl border text-xs font-bold flex flex-col items-center justify-center gap-1 transition-all ${
                    paymentProvider === 'stripe'
                      ? 'border-cyan-400 bg-cyan-500/10 text-cyan-300 shadow-md shadow-cyan-950/30'
                      : 'border-white/10 bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  <CreditCard size={18} className={paymentProvider === 'stripe' ? 'text-cyan-400' : 'text-slate-400'} />
                  <span>Stripe / Card</span>
                </button>

                {/* FPX Banking Tab */}
                <button
                  type="button"
                  onClick={() => setPaymentProvider('local_fpx')}
                  className={`p-2.5 rounded-xl border text-xs font-bold flex flex-col items-center justify-center gap-1 transition-all ${
                    paymentProvider === 'local_fpx'
                      ? 'border-amber-400 bg-amber-500/10 text-amber-300 shadow-md shadow-amber-950/30'
                      : 'border-white/10 bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  <Building2 size={18} className={paymentProvider === 'local_fpx' ? 'text-amber-400' : 'text-slate-400'} />
                  <span>FPX Banking</span>
                </button>
              </div>
            </div>

            {/* TAB CONTENT: DuitNow QR */}
            {paymentProvider === 'duitnow_qr' && (
              <div className="rounded-2xl border border-pink-500/30 overflow-hidden bg-slate-950/90 shadow-xl space-y-4 animate-in fade-in">
                {/* DuitNow Header */}
                <div className="bg-gradient-to-r from-[#ed008c] to-[#c70075] px-4 py-2.5 text-white flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-6 h-6 rounded-md bg-white grid place-items-center">
                      <QrCode size={15} className="text-[#ed008c]" />
                    </div>
                    <div>
                      <div className="text-xs font-black tracking-wider uppercase leading-none">DuitNow QR</div>
                      <div className="text-[9px] text-pink-100 font-semibold">Malaysia National QR Standard</div>
                    </div>
                  </div>
                  <span className="text-[10px] bg-white/20 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider text-white">
                    Instant Scan
                  </span>
                </div>

                {/* QR Display Container */}
                <div className="px-5 pb-5 flex flex-col items-center justify-center space-y-3">
                  <div className="p-2.5 bg-white rounded-2xl shadow-lg border-2 border-pink-500/30 flex items-center justify-center">
                    {duitnowQrUrl ? (
                      <img
                        src={duitnowQrUrl}
                        alt="DuitNow QR Code"
                        className="w-48 h-48 sm:w-52 sm:h-52 rounded-xl object-contain"
                      />
                    ) : (
                      <div className="w-48 h-48 flex items-center justify-center">
                        <Loader2 size={32} className="animate-spin text-pink-500" />
                      </div>
                    )}
                  </div>

                  {/* Amount & Merchant info */}
                  <div className="text-center space-y-0.5">
                    <div className="text-[11px] text-slate-400 font-semibold">Amount to Pay:</div>
                    <div className="text-2xl font-black text-white font-mono tracking-tight flex items-center justify-center gap-1">
                      <span className="text-pink-400 font-sans">RM</span> {calculateTotalDue().toFixed(2)}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Merchant: <strong className="text-slate-200">SENTINELAI CYBERTECH</strong>
                    </div>
                  </div>

                  {/* Reference ID Pill with Copy Button */}
                  <div className="w-full bg-slate-900/90 border border-white/10 rounded-xl p-2.5 flex items-center justify-between text-xs">
                    <div className="space-y-0.5">
                      <div className="text-[10px] text-slate-400 uppercase font-bold tracking-wider">Payment Reference:</div>
                      <div className="font-mono font-black text-cyan-300 tracking-wider text-sm">{duitnowRef}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopyRef(duitnowRef)}
                      className="px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 text-[11px] font-bold flex items-center gap-1 transition-colors"
                    >
                      {copiedRef ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                      <span>{copiedRef ? 'Copied!' : 'Copy'}</span>
                    </button>
                  </div>

                  {/* Optional Bank Reference Input */}
                  <div className="w-full space-y-1">
                    <label className="text-[11px] font-semibold text-slate-400 flex items-center justify-between">
                      <span>Receipt / Bank Ref No. (Optional):</span>
                      <span className="text-[10px] text-slate-500">For record</span>
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 2026090812345678"
                      value={userEnteredRef}
                      onChange={(e) => setUserEnteredRef(e.target.value)}
                      className="input text-xs font-mono py-1.5 w-full bg-slate-950"
                    />
                  </div>

                  {/* Supported Banks Badges */}
                  <div className="text-center space-y-1.5 pt-1 w-full border-t border-white/5">
                    <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                      Accepted in All Malaysian Bank Apps & eWallets
                    </div>
                    <div className="flex flex-wrap items-center justify-center gap-1 text-[10px] text-slate-300">
                      {['Maybank MAE', 'TNG eWallet', 'CIMB OCTO', 'GrabPay', 'Bank Islam', 'RHB', 'Public Bank'].map(b => (
                        <span key={b} className="px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-[10px]">
                          {b}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Stripe Live */}
            {paymentProvider === 'stripe' && (
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 space-y-4 animate-in fade-in">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CreditCard size={18} className="text-cyan-400" />
                    <span className="text-xs font-bold text-white">Stripe Live Checkout</span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 font-semibold border border-cyan-500/20">
                    Visa &bull; Mastercard &bull; Apple Pay &bull; Google Pay
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Pay securely using any Malaysian or international credit/debit card, Apple Pay, or Google Pay via Stripe's encrypted payment gateway.
                </p>

                {/* Option to Scan Stripe QR on Phone */}
                <div className="pt-1 border-t border-white/5 space-y-3">
                  {!stripeQrUrl ? (
                    <button
                      type="button"
                      onClick={handleGenerateStripeQr}
                      disabled={generatingStripeQr}
                      className="btn-ghost w-full py-2 text-xs font-bold border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 flex items-center justify-center gap-2"
                    >
                      {generatingStripeQr ? <Loader2 size={13} className="animate-spin" /> : <Smartphone size={14} />}
                      <span>{generatingStripeQr ? 'Generating Mobile QR...' : 'Scan QR to Pay with Phone (Apple/Google Pay)'}</span>
                    </button>
                  ) : (
                    <div className="p-3.5 rounded-xl bg-slate-900 border border-cyan-500/30 text-center space-y-2 animate-in zoom-in-95">
                      <div className="p-2 bg-white rounded-xl inline-block shadow-md">
                        <img src={stripeQrUrl} alt="Stripe Mobile QR" className="w-36 h-36 object-contain rounded-lg" />
                      </div>
                      <div className="text-[11px] text-cyan-300 font-semibold flex items-center justify-center gap-1.5">
                        <Smartphone size={13} /> Scan with your phone camera to pay with Apple / Google Pay
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB CONTENT: FPX Online Banking */}
            {paymentProvider === 'local_fpx' && (
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 space-y-3 animate-in fade-in">
                <div className="flex items-center gap-2 text-xs font-bold text-white">
                  <Building2 size={16} className="text-amber-400" />
                  <span>FPX Malaysian Online Banking</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Direct internet banking transfer with all major retail and business Malaysian banking institutions.
                </p>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {['Maybank2u', 'CIMB Clicks', 'Bank Islam', 'RHB Now', 'Public Bank', 'Hong Leong Connect', 'AmBank'].map(b => (
                    <span key={b} className="text-[10px] px-2 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300">
                      {b}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Modal Action Buttons */}
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="btn-secondary flex-1 text-xs py-2.5"
              >
                Cancel
              </button>

              {paymentProvider === 'duitnow_qr' && (
                <button
                  type="button"
                  onClick={handleConfirmCheckout}
                  disabled={processingPayment}
                  className="btn-primary flex-1 text-xs py-2.5 shadow-glow flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-500 to-teal-600 text-slate-950 font-black hover:brightness-110"
                >
                  {processingPayment ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
                  {processingPayment ? 'Verifying...' : `I Have Paid (Sahkan RM ${calculateTotalDue().toFixed(2)})`}
                </button>
              )}

              {paymentProvider === 'stripe' && (
                <button
                  type="button"
                  onClick={handleConfirmCheckout}
                  disabled={processingPayment}
                  className="btn-primary flex-1 text-xs py-2.5 shadow-glow flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-black"
                >
                  {processingPayment ? <Loader2 size={14} className="animate-spin" /> : <ExternalLink size={14} />}
                  {processingPayment ? 'Redirecting to Stripe...' : `Pay RM ${calculateTotalDue().toFixed(2)} with Stripe`}
                </button>
              )}

              {paymentProvider === 'local_fpx' && (
                <button
                  type="button"
                  onClick={handleConfirmCheckout}
                  disabled={processingPayment}
                  className="btn-primary flex-1 text-xs py-2.5 shadow-glow flex items-center justify-center gap-2 bg-gradient-to-r from-amber-500 to-orange-500 text-slate-950 font-black"
                >
                  {processingPayment ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
                  {processingPayment ? 'Processing...' : `Proceed with FPX Banking`}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
