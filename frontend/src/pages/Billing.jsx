import React, { useState, useEffect } from 'react'
import {
  CreditCard, Sparkles, Check, Zap, Shield, ArrowRight, CheckCircle2,
  Calendar, Layers, FileText, AlertCircle, RefreshCw, Loader2, Star,
  Lock, TrendingUp, HelpCircle, BadgeCheck
} from 'lucide-react'
import { api } from '../lib/api.js'

export default function Billing() {
  const [loading, setLoading] = useState(true)
  const [plans, setPlans] = useState([])
  const [subscription, setSubscription] = useState(null)
  const [history, setHistory] = useState([])
  const [interval, setInterval] = useState('monthly') // monthly | yearly
  const [upgradingPlan, setUpgradingPlan] = useState(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedPlan, setSelectedPlan] = useState(null)
  const [paymentProvider, setPaymentProvider] = useState('stripe')
  const [processingPayment, setProcessingPayment] = useState(false)
  const [successMsg, setSuccessMsg] = useState('')
  const [error, setError] = useState('')

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
  }, [])

  const handleOpenCheckout = (plan) => {
    setSelectedPlan(plan)
    setModalOpen(true)
  }

  const handleConfirmCheckout = async () => {
    if (!selectedPlan) return
    setProcessingPayment(true)
    setError('')
    setSuccessMsg('')

    try {
      const res = await api.billingCheckout(selectedPlan.id, interval)
      setSuccessMsg(`🎉 Success! Upgraded to ${selectedPlan.name}. Your quota has been updated.`)
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

  return (
    <div className="space-y-8 animate-in fade-in duration-300 pb-16">
      {/* Header Banner */}
      <div className="card p-6 border-white/10 relative overflow-hidden bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-indigo-950/40">
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl mx-auto">
        {plans.map((plan) => {
          const isCurrent = subscription?.isSubscribed && subscription?.plan_id === plan.id
          const price = interval === 'yearly' ? plan.priceYearly : plan.priceMonthly
          const periodText = interval === 'yearly' ? '/year' : '/month'

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
                  <Sparkles size={10} className="fill-slate-950 text-slate-950" /> VIP Security Advisory Included
                </div>
              )}

              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-extrabold text-white">{plan.name}</h3>
                  <div className="mt-3 flex items-baseline gap-1">
                    <span className="text-4xl font-black text-white">${price}</span>
                    <span className="text-xs text-slate-400 font-medium">{periodText}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
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
                {isCurrent ? (
                  <div className="w-full py-3 rounded-xl bg-white/5 border border-white/10 text-center text-xs font-bold text-slate-400 cursor-default">
                    Current Active Plan
                  </div>
                ) : (
                  <button
                    onClick={() => handleOpenCheckout(plan)}
                    className="btn-primary w-full py-3 rounded-xl font-extrabold text-xs flex items-center justify-center gap-2 shadow-glow hover:scale-[1.02] transition-all bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 text-slate-950 cursor-pointer"
                  >
                    <Zap size={15} className="fill-slate-950" /> Upgrade to {plan.name}
                  </button>
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
                    <td className="py-3 px-2 font-mono text-cyan-300">${Number(tx.amount).toFixed(2)} {tx.currency}</td>
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
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 grid place-items-center p-4 animate-in fade-in">
          <div className="card p-6 max-w-md w-full border-cyan-500/30 bg-slate-900 shadow-2xl space-y-5 animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 font-bold text-white text-base">
                <Sparkles size={18} className="text-cyan-400" />
                Upgrade to {selectedPlan.name}
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-white/10 space-y-2">
              <div className="flex justify-between text-xs text-slate-400">
                <span>Selected Plan:</span>
                <span className="font-bold text-white">{selectedPlan.name}</span>
              </div>
              <div className="flex justify-between text-xs text-slate-400">
                <span>Billing Interval:</span>
                <span className="font-semibold text-cyan-300 capitalize">{interval}</span>
              </div>
              <div className="flex justify-between text-xs text-slate-400">
                <span>Scan Quota:</span>
                <span className="font-bold text-white">{selectedPlan.scanQuota >= 9000 ? 'Unlimited' : `${selectedPlan.scanQuota} scans/mo`}</span>
              </div>
              <div className="h-px bg-white/10 my-2" />
              <div className="flex justify-between text-sm font-bold text-white">
                <span>Total Due:</span>
                <span className="text-cyan-400">${interval === 'yearly' ? selectedPlan.priceYearly : selectedPlan.priceMonthly} USD</span>
              </div>
            </div>

            {/* Payment Method Selector */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300">Payment Gateway</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setPaymentProvider('stripe')}
                  className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition-colors ${
                    paymentProvider === 'stripe'
                      ? 'border-cyan-400 bg-cyan-500/10 text-cyan-300'
                      : 'border-white/10 bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  <CreditCard size={14} /> Stripe / Card
                </button>
                <button
                  type="button"
                  onClick={() => setPaymentProvider('local_fpx')}
                  className={`p-3 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition-colors ${
                    paymentProvider === 'local_fpx'
                      ? 'border-cyan-400 bg-cyan-500/10 text-cyan-300'
                      : 'border-white/10 bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  <Zap size={14} /> FPX / Instant
                </button>
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="btn-secondary flex-1 text-xs py-2.5"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmCheckout}
                disabled={processingPayment}
                className="btn-primary flex-1 text-xs py-2.5 shadow-glow flex items-center justify-center gap-2"
              >
                {processingPayment ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
                {processingPayment ? 'Processing...' : 'Confirm & Upgrade'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
