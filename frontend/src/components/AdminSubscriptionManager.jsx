import React, { useState, useEffect } from 'react'
import {
  Tag, Percent, Plus, Trash2, Edit3, Check, X, ShieldCheck, Zap, Layers,
  Sparkles, RefreshCw, AlertCircle, Copy, CheckCircle2, Lock, Unlock,
  Users, DollarSign, Calendar, Sliders, ArrowRight, Star, Loader2, Award,
  HelpCircle, Eye, EyeOff
} from 'lucide-react'
import { api } from '../lib/api.js'

export default function AdminSubscriptionManager() {
  const [activeTab, setActiveTab] = useState('plans') // 'plans' | 'promos' | 'overrides'
  const [plans, setPlans] = useState([])
  const [promos, setPromos] = useState([])
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [actionBusy, setActionBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  // Plan Modals State
  const [planModalOpen, setPlanModalOpen] = useState(false)
  const [editingPlan, setEditingPlan] = useState(null)
  const [planForm, setPlanForm] = useState({
    id: '',
    name: '',
    description: '',
    priceMonthly: 0,
    priceYearly: 0,
    currency: 'MYR',
    scanQuota: 10,
    maxRepos: 1,
    features: ['DAST + SAST Scanning', 'Multi-LLM Consensus', 'PDF Executive Report'],
    isPopular: false,
    isOpen: true,
    isCustom: false,
    badge: '',
    sortOrder: 1,
  })
  const [featureInput, setFeatureInput] = useState('')

  // Promo Code Modal State
  const [promoModalOpen, setPromoModalOpen] = useState(false)
  const [editingPromo, setEditingPromo] = useState(null)
  const [promoForm, setPromoForm] = useState({
    code: '',
    discountType: 'percentage', // 'percentage' | 'fixed'
    discountValue: 20,
    applicablePlans: 'all',
    maxUses: 0,
    minPurchaseAmount: 0,
    expiresAt: '',
    isActive: true,
    note: '',
  })
  const [copiedCode, setCopiedCode] = useState('')

  // Custom User Override State
  const [selectedUser, setSelectedUser] = useState('')
  const [overrideForm, setOverrideForm] = useState({
    planId: 'pro',
    planName: 'SentinelAI Pro',
    quotaTotal: 50,
    status: 'active',
    discountPercent: 0,
    customNotes: '',
    extendDays: 30,
  })

  // Load all initial admin data
  const loadAll = async () => {
    setLoading(true)
    setErr('')
    try {
      const [plansRes, promosRes, clientsRes] = await Promise.all([
        api.adminPlans().catch(() => ({ plans: [] })),
        api.adminPromoCodes().catch(() => ({ promoCodes: [] })),
        api.adminClients().catch(() => []),
      ])
      setPlans(plansRes.plans || [])
      setPromos(promosRes.promoCodes || [])
      setClients(Array.isArray(clientsRes) ? clientsRes : [])
      if (clientsRes?.length > 0 && !selectedUser) {
        setSelectedUser(clientsRes[0].id)
      }
    } catch (e) {
      setErr(e.message || 'Failed to load subscription data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAll()
  }, [])

  const notifySuccess = (text) => {
    setMsg(text)
    setTimeout(() => setMsg(''), 4000)
  }

  // ── Plan Handlers ──────────────────────────────────────────────────────────

  const openCreatePlan = () => {
    setEditingPlan(null)
    setPlanForm({
      id: '',
      name: '',
      description: '',
      priceMonthly: 20,
      priceYearly: 200,
      currency: 'MYR',
      scanQuota: 25,
      maxRepos: 3,
      features: ['25 Autonomous AI Scans', '5 Linked Repositories', 'Real-time Webhook Alerts', 'PDF Report Exports'],
      isPopular: false,
      isOpen: true,
      isCustom: false,
      badge: 'Custom Choice',
      sortOrder: (plans.length + 1) * 10,
    })
    setFeatureInput('')
    setPlanModalOpen(true)
  }

  const openEditPlan = (plan) => {
    setEditingPlan(plan)
    setPlanForm({
      id: plan.id,
      name: plan.name,
      description: plan.description || '',
      priceMonthly: plan.priceMonthly,
      priceYearly: plan.priceYearly,
      currency: plan.currency || 'MYR',
      scanQuota: plan.scanQuota,
      maxRepos: plan.maxRepos || 1,
      features: Array.isArray(plan.features) ? [...plan.features] : [],
      isPopular: Boolean(plan.popular),
      isOpen: Boolean(plan.isOpen),
      isCustom: Boolean(plan.isCustom),
      badge: plan.badge || '',
      sortOrder: plan.sortOrder || 0,
    })
    setFeatureInput('')
    setPlanModalOpen(true)
  }

  const handleAddFeature = () => {
    if (!featureInput.trim()) return
    setPlanForm({
      ...planForm,
      features: [...planForm.features, featureInput.trim()],
    })
    setFeatureInput('')
  }

  const handleRemoveFeature = (idx) => {
    setPlanForm({
      ...planForm,
      features: planForm.features.filter((_, i) => i !== idx),
    })
  }

  const handleSavePlan = async (e) => {
    e.preventDefault()
    if (!planForm.name.trim()) return
    setActionBusy(true)
    setErr('')
    try {
      if (editingPlan) {
        await api.adminUpdatePlan(editingPlan.id, planForm)
        notifySuccess(`Plan "${planForm.name}" updated successfully!`)
      } else {
        await api.adminCreatePlan(planForm)
        notifySuccess(`New plan "${planForm.name}" created successfully!`)
      }
      setPlanModalOpen(false)
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to save plan')
    } finally {
      setActionBusy(false)
    }
  }

  const handleTogglePlan = async (plan) => {
    setActionBusy(true)
    setErr('')
    try {
      const nextStatus = !plan.isOpen
      await api.adminTogglePlanStatus(plan.id, nextStatus)
      notifySuccess(`Plan "${plan.name}" is now ${nextStatus ? 'OPEN (Public)' : 'CLOSED (Hidden)'}!`)
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to toggle plan status')
    } finally {
      setActionBusy(false)
    }
  }

  const handleDeletePlan = async (plan) => {
    if (!window.confirm(`Are you sure you want to delete plan "${plan.name}" (${plan.id})?`)) return
    setActionBusy(true)
    setErr('')
    try {
      await api.adminDeletePlan(plan.id)
      notifySuccess(`Plan "${plan.name}" deleted successfully.`)
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to delete plan')
    } finally {
      setActionBusy(false)
    }
  }

  // ── Promo Code Handlers ───────────────────────────────────────────────────

  const generateRandomPromo = () => {
    const prefixes = ['SENTINEL', 'CYBER', 'SECURITY', 'VIP', 'LAUNCH', 'AI']
    const p = prefixes[Math.floor(Math.random() * prefixes.length)]
    const num = Math.floor(1000 + Math.random() * 9000)
    setPromoForm(prev => ({ ...prev, code: `${p}-${num}` }))
  }

  const openCreatePromo = () => {
    setEditingPromo(null)
    setPromoForm({
      code: `SAVE${Math.floor(20 + Math.random() * 40)}`,
      discountType: 'percentage',
      discountValue: 25,
      applicablePlans: 'all',
      maxUses: 50,
      minPurchaseAmount: 0,
      expiresAt: '',
      isActive: true,
      note: 'Promotional discount campaign',
    })
    setPromoModalOpen(true)
  }

  const openEditPromo = (promo) => {
    setEditingPromo(promo)
    setPromoForm({
      code: promo.code,
      discountType: promo.discountType || 'percentage',
      discountValue: promo.discountValue,
      applicablePlans: promo.applicablePlans || 'all',
      maxUses: promo.maxUses || 0,
      minPurchaseAmount: promo.minPurchaseAmount || 0,
      expiresAt: promo.expiresAt ? promo.expiresAt.slice(0, 10) : '',
      isActive: Boolean(promo.isActive),
      note: promo.note || '',
    })
    setPromoModalOpen(true)
  }

  const handleSavePromo = async (e) => {
    e.preventDefault()
    if (!promoForm.code.trim()) return
    setActionBusy(true)
    setErr('')
    try {
      if (editingPromo) {
        await api.adminUpdatePromoCode(editingPromo.id, promoForm)
        notifySuccess(`Promo code "${promoForm.code}" updated successfully!`)
      } else {
        await api.adminCreatePromoCode(promoForm)
        notifySuccess(`New promo code "${promoForm.code}" created successfully!`)
      }
      setPromoModalOpen(false)
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to save promo code')
    } finally {
      setActionBusy(false)
    }
  }

  const handleTogglePromo = async (promo) => {
    setActionBusy(true)
    setErr('')
    try {
      const nextStatus = !promo.isActive
      await api.adminTogglePromoCode(promo.id, nextStatus)
      notifySuccess(`Promo code "${promo.code}" is now ${nextStatus ? 'ACTIVE' : 'INACTIVE'}!`)
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to toggle promo code')
    } finally {
      setActionBusy(false)
    }
  }

  const handleDeletePromo = async (promo) => {
    if (!window.confirm(`Are you sure you want to delete promo code "${promo.code}"?`)) return
    setActionBusy(true)
    setErr('')
    try {
      await api.adminDeletePromoCode(promo.id)
      notifySuccess(`Promo code "${promo.code}" deleted.`)
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to delete promo code')
    } finally {
      setActionBusy(false)
    }
  }

  const handleCopyCode = (code) => {
    navigator.clipboard.writeText(code)
    setCopiedCode(code)
    setTimeout(() => setCopiedCode(''), 2000)
  }

  // ── Custom Client Override Handler ────────────────────────────────────────

  const handleApplyOverride = async (e) => {
    e.preventDefault()
    if (!selectedUser) return
    setActionBusy(true)
    setErr('')
    try {
      const targetPlan = plans.find(p => p.id === overrideForm.planId)
      await api.adminCustomSubscriptionOverride({
        userId: selectedUser,
        planId: overrideForm.planId,
        planName: targetPlan ? targetPlan.name : overrideForm.planName,
        quotaTotal: Number(overrideForm.quotaTotal),
        status: overrideForm.status,
        discountPercent: Number(overrideForm.discountPercent),
        customNotes: overrideForm.customNotes,
        extendDays: Number(overrideForm.extendDays),
      })
      notifySuccess('Custom subscription override applied successfully to client account!')
      await loadAll()
    } catch (e2) {
      setErr(e2.message || 'Failed to apply custom override')
    } finally {
      setActionBusy(false)
    }
  }

  // Stats calculation
  const totalPlans = plans.length
  const openPlansCount = plans.filter(p => p.isOpen).length
  const closedPlansCount = plans.filter(p => !p.isOpen).length
  const activePromosCount = promos.filter(p => p.isActive).length

  return (
    <div className="space-y-6">
      {/* Top Banner & Tab Controls */}
      <div className="card p-6 border-cyan-500/30 bg-gradient-to-r from-slate-900/90 via-slate-900/80 to-indigo-950/40 shadow-2xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/20 border border-cyan-400/40 text-cyan-300">
                <Tag size={22} />
              </div>
              <h2 className="text-xl font-extrabold text-white tracking-tight">
                Subscription & Pricing Control Center
              </h2>
              <span className="text-[10px] uppercase font-bold px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
                Super Admin
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl">
              Create, edit, open/close subscription tiers, generate dynamic promo codes & vouchers, and grant bespoke custom quotas or client discounts.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={openCreatePlan}
              className="btn-primary text-xs flex items-center gap-1.5 py-2 px-3.5 shadow-glow"
            >
              <Plus size={15} /> Create Plan
            </button>
            <button
              type="button"
              onClick={openCreatePromo}
              className="btn-secondary text-xs flex items-center gap-1.5 py-2 px-3.5 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10"
            >
              <Tag size={15} /> New Promo Code
            </button>
            <button
              type="button"
              onClick={loadAll}
              disabled={loading || actionBusy}
              className="btn-ghost p-2 text-slate-400 hover:text-white"
              title="Refresh Data"
            >
              <RefreshCw size={16} className={loading ? 'animate-spin text-cyan-400' : ''} />
            </button>
          </div>
        </div>

        {/* Quick Stats Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-5">
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/10 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-400 uppercase font-semibold">Total Plans</span>
              <div className="text-xl font-mono font-bold text-white mt-0.5">{totalPlans}</div>
            </div>
            <Layers size={20} className="text-cyan-400 opacity-60" />
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-emerald-500/20 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-emerald-400 uppercase font-semibold">Open for Signups</span>
              <div className="text-xl font-mono font-bold text-emerald-300 mt-0.5">{openPlansCount}</div>
            </div>
            <Unlock size={20} className="text-emerald-400 opacity-60" />
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-700/50 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-slate-400 uppercase font-semibold">Closed / Hidden</span>
              <div className="text-xl font-mono font-bold text-slate-300 mt-0.5">{closedPlansCount}</div>
            </div>
            <Lock size={20} className="text-slate-400 opacity-60" />
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-purple-500/20 flex items-center justify-between">
            <div>
              <span className="text-[11px] text-purple-300 uppercase font-semibold">Active Promos</span>
              <div className="text-xl font-mono font-bold text-purple-300 mt-0.5">{activePromosCount}</div>
            </div>
            <Percent size={20} className="text-purple-400 opacity-60" />
          </div>
        </div>

        {/* Tab Pills */}
        <div className="flex items-center gap-2 pt-5 border-t border-white/10 mt-5">
          <button
            type="button"
            onClick={() => setActiveTab('plans')}
            className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
              activeTab === 'plans'
                ? 'bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(0,242,254,0.35)] font-extrabold'
                : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
            }`}
          >
            <Layers size={14} /> Subscription Tiers ({plans.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('promos')}
            className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
              activeTab === 'promos'
                ? 'bg-emerald-400 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.35)] font-extrabold'
                : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
            }`}
          >
            <Tag size={14} /> Promo Codes & Discounts ({promos.length})
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('overrides')}
            className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
              activeTab === 'overrides'
                ? 'bg-indigo-400 text-slate-950 shadow-[0_0_15px_rgba(129,140,248,0.35)] font-extrabold'
                : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
            }`}
          >
            <Sliders size={14} /> Bespoke Client Overrides
          </button>
        </div>
      </div>

      {/* Notifications */}
      {msg && (
        <div className="p-4 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
          <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
          <span>{msg}</span>
        </div>
      )}
      {err && (
        <div className="p-4 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
          <AlertCircle size={16} className="text-rose-400 shrink-0" />
          <span>{err}</span>
        </div>
      )}

      {/* ── TAB 1: SUBSCRIPTION PLANS ────────────────────────────────────────── */}
      {activeTab === 'plans' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers size={16} className="text-cyan-400" /> Configured Subscription Tiers
            </h3>
            <span className="text-xs text-slate-400">
              Open plans appear on the client <code className="text-cyan-300">/app/billing</code> and <code className="text-cyan-300">/pricing</code> pages.
            </span>
          </div>

          {loading ? (
            <div className="p-12 text-center text-slate-400 space-y-3">
              <Loader2 size={32} className="animate-spin text-cyan-400 mx-auto" />
              <p className="text-xs">Loading subscription tiers...</p>
            </div>
          ) : plans.length === 0 ? (
            <div className="card p-12 text-center space-y-4 border-dashed border-white/20">
              <Layers size={36} className="text-slate-500 mx-auto" />
              <div>
                <h4 className="text-base font-bold text-white">No Subscription Plans Found</h4>
                <p className="text-xs text-slate-400 mt-1">Create your first public or bespoke tier to get started.</p>
              </div>
              <button type="button" onClick={openCreatePlan} className="btn-primary text-xs mx-auto">
                <Plus size={14} /> Create Plan
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {plans.map((plan) => {
                const isUnlimited = plan.scanQuota >= 9000
                return (
                  <div
                    key={plan.id}
                    className={`card p-6 flex flex-col justify-between relative transition-all duration-300 border ${
                      plan.popular
                        ? 'border-cyan-400/50 bg-slate-900/90 shadow-xl shadow-cyan-950/40 ring-1 ring-cyan-400/30'
                        : plan.isOpen
                        ? 'border-white/10 bg-slate-950/70 hover:border-cyan-500/30'
                        : 'border-slate-800 bg-slate-950/40 opacity-75'
                    }`}
                  >
                    {/* Top Badges */}
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {plan.isOpen ? (
                          <span className="text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                            <Unlock size={10} /> Open
                          </span>
                        ) : (
                          <span className="text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-white/10 flex items-center gap-1">
                            <Lock size={10} /> Closed
                          </span>
                        )}

                        {plan.popular && (
                          <span className="text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 flex items-center gap-1">
                            <Star size={10} className="fill-cyan-300" /> Popular
                          </span>
                        )}

                        {plan.isCustom && (
                          <span className="text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-400/40 flex items-center gap-1">
                            <Sparkles size={10} /> Custom
                          </span>
                        )}
                      </div>

                      {plan.badge && (
                        <span className="text-[10px] font-bold text-slate-400 font-mono">
                          [{plan.badge}]
                        </span>
                      )}
                    </div>

                    {/* Plan Title & Price */}
                    <div className="space-y-2">
                      <div>
                        <h4 className="text-lg font-bold text-white flex items-center gap-2">
                          {plan.name}
                        </h4>
                        <span className="text-[11px] font-mono text-cyan-400/80">ID: {plan.id}</span>
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-2 min-h-[32px]">
                        {plan.description || 'Full access autonomous security pentesting capabilities.'}
                      </p>

                      <div className="pt-2 pb-1">
                        <div className="flex items-baseline gap-1.5">
                          <span className="text-2xl font-extrabold font-mono text-white">
                            {plan.currency || 'RM'} {plan.priceMonthly}
                          </span>
                          <span className="text-xs text-slate-400">{plan.id === 'pay_per_scan' ? '/scan' : '/mo'}</span>
                          <span className="text-xs font-mono text-slate-500 ml-2">
                            ({plan.currency || 'RM'} {plan.priceYearly}/yr)
                          </span>
                        </div>
                      </div>

                      {/* Quota Highlights */}
                      <div className="grid grid-cols-2 gap-2 pt-2 text-xs font-semibold">
                        <div className="p-2 rounded-lg bg-white/5 border border-white/10">
                          <span className="text-[10px] text-slate-400 block font-normal">Audit Quota</span>
                          <span className="text-cyan-300 font-mono font-bold">
                            {isUnlimited ? 'Unlimited' : `${plan.scanQuota} scans/mo`}
                          </span>
                        </div>
                        <div className="p-2 rounded-lg bg-white/5 border border-white/10">
                          <span className="text-[10px] text-slate-400 block font-normal">GitHub Repos</span>
                          <span className="text-slate-200 font-mono font-bold">
                            {plan.maxRepos >= 900 ? 'Unlimited' : `${plan.maxRepos} Repos`}
                          </span>
                        </div>
                      </div>

                      {/* Features List */}
                      <div className="pt-3 space-y-1.5">
                        <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Features Included</span>
                        <ul className="space-y-1 text-xs text-slate-300">
                          {(plan.features || []).slice(0, 4).map((feat, idx) => (
                            <li key={idx} className="flex items-start gap-1.5">
                              <Check size={14} className="text-emerald-400 shrink-0 mt-0.5" />
                              <span className="line-clamp-1">{feat}</span>
                            </li>
                          ))}
                          {(plan.features || []).length > 4 && (
                            <li className="text-[11px] text-cyan-400/80 italic font-mono pl-5">
                              + {(plan.features || []).length - 4} more capability perks
                            </li>
                          )}
                        </ul>
                      </div>
                    </div>

                    {/* Card Actions */}
                    <div className="flex items-center gap-2 pt-5 border-t border-white/10 mt-5">
                      <button
                        type="button"
                        onClick={() => handleTogglePlan(plan)}
                        disabled={actionBusy}
                        className={`btn-ghost text-xs flex-1 py-1.5 px-2 flex items-center justify-center gap-1.5 ${
                          plan.isOpen ? 'text-amber-300 hover:text-amber-200' : 'text-emerald-300 hover:text-emerald-200'
                        }`}
                        title={plan.isOpen ? 'Close Plan from Public Signups' : 'Open Plan for Public Signups'}
                      >
                        {plan.isOpen ? <EyeOff size={13} /> : <Eye size={13} />}
                        <span>{plan.isOpen ? 'Close' : 'Open'}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => openEditPlan(plan)}
                        disabled={actionBusy}
                        className="btn-ghost text-xs flex-1 py-1.5 px-2 flex items-center justify-center gap-1.5 text-cyan-300 hover:text-cyan-200"
                      >
                        <Edit3 size={13} />
                        <span>Edit</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleDeletePlan(plan)}
                        disabled={actionBusy}
                        className="btn-ghost text-xs py-1.5 px-2.5 text-rose-400 hover:text-rose-300"
                        title="Delete Plan"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: PROMO CODES & DISCOUNTS ──────────────────────────────────── */}
      {activeTab === 'promos' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Tag size={16} className="text-emerald-400" /> Active Promo Codes & Discounts
            </h3>
            <button
              type="button"
              onClick={openCreatePromo}
              className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-3"
            >
              <Plus size={14} /> Create Promo Code
            </button>
          </div>

          {loading ? (
            <div className="p-12 text-center text-slate-400">
              <Loader2 size={28} className="animate-spin text-emerald-400 mx-auto" />
            </div>
          ) : promos.length === 0 ? (
            <div className="card p-12 text-center space-y-4 border-dashed border-white/20">
              <Percent size={36} className="text-slate-500 mx-auto" />
              <div>
                <h4 className="text-base font-bold text-white">No Promo Codes Active</h4>
                <p className="text-xs text-slate-400 mt-1">Create promotional campaign discounts and discount vouchers.</p>
              </div>
              <button type="button" onClick={openCreatePromo} className="btn-primary text-xs mx-auto">
                <Plus size={14} /> Create Promo Code
              </button>
            </div>
          ) : (
            <div className="card border-white/10 overflow-hidden bg-slate-950/70">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-white/5 border-b border-white/10 text-slate-400 uppercase text-[10px] tracking-wider font-semibold">
                    <tr>
                      <th className="p-3.5">Promo Code</th>
                      <th className="p-3.5">Discount</th>
                      <th className="p-3.5">Applicable Tiers</th>
                      <th className="p-3.5">Redemptions</th>
                      <th className="p-3.5">Expiration</th>
                      <th className="p-3.5">Status</th>
                      <th className="p-3.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-slate-300 font-normal">
                    {promos.map((promo) => {
                      const isExpired = promo.expiresAt && new Date(promo.expiresAt) < new Date()
                      const isCapReached = promo.maxUses > 0 && promo.usedCount >= promo.maxUses

                      return (
                        <tr key={promo.id} className="hover:bg-white/5 transition-colors">
                          {/* Code + Copy */}
                          <td className="p-3.5">
                            <div className="flex items-center gap-2">
                              <code className="bg-emerald-950/50 text-emerald-300 font-mono font-bold px-2 py-1 rounded border border-emerald-500/30 text-xs">
                                {promo.code}
                              </code>
                              <button
                                type="button"
                                onClick={() => handleCopyCode(promo.code)}
                                className="text-slate-400 hover:text-white p-1"
                                title="Copy code"
                              >
                                {copiedCode === promo.code ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                              </button>
                            </div>
                            {promo.note && <div className="text-[11px] text-slate-400 mt-0.5 italic">{promo.note}</div>}
                          </td>

                          {/* Discount Value */}
                          <td className="p-3.5 font-bold font-mono text-white text-sm">
                            {promo.discountType === 'percentage' ? (
                              <span className="text-emerald-400">{promo.discountValue}% OFF</span>
                            ) : (
                              <span className="text-cyan-400">${promo.discountValue} OFF</span>
                            )}
                          </td>

                          {/* Applicable Plans */}
                          <td className="p-3.5 capitalize text-slate-300">
                            {promo.applicablePlans === 'all' ? (
                              <span className="px-2 py-0.5 rounded bg-white/10 text-[11px] font-semibold text-slate-200">
                                All Plans
                              </span>
                            ) : (
                              <span className="font-mono text-[11px] text-cyan-300">{promo.applicablePlans}</span>
                            )}
                          </td>

                          {/* Redemptions */}
                          <td className="p-3.5 font-mono">
                            <span className={isCapReached ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                              {promo.usedCount}
                            </span>
                            <span className="text-slate-500"> / {promo.maxUses === 0 ? '∞' : promo.maxUses}</span>
                          </td>

                          {/* Expiration */}
                          <td className="p-3.5">
                            {promo.expiresAt ? (
                              <span className={isExpired ? 'text-rose-400 font-semibold' : 'text-slate-300'}>
                                {new Date(promo.expiresAt).toLocaleDateString()}
                              </span>
                            ) : (
                              <span className="text-slate-500 italic">Never</span>
                            )}
                          </td>

                          {/* Status */}
                          <td className="p-3.5">
                            {isExpired ? (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">
                                Expired
                              </span>
                            ) : isCapReached ? (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30">
                                Max Used
                              </span>
                            ) : promo.isActive ? (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                                Active
                              </span>
                            ) : (
                              <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-white/10">
                                Inactive
                              </span>
                            )}
                          </td>

                          {/* Actions */}
                          <td className="p-3.5 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={() => handleTogglePromo(promo)}
                                disabled={actionBusy}
                                className="btn-ghost text-xs p-1.5 text-slate-300 hover:text-white"
                                title={promo.isActive ? 'Deactivate promo' : 'Activate promo'}
                              >
                                {promo.isActive ? <EyeOff size={14} className="text-amber-400" /> : <Eye size={14} className="text-emerald-400" />}
                              </button>
                              <button
                                type="button"
                                onClick={() => openEditPromo(promo)}
                                disabled={actionBusy}
                                className="btn-ghost text-xs p-1.5 text-cyan-300 hover:text-cyan-200"
                                title="Edit promo"
                              >
                                <Edit3 size={14} />
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDeletePromo(promo)}
                                disabled={actionBusy}
                                className="btn-ghost text-xs p-1.5 text-rose-400 hover:text-rose-300"
                                title="Delete promo"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 3: BESPOKE CLIENT OVERRIDES ─────────────────────────────────── */}
      {activeTab === 'overrides' && (
        <form onSubmit={handleApplyOverride} className="card p-6 space-y-6 border-indigo-500/30 bg-slate-900/60 shadow-2xl">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Sliders size={18} className="text-indigo-400" /> Grant Bespoke Custom Tier / User Quota Overrides
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Directly assign custom plans, custom scan credits, lifetime discounts, or manual expiration dates to specific clients or users.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* User Selector */}
            <div>
              <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Target Account / Client</label>
              <select
                value={selectedUser}
                onChange={(e) => {
                  const uid = e.target.value
                  setSelectedUser(uid)
                  const targetClient = clients.find(c => c.id === uid)
                  if (targetClient) {
                    setOverrideForm({
                      planId: targetClient.plan_id || 'pro',
                      planName: targetClient.plan_name || 'SentinelAI Pro',
                      quotaTotal: targetClient.scan_quota_total || 50,
                      status: targetClient.sub_status || 'active',
                      discountPercent: targetClient.discount_percent || 0,
                      customNotes: targetClient.custom_notes || '',
                      extendDays: 30,
                    })
                  }
                }}
                className="input text-xs w-full"
                required
              >
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.username} ({c.email || 'No email'}) &mdash; Current Plan: {c.plan_name || c.plan_id || 'Free Trial'}
                  </option>
                ))}
              </select>
            </div>

            {/* Plan Tier Assignment */}
            <div>
              <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Assign Plan Tier</label>
              <select
                value={overrideForm.planId}
                onChange={(e) => {
                  const pId = e.target.value
                  const found = plans.find(p => p.id === pId)
                  setOverrideForm({
                    ...overrideForm,
                    planId: pId,
                    planName: found ? found.name : pId,
                    quotaTotal: found ? found.scanQuota : overrideForm.quotaTotal,
                  })
                }}
                className="input text-xs w-full"
              >
                {plans.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.scanQuota >= 9000 ? 'Unlimited' : `${p.scanQuota} scans`}) &mdash; ${p.priceMonthly}/mo
                  </option>
                ))}
              </select>
            </div>

            {/* Scan Quota Override */}
            <div>
              <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Total Scan Quota Credits</label>
              <input
                type="number"
                min="0"
                max="99999"
                value={overrideForm.quotaTotal}
                onChange={(e) => setOverrideForm({ ...overrideForm, quotaTotal: e.target.value })}
                className="input text-xs font-mono font-bold"
                placeholder="e.g. 50, 500, 9999"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">Set 9999 for unlimited autonomous scans</span>
            </div>

            {/* Custom Lifetime Discount */}
            <div>
              <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Client Lifetime Discount (%)</label>
              <input
                type="number"
                min="0"
                max="100"
                value={overrideForm.discountPercent}
                onChange={(e) => setOverrideForm({ ...overrideForm, discountPercent: e.target.value })}
                className="input text-xs font-mono font-bold"
                placeholder="e.g. 20 (for 20% off)"
              />
            </div>

            {/* Subscription Validity Days */}
            <div>
              <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Validity Extension (Days from now)</label>
              <input
                type="number"
                min="1"
                max="3650"
                value={overrideForm.extendDays}
                onChange={(e) => setOverrideForm({ ...overrideForm, extendDays: e.target.value })}
                className="input text-xs font-mono"
                placeholder="e.g. 30, 90, 365"
              />
            </div>

            {/* Status Toggle */}
            <div>
              <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Subscription Status</label>
              <select
                value={overrideForm.status}
                onChange={(e) => setOverrideForm({ ...overrideForm, status: e.target.value })}
                className="input text-xs w-full font-semibold"
              >
                <option value="active">🟢 Active</option>
                <option value="inactive">⚪ Inactive / Suspended</option>
                <option value="expired">🔴 Expired</option>
              </select>
            </div>
          </div>

          {/* Admin Notes */}
          <div>
            <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Internal Admin Notes / Client Agreement</label>
            <input
              type="text"
              value={overrideForm.customNotes}
              onChange={(e) => setOverrideForm({ ...overrideForm, customNotes: e.target.value })}
              placeholder="e.g. Sponsored enterprise tier for Fintech partnership Q3 2026"
              className="input text-xs w-full"
            />
          </div>

          <div className="flex justify-end pt-3 border-t border-white/10">
            <button
              type="submit"
              disabled={actionBusy || !selectedUser}
              className="btn-concept-12 btn-concept-12--indigo"
            >
              <span className="btn-concept-12__text">
                {actionBusy ? 'Applying...' : 'Apply Subscription Override'}
              </span>
              <span className="btn-concept-12__icon">
                {actionBusy ? <Loader2 size={16} className="animate-spin" /> : <Check size={16} />}
              </span>
            </button>
          </div>
        </form>
      )}

      {/* ── MODAL: CREATE / EDIT SUBSCRIPTION PLAN ──────────────────────────── */}
      {planModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 grid place-items-center p-4 animate-in fade-in overflow-y-auto">
          <div className="card p-6 max-w-xl w-full border-cyan-500/40 bg-slate-900 shadow-2xl space-y-5 animate-in zoom-in-95 my-8">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 font-bold text-white text-base">
                <Layers size={18} className="text-cyan-400" />
                {editingPlan ? `Edit Plan: ${editingPlan.name}` : 'Create New Subscription Tier'}
              </div>
              <button
                onClick={() => setPlanModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSavePlan} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Plan ID (Slug)</label>
                  <input
                    type="text"
                    value={planForm.id}
                    onChange={(e) => setPlanForm({ ...planForm, id: e.target.value })}
                    disabled={!!editingPlan}
                    placeholder="e.g. pro-plus, enterprise-vip"
                    className="input text-xs font-mono"
                    required
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Plan Display Name</label>
                  <input
                    type="text"
                    value={planForm.name}
                    onChange={(e) => setPlanForm({ ...planForm, name: e.target.value })}
                    placeholder="e.g. SentinelAI Pro Plus"
                    className="input text-xs font-bold"
                    required
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Monthly Price (RM MYR)</label>
                  <input
                    type="number"
                    min="0"
                    step="0.01"
                    value={planForm.priceMonthly}
                    onChange={(e) => setPlanForm({ ...planForm, priceMonthly: e.target.value })}
                    className="input text-xs font-mono font-bold"
                    required
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Yearly Price (RM MYR)</label>
                  <input
                    type="number"
                    min="0"
                    step="0.01"
                    value={planForm.priceYearly}
                    onChange={(e) => setPlanForm({ ...planForm, priceYearly: e.target.value })}
                    className="input text-xs font-mono font-bold"
                    required
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Monthly Scan Quota</label>
                  <input
                    type="number"
                    min="0"
                    max="99999"
                    value={planForm.scanQuota}
                    onChange={(e) => setPlanForm({ ...planForm, scanQuota: e.target.value })}
                    className="input text-xs font-mono font-bold"
                    placeholder="Set 9999 for unlimited"
                    required
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Max Linked Repos</label>
                  <input
                    type="number"
                    min="1"
                    max="9999"
                    value={planForm.maxRepos}
                    onChange={(e) => setPlanForm({ ...planForm, maxRepos: e.target.value })}
                    className="input text-xs font-mono font-bold"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Description</label>
                <textarea
                  rows={2}
                  value={planForm.description}
                  onChange={(e) => setPlanForm({ ...planForm, description: e.target.value })}
                  placeholder="Short description of this tier..."
                  className="input text-xs w-full resize-none font-normal"
                />
              </div>

              {/* Feature Bullets Editor */}
              <div className="space-y-2">
                <label className="text-[10px] text-slate-400 uppercase font-bold block">Features & Capabilities</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={featureInput}
                    onChange={(e) => setFeatureInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddFeature() } }}
                    placeholder="Type feature (e.g. 24/7 Slack Alert Channel) & click Add"
                    className="input text-xs flex-1"
                  />
                  <button
                    type="button"
                    onClick={handleAddFeature}
                    className="btn-secondary text-xs px-3"
                  >
                    Add
                  </button>
                </div>

                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-1">
                  {planForm.features.map((feat, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-[11px] text-slate-200 flex items-center gap-1.5"
                    >
                      <Check size={11} className="text-emerald-400" />
                      <span>{feat}</span>
                      <button
                        type="button"
                        onClick={() => handleRemoveFeature(idx)}
                        className="text-slate-400 hover:text-rose-400 ml-1"
                      >
                        ✕
                      </button>
                    </span>
                  ))}
                </div>
              </div>

              {/* Toggles */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer p-2.5 rounded-xl bg-white/5 border border-white/10">
                  <input
                    type="checkbox"
                    checked={planForm.isOpen}
                    onChange={(e) => setPlanForm({ ...planForm, isOpen: e.target.checked })}
                    className="checkbox"
                  />
                  <span>Open for Signups</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer p-2.5 rounded-xl bg-white/5 border border-white/10">
                  <input
                    type="checkbox"
                    checked={planForm.isPopular}
                    onChange={(e) => setPlanForm({ ...planForm, isPopular: e.target.checked })}
                    className="checkbox"
                  />
                  <span>Popular Badge</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer p-2.5 rounded-xl bg-white/5 border border-white/10">
                  <input
                    type="checkbox"
                    checked={planForm.isCustom}
                    onChange={(e) => setPlanForm({ ...planForm, isCustom: e.target.checked })}
                    className="checkbox"
                  />
                  <span>Bespoke / Custom</span>
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setPlanModalOpen(false)}
                  className="btn-secondary text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionBusy}
                  className="btn-primary text-xs flex items-center gap-1.5"
                >
                  {actionBusy ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  <span>{editingPlan ? 'Update Plan' : 'Save New Plan'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: CREATE / EDIT PROMO CODE ─────────────────────────────────── */}
      {promoModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 grid place-items-center p-4 animate-in fade-in">
          <div className="card p-6 max-w-md w-full border-emerald-500/40 bg-slate-900 shadow-2xl space-y-5 animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2 font-bold text-white text-base">
                <Tag size={18} className="text-emerald-400" />
                {editingPromo ? `Edit Promo: ${editingPromo.code}` : 'Generate Promo Code'}
              </div>
              <button
                onClick={() => setPromoModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSavePromo} className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[10px] text-slate-400 uppercase font-bold">Promo Code String</label>
                  <button
                    type="button"
                    onClick={generateRandomPromo}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 font-semibold"
                  >
                    🎲 Generate Random
                  </button>
                </div>
                <input
                  type="text"
                  value={promoForm.code}
                  onChange={(e) => setPromoForm({ ...promoForm, code: e.target.value.toUpperCase() })}
                  placeholder="e.g. SENTINEL50, FYP2026"
                  className="input font-mono tracking-widest text-sm font-bold uppercase text-emerald-300"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Discount Type</label>
                  <select
                    value={promoForm.discountType}
                    onChange={(e) => setPromoForm({ ...promoForm, discountType: e.target.value })}
                    className="input text-xs"
                  >
                    <option value="percentage">% Percentage</option>
                    <option value="fixed">RM Fixed Amount</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                    Value ({promoForm.discountType === 'percentage' ? '%' : 'RM'})
                  </label>
                  <input
                    type="number"
                    min="1"
                    max={promoForm.discountType === 'percentage' ? 100 : 9999}
                    value={promoForm.discountValue}
                    onChange={(e) => setPromoForm({ ...promoForm, discountValue: e.target.value })}
                    className="input text-xs font-mono font-bold"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Usage Limit (0 = ∞)</label>
                  <input
                    type="number"
                    min="0"
                    value={promoForm.maxUses}
                    onChange={(e) => setPromoForm({ ...promoForm, maxUses: e.target.value })}
                    className="input text-xs font-mono"
                    placeholder="0 for unlimited"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Expiration Date</label>
                  <input
                    type="date"
                    value={promoForm.expiresAt}
                    onChange={(e) => setPromoForm({ ...promoForm, expiresAt: e.target.value })}
                    className="input text-xs"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Applicable Tier</label>
                <select
                  value={promoForm.applicablePlans}
                  onChange={(e) => setPromoForm({ ...promoForm, applicablePlans: e.target.value })}
                  className="input text-xs"
                >
                  <option value="all">🌐 All Subscription Plans</option>
                  {plans.map(p => (
                    <option key={p.id} value={p.id}>Only {p.name} ({p.id})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Campaign Note</label>
                <input
                  type="text"
                  value={promoForm.note}
                  onChange={(e) => setPromoForm({ ...promoForm, note: e.target.value })}
                  placeholder="e.g. BlackHat Asia 2026 Attendee Discount"
                  className="input text-xs w-full"
                />
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer p-2.5 rounded-xl bg-white/5 border border-white/10">
                <input
                  type="checkbox"
                  checked={promoForm.isActive}
                  onChange={(e) => setPromoForm({ ...promoForm, isActive: e.target.checked })}
                  className="checkbox"
                />
                <span>Active & Redeemable Immediately</span>
              </label>

              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setPromoModalOpen(false)}
                  className="btn-secondary text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionBusy}
                  className="btn-primary text-xs flex items-center gap-1.5"
                >
                  {actionBusy ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  <span>{editingPromo ? 'Update Promo' : 'Create Promo Code'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
