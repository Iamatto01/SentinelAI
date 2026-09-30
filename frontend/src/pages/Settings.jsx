import React, { useEffect, useState } from 'react'
import {
  Loader2, Save, KeyRound, UserCircle, CheckCircle2, Database, Bell,
  Building2, Moon, Upload, Sparkles, Image, Eye, EyeOff, Sliders, RefreshCw,
  Layers, Send, ExternalLink, ShieldCheck, Unlink, Bot, MessageSquare,
  Tag, Percent, Lock, Unlock, Star, Plus, AlertCircle
} from 'lucide-react'
import { api } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'
import AdminSubscriptionManager from '../components/AdminSubscriptionManager.jsx'

export default function Settings() {
  const { user, setUser } = useAuth()
  const { theme, setTheme, blur, setBlur, opacity, setOpacity, isStatic, setIsStatic, randomizeNow, wallpapers, activeWallpaper } = useTheme()
  const [email, setEmail] = useState('')
  const [pw, setPw] = useState({ currentPassword: '', newPassword: '', confirm: '' })
  const [pwShow, setPwShow] = useState({ current: false, next: false, confirm: false })
  const [pwBusy, setPwBusy] = useState(false)
  const [pwMsg, setPwMsg] = useState('')
  const [pwErr, setPwErr] = useState('')

  const [profileBusy, setProfileBusy] = useState(false)
  const [profileMsg, setProfileMsg] = useState('')
  const [profileErr, setProfileErr] = useState('')

  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const isAdmin = user?.role === 'admin'
  const isClient = user?.role === 'client'

  const [activeTab, setActiveTab] = useState('general') // 'general' | 'subscriptions' | 'ai' | 'alerts'

  const [apiKeys, setApiKeys] = useState({ 
    groq: '', groqModel: 'llama-3.3-70b-versatile', 
    openrouter: '', openrouterModel: 'inclusionai/ling-3.0-flash:free',
    bandelbanget: '', bandelbangetModel: 'deepseek-v4-pro'
  })
  const [testResults, setTestResults] = useState({})
  const [notifs, setNotifs] = useState({ scanFinish: true, criticalAlert: true, dnd: false })
  const [branding, setBranding] = useState({ companyName: '', logo: '' })
  const [teleStatus, setTeleStatus] = useState(null)
  
  // Dedicated Telegram State
  const [telePairCode, setTelePairCode] = useState('')
  const [teleLoading, setTeleLoading] = useState(false)
  const [teleMsg, setTeleMsg] = useState('')
  const [teleErr, setTeleErr] = useState('')

  // Dedicated Discord State
  const [discordPairCode, setDiscordPairCode] = useState('')
  const [discordLoading, setDiscordLoading] = useState(false)
  const [discordMsg, setDiscordMsg] = useState('')
  const [discordErr, setDiscordErr] = useState('')

  // Anonymous Community Feedback State
  const [feedbackCat, setFeedbackCat] = useState('General Feedback')
  const [feedbackRating, setFeedbackRating] = useState(5)
  const [feedbackText, setFeedbackText] = useState('')
  const [feedbackBusy, setFeedbackBusy] = useState(false)
  const [feedbackMsg, setFeedbackMsg] = useState('')
  const [feedbackErr, setFeedbackErr] = useState('')

  async function handleSendFeedback(e) {
    e.preventDefault()
    if (!feedbackText.trim()) return
    setFeedbackBusy(true)
    setFeedbackMsg('')
    setFeedbackErr('')
    try {
      const res = await api.sendFeedback({
        category: feedbackCat,
        rating: feedbackRating,
        message: feedbackText.trim(),
      })
      setFeedbackMsg(res.message || 'Feedback sent anonymously to muhammadsaifudinmj@gmail.com!')
      setFeedbackText('')
    } catch (e2) {
      setFeedbackErr(e2.message || 'Failed to send feedback')
    } finally {
      setFeedbackBusy(false)
    }
  }

  const loadTeleStatus = () => {
    api.telegramPairing().then(setTeleStatus).catch(() => {})
  }

  useEffect(() => {
    api.me().then((u) => setEmail(u.email || '')).catch(() => {})
    loadTeleStatus()
    if (isAdmin) {
      api.aiProviders().then((data) => {
        const p = data.providers || []
        const groq = p.find(x => x.id === 'groq') || {}
        const opr = p.find(x => x.id === 'openrouter') || {}
        const ban = p.find(x => x.id === 'bandelbanget') || {}
        setApiKeys({
          groq: groq.key || '', groqModel: groq.model || 'llama-3.3-70b-versatile',
          openrouter: opr.key || '', openrouterModel: opr.model || 'inclusionai/ling-3.0-flash:free',
          bandelbanget: ban.key || '', bandelbangetModel: ban.model || 'deepseek-v4-pro'
        })
      }).catch(() => {})
    }

    const params = new URLSearchParams(window.location.search)
    const tabParam = params.get('tab')
    if (tabParam && ['general', 'subscriptions', 'ai', 'alerts'].includes(tabParam)) {
      setActiveTab(tabParam)
    } else if (window.location.hash === '#subscriptions' && isAdmin) {
      setActiveTab('subscriptions')
    }
  }, [isAdmin])

  async function handlePairTelegram(e) {
    e.preventDefault()
    setTeleMsg(''); setTeleErr(''); setTeleLoading(true)
    try {
      const res = await api.pairTelegram(telePairCode)
      setTeleMsg(res.message || 'Telegram account paired successfully!')
      setTelePairCode('')
      loadTeleStatus()
    } catch (err) {
      setTeleErr(err.message || 'Failed to pair Telegram account')
    } finally {
      setTeleLoading(false)
    }
  }

  async function handlePairDiscord(e) {
    e.preventDefault()
    setDiscordMsg(''); setDiscordErr(''); setDiscordLoading(true)
    try {
      const res = await api.pairTelegram(discordPairCode)
      setDiscordMsg(res.message || 'Discord account paired successfully!')
      setDiscordPairCode('')
      loadTeleStatus()
    } catch (err) {
      setDiscordErr(err.message || 'Failed to pair Discord account')
    } finally {
      setDiscordLoading(false)
    }
  }

  async function handleUnpairChannel(platform) {
    const label = platform === 'discord' ? 'Discord' : 'Telegram'
    if (!window.confirm(`Adakah anda pasti mahu memutuskan sambungan ${label} daripada akaun ini?`)) return
    if (platform === 'discord') {
      setDiscordMsg(''); setDiscordErr(''); setDiscordLoading(true)
    } else {
      setTeleMsg(''); setTeleErr(''); setTeleLoading(true)
    }
    try {
      const res = await api.unpairChannel(platform)
      if (platform === 'discord') {
        setDiscordMsg(res.message || `${label} unlinked successfully.`)
      } else {
        setTeleMsg(res.message || `${label} unlinked successfully.`)
      }
      loadTeleStatus()
    } catch (err) {
      if (platform === 'discord') {
        setDiscordErr(err.message || `Failed to unlink ${label}`)
      } else {
        setTeleErr(err.message || `Failed to unlink ${label}`)
      }
    } finally {
      setTeleLoading(false)
      setDiscordLoading(false)
    }
  }

  async function saveProfile(e) {
    e.preventDefault()
    setProfileMsg('')
    setProfileErr('')
    setProfileBusy(true)
    try {
      const u = await api.updateMe({ email })
      setUser?.(u)
      setProfileMsg('Profile updated successfully.')
    } catch (e2) {
      setProfileErr(e2.message || 'Failed to update profile')
    } finally {
      setProfileBusy(false)
    }
  }

  async function savePassword(e) {
    e.preventDefault()
    setPwMsg('')
    setPwErr('')
    if (!pw.currentPassword) {
      setPwErr('Please enter your current password.')
      return
    }
    if (!pw.newPassword) {
      setPwErr('Please enter a new password.')
      return
    }
    if (pw.newPassword.length < 4) {
      setPwErr('New password must be at least 4 characters long.')
      return
    }
    if (pw.newPassword !== pw.confirm) {
      setPwErr('New passwords do not match.')
      return
    }
    setPwBusy(true)
    try {
      const res = await api.changePassword(pw.currentPassword, pw.newPassword)
      setPwMsg(res.message || 'Password updated successfully! You can now use your new password.')
      setPw({ currentPassword: '', newPassword: '', confirm: '' })
    } catch (e2) {
      setPwErr(e2.message || 'Failed to update password')
    } finally {
      setPwBusy(false)
    }
  }

  async function saveApiKeys(e) { 
    e.preventDefault(); 
    setMsg(''); setErr('')
    try {
      await api.saveAiSettings(apiKeys)
      setMsg('AI Settings updated successfully.')
    } catch(err) {
      setErr(err.message)
    }
  }

  async function testProvider(provider, key, model) {
    if (!key) return setTestResults(prev => ({ ...prev, [provider]: { error: 'Please enter a key first' } }))
    setTestResults(prev => ({ ...prev, [provider]: { loading: true } }))
    try {
      const res = await api.testAiProvider(provider, key, model)
      if (res.success) {
        setTestResults(prev => ({ ...prev, [provider]: { success: true, reply: res.reply, loading: false } }))
      } else {
        setTestResults(prev => ({ ...prev, [provider]: { error: res.error, loading: false } }))
      }
    } catch(err) {
      setTestResults(prev => ({ ...prev, [provider]: { error: err.message, loading: false } }))
    }
  }

  return (
    <div className="space-y-6 motion-fade-up pb-12">
      {/* Header */}
      <div className="flex flex-col gap-2 pb-2 border-b border-white/10">
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          System & Account Settings
        </h1>
        <p className="text-xs text-slate-400 max-w-xl">
          Configure subscription plans & discounts, dynamic AI wallpapers, profile details, AI provider API keys, security credentials, and platform notifications.
        </p>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-white/10 pb-4">
        <button
          type="button"
          onClick={() => setActiveTab('general')}
          className={`text-xs font-bold px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer ${
            activeTab === 'general'
              ? 'bg-cyan-500 text-slate-950 font-extrabold shadow-[0_0_15px_rgba(0,242,254,0.35)]'
              : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
          }`}
        >
          <UserCircle size={15} /> General & Wallpapers
        </button>

        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('subscriptions')}
            className={`text-xs font-bold px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'subscriptions'
                ? 'bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 text-slate-950 font-extrabold shadow-[0_0_18px_rgba(16,185,129,0.4)]'
                : 'text-emerald-300 hover:text-emerald-200 bg-emerald-500/10 border border-emerald-500/30'
            }`}
          >
            <Tag size={15} /> 💳 Subscription & Plans Manager
            <span className="text-[9px] uppercase px-1.5 py-0.2 rounded-full bg-black/40 text-emerald-300 font-mono font-bold">
              Admin
            </span>
          </button>
        )}

        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('ai')}
            className={`text-xs font-bold px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeTab === 'ai'
                ? 'bg-cyan-500 text-slate-950 font-extrabold shadow-[0_0_15px_rgba(0,242,254,0.35)]'
                : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
            }`}
          >
            <Database size={15} /> AI Providers
          </button>
        )}

        <button
          type="button"
          onClick={() => setActiveTab('telegram')}
          className={`text-xs font-bold px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer ${
            activeTab === 'telegram'
              ? 'bg-cyan-500 text-slate-950 font-extrabold shadow-[0_0_15px_rgba(0,242,254,0.35)]'
              : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
          }`}
        >
          <Send size={14} /> Telegram Bot
          {teleStatus?.telegram?.paired && (
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('discord')}
          className={`text-xs font-bold px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer ${
            activeTab === 'discord'
              ? 'bg-indigo-500 text-white font-extrabold shadow-[0_0_15px_rgba(99,102,241,0.35)]'
              : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
          }`}
        >
          <Bot size={14} /> Discord Bot
          {teleStatus?.discord?.paired && (
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('feedback')}
          className={`text-xs font-bold px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer ${
            activeTab === 'feedback'
              ? 'bg-cyan-500 text-slate-950 font-extrabold shadow-[0_0_15px_rgba(0,242,254,0.35)]'
              : 'text-slate-400 hover:text-white bg-white/5 border border-white/10'
          }`}
        >
          <MessageSquare size={14} /> Feedback
        </button>
      </div>

      {msg && <div className="card p-4 text-emerald-400 text-xs font-bold flex items-center gap-3 border-emerald-500/30 bg-emerald-500/10"><CheckCircle2 size={18} /> {msg}</div>}
      {err && <div className="card p-4 text-rose-400 text-xs font-bold flex items-center gap-3 border-rose-500/30 bg-rose-500/10">{err}</div>}

      {/* ── TAB: ADMIN SUBSCRIPTION & PLANS MANAGER ───────────────────────────── */}
      {activeTab === 'subscriptions' && isAdmin && (
        <div className="animate-in fade-in duration-300">
          <AdminSubscriptionManager />
        </div>
      )}

      {/* ── TAB: GENERAL & APPEARANCE ────────────────────────────────────────── */}
      {activeTab === 'general' && (
        <div className="space-y-8 max-w-5xl animate-in fade-in duration-300">
          {/* AI DYNAMIC WALLPAPER & BACKGROUND STUDIO */}
          <div className="card p-6 space-y-6 border-cyan-500/30 bg-slate-900/60 shadow-2xl relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-purple-500/20 border border-cyan-400/40 text-cyan-300">
                    <Sparkles size={20} />
                  </div>
                  <h3 className="text-lg font-extrabold text-white">AI Dynamic Wallpaper & Background Studio</h3>
                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
                    AI Generated
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  Choose your desired background aesthetic, enable random AI backgrounds on every visit, or customize blur and opacity.
                </p>
              </div>

              <button
                type="button"
                onClick={randomizeNow}
                className="btn-fizzy self-start sm:self-auto"
              >
                <RefreshCw size={14} className="animate-spin-slow" />
                <span>Roll Random AI Background</span>
              </button>
            </div>

            {/* Wallpaper Selection Grid */}
            <div className="space-y-3">
              <label className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Image size={14} className="text-cyan-400" /> Select Background Theme
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                {wallpapers.map((w) => {
                  const isActive = theme === w.id
                  return (
                    <button
                      key={w.id}
                      type="button"
                      onClick={() => setTheme(w.id)}
                      className={`relative rounded-2xl overflow-hidden border text-left p-3 flex flex-col justify-between h-28 transition-all duration-300 group ${
                        isActive
                          ? 'border-cyan-400 shadow-[0_0_15px_rgba(0,242,254,0.35)] ring-2 ring-cyan-400/50 bg-cyan-950/40 scale-[1.02]'
                          : 'border-white/10 bg-slate-950/60 hover:border-white/30 hover:scale-[1.01]'
                      }`}
                    >
                      {/* Background Preview Thumbnail */}
                      {w.preview && (
                        <div
                          className="absolute inset-0 bg-cover bg-center opacity-30 group-hover:opacity-45 transition-opacity"
                          style={{ backgroundImage: `url(${w.preview})` }}
                        />
                      )}
                      <div className="absolute inset-0 bg-gradient-to-t from-slate-950/90 via-slate-950/40 to-transparent" />

                      <div className="relative z-10 flex items-center justify-between w-full">
                        <span className="text-[10px] font-extrabold uppercase px-1.5 py-0.5 rounded bg-black/60 text-cyan-300 border border-white/10 backdrop-blur-md">
                          {w.id === 'random_ai' ? 'Dynamic' : w.id === 'static_dark' ? 'Static' : 'AI'}
                        </span>
                        {isActive && (
                          <div className="w-5 h-5 rounded-full bg-cyan-400 text-slate-950 flex items-center justify-center shadow-md">
                            <CheckCircle2 size={13} className="text-slate-950" />
                          </div>
                        )}
                      </div>

                      <div className="relative z-10 space-y-0.5">
                        <p className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors leading-tight">
                          {w.name}
                        </p>
                        <p className="text-[10px] text-slate-400 line-clamp-1">
                          {w.desc}
                        </p>
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Background Customizer Sliders & Toggles */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 pt-2 border-t border-white/10">
              {/* Blur Control */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <Eye size={13} className="text-cyan-400" /> Background Blur
                  </span>
                  <span className="text-cyan-300 font-bold font-mono">{blur}px</span>
                </div>
                <div className="flex items-center gap-2">
                  {[0, 4, 8, 16].map((b) => (
                    <button
                      key={b}
                      type="button"
                      onClick={() => setBlur(b)}
                      className={`flex-1 py-1.5 rounded-xl text-xs font-bold border transition-all ${
                        blur === b
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400'
                          : 'bg-white/5 text-slate-400 border-white/10 hover:border-white/20'
                      }`}
                    >
                      {b === 0 ? 'None' : `${b}px`}
                    </button>
                  ))}
                </div>
              </div>

              {/* Opacity Control */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <Sliders size={13} className="text-cyan-400" /> Layer Opacity
                  </span>
                  <span className="text-cyan-300 font-bold font-mono">
                    {opacity > 1 ? Math.round(opacity) : Math.round((opacity || 0.35) * 100)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.10"
                  max="0.95"
                  step="0.05"
                  value={opacity > 1 ? opacity / 100 : (opacity || 0.35)}
                  onChange={(e) => setOpacity(parseFloat(e.target.value))}
                  className="w-full accent-cyan-400 cursor-pointer h-2 bg-slate-950 rounded-lg appearance-none"
                />
              </div>

              {/* Particle Canvas / Static Mode */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <Layers size={13} className="text-cyan-400" /> Animation Mode
                  </span>
                  <span className="text-cyan-300 font-bold">{isStatic ? 'Static Wallpaper' : 'Particle Canvas'}</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setIsStatic(true)}
                    className={`flex-1 py-1.5 rounded-xl text-xs font-bold border transition-all ${
                      isStatic
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400'
                        : 'bg-white/5 text-slate-400 border-white/10 hover:border-white/20'
                    }`}
                  >
                    Static
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsStatic(false)}
                    className={`flex-1 py-1.5 rounded-xl text-xs font-bold border transition-all ${
                      !isStatic
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400'
                        : 'bg-white/5 text-slate-400 border-white/10 hover:border-white/20'
                    }`}
                  >
                    Animated ✨
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* USER PROFILE & SECURITY CREDENTIALS */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* User Profile Form */}
            <form onSubmit={saveProfile} className="card p-6 space-y-5 hover:border-cyan-400/40 transition-all duration-300 flex flex-col justify-between">
              <div className="space-y-5">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <h3 className="flex items-center gap-2 text-base font-bold text-white">
                    <UserCircle size={18} className="text-cyan-400" /> User Profile
                  </h3>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-400/30">
                    {user?.role || 'user'}
                  </span>
                </div>

                {profileErr && (
                  <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
                    <AlertCircle size={15} className="shrink-0 text-rose-400" />
                    <span>{profileErr}</span>
                  </div>
                )}

                {profileMsg && (
                  <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
                    <CheckCircle2 size={15} className="shrink-0 text-emerald-400" />
                    <span>{profileMsg}</span>
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <label className="label">Username</label>
                    <input className="input !bg-white/5 opacity-80 cursor-not-allowed" value={user?.username || ''} disabled />
                  </div>
                  <div>
                    <label className="label">Email Address</label>
                    <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                  </div>
                </div>
              </div>
              <div className="flex justify-end pt-4">
                <button type="submit" disabled={profileBusy} className="btn-primary text-xs w-full sm:w-auto flex items-center justify-center gap-2 cursor-pointer">
                  {profileBusy ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />}
                  <span>{profileBusy ? 'Saving...' : 'Save Profile'}</span>
                </button>
              </div>
            </form>

            {/* Security Credentials Form */}
            <form onSubmit={savePassword} className="card p-6 space-y-5 hover:border-purple-400/40 transition-all duration-300 flex flex-col justify-between">
              <div className="space-y-5">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <h3 className="flex items-center gap-2 text-base font-bold text-white">
                    <KeyRound size={18} className="text-purple-400" /> Security Credentials
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 font-bold border border-purple-400/30">
                    Bcrypt 12R
                  </span>
                </div>

                {pwErr && (
                  <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
                    <AlertCircle size={15} className="shrink-0 text-rose-400" />
                    <span>{pwErr}</span>
                  </div>
                )}

                {pwMsg && (
                  <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center gap-2 animate-in fade-in">
                    <CheckCircle2 size={15} className="shrink-0 text-emerald-400" />
                    <span>{pwMsg}</span>
                  </div>
                )}

                <div className="space-y-4">
                  {/* Current Password */}
                  <div>
                    <label className="label">Current Password</label>
                    <div className="relative flex items-center">
                      <input
                        type={pwShow.current ? 'text' : 'password'}
                        className="input pr-10"
                        value={pw.currentPassword}
                        onChange={(e) => setPw({ ...pw, currentPassword: e.target.value })}
                        placeholder="Enter current password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setPwShow({ ...pwShow, current: !pwShow.current })}
                        className="absolute right-3 text-slate-400 hover:text-white p-1"
                        tabIndex={-1}
                      >
                        {pwShow.current ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>

                  {/* New Password */}
                  <div>
                    <div className="flex items-center justify-between">
                      <label className="label">New Password</label>
                      <span className="text-[10px] text-slate-400 font-mono">Min 4 characters</span>
                    </div>
                    <div className="relative flex items-center">
                      <input
                        type={pwShow.next ? 'text' : 'password'}
                        className="input pr-10"
                        value={pw.newPassword}
                        onChange={(e) => setPw({ ...pw, newPassword: e.target.value })}
                        placeholder="Enter new password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setPwShow({ ...pwShow, next: !pwShow.next })}
                        className="absolute right-3 text-slate-400 hover:text-white p-1"
                        tabIndex={-1}
                      >
                        {pwShow.next ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>

                  {/* Confirm Password */}
                  <div>
                    <div className="flex items-center justify-between">
                      <label className="label">Confirm New Password</label>
                      {pw.confirm && (
                        <span className={`text-[10px] font-bold ${
                          pw.newPassword === pw.confirm ? 'text-emerald-400' : 'text-rose-400'
                        }`}>
                          {pw.newPassword === pw.confirm ? '✓ Passwords match' : '✕ Do not match'}
                        </span>
                      )}
                    </div>
                    <div className="relative flex items-center">
                      <input
                        type={pwShow.confirm ? 'text' : 'password'}
                        className="input pr-10"
                        value={pw.confirm}
                        onChange={(e) => setPw({ ...pw, confirm: e.target.value })}
                        placeholder="Confirm new password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setPwShow({ ...pwShow, confirm: !pwShow.confirm })}
                        className="absolute right-3 text-slate-400 hover:text-white p-1"
                        tabIndex={-1}
                      >
                        {pwShow.confirm ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-4">
                <button
                  type="submit"
                  disabled={pwBusy}
                  className="btn-primary text-xs w-full sm:w-auto flex items-center justify-center gap-2 cursor-pointer"
                >
                  {pwBusy ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />}
                  <span>{pwBusy ? 'Updating Password...' : 'Update Password'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── TAB: AI PROVIDERS ────────────────────────────────────────────────── */}
      {activeTab === 'ai' && isAdmin && (
        <div className="max-w-3xl animate-in fade-in duration-300">
          <form onSubmit={saveApiKeys} className="card p-6 space-y-5 hover:border-cyan-400/40 transition-all duration-300 border-cyan-500/20">
            <div>
              <h3 className="flex items-center gap-2 text-base font-bold text-white"><Database size={18} className="text-cyan-400" /> AI Provider API Keys</h3>
              <p className="text-xs text-slate-400 mt-1">Configure specialist AI LLM providers.</p>
            </div>
            <div className="space-y-5">
              {/* Groq */}
              <div className="space-y-2 p-4 bg-slate-900/60 rounded-xl border border-white/10">
                <div className="flex items-center justify-between mb-1">
                  <h4 className="text-xs font-bold text-white">Groq Cloud AI</h4>
                  <button type="button" onClick={() => testProvider('groq', apiKeys.groq, apiKeys.groqModel)} className="btn-ghost text-xs py-1 px-2.5">
                    {testResults.groq?.loading ? <Loader2 size={12} className="animate-spin text-cyan-400" /> : 'Test Model'}
                  </button>
                </div>
                <div><label className="text-[10px] text-slate-400 uppercase font-bold">API Key</label><input type="password" className="input text-xs" placeholder="gsk_..." value={apiKeys.groq} onChange={(e) => setApiKeys({...apiKeys, groq: e.target.value})} /></div>
                <div><label className="text-[10px] text-slate-400 uppercase font-bold">Model</label><input type="text" className="input text-xs" value={apiKeys.groqModel} onChange={(e) => setApiKeys({...apiKeys, groqModel: e.target.value})} /></div>
                {testResults.groq?.success && <p className="text-xs text-emerald-400 mt-2 p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">{testResults.groq.reply}</p>}
                {testResults.groq?.error && <p className="text-xs text-rose-400 mt-2 p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">{testResults.groq.error}</p>}
              </div>

              {/* OpenRouter */}
              <div className="space-y-2 p-4 bg-slate-900/60 rounded-xl border border-white/10">
                <div className="flex items-center justify-between mb-1">
                  <h4 className="text-xs font-bold text-white">OpenRouter AI</h4>
                  <button type="button" onClick={() => testProvider('openrouter', apiKeys.openrouter, apiKeys.openrouterModel)} className="btn-ghost text-xs py-1 px-2.5">
                    {testResults.openrouter?.loading ? <Loader2 size={12} className="animate-spin text-cyan-400" /> : 'Test Model'}
                  </button>
                </div>
                <div><label className="text-[10px] text-slate-400 uppercase font-bold">API Key</label><input type="password" className="input text-xs" placeholder="sk-or-v1-..." value={apiKeys.openrouter} onChange={(e) => setApiKeys({...apiKeys, openrouter: e.target.value})} /></div>
                <div><label className="text-[10px] text-slate-400 uppercase font-bold">Model</label><input type="text" className="input text-xs" value={apiKeys.openrouterModel} onChange={(e) => setApiKeys({...apiKeys, openrouterModel: e.target.value})} /></div>
                {testResults.openrouter?.success && <p className="text-xs text-emerald-400 mt-2 p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">{testResults.openrouter.reply}</p>}
                {testResults.openrouter?.error && <p className="text-xs text-rose-400 mt-2 p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">{testResults.openrouter.error}</p>}
              </div>
            </div>
            <div className="flex justify-end pt-2"><button type="submit" className="btn-primary text-xs"><Save size={15} /> Save API Keys</button></div>
          </form>
        </div>
      )}

      {/* ── TAB: TELEGRAM BOT INTEGRATION ──────────────────────────────────── */}
      {(activeTab === 'telegram' || activeTab === 'alerts') && (
        <div className="space-y-6 max-w-4xl animate-in fade-in duration-300">
          {/* TELEGRAM BOT INTEGRATION CARD */}
          <div className="card p-6 space-y-6 border-l-4 border-l-cyan-500 border-cyan-500/30 bg-[#161616] relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
                  <Send size={20} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Telegram Bot Integration
                  </h3>
                  <p className="text-xs text-slate-400">
                    Sambungkan akaun Telegram anda dengan <span className="text-cyan-300 font-mono font-semibold">@{teleStatus?.telegram?.botUsername || 'sentinelai_telebot'}</span> untuk melancarkan imbasan dari jauh, menerima amaran masa nyata & laporan pentest secara automatik.
                  </p>
                </div>
              </div>

              {teleStatus?.telegram?.paired ? (
                <span className="text-[11px] uppercase font-bold px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1.5 self-start sm:self-auto">
                  <ShieldCheck size={14} /> Connected
                </span>
              ) : (
                <span className="text-[11px] uppercase font-bold px-3 py-1 rounded-full bg-slate-800 text-slate-400 border border-white/10 self-start sm:self-auto">
                  Not Paired
                </span>
              )}
            </div>

            {teleMsg && <div className="p-3 text-xs font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">{teleMsg}</div>}
            {teleErr && <div className="p-3 text-xs font-semibold text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-xl">{teleErr}</div>}

            {/* Telegram Status Info & Unlink */}
            {teleStatus?.telegram?.paired ? (
              <div className="p-4 rounded-xl bg-cyan-950/25 border border-cyan-500/30 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-400 text-[11px]">Chat ID</span>
                    <div className="font-mono text-cyan-300 font-bold">{teleStatus.telegram.chatId}</div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[11px]">Nama Pengguna</span>
                    <div className="text-slate-200 font-semibold">{teleStatus.telegram.senderName || 'Telegram User'}</div>
                  </div>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-white/10 text-xs">
                  <a
                    href={`https://t.me/${teleStatus?.telegram?.botUsername || 'sentinelai_telebot'}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
                  >
                    <ExternalLink size={12} /> Buka Telegram
                  </a>
                  <button
                    type="button"
                    onClick={() => handleUnpairChannel('telegram')}
                    disabled={teleLoading}
                    className="text-rose-400 hover:text-rose-300 text-xs underline cursor-pointer"
                  >
                    {teleLoading ? 'Memutuskan...' : 'Putuskan Sambungan'}
                  </button>
                </div>
              </div>
            ) : (
              /* Telegram Pairing Step-by-Step Box */
              <form onSubmit={handlePairTelegram} className="space-y-4 p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30">
                <div className="text-xs text-slate-300 space-y-1.5">
                  <div>
                    <strong className="text-cyan-400">Langkah 1:</strong> Buka bot Telegram rasmi di <a href={`https://t.me/${teleStatus?.telegram?.botUsername || 'sentinelai_telebot'}`} target="_blank" rel="noreferrer" className="text-cyan-300 underline font-mono font-semibold">@{teleStatus?.telegram?.botUsername || 'sentinelai_telebot'}</a>
                  </div>
                  <div>
                    <strong className="text-cyan-400">Langkah 2:</strong> Hantar arahan <code className="bg-black/50 px-1.5 py-0.5 rounded text-cyan-300 font-mono font-bold">/start</code> untuk mendapatkan Kod Pengesahan 6-digit anda.
                  </div>
                  <div>
                    <strong className="text-cyan-400">Langkah 3:</strong> Masukkan kod 6-digit tersebut di bawah untuk mengaktifkan sambungan:
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-3 pt-1">
                  <input
                    type="text"
                    maxLength={10}
                    placeholder="Contoh: 141053"
                    value={telePairCode}
                    onChange={(e) => setTelePairCode(e.target.value)}
                    className="input font-mono tracking-widest text-center text-sm sm:max-w-xs focus:border-cyan-400"
                    required
                  />
                  <button
                    type="submit"
                    disabled={teleLoading || !telePairCode.trim()}
                    className="btn-concept-12"
                  >
                    <span className="btn-concept-12__text">
                      {teleLoading ? 'Menyambung...' : 'Sambung Telegram'}
                    </span>
                    <span className="btn-concept-12__icon">
                      {teleLoading ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                    </span>
                  </button>
                  <a
                    href={`https://t.me/${teleStatus?.telegram?.botUsername || 'sentinelai_telebot'}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-ghost text-xs py-2 px-3.5 flex items-center justify-center gap-1.5 sm:ml-auto"
                  >
                    <ExternalLink size={13} /> Buka Telegram
                  </a>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* ── TAB: DISCORD BOT INTEGRATION ───────────────────────────────────── */}
      {(activeTab === 'discord' || activeTab === 'alerts') && (
        <div className="space-y-6 max-w-4xl animate-in fade-in duration-300">
          {/* DISCORD & OTHER BOTS INTEGRATION CARD */}
          <div className="card p-6 space-y-6 border-l-4 border-l-indigo-500 border-indigo-500/30 bg-[#161616] relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-indigo-500/20 border border-indigo-400/30 flex items-center justify-center text-indigo-400">
                  <Bot size={20} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Discord & Other Bots Integration
                  </h3>
                  <p className="text-xs text-slate-400">
                    Sambungkan bot Discord <span className="text-indigo-300 font-mono font-semibold">@Sentinel AI</span> ke dalam server atau DM Discord anda untuk menerima log amaran audit, notifikasi GitHub PR, dan status imbasan.
                  </p>
                </div>
              </div>

              {teleStatus?.discord?.paired ? (
                <span className="text-[11px] uppercase font-bold px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1.5 self-start sm:self-auto">
                  <ShieldCheck size={14} /> Connected
                </span>
              ) : (
                <span className="text-[11px] uppercase font-bold px-3 py-1 rounded-full bg-slate-800 text-slate-400 border border-white/10 self-start sm:self-auto">
                  Not Paired
                </span>
              )}
            </div>

            {discordMsg && <div className="p-3 text-xs font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded-xl">{discordMsg}</div>}
            {discordErr && <div className="p-3 text-xs font-semibold text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-xl">{discordErr}</div>}

            {/* Discord Status Info & Unlink */}
            {teleStatus?.discord?.paired ? (
              <div className="p-4 rounded-xl bg-indigo-950/25 border border-indigo-500/30 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-400 text-[11px]">Channel / User ID</span>
                    <div className="font-mono text-indigo-300 font-bold">{teleStatus.discord.chatId}</div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[11px]">Nama Pengguna / Server</span>
                    <div className="text-slate-200 font-semibold">{teleStatus.discord.senderName || 'Discord User'}</div>
                  </div>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-white/10 text-xs">
                  <span className="text-[11px] text-slate-400 font-mono">Status: Aktif menerima notifikasi Discord</span>
                  <button
                    type="button"
                    onClick={() => handleUnpairChannel('discord')}
                    disabled={discordLoading}
                    className="text-rose-400 hover:text-rose-300 text-xs underline cursor-pointer"
                  >
                    {discordLoading ? 'Memutuskan...' : 'Putuskan Sambungan'}
                  </button>
                </div>
              </div>
            ) : (
              /* Discord Pairing Step-by-Step Box */
              <form onSubmit={handlePairDiscord} className="space-y-4 p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/30">
                <div className="text-xs text-slate-300 space-y-1.5">
                  <div>
                    <strong className="text-indigo-400">Langkah 1:</strong> Buka Discord anda (server channel atau Direct Message ke bot).
                  </div>
                  <div>
                    <strong className="text-indigo-400">Langkah 2:</strong> Taip arahan <code className="bg-black/50 px-1.5 py-0.5 rounded text-indigo-300 font-mono font-bold">@Sentinel AI /start</code> untuk menjana Kod Pengesahan 6-digit.
                  </div>
                  <div>
                    <strong className="text-indigo-400">Langkah 3:</strong> Masukkan kod 6-digit tersebut di bawah untuk mengaktifkan sambungan:
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-3 pt-1">
                  <input
                    type="text"
                    maxLength={10}
                    placeholder="Contoh: 839201"
                    value={discordPairCode}
                    onChange={(e) => setDiscordPairCode(e.target.value)}
                    className="input font-mono tracking-widest text-center text-sm sm:max-w-xs focus:border-indigo-400"
                    required
                  />
                  <button
                    type="submit"
                    disabled={discordLoading || !discordPairCode.trim()}
                    className="btn-concept-12 btn-concept-12--indigo"
                  >
                    <span className="btn-concept-12__text">
                      {discordLoading ? 'Menyambung...' : 'Sambung Discord'}
                    </span>
                    <span className="btn-concept-12__icon">
                      {discordLoading ? <Loader2 size={16} className="animate-spin" /> : <Bot size={16} />}
                    </span>
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* ── TAB: ANONYMOUS FEEDBACK & BUG REPORT ───────────────────────────── */}
      {(activeTab === 'feedback' || activeTab === 'alerts') && (
        <div className="space-y-6 max-w-4xl animate-in fade-in duration-300">
          {/* Anonymous Community Feedback & Bug Report Card */}
          <form onSubmit={handleSendFeedback} className="card p-6 space-y-5 hover:border-cyan-400/40 transition-all duration-300 border-cyan-500/20 bg-[#161616]">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-base font-bold text-white">
                  <MessageSquare size={18} className="text-cyan-400" /> Anonymous Feedback & Bug Report
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 font-bold">
                  100% Anonymous
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Have an idea, request, or issue? Your message is sent directly to the developer (<code className="text-cyan-300">muhammadsaifudinmj@gmail.com</code>).
              </p>
            </div>

            {feedbackMsg && (
              <div className="p-3.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center gap-2">
                <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                <span>{feedbackMsg}</span>
              </div>
            )}

            {feedbackErr && (
              <div className="p-3.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs font-semibold flex items-center gap-2">
                <CheckCircle2 size={16} className="text-rose-400 shrink-0" />
                <span>{feedbackErr}</span>
              </div>
            )}

            <div className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Category</label>
                  <select
                    value={feedbackCat}
                    onChange={(e) => setFeedbackCat(e.target.value)}
                    className="input text-xs"
                  >
                    <option value="General Feedback">💡 General Feedback</option>
                    <option value="Bug Report">🐛 Bug Report / Issue</option>
                    <option value="Feature Request">🚀 Feature Request</option>
                    <option value="Scan Tool Suggestion">🛡️ Kali Tool Suggestion</option>
                    <option value="UI & UX Improvement">✨ UI / UX Improvement</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Rating</label>
                  <div className="flex items-center gap-1 h-9 px-3 rounded-xl bg-white/5 border border-white/10">
                    {[1, 2, 3, 4, 5].map((star) => (
                      <button
                        type="button"
                        key={star}
                        onClick={() => setFeedbackRating(star)}
                        className={`text-base transition-transform hover:scale-125 cursor-pointer ${
                          star <= feedbackRating ? 'opacity-100' : 'opacity-30'
                        }`}
                      >
                        ⭐
                      </button>
                    ))}
                    <span className="text-[11px] text-slate-400 font-mono ml-2">({feedbackRating}/5)</span>
                  </div>
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Your Message</label>
                <textarea
                  rows={4}
                  value={feedbackText}
                  onChange={(e) => setFeedbackText(e.target.value)}
                  placeholder="Describe your bug, feedback, or suggestion in detail..."
                  className="input text-xs w-full resize-none font-normal"
                  required
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-white/10">
              <span className="text-[11px] text-slate-500 italic">No account identifier is linked or exposed.</span>
              <button
                type="submit"
                disabled={feedbackBusy || !feedbackText.trim()}
                className="btn-primary text-xs flex items-center gap-1.5 cursor-pointer"
              >
                {feedbackBusy ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
                <span>{feedbackBusy ? 'Sending...' : 'Send Anonymous Feedback'}</span>
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
