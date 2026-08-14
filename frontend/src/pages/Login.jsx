import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import {
  ArrowLeft, Loader2, ShieldCheck, KeyRound, User, EyeOff, Sparkles,
  Mail, Check, AlertCircle, Zap, Star
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import { useAuth } from '../lib/AuthContext.jsx'
import { api, setToken } from '../lib/api.js'

function EyeCursorTracker() {
  const [pupilOffset, setPupilOffset] = useState({ x: 0, y: 0 })
  const eyeRef = useRef(null)

  useEffect(() => {
    function handleMouseMove(e) {
      if (!eyeRef.current) return
      const rect = eyeRef.current.getBoundingClientRect()
      const eyeCenterX = rect.left + rect.width / 2
      const eyeCenterY = rect.top + rect.height / 2
      const deltaX = e.clientX - eyeCenterX
      const deltaY = e.clientY - eyeCenterY
      const distance = Math.hypot(deltaX, deltaY)
      const maxDistance = 4.5
      const factor = distance === 0 ? 0 : Math.min(distance / 150, 1) * maxDistance
      const angle = Math.atan2(deltaY, deltaX)
      setPupilOffset({
        x: Math.cos(angle) * factor,
        y: Math.sin(angle) * factor,
      })
    }
    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [])

  return (
    <svg
      ref={eyeRef}
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-cyan-400 drop-shadow-[0_0_10px_rgba(0,242,254,0.7)] transition-transform duration-75"
    >
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
      <circle cx={12 + pupilOffset.x} cy={12 + pupilOffset.y} r="3" fill="#00f2fe" stroke="none" />
    </svg>
  )
}

export default function Login() {
  const { login, setUser } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()

  // Parse URL query params
  const searchParams = new URLSearchParams(loc.search)
  const initialMode = searchParams.get('mode') === 'register' ? 'register' : 'login'
  const initialPlan = searchParams.get('plan') === 'enterprise' ? 'enterprise' : 'pro'
  const initialInterval = searchParams.get('interval') === 'yearly' ? 'yearly' : 'monthly'

  const [mode, setMode] = useState(initialMode) // 'login' | 'register'
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [planId, setPlanId] = useState(initialPlan)
  const [interval, setInterval] = useState(initialInterval)
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function submit(e) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      if (mode === 'login') {
        await login(username.trim(), password)
        nav(loc.state?.from?.pathname || '/app/dashboard', { replace: true })
      } else {
        // Register with Plan
        const res = await api.register({
          username: username.trim(),
          email: email.trim(),
          password,
          planId,
          billingInterval: interval,
          paymentProvider: 'stripe',
        })
        setToken(res.token)
        setUser(res.user)
        nav('/app/dashboard', { replace: true })
      }
    } catch (e2) {
      setErr(e2.message || (mode === 'login' ? 'Login failed' : 'Registration failed'))
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen grid place-items-center grid-bg p-4 sm:p-6 relative overflow-hidden selection:bg-cyan-500 selection:text-slate-950">
      {/* Top-Left Back Button */}
      <Link
        to="/"
        className="fixed top-5 left-5 z-50 inline-flex items-center gap-2 px-4 py-2 rounded-full glass border border-white/15 hover:border-cyan-400/50 text-xs font-semibold text-slate-300 hover:text-cyan-300 transition-all duration-300 shadow-2xl group"
      >
        <ArrowLeft size={15} className="group-hover:-translate-x-1 transition-transform duration-200 text-cyan-400" />
        <span>Back to Landing Page</span>
      </Link>

      {/* Vision Ambient Glowing Meshes */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-cyan-500/15 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/3 left-1/2 -translate-x-1/2 translate-y-1/2 w-[500px] h-[500px] bg-purple-600/15 rounded-full blur-[120px] pointer-events-none" />

      {/* Main Centered Login / Register Container */}
      <div className="w-full max-w-lg relative z-10 my-auto motion-fade-up">
        {/* Header Logo & Title */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="relative mb-3 group">
            <div className="absolute -inset-3 rounded-full bg-gradient-to-r from-cyan-400 via-blue-600 to-purple-600 opacity-60 blur-xl group-hover:opacity-90 transition duration-500" />
            <div className="relative">
              <InspectorLogo size={58} />
            </div>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">SentinelAI</h1>
          <p className="text-[10px] uppercase tracking-[0.25em] text-cyan-400 font-extrabold mt-1 flex items-center gap-1.5 justify-center">
            <Sparkles size={12} className="text-cyan-300 animate-pulse" /> Autonomous Security Suite
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex rounded-2xl bg-slate-900/80 p-1 border border-white/10 mb-4">
          <button
            type="button"
            onClick={() => { setMode('login'); setErr('') }}
            className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
              mode === 'login'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setMode('register'); setErr('') }}
            className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
              mode === 'register'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Create Account & Subscribe
          </button>
        </div>

        {/* Vision UI Form Card */}
        <form onSubmit={submit} className="glass rounded-3xl border border-white/20 p-6 sm:p-7 shadow-2xl space-y-4 relative">
          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <User size={13} className="text-cyan-400" /> Username
            </label>
            <input
              className="input py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              placeholder="Enter username"
              required
            />
          </div>

          {mode === 'register' && (
            <div className="space-y-1">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <Mail size={13} className="text-cyan-400" /> Email Address
              </label>
              <input
                type="email"
                className="input py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                placeholder="you@company.com"
                required
              />
            </div>
          )}

          <div className="space-y-1">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <KeyRound size={13} className="text-cyan-400" /> Password
            </label>
            <div className="relative flex items-center">
              <input
                type={showPassword ? 'text' : 'password'}
                className="input py-2.5 pr-11 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 p-1 rounded-lg hover:bg-white/10 text-slate-400 hover:text-cyan-300 transition-colors focus:outline-none"
                title={showPassword ? 'Hide password' : 'Reveal password'}
              >
                {showPassword ? <EyeCursorTracker /> : <EyeOff size={16} className="text-slate-400" />}
              </button>
            </div>
          </div>

          {/* Registration Plan Selection */}
          {mode === 'register' && (
            <div className="space-y-2 pt-2 border-t border-white/10">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-200">Select Subscription Plan:</span>
                <button
                  type="button"
                  onClick={() => setInterval(interval === 'monthly' ? 'yearly' : 'monthly')}
                  className="text-[11px] text-cyan-300 font-semibold hover:underline"
                >
                  {interval === 'yearly' ? 'Yearly (17% OFF)' : 'Monthly'}
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setPlanId('pro')}
                  className={`p-3 rounded-2xl border text-left transition-all cursor-pointer ${
                    planId === 'pro'
                      ? 'border-cyan-400 bg-cyan-500/15 ring-1 ring-cyan-400'
                      : 'border-white/10 bg-slate-950/60 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-extrabold text-white">SentinelAI Pro</span>
                    {planId === 'pro' && <Check size={14} className="text-cyan-400" />}
                  </div>
                  <div className="text-lg font-black text-cyan-300 mt-1">
                    ${interval === 'yearly' ? '190' : '19'}<span className="text-[10px] text-slate-400 font-normal">/{interval === 'yearly' ? 'yr' : 'mo'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">50 Scans &bull; 5 Repos</div>
                </button>

                <button
                  type="button"
                  onClick={() => setPlanId('enterprise')}
                  className={`p-3 rounded-2xl border text-left transition-all cursor-pointer ${
                    planId === 'enterprise'
                      ? 'border-emerald-400 bg-emerald-500/15 ring-1 ring-emerald-400'
                      : 'border-white/10 bg-slate-950/60 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-extrabold text-white">Enterprise</span>
                    {planId === 'enterprise' && <Check size={14} className="text-emerald-400" />}
                  </div>
                  <div className="text-lg font-black text-emerald-300 mt-1">
                    ${interval === 'yearly' ? '790' : '79'}<span className="text-[10px] text-slate-400 font-normal">/{interval === 'yearly' ? 'yr' : 'mo'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Unlimited Scans & Repos</div>
                </button>
              </div>
            </div>
          )}

          {err && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 font-semibold flex items-center gap-2">
              <AlertCircle size={14} className="shrink-0 text-rose-400" />
              <span>{err}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="btn-primary w-full justify-center py-3 text-xs font-extrabold shadow-glow hover:scale-[1.01] active:scale-[0.99] transition-all cursor-pointer"
          >
            {busy && <Loader2 size={15} className="animate-spin" />}
            {busy
              ? (mode === 'login' ? 'Authenticating...' : 'Activating Subscription...')
              : (mode === 'login' ? 'Sign In to Operations Center' : `Subscribe & Activate ${planId === 'enterprise' ? 'Enterprise' : 'Pro'}`)}
          </button>
        </form>
      </div>
    </div>
  )
}
