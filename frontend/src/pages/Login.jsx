import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import {
  ArrowLeft, Loader2, KeyRound, User, Eye, EyeOff, Sparkles,
  Mail, Check, AlertCircle, Lock, Sun, Moon
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import { useAuth } from '../lib/AuthContext.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'
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
  const { isNight, toggleNightMode } = useTheme()
  const { login, setUser } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()

  // Parse URL query params
  const searchParams = new URLSearchParams(loc.search)
  const initialMode = searchParams.get('mode') === 'register' ? 'register' : 'login'
  const initialPlan = searchParams.get('plan') || 'trial'
  const initialInterval = searchParams.get('interval') || 'monthly'

  const [mode, setMode] = useState(initialMode) // 'login' | 'register'
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [planId, setPlanId] = useState(initialPlan)
  const [interval, setInterval] = useState(initialInterval)
  const [plans, setPlans] = useState([])
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    fetch('/api/billing/plans')
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.plans?.length) setPlans(d.plans) })
      .catch(() => {})
  }, [])

  // Force empty inputs on initial load to prevent browser autofill hijack
  useEffect(() => {
    setUsername('')
    setPassword('')
    setEmail('')
  }, [mode])

  async function submit(e) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      if (mode === 'login') {
        await login(username.trim(), password)
        sessionStorage.setItem('sentinel_gate_trigger', 'true')
        nav(loc.state?.from?.pathname || '/app/dashboard', { replace: true })
      } else {
        // Register with Plan
        const res = await api.register({
          username: username.trim(),
          email: email.trim(),
          password,
          planId: planId || 'trial',
          billingInterval: interval,
          paymentProvider: 'stripe',
        })
        setToken(res.token)
        setUser(res.user)
        nav(planId && planId !== 'trial' ? `/app/billing?plan=${encodeURIComponent(planId)}&interval=${encodeURIComponent(interval)}` : '/app/dashboard', { replace: true })
      }
    } catch (e2) {
      const errMsg = e2.message || ''
      if (mode === 'login') {
        if (e2.status === 401 || errMsg.toLowerCase().includes('invalid') || errMsg.toLowerCase().includes('credential') || errMsg.toLowerCase().includes('failed (401)')) {
          setErr('Username or password is invalid')
        } else {
          setErr(errMsg || 'Username or password is invalid')
        }
      } else {
        setErr(errMsg || 'Registration failed')
      }
      setBusy(false)
    }
  }

  return (
    <div className={`min-h-screen grid place-items-center grid-bg p-4 sm:p-6 relative overflow-hidden selection:bg-cyan-500 selection:text-slate-950 transition-colors ${
      isNight ? 'bg-[#0c0f17]' : 'bg-[#f8fafc]'
    }`}>
      {/* Top-Left Back Button */}
      <Link
        to="/"
        className={`fixed top-5 left-5 z-50 inline-flex items-center gap-2 px-4 py-2 rounded-full border text-xs font-semibold transition-all duration-300 shadow-xl group ${
          isNight
            ? 'bg-slate-900/80 border-white/15 text-slate-300 hover:text-cyan-300 hover:border-cyan-400/50'
            : 'bg-white/95 border-slate-300 text-slate-700 hover:text-cyan-600 hover:border-cyan-500'
        }`}
      >
        <ArrowLeft size={15} className={`group-hover:-translate-x-1 transition-transform duration-200 ${isNight ? 'text-cyan-400' : 'text-cyan-500'}`} />
        <span>Back to Landing Page</span>
      </Link>

      {/* Top-Right Theme Switcher Button */}
      <button
        type="button"
        onClick={toggleNightMode}
        className={`fixed top-5 right-5 z-50 inline-flex items-center gap-2 px-3.5 py-2 rounded-full border text-xs font-bold transition-all duration-300 shadow-xl cursor-pointer active:scale-95 ${
          isNight
            ? 'bg-slate-900/80 border-white/15 text-slate-200 hover:text-white hover:border-cyan-400/50'
            : 'bg-white/95 border-slate-300 text-slate-800 hover:text-cyan-600 hover:border-cyan-500'
        }`}
        title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        aria-label="Toggle Theme"
      >
        {isNight ? (
          <>
            <Sun size={15} className="text-amber-400 animate-spin-slow" />
            <span>Light Mode</span>
          </>
        ) : (
          <>
            <Moon size={15} className="text-cyan-600" />
            <span>Dark Mode</span>
          </>
        )}
      </button>

      {/* Ambient Glowing Meshes */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-cyan-500/15 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/3 left-1/2 -translate-x-1/2 translate-y-1/2 w-[500px] h-[500px] bg-purple-600/15 rounded-full blur-[120px] pointer-events-none" />

      {/* Main Centered Login / Register Container */}
      <div className="w-full max-w-lg relative z-10 my-auto motion-fade-up">
        {/* Header Logo & Title */}
        <div className="flex flex-col items-center mb-6 text-center">
          <div className="relative mb-3 group">
            <div className="absolute -inset-3 rounded-full bg-gradient-to-r from-cyan-400 via-blue-600 to-purple-600 opacity-60 blur-xl group-hover:opacity-90 transition duration-500" />
            <div className="relative">
              <InspectorLogo size={52} />
            </div>
          </div>
          <h1 className={`text-2xl sm:text-3xl font-extrabold tracking-tight ${isNight ? 'text-white' : 'text-slate-900'}`}>
            SentinelAI
          </h1>
          <p className={`text-[10px] uppercase tracking-[0.25em] font-extrabold mt-1 flex items-center gap-1.5 justify-center ${isNight ? 'text-cyan-400' : 'text-cyan-600'}`}>
            <Sparkles size={12} className={`${isNight ? 'text-cyan-300' : 'text-cyan-500'} animate-pulse`} /> Autonomous Security Suite
          </p>
        </div>

        {/* Tab Switcher */}
        <div className={`flex rounded-2xl p-1 border mb-4 transition-colors ${
          isNight ? 'bg-[#0f1422] border-white/10' : 'bg-slate-200/90 border-slate-300'
        }`}>
          <button
            type="button"
            onClick={() => { setMode('login'); setErr('') }}
            className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
              mode === 'login'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-950'
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
                : isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-950'
            }`}
          >
            Create Account (Free Trial)
          </button>
        </div>

        {/* Adaptive Form Card */}
        <form
          onSubmit={submit}
          autoComplete="off"
          className={`rounded-3xl border p-6 sm:p-7 shadow-2xl space-y-4 relative transition-colors ${
            isNight
              ? 'bg-[#111726]/95 border-white/15 text-slate-100 shadow-2xl'
              : 'bg-white border-slate-200 text-slate-900 shadow-xl shadow-slate-200/50'
          }`}
        >
          {/* Hidden Dummy Inputs to prevent Chrome/Edge from autofilling saved credentials */}
          <input type="text" name="fakeusernameremembered" style={{ display: 'none' }} tabIndex={-1} autoComplete="off" />
          <input type="password" name="fakepasswordremembered" style={{ display: 'none' }} tabIndex={-1} autoComplete="off" />

          <div className="space-y-1">
            <label className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
              isNight ? 'text-slate-300' : 'text-slate-700'
            }`}>
              <User size={13} className={isNight ? 'text-cyan-400' : 'text-cyan-500'} /> Username
            </label>
            <input
              name="sentinel_auth_user"
              className={`input py-2.5 text-sm transition-all focus:border-cyan-400 ${
                isNight
                  ? 'text-slate-100 bg-[#182133] border-white/15 placeholder-slate-500'
                  : 'text-slate-900 bg-slate-50 border-slate-300 placeholder-slate-400 font-medium'
              }`}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              autoComplete="new-password"
              required
            />
          </div>

          {mode === 'register' && (
            <div className="space-y-1">
              <label className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                isNight ? 'text-slate-300' : 'text-slate-700'
              }`}>
                <Mail size={13} className={isNight ? 'text-cyan-400' : 'text-cyan-500'} /> Email Address
              </label>
              <input
                name="sentinel_auth_email"
                type="email"
                className={`input py-2.5 text-sm transition-all focus:border-cyan-400 ${
                  isNight
                    ? 'text-slate-100 bg-[#182133] border-white/15 placeholder-slate-500'
                    : 'text-slate-900 bg-slate-50 border-slate-300 placeholder-slate-400 font-medium'
                }`}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                autoComplete="off"
                required
              />
            </div>
          )}

          <div className="space-y-1">
            <label className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
              isNight ? 'text-slate-300' : 'text-slate-700'
            }`}>
              <KeyRound size={13} className={isNight ? 'text-cyan-400' : 'text-cyan-500'} /> Password
            </label>
            <div className="relative flex items-center">
              <input
                name="sentinel_auth_pass"
                type={showPassword ? 'text' : 'password'}
                className={`input py-2.5 pr-11 text-sm transition-all focus:border-cyan-400 ${
                  isNight
                    ? 'text-slate-100 bg-[#182133] border-white/15 placeholder-slate-500'
                    : 'text-slate-900 bg-slate-50 border-slate-300 placeholder-slate-400 font-medium'
                }`}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="new-password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className={`absolute right-3 p-1 rounded-lg transition-colors focus:outline-none ${
                  isNight ? 'hover:bg-white/10 text-slate-400 hover:text-cyan-300' : 'hover:bg-slate-200 text-slate-500 hover:text-cyan-600'
                }`}
                title={showPassword ? 'Hide password' : 'Reveal password'}
              >
                {showPassword ? (
                  <Eye size={16} className={isNight ? 'text-cyan-400' : 'text-cyan-500'} />
                ) : (
                  <EyeOff size={16} className="text-slate-400" />
                )}
              </button>
            </div>
          </div>

          {/* Registration Plan Selection (Synced dynamically with active database plans) */}
          {mode === 'register' && (() => {
            const proPlan = plans.find(p => p.id === 'pro') || { name: 'SentinelAI Pro', priceMonthly: 20 }
            const entPlan = plans.find(p => p.id === 'enterprise') || { name: 'Enterprise', priceMonthly: 80 }
            const trialPlan = plans.find(p => p.id === 'trial') || { name: 'Free Trial', scanQuota: 3 }

            return (
              <div className={`space-y-2.5 pt-2 border-t ${isNight ? 'border-white/10' : 'border-slate-200'}`}>
                <div className="flex items-center justify-between text-xs">
                  <span className={`font-bold ${isNight ? 'text-slate-200' : 'text-slate-800'}`}>Select Tier:</span>
                  <span className={`text-[10px] font-mono flex items-center gap-1 font-bold ${isNight ? 'text-cyan-400' : 'text-cyan-600'}`}>
                    <Sparkles size={11} /> 3 Free Trial Scans Included
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  {/* 1. Free Trial Card */}
                  <button
                    type="button"
                    onClick={() => setPlanId('trial')}
                    className={`p-3 rounded-2xl border text-left transition-all cursor-pointer relative overflow-hidden ${
                      planId === 'trial'
                        ? 'border-cyan-400 ring-2 ring-cyan-400/50 bg-cyan-500/15 shadow-[0_0_20px_rgba(0,242,254,0.25)]'
                        : isNight ? 'border-white/10 bg-slate-900/60 hover:border-white/20' : 'border-slate-200 bg-white hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`text-xs font-black tracking-tight ${isNight ? 'text-white' : 'text-slate-900'}`}>
                        Free Trial
                      </span>
                      {planId === 'trial' && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500 text-slate-950 font-black">
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <div className={`text-lg font-black mt-1 ${isNight ? 'text-cyan-300' : 'text-cyan-700'}`}>
                      RM 0 <span className={`text-[10px] font-normal ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>forever</span>
                    </div>
                    <div className={`text-[10px] font-semibold mt-0.5 ${isNight ? 'text-cyan-200' : 'text-cyan-600'}`}>
                      {trialPlan.scanQuota || 3} Free AI Scans
                    </div>
                  </button>

                  {/* 2. Pro Card */}
                  <button
                    type="button"
                    onClick={() => setPlanId('pro')}
                    className={`p-3 rounded-2xl border text-left transition-all cursor-pointer relative overflow-hidden ${
                      planId === 'pro'
                        ? 'border-cyan-400 ring-2 ring-cyan-400/50 bg-cyan-500/15 shadow-[0_0_20px_rgba(0,242,254,0.25)]'
                        : isNight ? 'border-white/10 bg-slate-900/60 hover:border-white/20' : 'border-slate-200 bg-white hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`text-xs font-black tracking-tight ${isNight ? 'text-white' : 'text-slate-900'}`}>
                        Pro Plan
                      </span>
                      {planId === 'pro' ? (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500 text-slate-950 font-black">
                          SELECTED
                        </span>
                      ) : (
                        <span className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">
                          POPULAR
                        </span>
                      )}
                    </div>
                    <div className={`text-lg font-black mt-1 ${isNight ? 'text-cyan-300' : 'text-cyan-700'}`}>
                      RM {proPlan.priceMonthly}<span className={`text-[10px] font-normal ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>/mo</span>
                    </div>
                    <div className={`text-[10px] mt-0.5 ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>50 Scans • 5 Repos</div>
                  </button>

                  {/* 3. Enterprise Card */}
                  <button
                    type="button"
                    onClick={() => setPlanId('enterprise')}
                    className={`p-3 rounded-2xl border text-left transition-all cursor-pointer relative overflow-hidden ${
                      planId === 'enterprise'
                        ? 'border-purple-400 ring-2 ring-purple-400/50 bg-purple-500/15 shadow-[0_0_20px_rgba(168,85,247,0.25)]'
                        : isNight ? 'border-white/10 bg-slate-900/60 hover:border-white/20' : 'border-slate-200 bg-white hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`text-xs font-black tracking-tight ${isNight ? 'text-white' : 'text-slate-900'}`}>
                        Enterprise
                      </span>
                      {planId === 'enterprise' ? (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500 text-white font-black">
                          SELECTED
                        </span>
                      ) : (
                        <span className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">
                          VIP
                        </span>
                      )}
                    </div>
                    <div className={`text-lg font-black mt-1 ${isNight ? 'text-purple-300' : 'text-purple-700'}`}>
                      RM {entPlan.priceMonthly}<span className={`text-[10px] font-normal ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>/mo</span>
                    </div>
                    <div className={`text-[10px] mt-0.5 ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>Unlimited • 1-on-1</div>
                  </button>
                </div>

                <div className={`text-center pt-1 text-[11px] font-medium ${isNight ? 'text-cyan-300/90' : 'text-cyan-700'}`}>
                  {planId === 'trial'
                    ? '✨ Free Trial: 3 Full AI Security Scans • Instant Access • No Card Required'
                    : `✨ Selected: ${planId === 'pro' ? 'SentinelAI Pro (RM ' + proPlan.priceMonthly + '/mo)' : 'SentinelAI Enterprise (RM ' + entPlan.priceMonthly + '/mo)'} — activate via DuitNow QR or Card in dashboard`}
                </div>
              </div>
            )
          })()}

          {err && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 font-semibold flex items-center gap-2">
              <AlertCircle size={14} className="shrink-0 text-rose-400" />
              <span>{err}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="btn-primary w-full justify-center py-3 text-xs font-extrabold shadow-glow hover:scale-[1.01] active:scale-[0.99] transition-all cursor-pointer mt-2"
          >
            {busy && <Loader2 size={15} className="animate-spin" />}
            {busy
              ? (mode === 'login' ? 'Authenticating...' : 'Creating Account...')
              : (mode === 'login'
                  ? 'Sign In to Operations Center'
                  : 'Create Free Account & Start Testing (3 Free Scans)')}
          </button>
        </form>
      </div>
    </div>
  )
}
