import React, { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Loader2, KeyRound, User, Eye, EyeOff, Sparkles,
  Mail, Check, AlertCircle, Sun, Moon
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import { useAuth } from '../lib/AuthContext.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'
import { api, setToken } from '../lib/api.js'

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

  // Clear inputs on mode switch
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
    <div className={`min-h-screen flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden selection:bg-purple-500 selection:text-white transition-colors ${
      isNight ? 'bg-[#090b14]' : 'bg-[#f8fafc]'
    }`}>

      {/* Top-Right Theme Switcher Button */}
      <button
        type="button"
        onClick={toggleNightMode}
        className={`fixed top-5 right-5 z-50 inline-flex items-center gap-2 px-3.5 py-2 rounded-full border text-xs font-bold transition-all duration-300 shadow-xl cursor-pointer active:scale-95 ${
          isNight
            ? 'bg-slate-900/80 border-white/15 text-slate-200 hover:text-white hover:border-purple-400/50'
            : 'bg-white/95 border-slate-300 text-slate-800 hover:text-purple-600 hover:border-purple-500'
        }`}
        title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        aria-label="Toggle Theme"
      >
        {isNight ? (
          <>
            <Sun size={15} className="text-amber-400" />
            <span>Light Mode</span>
          </>
        ) : (
          <>
            <Moon size={15} className="text-purple-600" />
            <span>Dark Mode</span>
          </>
        )}
      </button>

      {/* Ambient Glowing Spotlights */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-purple-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[350px] h-[350px] bg-violet-500/10 rounded-full blur-[90px] pointer-events-none" />

      {/* Main Unified Login Card */}
      <div className="w-full max-w-[460px] relative z-10 my-auto motion-fade-up">
        
        {/* Card Header & Brand */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-gradient-to-b from-purple-950/60 to-slate-900/90 border border-purple-500/30 shadow-[0_0_30px_rgba(168,85,247,0.25)] mb-3 relative group">
            <InspectorLogo size={42} />
          </div>
          <div className="flex items-center justify-center gap-2">
            <h1 className="text-2xl font-black tracking-tight text-white">
              Sentinel<span className="text-purple-400">AI</span>
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold">
              v2.4
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1.5">
            {mode === 'login'
              ? 'Sign in to access autonomous offensive security operations'
              : 'Create an account to start pentesting with 3 free scans'}
          </p>
        </div>

        {/* Unified Card Container */}
        <div className={`rounded-3xl border p-6 sm:p-8 backdrop-blur-2xl transition-all duration-300 shadow-2xl relative ${
          isNight
            ? 'bg-[#0f121e]/90 border-purple-500/20 shadow-[0_20px_60px_rgba(0,0,0,0.8),0_0_30px_rgba(168,85,247,0.08)] text-slate-100'
            : 'bg-white border-slate-200 text-slate-900 shadow-xl shadow-slate-200/50'
        }`}>

          {/* Mode Switcher Tabs */}
          <div className={`flex rounded-2xl p-1 border mb-6 transition-colors ${
            isNight ? 'bg-[#090b14] border-white/10' : 'bg-slate-100 border-slate-200'
          }`}>
            <button
              type="button"
              onClick={() => { setMode('login'); setErr('') }}
              className={`flex-1 py-2 text-xs font-bold rounded-xl transition-all cursor-pointer ${
                mode === 'login'
                  ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/30'
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
                  ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/30'
                  : isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-950'
              }`}
            >
              Create Account
            </button>
          </div>

          {/* Form */}
          <form onSubmit={submit} autoComplete="off" className="space-y-4">
            {/* Hidden Dummy Inputs to prevent Chrome/Edge from autofilling saved credentials */}
            <input type="text" name="fakeusernameremembered" style={{ display: 'none' }} tabIndex={-1} autoComplete="off" />
            <input type="password" name="fakepasswordremembered" style={{ display: 'none' }} tabIndex={-1} autoComplete="off" />

            <div className="space-y-1.5">
              <label className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                isNight ? 'text-slate-300' : 'text-slate-700'
              }`}>
                <User size={13} className={isNight ? 'text-purple-400' : 'text-purple-500'} /> Username or Email
              </label>
              <input
                name="sentinel_auth_user"
                className={`input py-2.5 text-sm transition-all focus:border-purple-400 focus:ring-2 focus:ring-purple-400/20 w-full ${
                  isNight
                    ? 'text-slate-100 bg-[#141829] border-white/10 placeholder-slate-500'
                    : 'text-slate-900 bg-slate-50 border-slate-300 placeholder-slate-400 font-medium'
                }`}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username or email"
                autoComplete="new-password"
                required
              />
            </div>

            {mode === 'register' && (
              <div className="space-y-1.5">
                <label className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                  isNight ? 'text-slate-300' : 'text-slate-700'
                }`}>
                  <Mail size={13} className={isNight ? 'text-purple-400' : 'text-purple-500'} /> Email Address
                </label>
                <input
                  name="sentinel_auth_email"
                  type="email"
                  className={`input py-2.5 text-sm transition-all focus:border-purple-400 focus:ring-2 focus:ring-purple-400/20 w-full ${
                    isNight
                      ? 'text-slate-100 bg-[#141829] border-white/10 placeholder-slate-500'
                      : 'text-slate-900 bg-slate-50 border-slate-300 placeholder-slate-400 font-medium'
                  }`}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@organization.com"
                  autoComplete="off"
                  required
                />
              </div>
            )}

            <div className="space-y-1.5">
              <label className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                isNight ? 'text-slate-300' : 'text-slate-700'
              }`}>
                <KeyRound size={13} className={isNight ? 'text-purple-400' : 'text-purple-500'} /> Password
              </label>
              <div className="relative flex items-center">
                <input
                  name="sentinel_auth_pass"
                  type={showPassword ? 'text' : 'password'}
                  className={`input py-2.5 pr-11 text-sm transition-all focus:border-purple-400 focus:ring-2 focus:ring-purple-400/20 w-full ${
                    isNight
                      ? 'text-slate-100 bg-[#141829] border-white/10 placeholder-slate-500'
                      : 'text-slate-900 bg-slate-50 border-slate-300 placeholder-slate-400 font-medium'
                  }`}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  autoComplete="new-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className={`absolute right-3 p-1 rounded-lg transition-colors focus:outline-none ${
                    isNight ? 'hover:bg-white/10 text-slate-400 hover:text-purple-300' : 'hover:bg-slate-200 text-slate-500 hover:text-purple-600'
                  }`}
                  title={showPassword ? 'Hide password' : 'Reveal password'}
                >
                  {showPassword ? (
                    <Eye size={16} className={isNight ? 'text-purple-400' : 'text-purple-500'} />
                  ) : (
                    <EyeOff size={16} className="text-slate-400" />
                  )}
                </button>
              </div>
            </div>

            {/* Registration Tier Selection */}
            {mode === 'register' && (() => {
              const proPlan = plans.find(p => p.id === 'pro') || { name: 'Pro Plan', priceMonthly: 20 }
              const entPlan = plans.find(p => p.id === 'enterprise') || { name: 'Enterprise', priceMonthly: 80 }

              return (
                <div className={`space-y-2 pt-2 border-t ${isNight ? 'border-white/10' : 'border-slate-200'}`}>
                  <div className="text-xs">
                    <span className={`font-bold ${isNight ? 'text-slate-200' : 'text-slate-800'}`}>Select Plan:</span>
                  </div>

                  <div className="grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      onClick={() => setPlanId('trial')}
                      className={`p-2 rounded-xl border text-center transition-all cursor-pointer ${
                        planId === 'trial'
                          ? 'border-purple-400 bg-purple-500/20 shadow-[0_0_15px_rgba(168,85,247,0.2)] text-white'
                          : isNight ? 'border-white/10 bg-slate-900/40 text-slate-400 hover:border-white/20' : 'border-slate-200 bg-white text-slate-600'
                      }`}
                    >
                      <div className="text-[11px] font-bold">Trial</div>
                      <div className="text-xs font-black text-purple-300 mt-0.5">RM 0</div>
                    </button>

                    <button
                      type="button"
                      onClick={() => setPlanId('pro')}
                      className={`p-2 rounded-xl border text-center transition-all cursor-pointer ${
                        planId === 'pro'
                          ? 'border-purple-400 bg-purple-500/20 shadow-[0_0_15px_rgba(168,85,247,0.2)] text-white'
                          : isNight ? 'border-white/10 bg-slate-900/40 text-slate-400 hover:border-white/20' : 'border-slate-200 bg-white text-slate-600'
                      }`}
                    >
                      <div className="text-[11px] font-bold">Pro</div>
                      <div className="text-xs font-black text-purple-300 mt-0.5">RM {proPlan.priceMonthly}</div>
                    </button>

                    <button
                      type="button"
                      onClick={() => setPlanId('enterprise')}
                      className={`p-2 rounded-xl border text-center transition-all cursor-pointer ${
                        planId === 'enterprise'
                          ? 'border-purple-400 bg-purple-500/20 shadow-[0_0_15px_rgba(168,85,247,0.2)] text-white'
                          : isNight ? 'border-white/10 bg-slate-900/40 text-slate-400 hover:border-white/20' : 'border-slate-200 bg-white text-slate-600'
                      }`}
                    >
                      <div className="text-[11px] font-bold">Enterprise</div>
                      <div className="text-xs font-black text-purple-300 mt-0.5">RM {entPlan.priceMonthly}</div>
                    </button>
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

            {/* Submit Button */}
            <button
              type="submit"
              disabled={busy}
              className="btn-shine w-full justify-center py-3 text-xs font-extrabold shadow-glow hover:scale-[1.01] active:scale-[0.99] transition-all cursor-pointer mt-2 flex items-center gap-2"
            >
              {busy ? (
                <>
                  <Loader2 size={15} className="animate-spin" />
                  <span>{mode === 'login' ? 'Authenticating...' : 'Creating Account...'}</span>
                </>
              ) : (
                <span>{mode === 'login' ? 'Sign In to Platform' : 'Create Free Account'}</span>
              )}
            </button>
          </form>
        </div>

      </div>
    </div>
  )
}
