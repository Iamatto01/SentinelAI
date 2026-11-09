import React, { useState, useEffect } from 'react'

import { useNavigate, useLocation, Link } from 'react-router-dom'

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

  const [rememberMe, setRememberMe] = useState(() => {

    try {

      const storedPref = localStorage.getItem('sentinel_remember_me')

      if (storedPref !== null) return storedPref === 'true'

      return true

    } catch {

      return true

    }

  })

  const [username, setUsername] = useState(() => {

    try {

      return localStorage.getItem('sentinel_remember_username') || ''

    } catch {

      return ''

    }

  })

  const [email, setEmail] = useState('')

  const [password, setPassword] = useState('')

  const [planId, setPlanId] = useState(initialPlan)

  const [interval, setInterval] = useState(initialInterval)

  const [plans, setPlans] = useState([])

  const [showPassword, setShowPassword] = useState(false)

  const [busy, setBusy] = useState(false)

  const [agreeTerms, setAgreeTerms] = useState(true)

  const [err, setErr] = useState('')



  useEffect(() => {

    fetch('/api/billing/plans')

      .then(r => r.ok ? r.json() : null)

      .then(d => {

        if (d?.plans?.length) {

          setPlans(d.plans)

          // If current selection is not valid in active plans, select first or popular

          setPlanId(prev => {

            if (d.plans.some(p => p.id === prev)) return prev

            const pop = d.plans.find(p => p.isPopular || p.is_popular)

            return pop ? pop.id : d.plans[0].id

          })

        }

      })

      .catch(() => {})

  }, [])



  // Restore remembered username on sign-in mode or reset for registration

  useEffect(() => {

    setPassword('')

    setErr('')

    if (mode === 'login') {

      try {

        const saved = localStorage.getItem('sentinel_remember_username')

        if (saved) {

          setUsername(saved)

        }

      } catch {}

    } else {

      setUsername('')

      setEmail('')

    }

  }, [mode])



  async function submit(e) {

    e.preventDefault()

    setErr('')

    setBusy(true)



    // Capture values from either DOM form elements (essential for instant browser autofill) or component state

    const formEl = e.currentTarget

    const formUser = formEl?.elements?.username?.value

    const formPass = formEl?.elements?.password?.value

    const formEmail = formEl?.elements?.email?.value



    const finalUsername = (typeof formUser === 'string' && formUser.trim() ? formUser : username).trim()

    const finalPassword = typeof formPass === 'string' && formPass ? formPass : password

    const finalEmail = (typeof formEmail === 'string' && formEmail.trim() ? formEmail : email).trim()



    if (finalUsername !== username) setUsername(finalUsername)

    if (finalPassword !== password) setPassword(finalPassword)



    try {

      if (mode === 'login') {

        await login(finalUsername, finalPassword, rememberMe)

        try {

          if (rememberMe) {

            localStorage.setItem('sentinel_remember_username', finalUsername)

            localStorage.setItem('sentinel_remember_me', 'true')

          } else {

            localStorage.removeItem('sentinel_remember_username')

            localStorage.setItem('sentinel_remember_me', 'false')

          }

        } catch {

          // ignore storage error if cookies/storage blocked

        }

        sessionStorage.setItem('sentinel_gate_trigger', 'true')

        nav(loc.state?.from?.pathname || '/app/dashboard', { replace: true })

      } else {

        if (!agreeTerms) {

          setErr('Please agree to the Terms of Service & Anti-Reverse Engineering Policy to continue.')

          setBusy(false)

          return

        }

        const res = await api.register({

          username: finalUsername,

          email: finalEmail,

          password: finalPassword,

          planId: planId || 'trial',

          billingInterval: interval,

          paymentProvider: 'stripe',

        })

        setToken(res.token, true)

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

    <div className={`min-h-screen flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden font-sans transition-colors duration-500 ${

      isNight

        ? 'bg-black text-white selection:bg-white selection:text-black'

        : 'bg-[#FAFAFA] text-zinc-950 selection:bg-black selection:text-white'

    }`}>

      {/* Top Overhead Spotlight */}

      <div

        className="pointer-events-none absolute inset-x-0 top-0 h-[500px] -translate-y-1/3 opacity-30 blur-3xl z-0"

        style={{

          background: isNight

            ? 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.25), transparent 75%)'

            : 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,0,0,0.08), transparent 75%)',

        }}

      />



      {/* Subtle Architectural Wireframe / Dot-Matrix Grid */}

      <div

        className="pointer-events-none absolute inset-0 opacity-[0.035] z-0"

        style={{

          backgroundImage: isNight

            ? 'linear-gradient(to right, #ffffff 1px, transparent 1px), linear-gradient(to bottom, #ffffff 1px, transparent 1px)'

            : 'linear-gradient(to right, #000000 1px, transparent 1px), linear-gradient(to bottom, #000000 1px, transparent 1px)',

          backgroundSize: '50px 50px',

          maskImage: 'radial-gradient(ellipse 80% 70% at 50% 50%, black 40%, transparent 90%)',

          WebkitMaskImage: 'radial-gradient(ellipse 80% 70% at 50% 50%, black 40%, transparent 90%)',

        }}

      />



      {/* Top-Left Back Button */}

      <Link

        to="/"

        className={`fixed top-5 left-5 z-50 inline-flex items-center px-4 py-2 rounded-xl border text-xs font-mono font-bold transition-all duration-300 cursor-pointer active:scale-95 ${

          isNight

            ? 'border-white/10 bg-[#0A0A0A]/90 text-neutral-300 hover:text-white hover:border-white/30 backdrop-blur-md'

            : 'border-zinc-300 bg-white/90 text-zinc-700 hover:text-black hover:border-zinc-400 backdrop-blur-md shadow-sm'

        }`}

        aria-label="Back to Landing Page"

      >

        Back to Landing Page

      </Link>



      {/* Top-Right Theme Switcher Button */}

      <button

        type="button"

        onClick={toggleNightMode}

        className={`fixed top-5 right-5 z-50 inline-flex items-center gap-2 px-3.5 py-2 rounded-xl border text-xs font-mono font-bold transition-all duration-300 cursor-pointer active:scale-95 ${

          isNight

            ? 'border-white/10 bg-[#0A0A0A]/90 text-neutral-300 hover:text-white hover:border-white/30 backdrop-blur-md'

            : 'border-zinc-300 bg-white/90 text-zinc-700 hover:text-black hover:border-zinc-400 backdrop-blur-md shadow-sm'

        }`}

        title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}

        aria-label="Toggle Theme"

      >

        {isNight ? (

          <>

            <Sun size={15} className="text-white hover:rotate-90 transition-transform duration-300" />

            <span>Light</span>

          </>

        ) : (

          <>

            <Moon size={15} className="text-black hover:-rotate-12 transition-transform duration-300" />

            <span>Dark</span>

          </>

        )}

      </button>



      {/* Main Unified Login Card */}

      <div className="w-full max-w-[460px] relative z-10 my-auto motion-fade-up">

        

        {/* Card Header & Brand */}

        <div className="text-center mb-6">

          <div className={`inline-flex items-center justify-center p-3 rounded-2xl border mb-3 relative group ${

            isNight

              ? 'border-white/20 bg-white/5'

              : 'border-zinc-300 bg-black/5'

          }`}>

            <InspectorLogo size={42} variant="base" className={isNight ? 'text-white' : 'text-black'} />

          </div>

          <div className="flex items-center justify-center gap-2">

            <h1 className={`text-2xl font-black tracking-tight font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>

              Sentinel<span className={isNight ? 'text-neutral-400' : 'text-zinc-500'}>AI</span>

            </h1>

            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold ${

              isNight

                ? 'border-white/20 bg-white/10 text-neutral-300'

                : 'border-zinc-300 bg-zinc-100 text-zinc-700'

            }`}>FYP 2</span>

          </div>

          <p className={`text-xs font-mono mt-1.5 ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>

            {mode === 'login'

              ? 'Sign in to access autonomous offensive security operations'

              : 'Create an account to start pentesting with 3 free scans'}

          </p>

        </div>



        {/* Unified Card Container */}

        <div className={`rounded-3xl border p-6 sm:p-8 backdrop-blur-2xl transition-all duration-300 shadow-2xl relative ${

          isNight

            ? 'bg-[#0A0A0A] border-white/10 shadow-[0_20px_60px_rgba(0,0,0,0.9)] text-white'

            : 'bg-white border-zinc-200 text-zinc-950 shadow-xl shadow-zinc-200/50'

        }`}>



          {/* Mode Switcher Tabs */}

          <div className={`flex rounded-2xl p-1 border mb-6 font-mono text-xs transition-colors ${

            isNight ? 'bg-black border-white/10' : 'bg-zinc-100 border-zinc-200'

          }`}>

            <button

              type="button"

              onClick={() => { setMode('login'); setErr('') }}

              className={`flex-1 py-2 rounded-xl font-bold transition-all cursor-pointer ${

                mode === 'login'

                  ? isNight

                    ? 'bg-white text-black font-black shadow-md'

                    : 'bg-black text-white !text-white font-black shadow-md'

                  : isNight

                    ? 'text-neutral-400 hover:text-white'

                    : 'text-zinc-600 hover:text-black'

              }`}

            >

              Sign In

            </button>

            <button

              type="button"

              onClick={() => { setMode('register'); setErr('') }}

              className={`flex-1 py-2 rounded-xl font-bold transition-all cursor-pointer ${

                mode === 'register'

                  ? isNight

                    ? 'bg-white text-black font-black shadow-md'

                    : 'bg-black text-white !text-white font-black shadow-md'

                  : isNight

                    ? 'text-neutral-400 hover:text-white'

                    : 'text-zinc-600 hover:text-black'

              }`}

            >

              Create Account

            </button>

          </div>



          {/* Form */}

          <form onSubmit={submit} method="POST" autoComplete="on" className="space-y-4">

            <div className="space-y-1.5 font-mono">

              <label htmlFor="username" className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${

                isNight ? 'text-neutral-300' : 'text-zinc-700'

              }`}>

                <User size={13} className={isNight ? 'text-neutral-400' : 'text-zinc-500'} /> Username or Email

              </label>

              <input

                id="username"

                name="username"

                type="text"

                className={`py-2.5 px-3 rounded-xl border text-sm transition-all w-full font-mono focus:outline-none ${

                  isNight

                    ? 'text-white bg-black border-white/15 placeholder-neutral-600 focus:border-white focus:ring-1 focus:ring-white/20'

                    : 'text-zinc-950 bg-zinc-50 border-zinc-300 placeholder-zinc-400 focus:border-black focus:ring-1 focus:ring-black/20'

                }`}

                value={username}

                onChange={(e) => setUsername(e.target.value)}

                placeholder="Enter your username or email"

                autoComplete="username"

                autoCapitalize="none"

                autoCorrect="off"

                spellCheck="false"

                required

              />

            </div>



            {mode === 'register' && (

              <div className="space-y-1.5 font-mono">

                <label htmlFor="email" className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${

                  isNight ? 'text-neutral-300' : 'text-zinc-700'

                }`}>

                  <Mail size={13} className={isNight ? 'text-neutral-400' : 'text-zinc-500'} /> Email Address

                </label>

                <input

                  id="email"

                  name="email"

                  type="email"

                  className={`py-2.5 px-3 rounded-xl border text-sm transition-all w-full font-mono focus:outline-none ${

                    isNight

                      ? 'text-white bg-black border-white/15 placeholder-neutral-600 focus:border-white focus:ring-1 focus:ring-white/20'

                      : 'text-zinc-950 bg-zinc-50 border-zinc-300 placeholder-zinc-400 focus:border-black focus:ring-1 focus:ring-black/20'

                  }`}

                  value={email}

                  onChange={(e) => setEmail(e.target.value)}

                  placeholder="analyst@organization.com"

                  autoComplete="email"

                  required

                />

              </div>

            )}



            <div className="space-y-1.5 font-mono">

              <label htmlFor="password" className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${

                isNight ? 'text-neutral-300' : 'text-zinc-700'

              }`}>

                <KeyRound size={13} className={isNight ? 'text-neutral-400' : 'text-zinc-500'} /> Password

              </label>

              <div className="relative flex items-center">

                <input

                  id="password"

                  name="password"

                  type={showPassword ? 'text' : 'password'}

                  className={`py-2.5 pl-3 pr-11 rounded-xl border text-sm transition-all w-full font-mono focus:outline-none ${

                    isNight

                      ? 'text-white bg-black border-white/15 placeholder-neutral-600 focus:border-white focus:ring-1 focus:ring-white/20'

                      : 'text-zinc-950 bg-zinc-50 border-zinc-300 placeholder-zinc-400 focus:border-black focus:ring-1 focus:ring-black/20'

                  }`}

                  value={password}

                  onChange={(e) => setPassword(e.target.value)}

                  placeholder="••••••••••••"

                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}

                  required

                />

                <button

                  type="button"

                  onClick={() => setShowPassword(!showPassword)}

                  className={`absolute right-3 p-1 rounded-lg transition-colors focus:outline-none cursor-pointer ${

                    isNight ? 'hover:bg-white/10 text-neutral-400 hover:text-white' : 'hover:bg-zinc-200 text-zinc-500 hover:text-black'

                  }`}

                  title={showPassword ? 'Hide password' : 'Reveal password'}

                >

                  {showPassword ? (

                    <Eye size={16} className={isNight ? 'text-white' : 'text-black'} />

                  ) : (

                    <EyeOff size={16} className={isNight ? 'text-neutral-500' : 'text-zinc-400'} />

                  )}

                </button>

              </div>

            </div>



            {/* Remember Me Checkbox (Sign In mode) */}

            {mode === 'login' && (

              <div className="flex items-center justify-between pt-0.5 font-mono">

                <label className="flex items-center gap-2 cursor-pointer select-none group">

                  <input

                    id="remember_me"

                    name="remember_me"

                    type="checkbox"

                    checked={rememberMe}

                    onChange={(e) => setRememberMe(e.target.checked)}

                    className={`h-4 w-4 rounded cursor-pointer transition-colors accent-black dark:accent-white ${

                      isNight

                        ? 'border-white/20 bg-black/60 focus:ring-0 checked:bg-white'

                        : 'border-zinc-300 bg-zinc-50 focus:ring-0 checked:bg-black'

                    }`}

                  />

                  <span className={`text-xs font-bold transition-colors ${

                    isNight

                      ? 'text-neutral-300 group-hover:text-white'

                      : 'text-zinc-700 group-hover:text-black'

                  }`}>

                    Remember me

                  </span>

                </label>

              </div>

            )}



            {/* Registration Tier Selection (Dynamically synced with Admin Settings) */}

            {mode === 'register' && (() => {

              const displayPlans = plans.length > 0 ? plans : [

                { id: 'trial', name: 'Free Trial', priceMonthly: 0, currency: 'MYR', scanQuota: 3 },

                { id: 'pay_per_scan', name: 'Pay-Per-Scan', priceMonthly: 3, currency: 'MYR', scanQuota: 1 },

                { id: 'pro', name: 'SentinelAI Pro', priceMonthly: 20, currency: 'MYR', scanQuota: 50, isPopular: true },

                { id: 'enterprise', name: 'SentinelAI Enterprise', priceMonthly: 80, currency: 'MYR', scanQuota: 250 },

              ]



              const cleanName = (p) => {

                const n = p.name || p.id

                return n.replace(/^SentinelAI\s+/i, '')

              }



              return (

                <div className={`space-y-2 pt-2 border-t font-mono ${isNight ? 'border-white/10' : 'border-zinc-200'}`}>

                  <div className="flex items-center justify-between text-xs">

                    <span className={`font-bold ${isNight ? 'text-neutral-200' : 'text-zinc-800'}`}>Select Plan:</span>

                    <span className={`text-[10px] ${isNight ? 'text-neutral-500' : 'text-zinc-500'}`}>Live Synced</span>

                  </div>



                  <div className={`grid gap-2 ${

                    displayPlans.length === 2 ? 'grid-cols-2' :

                    displayPlans.length === 3 ? 'grid-cols-3' :

                    displayPlans.length === 4 ? 'grid-cols-2 sm:grid-cols-4' :

                    'grid-cols-2 sm:grid-cols-3'

                  }`}>

                    {displayPlans.map((p) => {

                      const isSelected = (planId || 'trial') === p.id

                      const price = p.priceMonthly ?? p.price_monthly ?? 0

                      const curr = p.currency || 'MYR'

                      const isPopular = p.isPopular || p.is_popular

                      const quota = p.scanQuota ?? p.scan_quota



                      return (

                        <button

                          key={p.id}

                          type="button"

                          onClick={() => setPlanId(p.id)}

                          className={`relative p-2 rounded-xl border text-center transition-all cursor-pointer flex flex-col justify-between items-center min-h-[58px] ${

                            isSelected

                              ? isNight

                                ? 'border-white bg-white text-black font-black ring-1 ring-white/50 shadow-md'

                                : 'border-black bg-black text-white !text-white font-black ring-1 ring-black/50 shadow-md'

                              : isNight

                                ? 'border-white/10 bg-black/60 text-neutral-400 hover:border-white/20 hover:text-white'

                                : 'border-zinc-200 bg-zinc-50 text-zinc-600 hover:border-zinc-400 hover:text-black'

                          }`}

                        >

                          {isPopular && (

                            <span className={`absolute -top-1.5 right-1 px-1.5 py-0.2 rounded-full text-[8px] font-black tracking-wider uppercase ${

                              isSelected

                                ? isNight ? 'bg-black text-white' : 'bg-white text-black'

                                : isNight ? 'bg-white text-black' : 'bg-black text-white !text-white'

                            }`}>

                              Popular

                            </span>

                          )}

                          <div className="text-[11px] font-bold truncate max-w-full">{cleanName(p)}</div>

                          <div className={`text-xs font-black mt-0.5 ${

                            isSelected

                              ? isNight ? 'text-black' : 'text-white !text-white'

                              : isNight ? 'text-white' : 'text-zinc-950'

                          }`}>

                            {price === 0 ? 'Free' : `${curr === 'USD' ? '$' : 'RM '}${price}`}

                          </div>

                          {quota !== undefined && quota > 0 && (

                            <div className={`text-[9px] font-mono mt-0.5 ${

                              isSelected

                                ? isNight ? 'text-neutral-700' : 'text-zinc-300'

                                : isNight ? 'text-neutral-500' : 'text-zinc-500'

                            }`}>

                              {quota} {quota === 1 ? 'scan' : 'scans'}

                            </div>

                          )}

                        </button>

                      )

                    })}

                  </div>

                </div>

              )

            })()}



            {err && (

              <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 font-semibold flex items-center gap-2 font-mono">

                <AlertCircle size={14} className="shrink-0 text-rose-400" />

                <span>{err}</span>

              </div>

            )}



            {mode === 'register' && (

              <label className="flex items-start gap-2.5 pt-1 text-left cursor-pointer select-none">

                <input

                  type="checkbox"

                  checked={agreeTerms}

                  onChange={(e) => setAgreeTerms(e.target.checked)}

                  className="mt-0.5 h-3.5 w-3.5 rounded border-white/20 bg-white/5 text-cyan-400 focus:ring-0 cursor-pointer shrink-0"

                />

                <span className={`text-[11px] leading-tight font-sans ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>

                  I agree to the{' '}

                  <Link to="/terms" target="_blank" rel="noopener noreferrer" className={`underline font-bold ${isNight ? 'text-neutral-200 hover:text-white' : 'text-zinc-900 hover:text-black'}`}>

                    Terms of Service &amp; Anti-RE Policy

                  </Link>

                  {' '}and{' '}

                  <Link to="/privacy" target="_blank" rel="noopener noreferrer" className={`underline font-bold ${isNight ? 'text-neutral-200 hover:text-white' : 'text-zinc-900 hover:text-black'}`}>

                    Privacy Policy

                  </Link>.

                </span>

              </label>

            )}



            {/* Submit Button */}

            <button

              type="submit"

              disabled={busy}

              className={`w-full justify-center py-3 rounded-xl text-xs font-mono font-black uppercase tracking-wider transition-all hover:scale-[1.01] active:scale-[0.99] cursor-pointer mt-2 flex items-center gap-2 ${

                isNight

                  ? 'bg-white text-black hover:bg-neutral-200 shadow-[0_0_25px_rgba(255,255,255,0.25)]'

                  : 'bg-black text-white !text-white hover:bg-zinc-800 shadow-[0_0_20px_rgba(0,0,0,0.25)]'

              }`}

            >

              {busy ? (

                <>

                  <Loader2 size={15} className={`animate-spin ${isNight ? 'text-black' : 'text-white !text-white'}`} />

                  <span className={isNight ? 'text-black' : 'text-white !text-white'}>

                    {mode === 'login' ? 'Authenticating...' : 'Creating Account...'}

                  </span>

                </>

              ) : (

                <span className={isNight ? 'text-black' : 'text-white !text-white'}>

                  {mode === 'login' ? 'Sign In to Platform' : 'Create Free Account'}

                </span>

              )}

            </button>

          </form>

        </div>



      </div>

    </div>

  )

}

