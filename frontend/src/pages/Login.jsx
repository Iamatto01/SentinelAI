import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { ArrowLeft, Loader2, ShieldCheck, KeyRound, User, EyeOff, Sparkles } from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import { useAuth } from '../lib/AuthContext.jsx'

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
  const { login } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  async function submit(e) {
    e.preventDefault()
    setErr(''); setBusy(true)
    try {
      await login(username.trim(), password)
      nav(loc.state?.from?.pathname || '/app/dashboard', { replace: true })
    } catch (e2) {
      setErr(e2.message || 'Login failed')
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

      {/* Main Centered Login Container */}
      <div className="w-full max-w-md relative z-10 my-auto motion-fade-up">
        {/* Header Logo & Title */}
        <div className="flex flex-col items-center mb-8 text-center">
          <div className="relative mb-4 group">
            <div className="absolute -inset-3 rounded-full bg-gradient-to-r from-cyan-400 via-blue-600 to-purple-600 opacity-60 blur-xl group-hover:opacity-90 transition duration-500" />
            <div className="relative">
              <InspectorLogo size={68} />
            </div>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">SentinelAI</h1>
          <p className="text-[10px] uppercase tracking-[0.25em] text-cyan-400 font-extrabold mt-1.5 flex items-center gap-1.5 justify-center">
            <Sparkles size={12} className="text-cyan-300 animate-pulse" /> Vision Security Suite
          </p>
        </div>

        {/* Vision UI Form Card */}
        <form onSubmit={submit} className="glass rounded-3xl border border-white/20 p-7 sm:p-8 shadow-2xl space-y-5 relative">
          <div className="space-y-1.5">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <User size={14} className="text-cyan-400" /> Username
            </label>
            <div className="relative">
              <input
                className="input py-3 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                placeholder="Enter username"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <KeyRound size={14} className="text-cyan-400" /> Password
            </label>
            <div className="relative flex items-center">
              <input
                type={showPassword ? 'text' : 'password'}
                className="input py-3 pr-11 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="••••••••"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 p-1 rounded-lg hover:bg-white/10 text-slate-400 hover:text-cyan-300 transition-colors focus:outline-none"
                title={showPassword ? 'Hide password' : 'Reveal password'}
              >
                {showPassword ? <EyeCursorTracker /> : <EyeOff size={18} className="text-slate-400" />}
              </button>
            </div>
          </div>

          {err && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-xs text-rose-300 font-semibold">
              {err}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="btn-primary w-full justify-center py-3.5 text-sm font-extrabold shadow-glow hover:scale-[1.01] active:scale-[0.99] transition-all cursor-pointer"
          >
            {busy && <Loader2 size={16} className="animate-spin" />}
            {busy ? 'Authenticating...' : 'Sign In to Operations Center'}
          </button>
        </form>
      </div>
    </div>
  )
}



