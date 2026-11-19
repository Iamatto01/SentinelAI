import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, Home, LayoutDashboard, Sparkles, Heart, Compass, Terminal, ShieldAlert } from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function NotFound() {
  const navigate = useNavigate()
  const { isNight } = useTheme()
  const [petCount, setPetCount] = useState(0)
  const [isBooped, setIsBooped] = useState(false)

  const cuteQuotes = [
    'Beep boop! I scanned ports 1 to 65535, but this page is nowhere to be found! (´・ω・｀)',
    '404: Packet lost in cyberspace! But don\'t worry, I\'ll guard you while you\'re lost~',
    'Did a firewall eat this page? Nom nom nom... (๑ᵔ⤙ᵔ๑)',
    '*happy robot noises* BEEP BEEP! You found a secret glitch zone! (≧◡≦) ♡',
    'Initiating emergency cuddle protocol (づ｡◕‿‿◕｡)づ Safe and secure!',
  ]

  const activeQuote = cuteQuotes[petCount % cuteQuotes.length]

  function handleBoop() {
    setIsBooped(true)
    setPetCount(prev => prev + 1)
    setTimeout(() => setIsBooped(false), 600)
  }

  return (
    <PublicLayout>
      <div className="min-h-[85vh] flex items-center justify-center px-4 py-16 relative">
        {/* Ambient background glow */}
        <div className="absolute inset-0 pointer-events-none flex items-center justify-center overflow-hidden">
          <div className={`w-96 h-96 rounded-full blur-3xl opacity-25 ${
            isNight ? 'bg-cyan-500/30' : 'bg-purple-400/30'
          }`} />
          <div className={`w-72 h-72 rounded-full blur-3xl opacity-20 -translate-x-32 translate-y-24 ${
            isNight ? 'bg-pink-500/20' : 'bg-pink-300/30'
          }`} />
        </div>

        <div className="relative z-10 max-w-xl w-full text-center flex flex-col items-center">
          
          {/* Animated Cute Cyber Bot */}
          <div className="relative mb-6 cursor-pointer select-none group" onClick={handleBoop} title="Click to boop the bot!">
            {/* Boop Hearts Burst */}
            {isBooped && (
              <div className="absolute -top-8 inset-x-0 flex justify-center items-center gap-2 animate-bounce pointer-events-none">
                <span className="text-xl">💖</span>
                <span className="text-sm font-bold text-pink-400 font-mono">+1 Boop!</span>
                <span className="text-xl">✨</span>
              </div>
            )}

            {/* SVG Mascot */}
            <div className={`w-44 h-44 sm:w-52 sm:h-52 mx-auto transition-transform duration-300 ${
              isBooped ? 'scale-110 rotate-3' : 'hover:scale-105'
            }`}>
              <svg viewBox="0 0 200 200" className="w-full h-full drop-shadow-2xl">
                <defs>
                  <linearGradient id="botGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="50%" stopColor="#818cf8" />
                    <stop offset="100%" stopColor="#c084fc" />
                  </linearGradient>
                  <linearGradient id="bodyGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" stopColor={isNight ? '#1e293b' : '#ffffff'} />
                    <stop offset="100%" stopColor={isNight ? '#0f172a' : '#f1f5f9'} />
                  </linearGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                </defs>

                {/* Floating Shadow */}
                <ellipse cx="100" cy="188" rx="45" ry="8" fill={isNight ? '#00000066' : '#cbd5e166'} className="animate-pulse" />

                {/* Antenna */}
                <line x1="100" y1="52" x2="100" y2="30" stroke="#818cf8" strokeWidth="4" strokeLinecap="round" />
                <circle cx="100" cy="24" r="9" fill={isBooped ? '#ec4899' : '#38bdf8'} filter="url(#glow)" className="animate-pulse" />
                <circle cx="100" cy="24" r="4" fill="#ffffff" />

                {/* Left Ear / Audio Sensor */}
                <rect x="36" y="78" width="10" height="28" rx="5" fill="#818cf8" />
                <circle cx="41" cy="92" r="2.5" fill="#38bdf8" />

                {/* Right Ear / Audio Sensor */}
                <rect x="154" y="78" width="10" height="28" rx="5" fill="#818cf8" />
                <circle cx="159" cy="92" r="2.5" fill="#38bdf8" />

                {/* Robot Head Outer Box */}
                <rect
                  x="44" y="50" width="112" height="88" rx="28"
                  fill="url(#bodyGrad)"
                  stroke="url(#botGrad)"
                  strokeWidth="3.5"
                />

                {/* Visor Screen */}
                <rect
                  x="56" y="64" width="88" height="58" rx="18"
                  fill={isNight ? '#030712' : '#0f172a'}
                />

                {/* Cute Eyes - Dynamic blink / expression */}
                {isBooped ? (
                  // Happy Eyes: ^ ^
                  <g stroke="#38bdf8" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" fill="none">
                    <path d="M 72 94 Q 80 84 88 94" />
                    <path d="M 112 94 Q 120 84 128 94" />
                  </g>
                ) : (
                  // Normal Cute Big Sparkly Eyes
                  <g>
                    {/* Left Eye */}
                    <circle cx="78" cy="90" r="9" fill="#38bdf8" filter="url(#glow)" />
                    <circle cx="75" cy="87" r="3.5" fill="#ffffff" />
                    <circle cx="81" cy="93" r="1.5" fill="#ffffff" />

                    {/* Right Eye */}
                    <circle cx="122" cy="90" r="9" fill="#38bdf8" filter="url(#glow)" />
                    <circle cx="119" cy="87" r="3.5" fill="#ffffff" />
                    <circle cx="125" cy="93" r="1.5" fill="#ffffff" />
                  </g>
                )}

                {/* Cute Blushing Cheeks */}
                <ellipse cx="68" cy="107" rx="6" ry="3" fill="#f472b6" opacity={isBooped ? '0.9' : '0.5'} />
                <ellipse cx="132" cy="107" rx="6" ry="3" fill="#f472b6" opacity={isBooped ? '0.9' : '0.5'} />

                {/* Cute Smile / Mouth */}
                <path
                  d={isBooped ? "M 94 104 Q 100 114 106 104" : "M 95 106 Q 100 110 105 106"}
                  stroke="#ec4899"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  fill="none"
                />

                {/* Floating Body / Core */}
                <rect
                  x="68" y="144" width="64" height="34" rx="14"
                  fill="url(#bodyGrad)"
                  stroke="url(#botGrad)"
                  strokeWidth="3"
                />

                {/* Chest Badge / Little Heart */}
                <circle cx="100" cy="160" r="7" fill={isNight ? '#1e1b4b' : '#ede9fe'} />
                <path
                  d="M 100 163 C 97 159, 94 158, 97 155 C 99 153, 100 155, 100 156 C 100 155, 101 153, 103 155 C 106 158, 103 159, 100 163 Z"
                  fill="#ec4899"
                />

                {/* Left Floating Arm */}
                <rect x="52" y="148" width="12" height="22" rx="6" fill="#818cf8" transform="rotate(15 58 159)" />

                {/* Right Waving Arm */}
                <rect
                  x="136" y="148" width="12" height="22" rx="6" fill="#818cf8"
                  className={isBooped ? 'animate-bounce' : ''}
                  transform={isBooped ? 'rotate(-35 142 159)' : 'rotate(-15 142 159)'}
                />
              </svg>
            </div>

            {/* Tap Hint Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-medium transition-all bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 mt-1">
              <Heart size={12} className={petCount > 0 ? 'text-pink-400 fill-pink-400 animate-pulse' : 'text-purple-400'} />
              <span>{petCount === 0 ? 'Click to boop the cyber bot!' : `Booped ${petCount} time${petCount === 1 ? '' : 's'}!`}</span>
            </div>
          </div>

          {/* 404 Header Title */}
          <div className="space-y-2 mb-4">
            <div className="inline-block">
              <span className="text-6xl sm:text-7xl font-black tracking-tight bg-gradient-to-r from-cyan-400 via-indigo-400 to-pink-500 bg-clip-text text-transparent">
                404
              </span>
            </div>
            <h1 className={`text-2xl sm:text-3xl font-extrabold ${isNight ? 'text-slate-100' : 'text-slate-900'}`}>
              Oops! Page Lost in Cyberspace
            </h1>
          </div>

          {/* Speech Bubble with Cute Quote */}
          <div className={`relative max-w-md mx-auto p-4 rounded-2xl border text-sm sm:text-base transition-all duration-300 mb-8 ${
            isNight
              ? 'bg-ink-900/90 border-slate-800 text-slate-300 shadow-xl'
              : 'bg-white/95 border-slate-200 text-slate-700 shadow-md'
          }`}>
            <p className="font-medium leading-relaxed">
              "{activeQuote}"
            </p>
          </div>

          {/* Navigation Action Buttons */}
          <div className="flex flex-wrap items-center justify-center gap-3 w-full max-w-md">
            <button
              onClick={() => navigate(-1)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all border ${
                isNight
                  ? 'border-slate-800 bg-ink-900/70 text-slate-300 hover:bg-slate-800 hover:text-white'
                  : 'border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200'
              }`}
            >
              <ArrowLeft size={16} /> Go Back
            </button>

            <Link
              to="/app/dashboard"
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs sm:text-sm font-bold transition-all bg-gradient-to-r from-cyan-500 to-purple-600 text-white hover:opacity-95 shadow-md shadow-purple-500/25 active:scale-95"
            >
              <LayoutDashboard size={16} /> Dashboard
            </Link>

            <Link
              to="/"
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all border ${
                isNight
                  ? 'border-slate-800 bg-ink-900/70 text-slate-300 hover:bg-slate-800 hover:text-white'
                  : 'border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200'
              }`}
            >
              <Home size={16} /> Home
            </Link>
          </div>

          {/* Quick Links Help Bar */}
          <div className="mt-10 pt-6 border-t border-slate-700/20 w-full flex flex-wrap items-center justify-center gap-4 text-xs text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-[10px]">Safe Haven:</span>
            <Link to="/tools" className="hover:text-cyan-400 transition-colors">Tools & Engine</Link>
            <span>•</span>
            <Link to="/app/scans" className="hover:text-cyan-400 transition-colors">Scans</Link>
            <span>•</span>
            <Link to="/pricing" className="hover:text-cyan-400 transition-colors">Pricing</Link>
            <span>•</span>
            <Link to="/login" className="hover:text-cyan-400 transition-colors">Sign In</Link>
          </div>

        </div>
      </div>
    </PublicLayout>
  )
}
