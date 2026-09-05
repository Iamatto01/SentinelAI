import React, { useState, useEffect } from 'react'
import { Sun, Moon, Sparkles, ArrowUpRight, ArrowDownLeft, X, Check } from 'lucide-react'
import { useTheme } from '../lib/ThemeContext.jsx'

/**
 * DiagonalThemeSelector
 * Interactive diagonal split-screen theme selector on landing page entry.
 * Top-right: Light Mode (Day Protocol)
 * Bottom-left: Dark Mode (Night Protocol)
 * Selection triggers a dynamic diagonal tilting sweep ("menyenget") across the entire screen.
 */
export default function DiagonalThemeSelector({ isOpen, onClose }) {
  const { isNight, setIsNight } = useTheme()
  const [hovered, setHovered] = useState(null) // 'light' | 'dark' | null
  const [selected, setSelected] = useState(null) // 'light' | 'dark' | null
  const [phase, setPhase] = useState('idle') // 'idle' | 'sweeping' | 'fading' | 'closed'

  // Reset phase when isOpen changes to true
  useEffect(() => {
    if (isOpen) {
      setPhase('idle')
      setSelected(null)
      setHovered(null)
    }
  }, [isOpen])

  if (!isOpen || phase === 'closed') return null

  // Calculate polygon clip path coordinates based on state
  // Point 1: 0% 0%
  // Point 2: 100% 0%
  // Point 3: 100% Y2
  // Point 4: 0% Y1
  let y1 = 28
  let y2 = 72

  if (hovered === 'light') {
    y1 = 38
    y2 = 82
  } else if (hovered === 'dark') {
    y1 = 18
    y2 = 62
  }

  if (selected === 'light') {
    // Light sweeps down and covers entire screen with tilting diagonal angle
    y1 = 145
    y2 = 130
  } else if (selected === 'dark') {
    // Dark sweeps up and covers entire screen (Light retreats past top)
    y1 = -35
    y2 = -20
  }

  const handleSelect = (mode) => {
    if (selected) return
    setSelected(mode)
    setPhase('sweeping')

    // At 550ms, switch active theme in ThemeContext & persist
    setTimeout(() => {
      setIsNight(mode === 'dark')
      sessionStorage.setItem('sentinel_theme_choice', mode)
    }, 550)

    // At 850ms, begin smooth fade out
    setTimeout(() => {
      setPhase('fading')
    }, 850)

    // At 1150ms, cleanly unmount from DOM
    setTimeout(() => {
      setPhase('closed')
      if (onClose) onClose()
    }, 1150)
  }

  const handleSkip = (e) => {
    e.stopPropagation()
    sessionStorage.setItem('sentinel_theme_choice', isNight ? 'dark' : 'light')
    setPhase('closed')
    if (onClose) onClose()
  }

  const isFading = phase === 'fading'

  return (
    <div
      className={`fixed inset-0 z-[99999] overflow-hidden select-none transition-opacity duration-300 ${
        isFading ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
      role="dialog"
      aria-label="Interactive Theme Selection Protocol"
    >
      {/* ── BASE LAYER: DARK MODE (BELAH BAWAH / BOTTOM-LEFT) ──────────── */}
      <div
        onClick={() => handleSelect('dark')}
        onMouseEnter={() => !selected && setHovered('dark')}
        onMouseLeave={() => !selected && setHovered(null)}
        className="absolute inset-0 bg-[#07080c] cursor-pointer flex flex-col justify-end p-8 sm:p-14 text-white overflow-hidden transition-colors duration-500"
        style={{
          backgroundImage: `
            radial-gradient(ellipse 70% 60% at 20% 85%, rgba(14, 165, 233, 0.16), transparent 70%),
            radial-gradient(ellipse 50% 40% at 50% 90%, rgba(99, 102, 241, 0.12), transparent 60%)
          `,
        }}
      >
        {/* Dark Tech Grid */}
        <div className="absolute inset-0 opacity-25 pointer-events-none bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:24px_24px]" />

        {/* Large Ambient Watermark */}
        <div className="absolute bottom-6 left-6 sm:left-12 opacity-10 pointer-events-none font-mono text-7xl sm:text-9xl font-black text-cyan-400 select-none tracking-tighter">
          DARK
        </div>

        {/* Dark Mode Content Card */}
        <div className="relative z-10 max-w-lg mb-4 sm:mb-8 space-y-3 sm:space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/15 border border-cyan-400/30 text-cyan-300 text-xs font-bold font-mono uppercase tracking-wider">
            <Moon size={13} className="text-cyan-400 animate-pulse" />
            <span>NIGHT PROTOCOL // 0% EYE STRAIN</span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-white flex items-center gap-3">
            <span>DARK MODE</span>
            <ArrowDownLeft className="text-cyan-400 opacity-60 hidden sm:inline" size={36} />
          </h2>

          <p className="text-sm sm:text-base text-slate-400 leading-relaxed max-w-md">
            Strict obsidian minimalism engineered for high-intensity red teaming, Kali terminal operations, and stealth environments.
          </p>

          <div className="pt-2 flex items-center gap-3">
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); handleSelect('dark'); }}
              className="btn-primary py-3 px-6 text-sm font-bold shadow-[0_0_25px_rgba(0,242,254,0.35)] flex items-center gap-2 cursor-pointer rounded-2xl"
            >
              <Moon size={16} />
              <span>Enter in Dark Mode</span>
            </button>
            <span className="text-xs font-mono text-slate-500 hidden sm:inline">
              Click anywhere in dark zone
            </span>
          </div>
        </div>
      </div>

      {/* ── TOP LAYER: LIGHT MODE (BELAH ATAS KANAN / TOP-RIGHT) ────────── */}
      <div
        onClick={() => handleSelect('light')}
        onMouseEnter={() => !selected && setHovered('light')}
        onMouseLeave={() => !selected && setHovered(null)}
        className="absolute inset-0 bg-[#f8fafc] cursor-pointer flex flex-col justify-start items-end p-8 sm:p-14 text-slate-900 overflow-hidden"
        style={{
          clipPath: `polygon(0% 0%, 100% 0%, 100% ${y2}%, 0% ${y1}%)`,
          transition: selected ? 'clip-path 0.85s cubic-bezier(0.16, 1, 0.3, 1)' : 'clip-path 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
          backgroundImage: `
            radial-gradient(ellipse 70% 60% at 85% 15%, rgba(2, 132, 199, 0.12), transparent 70%),
            radial-gradient(ellipse 50% 40% at 65% 10%, rgba(245, 158, 11, 0.08), transparent 60%)
          `,
        }}
      >
        {/* Light Tech Grid */}
        <div className="absolute inset-0 opacity-35 pointer-events-none bg-[radial-gradient(#0284c7_1px,transparent_1px)] [background-size:24px_24px]" />

        {/* Large Ambient Watermark */}
        <div className="absolute top-6 right-6 sm:right-12 opacity-10 pointer-events-none font-mono text-7xl sm:text-9xl font-black text-amber-500 select-none text-right tracking-tighter">
          LIGHT
        </div>

        {/* Light Mode Content Card */}
        <div className="relative z-10 max-w-lg mt-4 sm:mt-8 space-y-3 sm:space-y-4 text-right flex flex-col items-end">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/15 border border-amber-500/30 text-amber-700 text-xs font-bold font-mono uppercase tracking-wider">
            <Sun size={13} className="text-amber-500 animate-spin" style={{ animationDuration: '9s' }} />
            <span>DAY PROTOCOL // CRISP RESEARCH</span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-slate-900 flex items-center justify-end gap-3">
            <ArrowUpRight className="text-amber-500 opacity-60 hidden sm:inline" size={36} />
            <span>LIGHT MODE</span>
          </h2>

          <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-md">
            Crisp high-readability research canvas designed for executive audits, code reviews, and bright ambient environments.
          </p>

          <div className="pt-2 flex items-center justify-end gap-3 flex-row-reverse">
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); handleSelect('light'); }}
              className="py-3 px-6 rounded-2xl bg-gradient-to-r from-amber-500 to-sky-500 text-white font-bold text-sm shadow-[0_10px_25px_rgba(245,158,11,0.3)] hover:shadow-[0_12px_30px_rgba(245,158,11,0.45)] transition-all flex items-center gap-2 cursor-pointer"
            >
              <Sun size={16} />
              <span>Enter in Light Mode</span>
            </button>
            <span className="text-xs font-mono text-slate-500 hidden sm:inline">
              Click anywhere in light zone
            </span>
          </div>
        </div>
      </div>

      {/* ── DIAGONAL CUT SEAM LASER ─────────────────────────────────────── */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none z-20"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="diagonalSeamGlow" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.9" />
            <stop offset="50%" stopColor="#ffffff" stopOpacity="1" />
            <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.9" />
          </linearGradient>
          <filter id="laserBlur">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <line
          x1="0%"
          y1={`${y1}%`}
          x2="100%"
          y2={`${y2}%`}
          stroke="url(#diagonalSeamGlow)"
          strokeWidth="3.5"
          filter="url(#laserBlur)"
          style={{
            transition: selected ? 'all 0.85s cubic-bezier(0.16, 1, 0.3, 1)' : 'all 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        />
      </svg>

      {/* ── CENTER FLOATING BADGE ON SEAM ───────────────────────────────── */}
      {!selected && (
        <div
          className="absolute z-30 pointer-events-none transition-all duration-300"
          style={{
            left: '50%',
            top: `${(y1 + y2) / 2}%`,
            transform: 'translate(-50%, -50%)',
          }}
        >
          <div className="px-5 py-2.5 rounded-full bg-slate-950/90 border border-white/20 shadow-[0_0_35px_rgba(0,0,0,0.8),0_0_15px_rgba(56,189,248,0.4)] backdrop-blur-xl flex items-center gap-3 text-white text-xs font-mono font-bold tracking-wider uppercase">
            <span className="text-amber-400 flex items-center gap-1">
              <Sun size={13} /> <span>Day</span>
            </span>
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-cyan-400 flex items-center gap-1">
              <span>Night</span> <Moon size={13} />
            </span>
          </div>
        </div>
      )}

      {/* ── TOP SKIP BUTTON ─────────────────────────────────────────────── */}
      <div className="absolute top-5 right-5 z-40">
        <button
          onClick={handleSkip}
          className="px-3.5 py-1.5 rounded-full bg-black/60 hover:bg-black/80 border border-white/20 text-slate-300 hover:text-white text-xs font-mono font-semibold transition-all flex items-center gap-1.5 cursor-pointer backdrop-blur-md shadow-lg"
          title="Skip theme selection"
        >
          <span>Skip Protocol</span>
          <X size={13} />
        </button>
      </div>
    </div>
  )
}
