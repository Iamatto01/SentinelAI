import React, { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTheme } from '../lib/ThemeContext.jsx'

/**
 * Animate a numeric value from 0 to `end` over `duration` ms.
 * Returns the current display value as a string.
 */
function useCountUp(end, duration = 900) {
  const [display, setDisplay] = useState(0)
  const rafRef = useRef(null)
  const startRef = useRef(null)
  const numEnd = typeof end === 'number' ? end : parseInt(end, 10)
  const isNumeric = !isNaN(numEnd)

  useEffect(() => {
    if (!isNumeric || numEnd === 0) { setDisplay(end); return }
    startRef.current = null
    const animate = (ts) => {
      if (!startRef.current) startRef.current = ts
      const elapsed = ts - startRef.current
      const progress = Math.min(elapsed / duration, 1)
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(eased * numEnd))
      if (progress < 1) rafRef.current = requestAnimationFrame(animate)
    }
    rafRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(rafRef.current)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [numEnd, duration])

  return isNumeric ? display : end
}

export default function StatCard({ icon: Icon, label, value, sub, tone = 'slate', trend, to, onClick }) {
  const themeCtx = useTheme()
  const isNight = themeCtx ? themeCtx.isNight : true
  const animated = useCountUp(value)
  const isLive = trend === 'Live' || (trend && trend.toLowerCase() === 'live')
  const isIdleOrReady = trend && (trend.toLowerCase() === 'idle' || trend.toLowerCase() === 'ready' || trend.toLowerCase() === 'standby')
  const isClickable = Boolean(to || onClick)

  const cardContent = (
    <>
      {/* Curved Ambient Aura */}
      <div className={`absolute -top-10 -right-10 w-28 h-28 rounded-full blur-2xl transition-all duration-500 pointer-events-none ${
        isNight ? 'bg-white/[0.04] group-hover:bg-white/[0.08]' : 'bg-slate-200/40 group-hover:bg-slate-200/70'
      }`} />

      <div className="flex items-start justify-between gap-3 relative z-10">
        <div className="min-w-0 flex-1">
          <p className={`text-[11px] uppercase tracking-wider font-bold truncate transition-colors ${
            isNight ? 'text-slate-400 group-hover:text-zinc-200' : 'text-slate-500 group-hover:text-slate-800'
          }`}>
            {label}
          </p>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            <p className={`text-2xl sm:text-3xl font-extrabold tracking-tight count-up leading-none ${
              isNight ? 'text-white' : 'text-slate-900'
            }`}>
              {animated}
            </p>
            {trend && (
              isLive ? (
                <span className="text-[11px] font-extrabold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-400/50 shadow-[0_0_12px_rgba(16,185,129,0.35)] animate-pulse flex items-center gap-1.5">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  Live
                </span>
              ) : isIdleOrReady ? (
                <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full flex items-center gap-1.5 shadow-sm border ${
                  isNight ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  {trend}
                </span>
              ) : (
                <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${
                  trend.startsWith('+')
                    ? (isNight ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200')
                    : (isNight ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' : 'bg-rose-50 text-rose-700 border-rose-200')
                }`}>
                  {trend}
                </span>
              )
            )}
          </div>
        </div>
        {Icon && (
          <div className={`w-11 h-11 rounded-2xl flex items-center justify-center transition-transform duration-300 group-hover:scale-105 shrink-0 shadow-sm ${
            tone === 'critical'
              ? (isNight ? 'bg-rose-500/15 text-rose-300 border border-rose-400/30 shadow-rose-500/15' : 'bg-rose-50 text-rose-600 border border-rose-200')
              : tone === 'emerald'
              ? (isNight ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-400/30 shadow-emerald-500/15' : 'bg-emerald-50 text-emerald-600 border border-emerald-200')
              : (isNight ? 'bg-white/10 text-white border border-white/20 shadow-white/5' : 'bg-slate-100 text-slate-800 border border-slate-300')
          }`}>
            <Icon size={19} />
          </div>
        )}
      </div>

      <div className="relative z-10 pt-2">
        {sub ? (
          <p className={`text-xs font-medium truncate transition-colors ${
            isNight ? 'text-slate-400 group-hover:text-slate-300' : 'text-slate-600 group-hover:text-slate-800'
          }`}>
            {sub}
          </p>
        ) : (
          <div className="h-4" />
        )}
        {/* Fixed subtle bottom accent bar (does NOT animate to 100% on hover) */}
        <div className={`w-full h-1 rounded-full mt-2.5 overflow-hidden ${
          isNight ? 'bg-white/[0.06]' : 'bg-slate-200'
        }`}>
          <div className={`h-full rounded-full transition-all duration-500 ${
            tone === 'critical' ? 'bg-gradient-to-r from-rose-500 to-amber-500 w-1/2' :
            tone === 'emerald' ? 'bg-gradient-to-r from-emerald-400 to-teal-500 w-3/4' :
            (isNight ? 'bg-gradient-to-r from-white via-zinc-400 to-zinc-600 w-3/5' : 'bg-gradient-to-r from-slate-600 to-slate-800 w-3/5')
          }`} />
        </div>
      </div>
    </>
  )

  const containerClasses = `rounded-3xl border backdrop-blur-xl p-5 relative overflow-hidden group hover-lift transition-all duration-300 h-full min-h-[125px] flex flex-col justify-between text-left ${
    isNight
      ? 'border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 hover:border-white/30 hover:shadow-[0_12px_32px_rgba(255,255,255,0.08)]'
      : 'border-slate-200 bg-white shadow-sm hover:border-slate-300 hover:shadow-md'
  } ${
    isClickable ? 'cursor-pointer active:scale-[0.98]' : ''
  }`

  if (to) {
    return (
      <Link to={to} className={containerClasses}>
        {cardContent}
      </Link>
    )
  }

  if (onClick) {
    return (
      <button onClick={onClick} type="button" className={containerClasses}>
        {cardContent}
      </button>
    )
  }

  return (
    <div className={containerClasses}>
      {cardContent}
    </div>
  )
}
