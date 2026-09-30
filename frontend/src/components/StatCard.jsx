import React, { useEffect, useRef, useState } from 'react'

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

export default function StatCard({ icon: Icon, label, value, sub, tone = 'purple', trend }) {
  const iconBoxes = {
    cyan: 'icon-box-purple',
    accent: 'icon-box-purple',
    purple: 'icon-box-purple',
    emerald: 'icon-box-emerald',
    amber: 'icon-box-amber',
    critical: 'icon-box-rose',
    high: 'icon-box-amber',
    medium: 'icon-box-purple',
    low: 'icon-box-purple',
    info: 'icon-box-emerald',
  }

  const boxClass = iconBoxes[tone] || 'icon-box-purple'
  const animated = useCountUp(value)
  const isLive = trend === 'Live' || (trend && trend.toLowerCase() === 'live')
  const isIdleOrReady = trend && (trend.toLowerCase() === 'idle' || trend.toLowerCase() === 'ready' || trend.toLowerCase() === 'standby')

  return (
    <div className="rounded-3xl border border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 backdrop-blur-xl p-5 relative overflow-hidden group hover:border-purple-400/40 hover:shadow-[0_12px_32px_rgba(168,85,247,0.15)] hover-lift transition-all duration-300 h-full min-h-[125px] flex flex-col justify-between">
      {/* Curved Ambient Aura */}
      <div className="absolute -top-10 -right-10 w-28 h-28 rounded-full bg-purple-500/10 blur-2xl group-hover:bg-purple-500/20 group-hover:scale-125 transition-all duration-500 pointer-events-none" />

      <div className="flex items-start justify-between gap-3 relative z-10">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider font-bold text-slate-400 truncate">{label}</p>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            <p className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight count-up leading-none">{animated}</p>
            {trend && (
              isLive ? (
                <span className="text-[11px] font-extrabold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-400/50 shadow-[0_0_12px_rgba(16,185,129,0.35)] animate-pulse flex items-center gap-1.5">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  Live
                </span>
              ) : isIdleOrReady ? (
                <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5 shadow-sm">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  {trend}
                </span>
              ) : (
                <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${
                  trend.startsWith('+')
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                }`}>
                  {trend}
                </span>
              )
            )}
          </div>
        </div>
        {Icon && (
          <div className={`w-11 h-11 rounded-2xl flex items-center justify-center transition-transform duration-300 group-hover:scale-110 shrink-0 shadow-md ${
            tone === 'critical' ? 'bg-rose-500/15 text-rose-300 border border-rose-400/30 shadow-rose-500/15' :
            tone === 'emerald' ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-400/30 shadow-emerald-500/15' :
            tone === 'purple' || tone === 'cyan' || tone === 'accent' ? 'bg-purple-500/15 text-purple-300 border border-purple-400/30 shadow-purple-500/15' :
            'bg-purple-500/15 text-purple-300 border border-purple-400/30 shadow-purple-500/15'
          }`}>
            <Icon size={19} />
          </div>
        )}
      </div>

      <div className="relative z-10 pt-2">
        {sub ? (
          <p className="text-xs text-slate-400 font-medium truncate">{sub}</p>
        ) : (
          <div className="h-4" />
        )}
        {/* Subtle bottom curved glowing accent bar */}
        <div className="w-full h-1 rounded-full bg-white/[0.04] mt-2.5 overflow-hidden">
          <div className={`h-full rounded-full transition-all duration-700 ${
            tone === 'critical' ? 'bg-gradient-to-r from-rose-500 to-amber-500 w-1/2 group-hover:w-full' :
            tone === 'emerald' ? 'bg-gradient-to-r from-emerald-400 to-teal-500 w-3/4 group-hover:w-full' :
            'bg-gradient-to-r from-purple-400 via-violet-500 to-indigo-500 w-3/5 group-hover:w-full'
          }`} />
        </div>
      </div>
    </div>
  )
}
