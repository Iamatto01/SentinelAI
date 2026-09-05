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

export default function StatCard({ icon: Icon, label, value, sub, tone = 'cyan', trend }) {
  const iconBoxes = {
    cyan: 'icon-box-cyan',
    accent: 'icon-box-cyan',
    purple: 'icon-box-purple',
    emerald: 'icon-box-emerald',
    amber: 'icon-box-amber',
    critical: 'icon-box-rose',
    high: 'icon-box-amber',
    medium: 'icon-box-purple',
    low: 'icon-box-cyan',
    info: 'icon-box-emerald',
  }

  const boxClass = iconBoxes[tone] || 'icon-box-cyan'
  const animated = useCountUp(value)
  const isLive = trend === 'Live' || (trend && trend.toLowerCase() === 'live')

  return (
    <div className="card glass-in p-5 relative overflow-hidden group hover:border-cyan-400/40 hover-lift transition-all duration-300 h-full min-h-[118px] flex flex-col justify-between">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider font-bold text-slate-400 truncate">{label}</p>
          <div className="flex items-center gap-2 mt-1.5">
            <p className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight count-up leading-none">{animated}</p>
            {trend && (
              isLive ? (
                <span className="text-[11px] font-extrabold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-400/50 shadow-[0_0_12px_rgba(16,185,129,0.35)] animate-pulse flex items-center gap-1.5">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  Live
                </span>
              ) : (
                <span className={`text-[11px] font-bold px-1.5 py-0.5 rounded-md ${
                  trend.startsWith('+')
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20'
                    : 'bg-slate-800/80 text-slate-400 border border-white/5'
                }`}>
                  {trend}
                </span>
              )
            )}
          </div>
        </div>
        {Icon && (
          <div className={`icon-box ${boxClass} group-hover:scale-110 transition-transform duration-300 shrink-0 !p-2.5`}>
            <Icon size={20} />
          </div>
        )}
      </div>
      {sub ? (
        <p className="mt-2 text-xs text-slate-400 font-medium truncate">{sub}</p>
      ) : (
        <div className="h-4" />
      )}
    </div>
  )
}
