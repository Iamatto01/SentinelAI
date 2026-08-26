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

  return (
    <div className="card glass-in p-5 relative overflow-hidden group hover:border-cyan-400/40 hover-lift transition-all duration-300">
      <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-xl pointer-events-none group-hover:bg-cyan-500/10 transition-colors" />
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[11px] uppercase tracking-wider font-bold text-slate-400">{label}</p>
          <div className="flex items-baseline gap-2 mt-1">
            <p className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight count-up">{animated}</p>
            {trend && (
              <span className={`text-[11px] font-bold px-1.5 py-0.5 rounded-md ${trend.startsWith('+') ? 'bg-emerald-500/15 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                {trend}
              </span>
            )}
          </div>
          {sub && <p className="mt-1 text-xs text-slate-400 font-medium">{sub}</p>}
        </div>
        {Icon && (
          <div className={`icon-box ${boxClass} group-hover:scale-110 transition-transform duration-300`}>
            <Icon size={22} />
          </div>
        )}
      </div>
    </div>
  )
}
