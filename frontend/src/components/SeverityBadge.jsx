import React, { useState, useRef, useEffect } from 'react'

const COLORS = {
  critical: 'bg-rose-500/15 text-rose-400 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.25)]',
  high: 'bg-amber-500/15 text-amber-400 border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.25)]',
  medium: 'bg-purple-500/15 text-purple-300 border-purple-500/40 shadow-[0_0_12px_rgba(168,85,247,0.25)]',
  low: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40 shadow-[0_0_12px_rgba(0,242,254,0.25)]',
  info: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.25)]',
}

const SEVS = ['critical', 'high', 'medium', 'low', 'info']

export default function SeverityBadge({ severity, onChange }) {
  const s = (severity || 'info').toLowerCase()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  if (!onChange) {
    return <span className={`chip border ${COLORS[s] || COLORS.info}`}>{s}</span>
  }

  return (
    <span ref={ref} className="relative">
      <button
        onClick={(e) => { e.stopPropagation(); setOpen(o => !o) }}
        className={`chip border cursor-pointer hover:scale-105 transition-transform ${COLORS[s] || COLORS.info}`}
        title="Click to override severity"
      >
        {s} ▾
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1.5 z-50 glass-deep border border-white/15 rounded-xl shadow-2xl overflow-hidden min-w-[110px] backdrop-blur-xl">
          {SEVS.map(sev => (
            <button
              key={sev}
              onClick={(e) => {
                e.stopPropagation()
                onChange(sev)
                setOpen(false)
              }}
              className={`block w-full text-left px-3.5 py-2 text-xs font-bold uppercase tracking-wider hover:bg-white/10 transition ${sev === s ? 'text-cyan-300 bg-white/5' : 'text-slate-300'}`}
            >
              {sev}
            </button>
          ))}
        </div>
      )}
    </span>
  )
}

