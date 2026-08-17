import React from 'react'
import { useTheme } from '../lib/ThemeContext.jsx'

/**
 * Compact Sun/Moon pill toggle (32px x 18px).
 * Small, clean, and functional — flips the app between
 * Night (dark) and Day (light) themes via ThemeContext.
 */
export default function ThemeSwitch({ compact = false }) {
  const { isNight, toggleNightMode } = useTheme()

  return (
    <div
      onClick={toggleNightMode}
      className={`flex items-center select-none cursor-pointer group transition-all ${
        compact ? 'justify-center w-full py-0.5' : 'justify-between w-full gap-2.5 px-1'
      }`}
      title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
      role="switch"
      aria-checked={isNight}
      aria-label="Toggle dark mode"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleNightMode() } }}
    >
      {!compact && (
        <div className="flex flex-col text-left min-w-0">
          <span className="text-xs font-bold text-slate-200 group-hover:text-cyan-300 transition-colors truncate">
            {isNight ? 'Dark Vision' : 'Light Mode'}
          </span>
          <span className="text-[10px] text-slate-400 truncate">
            {isNight ? 'Night Sky' : 'Day Sky'}
          </span>
        </div>
      )}

      {/* Compact Sun / Moon Toggle Pill (32px x 18px) */}
      <div
        className={`relative shrink-0 w-[32px] h-[18px] rounded-full overflow-hidden border transition-all duration-300 group-hover:scale-105 active:scale-95 ${
          isNight
            ? 'bg-slate-800 border-white/20'
            : 'bg-gradient-to-r from-sky-300 to-amber-200 border-white/40'
        }`}
      >
        {/* Tiny stars in night mode */}
        {isNight && (
          <span className="absolute top-[3px] left-[6px] w-[2px] h-[2px] rounded-full bg-white/80" />
        )}
        {isNight && (
          <span className="absolute top-[9px] left-[10px] w-[1.5px] h-[1.5px] rounded-full bg-white/60" />
        )}

        {/* Sliding thumb: sun by day, moon by night */}
        <div
          className="absolute top-[2px] w-[14px] h-[14px] rounded-full shadow-sm transition-all duration-300 ease-out"
          style={{
            left: isNight ? '16px' : '2px',
            transitionTimingFunction: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
            background: isNight
              ? 'radial-gradient(circle at 35% 35%, #e2e8f0 0%, #cbd5e1 60%, #94a3b8 100%)'
              : 'radial-gradient(circle at 35% 35%, #ffea79 0%, #f39c12 70%, #d68910 100%)',
          }}
        >
          {/* Moon crater (night) */}
          {isNight && (
            <span className="absolute top-[4px] left-[3px] w-[3px] h-[3px] rounded-full bg-slate-500/70" />
          )}
          {/* Sun rays hint (day) */}
          {!isNight && (
            <span className="absolute inset-0 rounded-full ring-1 ring-amber-300/60" />
          )}
        </div>
      </div>
    </div>
  )
}
