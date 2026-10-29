import React, { useEffect, useState } from 'react'
import { motion, useScroll, useSpring } from 'framer-motion'
import { useTheme } from '../../lib/ThemeContext.jsx'

const SECTIONS = [
  { id: 'platform', label: '01 RECON' },
  { id: 'terminal', label: '02 PIPELINE' },
  { id: 'models', label: '03 AI MESH' },
  { id: 'matrix', label: '04 MATRIX' },
  { id: 'architecture', label: '05 BLUEPRINT' },
  { id: 'pricing', label: '06 PRICING' },
  { id: 'faq', label: '07 FAQ' },
]

export default function ScrollProgressHUD() {
  const { isNight } = useTheme()
  const { scrollYProgress } = useScroll()
  const scaleY = useSpring(scrollYProgress, { stiffness: 140, damping: 25, restDelta: 0.001 })
  const [activeSection, setActiveSection] = useState('platform')

  useEffect(() => {
    const handleScroll = () => {
      const scrollPos = window.scrollY + window.innerHeight * 0.35

      for (let i = SECTIONS.length - 1; i >= 0; i--) {
        const el = document.getElementById(SECTIONS[i].id)
        if (el) {
          const top = el.offsetTop
          if (scrollPos >= top) {
            setActiveSection(SECTIONS[i].id)
            break
          }
        }
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const scrollTo = (id) => {
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' })
    }
  }

  return (
    <>
      {/* Top Window Laser Progress Bar (Visible on all viewports) */}
      <motion.div
        className={`fixed top-0 left-0 right-0 h-[2.5px] origin-left z-50 pointer-events-none transition-colors duration-300 ${
          isNight
            ? 'bg-white shadow-[0_0_14px_rgba(255,255,255,1)]'
            : 'bg-black shadow-[0_0_12px_rgba(0,0,0,0.6)]'
        }`}
        style={{ scaleX: scaleY }}
      />

      {/* Floating Vertical Scrollytelling HUD on Desktop */}
      <div className="fixed right-4 sm:right-6 top-1/2 -translate-y-1/2 z-40 hidden lg:flex flex-col items-end gap-3 pointer-events-auto select-none">
        <div className="relative flex flex-col items-end py-2">
          {/* Track Line */}
          <div className={`absolute right-[5px] top-0 bottom-0 w-[1px] transition-colors duration-300 ${
            isNight ? 'bg-white/10' : 'bg-black/10'
          }`} />

          {/* Dynamic Glowing Laser Progress Line */}
          <motion.div
            className={`absolute right-[5px] top-0 w-[2px] origin-top transition-colors duration-300 ${
              isNight
                ? 'bg-white shadow-[0_0_10px_rgba(255,255,255,0.9)]'
                : 'bg-black shadow-[0_0_8px_rgba(0,0,0,0.5)]'
            }`}
            style={{ scaleY, height: '100%' }}
          />

          {/* Navigation Step Indicators */}
          <div className="flex flex-col gap-5 relative z-10">
            {SECTIONS.map((sec) => {
              const isActive = activeSection === sec.id

              return (
                <button
                  key={sec.id}
                  type="button"
                  onClick={() => scrollTo(sec.id)}
                  className="group flex items-center gap-3 cursor-pointer focus:outline-none"
                >
                  {/* Monospace Hover Label */}
                  <span
                    className={`text-[9px] font-mono tracking-widest uppercase transition-all duration-300 ${
                      isActive
                        ? isNight ? 'text-white font-bold opacity-100 translate-x-0' : 'text-black font-bold opacity-100 translate-x-0'
                        : isNight ? 'text-neutral-500 opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0' : 'text-zinc-500 opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0'
                    }`}
                  >
                    {sec.label}
                  </span>

                  {/* Node Pip */}
                  <div
                    className={`rounded-full transition-all duration-300 ${
                      isActive
                        ? isNight
                          ? 'w-3 h-3 bg-white shadow-[0_0_12px_rgba(255,255,255,1)] ring-2 ring-white/30'
                          : 'w-3 h-3 bg-black shadow-[0_0_10px_rgba(0,0,0,0.5)] ring-2 ring-black/20'
                        : isNight
                          ? 'w-2 h-2 bg-neutral-700 group-hover:bg-neutral-300'
                          : 'w-2 h-2 bg-zinc-300 group-hover:bg-zinc-700'
                    }`}
                  />
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </>
  )
}
