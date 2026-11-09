import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Cookie, ShieldCheck, Check, X, ArrowUpRight } from 'lucide-react'
import { useTheme } from '../lib/ThemeContext.jsx'

export const COOKIE_CONSENT_KEY = 'sentinel_cookie_consent'

export default function CookieConsentBanner() {
  const { isNight } = useTheme()
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    try {
      const saved = localStorage.getItem(COOKIE_CONSENT_KEY)
      if (!saved) {
        // Small delay so page mounts smoothly before banner slides up
        const timer = setTimeout(() => setIsVisible(true), 900)
        return () => clearTimeout(timer)
      }
    } catch {
      setIsVisible(true)
    }
  }, [])

  // Allow re-opening banner from footer links or settings via event
  useEffect(() => {
    const handleOpen = () => setIsVisible(true)
    window.addEventListener('sentinel_open_cookie_preferences', handleOpen)
    return () => window.removeEventListener('sentinel_open_cookie_preferences', handleOpen)
  }, [])

  const handleConsent = (mode) => {
    try {
      localStorage.setItem(COOKIE_CONSENT_KEY, mode)
    } catch {
      // ignore
    }
    setIsVisible(false)
  }

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.aside
          role="dialog"
          aria-label="Cookie and storage preferences"
          initial={{ opacity: 0, y: 50, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 30, scale: 0.95 }}
          transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
          className="fixed bottom-2 sm:bottom-4 inset-x-2 sm:inset-x-auto sm:left-1/2 sm:-translate-x-1/2 sm:max-w-2xl sm:w-full z-50 pointer-events-auto"
        >
          <div
            className={`px-3 py-1.5 sm:px-4 sm:py-2 rounded-xl sm:rounded-2xl border shadow-xl backdrop-blur-2xl transition-colors duration-300 ${
              isNight
                ? 'bg-neutral-950/95 border-white/15 text-white shadow-[0_8px_30px_rgba(0,0,0,0.85)]'
                : 'bg-white/95 border-slate-200/90 text-slate-900 shadow-[0_8px_25px_rgba(0,0,0,0.12)]'
            }`}
          >
            <div className="flex items-center justify-between gap-2 sm:gap-3">
              {/* Icon & Message */}
              <div className="flex items-center gap-2 sm:gap-2.5 min-w-0 flex-1">
                <div
                  className={`p-1 sm:p-1.5 rounded-lg border shrink-0 ${
                    isNight
                      ? 'bg-white/5 border-white/10 text-amber-400'
                      : 'bg-amber-50 border-amber-200 text-amber-700'
                  }`}
                >
                  <Cookie size={14} className="sm:w-4 sm:h-4 stroke-[2.2]" />
                </div>
                <div className="min-w-0 text-[11px] sm:text-xs font-sans leading-tight">
                  <span className="font-semibold">Cookies &amp; storage: </span>
                  <span className={isNight ? 'text-neutral-400' : 'text-slate-600'}>
                    Essential session &amp; auth use only.{' '}
                  </span>
                  <Link
                    to="/privacy"
                    onClick={() => setIsVisible(false)}
                    className={`inline-flex items-center gap-0.5 underline underline-offset-2 font-mono text-[10px] sm:text-[11px] ${
                      isNight ? 'text-neutral-300 hover:text-white' : 'text-slate-800 hover:text-black'
                    }`}
                  >
                    <span>Privacy</span>
                    <ArrowUpRight size={10} />
                  </Link>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-1 sm:gap-1.5 shrink-0">
                <button
                  type="button"
                  onClick={() => handleConsent('essential')}
                  className={`hidden sm:inline-block px-2.5 py-1 rounded-lg text-[11px] font-mono font-medium border transition-all cursor-pointer whitespace-nowrap ${
                    isNight
                      ? 'border-white/15 bg-white/5 text-neutral-300 hover:bg-white/10 hover:text-white'
                      : 'border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200 hover:text-black'
                  }`}
                >
                  Essential
                </button>
                <button
                  type="button"
                  onClick={() => handleConsent('accepted')}
                  className={`inline-flex items-center justify-center gap-1 px-2.5 sm:px-3 py-1 rounded-lg text-[11px] font-mono font-bold transition-all shadow-sm cursor-pointer whitespace-nowrap ${
                    isNight
                      ? 'bg-white text-black hover:bg-neutral-200'
                      : 'bg-slate-900 text-white hover:bg-black'
                  }`}
                >
                  <Check size={11} className="stroke-[2.5]" />
                  <span>Accept</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleConsent('essential')}
                  aria-label="Dismiss banner"
                  className={`p-1 rounded-lg border transition-colors cursor-pointer shrink-0 ${
                    isNight
                      ? 'border-white/10 text-neutral-400 hover:text-white hover:bg-white/5'
                      : 'border-slate-200 text-slate-500 hover:text-black hover:bg-slate-100'
                  }`}
                >
                  <X size={12} />
                </button>
              </div>
            </div>
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  )
}
