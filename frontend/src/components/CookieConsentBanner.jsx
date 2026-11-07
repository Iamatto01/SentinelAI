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
          className="fixed bottom-3 sm:bottom-6 inset-x-3 sm:inset-x-0 sm:max-w-3xl sm:mx-auto z-50 pointer-events-auto"
        >
          <div
            className={`p-4 sm:p-5 rounded-2xl sm:rounded-3xl border shadow-2xl backdrop-blur-2xl transition-colors duration-300 ${
              isNight
                ? 'bg-neutral-950/90 border-white/15 text-white shadow-[0_16px_50px_rgba(0,0,0,0.85)]'
                : 'bg-white/95 border-slate-200/90 text-slate-900 shadow-[0_16px_40px_rgba(0,0,0,0.12)]'
            }`}
          >
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              {/* Icon & Message */}
              <div className="flex items-start gap-3.5">
                <div
                  className={`p-2.5 rounded-xl border shrink-0 ${
                    isNight
                      ? 'bg-white/5 border-white/10 text-white'
                      : 'bg-slate-100 border-slate-200 text-slate-800'
                  }`}
                >
                  <Cookie size={20} className="stroke-[2.2]" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs sm:text-sm font-bold font-sans tracking-tight">
                      Cookie &amp; Local Storage Governance
                    </h3>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full uppercase tracking-wider font-semibold border ${
                        isNight
                          ? 'bg-white/5 border-white/10 text-neutral-300'
                          : 'bg-slate-100 border-slate-200 text-slate-700'
                      }`}
                    >
                      Local-First
                    </span>
                  </div>
                  <p
                    className={`text-xs font-sans leading-relaxed max-w-xl ${
                      isNight ? 'text-neutral-400' : 'text-slate-600'
                    }`}
                  >
                    SentinelAI uses essential local storage &amp; cookies strictly for JWT session authentication,
                    dark/light theme persistence, and offline audit caching. We do not use third-party tracking or
                    ad-network cookies.
                  </p>
                  <div className="flex items-center gap-3 pt-1 text-[11px] font-mono">
                    <Link
                      to="/privacy"
                      onClick={() => setIsVisible(false)}
                      className={`inline-flex items-center gap-1 underline underline-offset-2 ${
                        isNight ? 'text-neutral-300 hover:text-white' : 'text-slate-800 hover:text-black'
                      }`}
                    >
                      <span>Privacy &amp; Cookie Policy</span>
                      <ArrowUpRight size={11} />
                    </Link>
                    <span className="opacity-40">&bull;</span>
                    <Link
                      to="/terms"
                      onClick={() => setIsVisible(false)}
                      className={`inline-flex items-center gap-1 underline underline-offset-2 ${
                        isNight ? 'text-neutral-300 hover:text-white' : 'text-slate-800 hover:text-black'
                      }`}
                    >
                      <span>Terms of Service</span>
                      <ArrowUpRight size={11} />
                    </Link>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 w-full sm:w-auto shrink-0 pt-2 sm:pt-0">
                <button
                  type="button"
                  onClick={() => handleConsent('essential')}
                  className={`flex-1 sm:flex-initial px-3.5 py-2 rounded-xl text-xs font-mono font-medium border transition-all cursor-pointer ${
                    isNight
                      ? 'border-white/15 bg-white/5 text-neutral-300 hover:bg-white/10 hover:text-white'
                      : 'border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200 hover:text-black'
                  }`}
                >
                  Essential Only
                </button>
                <button
                  type="button"
                  onClick={() => handleConsent('accepted')}
                  className={`flex-1 sm:flex-initial inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all shadow-md cursor-pointer ${
                    isNight
                      ? 'bg-white text-black hover:bg-neutral-200'
                      : 'bg-slate-900 text-white hover:bg-black'
                  }`}
                >
                  <Check size={14} className="stroke-[2.5]" />
                  <span>Accept All</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleConsent('essential')}
                  aria-label="Dismiss banner"
                  className={`p-2 rounded-xl border transition-colors cursor-pointer ${
                    isNight
                      ? 'border-white/10 text-neutral-400 hover:text-white hover:bg-white/5'
                      : 'border-slate-200 text-slate-500 hover:text-black hover:bg-slate-100'
                  }`}
                >
                  <X size={14} />
                </button>
              </div>
            </div>
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  )
}
