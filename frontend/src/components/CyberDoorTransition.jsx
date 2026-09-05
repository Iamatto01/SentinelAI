import React, { useState, useEffect } from 'react'
import InspectorLogo from './InspectorLogo.jsx'
import { ShieldCheck, Sparkles, Lock, Unlock } from 'lucide-react'

/**
 * CyberDoorTransition
 * Cinematic high-tech double vault door opening animation on entering the website.
 * Features left & right sliding doors, cyan laser seam, center biometric lock emblem,
 * and burst of light revealing the platform.
 */
export default function CyberDoorTransition({ onComplete }) {
  const [phase, setPhase] = useState('sealed') // 'sealed' | 'unlocking' | 'opening' | 'done'

  useEffect(() => {
    // 1. Hold sealed for 350ms, then trigger unlocking sequence
    const t1 = setTimeout(() => {
      setPhase('unlocking')
    }, 350)

    // 2. Unlocked: Doors slide apart at 750ms
    const t2 = setTimeout(() => {
      setPhase('opening')
    }, 750)

    // 3. Complete: Cleanly remove from DOM at 1600ms
    const t3 = setTimeout(() => {
      setPhase('done')
      if (onComplete) onComplete()
    }, 1650)

    return () => {
      clearTimeout(t1)
      clearTimeout(t2)
      clearTimeout(t3)
    }
  }, [onComplete])

  // Skip animation instantly if user clicks anywhere
  const handleSkip = () => {
    setPhase('opening')
    setTimeout(() => {
      setPhase('done')
      if (onComplete) onComplete()
    }, 350)
  }

  if (phase === 'done') return null

  const isOpening = phase === 'opening'
  const isUnlocking = phase === 'unlocking' || phase === 'opening'

  return (
    <div
      onClick={handleSkip}
      className="fixed inset-0 z-[99999] overflow-hidden select-none cursor-pointer"
      title="Click anywhere to skip entrance animation"
      aria-label="SentinelAI Security Gateway Opening"
    >
      <style>{`
        @keyframes doorScanLaser {
          0% { top: 10%; opacity: 0.2; }
          50% { top: 90%; opacity: 1; }
          100% { top: 10%; opacity: 0.2; }
        }
        @keyframes doorRingPulse {
          0%, 100% { transform: scale(1) rotate(0deg); border-color: rgba(56, 189, 248, 0.4); }
          50% { transform: scale(1.08) rotate(180deg); border-color: rgba(0, 242, 254, 0.85); box-shadow: 0 0 35px rgba(0, 242, 254, 0.5); }
        }
        @keyframes doorLightBurst {
          0% { opacity: 0; width: 2px; }
          50% { opacity: 1; width: 60px; filter: blur(12px); }
          100% { opacity: 0; width: 200px; filter: blur(30px); }
        }
      `}</style>

      {/* ── LEFT DOOR PANEL ────────────────────────────────────────────── */}
      <div
        className={`absolute top-0 left-0 bottom-0 w-1/2 bg-[#0a0c13] border-r-2 border-cyan-400/60 transition-transform duration-800 ease-in-out will-change-transform ${
          isOpening ? '-translate-x-full' : 'translate-x-0'
        }`}
        style={{
          boxShadow: isOpening ? 'none' : 'inset -15px 0 35px rgba(0,0,0,0.8), 6px 0 25px rgba(14,165,233,0.35)',
          backgroundImage: `
            linear-gradient(135deg, rgba(255,255,255,0.02) 25%, transparent 25%),
            linear-gradient(225deg, rgba(255,255,255,0.02) 25%, transparent 25%),
            linear-gradient(to right, #07080c 0%, #0d0f18 70%, #111422 100%)
          `,
        }}
      >
        {/* Left Tech Texture Panels */}
        <div className="absolute inset-0 opacity-20 pointer-events-none bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:24px_24px]" />
        
        {/* Left Door Structural Grooves */}
        <div className="absolute right-8 top-1/4 bottom-1/4 w-px bg-white/10" />
        <div className="absolute right-16 top-1/3 bottom-1/3 w-px bg-white/5" />
        
        {/* Door Serial Code & Warning Plate */}
        <div className="absolute top-8 left-8 text-[11px] font-mono tracking-widest text-slate-500 uppercase flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>GATE-01 // ALPHA WING</span>
        </div>
        
        <div className="absolute bottom-8 left-8 text-[10px] font-mono text-slate-600 tracking-wider">
          SYSTEM: KALI NATIVE KERNEL V5.4
        </div>
      </div>

      {/* ── RIGHT DOOR PANEL ───────────────────────────────────────────── */}
      <div
        className={`absolute top-0 right-0 bottom-0 w-1/2 bg-[#0a0c13] border-l-2 border-cyan-400/60 transition-transform duration-800 ease-in-out will-change-transform ${
          isOpening ? 'translate-x-full' : 'translate-x-0'
        }`}
        style={{
          boxShadow: isOpening ? 'none' : 'inset 15px 0 35px rgba(0,0,0,0.8), -6px 0 25px rgba(14,165,233,0.35)',
          backgroundImage: `
            linear-gradient(135deg, rgba(255,255,255,0.02) 25%, transparent 25%),
            linear-gradient(225deg, rgba(255,255,255,0.02) 25%, transparent 25%),
            linear-gradient(to left, #07080c 0%, #0d0f18 70%, #111422 100%)
          `,
        }}
      >
        {/* Right Tech Texture Panels */}
        <div className="absolute inset-0 opacity-20 pointer-events-none bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:24px_24px]" />

        {/* Right Door Structural Grooves */}
        <div className="absolute left-8 top-1/4 bottom-1/4 w-px bg-white/10" />
        <div className="absolute left-16 top-1/3 bottom-1/3 w-px bg-white/5" />

        {/* Right Serial Code */}
        <div className="absolute top-8 right-8 text-[11px] font-mono tracking-widest text-slate-500 uppercase text-right flex items-center gap-2 justify-end">
          <span>SEC-GATE // 53 PERSONAS</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        </div>

        <div className="absolute bottom-8 right-8 text-[10px] font-mono text-slate-600 tracking-wider text-right">
          STATUS: BIO-TOKEN VALIDATED
        </div>
      </div>

      {/* ── VERTICAL LASER SEAM IN CENTER ──────────────────────────────── */}
      {!isOpening && (
        <div
          className="absolute top-0 bottom-0 left-1/2 -translate-x-1/2 w-0.5 bg-cyan-400 shadow-[0_0_18px_#00f2fe,0_0_35px_#38bdf8] pointer-events-none z-10 transition-opacity duration-300"
        />
      )}

      {/* ── LIGHT BURST WHEN DOORS OPEN ────────────────────────────────── */}
      {isOpening && (
        <div
          className="absolute inset-y-0 left-1/2 -translate-x-1/2 bg-gradient-to-r from-transparent via-cyan-300 to-transparent pointer-events-none z-20"
          style={{ animation: 'doorLightBurst 0.9s cubic-bezier(0.16, 1, 0.3, 1) forwards' }}
        />
      )}

      {/* ── CENTER CYBER EMBLEM & BIOMETRIC LOCK ───────────────────────── */}
      <div
        className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-30 flex flex-col items-center gap-3 transition-all duration-500 pointer-events-none ${
          isOpening ? 'scale-125 opacity-0' : 'scale-100 opacity-100'
        }`}
      >
        {/* Orbital Rotating Ring */}
        <div className="relative flex items-center justify-center">
          <div
            className="w-28 h-28 sm:w-32 sm:h-32 rounded-full border-2 border-cyan-400/40 border-dashed absolute"
            style={{ animation: 'doorRingPulse 3s ease-in-out infinite' }}
          />

          <div className="w-24 h-24 sm:w-28 sm:h-28 rounded-full border border-white/20 bg-[#0d0f18]/95 backdrop-blur-2xl flex flex-col items-center justify-center p-3 shadow-[0_0_40px_rgba(0,0,0,0.8),inset_0_1px_0_rgba(255,255,255,0.2)]">
            <InspectorLogo size={36} />
            <span className="mt-1 text-[9px] font-black tracking-widest text-cyan-400 uppercase">
              SentinelAI
            </span>
          </div>
        </div>

        {/* Status Badge */}
        <div className="px-4 py-1.5 rounded-full bg-[#111422]/90 border border-cyan-500/40 shadow-lg backdrop-blur-xl flex items-center gap-2">
          {isUnlocking ? (
            <>
              <Unlock size={13} className="text-emerald-400 animate-pulse" />
              <span className="text-xs font-mono font-black text-emerald-300 tracking-wider">
                ACCESS GRANTED
              </span>
            </>
          ) : (
            <>
              <Lock size={13} className="text-cyan-400" />
              <span className="text-xs font-mono font-bold text-cyan-300 tracking-wider">
                DECRYPTING GATEWAY...
              </span>
            </>
          )}
        </div>

        <p className="text-[10px] font-mono text-slate-500 tracking-wider mt-1">
          Click anywhere to skip
        </p>
      </div>
    </div>
  )
}
