import React, { useState, useEffect } from 'react'

export default function PageTurnTransition({ duration = 1200, onComplete }) {
  const [isActive, setIsActive] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsActive(false)
      if (onComplete) onComplete()
    }, duration)
    return () => clearTimeout(timer)
  }, [duration, onComplete])

  if (!isActive) return null

  return (
    <div
      className="fixed inset-0 z-[9999] pointer-events-none overflow-hidden select-none"
      style={{ perspective: '1200px' }}
      aria-hidden="true"
    >
      {/* ── 1. Old Sheet / Cover Layer Peeling Away from Top-Left to Bottom-Right ── */}
      <div className="absolute inset-0 bg-[#060b26] page-turn-sheet" />

      {/* ── 2. 3D Diagonal Fold / Crease Bar & Dynamic Shadow Sweep ── */}
      <div className="absolute inset-0 page-turn-crease" />

      {/* ── 3. Page Curl Under-Flap Highlight & Glow ── */}
      <div className="absolute inset-0 page-turn-sheen" />
    </div>
  )
}
