import React, { useState, useEffect } from 'react'

export default function PageTurnTransition({ duration = 1400 }) {
  const [phase, setPhase] = useState('active') // 'active' | 'done'

  useEffect(() => {
    const t = setTimeout(() => setPhase('done'), duration)
    return () => clearTimeout(t)
  }, [duration])

  if (phase === 'done') return null

  return (
    <div className="fixed inset-0 z-[9999] pointer-events-none overflow-hidden" aria-hidden="true">
      {/* Main curtain sheet that sweeps diagonally */}
      <div className="pt-curtain" />
      {/* Light streak along the fold edge */}
      <div className="pt-light-streak" />
      {/* Subtle ambient glow */}
      <div className="pt-glow" />
    </div>
  )
}
