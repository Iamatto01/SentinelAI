import React, { useRef, useState } from 'react'
import { useTheme } from '../../lib/ThemeContext.jsx'

/**
 * SpotlightCard
 * Frosted glassmorphic card with mouse-tracking radial spotlight border glow.
 * Pure monochrome aesthetic: black/white luminescence.
 * Automatically adapts between Dark Mode and Light Mode.
 */
export default function SpotlightCard({
  children,
  className = '',
  spotlightColor,
  radius = 350,
  as: Component = 'div',
  onClick,
  ...props
}) {
  const { isNight } = useTheme()
  const cardRef = useRef(null)
  const [position, setPosition] = useState({ x: 0, y: 0 })
  const [isHovered, setIsHovered] = useState(false)

  const defaultSpotlight = isNight
    ? 'rgba(168, 85, 247, 0.18)'
    : 'rgba(124, 58, 237, 0.10)'

  const effectiveSpotlight = spotlightColor || defaultSpotlight

  const handleMouseMove = (e) => {
    if (!cardRef.current) return
    const rect = cardRef.current.getBoundingClientRect()
    setPosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    })
  }

  const baseThemeClasses = isNight
    ? 'border-white/10 bg-[#080808]/90 text-white hover:border-white/25'
    : 'border-zinc-200 bg-white/95 text-zinc-900 shadow-sm hover:border-zinc-400'

  return (
    <Component
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={onClick}
      className={`group relative overflow-hidden rounded-2xl border backdrop-blur-xl transition-all duration-300 ${baseThemeClasses} ${className}`}
      {...props}
    >
      {/* Volumetric Mouse Spotlight Overlay */}
      <div
        className="pointer-events-none absolute -inset-px rounded-[inherit] transition-opacity duration-300 z-10"
        style={{
          opacity: isHovered ? 1 : 0,
          background: `radial-gradient(${radius}px circle at ${position.x}px ${position.y}px, ${effectiveSpotlight}, transparent 70%)`,
        }}
        aria-hidden="true"
      />

      {/* Card Content */}
      <div className="relative z-20 h-full w-full">{children}</div>
    </Component>
  )
}
