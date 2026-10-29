import React, { useRef, useState } from 'react'

/**
 * SpotlightCard
 * Frosted glassmorphic card with mouse-tracking radial spotlight border glow.
 * Pure monochrome aesthetic: black/white luminescence.
 */
export default function SpotlightCard({
  children,
  className = '',
  spotlightColor = 'rgba(255, 255, 255, 0.14)',
  radius = 350,
  as: Component = 'div',
  onClick,
  ...props
}) {
  const cardRef = useRef(null)
  const [position, setPosition] = useState({ x: 0, y: 0 })
  const [isHovered, setIsHovered] = useState(false)

  const handleMouseMove = (e) => {
    if (!cardRef.current) return
    const rect = cardRef.current.getBoundingClientRect()
    setPosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    })
  }

  return (
    <Component
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={onClick}
      className={`group relative overflow-hidden rounded-2xl border border-white/10 bg-[#080808]/90 backdrop-blur-xl transition-all duration-300 hover:border-white/25 ${className}`}
      {...props}
    >
      {/* Volumetric Mouse Spotlight Overlay */}
      <div
        className="pointer-events-none absolute -inset-px rounded-[inherit] transition-opacity duration-300 z-10"
        style={{
          opacity: isHovered ? 1 : 0,
          background: `radial-gradient(${radius}px circle at ${position.x}px ${position.y}px, ${spotlightColor}, transparent 70%)`,
        }}
        aria-hidden="true"
      />

      {/* Card Content */}
      <div className="relative z-20 h-full w-full">{children}</div>
    </Component>
  )
}
