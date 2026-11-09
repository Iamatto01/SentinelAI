import React from 'react'

/**
 * Official Brand Logo Component - Chicken on Fire Emblem
 *
 * Supports:
 * - variant="base" (default): Transparent Chicken on Fire logo with adaptive halo
 * - variant="badge": Rounded dark container with flame border (Favicon style)
 * - variant="cyber": Flame aura glow variant
 */
export default function InspectorLogo({
  className = 'w-9 h-9',
  size = 36,
  variant = 'base',
  accent = 'cyan',
}) {
  const gradId = React.useId()

  if (variant === 'badge') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        fill="none"
        className={`shrink-0 ${className}`}
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id={`bg-${gradId}`} x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#181a20" />
            <stop offset="100%" stopColor="#0a0c10" />
          </linearGradient>
          <linearGradient id={`stroke-${gradId}`} x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#ea580c" />
          </linearGradient>
        </defs>
        <rect width="64" height="64" rx="16" fill={`url(#bg-${gradId})`} />
        <rect x="0.75" y="0.75" width="62.5" height="62.5" rx="15.25" stroke={`url(#stroke-${gradId})`} strokeWidth="1.5" strokeOpacity="0.9" />
        <image href="/logo.png" x="6" y="6" width="52" height="52" />
      </svg>
    )
  }

  if (variant === 'cyber') {
    return (
      <div
        className={`relative shrink-0 flex items-center justify-center ${className}`}
        style={{ width: size, height: size }}
      >
        <div className="absolute inset-0 bg-orange-500/25 rounded-full blur-md animate-pulse pointer-events-none" />
        <svg
          width={size}
          height={size}
          viewBox="0 0 512 512"
          fill="none"
          className="relative z-10 w-full h-full shrink-0"
          xmlns="http://www.w3.org/2000/svg"
        >
          <image href="/logo.png" width="512" height="512" />
        </svg>
      </div>
    )
  }

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 512 512"
      fill="none"
      className={`shrink-0 transition-transform duration-300 ${className}`}
      xmlns="http://www.w3.org/2000/svg"
    >
      <image href="/logo.png" width="512" height="512" />
    </svg>
  )
}

// Named alias for modern Sentinel naming
export { InspectorLogo as SentinelLogo }
