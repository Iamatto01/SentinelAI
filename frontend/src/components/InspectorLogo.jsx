import React from 'react'

/**
 * Official Brand Logo Component
 * Base geometry authentically matches the master reference (geometric wireframe stealth/spire emblem).
 * 
 * Supports:
 * - variant="base" (default): Crisp geometric wireframe base logo
 * - variant="cyber": High-tech cyan/blue/purple gradient with subtle cyber glow
 * - variant="shield": Full security shield & padlock insignia (Reference Image 2)
 * - variant="badge": Rounded cyber squircle badge container (Favicon style)
 */

const BASE_OUTER = 'M 256.0,56.0 L 106.6,273.2 L 43.1,314.0 L 43.1,400.0 L 110.9,425.8 L 256.0,372.0 L 401.1,425.8 L 468.9,400.0 L 468.9,314.0 L 405.4,273.2 Z'

const BASE_HOLES = [
  // Pair 1: Top inner
  'M 246.3,111.9 L 248.5,193.6 L 199.0,225.8 Z',
  'M 265.7,111.9 L 313.0,225.8 L 263.5,193.6 Z',
  // Pair 2: Top outer
  'M 231.3,111.9 L 177.5,180.7 L 184.0,228.0 Z',
  'M 280.7,111.9 L 328.0,228.0 L 334.5,180.7 Z',
  // Pair 3: Shoulder outer
  'M 164.6,204.3 L 134.5,262.4 L 168.9,243.0 Z',
  'M 347.4,204.3 L 343.1,243.0 L 377.5,262.4 Z',
  // Pair 4: Mid inner
  'M 235.6,225.8 L 186.1,251.6 L 186.1,307.6 Z',
  'M 276.4,225.8 L 325.9,307.6 L 325.9,251.6 Z',
  // Pair 5: Mid outer
  'M 166.8,264.6 L 128.1,281.8 L 168.9,305.4 Z',
  'M 345.2,264.6 L 343.1,305.4 L 383.9,281.8 Z',
  // Pair 6: Mid chevron quads
  'M 246.3,225.8 L 248.5,281.8 L 186.1,382.8 L 184.0,329.0 Z',
  'M 265.7,225.8 L 328.0,329.0 L 325.9,382.8 L 263.5,281.8 Z',
  // Pair 7: Wing top rhombus
  'M 117.3,294.6 L 162.5,322.6 L 117.3,350.6 Z',
  'M 394.7,294.6 L 394.7,350.6 L 349.5,322.6 Z',
  // Pair 8: Wing outer vertical
  'M 104.4,299.0 L 59.3,322.6 L 59.3,385.0 L 104.4,357.0 Z',
  'M 407.6,299.0 L 407.6,357.0 L 452.7,385.0 L 452.7,322.6 Z',
  // Pair 9: Wing inner triangle
  'M 166.8,331.2 L 121.6,359.2 L 166.8,387.1 Z',
  'M 345.2,331.2 L 345.2,387.1 L 390.4,359.2 Z',
  // Pair 10: Wing bottom rhombus
  'M 113.0,365.6 L 63.6,393.6 L 110.9,425.8 L 162.5,395.7 Z',
  'M 399.0,365.6 L 349.5,395.7 L 401.1,425.8 L 448.4,393.6 Z'
].join(' ')

const FULL_BASE_PATH = `${BASE_OUTER} ${BASE_HOLES}`

export default function InspectorLogo({
  className = 'w-9 h-9',
  size = 36,
  variant = 'base',
  accent = 'cyan', // 'cyan' | 'purple' | 'navy'
}) {
  const gradId = React.useId()

  // Variant 1: Pure Base Logo (Default)
  if (variant === 'base') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 512 512"
        fill="none"
        className={`shrink-0 transition-transform duration-300 ${className}`}
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id={`grad-${gradId}`} x1="256" y1="56" x2="256" y2="430" gradientUnits="userSpaceOnUse">
            {accent === 'purple' ? (
              <>
                <stop offset="0%" stopColor="#c084fc" />
                <stop offset="50%" stopColor="#a855f7" />
                <stop offset="100%" stopColor="#6b21a8" />
              </>
            ) : accent === 'navy' ? (
              <>
                <stop offset="0%" stopColor="#1e3a8a" />
                <stop offset="100%" stopColor="#0f172a" />
              </>
            ) : (
              <>
                <stop offset="0%" stopColor="#38bdf8" />
                <stop offset="50%" stopColor="#2563eb" />
                <stop offset="100%" stopColor="#0ea5e9" />
              </>
            )}
          </linearGradient>
        </defs>
        <path d={FULL_BASE_PATH} fill={`url(#grad-${gradId})`} fillRule="evenodd" />
      </svg>
    )
  }

  // Variant 2: Badge / Squircle container (Like the favicon, perfect for standalone icons)
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
            <stop offset="0%" stopColor="#0f172a" />
            <stop offset="100%" stopColor="#020617" />
          </linearGradient>
          <linearGradient id={`emblem-${gradId}`} x1="32" y1="8" x2="32" y2="56" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#38bdf8" />
            <stop offset="60%" stopColor="#60a5fa" />
            <stop offset="100%" stopColor="#ffffff" />
          </linearGradient>
        </defs>
        <rect width="64" height="64" rx="16" fill={`url(#bg-${gradId})`} />
        <rect x="0.75" y="0.75" width="62.5" height="62.5" rx="15.25" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.6" />
        <g transform="translate(7, 8) scale(0.098)">
          <path d={FULL_BASE_PATH} fill={`url(#emblem-${gradId})`} fillRule="evenodd" />
        </g>
      </svg>
    )
  }

  // Variant 3: Cyber Security Variant (Shield, Circuits & Padlock from Reference Image 2)
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 512 512"
      fill="none"
      className={`shrink-0 ${className}`}
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id={`cyberGrad-${gradId}`} x1="256" y1="56" x2="256" y2="430" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="50%" stopColor="#1d4ed8" />
          <stop offset="100%" stopColor="#0f172a" />
        </linearGradient>
        <linearGradient id={`shieldGrad-${gradId}`} x1="330" y1="140" x2="440" y2="280" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#1e293b" />
          <stop offset="100%" stopColor="#020617" />
        </linearGradient>
      </defs>

      {/* Circuit lines on left */}
      <g stroke="#38bdf8" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" opacity="0.85">
        <path d="M 60 190 L 120 190 L 155 220" />
        <circle cx="60" cy="190" r="7" fill="#38bdf8" />
        <path d="M 90 240 L 140 240" />
        <circle cx="90" cy="240" r="7" fill="#38bdf8" />
        <path d="M 40 280 L 110 280 L 135 260" />
        <circle cx="40" cy="280" r="7" fill="#38bdf8" />
      </g>

      {/* Base Logo */}
      <path d={FULL_BASE_PATH} fill={`url(#cyberGrad-${gradId})`} fillRule="evenodd" />

      {/* Shield on right */}
      <g transform="translate(10, 0)">
        <g stroke="#38bdf8" strokeWidth="4" strokeLinecap="round" opacity="0.85">
          <line x1="390" y1="170" x2="430" y2="150" />
          <circle cx="430" cy="150" r="6" fill="#38bdf8" />
          <line x1="420" y1="210" x2="465" y2="210" />
          <circle cx="465" cy="210" r="6" fill="#38bdf8" />
          <line x1="400" y1="260" x2="445" y2="280" />
          <circle cx="445" cy="280" r="6" fill="#38bdf8" />
        </g>
        <path
          d="M 335 150 Q 380 140 405 160 C 405 230 380 270 335 295 C 290 270 265 230 265 160 Q 290 140 335 150 Z"
          fill={`url(#shieldGrad-${gradId})`}
          stroke="#38bdf8"
          strokeWidth="6"
          strokeLinejoin="round"
        />
        <circle cx="335" cy="215" r="16" stroke="#38bdf8" strokeWidth="4" fill="#0f172a" />
        <circle cx="335" cy="215" r="5" fill="#38bdf8" />
      </g>

      {/* Padlock in bottom notch */}
      <g transform="translate(256, 400)">
        <path d="M -14 -12 A 14 14 0 0 1 14 -12 L 14 0 L -14 0 Z" fill="none" stroke="#38bdf8" strokeWidth="5" strokeLinecap="round" />
        <rect x="-20" y="0" width="40" height="32" rx="6" fill="#0f172a" stroke="#38bdf8" strokeWidth="4" />
        <circle cx="0" cy="13" r="4.5" fill="#38bdf8" />
        <polygon points="-2,13 2,13 3,23 -3,23" fill="#38bdf8" />
      </g>
    </svg>
  )
}

// Named alias for modern Sentinel naming
export { InspectorLogo as SentinelLogo }
