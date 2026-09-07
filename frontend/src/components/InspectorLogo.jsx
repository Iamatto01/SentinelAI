import React from 'react'

export default function InspectorLogo({ className = 'w-9 h-9', size = 36 }) {
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
        <linearGradient id="sentinelGrad" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00f2fe" />
          <stop offset="50%" stopColor="#0284c7" />
          <stop offset="100%" stopColor="#1e1b4b" />
        </linearGradient>
        <linearGradient id="sentinelGlow" x1="16" y1="12" x2="48" y2="52" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ffffff" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.6" />
        </linearGradient>
      </defs>

      {/* Cyber Squircle Container */}
      <rect width="64" height="64" rx="18" fill="url(#sentinelGrad)" />
      <rect x="1" y="1" width="62" height="62" rx="17" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.5" />

      {/* Outer Security Shield */}
      <path
        d="M32 12L46 18.5V31.5C46 41.5 39.5 49 32 52C24.5 49 18 41.5 18 31.5V18.5L32 12Z"
        fill="#0a0f1d"
        fillOpacity="0.75"
        stroke="url(#sentinelGlow)"
        strokeWidth="2.5"
        strokeLinejoin="round"
      />

      {/* Cyber AI Sentinel Eye / Crosshair */}
      <path
        d="M24 32C24 32 27.5 25 32 25C36.5 25 40 32 40 32C40 32 36.5 39 32 39C27.5 39 24 32 24 32Z"
        stroke="#00f2fe"
        strokeWidth="2"
        strokeLinejoin="round"
        fill="#0284c7"
        fillOpacity="0.3"
      />
      <circle cx="32" cy="32" r="4.5" fill="#00f2fe" />
      <circle cx="32" cy="32" r="2" fill="#ffffff" />

      {/* Crosshair telemetry ticks */}
      <line x1="32" y1="21" x2="32" y2="23" stroke="#00f2fe" strokeWidth="2" strokeLinecap="round" />
      <line x1="32" y1="41" x2="32" y2="43" stroke="#00f2fe" strokeWidth="2" strokeLinecap="round" />
      <line x1="21" y1="32" x2="23" y2="32" stroke="#00f2fe" strokeWidth="2" strokeLinecap="round" />
      <line x1="41" y1="32" x2="43" y2="32" stroke="#00f2fe" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}
