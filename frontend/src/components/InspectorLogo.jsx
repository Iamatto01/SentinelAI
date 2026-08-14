import React from 'react'

export default function InspectorLogo({ className = 'w-9 h-9', size = 36 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" className={className} xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="redGradLogo" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ef4444"/>
          <stop offset="100%" stopColor="#991b1b"/>
        </linearGradient>
      </defs>

      {/* Red Container */}
      <rect width="64" height="64" rx="16" fill="url(#redGradLogo)"/>
      <rect width="64" height="64" rx="16" stroke="#fca5a5" strokeWidth="1.5" strokeOpacity="0.3"/>
      
      {/* Inspector Fedora Hat */}
      <path d="M22 26 C22 17, 42 17, 42 26 Z" fill="#ffffff"/>
      <path d="M21 24.5 H43 V26.5 H21 Z" fill="#7f1d1d"/>
      <path d="M12 28.5 C 18 26.5, 46 26.5, 52 28.5 C 46 30.5, 18 30.5, 12 28.5 Z" fill="#ffffff"/>

      {/* Glasses */}
      <path d="M22 33 H30 V37 H22 Z" fill="#ffffff" fillOpacity="0.9"/>
      <path d="M34 33 H42 V37 H34 Z" fill="#ffffff" fillOpacity="0.9"/>
      <path d="M30 34 H34" stroke="#ffffff" strokeWidth="2"/>

      {/* Red Magnifying Glass (Kanta Pembesar) */}
      <circle cx="37" cy="44" r="9" stroke="#ffffff" strokeWidth="3" fill="#991b1b" fillOpacity="0.5"/>
      <line x1="43.5" y1="50.5" x2="52" y2="58" stroke="#ffffff" strokeWidth="3.5" strokeLinecap="round"/>
      <circle cx="34" cy="41" r="2.5" fill="#ffffff" opacity="0.6"/>
    </svg>
  )
}
