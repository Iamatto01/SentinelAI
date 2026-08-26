import React, { useEffect, useRef, useState } from 'react'
import mermaid from 'mermaid'

// Exact replica of the SentinelAI public portal architecture diagram (ARCHITECTURE.md)
const MERMAID_DEFINITION = `graph TD
    PublicLayout["🌐 Public Layout (Glassmorphic Header & Footer)"]
    PublicLayout --> Home["/ (Home - Hero, Highlights, Live Architecture)"]
    PublicLayout --> About["/about (About SentinelAI, FYP2 Research, Creator & Philosophy)"]
    PublicLayout --> Tools["/tools (150+ Kali Tools & 51 AI Agent Personas Directory)"]
    PublicLayout --> Services["/services (Pentest, DevSecOps, Advisory & Exploit Automation)"]
    PublicLayout --> Pricing["/pricing (Subscription Plans, Feature Matrix & ROI Calculator)"]
    PublicLayout --> Contact["/contact (Contact Us, Consultation Booking & Support Channels)"]`

let mermaidInitialized = false

function ensureMermaidInit() {
  if (!mermaidInitialized) {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'dark',
      darkMode: true,
      securityLevel: 'loose',
      themeVariables: {
        primaryColor: '#0b1437',
        primaryTextColor: '#e2e8f0',
        primaryBorderColor: '#00f2fe',
        lineColor: '#22d3ee',
        secondaryColor: '#071228',
        tertiaryColor: '#060b26',
        fontSize: '13px',
      },
      flowchart: { curve: 'basis', useMaxWidth: true },
    })
    mermaidInitialized = true
  }
}

export default function MermaidDiagram() {
  const containerRef = useRef(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    const id = 'mermaid-portal-' + Math.random().toString(36).slice(2, 9)

    async function render() {
      try {
        ensureMermaidInit()
        const { svg } = await mermaid.render(id, MERMAID_DEFINITION)
        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = svg
        }
      } catch (e) {
        console.error('Mermaid render failed:', e)
        if (!cancelled) setError(e.message || String(e))
      }
    }

    render()
    return () => { cancelled = true }
  }, [])

  if (error) {
    return (
      <div className="p-6 rounded-3xl border border-rose-500/30 bg-slate-950/70 text-center">
        <p className="text-xs text-rose-400 font-mono">Diagram failed to render: {error}</p>
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className="mermaid-diagram p-4 sm:p-8 rounded-3xl overflow-x-auto [&_svg]:mx-auto [&_svg]:max-w-full"
      style={{
        background: 'rgba(6, 11, 38, 0.5)',
        backdropFilter: 'blur(40px) saturate(180%)',
        WebkitBackdropFilter: 'blur(40px) saturate(180%)',
        border: '1px solid rgba(0, 242, 254, 0.15)',
        boxShadow: '0 12px 40px rgba(0, 0, 0, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.06)',
      }}
    />
  )
}
