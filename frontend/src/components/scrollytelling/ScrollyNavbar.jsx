import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Menu, X, ArrowUpRight, ShieldCheck, Terminal, Bot, Database,
  Cpu, Layers, ExternalLink, ChevronDown, Sparkles
} from 'lucide-react'
import InspectorLogo from '../InspectorLogo.jsx'

const SCROLL_ANCHORS = [
  { href: '#platform', label: 'Platform' },
  { href: '#terminal', label: 'Live Pentest' },
  { href: '#models', label: 'AI Models' },
  { href: '#matrix', label: 'Vulnerability Matrix' },
  { href: '#architecture', label: 'Architecture' },
  { href: '#pricing', label: 'Pricing' },
  { href: '#faq', label: 'Docs / FAQ' },
]

const MORE_PAGES = [
  { to: '/tools', label: '150+ Kali Tools', desc: 'DAST, SAST, Fuzzing arsenal' },
  { to: '/services', label: 'Security Solutions', desc: 'Blackbox, Whitebox & vCISO' },
  { to: '/about', label: 'Research & Mission', desc: 'Zero-cloud local-first privacy' },
  { to: '/contact', label: 'Contact Lead Dev', desc: 'IIUM KICT research team' },
]

export default function ScrollyNavbar() {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const handleAnchorClick = (e, href) => {
    e.preventDefault()
    setMobileOpen(false)
    const target = document.querySelector(href)
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  return (
    <>
      <header
        className={`fixed top-0 inset-x-0 z-50 transition-all duration-300 ${
          scrolled
            ? 'bg-black/85 backdrop-blur-md border-b border-white/10 shadow-[0_10px_30px_rgba(0,0,0,0.8)]'
            : 'bg-black/60 backdrop-blur-md border-b border-white/10'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Left: Brand + Live Status Badge */}
          <div className="flex items-center gap-4">
            <Link to="/" className="flex items-center gap-2.5 group">
              <div className="p-1 rounded-lg border border-white/20 bg-white/5 transition-all group-hover:border-white/50 group-hover:bg-white/10">
                <InspectorLogo size={24} variant="base" className="text-white" />
              </div>
              <div className="flex items-baseline gap-1">
                <span className="font-extrabold text-white text-base tracking-tight font-sans">
                  Sentinel<span className="text-neutral-400">AI</span>
                </span>
                <span className="text-[10px] font-mono text-neutral-500 uppercase tracking-widest hidden sm:inline">
                  .studio
                </span>
              </div>
            </Link>

            {/* Live Status Indicator Dot [ ONLINE ] */}
            <div className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-white/10 bg-white/[0.03] text-[11px] font-mono text-neutral-300">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
              </span>
              <span className="font-bold tracking-wider">[ ONLINE ]</span>
            </div>
          </div>

          {/* Center: Smooth-scroll Anchor Links */}
          <nav className="hidden xl:flex items-center gap-1">
            {SCROLL_ANCHORS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onClick={(e) => handleAnchorClick(e, link.href)}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-medium text-neutral-400 hover:text-white hover:bg-white/5 transition-colors"
              >
                {link.label}
              </a>
            ))}

            {/* More Platform Pages Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setDropdownOpen(!dropdownOpen)}
                onBlur={() => setTimeout(() => setDropdownOpen(false), 200)}
                className="px-2.5 py-1.5 rounded-lg text-xs font-mono font-medium text-neutral-400 hover:text-white hover:bg-white/5 transition-colors flex items-center gap-1 cursor-pointer"
              >
                <span>Modules</span>
                <ChevronDown size={13} className={`transition-transform duration-200 ${dropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {dropdownOpen && (
                <div className="absolute top-full right-0 mt-2 w-64 rounded-xl border border-white/10 bg-[#0A0A0A] p-2 shadow-2xl backdrop-blur-2xl z-50">
                  {MORE_PAGES.map((page) => (
                    <Link
                      key={page.to}
                      to={page.to}
                      className="block p-2 rounded-lg hover:bg-white/5 transition-colors group"
                    >
                      <div className="text-xs font-bold text-white group-hover:text-white flex items-center justify-between">
                        <span>{page.label}</span>
                        <ArrowUpRight size={12} className="text-neutral-500 group-hover:text-white transition-colors" />
                      </div>
                      <div className="text-[11px] text-neutral-400 font-mono mt-0.5">{page.desc}</div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </nav>

          {/* Right: Auth / CTA Buttons */}
          <div className="flex items-center gap-3">
            <Link
              to="/login"
              className="px-3.5 py-1.5 rounded-lg text-xs font-mono text-neutral-300 hover:text-white transition-colors hidden sm:inline-block"
            >
              Sign In
            </Link>

            <Link
              to="/login?mode=register&plan=trial"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold font-sans uppercase tracking-wider bg-white text-black hover:bg-neutral-200 shadow-[0_0_25px_rgba(255,255,255,0.25)] transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              <span>Launch Console</span>
              <ArrowUpRight size={14} className="stroke-[2.5]" />
            </Link>

            {/* Mobile Hamburger */}
            <button
              type="button"
              onClick={() => setMobileOpen(!mobileOpen)}
              className="xl:hidden p-2 rounded-lg border border-white/10 text-neutral-300 hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              {mobileOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 xl:hidden">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          <div className="fixed inset-x-4 top-20 rounded-2xl border border-white/10 bg-[#080808]/95 p-5 shadow-2xl backdrop-blur-xl space-y-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <span className="text-xs font-mono text-neutral-400 font-bold tracking-wider">
                NAVIGATION ARCHITECTURE
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-white/10 text-[10px] font-mono text-neutral-300">
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                ONLINE
              </span>
            </div>

            <nav className="space-y-1">
              {SCROLL_ANCHORS.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  onClick={(e) => handleAnchorClick(e, link.href)}
                  className="flex items-center justify-between p-2.5 rounded-lg text-sm font-mono text-neutral-300 hover:text-white hover:bg-white/5 transition-colors"
                >
                  <span>{link.label}</span>
                  <ArrowUpRight size={14} className="text-neutral-500" />
                </a>
              ))}
            </nav>

            <div className="pt-3 border-t border-white/10 space-y-1">
              <div className="text-[10px] font-mono uppercase tracking-widest text-neutral-500 px-2 py-1">
                Deep Dive Modules
              </div>
              {MORE_PAGES.map((page) => (
                <Link
                  key={page.to}
                  to={page.to}
                  onClick={() => setMobileOpen(false)}
                  className="flex items-center justify-between p-2 rounded-lg text-xs font-mono text-neutral-400 hover:text-white hover:bg-white/5 transition-colors"
                >
                  <span>{page.label}</span>
                  <span className="text-[10px] text-neutral-600">{page.desc}</span>
                </Link>
              ))}
            </div>

            <div className="pt-3 border-t border-white/10 flex flex-col gap-2">
              <Link
                to="/login"
                onClick={() => setMobileOpen(false)}
                className="w-full py-2.5 rounded-lg border border-white/15 text-center text-xs font-mono text-white hover:bg-white/5"
              >
                Sign In
              </Link>
              <Link
                to="/login?mode=register&plan=trial"
                onClick={() => setMobileOpen(false)}
                className="w-full py-2.5 rounded-lg bg-white text-black text-center text-xs font-bold uppercase tracking-wider hover:bg-neutral-200"
              >
                Start Pentest (3 Free Scans)
              </Link>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
