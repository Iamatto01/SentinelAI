import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Menu, X, ArrowUpRight, ShieldCheck, Terminal, Bot, Database,
  Cpu, Layers, ExternalLink, ChevronDown, Sparkles, Sun, Moon
} from 'lucide-react'
import InspectorLogo from '../InspectorLogo.jsx'
import { useTheme } from '../../lib/ThemeContext.jsx'

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
  const { isNight, toggleNightMode } = useTheme()
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

  const triggerThemeProtocol = () => {
    window.dispatchEvent(new CustomEvent('sentinel_replay_theme_intro'))
    setDropdownOpen(false)
    setMobileOpen(false)
  }

  return (
    <>
      <header
        className={`fixed top-0 inset-x-0 z-50 transition-all duration-300 ${
          isNight
            ? scrolled
              ? 'bg-black/85 backdrop-blur-md border-b border-white/10 shadow-[0_10px_30px_rgba(0,0,0,0.8)]'
              : 'bg-black/60 backdrop-blur-md border-b border-white/10'
            : scrolled
              ? 'bg-white/90 backdrop-blur-md border-b border-zinc-200 shadow-[0_4px_20px_rgba(0,0,0,0.06)] text-black'
              : 'bg-white/75 backdrop-blur-md border-b border-zinc-200 text-black'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Left: Brand */}
          <div className="flex items-center gap-4">
            <Link to="/" className="flex items-center gap-2.5 group">
              <div className={`p-1 rounded-lg border transition-all ${
                isNight
                  ? 'border-white/20 bg-white/5 group-hover:border-white/50 group-hover:bg-white/10'
                  : 'border-zinc-300 bg-black/5 group-hover:border-black/40 group-hover:bg-black/10'
              }`}>
                <InspectorLogo size={24} variant="base" className={isNight ? 'text-white' : 'text-black'} />
              </div>
              <div className="flex items-baseline gap-1">
                <span className={`font-extrabold text-base tracking-tight font-sans ${
                  isNight ? 'text-white' : 'text-black'
                }`}>
                  Sentinel<span className={isNight ? 'text-neutral-400' : 'text-zinc-500'}>AI</span>
                </span>
              </div>
            </Link>
          </div>

          {/* Center: Smooth-scroll Anchor Links */}
          <nav className="hidden xl:flex items-center gap-1">
            {SCROLL_ANCHORS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onClick={(e) => handleAnchorClick(e, link.href)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  isNight
                    ? 'text-neutral-400 hover:text-white hover:bg-white/5'
                    : 'text-zinc-600 hover:text-black hover:bg-zinc-100'
                }`}
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
                className={`px-2.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors flex items-center gap-1 cursor-pointer ${
                  isNight
                    ? 'text-neutral-400 hover:text-white hover:bg-white/5'
                    : 'text-zinc-600 hover:text-black hover:bg-zinc-100'
                }`}
              >
                <span>Modules</span>
                <ChevronDown size={13} className={`transition-transform duration-200 ${dropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {dropdownOpen && (
                <div className={`absolute top-full right-0 mt-2 w-64 rounded-xl border p-2 shadow-2xl backdrop-blur-2xl z-50 ${
                  isNight ? 'border-white/10 bg-[#0A0A0A]' : 'border-zinc-200 bg-white'
                }`}>
                  {MORE_PAGES.map((page) => (
                    <Link
                      key={page.to}
                      to={page.to}
                      className={`block p-2 rounded-lg transition-colors group ${
                        isNight ? 'hover:bg-white/5' : 'hover:bg-zinc-100'
                      }`}
                    >
                      <div className={`text-xs font-bold flex items-center justify-between ${
                        isNight ? 'text-white' : 'text-black'
                      }`}>
                        <span>{page.label}</span>
                        <ArrowUpRight size={12} className={isNight ? 'text-neutral-500 group-hover:text-white' : 'text-zinc-400 group-hover:text-black'} />
                      </div>
                      <div className={`text-[11px] font-mono mt-0.5 ${
                        isNight ? 'text-neutral-400' : 'text-zinc-500'
                      }`}>{page.desc}</div>
                    </Link>
                  ))}

                  <div className={`pt-2 mt-2 border-t ${isNight ? 'border-white/10' : 'border-zinc-200'}`}>
                    <button
                      type="button"
                      onClick={triggerThemeProtocol}
                      className={`w-full text-left p-2 rounded-lg text-xs font-mono font-bold flex items-center justify-between ${
                        isNight ? 'text-neutral-300 hover:bg-white/5' : 'text-zinc-700 hover:bg-zinc-100'
                      }`}
                    >
                      <span>Theme Selection Protocol</span>
                      <Sparkles size={12} />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </nav>

          {/* Right: Theme Toggle + Auth / CTA Buttons */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* ── Prominent Dark / Light Mode Switcher ───────────────── */}
            <button
              type="button"
              onClick={toggleNightMode}
              className={`p-2 rounded-xl border transition-all cursor-pointer flex items-center justify-center ${
                isNight
                  ? 'text-neutral-300 hover:text-white bg-white/[0.04] hover:bg-white/[0.1] border-white/10 hover:border-white/30'
                  : 'text-zinc-700 hover:text-black bg-zinc-100 hover:bg-zinc-200 border-zinc-300'
              }`}
              title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              aria-label="Toggle Theme"
            >
              {isNight ? (
                <Sun size={16} className="text-white hover:rotate-90 transition-transform duration-300" />
              ) : (
                <Moon size={16} className="text-black hover:-rotate-12 transition-transform duration-300" />
              )}
            </button>

            <Link
              to="/login"
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-colors hidden sm:inline-block ${
                isNight ? 'text-neutral-300 hover:text-white' : 'text-zinc-700 hover:text-black font-semibold'
              }`}
            >
              Sign In
            </Link>

            <Link
              to="/login?mode=register&plan=trial"
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold font-sans uppercase tracking-wider transition-all hover:scale-[1.02] active:scale-[0.98] ${
                isNight
                  ? 'bg-white text-black hover:bg-neutral-200 shadow-[0_0_25px_rgba(255,255,255,0.25)]'
                  : 'bg-black text-white hover:bg-zinc-800 shadow-[0_0_20px_rgba(0,0,0,0.25)]'
              }`}
            >
              <span>Launch Console</span>
              <ArrowUpRight size={14} className="stroke-[2.5]" />
            </Link>

            {/* Mobile Hamburger */}
            <button
              type="button"
              onClick={() => setMobileOpen(!mobileOpen)}
              className={`xl:hidden p-2 rounded-lg border transition-colors cursor-pointer ${
                isNight
                  ? 'border-white/10 text-neutral-300 hover:text-white hover:bg-white/5'
                  : 'border-zinc-300 text-zinc-700 hover:text-black hover:bg-zinc-100'
              }`}
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
          <div className={`fixed inset-x-4 top-20 rounded-2xl border p-5 shadow-2xl backdrop-blur-xl space-y-4 max-h-[80vh] overflow-y-auto ${
            isNight ? 'border-white/10 bg-[#080808]/95 text-white' : 'border-zinc-200 bg-white/95 text-black'
          }`}>
            <div className={`flex items-center justify-between pb-3 border-b ${
              isNight ? 'border-white/10' : 'border-zinc-200'
            }`}>
              <span className={`text-xs font-mono font-bold tracking-wider ${
                isNight ? 'text-neutral-400' : 'text-zinc-500'
              }`}>
                NAVIGATION ARCHITECTURE
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={toggleNightMode}
                  className={`p-1.5 rounded-lg border text-xs font-mono flex items-center gap-1 ${
                    isNight ? 'border-white/20 bg-white/5' : 'border-zinc-300 bg-zinc-100'
                  }`}
                >
                  {isNight ? <Sun size={13} /> : <Moon size={13} />}
                  <span>{isNight ? 'Light' : 'Dark'}</span>
                </button>
              </div>
            </div>

            <nav className="space-y-1">
              {SCROLL_ANCHORS.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  onClick={(e) => handleAnchorClick(e, link.href)}
                  className={`flex items-center justify-between p-2.5 rounded-lg text-sm font-mono transition-colors ${
                    isNight
                      ? 'text-neutral-300 hover:text-white hover:bg-white/5'
                      : 'text-zinc-700 hover:text-black hover:bg-zinc-100'
                  }`}
                >
                  <span>{link.label}</span>
                  <ArrowUpRight size={14} className={isNight ? 'text-neutral-500' : 'text-zinc-400'} />
                </a>
              ))}
            </nav>

            <div className={`pt-3 border-t space-y-2 ${isNight ? 'border-white/10' : 'border-zinc-200'}`}>
              <div className={`text-[10px] font-mono uppercase tracking-wider ${
                isNight ? 'text-neutral-500' : 'text-zinc-500'
              }`}>
                MODULES &amp; AUDITS
              </div>
              <div className="grid grid-cols-2 gap-2">
                {MORE_PAGES.map((page) => (
                  <Link
                    key={page.to}
                    to={page.to}
                    onClick={() => setMobileOpen(false)}
                    className={`p-2 rounded-lg border text-xs font-mono font-bold transition-colors ${
                      isNight
                        ? 'border-white/10 bg-white/5 text-neutral-300 hover:text-white'
                        : 'border-zinc-200 bg-zinc-50 text-zinc-800 hover:text-black'
                    }`}
                  >
                    {page.label}
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
