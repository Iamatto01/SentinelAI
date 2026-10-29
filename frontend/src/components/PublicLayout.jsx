import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  ArrowRight, Menu, X, Github, Send, MessageCircle, Mail,
  ShieldCheck, Cpu, Database, Terminal, Sparkles, LogIn,
  ChevronRight, Home, Tag, Activity, Globe2, Shield, Sun, Moon
} from 'lucide-react'
import InspectorLogo from './InspectorLogo.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'

const NAV_LINKS = [
  { to: '/', label: 'Home', icon: Home, desc: 'Overview & autonomous pentest engine' },
  { to: '/about', label: 'About', icon: ShieldCheck, desc: 'Mission & local-first zero-cloud privacy' },
  { to: '/tools', label: 'Tools & AI', icon: Terminal, desc: '150+ Kali Linux tools & 53 AI personas' },
  { to: '/services', label: 'Services', icon: Cpu, desc: 'Blackbox pentesting & DevSecOps CI/CD' },
  { to: '/pricing', label: 'Pricing', icon: Tag, desc: 'Transparent plans & researcher quotas' },
  { to: '/contact', label: 'Contact', icon: Mail, desc: 'Get in touch with security research lead' },
]

export default function PublicLayout({ children, forceTheme, isSplitPreview = false }) {
  const { isNight: ctxNight, toggleNightMode } = useTheme()
  const isNight = forceTheme ? (forceTheme === 'dark') : ctxNight
  const [mobileOpen, setMobileOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const location = useLocation()

  // Track scroll position for dynamic glass elevation
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll, { passive: true })
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  // Close mobile drawer on route change + scroll to top on navigation
  useEffect(() => {
    setMobileOpen(false)
    window.scrollTo({ top: 0, behavior: 'instant' })
  }, [location.pathname])

  return (
    <div className={`at-home min-h-screen relative overflow-x-hidden ${isNight ? 'night' : 'day-mode'}`}>
      {/* Ambient Grid */}
      <div className="at-home__grid" />
      <div className="at-home__noise" />

      {/* ── High-Tech Floating Glassmorphic Header (Follows User on Scroll) ── */}
      <header className="fixed top-0 sm:top-3 inset-x-0 z-50 w-full sm:w-[calc(100%-2rem)] sm:max-w-6xl sm:mx-auto px-3 sm:px-0 transition-all duration-300">
        <div
          className={`w-full px-4 sm:px-6 py-2.5 sm:py-3 flex items-center justify-between sm:rounded-2xl transition-all duration-300 ${
            isNight
              ? scrolled
                ? 'bg-black/90 backdrop-blur-2xl border-b sm:border border-white/10 shadow-[0_12px_36px_rgba(0,0,0,0.8),0_0_20px_rgba(255,255,255,0.06)]'
                : 'bg-black/75 backdrop-blur-xl border-b sm:border border-white/10 shadow-[0_8px_32px_rgba(0,0,0,0.5)]'
              : scrolled
                ? 'bg-white/95 backdrop-blur-2xl border-b sm:border border-slate-200/80 shadow-[0_8px_30px_rgba(0,0,0,0.08)] text-slate-900'
                : 'bg-white/85 backdrop-blur-xl border-b sm:border border-slate-200/60 shadow-[0_4px_20px_rgba(0,0,0,0.04)] text-slate-900'
          }`}
        >
          {/* Brand Logo */}
          <Link to="/" className="flex items-center gap-2.5 group shrink-0">
            <div className={`p-1 rounded-xl border transition-all duration-300 ${
              isNight
                ? 'bg-white/5 border-white/15 group-hover:border-white/40 group-hover:shadow-[0_0_14px_rgba(255,255,255,0.2)]'
                : 'bg-slate-100 border-slate-200 group-hover:border-slate-400'
            }`}>
              <InspectorLogo size={24} variant="base" className={isNight ? 'text-white' : 'text-slate-900'} />
            </div>
            <span className={`font-extrabold text-sm sm:text-base tracking-tight transition-colors font-sans ${
              isNight ? 'text-white group-hover:text-neutral-300' : 'text-slate-900 group-hover:text-black'
            }`}>
              Sentinel<span className={isNight ? 'text-neutral-400' : 'text-slate-600'}>AI</span>
            </span>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className={`hidden lg:flex items-center gap-1 p-1 rounded-xl border ${
            isNight ? 'bg-white/[0.03] border-white/[0.08]' : 'bg-slate-100/90 border-slate-200/80'
          }`}>
            {NAV_LINKS.map((l) => {
              const isActive = location.pathname === l.to
              return (
                <Link
                  key={l.to}
                  to={l.to}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all duration-200 ${
                    isActive
                      ? isNight
                        ? 'bg-white/10 text-white border border-white/20 shadow-[0_0_12px_rgba(255,255,255,0.1)] font-bold'
                        : 'bg-white text-black border border-slate-300 shadow-sm font-bold'
                      : isNight
                        ? 'text-neutral-400 hover:text-white hover:bg-white/[0.06] border border-transparent'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-white/60 border border-transparent'
                  }`}
                >
                  {l.label}
                </Link>
              )
            })}
          </nav>

          {/* Action CTAs */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Dark / Light Mode Toggle */}
            <button
              onClick={toggleNightMode}
              className={`p-2 rounded-xl border transition-all cursor-pointer flex items-center justify-center ${
                isNight
                  ? 'text-neutral-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.08] border-white/10 hover:border-white/20'
                  : 'text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 border-slate-200'
              }`}
              title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              aria-label="Toggle Theme"
            >
              {isNight ? (
                <Sun size={15} className="text-white hover:rotate-90 transition-transform duration-300" />
              ) : (
                <Moon size={15} className="text-black hover:-rotate-12 transition-transform duration-300" />
              )}
            </button>

            {/* Sign In */}
            <Link
              to="/login"
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-mono font-semibold border transition-all ${
                isNight
                  ? 'text-neutral-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.08] border-white/10 hover:border-white/20'
                  : 'text-slate-700 hover:text-slate-900 bg-slate-100 hover:bg-slate-200 border-slate-200'
              }`}
            >
              <LogIn size={13} className={isNight ? 'text-neutral-400' : 'text-slate-500'} />
              <span>Sign In</span>
            </Link>

            {/* Mobile Hamburger Toggle Button */}
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className={`lg:hidden p-2 rounded-xl border active:scale-95 transition-all cursor-pointer ${
                isNight
                  ? 'bg-white/5 border-white/10 text-neutral-200 hover:text-white hover:border-white/30 hover:bg-white/10'
                  : 'bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900 hover:border-slate-300'
              }`}
              aria-label="Toggle navigation menu"
            >
              {mobileOpen ? <X size={17} /> : <Menu size={17} />}
            </button>
          </div>
        </div>
      </header>

      {/* Spacer to preserve content flow with fixed header */}
      <div className="h-16 sm:h-20 w-full shrink-0 pointer-events-none" aria-hidden="true" />

      {/* ── Mobile Navigation Drawer Backdrop & Modal ────────────────────── */}
      {mobileOpen && (
        <>
          {/* Backdrop Overlay */}
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-md z-40 lg:hidden transition-opacity"
            onClick={() => setMobileOpen(false)}
          />

          {/* Drawer Card */}
          <div className="fixed inset-x-3 sm:inset-x-6 top-16 sm:top-20 z-50 lg:hidden rounded-2xl sm:rounded-3xl border border-white/15 bg-black/95 backdrop-blur-2xl shadow-[0_20px_50px_rgba(0,0,0,0.9),0_0_30px_rgba(255,255,255,0.08)] p-4 sm:p-5 space-y-4 max-h-[85vh] overflow-y-auto">
            {/* Engine Status Banner */}
            <div className="flex items-center justify-between px-3.5 py-2 rounded-xl bg-white/[0.04] border border-white/10 text-xs text-neutral-300">
              <span className="flex items-center gap-2 font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
                Native Kali Engine Active
              </span>
              <span className="text-[10px] text-neutral-400 font-mono">150+ Tools</span>
            </div>

            {/* Navigation List */}
            <nav className="space-y-1.5 font-mono">
              {NAV_LINKS.map((l) => {
                const Icon = l.icon
                const isActive = location.pathname === l.to
                return (
                  <Link
                    key={l.to}
                    to={l.to}
                    onClick={() => setMobileOpen(false)}
                    className={`flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                      isActive
                        ? 'bg-white/10 text-white border border-white/20 shadow-[0_0_15px_rgba(255,255,255,0.1)]'
                        : 'text-neutral-300 hover:bg-white/5 hover:text-white border border-transparent'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-1.5 rounded-lg ${isActive ? 'bg-white/15 text-white' : 'bg-white/5 text-neutral-400'}`}>
                        <Icon size={16} />
                      </div>
                      <div className="text-left">
                        <div className="leading-tight">{l.label}</div>
                        <div className="text-[10px] text-neutral-500 font-normal leading-tight mt-0.5">{l.desc}</div>
                      </div>
                    </div>
                    <ChevronRight size={15} className={isActive ? 'text-white' : 'text-neutral-600'} />
                  </Link>
                )
              })}
            </nav>

            {/* Drawer Action CTAs */}
            <div className="pt-3 border-t border-white/10 space-y-2">
              <div className="flex items-center">
                <button
                  onClick={toggleNightMode}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-xl text-xs font-mono font-semibold bg-white/5 border border-white/10 text-neutral-200 cursor-pointer"
                >
                  {isNight ? <Sun size={14} className="text-white" /> : <Moon size={14} className="text-black" />}
                  <span>{isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}</span>
                </button>
              </div>

              <Link
                to="/login?mode=register&plan=trial"
                onClick={() => setMobileOpen(false)}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl font-bold font-mono text-xs uppercase tracking-wider text-black bg-white shadow-md hover:bg-neutral-200 transition-all"
              >
                <Sparkles size={14} />
                <span>Start Free Assessment</span>
                <ArrowRight size={14} />
              </Link>
              <Link
                to="/login"
                onClick={() => setMobileOpen(false)}
                className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-xl font-mono text-xs text-neutral-300 bg-white/5 border border-white/10 hover:bg-white/10 hover:text-white transition-all"
              >
                <LogIn size={14} />
                <span>Sign In to Platform</span>
              </Link>
            </div>
          </div>
        </>
      )}

      {/* ── Page Content ─────────────────────────────────────────────────── */}
      <main>{children}</main>

      {/* ── Glassmorphic Footer ──────────────────────────────────────────── */}
      <footer
        className="relative mt-24 border-t border-white/10 px-4 sm:px-8 py-12"
        style={{ background: '#050505', backdropFilter: 'blur(30px)', WebkitBackdropFilter: 'blur(30px)' }}
      >
        <div className="max-w-6xl mx-auto grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10">
          {/* Brand */}
          <div className="space-y-3">
            <div className="flex items-center gap-2.5">
              <InspectorLogo size={28} variant="base" className="text-white" />
              <span className="font-extrabold text-white tracking-tight font-sans">SentinelAI</span>
            </div>
            <p className="text-xs text-neutral-400 leading-relaxed font-sans">
              Autonomous AI security assessment platform — 150+ Kali tools, 53 specialist AI personas, local-first RAG intelligence.
            </p>
            <div className="flex items-center gap-2 pt-1">
              <a href="https://github.com/Iamatto01" target="_blank" rel="noreferrer" aria-label="GitHub" className="p-2 rounded-xl bg-white/5 border border-white/10 text-neutral-300 hover:text-white hover:border-white/30 transition-colors">
                <Github size={15} />
              </a>
              <a href="https://www.linkedin.com/in/saifudinjamal/" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn" className="p-2 rounded-xl bg-white/5 border border-white/10 text-neutral-300 hover:text-white hover:border-white/30 transition-colors">
                <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
                  <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.67a1.66 1.66 0 0 0-1.66 1.66c0 .92.74 1.66 1.66 1.66a1.66 1.66 0 0 0 1.66-1.66c0-.92-.74-1.66-1.66-1.66Z" />
                </svg>
              </a>
              <a href="https://t.me/sentinelai_telebot" target="_blank" rel="noreferrer" aria-label="Telegram" className="p-2 rounded-xl bg-white/5 border border-white/10 text-neutral-300 hover:text-white hover:border-white/30 transition-colors">
                <Send size={15} />
              </a>
              <a href="https://discord.com/oauth2/authorize?client_id=1539651318648545420" target="_blank" rel="noreferrer" aria-label="Discord" className="p-2 rounded-xl bg-white/5 border border-white/10 text-neutral-300 hover:text-white hover:border-white/30 transition-colors">
                <MessageCircle size={15} />
              </a>
              <a href="mailto:muhammadsaifudinmj@gmail.com" aria-label="Email" className="p-2 rounded-xl bg-white/5 border border-white/10 text-neutral-300 hover:text-white hover:border-white/30 transition-colors">
                <Mail size={15} />
              </a>
            </div>
          </div>

          {/* Sitemap */}
          <div className="space-y-3 font-mono text-xs">
            <h4 className="font-bold uppercase tracking-wider text-white text-[11px]">Sitemap</h4>
            <ul className="space-y-2 text-neutral-400">
              {NAV_LINKS.map((l) => (
                <li key={l.to}>
                  <Link to={l.to} className="hover:text-white transition-colors">{l.label}</Link>
                </li>
              ))}
              <li><Link to="/login" className="hover:text-white transition-colors">Sign In / Register</Link></li>
            </ul>
          </div>

          {/* Solutions */}
          <div className="space-y-3 font-mono text-xs">
            <h4 className="font-bold uppercase tracking-wider text-white text-[11px]">Solutions</h4>
            <ul className="space-y-2 text-neutral-400">
              <li><Link to="/services" className="hover:text-white transition-colors">Autonomous Blackbox Pentesting</Link></li>
              <li><Link to="/services" className="hover:text-white transition-colors">Whitebox DevSecOps &amp; GitHub CI</Link></li>
              <li><Link to="/services" className="hover:text-white transition-colors">Autonomous Exploitation Engine</Link></li>
              <li><Link to="/services" className="hover:text-white transition-colors">Virtual CISO Advisory</Link></li>
              <li><Link to="/services" className="hover:text-white transition-colors">24/7 Surface Monitoring</Link></li>
            </ul>
          </div>

          {/* Tech Stack */}
          <div className="space-y-3 font-mono text-xs">
            <h4 className="font-bold uppercase tracking-wider text-white text-[11px]">Built With</h4>
            <ul className="space-y-2 text-neutral-400 font-mono">
              <li className="flex items-center gap-2"><Terminal size={13} className="text-white" /> Native Kali Engine</li>
              <li className="flex items-center gap-2"><Database size={13} className="text-white" /> SQLite WAL (Local-First)</li>
              <li className="flex items-center gap-2"><Cpu size={13} className="text-white" /> DeepSeek / Groq Multi-LLM</li>
              <li className="flex items-center gap-2"><ShieldCheck size={13} className="text-white" /> React + Vite Frontend</li>
            </ul>
          </div>
        </div>

        <div className="max-w-6xl mx-auto mt-10 pt-6 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-neutral-500">
          <span>&copy; {new Date().getFullYear()} SentinelAI &mdash; Muhammad Saifudin. All rights reserved.</span>
          <span className="flex items-center gap-1.5 text-neutral-400">
            <ShieldCheck size={12} className="text-white" />
            Academic research project &mdash; IIUM KICT Final Year Project 2
          </span>
        </div>
      </footer>
    </div>
  )
}
