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
      {/* Ambient Grid & Background Blobs */}
      <div className="at-home__grid" />
      <div className="at-home__noise" />
      <div className="at-home__blob at-home__blob--a" />
      <div className="at-home__blob at-home__blob--b" />
      <div className="at-home__blob at-home__blob--c" />

      {/* ── High-Tech Glassmorphic Header ─────────────────────────────────── */}
      <header className="sticky top-0 sm:top-4 z-50 w-full sm:w-[calc(100%-2rem)] sm:max-w-6xl sm:mx-auto px-3 sm:px-0 transition-all duration-300">
        <div
          className={`w-full px-4 sm:px-6 py-2.5 sm:py-3 flex items-center justify-between sm:rounded-2xl transition-all duration-300 ${
            scrolled
              ? 'bg-[#0e1017]/90 backdrop-blur-2xl border-b sm:border border-white/[0.08] shadow-[0_12px_36px_rgba(0,0,0,0.7),0_0_20px_rgba(14,165,233,0.08)]'
              : 'bg-[#0e1017]/75 backdrop-blur-xl border-b sm:border border-white/[0.08] shadow-[0_8px_32px_rgba(0,0,0,0.4)]'
          }`}
        >
          {/* Brand Logo */}
          <Link to="/" className="flex items-center gap-2.5 group shrink-0">
            <div className="p-1 rounded-xl bg-[#161822] border border-white/10 group-hover:border-cyan-400/50 group-hover:shadow-[0_0_14px_rgba(56,189,248,0.25)] transition-all duration-300">
              <InspectorLogo size={24} className="sm:w-7 sm:h-7" />
            </div>
            <span className="font-extrabold text-sm sm:text-base text-white tracking-tight group-hover:text-cyan-300 transition-colors">
              Sentinel<span className="text-cyan-400">AI</span>
            </span>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden lg:flex items-center gap-1 bg-white/[0.03] p-1 rounded-xl border border-white/[0.06]">
            {NAV_LINKS.map((l) => {
              const isActive = location.pathname === l.to
              return (
                <Link
                  key={l.to}
                  to={l.to}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 shadow-[0_0_12px_rgba(0,242,254,0.12)] font-bold'
                      : 'text-zinc-400 hover:text-white hover:bg-white/[0.06] border border-transparent'
                  }`}
                >
                  {l.label}
                </Link>
              )
            })}
          </nav>

          {/* Action CTAs */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Interactive Theme Split protocol button */}
            {!isSplitPreview && (
              <button
                type="button"
                onClick={() => window.dispatchEvent(new CustomEvent('sentinel_replay_theme_intro'))}
                className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 hover:border-white/20 transition-all cursor-pointer"
                title="Open Interactive Theme Split Screen"
              >
                <Sparkles size={13} className="text-cyan-400" />
                <span>Theme Split</span>
              </button>
            )}

            {/* Dark / Light Mode Toggle */}
            <button
              onClick={toggleNightMode}
              className="p-2 rounded-xl text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 hover:border-white/20 transition-all cursor-pointer flex items-center justify-center"
              title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              aria-label="Toggle Theme"
            >
              {isNight ? (
                <Sun size={15} className="text-amber-400 hover:rotate-90 transition-transform duration-300" />
              ) : (
                <Moon size={15} className="text-indigo-400 hover:-rotate-12 transition-transform duration-300" />
              )}
            </button>

            {/* Desktop / Tablet Sign In */}
            <Link
              to="/login"
              className="hidden md:inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold text-zinc-300 hover:text-white bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 hover:border-white/20 transition-all"
            >
              <LogIn size={13} className="text-zinc-400" />
              <span>Sign In</span>
            </Link>

            {/* Primary Get Started CTA */}
            <Link
              to="/login?mode=register&plan=trial"
              className="inline-flex items-center gap-1.5 px-3.5 sm:px-4 py-1.5 sm:py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 shadow-md shadow-cyan-950/50 border border-cyan-400/30 hover:shadow-cyan-500/25 hover:scale-[1.02] active:scale-[0.98] transition-all"
            >
              <Sparkles size={13} className="hidden sm:inline-block text-cyan-200" />
              <span>Get Started Free</span>
              <ArrowRight size={13} />
            </Link>

            {/* Mobile Hamburger Toggle Button */}
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="lg:hidden p-2 rounded-xl bg-white/5 border border-white/10 text-slate-200 hover:text-cyan-300 hover:border-cyan-400/40 hover:bg-white/10 active:scale-95 transition-all cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              {mobileOpen ? <X size={17} /> : <Menu size={17} />}
            </button>
          </div>
        </div>
      </header>

      {/* ── Mobile Navigation Drawer Backdrop & Modal ────────────────────── */}
      {mobileOpen && (
        <>
          {/* Backdrop Overlay */}
          <div
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-40 lg:hidden transition-opacity"
            onClick={() => setMobileOpen(false)}
          />

          {/* Drawer Card */}
          <div className="fixed inset-x-3 sm:inset-x-6 top-16 sm:top-20 z-50 lg:hidden rounded-2xl sm:rounded-3xl border border-cyan-500/20 bg-slate-950/95 backdrop-blur-2xl shadow-[0_20px_50px_rgba(0,0,0,0.8),0_0_30px_rgba(0,242,254,0.15)] p-4 sm:p-5 space-y-4 max-h-[85vh] overflow-y-auto">
            {/* Engine Status Banner */}
            <div className="flex items-center justify-between px-3.5 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-xs text-cyan-300">
              <span className="flex items-center gap-2 font-mono text-[11px]">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Native Kali Engine Active
              </span>
              <span className="text-[10px] text-slate-400 font-mono">150+ Tools</span>
            </div>

            {/* Navigation List */}
            <nav className="space-y-1.5">
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
                        ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-300 border border-cyan-400/30 shadow-[0_0_15px_rgba(0,242,254,0.12)]'
                        : 'text-slate-300 hover:bg-white/5 hover:text-white border border-transparent'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-1.5 rounded-lg ${isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-white/5 text-slate-400'}`}>
                        <Icon size={16} />
                      </div>
                      <div className="text-left">
                        <div className="leading-tight">{l.label}</div>
                        <div className="text-[10px] text-slate-500 font-normal leading-tight mt-0.5">{l.desc}</div>
                      </div>
                    </div>
                    <ChevronRight size={15} className={isActive ? 'text-cyan-400' : 'text-slate-600'} />
                  </Link>
                )
              })}
            </nav>

            {/* Drawer Action CTAs */}
            <div className="pt-3 border-t border-white/10 space-y-2">
              <div className="flex items-center">
                <button
                  onClick={toggleNightMode}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-xl text-xs font-semibold bg-white/5 border border-white/10 text-slate-200 cursor-pointer"
                >
                  {isNight ? <Sun size={14} className="text-amber-400" /> : <Moon size={14} className="text-indigo-400" />}
                  <span>{isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}</span>
                </button>
              </div>

              <Link
                to="/login?mode=register&plan=trial"
                onClick={() => setMobileOpen(false)}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl font-bold text-sm text-white bg-gradient-to-r from-cyan-500 to-blue-600 shadow-md transition-all"
              >
                <Sparkles size={15} />
                <span>Start Free Assessment</span>
                <ArrowRight size={15} />
              </Link>
              <Link
                to="/login"
                onClick={() => setMobileOpen(false)}
                className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-xl font-semibold text-xs text-slate-300 bg-white/5 border border-white/10 hover:bg-white/10 hover:text-white transition-all"
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
        style={{ background: 'rgba(2, 6, 23, 0.55)', backdropFilter: 'blur(30px)', WebkitBackdropFilter: 'blur(30px)' }}
      >
        <div className="max-w-6xl mx-auto grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10">
          {/* Brand */}
          <div className="space-y-3">
            <div className="flex items-center gap-2.5">
              <InspectorLogo size={28} />
              <span className="font-extrabold text-white tracking-tight">SentinelAI</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Autonomous AI security assessment platform — 150+ Kali tools, 53 specialist AI personas, local-first RAG intelligence.
            </p>
            <div className="flex items-center gap-2 pt-1">
              <a href="https://github.com/Iamatto01" target="_blank" rel="noreferrer" aria-label="GitHub" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-cyan-300 hover:border-cyan-400/50 transition-colors">
                <Github size={15} />
              </a>
              <a href="https://t.me/sentinelai_telebot" target="_blank" rel="noreferrer" aria-label="Telegram" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-cyan-300 hover:border-cyan-400/50 transition-colors">
                <Send size={15} />
              </a>
              <a href="https://discord.com/oauth2/authorize?client_id=1539651318648545420" target="_blank" rel="noreferrer" aria-label="Discord" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-indigo-300 hover:border-indigo-400/50 transition-colors">
                <MessageCircle size={15} />
              </a>
              <a href="mailto:muhammadsaifudinmj@gmail.com" aria-label="Email" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-emerald-300 hover:border-emerald-400/50 transition-colors">
                <Mail size={15} />
              </a>
            </div>
          </div>

          {/* Sitemap */}
          <div className="space-y-3">
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-cyan-300">Sitemap</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              {NAV_LINKS.map((l) => (
                <li key={l.to}>
                  <Link to={l.to} className="hover:text-cyan-300 transition-colors">{l.label}</Link>
                </li>
              ))}
              <li><Link to="/login" className="hover:text-cyan-300 transition-colors">Sign In / Register</Link></li>
            </ul>
          </div>

          {/* Services */}
          <div className="space-y-3">
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-cyan-300">Solutions</h4>
            <ul className="space-y-2 text-xs text-slate-400">
              <li><Link to="/services" className="hover:text-cyan-300 transition-colors">Autonomous Blackbox Pentesting</Link></li>
              <li><Link to="/services" className="hover:text-cyan-300 transition-colors">Whitebox DevSecOps & GitHub CI</Link></li>
              <li><Link to="/services" className="hover:text-cyan-300 transition-colors">Autonomous Exploitation Engine</Link></li>
              <li><Link to="/services" className="hover:text-cyan-300 transition-colors">Virtual CISO Advisory</Link></li>
              <li><Link to="/services" className="hover:text-cyan-300 transition-colors">24/7 Surface Monitoring</Link></li>
            </ul>
          </div>

          {/* Tech Stack */}
          <div className="space-y-3">
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-cyan-300">Built With</h4>
            <ul className="space-y-2 text-xs text-slate-400 font-mono">
              <li className="flex items-center gap-2"><Terminal size={13} className="text-emerald-400" /> Native Kali Engine</li>
              <li className="flex items-center gap-2"><Database size={13} className="text-amber-400" /> SQLite WAL (Local-First)</li>
              <li className="flex items-center gap-2"><Cpu size={13} className="text-cyan-400" /> DeepSeek / Groq Multi-LLM</li>
              <li className="flex items-center gap-2"><ShieldCheck size={13} className="text-indigo-400" /> React + Vite Frontend</li>
            </ul>
          </div>
        </div>

        <div className="max-w-6xl mx-auto mt-10 pt-6 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-slate-500">
          <span>&copy; {new Date().getFullYear()} SentinelAI &mdash; Muhammad Saifudin. All rights reserved.</span>
          <span className="flex items-center gap-1.5">
            <ShieldCheck size={12} className="text-cyan-500" />
            Academic research project &mdash; IIUM KICT Final Year Project 2
          </span>
        </div>
      </footer>
    </div>
  )
}
