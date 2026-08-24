import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  ArrowRight, Menu, X, Github, Send, MessageCircle, Mail,
  ShieldCheck, Cpu, Database, Terminal
} from 'lucide-react'
import InspectorLogo from './InspectorLogo.jsx'

const NAV_LINKS = [
  { to: '/', label: 'Home' },
  { to: '/about', label: 'About' },
  { to: '/tools', label: 'Tools & AI' },
  { to: '/services', label: 'Services' },
  { to: '/pricing', label: 'Pricing' },
  { to: '/contact', label: 'Contact' },
]

const GLASS = {
  background: 'rgba(6, 11, 38, 0.45)',
  backdropFilter: 'blur(40px) saturate(180%)',
  WebkitBackdropFilter: 'blur(40px) saturate(180%)',
}

export default function PublicLayout({ children }) {
  const [mobileOpen, setMobileOpen] = useState(false)
  const location = useLocation()

  // Close mobile drawer on route change + scroll to top on navigation
  useEffect(() => {
    setMobileOpen(false)
    window.scrollTo({ top: 0, behavior: 'instant' })
  }, [location.pathname])

  return (
    <div className="at-home min-h-screen relative overflow-x-hidden">
      {/* Ambient Grid & Background Blobs */}
      <div className="at-home__grid" />
      <div className="at-home__noise" />
      <div className="at-home__blob at-home__blob--a" />
      <div className="at-home__blob at-home__blob--b" />
      <div className="at-home__blob at-home__blob--c" />

      {/* ── Floating Glassmorphic Header ─────────────────────────────────── */}
      <header
        className="sticky top-5 sm:top-6 z-50 w-[calc(100%-2.5rem)] max-w-5xl mx-auto px-6 sm:px-8 py-3 flex items-center justify-between rounded-full border border-white/[0.12] shadow-2xl transition-all mb-2"
        style={{ ...GLASS, boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.08)' }}
      >
        <Link to="/" className="flex items-center gap-2.5 group shrink-0">
          <InspectorLogo size={26} />
          <span className="font-extrabold text-sm sm:text-base text-white tracking-tight group-hover:text-cyan-300 transition-colors">
            SentinelAI
          </span>
        </Link>

        <nav className="hidden md:flex items-center gap-6 text-xs font-bold text-slate-300">
          {NAV_LINKS.map((l) => (
            <Link
              key={l.to}
              to={l.to}
              className={`transition-colors ${
                location.pathname === l.to ? 'text-cyan-400' : 'hover:text-cyan-400'
              }`}
            >
              {l.label}
            </Link>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          <Link to="/login" className="hidden sm:inline-flex btn-thin">
            Sign In
          </Link>
          <Link
            to="/login?mode=register&plan=pro"
            className="btn-rounded-pulse btn-rounded-pulse--sm"
          >
            <span>Get Started</span>
          </Link>
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden p-2 rounded-xl bg-white/5 border border-white/10 text-slate-200 cursor-pointer"
            aria-label="Toggle navigation menu"
          >
            {mobileOpen ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>
      </header>

      {/* ── Mobile Navigation Drawer ─────────────────────────────────────── */}
      {mobileOpen && (
        <div className="fixed inset-x-4 top-20 z-40 md:hidden rounded-3xl border border-white/15 shadow-2xl p-4 space-y-1" style={GLASS}>
          {NAV_LINKS.map((l) => (
            <Link
              key={l.to}
              to={l.to}
              className={`block px-4 py-2.5 rounded-xl text-sm font-bold transition-colors ${
                location.pathname === l.to
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-400/30'
                  : 'text-slate-300 hover:bg-white/5 hover:text-white'
              }`}
            >
              {l.label}
            </Link>
          ))}
          <Link to="/login" className="block px-4 py-2.5 rounded-xl text-sm font-bold text-slate-300 hover:bg-white/5 hover:text-white">
            Sign In
          </Link>
        </div>
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
              Autonomous AI security assessment platform — 150+ Kali tools, 51 specialist AI personas, local-first RAG intelligence.
            </p>
            <div className="flex items-center gap-2 pt-1">
              <a href="https://github.com/Iamatto01" target="_blank" rel="noreferrer" aria-label="GitHub" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-cyan-300 hover:border-cyan-400/50 transition-colors">
                <Github size={15} />
              </a>
              <a href="https://t.me/" target="_blank" rel="noreferrer" aria-label="Telegram" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-cyan-300 hover:border-cyan-400/50 transition-colors">
                <Send size={15} />
              </a>
              <a href="https://discord.com/" target="_blank" rel="noreferrer" aria-label="Discord" className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 hover:text-indigo-300 hover:border-indigo-400/50 transition-colors">
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
              <li className="flex items-center gap-2"><Terminal size={13} className="text-emerald-400" /> Hexstrike Kali Engine</li>
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
