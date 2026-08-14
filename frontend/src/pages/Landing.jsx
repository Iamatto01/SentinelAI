import React from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldAlert, Bot, Radar, FileText, ArrowRight, ShieldCheck, Cpu, DatabaseZap, Sparkles, Globe2, Binary
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import './Home.css'

export default function Landing() {
  return (
    <div className="at-home min-h-screen relative overflow-x-hidden">
      {/* Scroll indicator bar */}
      <div className="at-home__scroll-bar" />

      {/* Grid overlay */}
      <div className="at-home__grid" />
      <div className="at-home__noise" />

      {/* Ambient background blobs */}
      <div className="at-home__blob at-home__blob--a" />
      <div className="at-home__blob at-home__blob--b" />
      <div className="at-home__blob at-home__blob--c" />

      {/* Header */}
      <header className="w-full px-6 sm:px-12 py-6 flex items-center justify-between max-w-7xl mx-auto z-20 relative">
        <Link to="/" className="at-home__brand flex items-center gap-3">
          <InspectorLogo size={36} />
          <span className="font-bold text-lg text-white tracking-tight">SentinelAI</span>
        </Link>

        <div className="flex items-center gap-4">
          <Link to="/login" className="at-home__btn at-home__btn--solid text-xs py-2.5 px-5 font-semibold shadow-glow flex items-center gap-2">
            <span>Sign In</span> <ArrowRight size={14} />
          </Link>
        </div>
      </header>


      {/* Main Content */}
      <main className="at-home__content">
        <div className="at-home__hero at-stagger-1">
          <div className="at-home__eyebrow">
            <Sparkles size={14} className="text-cyan-400 animate-pulse" />
            <span>Unified Pentest Platform v2.0</span>
          </div>

          <h1 className="at-home__title text-white">
            Autonomous AI <br />
            <span className="at-home__gradient-text font-extrabold">
              Security Assessment
            </span>
          </h1>

          <p className="at-home__subtitle">
            SentinelAI orchestrates 150+ real Kali Linux pentest tools via the Hexstrike Engine, 51 specialist AI personas, and local-first RAG knowledge base.
          </p>

          <div className="at-home__hero-actions mt-4">
            <Link to="/login" className="at-home__btn at-home__btn--solid at-home__btn--hero shadow-glow hover:scale-105 transition-transform">
              Start Free Assessment <ArrowRight size={16} />
            </Link>
            <a href="#features" className="at-home__btn at-home__btn--ghost at-home__btn--hero hover:border-cyan-400/50">
              Explore Capabilities
            </a>
          </div>

          <div className="at-home__metrics at-stagger-2">
            <article className="hover:border-cyan-400/50 transition-colors">
              <h3 className="text-cyan-400">150+ Tools</h3>
              <p>Hexstrike Kali Security Engine</p>
            </article>
            <article className="hover:border-amber-400/50 transition-colors">
              <h3 className="text-amber-400">51 Personas</h3>
              <p>Specialist AI Verification Agents</p>
            </article>
            <article className="hover:border-emerald-400/50 transition-colors">
              <h3 className="text-emerald-400">0% Noise</h3>
              <p>Automated False-Positive Filtering</p>
            </article>
          </div>
        </div>

        {/* Hero Visual Card */}
        <div className="at-home__visual at-stagger-2">
          <div className="at-home__visual-frame glass p-6 border border-white/15 rounded-3xl flex flex-col justify-between shadow-2xl relative overflow-hidden">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                <InspectorLogo size={40} />
                <div>
                  <h3 className="font-bold text-slate-100 text-base">SentinelAI Inspector Core</h3>
                  <p className="text-xs text-red-400 font-mono flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-red-400 animate-ping inline-block" />
                    Status: Active Scanning Engine
                  </p>
                </div>
              </div>
              <span className="chip bg-red-500/20 text-red-400 border border-red-500/40 text-xs px-3 py-1 font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" /> 24/7 Monitoring
              </span>
            </div>

            <div className="my-6 space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between hover:border-emerald-400/40 transition-colors">
                <span className="text-slate-400">Hexstrike API Engine</span>
                <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> 127.0.0.1:8888 (Online)
                </span>
              </div>
              <div className="p-3 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between hover:border-cyan-400/40 transition-colors">
                <span className="text-slate-400">AI Agents Verification</span>
                <span className="text-cyan-400 font-semibold">51 Specialist Personas</span>
              </div>
              <div className="p-3 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between hover:border-amber-400/40 transition-colors">
                <span className="text-slate-400">Knowledge Base RAG</span>
                <span className="text-amber-400 font-semibold">PayloadsAllTheThings FTS5</span>
              </div>
            </div>

            <div className="pt-4 border-t border-white/10 flex justify-between items-center text-xs">
              <span className="text-slate-400">Ready to audit targets?</span>
              <Link to="/login" className="btn-primary text-xs py-2 px-4 hover:scale-105 transition-transform">
                Launch Dashboard
              </Link>
            </div>
          </div>
        </div>

        {/* FYP 2 Creator Showcase Card */}
        <div className="at-home__hero max-w-5xl mx-auto my-12 px-4">
          <div className="glass p-6 sm:p-8 border border-cyan-500/30 rounded-3xl bg-slate-950/60 shadow-2xl backdrop-blur-2xl flex flex-col md:flex-row items-center gap-6 sm:gap-8 relative overflow-hidden group hover:border-cyan-400/60 transition-all duration-500">
            <div className="absolute -right-20 -bottom-20 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none group-hover:bg-cyan-500/20 transition-all duration-500" />
            
            {/* Avatar Frame */}
            <div className="relative shrink-0">
              <div className="absolute -inset-1.5 rounded-2xl bg-gradient-to-r from-cyan-400 via-accent to-red-500 opacity-75 blur-md group-hover:opacity-100 transition duration-500 animate-pulse" />
              <img
                src="/fyp2_presenter.png"
                alt="Muhammad Saifudin - FYP 2 Showcase Architect"
                className="relative w-36 h-36 sm:w-44 sm:h-44 rounded-2xl object-cover border-2 border-slate-900 shadow-2xl"
              />
              <span className="absolute -bottom-2 right-2 bg-slate-950/90 text-cyan-400 text-[10px] font-extrabold px-2.5 py-1 rounded-full border border-cyan-400/40 shadow-lg uppercase tracking-wider">
                FYP 2 Creator
              </span>
            </div>

            {/* Showcase Info */}
            <div className="flex-1 text-center md:text-left space-y-2.5 z-10">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-semibold">
                <Sparkles size={13} className="text-cyan-400 animate-spin" /> Final Year Project 2 Showcase
              </div>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                Muhammad Saifudin
              </h2>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-medium">
                Lead Architect & Researcher for <span className="text-cyan-300 font-bold">SentinelAI</span> — Unified Autonomous Penetration Testing Platform combining 150+ Kali Linux Security Tools, 51 Specialist AI Personas, and RAG Exploit Intelligence.
              </p>
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 pt-1 text-[11px] font-mono">
                <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300">Degree Final Year Project</span>
                <span className="px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-400/30 text-emerald-300">Autonomous Pentesting</span>
                <span className="px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-400/30 text-cyan-300">Kali Linux REST Engine</span>
              </div>
            </div>
          </div>
        </div>

        {/* Ticker / Signal Strip */}
        <div className="at-home__signal-strip at-stagger-3">
          <div className="at-home__signal-track">
            <span>NMAP PORT RECON</span>
            <span>SQLMAP INJECTION PROBE</span>
            <span>NUCLEI VULN SCAN</span>
            <span>FFUF DIRECTORY BRUTEFORCE</span>
            <span>WHITEBOX CODE AUDIT</span>
            <span>51 AI SPECIALIST PERSONAS</span>
            <span>HEXSTRIKE KALI ENGINE</span>
          </div>
        </div>

        {/* Features Section */}
        <div id="features" className="at-home__features at-stagger-4">
          <div className="card p-6 border border-white/10 bg-white/[0.03] backdrop-blur-xl hover:border-cyan-400/50 hover:-translate-y-1 transition-all duration-300">
            <Bot className="text-cyan-400 mb-3" size={32} />
            <h3 className="text-lg font-bold text-white mb-2">51 Specialist AI Agents</h3>
            <p className="text-sm text-slate-400">
              Automated routing of findings to specialized AI personas (Web Hunter, Database Attacker, Code Auditor) to filter out noise and false positives.
            </p>
          </div>
          <div className="card p-6 border border-white/10 bg-white/[0.03] backdrop-blur-xl hover:border-amber-400/50 hover:-translate-y-1 transition-all duration-300">
            <Radar className="text-amber-400 mb-3" size={32} />
            <h3 className="text-lg font-bold text-white mb-2">150+ Kali Security Tools</h3>
            <p className="text-sm text-slate-400">
              Hexstrike REST API engine dynamically chains nmap, nuclei, sqlmap, ffuf, nikto, subfinder, and more based on target analysis.
            </p>
          </div>
          <div className="card p-6 border border-white/10 bg-white/[0.03] backdrop-blur-xl hover:border-emerald-400/50 hover:-translate-y-1 transition-all duration-300">
            <ShieldCheck className="text-emerald-400 mb-3" size={32} />
            <h3 className="text-lg font-bold text-white mb-2">Blackbox & Whitebox Unified</h3>
            <p className="text-sm text-slate-400">
              Scan live website URLs or upload source code (JavaScript, Python, PHP, Java) for automated static code review in one unified platform.
            </p>
          </div>
          <div className="card p-6 border border-white/10 bg-white/[0.03] backdrop-blur-xl hover:border-red-400/50 hover:-translate-y-1 transition-all duration-300">
            <DatabaseZap className="text-red-400 mb-3" size={32} />
            <h3 className="text-lg font-bold text-white mb-2">RAG Exploits & PoC Search</h3>
            <p className="text-sm text-slate-400">
              Embedded SQLite FTS5 vector search queries PayloadsAllTheThings database to suggest instant Proof-of-Concept exploits.
            </p>
          </div>
        </div>

        {/* CTA Section */}
        <div className="at-home__cta">
          <h2 className="text-3xl font-bold text-white mb-3">Ready to Assessment Your Targets?</h2>
          <p className="text-slate-400 max-w-xl mx-auto mb-6">
            Log in to access your SentinelAI Pentest Suite dashboard, launch blackbox scans, or run whitebox code audits.
          </p>
          <div className="flex justify-center gap-4">
            <Link to="/login" className="at-home__btn at-home__btn--solid at-home__btn--hero">
              Get Started Now <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </main>
    </div>
  )
}
