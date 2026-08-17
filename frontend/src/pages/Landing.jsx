import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldAlert, Bot, Radar, FileText, ArrowRight, ShieldCheck, Cpu, DatabaseZap, Sparkles, Globe2, Binary, CheckCircle2,
  ChevronRight, ChevronDown, Layers, Terminal, Network, GitBranch, Zap, Server, Workflow, Code2, KeyRound, Activity
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import './Home.css'

export default function Landing() {
  const [interval, setInterval] = useState('monthly')
  const [archMode, setArchMode] = useState('osint') // 'osint' | 'mermaid'
  const [expandedCategories, setExpandedCategories] = useState({
    frontend: true, backend: true, hexstrike: true, ai: true, rag: true, devsecops: true
  })

  const toggleCategory = (cat) => {
    setExpandedCategories(prev => ({ ...prev, [cat]: !prev[cat] }))
  }
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

        <nav className="hidden md:flex items-center gap-8 text-xs font-semibold text-slate-300">
          <a href="#features" className="hover:text-cyan-400 transition-colors">Features</a>
          <a href="#pricing" className="hover:text-cyan-400 transition-colors">Pricing & Plans</a>
          <a href="#architecture" className="hover:text-cyan-400 transition-colors">Architecture</a>
        </nav>

        <div className="flex items-center gap-3">
          <Link to="/login" className="text-xs font-semibold text-slate-300 hover:text-white px-3 py-2">
            Sign In
          </Link>
          <Link to="/login?mode=register&plan=pro" className="at-home__btn at-home__btn--solid text-xs py-2.5 px-5 font-semibold shadow-glow flex items-center gap-2">
            <span>Get Started</span> <ArrowRight size={14} />
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
                src="/saif.png"
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
        </div>

        {/* System Architecture Section (OSINT Framework & Mermaid Style) */}
        <div id="architecture" className="my-20 max-w-6xl mx-auto px-4 space-y-8 scroll-mt-24">
          <div className="text-center space-y-3">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-bold uppercase tracking-wider">
              <Network size={14} className="text-cyan-400" /> Platform Engineering & Data Flow
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Real System Architecture & Workflow
            </h2>
            <p className="text-sm text-slate-400 max-w-2xl mx-auto">
              Explore SentinelAI's decoupled micro-service architecture, real-time HexStrike REST API engine, 51 AI specialist agent personas, and local FTS5 RAG payload search.
            </p>

            {/* Mode Switcher Buttons */}
            <div className="flex items-center justify-center gap-3 pt-4">
              <button
                onClick={() => setArchMode('osint')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'osint'
                    ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Network size={15} /> OSINT Framework Tree View
              </button>
              <button
                onClick={() => setArchMode('mermaid')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'mermaid'
                    ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Workflow size={15} /> Mermaid Data Flow Diagram
              </button>
            </div>
          </div>

          {/* OSINT FRAMEWORK TREE VIEW */}
          {archMode === 'osint' && (
            <div className="card p-6 sm:p-8 border border-white/15 bg-slate-950/80 shadow-2xl rounded-3xl space-y-6">
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500/80" />
                  <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                  <span className="text-xs font-mono text-slate-400 ml-2">sentinelai-system-architecture.tree</span>
                </div>
                <div className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-3 py-1 rounded-full border border-cyan-500/30">
                  Interactive Node Graph · Click category to collapse/expand
                </div>
              </div>

              {/* Tree Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* Category 1: Frontend Layer */}
                <div className="space-y-3 bg-slate-900/60 p-4 rounded-2xl border border-cyan-500/20 hover:border-cyan-400/40 transition-colors">
                  <div
                    onClick={() => toggleCategory('frontend')}
                    className="flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                      <Code2 size={16} />
                      <span>1. Frontend UI Layer</span>
                    </div>
                    {expandedCategories.frontend ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
                  </div>
                  {expandedCategories.frontend && (
                    <div className="pl-3 border-l-2 border-cyan-500/30 space-y-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-cyan-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>React 18 SPA (Vision UI)</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold">Vite 6</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">High-performance dark glassmorphic dashboard with live telemetry.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-cyan-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>Attack Surface Map</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold">SVG Force</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Force-directed topological graph with saved node location persistence.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-cyan-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>Interactive Finding Drawer</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">Drawer UI</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Layman plain-English vulns summary & AI chat assistant tab.</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Category 2: Backend Orchestrator */}
                <div className="space-y-3 bg-slate-900/60 p-4 rounded-2xl border border-purple-500/20 hover:border-purple-400/40 transition-colors">
                  <div
                    onClick={() => toggleCategory('backend')}
                    className="flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-purple-400 font-bold text-sm">
                      <Server size={16} />
                      <span>2. Express API Gateway</span>
                    </div>
                    {expandedCategories.backend ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
                  </div>
                  {expandedCategories.backend && (
                    <div className="pl-3 border-l-2 border-purple-500/30 space-y-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-purple-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>JWT Auth & Access Control</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold">JWT 12h</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Role-based access control (Admin, Analyst, Client portal permissions).</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-purple-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>SQLite WAL Local Database</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">Better-SQLite3</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Zero external cloud deps; embedded WAL database with auto backups.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-purple-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>Autonomous Exploitation Engine</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold">AEE State</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Exploit campaign state machine, Metasploit RPC bridge, & approval gates.</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Category 3: HexStrike Kali Engine */}
                <div className="space-y-3 bg-slate-900/60 p-4 rounded-2xl border border-red-500/20 hover:border-red-400/40 transition-colors">
                  <div
                    onClick={() => toggleCategory('hexstrike')}
                    className="flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-red-400 font-bold text-sm">
                      <Terminal size={16} />
                      <span>3. HexStrike Kali Engine</span>
                    </div>
                    {expandedCategories.hexstrike ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
                  </div>
                  {expandedCategories.hexstrike && (
                    <div className="pl-3 border-l-2 border-red-500/30 space-y-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-red-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>REST Gateway (127.0.0.1:8888)</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-bold">150+ Tools</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Orchestrates Nmap, Nuclei, Nikto, Subfinder, FFUF, SQLMap & Hydra.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-red-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>Static Whitebox AST Parser</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold">Code Review</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">AST regex scanner analyzing JS, Python, PHP, Java for injection & secrets.</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Category 4: 51 AI Specialist Personas */}
                <div className="space-y-3 bg-slate-900/60 p-4 rounded-2xl border border-amber-500/20 hover:border-amber-400/40 transition-colors">
                  <div
                    onClick={() => toggleCategory('ai')}
                    className="flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
                      <Bot size={16} />
                      <span>4. 51 AI Specialist Agents</span>
                    </div>
                    {expandedCategories.ai ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
                  </div>
                  {expandedCategories.ai && (
                    <div className="pl-3 border-l-2 border-amber-500/30 space-y-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-amber-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>Multi-Model LLM Client</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold">Groq / OpenRouter</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Dynamic failover between Groq Llama-3.3, OpenRouter, and Ollama local LLMs.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-amber-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>Verification & Remediation Agent</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">0% Noise</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Filters false positives, assigns CVSS risk scores, and generates patch diffs.</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Category 5: RAG Intelligence */}
                <div className="space-y-3 bg-slate-900/60 p-4 rounded-2xl border border-emerald-500/20 hover:border-emerald-400/40 transition-colors">
                  <div
                    onClick={() => toggleCategory('rag')}
                    className="flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                      <DatabaseZap size={16} />
                      <span>5. Local RAG Exploit Store</span>
                    </div>
                    {expandedCategories.rag ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
                  </div>
                  {expandedCategories.rag && (
                    <div className="pl-3 border-l-2 border-emerald-500/30 space-y-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-emerald-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>PayloadsAllTheThings FTS5</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">Full-Text</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Indexed SQLite FTS5 database querying real bypass payloads & PoCs.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-emerald-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>NVD CVE Cache & OWASP Top 10</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold">CVE Sync</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Categorizes findings by OWASP Top 10 (2021) and CWE IDs.</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Category 6: DevSecOps Delivery */}
                <div className="space-y-3 bg-slate-900/60 p-4 rounded-2xl border border-blue-500/20 hover:border-blue-400/40 transition-colors">
                  <div
                    onClick={() => toggleCategory('devsecops')}
                    className="flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-2 text-blue-400 font-bold text-sm">
                      <GitBranch size={16} />
                      <span>6. CI/CD & Delivery Layer</span>
                    </div>
                    {expandedCategories.devsecops ? <ChevronDown size={16} className="text-slate-400" /> : <ChevronRight size={16} className="text-slate-400" />}
                  </div>
                  {expandedCategories.devsecops && (
                    <div className="pl-3 border-l-2 border-blue-500/30 space-y-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-blue-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>GitHub PR Inline Review Bot</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold">Octokit Bot</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Posts line-by-line security review comments directly into GitHub Pull Requests.</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-950/70 border border-white/10 hover:border-blue-400/40 transition-colors">
                        <div className="font-semibold text-slate-100 flex items-center justify-between">
                          <span>PDF Email Transporter</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">Nodemailer</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">Generates executive PDF reports and delivers email attachments on commit push.</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* MERMAID DATA FLOW DIAGRAM VIEW */}
          {archMode === 'mermaid' && (
            <div className="card p-6 sm:p-8 border border-white/15 bg-slate-950/80 shadow-2xl rounded-3xl space-y-8">
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse" />
                  <span className="text-xs font-mono text-slate-300">Mermaid Pipeline Execution Flow Diagram</span>
                </div>
                <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full border border-emerald-500/30">
                  Sub-second Orchestration Pipeline
                </span>
              </div>

              {/* Sequential Flow Nodes */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
                {/* Step 1 */}
                <div className="p-5 rounded-2xl bg-slate-900/80 border border-cyan-500/40 space-y-3 relative hover:border-cyan-400 transition-colors shadow-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">Step 1 · Trigger</span>
                    <Globe2 size={16} className="text-cyan-400" />
                  </div>
                  <h4 className="text-sm font-extrabold text-white">Target Input / Webhook Push</h4>
                  <p className="text-xs text-slate-400">User submits Web/API URL or GitHub pushes code to linked repository.</p>
                  <div className="text-[10px] font-mono text-cyan-300 bg-cyan-950/60 p-2 rounded-lg border border-cyan-500/20">
                    POST /api/scans/launch
                  </div>
                </div>

                {/* Step 2 */}
                <div className="p-5 rounded-2xl bg-slate-900/80 border border-purple-500/40 space-y-3 relative hover:border-purple-400 transition-colors shadow-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">Step 2 · Orchestration</span>
                    <Server size={16} className="text-purple-400" />
                  </div>
                  <h4 className="text-sm font-extrabold text-white">Express Backend Gateway</h4>
                  <p className="text-xs text-slate-400">Authenticates JWT, verifies client quota, creates scan job record in SQLite DB.</p>
                  <div className="text-[10px] font-mono text-purple-300 bg-purple-950/60 p-2 rounded-lg border border-purple-500/20">
                    db.run('INSERT INTO scans...')
                  </div>
                </div>

                {/* Step 3 */}
                <div className="p-5 rounded-2xl bg-slate-900/80 border border-red-500/40 space-y-3 relative hover:border-red-400 transition-colors shadow-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">Step 3 · Execution</span>
                    <Terminal size={16} className="text-red-400" />
                  </div>
                  <h4 className="text-sm font-extrabold text-white">HexStrike REST Engine</h4>
                  <p className="text-xs text-slate-400">Chains 150+ Kali tools (Nmap, Nuclei, FFUF, SQLMap) + AST static code parser.</p>
                  <div className="text-[10px] font-mono text-red-300 bg-red-950/60 p-2 rounded-lg border border-red-500/20">
                    HTTP POST http://127.0.0.1:8888
                  </div>
                </div>

                {/* Step 4 */}
                <div className="p-5 rounded-2xl bg-slate-900/80 border border-amber-500/40 space-y-3 relative hover:border-amber-400 transition-colors shadow-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">Step 4 · AI Persona Filter</span>
                    <Bot size={16} className="text-amber-400" />
                  </div>
                  <h4 className="text-sm font-extrabold text-white">51 Specialist AI Personas</h4>
                  <p className="text-xs text-slate-400">Evaluates evidence, eliminates false positives, and calculates CVSS risk scores.</p>
                  <div className="text-[10px] font-mono text-amber-300 bg-amber-950/60 p-2 rounded-lg border border-amber-500/20">
                    Groq / OpenRouter AI Client
                  </div>
                </div>

                {/* Step 5 */}
                <div className="p-5 rounded-2xl bg-slate-900/80 border border-emerald-500/40 space-y-3 relative hover:border-emerald-400 transition-colors shadow-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Step 5 · RAG Enrichment</span>
                    <DatabaseZap size={16} className="text-emerald-400" />
                  </div>
                  <h4 className="text-sm font-extrabold text-white">PayloadsAllTheThings RAG</h4>
                  <p className="text-xs text-slate-400">Queries SQLite FTS5 vector index for bypass payloads and auto-remediation diffs.</p>
                  <div className="text-[10px] font-mono text-emerald-300 bg-emerald-950/60 p-2 rounded-lg border border-emerald-500/20">
                    MATCH 'payload_index MATCH...'
                  </div>
                </div>

                {/* Step 6 */}
                <div className="p-5 rounded-2xl bg-slate-900/80 border border-blue-500/40 space-y-3 relative hover:border-blue-400 transition-colors shadow-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">Step 6 · Delivery</span>
                    <FileText size={16} className="text-blue-400" />
                  </div>
                  <h4 className="text-sm font-extrabold text-white">PDF & GitHub Delivery</h4>
                  <p className="text-xs text-slate-400">Generates executive PDF report, emails attachment, and posts GitHub PR inline review.</p>
                  <div className="text-[10px] font-mono text-blue-300 bg-blue-950/60 p-2 rounded-lg border border-blue-500/20">
                    PDFKit + Nodemailer + Octokit
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Pricing Section */}
        <div id="pricing" className="my-16 max-w-5xl mx-auto px-4 space-y-8">
          <div className="text-center space-y-3">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-bold uppercase tracking-wider">
              <Sparkles size={12} className="text-cyan-400" /> Transparent SaaS Pricing
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Choose Your SentinelAI Plan
            </h2>
            <p className="text-sm text-slate-400 max-w-xl mx-auto">
              Subscribe to unlock autonomous AI code audits, Kali Linux vulnerability scans, continuous GitHub webhooks, and executive PDF reports.
            </p>

            {/* Monthly / Yearly Switch */}
            <div className="flex items-center justify-center gap-3 pt-4">
              <span className={`text-xs font-semibold ${interval === 'monthly' ? 'text-white' : 'text-slate-500'}`}>Monthly Billing</span>
              <button
                onClick={() => setInterval(interval === 'monthly' ? 'yearly' : 'monthly')}
                className="w-12 h-6 rounded-full bg-slate-900 border border-white/20 p-0.5 relative transition-colors cursor-pointer"
              >
                <div
                  className={`w-5 h-5 rounded-full bg-cyan-400 transition-transform duration-200 ${
                    interval === 'yearly' ? 'translate-x-6' : 'translate-x-0'
                  }`}
                />
              </button>
              <span className={`text-xs font-semibold flex items-center gap-1.5 ${interval === 'yearly' ? 'text-white' : 'text-slate-500'}`}>
                Yearly Billing
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                  Save 17%
                </span>
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Pro Card */}
            <div className="card p-8 border-cyan-500/50 bg-gradient-to-b from-slate-900/90 via-slate-900/80 to-cyan-950/30 shadow-2xl shadow-cyan-950/40 ring-1 ring-cyan-400/40 relative flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 text-slate-950 font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-cyan-500/30 flex items-center gap-1">
                <Sparkles size={10} className="fill-slate-950" /> Most Popular
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-extrabold text-white">SentinelAI Pro</h3>
                  <div className="mt-3 flex items-baseline gap-1">
                    <span className="text-4xl font-black text-white">${interval === 'yearly' ? '190' : '19'}</span>
                    <span className="text-xs text-slate-400 font-medium">{interval === 'yearly' ? '/year' : '/month'}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Ideal for active developers and software teams needing continuous audit automation.
                  </p>
                </div>

                <div className="h-px bg-white/10" />

                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-cyan-400 shrink-0" />
                    <span><strong>50 AI Code Audits</strong> / month</span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-cyan-400 shrink-0" />
                    <span><strong>5 Linked Repositories</strong> (Public & Private)</span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-cyan-400 shrink-0" />
                    <span>Continuous Webhooks (Push & PR triggers)</span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-cyan-400 shrink-0" />
                    <span>Automated Email PDF Delivery on every commit</span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-cyan-400 shrink-0" />
                    <span>AI Auto-Fix & Remediation Diffs</span>
                  </li>
                </ul>
              </div>

              <div className="pt-8">
                <Link
                  to={`/login?mode=register&plan=pro&interval=${interval}`}
                  className="btn-primary w-full justify-center py-3.5 text-xs font-extrabold shadow-glow hover:scale-[1.01] transition-transform flex items-center gap-2"
                >
                  <span>Subscribe to SentinelAI Pro</span> <ArrowRight size={14} />
                </Link>
              </div>
            </div>

            {/* Enterprise Card */}
            <div className="card p-8 border-white/10 bg-slate-950/70 hover:border-white/20 flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
              <div className="space-y-6">
                <div>
                  <h3 className="text-xl font-extrabold text-white">SentinelAI Enterprise</h3>
                  <div className="mt-3 flex items-baseline gap-1">
                    <span className="text-4xl font-black text-white">${interval === 'yearly' ? '790' : '79'}</span>
                    <span className="text-xs text-slate-400 font-medium">{interval === 'yearly' ? '/year' : '/month'}</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Full continuous DevSecOps pipeline for organizations requiring unlimited audits & compliance.
                  </p>
                </div>

                <div className="h-px bg-white/10" />

                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span><strong>Unlimited AI Code Audits</strong></span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span><strong>Unlimited GitHub Repositories</strong></span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span>GitHub PR Bot Inline Code Review</span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span>Real-time Slack / Discord Webhook Alerts</span>
                  </li>
                  <li className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span>Executive White-label PDF Reports & SLA</span>
                  </li>
                </ul>
              </div>

              <div className="pt-8">
                <Link
                  to={`/login?mode=register&plan=enterprise&interval=${interval}`}
                  className="btn-secondary w-full justify-center py-3.5 text-xs font-extrabold border-white/20 hover:border-cyan-400/50 hover:text-cyan-300 transition-colors flex items-center gap-2"
                >
                  <span>Subscribe to Enterprise</span> <ArrowRight size={14} />
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* CTA Section */}
        <div className="at-home__cta">
          <h2 className="text-3xl font-bold text-white mb-3">Ready to Audit Your Targets?</h2>
          <p className="text-slate-400 max-w-xl mx-auto mb-6">
            Log in to access your SentinelAI Pentest Suite dashboard, launch URL scans, or run GitHub continuous code audits.
          </p>
          <div className="flex justify-center gap-4">
            <Link to="/login?mode=register&plan=pro" className="at-home__btn at-home__btn--solid at-home__btn--hero">
              Get Started Now <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </main>
    </div>
  )
}
