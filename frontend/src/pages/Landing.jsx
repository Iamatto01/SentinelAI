import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldAlert, Bot, Radar, FileText, ShieldCheck, Cpu, DatabaseZap, Sparkles, Globe2, Binary, CheckCircle2,
  ChevronRight, ChevronDown, Layers, Terminal, Network, GitBranch, Zap, Server, Workflow, Code2, KeyRound, Activity,
  ArrowRight
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import SystemTree from '../components/SystemTree.jsx'
import PageTurnTransition from '../components/PageTurnTransition.jsx'
import PublicLayout from '../components/PublicLayout.jsx'
import MermaidDiagram from '../components/MermaidDiagram.jsx'
import './Home.css'

export default function Landing() {
  const [interval, setInterval] = useState('monthly')
  const [archMode, setArchMode] = useState('tree') // 'tree' | 'flow' | 'mermaid'
  const [hoveredStep, setHoveredStep] = useState(null)
  const [agentsCount, setAgentsCount] = useState(53)

  useEffect(() => {
    fetch('/api/public/stats')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.agentsCount) setAgentsCount(d.agentsCount)
      })
      .catch(() => {})
  }, [])

  const ARCH_STEPS = [
    {
      id: 1,
      num: '01',
      title: 'Target Ingestion & Triggers',
      short: 'URL scan submission or automated GitHub Webhook trigger on commit push / PR.',
      icon: Globe2,
      tech: 'REST API & Webhooks',
      details: [
        { label: 'Blackbox Trigger', desc: 'Live target URL or IP range entered via web dashboard' },
        { label: 'Whitebox Webhook', desc: 'GitHub Push & Pull Request event listener (Octokit Bot)' },
        { label: 'Scope Boundary', desc: 'Automated CIDR and domain validation to prevent unauthorized scans' }
      ]
    },
    {
      id: 2,
      num: '02',
      title: 'Express API Gateway',
      short: 'JWT 12h authentication, RBAC access control, scan quota verification, & SQLite WAL DB.',
      icon: Server,
      tech: 'Node.js & SQLite WAL',
      details: [
        { label: 'Role-Based Auth', desc: 'Admin, Security Analyst, and Client portal permission isolation' },
        { label: 'Quota Gatekeeper', desc: 'Enforces monthly scan limits per subscription tier before execution' },
        { label: 'Embedded WAL DB', desc: 'Local zero-cloud SQLite storage with point-in-time audit logs' }
      ]
    },
    {
      id: 3,
      num: '03',
      title: 'Native Kali Engine',
      short: 'Chains 150+ Kali Linux pentest tools via direct subprocess execution and runs AST static code analysis.',
      icon: Terminal,
      tech: '150+ Kali Tools (Direct Execution)',
      details: [
        { label: 'Recon & Discovery', desc: 'Nmap port scan, Subfinder subdomain recon, Masscan, WhatWeb' },
        { label: 'Vuln Probing', desc: 'Nuclei template scans, Nikto, SQLMap injection, FFUF fuzzing' },
        { label: 'AST Code Parser', desc: 'Static code parser scanning JS, Python, PHP for OWASP Top 10 flaws' }
      ]
    },
    {
      id: 4,
      num: '04',
      title: `${agentsCount} AI Specialist Personas`,
      short: 'Multi-LLM consensus engine (Groq, OpenRouter, DeepSeek) filters noise & scores risk.',
      icon: Bot,
      tech: 'Multi-LLM Groq / DeepSeek',
      details: [
        { label: 'False-Positive Filter', desc: 'AI persona verifies raw tool stdout to eliminate misleading alerts' },
        { label: 'Risk Categorization', desc: 'Auto-calculates CVSS v3.1 base score (Critical, High, Medium, Low)' },
        { label: 'Plain-English Summary', desc: 'Generates layman explanations and non-technical business summaries' }
      ]
    },
    {
      id: 5,
      num: '05',
      title: 'Local-First RAG Knowledge Base',
      short: 'PayloadsAllTheThings FTS5 vector search matches verified exploit payloads & auto-fix diffs.',
      icon: DatabaseZap,
      tech: 'PayloadsAllTheThings FTS5',
      details: [
        { label: 'FTS5 Payload Search', desc: 'Searches 10,000+ curated security payloads in SQLite full-text index' },
        { label: 'Patch Generation', desc: 'Synthesizes context-aware git diff code patches to remediate vulns' },
        { label: 'Attack Graph Link', desc: 'Generates visual topological attack paths in force-directed node map' }
      ]
    },
    {
      id: 6,
      num: '06',
      title: 'CI/CD & Executive Delivery',
      short: 'Generates executive PDF reports, emails attachments, and posts inline PR code reviews.',
      icon: FileText,
      tech: 'PDFKit + Octokit Bot',
      details: [
        { label: 'Executive PDF Report', desc: 'Generates comprehensive audit documents with risk matrices & charts' },
        { label: 'GitHub PR Inline Bot', desc: 'Directly comments on vulnerable lines in GitHub Pull Requests' },
        { label: 'Real-time Webhooks', desc: 'Dispatches instant security alerts to Slack, Discord, and Email' }
      ]
    }
  ]

  return (
    <PublicLayout>
      {/* ── Main Hero Content (Original 2-Column Side-by-Side Layout) ──────── */}
      <main className="at-home__content">
        {/* Left Column Hero Text */}
        <div className="at-home__hero at-stagger-1 text-left">
          <h1 className="at-home__title text-white">
            Autonomous AI <br />
            <span className="at-home__gradient-text font-extrabold">
              Security Assessment
            </span>
          </h1>

          <p className="at-home__subtitle">
            SentinelAI orchestrates 150+ real Kali Linux pentest tools via the Native Kali Engine, {agentsCount} specialist AI personas, and local-first RAG knowledge base.
          </p>

          <div className="at-home__hero-actions mt-4 sm:mt-5 gap-3 sm:gap-4 flex items-center flex-wrap">
            {/* Shine Sweep — primary hero action */}
            <Link to="/login" className="btn-shine btn-lg">
              Start Free Assessment <ArrowRight size={16} />
            </Link>
            {/* Neon Border Draw — secondary ghost action */}
            <a href="#features" className="btn-neon-draw btn-lg">
              Explore Capabilities
            </a>
          </div>

          <div className="at-home__metrics at-box-placed-2">
            <article className="hover:border-cyan-400/40 hover:-translate-y-1 transition-all duration-300">
              <h3 className="text-cyan-400 font-extrabold text-xl sm:text-2xl tracking-tight">150+ Tools</h3>
              <p className="text-xs text-zinc-400">Native Kali Engine</p>
            </article>
            <article className="hover:border-sky-400/40 hover:-translate-y-1 transition-all duration-300">
              <h3 className="text-sky-300 font-extrabold text-xl sm:text-2xl tracking-tight">{agentsCount} Personas</h3>
              <p className="text-xs text-zinc-400">Specialist AI Agents</p>
            </article>
            <article className="hover:border-emerald-400/40 hover:-translate-y-1 transition-all duration-300">
              <h3 className="text-emerald-400 font-extrabold text-xl sm:text-2xl tracking-tight">0% Noise</h3>
              <p className="text-xs text-zinc-400">False-Positive Filter</p>
            </article>
          </div>
        </div>

        {/* Right Column Hero Visual Card */}
        <div className="at-home__visual at-box-placed-2">
          <div className="at-home__visual-frame p-7 sm:p-8 rounded-3xl flex flex-col justify-between relative overflow-hidden bg-[#11131a] border border-white/[0.08] shadow-[0_20px_50px_rgba(0,0,0,0.6),inset_0_1px_0_rgba(255,255,255,0.06)]">
            {/* Top subtle cyber accent line */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />

            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-1.5 rounded-xl bg-[#181a24] border border-white/10 shadow-inner">
                  <InspectorLogo size={32} />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-base">SentinelAI Inspector Core</h3>
                  <p className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse inline-block shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                    Status: Active Scanning Engine
                  </p>
                </div>
              </div>
              <span className="chip bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 text-xs px-2.5 py-1 font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> 24/7 Monitoring
              </span>
            </div>

            <div className="my-6 space-y-3 font-mono text-xs">
              <div className="at-dock-1 p-3.5 rounded-xl bg-black/40 border border-white/[0.06] flex items-center justify-between hover:border-cyan-400/40 transition-colors">
                <div className="flex items-center gap-2.5">
                  <div className="p-1 rounded-lg bg-cyan-500/10 text-cyan-400">
                    <Radar size={14} />
                  </div>
                  <span className="text-slate-200 font-sans font-medium text-xs">DAST Dynamic Analysis</span>
                </div>
                <span className="text-cyan-400 font-semibold flex items-center gap-1.5 text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" /> Live Probing
                </span>
              </div>
              <div className="at-dock-2 p-3.5 rounded-xl bg-black/40 border border-white/[0.06] flex items-center justify-between hover:border-sky-400/40 transition-colors">
                <div className="flex items-center gap-2.5">
                  <div className="p-1 rounded-lg bg-sky-500/10 text-sky-400">
                    <Code2 size={14} />
                  </div>
                  <span className="text-slate-200 font-sans font-medium text-xs">SAST Static Code Parser</span>
                </div>
                <span className="text-sky-300 font-semibold text-[11px] bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">OWASP Top 10</span>
              </div>
              <div className="at-dock-3 p-3.5 rounded-xl bg-black/40 border border-white/[0.06] flex items-center justify-between hover:border-indigo-400/40 transition-colors">
                <div className="flex items-center gap-2.5">
                  <div className="p-1 rounded-lg bg-indigo-500/10 text-indigo-400">
                    <Bot size={14} />
                  </div>
                  <span className="text-slate-200 font-sans font-medium text-xs">Multi-LLM Consensus AI</span>
                </div>
                <span className="text-indigo-300 font-semibold text-[11px] bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">0% False Positives</span>
              </div>
            </div>

            <div className="pt-3 border-t border-white/10 flex justify-between items-center text-xs">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Sparkles size={13} className="text-cyan-400" /> 3 Free Trial Scans
              </span>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Ready for Targets
              </span>
            </div>
          </div>
        </div>
      </main>

      {/* ── Upper Hero Extension: Signal Strip & FYP Creator Showcase ──────── */}
      <div className="max-w-6xl mx-auto px-4 sm:px-8 space-y-8 mt-10 sm:mt-14 mb-24 sm:mb-32">
        {/* Ticker / Signal Strip */}
        <div className="at-home__signal-strip at-box-placed-3 my-0 bg-[#111111] border border-white/[0.07]">
          <div className="at-home__signal-track">
            <span>NMAP PORT RECON</span>
            <span>SQLMAP INJECTION PROBE</span>
            <span>NUCLEI VULN SCAN</span>
            <span>FFUF DIRECTORY BRUTEFORCE</span>
            <span>WHITEBOX CODE AUDIT</span>
            <span>{agentsCount} AI SPECIALIST PERSONAS</span>
            <span>NATIVE KALI ENGINE</span>
          </div>
        </div>

        {/* ── FYP Creator & Lead Security Architect Showcase Banner ─────────────── */}
        <section className="scroll-mt-32 my-0 at-box-placed-4">
          <div className="p-6 sm:p-8 rounded-3xl shadow-xl relative overflow-hidden bg-[#11131a] border border-cyan-500/30 hover:border-cyan-400/50 transition-colors">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 sm:gap-8">
              {/* Creator Photo - Strictly constrained 120x120 square with centered face */}
              <div className="relative shrink-0 flex flex-col items-center">
                <div
                  className="rounded-2xl overflow-hidden border-2 border-cyan-400/40 shadow-lg shadow-cyan-950/40 bg-slate-900 ring-2 ring-cyan-500/20"
                  style={{ width: '120px', height: '120px', minWidth: '120px', minHeight: '120px', maxWidth: '120px', maxHeight: '120px' }}
                >
                  <img
                    src="/saif.png"
                    alt="Muhammad Saifudin"
                    style={{
                      width: '120px',
                      height: '120px',
                      minWidth: '120px',
                      minHeight: '120px',
                      maxWidth: '120px',
                      maxHeight: '120px',
                      objectFit: 'cover',
                      objectPosition: '85% 85%',
                      display: 'block',
                    }}
                    onError={(e) => { e.currentTarget.src = '/fyp2_presenter.png' }}
                  />
                </div>
                <span className="mt-1.5 px-2 py-0.5 rounded-full bg-cyan-500 text-slate-950 text-[9px] font-black uppercase tracking-wider shadow">
                  Lead Dev
                </span>
              </div>

              {/* Creator Bio & Links */}
              <div className="flex-1 text-center sm:text-left space-y-2 min-w-0">
                <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 font-extrabold border border-cyan-500/30 uppercase tracking-wide flex items-center gap-1">
                    <Sparkles size={11} className="text-cyan-400" /> Final Year Project 2 Showcase
                  </span>
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 font-bold border border-indigo-500/30">
                    IIUM &bull; KICT
                  </span>
                </div>

                <div>
                  <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                    Muhammad Saifudin
                  </h3>
                  <p className="text-xs font-semibold text-cyan-400">
                    Lead AI Security Architect & FYP 2 Creator
                  </p>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                  Researched and built SentinelAI — an autonomous multi-agent pentest orchestration platform combining 150+ Kali Linux tools, {agentsCount} LLM specialist personas, and PayloadsAllTheThings RAG intelligence.
                </p>

                {/* Professional Links */}
                <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2 pt-1">
                  <a
                    href="https://github.com/Iamatto01"
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/15 hover:border-cyan-400/60 text-slate-200 hover:text-cyan-300 text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
                  >
                    <GitBranch size={13} className="text-cyan-400" />
                    <span>GitHub: @Iamatto01</span>
                  </a>

                  <a
                    href="https://www.linkedin.com/in/muhammad-saifudin"
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/15 hover:border-blue-400/60 text-slate-200 hover:text-blue-300 text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
                  >
                    <svg className="w-3.5 h-3.5 fill-blue-400" viewBox="0 0 24 24">
                      <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.67a1.66 1.66 0 0 0-1.66 1.66c0 .92.74 1.66 1.66 1.66a1.66 1.66 0 0 0 1.66-1.66c0-.92-.74-1.66-1.66-1.66Z" />
                    </svg>
                    <span>LinkedIn</span>
                  </a>

                  <span className="text-[11px] text-slate-400 font-mono flex items-center gap-1 pl-1">
                    <ShieldCheck size={12} className="text-emerald-400" />
                    <span>Academic Pentest Platform</span>
                  </span>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* ── Features & Architecture (Spacious Full-Width Sections) ─────────── */}
      <div className="max-w-6xl mx-auto px-4 sm:px-8 space-y-36 sm:space-y-44 pb-36">
        {/* Features Section */}
        <div id="features" className="space-y-6 scroll-mt-24">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Unified Security Capabilities
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-lg mx-auto">
              Engineered to eliminate manual testing friction while giving red teams full control over exploit campaigns.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300 border border-white/[0.08] bg-[#11131a] hover:border-cyan-400/40 shadow-lg">
              <Bot className="text-cyan-400 mb-3" size={32} />
              <h3 className="text-lg font-bold text-white mb-2">{agentsCount} Specialist AI Agents</h3>
              <p className="text-sm text-slate-400">
                Automated routing of findings to specialized AI personas (Web Hunter, Database Attacker, Code Auditor) to filter out noise and false positives.
              </p>
            </div>
            <div className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300 border border-white/[0.08] bg-[#11131a] hover:border-sky-400/40 shadow-lg">
              <Radar className="text-sky-400 mb-3" size={32} />
              <h3 className="text-lg font-bold text-white mb-2">150+ Kali Security Tools</h3>
              <p className="text-sm text-slate-400">
                The native engine dynamically chains nmap, nuclei, sqlmap, ffuf, nikto, subfinder, and more based on target analysis.
              </p>
            </div>
            <div className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300 border border-white/[0.08] bg-[#11131a] hover:border-emerald-400/40 shadow-lg">
              <ShieldCheck className="text-emerald-400 mb-3" size={32} />
              <h3 className="text-lg font-bold text-white mb-2">Blackbox &amp; Whitebox Unified</h3>
              <p className="text-sm text-slate-400">
                Scan live website URLs or upload source code (JavaScript, Python, PHP, Java) for automated static code review in one unified platform.
              </p>
            </div>
          </div>
        </div>

        {/* ── GRAND SYSTEM ARCHITECTURE TREE SECTION ──────────────────────── */}
        <section id="architecture" className="space-y-8 scroll-mt-24 pt-4">
          <div className="text-center space-y-3">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-bold uppercase tracking-wider">
              <Network size={14} className="text-cyan-400" /> Grand System Hierarchy & Flow Tree
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Real System Architecture & Workflow Tree
            </h2>
            <p className="text-sm text-slate-400 max-w-2xl mx-auto">
              Interactive parent-child architecture tree showing how SentinelAI branches across UI, API Gateway, Kali Tool Engine, AI Personas, RAG Index, and DevSecOps.
            </p>

            {/* View Switcher Buttons */}
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={() => setArchMode('tree')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'tree'
                    ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Network size={15} /> Grand Architecture Tree
              </button>
              <button
                onClick={() => setArchMode('flow')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'flow'
                    ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Workflow size={15} /> Sequential Pipeline Flow
              </button>
              <button
                onClick={() => setArchMode('mermaid')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'mermaid'
                    ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Binary size={15} /> Full Execution Flowchart
              </button>
            </div>
          </div>

          {/* Render Grand System Tree */}
          {archMode === 'tree' && (
            <SystemTree />
          )}

          {/* Render Exact Mermaid Diagram (Public Layout → Routes) */}
          {archMode === 'mermaid' && (
            <MermaidDiagram />
          )}

          {/* Render Sequential Pipeline Flow */}
          {archMode === 'flow' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {ARCH_STEPS.map((step, idx) => {
                  const Icon = step.icon
                  const isHovered = hoveredStep === step.id

                  return (
                    <div
                      key={step.id}
                      onMouseEnter={() => setHoveredStep(step.id)}
                      onMouseLeave={() => setHoveredStep(null)}
                      onClick={() => setHoveredStep(isHovered ? null : step.id)}
                      className={`card p-5 sm:p-6 border transition-all duration-300 rounded-3xl relative overflow-hidden flex flex-col justify-between cursor-pointer group ${
                        isHovered
                          ? 'border-cyan-400/80 bg-slate-900/90 shadow-2xl shadow-cyan-500/20 scale-[1.02] ring-1 ring-cyan-400/40'
                          : 'border-white/10 bg-slate-950/70 hover:border-white/20'
                      }`}
                    >
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-extrabold px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
                              STEP {step.num}
                            </span>
                            <span className="text-[10px] font-mono text-slate-400">
                              {step.tech}
                            </span>
                          </div>

                          <div className="p-1.5 rounded-xl bg-white/5 text-slate-400 group-hover:text-cyan-300 group-hover:bg-cyan-500/20 transition-colors">
                            <ChevronRight size={14} className="group-hover:translate-x-0.5 transition-transform" />
                          </div>
                        </div>

                        <div className="flex items-start gap-3.5">
                          <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-400/30 text-cyan-400 shrink-0 group-hover:scale-110 group-hover:bg-cyan-500 group-hover:text-slate-950 transition-all">
                            <Icon size={22} />
                          </div>
                          <div>
                            <h3 className="text-base font-extrabold text-white group-hover:text-cyan-300 transition-colors">
                              {step.title}
                            </h3>
                            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                              {step.short}
                            </p>
                          </div>
                        </div>

                        <div className={`space-y-2 pt-3 border-t border-white/10 transition-all duration-300 ${
                          isHovered ? 'opacity-100 max-h-96' : 'opacity-85 lg:opacity-60 max-h-96'
                        }`}>
                          <div className="text-[11px] font-bold text-cyan-300 flex items-center gap-1.5">
                            <Sparkles size={12} /> Key Sub-modules & Tech:
                          </div>
                          <div className="space-y-1.5">
                            {step.details.map((d, i) => (
                              <div key={i} className="p-2 rounded-xl bg-black/40 border border-white/5 hover:border-cyan-400/30 transition-colors text-[11px]">
                                <span className="font-bold text-slate-200">{d.label}: </span>
                                <span className="text-slate-400">{d.desc}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div className="pt-3 text-[10px] text-slate-500 font-mono flex items-center justify-between border-t border-white/5 mt-4">
                        <span>Pipeline Node {idx + 1} of 6</span>
                        <span className="text-cyan-400 font-semibold">{isHovered ? 'Active Inspection' : 'Hover to Inspect'}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </section>

        {/* ── STANDALONE PRICING SECTION (Spacious with Generous Top Margins) ── */}
        <section id="pricing" className="space-y-16 scroll-mt-32 pt-24 sm:pt-32 border-t border-white/10 mt-12 sm:mt-20">
          <div className="text-center space-y-3">
            <div className="inline-flex items-center gap-1.5 px-3.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-bold uppercase tracking-wider">
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

          <div className="grid grid-cols-1 md:grid-cols-2 gap-10 max-w-4xl mx-auto pt-6">
            {/* Pro Card */}
            <div className="card p-8 sm:p-9 border-cyan-500/50 bg-gradient-to-b from-slate-900/90 via-slate-900/80 to-cyan-950/30 shadow-2xl shadow-cyan-950/40 ring-1 ring-cyan-400/40 relative flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
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
                {/* #11 Flush Button for Pro */}
                <Link
                  to={`/login?mode=register&plan=pro&interval=${interval}`}
                  className="btn-flush w-full justify-center"
                >
                  <span>Subscribe to SentinelAI Pro</span>
                </Link>
              </div>
            </div>

            {/* Enterprise Card */}
            <div className="card p-8 sm:p-9 border-white/10 bg-slate-950/70 hover:border-white/20 flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
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
                {/* #19 Fancy VIP Button for Enterprise */}
                <Link
                  to={`/login?mode=register&plan=enterprise&interval=${interval}`}
                  className="btn-fancy-vip w-full justify-center"
                >
                  <span>Subscribe to Enterprise</span>
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* ── Bottom Call To Action ─────────────────────────────────────────── */}
        <div className="card mt-28 sm:mt-36 p-10 sm:p-14 border border-cyan-500/30 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 text-center rounded-3xl shadow-2xl space-y-8">
          <div className="space-y-3">
            <h2 className="text-2xl sm:text-3xl font-bold text-white">Ready to Audit Your Targets?</h2>
            <p className="text-slate-400 text-xs sm:text-sm max-w-xl mx-auto leading-relaxed">
              Log in to access your SentinelAI Pentest Suite dashboard, launch URL scans, or run GitHub continuous code audits.
            </p>
          </div>
          <div className="flex justify-center gap-4">
            <Link to="/login?mode=register&plan=trial" className="btn-gradient-flow btn-lg">
              Get Started Free <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </div>
    </PublicLayout>
  )
}
