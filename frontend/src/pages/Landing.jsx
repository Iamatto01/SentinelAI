import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldAlert, Bot, Radar, FileText, ShieldCheck, Cpu, DatabaseZap, Sparkles, Globe2, Binary, CheckCircle2,
  ChevronRight, ChevronDown, Layers, Terminal, Network, GitBranch, Zap, Server, Workflow, Code2, KeyRound, Activity,
  ArrowRight, Radio, Wifi, Flame, RefreshCw
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import SystemTree from '../components/SystemTree.jsx'
import PageTurnTransition from '../components/PageTurnTransition.jsx'
import PublicLayout from '../components/PublicLayout.jsx'
import MermaidDiagram from '../components/MermaidDiagram.jsx'
import DiagonalThemeSelector from '../components/DiagonalThemeSelector.jsx'
import './Home.css'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function Landing() {
  const { isNight } = useTheme()
  const [interval, setInterval] = useState('monthly')
  const [archMode, setArchMode] = useState('tree') // 'tree' | 'flow' | 'mermaid'
  const [heroTab, setHeroTab] = useState('radar') // 'radar' | 'terminal' | 'mesh'
  const [hoveredStep, setHoveredStep] = useState(null)
  const [agentsCount, setAgentsCount] = useState(53)
  const [showThemeIntro, setShowThemeIntro] = useState(false)
  const [plans, setPlans] = useState([])

  // Listen for replay event from navbar
  useEffect(() => {
    const handleReplay = () => setShowThemeIntro(true)
    window.addEventListener('sentinel_replay_theme_intro', handleReplay)
    return () => window.removeEventListener('sentinel_replay_theme_intro', handleReplay)
  }, [])

  useEffect(() => {
    fetch('/api/public/stats')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.agentsCount) setAgentsCount(d.agentsCount)
      })
      .catch(() => {})

    fetch('/api/billing/plans')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.plans?.length) setPlans(d.plans)
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
      {/* ── Interactive Diagonal Split-Screen Theme Selector ─────────────── */}
      <DiagonalThemeSelector
        isOpen={showThemeIntro}
        onClose={() => setShowThemeIntro(false)}
      />

      {/* ── Main Hero Content (2-Column Side-by-Side WOW Cyber Layout) ──────── */}
      <main className="at-home__content">
        {/* Left Column Hero Text */}
        <div className="at-home__hero at-stagger-1 text-left">
          {/* Cyber High-Tech Badge */}
          <div className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-xs font-bold uppercase tracking-wider mb-1 w-fit transition-colors ${
            isNight
              ? 'border-purple-500/40 bg-purple-950/30 text-purple-300 shadow-[0_0_20px_rgba(168,85,247,0.2)]'
              : 'border-purple-400 bg-purple-50 text-purple-800'
          }`}>
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${isNight ? 'bg-purple-500' : 'bg-purple-600'}`}></span>
            </span>
            <span>Autonomous Offensive Security Pentest Mesh</span>
          </div>

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

          <div className="at-home__metrics at-stagger-2 at-box-placed-2">
            <article className="border border-purple-500/20 bg-[#120e24]/70 hover:border-purple-400/60 hover:-translate-y-1 transition-all duration-300 shadow-[0_4px_20px_rgba(168,85,247,0.1)]">
              <h3 className="text-purple-400 font-extrabold text-xl sm:text-2xl tracking-tight">150+ Tools</h3>
              <p className="text-xs text-zinc-400">Native Kali Engine</p>
            </article>
            <article className="border border-violet-500/20 bg-[#160f2e]/70 hover:border-violet-400/60 hover:-translate-y-1 transition-all duration-300 shadow-[0_4px_20px_rgba(139,92,246,0.1)]">
              <h3 className="text-violet-300 font-extrabold text-xl sm:text-2xl tracking-tight">{agentsCount} Personas</h3>
              <p className="text-xs text-zinc-400">Specialist AI Agents</p>
            </article>
            <article className="border border-emerald-500/20 bg-[#0d1e1a]/70 hover:border-emerald-400/60 hover:-translate-y-1 transition-all duration-300 shadow-[0_4px_20px_rgba(16,185,129,0.1)]">
              <h3 className="text-emerald-400 font-extrabold text-xl sm:text-2xl tracking-tight">0% Noise</h3>
              <p className="text-xs text-zinc-400">False-Positive Filter</p>
            </article>
          </div>
        </div>

        {/* Right Column Hero Visual Card — Holographic Threat Matrix & Diagnostic Console */}
        <div className="at-home__visual at-stagger-2 at-box-placed-2">
          <div className={`at-home__visual-frame p-5 sm:p-7 rounded-3xl flex flex-col justify-between relative overflow-hidden border shadow-[0_20px_60px_rgba(0,0,0,0.3)] ${
            isNight
              ? 'bg-[#0c0d16]/90 border-purple-500/30 shadow-[0_20px_60px_rgba(0,0,0,0.8),0_0_40px_rgba(168,85,247,0.18)]'
              : 'bg-white border-purple-200 shadow-[0_8px_32px_rgba(109,40,217,0.12)]'
          }`}>
            {/* Top neon accent line */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-purple-500 to-transparent" />

            {/* Header with Title and Mode Switcher */}
            <div className={`flex flex-col sm:flex-row sm:items-center justify-between border-b pb-4 gap-3 ${
              isNight ? 'border-white/10' : 'border-slate-200'
            }`}>
              <div className="flex items-center gap-3">
                <div className={`p-1.5 rounded-xl border ${
                  isNight
                    ? 'bg-purple-950/40 border-purple-500/30 shadow-[0_0_12px_rgba(168,85,247,0.25)]'
                    : 'bg-purple-100 border-purple-300'
                }`}>
                  <InspectorLogo size={30} />
                </div>
                <div>
                  <h3 className={`font-bold text-sm sm:text-base flex items-center gap-2 ${
                    isNight ? 'text-slate-100' : 'text-slate-900'
                  }`}>
                    <span>Threat Radar & Matrix</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold border ${
                      isNight
                        ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                        : 'bg-purple-100 text-purple-800 border-purple-300'
                    }`}>v2.4</span>
                  </h3>
                  <p className={`text-xs font-mono flex items-center gap-1.5 mt-0.5 ${
                    isNight ? 'text-emerald-400' : 'text-emerald-700 font-semibold'
                  }`}>
                    <span className={`w-2 h-2 rounded-full animate-pulse ${
                      isNight ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.9)]' : 'bg-emerald-600'
                    }`} />
                    Kali Engine Online &bull; Subprocess Daemon
                  </p>
                </div>
              </div>

              {/* Interactive Tab Switcher */}
              <div className={`flex items-center gap-1 p-1 rounded-xl border self-start sm:self-auto ${
                isNight ? 'bg-black/40 border-white/10' : 'bg-slate-100 border-slate-200'
              }`}>
                <button
                  type="button"
                  onClick={() => setHeroTab('radar')}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                    heroTab === 'radar'
                      ? 'bg-purple-600 text-white shadow-[0_0_10px_rgba(168,85,247,0.5)]'
                      : isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Radar size={12} />
                  <span>Radar</span>
                </button>
                <button
                  type="button"
                  onClick={() => setHeroTab('terminal')}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                    heroTab === 'terminal'
                      ? 'bg-purple-600 text-white shadow-[0_0_10px_rgba(168,85,247,0.5)]'
                      : isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Terminal size={12} />
                  <span>CLI Stdout</span>
                </button>
                <button
                  type="button"
                  onClick={() => setHeroTab('mesh')}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                    heroTab === 'mesh'
                      ? 'bg-purple-600 text-white shadow-[0_0_10px_rgba(168,85,247,0.5)]'
                      : isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Bot size={12} />
                  <span>AI Mesh</span>
                </button>
              </div>
            </div>

            {/* Tab 1: RADAR VIEW */}
            {heroTab === 'radar' && (
              <div className="my-5 space-y-4">
                {/* Holographic Radar Circle & Readout */}
                <div className={`relative rounded-2xl border p-4 flex flex-col sm:flex-row items-center gap-5 overflow-hidden ${
                  isNight ? 'bg-black/50 border-purple-500/20' : 'bg-slate-50 border-slate-200'
                }`}>
                  {/* Animated Radar Graphic */}
                  <div className="relative w-32 h-32 shrink-0 flex items-center justify-center">
                    {/* Concentric Rings */}
                    <div className="absolute inset-0 rounded-full border border-purple-500/20" />
                    <div className="absolute inset-3 rounded-full border border-purple-500/30 border-dashed" />
                    <div className="absolute inset-7 rounded-full border border-purple-500/40" />
                    <div className="absolute inset-11 rounded-full border border-purple-500/60" />
                    {/* Radar Crosshairs */}
                    <div className="absolute inset-x-0 top-1/2 h-px bg-purple-500/20" />
                    <div className="absolute inset-y-0 left-1/2 w-px bg-purple-500/20" />
                    {/* Sweeping Beam */}
                    <div
                      className="absolute inset-0 rounded-full pointer-events-none"
                      style={{
                        background: 'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(168, 85, 247, 0.45) 360deg)',
                        animation: 'btnBeamSpin 3.5s linear infinite'
                      }}
                    />
                    {/* Ping Blips */}
                    <div className="absolute top-6 right-8 w-2 h-2 rounded-full bg-rose-400 animate-ping" />
                    <div className="absolute top-6 right-8 w-2 h-2 rounded-full bg-rose-500" />
                    <div className="absolute bottom-7 left-7 w-2 h-2 rounded-full bg-amber-400" />
                    <div className="absolute top-10 left-10 w-2 h-2 rounded-full bg-emerald-400" />
                    {/* Central Inspector Eye */}
                    <div className="relative z-10 w-4 h-4 rounded-full bg-purple-500 shadow-[0_0_12px_rgba(168,85,247,1)] flex items-center justify-center">
                      <div className="w-1.5 h-1.5 rounded-full bg-white" />
                    </div>
                  </div>

                  {/* Target Telemetry */}
                  <div className="flex-1 min-w-0 space-y-2 text-xs font-mono w-full">
                    <div className="flex items-center justify-between">
                      <span className={`text-[11px] font-bold ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>ACTIVE TARGET</span>
                      <span className={`font-bold text-[11px] flex items-center gap-1 ${
                        isNight ? 'text-purple-300' : 'text-purple-700'
                      }`}>
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse" />
                        https://demo.sentinelai.studio
                      </span>
                    </div>
                    <div className={`p-2.5 rounded-xl border space-y-1.5 text-[11px] ${
                      isNight ? 'bg-[#141224] border-white/5' : 'bg-white border-slate-200'
                    }`}>
                      <div className="flex justify-between">
                        <span className={isNight ? 'text-slate-400' : 'text-slate-500'}>Host IP:</span>
                        <span className={`font-semibold ${isNight ? 'text-purple-300' : 'text-purple-800'}`}>192.168.68.132</span>
                      </div>
                      <div className="flex justify-between">
                        <span className={isNight ? 'text-slate-400' : 'text-slate-500'}>Open Services:</span>
                        <span className={`font-semibold ${isNight ? 'text-emerald-400' : 'text-emerald-700'}`}>80 (HTTP), 443 (HTTPS), 22 (SSH)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className={isNight ? 'text-slate-400' : 'text-slate-500'}>TLS Encryption:</span>
                        <span className={`font-semibold ${isNight ? 'text-purple-300' : 'text-purple-800'}`}>TLS 1.3 / OpenSSL 3.0</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Module Diagnostic Cards */}
                <div className="grid grid-cols-3 gap-2 text-center text-xs">
                  <div className={`p-2.5 rounded-xl border ${isNight ? 'bg-purple-950/25 border-purple-500/20' : 'bg-purple-50 border-purple-200 shadow-sm'}`}>
                    <div className={`text-[10px] font-mono font-extrabold ${isNight ? 'text-purple-300' : 'text-purple-800'}`}>DAST PROBES</div>
                    <div className={`text-base font-black mt-0.5 ${isNight ? 'text-white' : 'text-slate-900'}`}>142</div>
                    <div className={`text-[9px] font-mono font-bold ${isNight ? 'text-emerald-400' : 'text-emerald-700'}`}>100% Passed</div>
                  </div>
                  <div className={`p-2.5 rounded-xl border ${isNight ? 'bg-violet-950/25 border-violet-500/20' : 'bg-violet-50 border-violet-200 shadow-sm'}`}>
                    <div className={`text-[10px] font-mono font-extrabold ${isNight ? 'text-violet-300' : 'text-violet-800'}`}>VULN MATCHES</div>
                    <div className={`text-base font-black mt-0.5 ${isNight ? 'text-amber-400' : 'text-amber-800'}`}>2 High</div>
                    <div className={`text-[9px] font-mono font-bold ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>0 Critical</div>
                  </div>
                  <div className={`p-2.5 rounded-xl border ${isNight ? 'bg-indigo-950/25 border-indigo-500/20' : 'bg-indigo-50 border-indigo-200 shadow-sm'}`}>
                    <div className={`text-[10px] font-mono font-extrabold ${isNight ? 'text-indigo-300' : 'text-indigo-800'}`}>RAG EXPLOITS</div>
                    <div className={`text-base font-black mt-0.5 ${isNight ? 'text-purple-300' : 'text-purple-800'}`}>10,482</div>
                    <div className={`text-[9px] font-mono font-bold ${isNight ? 'text-purple-400' : 'text-purple-700'}`}>FTS5 Indexed</div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 2: TERMINAL STDOUT */}
            {heroTab === 'terminal' && (
              <div className="my-5 rounded-2xl bg-[#090a10] border border-purple-500/25 p-3.5 font-mono text-[11px] leading-relaxed shadow-inner overflow-hidden">
                <div className="flex items-center gap-1.5 pb-2.5 mb-2.5 border-b border-white/10 text-slate-400 text-[10px]">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  <span className="ml-2 font-semibold text-purple-300">kali@sentinelai: ~/engine/subprocess</span>
                </div>
                <div className="space-y-1.5 text-slate-300">
                  <p className="text-purple-400">$ nmap -sV -sC -p 80,443,8080 demo.sentinelai.studio</p>
                  <p className="text-slate-400">[+] Nmap: 3 open service banners identified in 1.42s</p>
                  <p className="text-purple-400">$ nuclei -u https://demo.sentinelai.studio -t cves/2024/</p>
                  <p className="text-amber-300">[!] [HIGH] Nuclei matched CVE-2024-27198 authentication bypass</p>
                  <p className="text-purple-400">$ sqlmap -u "https://demo.sentinelai.studio/api/search?q=1" --batch</p>
                  <p className="text-slate-400">[+] AI Persona #07 verifying boolean blind response delay...</p>
                  <p className="text-emerald-400 font-semibold">[✓] Persona #01 'Web Hunter' synthesized patch diff (unified format)</p>
                  <p className="text-purple-300 flex items-center gap-1">
                    <span className="inline-block w-2 h-3.5 bg-purple-400 animate-pulse" />
                    <span>Audit complete &bull; Executive PDF report generated in 3.42s</span>
                  </p>
                </div>
              </div>
            )}

            {/* Tab 3: AI MESH CONSENSUS */}
            {heroTab === 'mesh' && (
              <div className="my-5 space-y-2.5 font-mono text-xs">
                <div className="p-3 rounded-xl bg-black/40 border border-purple-500/20 hover:border-purple-400/40 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-purple-300 font-bold flex items-center gap-1.5 text-[11px]">
                      <Bot size={13} className="text-purple-400" /> Persona #01 &bull; Web Hunter
                    </span>
                    <span className="text-emerald-400 text-[10px] font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      99.4% Confidence
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] font-sans">
                    Analyzes AST code tokens & OWASP Top 10 vulnerabilities via DeepSeek-R1 consensus.
                  </p>
                </div>

                <div className="p-3 rounded-xl bg-black/40 border border-violet-500/20 hover:border-violet-400/40 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-violet-300 font-bold flex items-center gap-1.5 text-[11px]">
                      <Cpu size={13} className="text-violet-400" /> Persona #07 &bull; Database Attacker
                    </span>
                    <span className="text-emerald-400 text-[10px] font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      98.8% Verified
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] font-sans">
                    Synthesizes Boolean Blind and Time-Based SQLi payloads from PayloadsAllTheThings RAG.
                  </p>
                </div>

                <div className="p-3 rounded-xl bg-black/40 border border-indigo-500/20 hover:border-indigo-400/40 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-indigo-300 font-bold flex items-center gap-1.5 text-[11px]">
                      <ShieldCheck size={13} className="text-indigo-400" /> Persona #19 &bull; Noise Reducer
                    </span>
                    <span className="text-purple-300 text-[10px] font-bold bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                      0% Noise
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] font-sans">
                    Prunes honeypots and false positives through multi-LLM verification before reporting.
                  </p>
                </div>
              </div>
            )}

            {/* Bottom Telemetry Bar */}
            <div className="pt-3 border-t border-white/10 flex flex-wrap justify-between items-center text-xs gap-2">
              <span className="text-slate-400 flex items-center gap-1.5 text-[11px]">
                <Sparkles size={13} className="text-purple-400" /> 3 Free Trial Scans Available
              </span>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Subprocess Ready
              </span>
            </div>
          </div>
        </div>
      </main>

      {/* ── Upper Hero Extension: Signal Strip & FYP Creator Showcase ──────── */}
      <div className="max-w-6xl mx-auto px-4 sm:px-8 space-y-8 mt-12 sm:mt-16 mb-24 sm:mb-32">
        {/* Ticker / Signal Strip */}
        <div className="at-home__signal-strip at-stagger-3 at-box-placed-3 my-0 bg-[#111111] border border-white/[0.07]">
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
          <div className="p-6 sm:p-8 rounded-3xl shadow-xl relative overflow-hidden bg-[#11131a] border border-purple-500/35 hover:border-purple-400/60 shadow-[0_12px_40px_rgba(0,0,0,0.6),0_0_30px_rgba(168,85,247,0.15)] transition-colors">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 sm:gap-8">
              {/* Creator Photo - Strictly constrained 120x120 square with centered face */}
              <div className="relative shrink-0 flex flex-col items-center">
                <div
                  className="rounded-2xl overflow-hidden border-2 border-purple-400/50 shadow-lg shadow-purple-950/50 bg-slate-900 ring-2 ring-purple-500/30"
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
                <span className="mt-1.5 px-2 py-0.5 rounded-full bg-purple-600 text-white text-[9px] font-black uppercase tracking-wider shadow">
                  Lead Dev
                </span>
              </div>

              {/* Creator Bio & Links */}
              <div className="flex-1 text-center sm:text-left space-y-2 min-w-0">
                <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-purple-500/15 text-purple-300 font-extrabold border border-purple-500/30 uppercase tracking-wide flex items-center gap-1">
                    <Sparkles size={11} className="text-purple-400" /> Final Year Project 2 Showcase
                  </span>
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 font-bold border border-indigo-500/30">
                    IIUM &bull; KICT
                  </span>
                </div>

                <div>
                  <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">
                    Muhammad Saifudin
                  </h3>
                  <p className="text-xs font-semibold text-purple-400">
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
                    className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/15 hover:border-purple-400/60 text-slate-200 hover:text-purple-300 text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
                  >
                    <GitBranch size={13} className="text-purple-400" />
                    <span>GitHub: @Iamatto01</span>
                  </a>

                  <a
                    href="https://www.linkedin.com/in/saifudinjamal/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/15 hover:border-purple-400/60 text-slate-200 hover:text-purple-300 text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
                  >
                    <svg className="w-3.5 h-3.5 fill-purple-400" viewBox="0 0 24 24">
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
            <div className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300 border border-white/[0.08] bg-[#11131a] hover:border-purple-400/50 shadow-lg">
              <Bot className="text-purple-400 mb-3" size={32} />
              <h3 className="text-lg font-bold text-white mb-2">{agentsCount} Specialist AI Agents</h3>
              <p className="text-sm text-slate-400">
                Automated routing of findings to specialized AI personas (Web Hunter, Database Attacker, Code Auditor) to filter out noise and false positives.
              </p>
            </div>
            <div className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300 border border-white/[0.08] bg-[#11131a] hover:border-violet-400/50 shadow-lg">
              <Radar className="text-violet-400 mb-3" size={32} />
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
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-purple-500/10 border border-purple-400/30 text-purple-300 text-xs font-bold uppercase tracking-wider">
              <Network size={14} className="text-purple-400" /> Grand System Hierarchy & Flow Tree
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
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Network size={15} /> Grand Architecture Tree
              </button>
              <button
                onClick={() => setArchMode('flow')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'flow'
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/30 font-extrabold'
                    : 'bg-white/5 text-slate-300 border border-white/10 hover:bg-white/10'
                }`}
              >
                <Workflow size={15} /> Sequential Pipeline Flow
              </button>
              <button
                onClick={() => setArchMode('mermaid')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                  archMode === 'mermaid'
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/30 font-extrabold'
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
                          ? 'border-purple-400/80 bg-slate-900/90 shadow-2xl shadow-purple-500/20 scale-[1.02] ring-1 ring-purple-400/40'
                          : 'border-white/10 bg-slate-950/70 hover:border-white/20'
                      }`}
                    >
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-extrabold px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-400/30">
                              STEP {step.num}
                            </span>
                            <span className="text-[10px] font-mono text-slate-400">
                              {step.tech}
                            </span>
                          </div>

                          <div className="p-1.5 rounded-xl bg-white/5 text-slate-400 group-hover:text-purple-300 group-hover:bg-purple-500/20 transition-colors">
                            <ChevronRight size={14} className="group-hover:translate-x-0.5 transition-transform" />
                          </div>
                        </div>

                        <div className="flex items-start gap-3.5">
                          <div className="p-3 rounded-2xl bg-purple-500/10 border border-purple-400/30 text-purple-400 shrink-0 group-hover:scale-110 group-hover:bg-purple-600 group-hover:text-white transition-all">
                            <Icon size={22} />
                          </div>
                          <div>
                            <h3 className="text-base font-extrabold text-white group-hover:text-purple-300 transition-colors">
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
                          <div className="text-[11px] font-bold text-purple-300 flex items-center gap-1.5">
                            <Sparkles size={12} /> Key Sub-modules & Tech:
                          </div>
                          <div className="space-y-1.5">
                            {step.details.map((d, i) => (
                              <div key={i} className="p-2 rounded-xl bg-black/40 border border-white/5 hover:border-purple-400/30 transition-colors text-[11px]">
                                <span className="font-bold text-slate-200">{d.label}: </span>
                                <span className="text-slate-400">{d.desc}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div className="pt-3 text-[10px] text-slate-500 font-mono flex items-center justify-between border-t border-white/5 mt-4">
                        <span>Pipeline Node {idx + 1} of 6</span>
                        <span className="text-purple-400 font-semibold">{isHovered ? 'Active Inspection' : 'Hover to Inspect'}</span>
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
            <div className="inline-flex items-center gap-1.5 px-3.5 py-1 rounded-full bg-purple-500/10 border border-purple-400/30 text-purple-300 text-xs font-bold uppercase tracking-wider">
              <Sparkles size={12} className="text-purple-400" /> Transparent SaaS Pricing
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
                  className={`w-5 h-5 rounded-full bg-purple-500 transition-transform duration-200 ${
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

          {(() => {
            const proPlan = plans.find(p => p.id === 'pro') || {
              id: 'pro',
              name: 'SentinelAI Pro',
              priceMonthly: 20,
              priceYearly: 200,
              description: 'Ideal for active developers and software teams needing continuous audit automation.'
            }
            const enterprisePlan = plans.find(p => p.id === 'enterprise') || {
              id: 'enterprise',
              name: 'SentinelAI Enterprise',
              priceMonthly: 80,
              priceYearly: 800,
              description: 'Full continuous DevSecOps pipeline for organizations requiring unlimited audits & compliance.'
            }
            const ppsPlan = plans.find(p => p.id === 'pay_per_scan') || {
              id: 'pay_per_scan',
              name: 'Pay-Per-Scan Credit',
              priceMonthly: 3,
              description: 'Top-up single autonomous scans on demand. No recurring monthly commitment.'
            }

            return (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto pt-6">
                {/* Pay-Per-Scan Card */}
                <div className="card p-7 border-white/10 bg-slate-950/70 hover:border-purple-500/30 flex flex-col justify-between hover:scale-[1.01] transition-transform duration-300">
                  <div className="space-y-6">
                    <div>
                      <span className="text-[10px] font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/30">
                        On-Demand Top-Up
                      </span>
                      <h3 className="text-xl font-extrabold text-white mt-3">{ppsPlan.name}</h3>
                      <div className="mt-3 flex items-baseline gap-1">
                        <span className="text-4xl font-black text-white">RM {ppsPlan.priceMonthly}</span>
                        <span className="text-xs text-slate-400 font-medium">/ scan</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-2">
                        {ppsPlan.description || 'Top-up single autonomous scans on demand. No recurring monthly commitment.'}
                      </p>
                    </div>

                    <div className="h-px bg-white/10" />

                    <ul className="space-y-3 text-xs text-slate-300">
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span><strong>1 Full Security Scan</strong> credit added</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span><strong>Full 150+ Toolchain</strong> (DAST & SAST)</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span>Live stdout terminal & real-time telemetry</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span>Instant downloadable PDF Audit Report</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span>No recurring monthly subscription</span>
                      </li>
                    </ul>
                  </div>

                  <div className="pt-8">
                    <Link
                      to="/login?mode=register&plan=pay_per_scan"
                      className="btn-ghost w-full justify-center py-3 text-xs font-bold border border-white/15 hover:border-purple-400 text-purple-300 hover:text-white"
                    >
                      <span>Buy Scan Credit (RM {ppsPlan.priceMonthly})</span>
                    </Link>
                  </div>
                </div>

                {/* Pro Card */}
                <div className="card p-7 border-purple-500/60 bg-gradient-to-b from-slate-900/90 via-slate-900/80 to-purple-950/30 shadow-2xl shadow-purple-950/40 ring-1 ring-purple-400/40 relative flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-purple-500/30 flex items-center gap-1">
                    <Sparkles size={10} className="fill-white" /> Most Popular
                  </div>

                  <div className="space-y-6">
                    <div>
                      <h3 className="text-xl font-extrabold text-white">{proPlan.name}</h3>
                      <div className="mt-3 flex items-baseline gap-1">
                        <span className="text-4xl font-black text-white">RM {interval === 'yearly' ? proPlan.priceYearly : proPlan.priceMonthly}</span>
                        <span className="text-xs text-slate-400 font-medium">{interval === 'yearly' ? '/year' : '/month'}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-2">
                        {proPlan.description || 'Ideal for active developers and software teams needing continuous audit automation.'}
                      </p>
                    </div>

                    <div className="h-px bg-white/10" />

                    <ul className="space-y-3 text-xs text-slate-300">
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span><strong>50 AI Code Audits</strong> / month</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span><strong>5 Linked Repositories</strong> (Public & Private)</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span>Continuous Webhooks (Push & PR triggers)</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span>Automated Email PDF Delivery on every commit</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-purple-400 shrink-0" />
                        <span>AI Auto-Fix & Remediation Diffs</span>
                      </li>
                    </ul>
                  </div>

                  <div className="pt-8">
                    <Link
                      to={`/login?mode=register&plan=pro&interval=${interval}`}
                      className="btn-shine w-full justify-center py-3"
                    >
                      <span>Subscribe to SentinelAI Pro</span>
                    </Link>
                  </div>
                </div>

                {/* Enterprise Card */}
                <div className="card p-7 border-white/10 bg-slate-950/70 hover:border-white/20 flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300 relative">
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-amber-500 via-purple-500 to-pink-500 text-slate-950 font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-amber-500/30 flex items-center gap-1">
                    <Sparkles size={10} className="fill-slate-950 text-slate-950" /> VIP Red Team Advisory
                  </div>

                  <div className="space-y-6">
                    <div>
                      <h3 className="text-xl font-extrabold text-white">{enterprisePlan.name}</h3>
                      <div className="mt-3 flex items-baseline gap-1">
                        <span className="text-4xl font-black text-white">RM {interval === 'yearly' ? enterprisePlan.priceYearly : enterprisePlan.priceMonthly}</span>
                        <span className="text-xs text-slate-400 font-medium">{interval === 'yearly' ? '/year' : '/month'}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-2">
                        {enterprisePlan.description || 'Full continuous DevSecOps pipeline for organizations requiring unlimited audits & compliance.'}
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
                        <span>1-on-1 Certified Consultant Advisory</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                        <span>Real-time Slack / Discord / Telegram Relays</span>
                      </li>
                      <li className="flex items-center gap-2.5">
                        <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                        <span>Executive White-label PDF Reports & Dedicated SLA</span>
                      </li>
                    </ul>
                  </div>

                  <div className="pt-8">
                    <Link
                      to={`/login?mode=register&plan=enterprise&interval=${interval}`}
                      className="btn-fancy-vip w-full justify-center"
                    >
                      <span>Subscribe to Enterprise</span>
                    </Link>
                  </div>
                </div>
              </div>
            )
          })()}
        </section>

        {/* ── Bottom Call To Action ─────────────────────────────────────────── */}
        <div className="card mt-28 sm:mt-36 p-10 sm:p-14 border border-purple-500/30 bg-gradient-to-r from-slate-950 via-[#0e0c1a] to-purple-950/40 text-center rounded-3xl shadow-2xl space-y-8">
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
