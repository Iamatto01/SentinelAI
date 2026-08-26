import React, { useState } from 'react'
import {
  Server, Terminal, Bot, DatabaseZap, FileText, Globe2, ShieldAlert,
  Sparkles, CheckCircle2, ChevronDown, ChevronRight, Zap, Code2, Network,
  GitBranch, Lock, Cpu, Activity, Info, ExternalLink, Layers, Check, X
} from 'lucide-react'
import InspectorLogo from './InspectorLogo.jsx'

const LAYERS = [
  {
    id: 'frontend',
    num: '01',
    title: 'Frontend UI Layer',
    tech: 'React 18 + Vite 6 + Tailwind CSS',
    icon: Code2,
    accent: 'cyan',
    desc: 'High-performance dark glassmorphic dashboard with real-time SSE telemetry, interactive topology maps, and AI chat assistant.',
    modules: [
      { name: 'Vision UI Dashboard', detail: 'SPA with real-time scan telemetry via Server-Sent Events and WebSocket.' },
      { name: 'Attack Surface Map', detail: 'Force-directed SVG topology graph with draggable nodes and saved layouts.' },
      { name: 'Interactive Finding Drawer', detail: 'Plain-language remediation summaries and inline AI chat for each finding.' }
    ]
  },
  {
    id: 'backend',
    num: '02',
    title: 'Express API Gateway',
    tech: 'Node.js + Express + Socket.IO + JWT',
    icon: Server,
    accent: 'violet',
    desc: 'Central orchestration layer handling JWT role-based access control, multi-tenant client isolation, subscription quotas, and scan queues.',
    modules: [
      { name: 'JWT Auth & RBAC', detail: 'Admin, Analyst, and Client roles with strict project-level data isolation.' },
      { name: 'SQLite WAL Database', detail: 'Zero-cloud-dependency embedded database with auto-migration and backups.' },
      { name: 'Exploit State Machine', detail: 'Autonomous exploit campaign orchestration with human approval gates.' }
    ]
  },
  {
    id: 'hexstrike',
    num: '03',
    title: 'Hexstrike Kali Engine',
    tech: '150+ Tools + Kali Linux + REST API',
    icon: Terminal,
    accent: 'rose',
    desc: 'Chains 150+ real Kali Linux security tools via local REST API and executes AST-based static code analysis for whitebox audits.',
    modules: [
      { name: 'DAST Tool Orchestrator', detail: 'Automates Nmap, Nuclei, Nikto, Subfinder, FFUF, SQLMap, and Hydra.' },
      { name: 'SAST Whitebox AST Parser', detail: 'Static analysis scanning JS, Python, PHP, and Java source code for flaws.' },
      { name: 'Metasploit RPC Bridge', detail: 'Active session handler for reverse TCP meterpreter and post-exploitation.' }
    ]
  },
  {
    id: 'ai',
    num: '04',
    title: 'AI Agent Reasoning Core',
    tech: '53 Specialist Personas + Multi-LLM',
    icon: Bot,
    accent: 'amber',
    desc: '53 specialist AI personas verify raw tool outputs, eliminate false-positive noise, calculate CVSS risk scores, and generate dual-tier reports.',
    modules: [
      { name: 'Web Hunter & Exploit Persona', detail: 'Validates XSS, SQLi, SSRF findings and generates proof-of-concept steps.' },
      { name: 'False-Positive Elimination', detail: 'Context-aware verification that discards benign scan noise automatically.' },
      { name: 'CVSS v3.1 Risk Calculator', detail: 'Automated base, temporal, and environmental severity score evaluation.' }
    ]
  },
  {
    id: 'rag',
    num: '05',
    title: 'Local RAG Knowledge Base',
    tech: 'SQLite FTS5 + PayloadsAllTheThings',
    icon: DatabaseZap,
    accent: 'emerald',
    desc: 'Full-text vector index matching curated security payloads and synthesizing auto-fix code diffs entirely offline.',
    modules: [
      { name: 'PayloadsAllTheThings FTS5', detail: 'Searches 10,000+ exploit bypass techniques locally in milliseconds.' },
      { name: 'Contextual Patch Generator', detail: 'Synthesizes clean git diff patches to remediate discovered vulnerabilities.' },
      { name: 'Attack Vector Graph Linker', detail: 'Maps vulnerable endpoints to potential lateral movement paths.' }
    ]
  },
  {
    id: 'cicd',
    num: '06',
    title: 'CI/CD & Delivery Layer',
    tech: 'GitHub Bot + PDFKit + Webhooks',
    icon: GitBranch,
    accent: 'blue',
    desc: 'Delivers executive PDF reports, posts line-by-line GitHub PR code reviews, and dispatches real-time alerts via Discord, Telegram, and email.',
    modules: [
      { name: 'GitHub PR Inline Review Bot', detail: 'Posts security review comments directly on pull request code diffs.' },
      { name: 'Executive PDF Generator', detail: 'Renders branded penetration testing reports with risk matrices and charts.' },
      { name: 'Multi-Channel Alert Dispatcher', detail: 'Real-time notifications via Discord bot, Telegram bot, Slack, and email.' }
    ]
  }
]

const ACCENT_MAP = {
  cyan:    { border: 'border-cyan-500/40',    bg: 'bg-cyan-500/10',    text: 'text-cyan-400',    dot: 'bg-cyan-400',    glow: 'hover:shadow-cyan-500/20',    numBg: 'bg-cyan-500',    line: 'from-cyan-500/60' },
  violet:  { border: 'border-violet-500/40',  bg: 'bg-violet-500/10',  text: 'text-violet-400',  dot: 'bg-violet-400',  glow: 'hover:shadow-violet-500/20',  numBg: 'bg-violet-500',  line: 'from-violet-500/60' },
  rose:    { border: 'border-rose-500/40',    bg: 'bg-rose-500/10',    text: 'text-rose-400',    dot: 'bg-rose-400',    glow: 'hover:shadow-rose-500/20',    numBg: 'bg-rose-500',    line: 'from-rose-500/60' },
  amber:   { border: 'border-amber-500/40',   bg: 'bg-amber-500/10',   text: 'text-amber-400',   dot: 'bg-amber-400',   glow: 'hover:shadow-amber-500/20',   numBg: 'bg-amber-500',   line: 'from-amber-500/60' },
  emerald: { border: 'border-emerald-500/40', bg: 'bg-emerald-500/10', text: 'text-emerald-400', dot: 'bg-emerald-400', glow: 'hover:shadow-emerald-500/20', numBg: 'bg-emerald-500', line: 'from-emerald-500/60' },
  blue:    { border: 'border-blue-500/40',    bg: 'bg-blue-500/10',    text: 'text-blue-400',    dot: 'bg-blue-400',    glow: 'hover:shadow-blue-500/20',    numBg: 'bg-blue-500',    line: 'from-blue-500/60' },
}


export default function SystemTree() {
  const [expanded, setExpanded] = useState({})
  const [inspecting, setInspecting] = useState(null)

  const toggle = (id) => setExpanded(prev => ({ ...prev, [id]: !prev[id] }))

  return (
    <div className="w-full space-y-6">

      {/* ── Root Node ── */}
      <div className="flex flex-col items-center">
        <div className="relative px-8 py-5 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/40 border-2 border-cyan-400/50 shadow-2xl shadow-cyan-500/15 max-w-lg w-full text-center">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-cyan-500 text-slate-950 text-[10px] font-black uppercase tracking-widest shadow-lg shadow-cyan-500/40">
            System Root
          </div>
          <div className="flex items-center justify-center gap-3 mt-2">
            <div className="p-2 rounded-xl bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/30">
              <InspectorLogo size={28} />
            </div>
            <div className="text-left">
              <h2 className="text-xl font-black text-white leading-tight">SentinelAI Core Engine</h2>
              <p className="text-[11px] text-slate-400 font-medium mt-0.5">Unified Autonomous Penetration Testing & AI Reasoning Platform</p>
            </div>
          </div>
        </div>

        {/* Vertical connector from root */}
        <div className="w-px h-10 bg-gradient-to-b from-cyan-400/80 to-cyan-500/20" />

        {/* Horizontal distribution bar */}
        <div className="hidden lg:block w-[85%] max-w-5xl h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent relative">
          <div className="absolute left-0 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-cyan-400/60" />
          <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-cyan-400/60" />
        </div>
      </div>

      {/* ── Layer Cards (Vertical List) ── */}
      <div className="space-y-4 max-w-5xl mx-auto">
        {LAYERS.map((layer, idx) => {
          const Icon = layer.icon
          const a = ACCENT_MAP[layer.accent]
          const isOpen = expanded[layer.id]

          return (
            <div key={layer.id} className="relative">
              {/* Vertical connector between cards */}
              {idx > 0 && (
                <div className="absolute -top-4 left-8 lg:left-1/2 lg:-translate-x-1/2 w-px h-4 bg-gradient-to-b from-slate-600/40 to-slate-700/20" />
              )}

              {/* Main Layer Card */}
              <div className={`rounded-2xl border ${a.border} bg-slate-900/80 backdrop-blur-sm shadow-lg ${a.glow} hover:shadow-xl transition-all duration-300`}>
                {/* Header Row */}
                <div
                  className="flex items-center gap-4 p-5 cursor-pointer select-none"
                  onClick={() => toggle(layer.id)}
                >
                  {/* Number Badge */}
                  <div className={`w-10 h-10 rounded-xl ${a.numBg} text-slate-950 flex items-center justify-center font-black text-sm shrink-0 shadow-lg`}>
                    {layer.num}
                  </div>

                  {/* Icon */}
                  <div className={`p-2.5 rounded-xl bg-slate-950/80 border border-white/10 ${a.text} shrink-0`}>
                    <Icon size={20} />
                  </div>

                  {/* Title & Tech */}
                  <div className="flex-1 min-w-0">
                    <h3 className="text-base font-bold text-white leading-snug">{layer.title}</h3>
                    <p className="text-[11px] text-slate-400 font-mono truncate">{layer.tech}</p>
                  </div>

                  {/* Module Count & Expand Toggle */}
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="hidden sm:inline-block text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                      {layer.modules.length} modules
                    </span>
                    <div className={`p-1.5 rounded-lg border border-white/10 ${a.text} transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}>
                      <ChevronDown size={16} />
                    </div>
                  </div>
                </div>

                {/* Description (always visible) */}
                <div className="px-5 pb-4 -mt-1">
                  <p className="text-xs text-slate-300 leading-relaxed pl-[4.5rem]">
                    {layer.desc}
                  </p>
                </div>

                {/* Expanded Modules */}
                {isOpen && (
                  <div className="border-t border-white/5 bg-slate-950/40">
                    <div className="p-5 pl-[4.5rem] sm:pl-24 space-y-3">
                      {layer.modules.map((mod, mIdx) => (
                        <div
                          key={mIdx}
                          className="flex items-start gap-3 group/mod"
                        >
                          <div className={`w-2 h-2 rounded-full ${a.dot} mt-1.5 shrink-0 group-hover/mod:scale-150 transition-transform`} />
                          <div className="space-y-0.5 min-w-0">
                            <div className="text-sm font-semibold text-slate-200 group-hover/mod:text-white transition-colors">
                              {mod.name}
                            </div>
                            <div className="text-xs text-slate-400 leading-relaxed">
                              {mod.detail}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* ── Data Flow Legend ── */}
      <div className="max-w-5xl mx-auto pt-4">
        <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 p-4 rounded-xl bg-slate-950/60 border border-white/5">
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Architecture Layers:</span>
          {LAYERS.map(l => {
            const a = ACCENT_MAP[l.accent]
            return (
              <div key={l.id} className="flex items-center gap-1.5">
                <div className={`w-2.5 h-2.5 rounded-full ${a.dot}`} />
                <span className="text-[11px] text-slate-400 font-medium">{l.title}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
