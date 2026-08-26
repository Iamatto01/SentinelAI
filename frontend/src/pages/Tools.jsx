import React, { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, Search, Terminal, Bot, DatabaseZap, Radar, Globe2,
  Swords, Code2, ShieldCheck, Network, Bug, KeyRound
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'

const GLASS_CARD = {
  background: 'rgba(255, 255, 255, 0.04)',
  backdropFilter: 'blur(40px) saturate(180%)',
  WebkitBackdropFilter: 'blur(40px) saturate(180%)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.06)',
}

// ── Kali Tool Catalog (grouped by pipeline stage & DAST / SAST) ─────────────
const TOOL_CATEGORIES = [
  {
    id: 'dast',
    icon: Bug,
    color: 'text-amber-400',
    accent: 'hover:border-amber-400/40',
    title: 'Dynamic App Security Testing (DAST)',
    desc: 'Live blackbox vulnerability probing, template-based testing, and heuristic injection fuzzing.',
    tools: ['Nuclei (YAML Templates)', 'Nikto Web Scanner', 'SQLMap Injection Engine', 'FFUF Web Fuzzer', 'WPScan CMS Auditor', 'Dalfox XSS Scanner', 'Arjun Parameter Discovery', 'WAFW00F Bypass Detector', 'Rustscan Port Prober', 'Jaeles Dynamic Engine'],
  },
  {
    id: 'sast',
    icon: Code2,
    color: 'text-indigo-400',
    accent: 'hover:border-indigo-400/40',
    title: 'Static Code Analysis (SAST)',
    desc: 'Whitebox AST-based source code auditing for OWASP Top 10 vulnerabilities across multiple languages.',
    tools: ['JS / TypeScript AST Parser', 'Python AST Security Parser', 'PHP Vulnerability Parser', 'Java AST Security Engine', 'Go AST Code Scanner', 'Taint-Flow Source-to-Sink Engine'],
  },
  {
    id: 'recon',
    icon: Radar,
    color: 'text-cyan-400',
    accent: 'hover:border-cyan-400/40',
    title: 'Recon & Attack Surface Mapping',
    desc: 'Passive and active surface discovery, DNS enumeration, and technology fingerprinting.',
    tools: ['Nmap Port Scanner', 'Masscan Fast Scanner', 'Subfinder Subdomain Recon', 'Amass OSINT Mapping', 'WhatWeb Tech Identifier', 'DNSBrute Enumerator', 'Katana Web Crawler', 'Waybackurls Archive Discovery'],
  },
  {
    id: 'fuzz',
    icon: Globe2,
    color: 'text-emerald-400',
    accent: 'hover:border-emerald-400/40',
    title: 'Web & Parameter Fuzzing',
    desc: 'High-speed directory discovery, hidden parameter identification, and payload permutation.',
    tools: ['FFUF Directory Fuzzer', 'Gobuster URL Bruter', 'X8 Hidden Parameter Tool', 'Gau Endpoint Fetcher', 'Qsreplace Parameter Injector'],
  },
  {
    id: 'exploit',
    icon: Swords,
    color: 'text-rose-400',
    accent: 'hover:border-rose-400/40',
    title: 'Controlled Exploitation & PoC',
    desc: 'Controlled proof-of-concept verification with mandatory human-in-the-loop safety approval gates.',
    tools: ['Metasploit RPC (msfrpcd)', 'Hydra Credential Tester', 'Hashcat Password Cracker', 'Searchsploit Exploit DB', 'Impacket Network Suite', 'CrackMapExec Lateral Tool'],
  },
]

// ── 51 AI Agent Personas Matrix ──────────────────────────────────────────────
const AGENT_PERSONAS = [
  'Web Hunter', 'Database Attacker', 'Code Auditor', 'BizLogic Hunter', 'Cloud Security',
  'LLM Red Team', 'API Security', 'Network Attacker', 'Credential Tester', 'Crypto Analyzer',
  'Reverse Engineer', 'Malware Analyst', 'Forensics Analyst', 'Mobile Pentester', 'IoT Pentester',
  'Wireless Pentester', 'SCADA Attacker', 'Container Breakout', 'Lateral Movement', 'C2 Operator',
  'Evasion Specialist', 'Payload Crafter', 'Phishing Operator', 'OSINT Collector', 'Vuln Scanner',
  'Exploit Guide', 'Exploit Chainer', 'Privesc Advisor', 'Threat Modeler', 'Risk Scorer',
  'Detection Engineer', 'Compliance Mapper', 'Report Generator', 'Engagement Planner', 'Social Engineer',
  'Data Exfiltrator', 'Persistence Planner', 'Traffic Analyzer', 'Stig Analyst', 'Password Auditor',
  'Attack Planner', 'Swarm Orchestrator', 'Poc Validator', 'Bug Bounty', 'CTF Solver',
  'CICD Red Team', 'Recon Advisor', 'Opsec Anonymizer', 'AI Recon', 'Scope Guard',
  'Ad Attacker',
]

export default function Tools() {
  const [query, setQuery] = useState('')
  const [activeCat, setActiveCat] = useState('all')

  // Filter tools across all categories by search query + active category
  const filtered = useMemo(() => {
    return TOOL_CATEGORIES
      .filter((c) => activeCat === 'all' || c.id === activeCat)
      .map((c) => ({
        ...c,
        tools: c.tools.filter(
          (t) => t.toLowerCase().includes(query.toLowerCase())
        ),
      }))
      .filter((c) => c.tools.length > 0)
  }, [query, activeCat])

  const totalTools = TOOL_CATEGORIES.reduce((n, c) => n + c.tools.length, 0)

  return (
    <PublicLayout>
      <div className="max-w-6xl mx-auto px-4 sm:px-8 pt-16 sm:pt-24 pb-12 space-y-24">
        {/* ── Hero ─────────────────────────────────────────────────────────── */}
        <section className="text-center space-y-5">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-bold uppercase tracking-wider">
            <ShieldCheck size={14} className="text-cyan-400" /> Full DAST &amp; SAST Dual-Engine Platform
          </div>
          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            150+ Kali Tools &amp; <span className="at-home__gradient-text">51 AI Personas</span>
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Every tool in the Hexstrike engine is real, installed, and health-checked — combining live dynamic blackbox testing (DAST) with whitebox static code parsing (SAST).
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <Link to="/services" className="btn-swipe btn-lg">
              See Them in Action <ArrowRight size={15} />
            </Link>
          </div>
        </section>

        {/* ── Interactive Tool Directory ───────────────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Interactive Tool Catalog</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              Filterable &amp; searchable directory of the core Hexstrike toolchain.
            </p>
          </div>

          {/* Search + Category Filter */}
          <div className="space-y-4">
            <div className="relative max-w-md mx-auto">
              <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search tools… (e.g. nmap, sqlmap, nuclei)"
                className="w-full pl-10 pr-4 py-3 rounded-2xl bg-slate-950/70 border border-white/15 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/30 transition-colors"
              />
            </div>

            <div className="flex flex-wrap items-center justify-center gap-2">
              <button
                onClick={() => setActiveCat('all')}
                className={`btn-swipe-right ${activeCat === 'all' ? 'btn-swipe-right--active' : ''}`}
              >
                All Categories
              </button>
              {TOOL_CATEGORIES.map((c) => {
                const Icon = c.icon
                return (
                  <button
                    key={c.id}
                    onClick={() => setActiveCat(c.id)}
                    className={`btn-swipe-right ${activeCat === c.id ? 'btn-swipe-right--active' : ''}`}
                  >
                    <Icon size={13} /> {c.title}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Category Cards */}
          {filtered.length === 0 ? (
            <p className="text-center text-sm text-slate-500 py-10">No tools match &ldquo;{query}&rdquo;.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filtered.map((cat) => {
                const Icon = cat.icon
                return (
                  <div key={cat.id} className={`p-6 rounded-2xl transition-all duration-300 hover:-translate-y-1 ${cat.accent}`} style={GLASS_CARD}>
                    <div className="flex items-center gap-3 mb-3">
                      <div className={`p-2 rounded-xl bg-black/40 border border-white/10 ${cat.color}`}>
                        <Icon size={20} />
                      </div>
                      <h3 className="text-sm font-extrabold text-white">{cat.title}</h3>
                    </div>
                    <p className="text-[11px] text-slate-400 mb-4 leading-relaxed">{cat.desc}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {cat.tools.map((t) => (
                        <span key={t} className="px-2 py-0.5 rounded-lg bg-black/50 border border-white/10 text-[11px] font-mono text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300 transition-colors">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>

        {/* ── 51 AI Agent Personas Matrix ──────────────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-amber-500/10 border border-amber-400/30 text-amber-300 text-xs font-bold uppercase tracking-wider">
              <Bot size={13} className="text-amber-400" /> Specialist Agent Matrix
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">51 AI Agent Personas</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              Each finding is routed to the persona best suited to verify, exploit, or remediate it — under multi-LLM consensus.
            </p>
          </div>

          <div className="p-6 sm:p-8 rounded-3xl" style={GLASS_CARD}>
            <div className="flex flex-wrap gap-2 justify-center">
              {AGENT_PERSONAS.map((p) => (
                <span
                  key={p}
                  className="px-3 py-1.5 rounded-xl bg-slate-950/80 border border-white/10 text-[11px] font-bold text-slate-300 hover:border-amber-400/50 hover:text-amber-300 hover:bg-amber-500/5 transition-all cursor-default"
                >
                  {p}
                </span>
              ))}
            </div>
            <p className="text-center text-[11px] text-slate-500 mt-5 font-mono">
              {AGENT_PERSONAS.length} personas registered in the consensus routing table
            </p>
          </div>
        </section>

        {/* ── PayloadsAllTheThings RAG Showcase ────────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-400/30 text-emerald-300 text-xs font-bold uppercase tracking-wider">
              <DatabaseZap size={13} className="text-emerald-400" /> Local-First Knowledge Engine
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">PayloadsAllTheThings RAG Engine</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              10,000+ curated PoC exploit files indexed locally with SQLite FTS5 — sub-second retrieval, zero cloud dependency.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              { icon: DatabaseZap, color: 'text-emerald-400', t: 'FTS5 Full-Text Index', d: 'Every payload, PoC script, and cheat-sheet tokenized into a local SQLite FTS5 index queried in milliseconds.' },
              { icon: KeyRound, color: 'text-amber-400', t: 'Verified Payload Matching', d: 'Findings are matched against proven exploit payloads so reports ship with working reproduction steps.' },
              { icon: Network, color: 'text-cyan-400', t: 'Attack Graph Linking', d: 'Related payloads are linked into topological attack paths visualized on a force-directed node map.' },
            ].map((f) => {
              const Icon = f.icon
              return (
                <div key={f.t} className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300" style={GLASS_CARD}>
                  <Icon className={`${f.color} mb-3`} size={28} />
                  <h3 className="text-base font-bold text-white mb-2">{f.t}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{f.d}</p>
                </div>
              )
            })}
          </div>
        </section>

        {/* ── CTA ──────────────────────────────────────────────────────────── */}
        <section className="card p-10 sm:p-14 border border-cyan-500/30 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 text-center rounded-3xl shadow-2xl space-y-6">
          <ShieldCheck className="mx-auto text-cyan-400" size={36} />
          <h2 className="text-2xl sm:text-3xl font-bold text-white">Put the Arsenal to Work</h2>
          <p className="text-slate-400 text-xs sm:text-sm max-w-xl mx-auto leading-relaxed">
            Launch your first autonomous assessment and watch {totalTools}+ tools chain themselves against your target.
          </p>
          <div className="flex justify-center gap-4">
            <Link to="/login?mode=register&plan=pro" className="btn-concept-12">
              <span className="btn-concept-12__text">Get Started Now</span>
              <span className="btn-concept-12__icon">
                <ShieldCheck size={18} />
              </span>
            </Link>
          </div>
        </section>
      </div>
    </PublicLayout>
  )
}
