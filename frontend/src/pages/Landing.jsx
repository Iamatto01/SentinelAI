import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, ArrowUpRight, ShieldCheck, Terminal, Bot, Radar,
  DatabaseZap, Sparkles, Cpu, CheckCircle2, ChevronRight, Activity,
  GitBranch, Code2, Globe2, Network, Workflow, Zap, Layers
} from 'lucide-react'
import InspectorLogo from '../components/InspectorLogo.jsx'
import ScrollyNavbar from '../components/scrollytelling/ScrollyNavbar.jsx'
import HeroNodeGraph from '../components/scrollytelling/HeroNodeGraph.jsx'
import LiveScanTerminal from '../components/scrollytelling/LiveScanTerminal.jsx'
import AiModelSelector from '../components/scrollytelling/AiModelSelector.jsx'
import VulnerabilityBento from '../components/scrollytelling/VulnerabilityBento.jsx'
import ViceVersaSection from '../components/scrollytelling/ViceVersaSection.jsx'
import MonochromePricing from '../components/scrollytelling/MonochromePricing.jsx'
import MonochromeFaqFooter from '../components/scrollytelling/MonochromeFaqFooter.jsx'
import SpotlightCard from '../components/scrollytelling/SpotlightCard.jsx'
import './Home.css'

export default function Landing() {
  const [agentsCount, setAgentsCount] = useState(53)
  const [heroTab, setHeroTab] = useState('radar') // 'radar' | 'terminal' | 'mesh'

  useEffect(() => {
    fetch('/api/public/stats')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.agentsCount) setAgentsCount(d.agentsCount)
      })
      .catch(() => {})
  }, [])

  return (
    <div className="min-h-screen bg-black text-white font-sans antialiased selection:bg-white selection:text-black overflow-x-hidden">
      {/* ── SECTION 1: Sticky Glassmorphic Navigation Bar ────────────────── */}
      <ScrollyNavbar />

      {/* ── SECTION 2: Hero Section (Dark Dominant #000000 + Overhead Spotlight) ── */}
      <section
        id="platform"
        className="relative min-h-[92vh] pt-28 sm:pt-36 pb-20 flex flex-col justify-center items-center overflow-hidden bg-black"
      >
        {/* Top Volumetric Overhead Spotlight Beam */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-[600px] -translate-y-1/3 opacity-30 blur-3xl z-0"
          style={{
            background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.28), transparent 75%)',
          }}
        />

        {/* Subtle Architectural Wireframe / Dot-Matrix Grid */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.035] z-0"
          style={{
            backgroundImage:
              'linear-gradient(to right, #ffffff 1px, transparent 1px), linear-gradient(to bottom, #ffffff 1px, transparent 1px)',
            backgroundSize: '50px 50px',
            maskImage: 'radial-gradient(ellipse 80% 70% at 50% 40%, black 40%, transparent 90%)',
            WebkitMaskImage: 'radial-gradient(ellipse 80% 70% at 50% 40%, black 40%, transparent 90%)',
          }}
        />

        {/* Interactive 3D/Canvas Background: Monochrome Node-Graph */}
        <HeroNodeGraph />

        {/* Hero Content Container */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 w-full">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center">
            {/* Left Hero Column: Typography & CTAs */}
            <div className="lg:col-span-7 space-y-6 text-left">
              {/* Top Status Pill */}
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-white/20 bg-white/[0.04] text-[11px] font-mono tracking-wider backdrop-blur-md shadow-[0_0_15px_rgba(255,255,255,0.08)]">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
                </span>
                <span className="font-bold text-neutral-200">
                  [ SYSTEM ONLINE // AUTONOMOUS AI PENTEST ENGINE ]
                </span>
              </div>

              {/* Metallic Typographic Reveal Headline */}
              <h1 className="text-4xl sm:text-6xl xl:text-7xl font-black tracking-[-0.03em] leading-[1.05] font-sans">
                Autonomous AI <br />
                <span className="bg-gradient-to-b from-white via-white to-neutral-500 bg-clip-text text-transparent">
                  Offensive Security
                </span>
              </h1>

              {/* Subheadline */}
              <p className="text-sm sm:text-base text-neutral-400 font-sans max-w-xl leading-relaxed">
                SentinelAI orchestrates 150+ real Kali Linux pentest tools via the Native Kali Engine,
                {' '}{agentsCount} specialist AI personas, and local-first RAG knowledge base. Zero cloud exposure,
                continuous vulnerability mapping, and automated git patch synthesis.
              </p>

              {/* Hero Action CTAs */}
              <div className="flex flex-wrap items-center gap-4 pt-2">
                <Link
                  to="/login?mode=register&plan=trial"
                  className="px-6 py-3.5 rounded-xl bg-white text-black font-mono text-xs font-black uppercase tracking-wider flex items-center gap-2 hover:bg-neutral-200 shadow-[0_0_35px_rgba(255,255,255,0.35)] transition-all hover:scale-[1.02] active:scale-[0.98]"
                >
                  <span>Start Free Assessment</span>
                  <ArrowRight size={14} className="stroke-[2.5]" />
                </Link>

                <a
                  href="#terminal"
                  className="px-6 py-3.5 rounded-xl border border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10 hover:border-white/40 font-mono text-xs font-bold transition-all"
                >
                  Explore Capabilities
                </a>
              </div>

              {/* Metrics Strip */}
              <div className="grid grid-cols-3 gap-3 pt-4 max-w-lg font-mono">
                <div className="p-3 rounded-xl border border-white/10 bg-[#0A0A0A]/80 backdrop-blur-md">
                  <div className="text-xl sm:text-2xl font-black text-white">150+</div>
                  <div className="text-[10px] text-neutral-500 uppercase mt-0.5">Kali Security Tools</div>
                </div>

                <div className="p-3 rounded-xl border border-white/10 bg-[#0A0A0A]/80 backdrop-blur-md">
                  <div className="text-xl sm:text-2xl font-black text-white">{agentsCount}</div>
                  <div className="text-[10px] text-neutral-500 uppercase mt-0.5">Specialist Personas</div>
                </div>

                <div className="p-3 rounded-xl border border-white/10 bg-[#0A0A0A]/80 backdrop-blur-md">
                  <div className="text-xl sm:text-2xl font-black text-white">0%</div>
                  <div className="text-[10px] text-neutral-500 uppercase mt-0.5">False Positives</div>
                </div>
              </div>
            </div>

            {/* Right Hero Column: Interactive Threat Radar & Diagnostic Console */}
            <div className="lg:col-span-5">
              <SpotlightCard className="p-5 sm:p-6 border border-white/15 bg-[#080808]/90">
                {/* Header */}
                <div className="flex items-center justify-between pb-3.5 border-b border-white/10">
                  <div className="flex items-center gap-2.5">
                    <div className="p-1.5 rounded-lg border border-white/20 bg-white/5">
                      <InspectorLogo size={22} variant="base" className="text-white" />
                    </div>
                    <div>
                      <h2 className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                        <span>THREAT RADAR // MATRIX</span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded border border-white/20 bg-white/10 text-neutral-300">
                          v2.4
                        </span>
                      </h2>
                      <p className="text-[10px] font-mono text-neutral-400 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                        Subprocess Engine Active
                      </p>
                    </div>
                  </div>

                  {/* Interactive Switcher */}
                  <div className="flex items-center gap-1 p-0.5 rounded-lg border border-white/10 bg-black/60 font-mono text-[10px]">
                    <button
                      type="button"
                      onClick={() => setHeroTab('radar')}
                      className={`px-2 py-1 rounded font-bold transition-all cursor-pointer ${
                        heroTab === 'radar' ? 'bg-white text-black' : 'text-neutral-400 hover:text-white'
                      }`}
                    >
                      Radar
                    </button>
                    <button
                      type="button"
                      onClick={() => setHeroTab('terminal')}
                      className={`px-2 py-1 rounded font-bold transition-all cursor-pointer ${
                        heroTab === 'terminal' ? 'bg-white text-black' : 'text-neutral-400 hover:text-white'
                      }`}
                    >
                      CLI
                    </button>
                    <button
                      type="button"
                      onClick={() => setHeroTab('mesh')}
                      className={`px-2 py-1 rounded font-bold transition-all cursor-pointer ${
                        heroTab === 'mesh' ? 'bg-white text-black' : 'text-neutral-400 hover:text-white'
                      }`}
                    >
                      Mesh
                    </button>
                  </div>
                </div>

                {/* TAB 1: RADAR */}
                {heroTab === 'radar' && (
                  <div className="my-4 space-y-4 font-mono text-xs">
                    <div className="p-4 rounded-xl border border-white/10 bg-black/60 flex flex-col sm:flex-row items-center gap-4">
                      {/* Animated Radar Circle */}
                      <div className="relative w-28 h-28 shrink-0 flex items-center justify-center">
                        <div className="absolute inset-0 rounded-full border border-white/15" />
                        <div className="absolute inset-2.5 rounded-full border border-white/20 border-dashed" />
                        <div className="absolute inset-6 rounded-full border border-white/30" />
                        <div className="absolute inset-9 rounded-full border border-white/40" />
                        <div className="absolute inset-x-0 top-1/2 h-px bg-white/15" />
                        <div className="absolute inset-y-0 left-1/2 w-px bg-white/15" />
                        <div
                          className="absolute inset-0 rounded-full pointer-events-none"
                          style={{
                            background:
                              'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(255, 255, 255, 0.4) 360deg)',
                            animation: 'spin 3s linear infinite',
                          }}
                        />
                        <div className="relative z-10 w-3 h-3 rounded-full bg-white shadow-[0_0_10px_rgba(255,255,255,1)]" />
                      </div>

                      {/* Telemetry info */}
                      <div className="flex-1 min-w-0 space-y-1.5 text-[11px] w-full">
                        <div className="text-[10px] text-neutral-500 uppercase">ACTIVE TARGET</div>
                        <div className="text-white font-bold truncate">https://demo.sentinelai.studio</div>
                        <div className="p-2 rounded bg-black/80 border border-white/10 space-y-1 text-[10px] text-neutral-300">
                          <div className="flex justify-between">
                            <span className="text-neutral-500">Host IP:</span>
                            <span className="font-semibold text-white">192.168.68.132</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-neutral-500">Services:</span>
                            <span className="font-semibold text-white">80, 443, 22</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-neutral-500">TLS:</span>
                            <span className="font-semibold text-white">TLS 1.3 / OpenSSL</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Quick diagnostic row */}
                    <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                      <div className="p-2 rounded-lg bg-black/60 border border-white/10">
                        <div className="text-neutral-500 uppercase">DAST PROBES</div>
                        <div className="text-sm font-bold text-white mt-0.5">142</div>
                        <div className="text-neutral-400">100% Passed</div>
                      </div>
                      <div className="p-2 rounded-lg bg-black/60 border border-white/10">
                        <div className="text-neutral-500 uppercase">VULN MATCHES</div>
                        <div className="text-sm font-bold text-white mt-0.5">2 High</div>
                        <div className="text-neutral-400">0 Critical</div>
                      </div>
                      <div className="p-2 rounded-lg bg-black/60 border border-white/10">
                        <div className="text-neutral-500 uppercase">RAG PAYLOADS</div>
                        <div className="text-sm font-bold text-white mt-0.5">10,482</div>
                        <div className="text-neutral-400">FTS5 Indexed</div>
                      </div>
                    </div>
                  </div>
                )}

                {/* TAB 2: TERMINAL CLI STDOUT */}
                {heroTab === 'terminal' && (
                  <div className="my-4 rounded-xl bg-black border border-white/10 p-3 font-mono text-[11px] leading-relaxed space-y-1.5 h-[190px] overflow-y-auto">
                    <p className="text-white font-bold">$ nmap -sV -sC -p 80,443 demo.sentinelai.studio</p>
                    <p className="text-neutral-400">[+] Nmap: 2 open service banners identified in 1.42s</p>
                    <p className="text-white font-bold">$ nuclei -u https://demo.sentinelai.studio -t cves/</p>
                    <p className="text-white bg-white/10 px-1 py-0.5 rounded font-extrabold">
                      [!] [CRITICAL] Matched CVE-2024-27198 auth bypass
                    </p>
                    <p className="text-white font-bold">$ sqlmap -u "/api/search?q=1" --batch</p>
                    <p className="text-neutral-400">[+] AI Persona #07 verifying boolean blind response delay...</p>
                    <p className="text-white font-semibold">[✓] Persona #01 'Web Hunter' synthesized patch diff</p>
                  </div>
                )}

                {/* TAB 3: AI MESH CONSENSUS */}
                {heroTab === 'mesh' && (
                  <div className="my-4 space-y-2 font-mono text-xs h-[190px] overflow-y-auto">
                    <div className="p-2.5 rounded-lg bg-black border border-white/10 space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-white font-bold">Persona #01 &bull; Web Hunter</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded border border-white/20 bg-white/10 text-white">
                          99.4% Confidence
                        </span>
                      </div>
                      <p className="text-[10px] text-neutral-400 font-sans">
                        Analyzes AST code tokens &amp; OWASP Top 10 vulnerabilities via DeepSeek-V4 consensus.
                      </p>
                    </div>

                    <div className="p-2.5 rounded-lg bg-black border border-white/10 space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-white font-bold">Persona #07 &bull; Database Attacker</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded border border-white/20 bg-white/10 text-white">
                          98.8% Verified
                        </span>
                      </div>
                      <p className="text-[10px] text-neutral-400 font-sans">
                        Synthesizes Boolean Blind and Time-Based SQLi payloads from PayloadsAllTheThings RAG.
                      </p>
                    </div>
                  </div>
                )}

                {/* Footer Telemetry */}
                <div className="pt-3 border-t border-white/10 flex items-center justify-between text-[11px] font-mono text-neutral-400">
                  <span>3 Free Scans Available</span>
                  <span className="text-white font-bold">[ SUBPROCESS READY ]</span>
                </div>
              </SpotlightCard>
            </div>
          </div>
        </div>
      </section>

      {/* ── SIGNAL STRIP (High-Contrast Ticker) ──────────────────────────── */}
      <div className="border-y border-white/10 bg-[#0A0A0A] overflow-hidden py-3">
        <div className="flex animate-marquee whitespace-nowrap text-xs font-mono text-neutral-400 gap-8">
          <span>NMAP PORT RECON</span>
          <span>&bull;</span>
          <span>SQLMAP INJECTION PROBE</span>
          <span>&bull;</span>
          <span>NUCLEI VULN SCAN</span>
          <span>&bull;</span>
          <span>FFUF DIRECTORY BRUTEFORCE</span>
          <span>&bull;</span>
          <span>WHITEBOX CODE AUDIT</span>
          <span>&bull;</span>
          <span>{agentsCount} AI SPECIALIST PERSONAS</span>
          <span>&bull;</span>
          <span>NATIVE KALI ENGINE</span>
          <span>&bull;</span>
          <span>LOCAL-FIRST SQLITE WAL</span>
          <span>&bull;</span>
          <span>METASPLOIT RPC POC</span>
          <span>&bull;</span>
          <span>AUTOMATED GIT PATCH DIFFS</span>
          <span>&bull;</span>
          <span>NMAP PORT RECON</span>
          <span>&bull;</span>
          <span>SQLMAP INJECTION PROBE</span>
          <span>&bull;</span>
          <span>NUCLEI VULN SCAN</span>
          <span>&bull;</span>
          <span>FFUF DIRECTORY BRUTEFORCE</span>
          <span>&bull;</span>
          <span>WHITEBOX CODE AUDIT</span>
          <span>&bull;</span>
          <span>{agentsCount} AI SPECIALIST PERSONAS</span>
          <span>&bull;</span>
          <span>NATIVE KALI ENGINE</span>
        </div>
      </div>

      {/* ── FYP CREATOR & LEAD ARCHITECT SHOWCASE ────────────────────────── */}
      <section className="py-16 sm:py-20 bg-black border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SpotlightCard className="p-6 sm:p-8 border border-white/15 bg-[#080808]/90">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 sm:gap-8">
              {/* Creator Photo - Strictly constrained 120x120 */}
              <div className="relative shrink-0 flex flex-col items-center">
                <div
                  className="rounded-2xl overflow-hidden border-2 border-white/40 shadow-2xl bg-neutral-900"
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
                <span className="mt-2 px-2.5 py-0.5 rounded-full bg-white text-black text-[9px] font-mono font-black uppercase tracking-wider">
                  Lead Dev
                </span>
              </div>

              {/* Creator Bio & Links */}
              <div className="flex-1 text-center sm:text-left space-y-2 min-w-0">
                <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                  <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full border border-white/20 bg-white/5 text-neutral-300 font-bold uppercase tracking-wide flex items-center gap-1">
                    <Sparkles size={11} className="text-white" />
                    Final Year Project 2 Showcase
                  </span>
                  <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full border border-white/20 bg-white/5 text-neutral-400">
                    IIUM &bull; KICT
                  </span>
                </div>

                <div>
                  <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight font-sans">
                    Muhammad Saifudin
                  </h2>
                  <p className="text-xs font-mono text-neutral-400">
                    Lead AI Security Architect &amp; FYP 2 Creator
                  </p>
                </div>

                <p className="text-xs text-neutral-300 leading-relaxed font-sans max-w-3xl">
                  Researched and built SentinelAI — an autonomous multi-agent pentest orchestration platform
                  combining 150+ Kali Linux tools, {agentsCount} LLM specialist personas, and PayloadsAllTheThings
                  RAG intelligence. Eliminates human fatigue while cutting testing costs by up to 90%.
                </p>

                {/* Professional Links */}
                <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2 pt-2">
                  <a
                    href="https://github.com/Iamatto01"
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-lg border border-white/20 bg-white/5 hover:bg-white/10 text-neutral-200 hover:text-white text-xs font-mono font-bold transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <GitBranch size={13} className="text-white" />
                    <span>GitHub: @Iamatto01</span>
                  </a>

                  <a
                    href="https://www.linkedin.com/in/saifudinjamal/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 rounded-lg border border-white/20 bg-white/5 hover:bg-white/10 text-neutral-200 hover:text-white text-xs font-mono font-bold transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
                      <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.67a1.66 1.66 0 0 0-1.66 1.66c0 .92.74 1.66 1.66 1.66a1.66 1.66 0 0 0 1.66-1.66c0-.92-.74-1.66-1.66-1.66Z" />
                    </svg>
                    <span>LinkedIn</span>
                  </a>

                  <span className="text-[11px] text-neutral-500 font-mono flex items-center gap-1 pl-2">
                    <ShieldCheck size={13} className="text-white" />
                    <span>Academic Pentest Platform</span>
                  </span>
                </div>
              </div>
            </div>
          </SpotlightCard>
        </div>
      </section>

      {/* ── CORE CAPABILITIES HIGHLIGHT CARDS ───────────────────────────── */}
      <section className="py-20 sm:py-24 bg-black border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight font-sans">
              Unified Security Capabilities
            </h2>
            <p className="text-xs sm:text-sm text-neutral-400 font-sans leading-relaxed">
              Engineered to eliminate manual testing friction while giving red teams full control over exploit campaigns.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <SpotlightCard className="p-6 sm:p-7 space-y-4">
              <div className="p-2.5 rounded-xl border border-white/20 bg-white/5 w-fit text-white">
                <Bot size={24} />
              </div>
              <h3 className="text-lg font-bold text-white font-sans">{agentsCount} Specialist AI Agents</h3>
              <p className="text-xs sm:text-sm text-neutral-400 font-sans leading-relaxed">
                Automated routing of findings to specialized AI personas (Web Hunter, Database Attacker, Code Auditor) to filter out noise and false positives.
              </p>
            </SpotlightCard>

            <SpotlightCard className="p-6 sm:p-7 space-y-4">
              <div className="p-2.5 rounded-xl border border-white/20 bg-white/5 w-fit text-white">
                <Radar size={24} />
              </div>
              <h3 className="text-lg font-bold text-white font-sans">150+ Kali Security Tools</h3>
              <p className="text-xs sm:text-sm text-neutral-400 font-sans leading-relaxed">
                The native engine dynamically chains nmap, nuclei, sqlmap, ffuf, nikto, subfinder, and more based on real-time attack surface discovery.
              </p>
            </SpotlightCard>

            <SpotlightCard className="p-6 sm:p-7 space-y-4">
              <div className="p-2.5 rounded-xl border border-white/20 bg-white/5 w-fit text-white">
                <ShieldCheck size={24} />
              </div>
              <h3 className="text-lg font-bold text-white font-sans">Blackbox &amp; Whitebox Unified</h3>
              <p className="text-xs sm:text-sm text-neutral-400 font-sans leading-relaxed">
                Scan live website URLs or upload source code (JavaScript, Python, PHP, Java, Go) for automated static code review in one unified platform.
              </p>
            </SpotlightCard>
          </div>
        </div>
      </section>

      {/* ── SECTION 3: Interactive Live Scan Terminal & Execution Pipeline ── */}
      <LiveScanTerminal />

      {/* ── SECTION 4: AI Model & Agent Layout Section ────────────────────── */}
      <AiModelSelector />

      {/* ── SECTION 5: Vulnerability Mapping Bento Grid ──────────────────── */}
      <VulnerabilityBento />

      {/* ── SECTION 6: "Vice Versa" Scroll Inversion (White Background #FFFFFF) ── */}
      <ViceVersaSection />

      {/* ── SECTION 7: Subscription & Pricing Tiers (Return to Obsidian #000000) ── */}
      <MonochromePricing />

      {/* ── SECTION 8: Trust, FAQ & Footer Section ───────────────────────── */}
      <MonochromeFaqFooter />
    </div>
  )
}
