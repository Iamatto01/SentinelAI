import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  ArrowRight, ArrowUpRight, ShieldCheck, Terminal, Bot, Radar,
  DatabaseZap, Sparkles, Cpu, CheckCircle2, ChevronRight, Activity,
  GitBranch, Code2, Globe2, Network, Workflow, Zap, Layers
} from 'lucide-react'
import ScrollyNavbar from '../components/scrollytelling/ScrollyNavbar.jsx'
import ScrollProgressHUD from '../components/scrollytelling/ScrollProgressHUD.jsx'
import LiveScanTerminal from '../components/scrollytelling/LiveScanTerminal.jsx'
import AiModelSelector from '../components/scrollytelling/AiModelSelector.jsx'
import VulnerabilityBento from '../components/scrollytelling/VulnerabilityBento.jsx'
import ViceVersaSection from '../components/scrollytelling/ViceVersaSection.jsx'
import MonochromePricing from '../components/scrollytelling/MonochromePricing.jsx'
import MonochromeFaqFooter from '../components/scrollytelling/MonochromeFaqFooter.jsx'
import SpotlightCard from '../components/scrollytelling/SpotlightCard.jsx'
import DiagonalThemeSelector from '../components/DiagonalThemeSelector.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'
import './Home.css'

export default function Landing() {
  const { isNight } = useTheme()
  const [agentsCount, setAgentsCount] = useState(53)
  const [showThemeIntro, setShowThemeIntro] = useState(false)

  // Listen for replay event from navbar or dropdown
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
  }, [])

  return (
    <div className={`min-h-screen font-sans antialiased overflow-x-hidden relative transition-colors duration-500 ${
      isNight
        ? 'bg-black text-white selection:bg-white selection:text-black'
        : 'bg-[#FAFAFA] text-zinc-950 selection:bg-black selection:text-white'
    }`}>
      {/* ── Interactive Diagonal Split-Screen Theme Selector Protocol ───── */}
      <DiagonalThemeSelector
        isOpen={showThemeIntro}
        onClose={() => setShowThemeIntro(false)}
      />

      {/* ── Minimalist Scrollytelling Progress Scrubber ─────────────────── */}
      <ScrollProgressHUD />

      {/* ── SECTION 1: Sticky Glassmorphic Navigation Bar ────────────────── */}
      <ScrollyNavbar />

      {/* ── SECTION 2: Hero Section (Dark / Light Adaptive + Overhead Spotlight) ── */}
      <section
        id="platform"
        className={`relative min-h-[92vh] pt-28 sm:pt-36 pb-20 flex flex-col justify-center items-center overflow-hidden transition-colors duration-500 ${
          isNight ? 'bg-black' : 'bg-[#FAFAFA]'
        }`}
      >
        {/* Top Volumetric Overhead Spotlight Beam */}
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-[600px] -translate-y-1/3 opacity-30 blur-3xl z-0"
          style={{
            background: isNight
              ? 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.28), transparent 75%)'
              : 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,0,0,0.08), transparent 75%)',
          }}
        />

        {/* Subtle Architectural Wireframe / Dot-Matrix Grid */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.035] z-0"
          style={{
            backgroundImage: isNight
              ? 'linear-gradient(to right, #ffffff 1px, transparent 1px), linear-gradient(to bottom, #ffffff 1px, transparent 1px)'
              : 'linear-gradient(to right, #000000 1px, transparent 1px), linear-gradient(to bottom, #000000 1px, transparent 1px)',
            backgroundSize: '50px 50px',
            maskImage: 'radial-gradient(ellipse 80% 70% at 50% 40%, black 40%, transparent 90%)',
            WebkitMaskImage: 'radial-gradient(ellipse 80% 70% at 50% 40%, black 40%, transparent 90%)',
          }}
        />

        {/* Hero Content Container */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 w-full">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center">
            {/* Left Hero Column: Typography & CTAs with Fluid Entrance Physics */}
            <motion.div
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
              className="lg:col-span-8 space-y-6 text-left"
            >
              {/* Metallic Typographic Reveal Headline */}
              <h1 className="text-4xl sm:text-6xl xl:text-7xl font-black tracking-[-0.03em] leading-[1.05] font-sans">
                Autonomous AI <br />
                <span className={`bg-clip-text text-transparent ${
                  isNight
                    ? 'bg-gradient-to-b from-white via-white to-neutral-500'
                    : 'bg-gradient-to-b from-zinc-950 via-zinc-900 to-zinc-600'
                }`}>
                  Offensive Security
                </span>
              </h1>

              {/* Subheadline */}
              <p className={`text-sm sm:text-base font-sans max-w-xl leading-relaxed ${
                isNight ? 'text-neutral-400' : 'text-zinc-600'
              }`}>
                SentinelAI orchestrates 150+ real Kali Linux pentest tools via the Native Kali Engine,
                {' '}{agentsCount} specialist AI personas, and local-first RAG knowledge base. Zero cloud exposure,
                continuous vulnerability mapping, and automated git patch synthesis.
              </p>

              {/* Hero Action CTAs */}
              <div className="flex flex-wrap items-center gap-4 pt-2">
                <Link
                  to="/login?mode=register&plan=trial"
                  style={!isNight ? { color: '#ffffff' } : {}}
                  className={`px-6 py-3.5 rounded-xl font-mono text-xs font-black uppercase tracking-wider flex items-center gap-2 transition-all hover:scale-[1.02] active:scale-[0.98] ${
                    isNight
                      ? 'bg-white text-black hover:bg-neutral-200 shadow-[0_0_35px_rgba(255,255,255,0.35)]'
                      : 'bg-black text-white hover:bg-zinc-800 shadow-[0_0_25px_rgba(0,0,0,0.25)]'
                  }`}
                >
                  <span style={!isNight ? { color: '#ffffff' } : {}}>Start Free Assessment</span>
                  <ArrowRight size={14} className="stroke-[2.5]" style={!isNight ? { stroke: '#ffffff' } : {}} />
                </Link>

                <a
                  href="#terminal"
                  className={`px-6 py-3.5 rounded-xl border font-mono text-xs font-bold transition-all ${
                    isNight
                      ? 'border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10 hover:border-white/40'
                      : 'border-zinc-300 bg-black/5 text-zinc-800 hover:text-black hover:bg-black/10 hover:border-zinc-400'
                  }`}
                >
                  Explore Capabilities
                </a>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── SIGNAL STRIP (High-Contrast Ticker) ──────────────────────────── */}
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.7 }}
        className={`border-y overflow-hidden py-3 transition-colors duration-500 ${
          isNight ? 'border-white/10 bg-[#0A0A0A] text-neutral-400' : 'border-zinc-200 bg-zinc-100 text-zinc-600'
        }`}
      >
        <div className="flex animate-marquee whitespace-nowrap text-xs font-mono gap-8 will-change-transform">
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
          <span>&bull;</span>
          <span>LOCAL-FIRST SQLITE WAL</span>
          <span>&bull;</span>
          <span>METASPLOIT RPC POC</span>
          <span>&bull;</span>
          <span>AUTOMATED GIT PATCH DIFFS</span>
        </div>
      </motion.div>

      {/* ── FYP CREATOR & LEAD ARCHITECT SHOWCASE (Assembly on Scroll) ───── */}
      <section className={`py-16 sm:py-20 border-b overflow-hidden transition-colors duration-500 ${
        isNight ? 'bg-black border-white/10' : 'bg-[#FAFAFA] border-zinc-200'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: 40, scale: 0.96 }}
            whileInView={{ opacity: 1, y: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.25 }}
            transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          >
            <SpotlightCard className="p-6 sm:p-8">
              <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 sm:gap-8">
                {/* Creator Photo - Strictly constrained 120x120 */}
                <div className="relative shrink-0 flex flex-col items-center">
                  <div
                    className={`rounded-2xl overflow-hidden border-2 shadow-2xl ${
                      isNight ? 'border-white/40 bg-neutral-900' : 'border-zinc-400 bg-zinc-200'
                    }`}
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
                        objectPosition: '50% 25%',
                        display: 'block',
                      }}
                      onError={(e) => { e.currentTarget.src = '/saif.JPG' }}
                    />
                  </div>
                  <span className={`mt-2 px-2.5 py-0.5 rounded-full text-[9px] font-mono font-black uppercase tracking-wider ${
                    isNight ? 'bg-white text-black' : 'bg-black text-white'
                  }`}>
                    Lead Dev
                  </span>
                </div>

                {/* Creator Bio & Links */}
                <div className="flex-1 text-center sm:text-left space-y-2 min-w-0">
                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                    <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wide ${
                      isNight ? 'border-white/20 bg-white/5 text-neutral-300' : 'border-zinc-300 bg-zinc-100 text-zinc-700'
                    }`}>
                      Final Year Project 2 Showcase
                    </span>
                    <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full border ${
                      isNight ? 'border-white/20 bg-white/5 text-neutral-400' : 'border-zinc-300 bg-zinc-100 text-zinc-500'
                    }`}>
                      IIUM &bull; KICT
                    </span>
                  </div>

                  <div>
                    <h2 className={`text-xl sm:text-2xl font-bold tracking-tight font-sans ${
                      isNight ? 'text-white' : 'text-zinc-950'
                    }`}>
                      Muhammad Saifudin
                    </h2>
                    <p className={`text-xs font-mono ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>
                      Lead AI Security Architect &amp; FYP 2 Creator
                    </p>
                  </div>

                  <p className={`text-xs leading-relaxed font-sans max-w-3xl ${
                    isNight ? 'text-neutral-300' : 'text-zinc-600'
                  }`}>
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
                      className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                        isNight
                          ? 'border-white/20 bg-white/5 hover:bg-white/10 text-neutral-200 hover:text-white'
                          : 'border-zinc-300 bg-zinc-100 hover:bg-zinc-200 text-zinc-800 hover:text-black'
                      }`}
                    >
                      <GitBranch size={13} className={isNight ? 'text-white' : 'text-black'} />
                      <span>GitHub: @Iamatto01</span>
                    </a>

                    <a
                      href="https://www.linkedin.com/in/saifudinjamal/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                        isNight
                          ? 'border-white/20 bg-white/5 hover:bg-white/10 text-neutral-200 hover:text-white'
                          : 'border-zinc-300 bg-zinc-100 hover:bg-zinc-200 text-zinc-800 hover:text-black'
                      }`}
                    >
                      <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
                        <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.67a1.66 1.66 0 0 0-1.66 1.66c0 .92.74 1.66 1.66 1.66a1.66 1.66 0 0 0 1.66-1.66c0-.92-.74-1.66-1.66-1.66Z" />
                      </svg>
                      <span>LinkedIn</span>
                    </a>
                  </div>
                </div>
              </div>
            </SpotlightCard>
          </motion.div>
        </div>
      </section>

      {/* ── CORE CAPABILITIES HIGHLIGHT CARDS (Converge & Assemble on Scroll) ─ */}
      <section className={`py-20 sm:py-24 border-b overflow-hidden transition-colors duration-500 ${
        isNight ? 'bg-black border-white/10' : 'bg-[#FAFAFA] border-zinc-200'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.7 }}
            className="text-center space-y-3 max-w-2xl mx-auto"
          >
            <h2 className={`text-2xl sm:text-4xl font-extrabold tracking-tight font-sans ${
              isNight ? 'text-white' : 'text-zinc-950'
            }`}>
              Unified Security Capabilities
            </h2>
            <p className={`text-xs sm:text-sm font-sans leading-relaxed ${
              isNight ? 'text-neutral-400' : 'text-zinc-600'
            }`}>
              Engineered to eliminate manual testing friction while giving red teams full control over exploit campaigns.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Card 1 glides from left */}
            <motion.div
              initial={{ opacity: 0, x: -50, scale: 0.95 }}
              whileInView={{ opacity: 1, x: 0, scale: 1 }}
              viewport={{ once: true, amount: 0.25 }}
              transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
            >
              <SpotlightCard className="p-6 sm:p-7 space-y-4 h-full">
                <div className={`p-2.5 rounded-xl border w-fit ${
                  isNight ? 'border-white/20 bg-white/5 text-white' : 'border-zinc-300 bg-zinc-100 text-black'
                }`}>
                  <Bot size={24} />
                </div>
                <h3 className={`text-lg font-bold font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                  {agentsCount} Specialist AI Agents
                </h3>
                <p className={`text-xs sm:text-sm font-sans leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                  Automated routing of findings to specialized AI personas (Web Hunter, Database Attacker, Code Auditor) to filter out noise and false positives.
                </p>
              </SpotlightCard>
            </motion.div>

            {/* Card 2 drops in from center */}
            <motion.div
              initial={{ opacity: 0, y: 40, scale: 0.95 }}
              whileInView={{ opacity: 1, y: 0, scale: 1 }}
              viewport={{ once: true, amount: 0.25 }}
              transition={{ duration: 0.75, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
            >
              <SpotlightCard className="p-6 sm:p-7 space-y-4 h-full">
                <div className={`p-2.5 rounded-xl border w-fit ${
                  isNight ? 'border-white/20 bg-white/5 text-white' : 'border-zinc-300 bg-zinc-100 text-black'
                }`}>
                  <Radar size={24} />
                </div>
                <h3 className={`text-lg font-bold font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                  150+ Kali Security Tools
                </h3>
                <p className={`text-xs sm:text-sm font-sans leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                  The native engine dynamically chains nmap, nuclei, sqlmap, ffuf, nikto, subfinder, and more based on real-time attack surface discovery.
                </p>
              </SpotlightCard>
            </motion.div>

            {/* Card 3 glides from right */}
            <motion.div
              initial={{ opacity: 0, x: 50, scale: 0.95 }}
              whileInView={{ opacity: 1, x: 0, scale: 1 }}
              viewport={{ once: true, amount: 0.25 }}
              transition={{ duration: 0.75, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
            >
              <SpotlightCard className="p-6 sm:p-7 space-y-4 h-full">
                <div className={`p-2.5 rounded-xl border w-fit ${
                  isNight ? 'border-white/20 bg-white/5 text-white' : 'border-zinc-300 bg-zinc-100 text-black'
                }`}>
                  <ShieldCheck size={24} />
                </div>
                <h3 className={`text-lg font-bold font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                  Blackbox &amp; Whitebox Unified
                </h3>
                <p className={`text-xs sm:text-sm font-sans leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                  Scan live website URLs or upload source code (JavaScript, Python, PHP, Java, Go) for automated static code review in one unified platform.
                </p>
              </SpotlightCard>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── SECTION 3: Interactive Live Scan Terminal & Execution Pipeline ── */}
      <LiveScanTerminal />

      {/* ── SECTION 4: AI Model & Agent Layout Section ────────────────────── */}
      <AiModelSelector />

      {/* ── SECTION 5: Vulnerability Mapping Bento Grid (Converging Grid) ── */}
      <VulnerabilityBento />

      {/* ── SECTION 6: "Vice Versa" Scroll Inversion Section ─────────────── */}
      <ViceVersaSection />

      {/* ── SECTION 7: Subscription & Pricing Tiers (Assemble on Scroll) ─── */}
      <MonochromePricing />

      {/* ── SECTION 8: Trust, FAQ & Footer Section ───────────────────────── */}
      <MonochromeFaqFooter />
    </div>
  )
}
