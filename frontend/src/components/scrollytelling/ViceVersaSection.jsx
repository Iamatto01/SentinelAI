import React, { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Workflow, Network, Binary, Globe2, Server, Terminal,
  Bot, DatabaseZap, FileText, ChevronRight, CheckCircle2,
  ArrowRight, Sparkles, Layers, ShieldCheck
} from 'lucide-react'
import { useTheme } from '../../lib/ThemeContext.jsx'

const PIPELINE_STEPS = [
  {
    num: '01',
    title: 'Target Intake & Triggers',
    tech: 'REST API & Webhooks',
    short: 'Blackbox domain/IP scan submission or automated GitHub Webhook trigger on commit push and pull request.',
    initialPos: { x: -60, y: -40 },
    details: [
      { label: 'Blackbox Trigger', val: 'Target URL or IP CIDR range entered via web dashboard' },
      { label: 'Whitebox Webhook', val: 'GitHub Push & Pull Request event listener via Octokit Bot' },
      { label: 'Scope Boundary', val: 'Automated domain validation & IP sanitization to prevent out-of-scope testing' }
    ]
  },
  {
    num: '02',
    title: 'Express API Gateway & Quota',
    tech: 'Node.js & SQLite WAL',
    short: 'JWT 12h authentication, RBAC multi-tenant isolation, 3 free trial scans & subscription quota enforcement.',
    initialPos: { x: 0, y: -60 },
    details: [
      { label: 'Role-Based Auth', val: 'Strict Admin, Security Analyst, and Client portal permission isolation' },
      { label: 'Quota Gatekeeper', val: 'Enforces scan limits (Free Trial: 3, Pro: 50, Enterprise: Unlimited)' },
      { label: 'Embedded WAL DB', val: 'Local-first zero-cloud SQLite storage with point-in-time recovery' }
    ]
  },
  {
    num: '03',
    title: 'Native Kali Engine',
    tech: '150+ Subprocess Tools',
    short: 'Chains 150+ real Kali Linux pentest tools via direct subprocess execution and runs AST static code analysis.',
    initialPos: { x: 60, y: -40 },
    details: [
      { label: 'Recon & Discovery', val: 'Nmap port scan, Subfinder subdomain recon, Masscan, WhatWeb' },
      { label: 'Vuln Probing', val: 'Nuclei template scans, Nikto, SQLMap injection, FFUF fuzzing' },
      { label: 'AST Code Parser', val: 'Static code parser scanning JS, Python, PHP, Java for OWASP Top 10 flaws' }
    ]
  },
  {
    num: '04',
    title: 'Multi-LLM AI Consensus',
    tech: '53 Specialist Personas',
    short: 'Staged verification across DeepSeek V4 Pro, Groq Llama 3.3 70B, and Ling Flash to eliminate false positives.',
    initialPos: { x: -60, y: 40 },
    details: [
      { label: 'Noise Filter', val: 'Context-aware verification suppresses raw tool false alarms (0% noise)' },
      { label: 'Risk Categorization', val: 'Auto-calculates CVSS v3.1 base score (Critical, High, Medium, Low)' },
      { label: 'Plain-English Summary', val: 'Generates layman explanations and non-technical business summaries' }
    ]
  },
  {
    num: '05',
    title: 'Local RAG Knowledge Base',
    tech: 'PayloadsAllTheThings FTS5',
    short: 'Searches 10,000+ curated payloads in embedded SQLite full-text index and synthesizes unified git diff patches.',
    initialPos: { x: 0, y: 60 },
    details: [
      { label: 'FTS5 Payload Search', val: 'Sub-millisecond retrieval of verified PoC exploit vectors' },
      { label: 'Patch Generation', val: 'Context-aware automated git diff code patch synthesis' },
      { label: 'Attack Graph Link', val: 'Generates topological attack paths in force-directed node map' }
    ]
  },
  {
    num: '06',
    title: 'CI/CD & Executive Delivery',
    tech: 'Octokit Bot + PDFKit',
    short: 'Pushes verified code reviews to GitHub PRs, sends email attachments, and dispatches real-time webhooks.',
    initialPos: { x: 60, y: 40 },
    details: [
      { label: 'GitHub Octokit Bot', val: 'Posts inline code review comments directly on vulnerable PR lines' },
      { label: 'Executive PDF Report', val: 'Compiles 40+ page ISO 27001 / OWASP compliance audit report' },
      { label: 'Instant Relays', val: 'Sends alert notifications to Telegram, Discord, and Slack channels' }
    ]
  }
]

export default function ViceVersaSection() {
  const { isNight } = useTheme()
  const [activeStep, setActiveStep] = useState(1)
  const [viewMode, setViewMode] = useState('pipeline')

  // In dark mode: inverts to White. In light mode: inverts to Dark!
  const isInvertedWhite = isNight

  return (
    <section
      id="architecture"
      className={`relative scroll-mt-16 py-28 sm:py-36 transition-colors duration-700 overflow-hidden ${
        isInvertedWhite
          ? 'bg-white text-black selection:bg-black selection:text-white'
          : 'bg-black text-white selection:bg-white selection:text-black'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Animated Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-3xl mx-auto space-y-4 mb-16 sm:mb-20"
        >
          <div className={`inline-flex items-center gap-2 px-3.5 py-1 rounded-full border text-[11px] font-mono ${
            isInvertedWhite
              ? 'border-black/20 bg-neutral-100 text-black'
              : 'border-white/20 bg-white/5 text-white'
          }`}>
            <Workflow size={13} className={isInvertedWhite ? 'text-black' : 'text-white'} />
            <span className="font-bold uppercase tracking-wider">
              SYSTEM ARCHITECTURE // {isInvertedWhite ? 'VICE VERSA INVERSION' : 'OBSIDIAN REVERSE INVERSION'}
            </span>
          </div>

          <h2 className={`text-3xl sm:text-5xl font-black tracking-tight font-sans ${
            isInvertedWhite ? 'text-black' : 'text-white'
          }`}>
            Security Blueprint &amp; <br />
            <span className="underline decoration-1 underline-offset-8">
              End-to-End Execution Pipeline
            </span>
          </h2>

          <p className={`text-sm sm:text-base font-sans leading-relaxed ${
            isInvertedWhite ? 'text-neutral-600' : 'text-neutral-400'
          }`}>
            {isInvertedWhite ? 'Stark black architectural wireframes on a stark white canvas.' : 'Obsidian wireframes on a pitch-black canvas.'} Watch the subsystem cards
            glide inward and assemble together into the architecture matrix.
          </p>

          {/* Mode Switcher */}
          <div className="flex items-center justify-center gap-2 pt-2">
            <button
              type="button"
              onClick={() => setViewMode('pipeline')}
              className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer border ${
                viewMode === 'pipeline'
                  ? isInvertedWhite ? 'bg-black text-white border-black shadow' : 'bg-white text-black border-white shadow'
                  : isInvertedWhite ? 'bg-neutral-100 text-neutral-700 border-neutral-300 hover:border-black' : 'bg-white/5 text-neutral-300 border-white/20 hover:border-white'
              }`}
            >
              Sequential Pipeline (6 Stages)
            </button>
            <button
              type="button"
              onClick={() => setViewMode('wireframe')}
              className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer border ${
                viewMode === 'wireframe'
                  ? isInvertedWhite ? 'bg-black text-white border-black shadow' : 'bg-white text-black border-white shadow'
                  : isInvertedWhite ? 'bg-neutral-100 text-neutral-700 border-neutral-300 hover:border-black' : 'bg-white/5 text-neutral-300 border-white/20 hover:border-white'
              }`}
            >
              Wireframe Flowchart
            </button>
          </div>
        </motion.div>

        {/* ── VIEW 1: SEQUENTIAL PIPELINE WITH CONVERGING GRID CARDS ── */}
        {viewMode === 'pipeline' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {PIPELINE_STEPS.map((step, idx) => {
              const isActive = activeStep === idx + 1

              return (
                <motion.div
                  key={step.num}
                  initial={{ opacity: 0, x: step.initialPos.x, y: step.initialPos.y, scale: 0.94 }}
                  whileInView={{ opacity: 1, x: 0, y: 0, scale: 1 }}
                  viewport={{ once: true, amount: 0.2 }}
                  transition={{ duration: 0.75, delay: idx * 0.1, ease: [0.16, 1, 0.3, 1] }}
                  onClick={() => setActiveStep(idx + 1)}
                  className={`group relative p-6 sm:p-7 rounded-2xl border transition-all duration-300 cursor-pointer flex flex-col justify-between ${
                    isInvertedWhite
                      ? isActive
                        ? 'border-black bg-white shadow-[0_15px_35px_rgba(0,0,0,0.15)] ring-2 ring-black scale-[1.02]'
                        : 'border-neutral-300 bg-[#F4F4F5] hover:border-black hover:bg-black hover:text-white hover:shadow-2xl'
                      : isActive
                        ? 'border-white bg-[#141414] shadow-[0_15px_35px_rgba(255,255,255,0.15)] ring-2 ring-white scale-[1.02]'
                        : 'border-white/15 bg-[#0D0D0D] hover:border-white hover:bg-white hover:text-black hover:shadow-2xl'
                  }`}
                >
                  <div className="space-y-4">
                    {/* Header Row */}
                    <div className={`flex items-center justify-between pb-3 border-b ${
                      isInvertedWhite
                        ? 'border-neutral-300 group-hover:border-neutral-700'
                        : 'border-white/10 group-hover:border-neutral-300'
                    }`}>
                      <span className={`text-2xl font-black font-mono ${
                        isInvertedWhite ? 'text-black group-hover:text-white' : 'text-white group-hover:text-black'
                      }`}>
                        {step.num}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider ${
                        isInvertedWhite
                          ? 'border-neutral-300 bg-white text-neutral-700 group-hover:bg-neutral-800 group-hover:text-neutral-200 group-hover:border-neutral-700'
                          : 'border-white/20 bg-white/5 text-neutral-300 group-hover:bg-neutral-200 group-hover:text-black group-hover:border-neutral-400'
                      }`}>
                        {step.tech}
                      </span>
                    </div>

                    <h3 className={`text-lg font-bold font-sans tracking-tight ${
                      isInvertedWhite ? 'text-black group-hover:text-white' : 'text-white group-hover:text-black'
                    }`}>
                      {step.title}
                    </h3>

                    <p className={`text-xs leading-relaxed font-sans ${
                      isInvertedWhite ? 'text-neutral-600 group-hover:text-neutral-300' : 'text-neutral-400 group-hover:text-neutral-700'
                    }`}>
                      {step.short}
                    </p>

                    {/* Expandable Breakdown Pill */}
                    <div className={`pt-2 space-y-2 border-t text-[11px] font-mono ${
                      isInvertedWhite
                        ? 'border-neutral-200 group-hover:border-neutral-800'
                        : 'border-white/10 group-hover:border-neutral-200'
                    }`}>
                      {step.details.map((d, i) => (
                        <div key={i} className="flex items-start gap-1.5">
                          <CheckCircle2 size={12} className={`shrink-0 mt-0.5 ${
                            isInvertedWhite ? 'text-black group-hover:text-white' : 'text-white group-hover:text-black'
                          }`} />
                          <div>
                            <span className={`font-bold ${
                              isInvertedWhite ? 'text-black group-hover:text-white' : 'text-white group-hover:text-black'
                            }`}>{d.label}: </span>
                            <span className={isInvertedWhite ? 'text-neutral-600 group-hover:text-neutral-300' : 'text-neutral-400 group-hover:text-neutral-700'}>{d.val}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className={`pt-4 mt-4 border-t flex items-center justify-between text-[10px] font-mono ${
                    isInvertedWhite
                      ? 'border-neutral-200 group-hover:border-neutral-800 text-neutral-500 group-hover:text-neutral-400'
                      : 'border-white/10 group-hover:border-neutral-200 text-neutral-400 group-hover:text-neutral-600'
                  }`}>
                    <span>SentinelAI Architecture</span>
                    <ArrowRight size={12} className="group-hover:translate-x-1 transition-transform" />
                  </div>
                </motion.div>
              )
            })}
          </div>
        )}

        {/* ── VIEW 2: TECHNICAL WIREFRAME DIAGRAM ── */}
        {viewMode === 'wireframe' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`p-6 sm:p-10 rounded-3xl border ${
              isInvertedWhite
                ? 'border-black bg-[#F4F4F5] text-black shadow-xl'
                : 'border-white bg-[#0D0D0D] text-white shadow-xl'
            }`}
          >
            <div className={`flex items-center justify-between pb-6 border-b ${
              isInvertedWhite ? 'border-neutral-300' : 'border-white/10'
            }`}>
              <div>
                <h3 className="text-xl font-black font-sans">Topological End-to-End Blueprint</h3>
                <p className={`text-xs font-mono mt-0.5 ${isInvertedWhite ? 'text-neutral-600' : 'text-neutral-400'}`}>
                  Target Intake &rarr; Subprocess Kali Daemon &rarr; Consensus RAG &rarr; Git Auto-Patch
                </p>
              </div>
              <span className={`text-xs font-mono px-3 py-1 rounded-full font-bold ${
                isInvertedWhite ? 'bg-black text-white' : 'bg-white text-black'
              }`}>
                SPEC v2.4
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-8 font-mono text-xs">
              <div className={`p-4 rounded-xl border space-y-2 ${
                isInvertedWhite ? 'bg-white border-black/20' : 'bg-black border-white/20'
              }`}>
                <div className={`text-[10px] uppercase font-bold ${
                  isInvertedWhite ? 'text-neutral-500' : 'text-neutral-400'
                }`}>TIER 1 // INTAKE</div>
                <div className="font-bold text-sm">Target Scope &amp; API Gateway</div>
                <p className={isInvertedWhite ? 'text-neutral-600 text-[11px]' : 'text-neutral-400 text-[11px]'}>
                  Ingests URLs, verifies authorization boundaries, checks monthly subscription scan quotas, and allocates local SQLite WAL storage.
                </p>
              </div>

              <div className={`p-4 rounded-xl border space-y-2 ${
                isInvertedWhite ? 'bg-white border-black/20' : 'bg-black border-white/20'
              }`}>
                <div className={`text-[10px] uppercase font-bold ${
                  isInvertedWhite ? 'text-neutral-500' : 'text-neutral-400'
                }`}>TIER 2 // ENGINE</div>
                <div className="font-bold text-sm">Native Kali 150+ Tools</div>
                <p className={isInvertedWhite ? 'text-neutral-600 text-[11px]' : 'text-neutral-400 text-[11px]'}>
                  Spawns local subprocess daemons executing Nmap, Nuclei, SQLMap, FFUF, and AST code audits without intermediate network hops.
                </p>
              </div>

              <div className={`p-4 rounded-xl border space-y-2 ${
                isInvertedWhite ? 'bg-white border-black/20' : 'bg-black border-white/20'
              }`}>
                <div className={`text-[10px] uppercase font-bold ${
                  isInvertedWhite ? 'text-neutral-500' : 'text-neutral-400'
                }`}>TIER 3 // SYNTHESIS</div>
                <div className="font-bold text-sm">AI Consensus &amp; Patch PR</div>
                <p className={isInvertedWhite ? 'text-neutral-600 text-[11px]' : 'text-neutral-400 text-[11px]'}>
                  Validates proof-of-concepts, ensures 0% false positives, writes unified git diffs, and compiles 40+ page executive PDFs.
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </section>
  )
}
