import React, { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Workflow, Network, Binary, Globe2, Server, Terminal,
  Bot, DatabaseZap, FileText, ChevronRight, CheckCircle2,
  ArrowRight, Sparkles, Layers, ShieldCheck
} from 'lucide-react'

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
    short: 'Searches 10,000+ curated exploit techniques in SQLite full-text index and synthesizes context-aware git diff patches.',
    initialPos: { x: 0, y: 60 },
    details: [
      { label: 'FTS5 Vector Search', val: '10,000+ curated security payloads indexed locally for rapid retrieval' },
      { label: 'Patch Generation', val: 'Synthesizes clean git diff patches ready to commit to GitHub repos' },
      { label: 'Attack Graph Link', val: 'Maps vulnerable endpoints into topological lateral movement paths' }
    ]
  },
  {
    num: '06',
    title: 'CI/CD & Executive Delivery',
    tech: 'PDFKit + Octokit Bot',
    short: 'Renders executive PDF reports, emails attachments, and posts line-by-line GitHub PR review comments.',
    initialPos: { x: 60, y: 40 },
    details: [
      { label: 'Executive PDF Report', val: 'Comprehensive audit reports with risk matrices, CVSS, and charts' },
      { label: 'GitHub PR Inline Bot', val: 'Directly comments on vulnerable lines in GitHub Pull Requests' },
      { label: 'Real-Time Webhooks', val: 'Instant alerts dispatched to Slack, Discord, Telegram, and Email' }
    ]
  }
]

export default function ViceVersaSection() {
  const [activeStep, setActiveStep] = useState(1)
  const [viewMode, setViewMode] = useState('pipeline')

  return (
    <section
      id="architecture"
      className="relative scroll-mt-16 py-28 sm:py-36 bg-white text-black transition-colors duration-700 selection:bg-black selection:text-white overflow-hidden"
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
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-black/20 bg-neutral-100 text-[11px] font-mono text-black">
            <Workflow size={13} className="text-black" />
            <span className="font-bold uppercase tracking-wider">
              SYSTEM ARCHITECTURE // "VICE VERSA" WHITE INVERSION
            </span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-black text-black tracking-tight font-sans">
            Security Blueprint &amp; <br />
            <span className="underline decoration-1 underline-offset-8">
              End-to-End Execution Pipeline
            </span>
          </h2>

          <p className="text-sm sm:text-base text-neutral-600 font-sans leading-relaxed">
            Stark black architectural wireframes on a stark white canvas. Watch the subsystem cards
            glide inward and assemble together into the architecture matrix.
          </p>

          {/* Mode Switcher */}
          <div className="flex items-center justify-center gap-2 pt-2">
            <button
              type="button"
              onClick={() => setViewMode('pipeline')}
              className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer border ${
                viewMode === 'pipeline'
                  ? 'bg-black text-white border-black shadow'
                  : 'bg-neutral-100 text-neutral-700 border-neutral-300 hover:border-black'
              }`}
            >
              Sequential Pipeline (6 Stages)
            </button>
            <button
              type="button"
              onClick={() => setViewMode('wireframe')}
              className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer border ${
                viewMode === 'wireframe'
                  ? 'bg-black text-white border-black shadow'
                  : 'bg-neutral-100 text-neutral-700 border-neutral-300 hover:border-black'
              }`}
            >
              Architectural Topology Map
            </button>
          </div>
        </motion.div>

        {/* VIEW 1: SEQUENTIAL PIPELINE WITH MOVE & ASSEMBLE ANIMATIONS */}
        {viewMode === 'pipeline' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {PIPELINE_STEPS.map((step, idx) => {
              const isSelected = activeStep === idx + 1

              return (
                <motion.div
                  key={step.num}
                  initial={{
                    opacity: 0,
                    x: step.initialPos.x,
                    y: step.initialPos.y,
                    scale: 0.92,
                  }}
                  whileInView={{
                    opacity: 1,
                    x: 0,
                    y: 0,
                    scale: 1,
                  }}
                  viewport={{ once: true, amount: 0.2 }}
                  transition={{
                    duration: 0.75,
                    delay: idx * 0.08,
                    ease: [0.16, 1, 0.3, 1],
                  }}
                  onMouseEnter={() => setActiveStep(idx + 1)}
                  onClick={() => setActiveStep(idx + 1)}
                  className={`p-6 sm:p-7 rounded-2xl border transition-all duration-300 flex flex-col justify-between cursor-pointer group ${
                    isSelected
                      ? 'bg-black text-white border-black shadow-2xl scale-[1.02]'
                      : 'bg-neutral-50 text-black border-neutral-300 hover:bg-black hover:text-white hover:border-black hover:scale-[1.02]'
                  }`}
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b border-current/15">
                      <span className="text-xs font-mono font-extrabold px-2.5 py-1 rounded border border-current">
                        STEP {step.num}
                      </span>
                      <span className="text-[11px] font-mono opacity-70">
                        {step.tech}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-lg font-bold font-sans tracking-tight mb-1">
                        {step.title}
                      </h3>
                      <p className="text-xs leading-relaxed opacity-80 font-sans">
                        {step.short}
                      </p>
                    </div>

                    {/* Sub-module details */}
                    <div className="space-y-1.5 pt-2">
                      {step.details.map((d, i) => (
                        <div
                          key={i}
                          className="p-2 rounded border border-current/10 bg-current/5 text-[11px] font-mono flex items-start gap-1.5"
                        >
                          <span className="font-bold shrink-0">{d.label}:</span>
                          <span className="opacity-80">{d.val}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="pt-4 border-t border-current/15 flex items-center justify-between text-[10px] font-mono opacity-60 mt-4">
                    <span>Subsystem 0{idx + 1} of 06</span>
                    <span className="font-bold uppercase">
                      {isSelected ? 'ACTIVE INSPECTION' : 'HOVER TO INVERT'}
                    </span>
                  </div>
                </motion.div>
              )
            })}
          </div>
        )}

        {/* VIEW 2: ARCHITECTURAL WIREFRAME BLUEPRINT */}
        {viewMode === 'wireframe' && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
            className="rounded-3xl border-2 border-black bg-neutral-50 p-6 sm:p-10 font-mono"
          >
            <div className="flex items-center justify-between pb-6 border-b border-black text-xs">
              <span className="font-bold tracking-wider">
                SENTINELAI // HIGH-CONTRAST WIREFRAME BLUEPRINT
              </span>
              <span className="px-2 py-0.5 rounded bg-black text-white text-[10px] font-bold">
                SYSTEM SPEC V2.4
              </span>
            </div>

            <div className="my-8 grid grid-cols-1 md:grid-cols-5 gap-4 items-center">
              {/* Box 1 */}
              <div className="p-4 rounded-xl border border-black bg-white text-center space-y-1">
                <div className="text-[10px] text-neutral-500 uppercase">Input Layer</div>
                <div className="font-bold text-sm text-black">Target Intake</div>
                <div className="text-[10px] text-neutral-600">URL / IP / GitHub Webhooks</div>
              </div>

              {/* Arrow */}
              <div className="hidden md:flex justify-center text-black font-black text-lg">
                →
              </div>

              {/* Box 2 */}
              <div className="p-4 rounded-xl border border-black bg-white text-center space-y-1">
                <div className="text-[10px] text-neutral-500 uppercase">Gateway</div>
                <div className="font-bold text-sm text-black">API &amp; Quota Guard</div>
                <div className="text-[10px] text-neutral-600">JWT 12h &bull; SQLite WAL</div>
              </div>

              {/* Arrow */}
              <div className="hidden md:flex justify-center text-black font-black text-lg">
                →
              </div>

              {/* Box 3 */}
              <div className="p-4 rounded-xl border border-black bg-black text-white text-center space-y-1 shadow-lg">
                <div className="text-[10px] text-neutral-400 uppercase">Execution Core</div>
                <div className="font-bold text-sm text-white">Native Kali Engine</div>
                <div className="text-[10px] text-neutral-300">150+ Subprocess Tools</div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-center my-4">
              {/* Box 4 */}
              <div className="p-4 rounded-xl border border-black bg-black text-white text-center space-y-1 shadow-lg">
                <div className="text-[10px] text-neutral-400 uppercase">AI Arbiter</div>
                <div className="font-bold text-sm text-white">Multi-LLM Consensus</div>
                <div className="text-[10px] text-neutral-300">53 Specialist Personas</div>
              </div>

              {/* Arrow */}
              <div className="hidden md:flex justify-center text-black font-black text-lg">
                ←
              </div>

              {/* Box 5 */}
              <div className="p-4 rounded-xl border border-black bg-white text-center space-y-1">
                <div className="text-[10px] text-neutral-500 uppercase">Intelligence RAG</div>
                <div className="font-bold text-sm text-black">Payloads FTS5</div>
                <div className="text-[10px] text-neutral-600">10,000+ Exploit Index</div>
              </div>

              {/* Arrow */}
              <div className="hidden md:flex justify-center text-black font-black text-lg">
                ←
              </div>

              {/* Box 6 */}
              <div className="p-4 rounded-xl border border-black bg-white text-center space-y-1">
                <div className="text-[10px] text-neutral-500 uppercase">Delivery</div>
                <div className="font-bold text-sm text-black">Audit Reports &amp; PR</div>
                <div className="text-[10px] text-neutral-600">Executive PDF &bull; Bot</div>
              </div>
            </div>

            <div className="pt-6 border-t border-black text-xs text-neutral-600 flex flex-col sm:flex-row items-center justify-between gap-2">
              <span>All operations execute on local infrastructure with zero cloud exfiltration.</span>
              <span className="font-bold text-black">[ VERIFIED AIR-GAP COMPATIBLE ]</span>
            </div>
          </motion.div>
        )}
      </div>
    </section>
  )
}
