import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bot, Cpu, Zap, Activity, ShieldCheck, DatabaseZap, Terminal,
  Code2, CheckCircle2, ArrowRight, Layers, Sparkles
} from 'lucide-react'
import SpotlightCard from './SpotlightCard.jsx'

const AI_MODELS = [
  {
    id: 'deepseek-v4',
    name: 'Deep Exploit Reasoning Model',
    provider: 'DeepSeek V4 Pro (Heavy Tier // Bandelbanget)',
    role: 'Multi-Step Vulnerability Chaining & Zero-Day Logic',
    badge: 'HEAVY REASONING',
    latency: '420ms',
    latencyRating: 'Deep Thought',
    contextWindow: '128,000 Tokens',
    contextPct: 95,
    accuracy: 99.7,
    environments: ['Web Applications', 'REST/GraphQL APIs', 'Cloud Infrastructure', 'Kali Subprocess'],
    description:
      'Reserved for deep AST source code audits and complex multi-hop exploit verification. Synthesizes proof-of-concept vectors by cross-referencing PayloadsAllTheThings vector embeddings.',
    samplePrompt: 'System: You are Persona #01 "Web Hunter". Verify CVE-2024-27198 authentication bypass on endpoint /api/v1/setup. Synthesize unified git diff patch.',
    sampleOutput: '[DeepSeek V4]: Exploit validated via authBypass header trick. Root token generated. Synthesizing RFC-standard git patch to enforce RS256 algorithm verification...'
  },
  {
    id: 'ling-flash',
    name: 'Fast Recon & Triage Agent',
    provider: 'Ling-3.0 Flash (Fast Tier // OpenRouter)',
    role: 'Real-Time Asset Discovery & Subdomain Filtering',
    badge: 'ULTRA-LOW LATENCY',
    latency: '38ms',
    latencyRating: 'Instantaneous',
    contextWindow: '64,000 Tokens',
    contextPct: 65,
    accuracy: 99.1,
    environments: ['Web Applications', 'DNS / Subdomains', 'Port Scans', 'WAF Fingerprinting'],
    description:
      'High-throughput parser handling hundreds of raw Nmap, Subfinder, and Katana stdout streams per second. Eliminates unroutable IPs and deduplicates attack surfaces.',
    samplePrompt: 'Analyze Nmap XML stdout for demo.sentinelai.studio. Extract all responsive service banners and filter out honeypot ports.',
    sampleOutput: '[Ling Flash]: 4 active endpoints isolated: 80/nginx, 443/TLS1.3, 8080/Express, 8443/Internal. Zero honeypot signatures detected.'
  },
  {
    id: 'groq-llama',
    name: 'Real-Time Consensus LLM',
    provider: 'Llama 3.3 70B Versatile (Fallback Tier // Groq Cloud)',
    role: 'False-Positive Elimination & CVSS Risk Scoring',
    badge: '70B PARAMETERS',
    latency: '68ms',
    latencyRating: 'Sub-100ms',
    contextWindow: '128,000 Tokens',
    contextPct: 95,
    accuracy: 99.4,
    environments: ['Live CLI Stdout', 'REST APIs', 'Cloud Infrastructure', 'Docker / Kali'],
    description:
      'Executes multi-LLM consensus voting against raw scanner outputs. Verifies HTTP status codes, reflection tags, and response length deltas to ensure 0% false positives.',
    samplePrompt: 'Review raw SQLMap time-based blind injection logs. Confirm boolean delay validity against 5.000s threshold.',
    sampleOutput: '[Llama 3.3 70B]: Validated 5.021s sleep delay on parameter "q". Probability of false positive: <0.001%. CVSS 3.1 calculated: 8.9 HIGH.'
  },
  {
    id: 'code-auditor',
    name: 'Code Audit & AST Parser LLM',
    provider: 'AST Security Engine (JS / Python / PHP / Java / Go)',
    role: 'Whitebox Static Code Analysis & Taint Flow Tracking',
    badge: 'WHITEBOX SAST',
    latency: '140ms',
    latencyRating: 'Fast AST Walk',
    contextWindow: '32,000 Tokens',
    contextPct: 45,
    accuracy: 98.9,
    environments: ['Git Repositories', 'GitHub Pull Requests', 'CI/CD Pipelines', 'Local Workspace'],
    description:
      'Parses Abstract Syntax Trees across modern languages to detect hardcoded secrets, unsafe deserialization, SQL injection sinks, and OWASP Top 10 flaws before deployment.',
    samplePrompt: 'Audit /backend/src/auth.js for improper JWT algorithm validation and missing secret fallbacks.',
    sampleOutput: '[AST Auditor]: Taint sink identified at Line 42: jwt.decode() invoked without verify=True. Severity: HIGH. Remediated in PR recommendation.'
  },
  {
    id: 'remediation-agent',
    name: 'Automated Remediation Agent',
    provider: 'PayloadsAllTheThings RAG + Multi-Persona Consensus',
    role: 'Git Diff Code Patch Synthesis & Auto-PR Deployment',
    badge: 'AUTONOMOUS FIX',
    latency: '180ms',
    latencyRating: 'Real-Time Patch',
    contextWindow: '128,000 Tokens',
    contextPct: 95,
    accuracy: 99.5,
    environments: ['GitHub Octokit Bot', 'Local Git Repos', 'Executive PDFKit', 'Slack / Webhooks'],
    description:
      'Synthesizes production-ready, context-aware code patches in unified git diff format. Integrates with GitHub Octokit to post inline PR code reviews directly on vulnerable lines.',
    samplePrompt: 'Generate drop-in replacement patch for vulnerable JWT auth middleware with strict RS256 algorithm whitelist.',
    sampleOutput: '[Remediation Agent]: Patch synthesized successfully. Validated against test suite. Automated Octokit review comment posted to GitHub PR #14.'
  },
  {
    id: 'database-attacker',
    name: 'Database Attacker Persona',
    provider: 'Persona #07 + SQLMap Daemon RPC',
    role: 'Autonomous SQL Injection Chaining & Schema Extraction',
    badge: 'INJECTION PROBE',
    latency: '95ms',
    latencyRating: 'Sub-100ms',
    contextWindow: '64,000 Tokens',
    contextPct: 65,
    accuracy: 99.2,
    environments: ['PostgreSQL', 'MySQL / MariaDB', 'SQLite WAL', 'MSSQL / Oracle'],
    description:
      'Chains stacked queries, error-based inference, and boolean blind payloads to enumerate schemas without triggering brittle WAF rate limits.',
    samplePrompt: 'Execute controlled time-based injection against target /api/items?cat=1. Extract DB version fingerprint safely.',
    sampleOutput: '[DB Attacker]: SQLite 3.45.1 detected with WAL mode active. No data exfiltration permitted per safe-mode bounds.'
  }
]

export default function AiModelSelector() {
  const [selectedId, setSelectedId] = useState('deepseek-v4')
  const currentModel = AI_MODELS.find((m) => m.id === selectedId) || AI_MODELS[0]

  return (
    <section id="models" className="relative scroll-mt-20 py-24 sm:py-32 bg-black border-t border-white/10 text-white overflow-hidden">
      {/* Top Overhead Volumetric Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-96 -translate-y-1/2 opacity-25 blur-3xl z-0"
        style={{
          background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.2), transparent)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Header with Scroll Reveal */}
        <motion.div
          initial={{ opacity: 0, y: 35 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-3xl mx-auto space-y-4 mb-14 sm:mb-16"
        >
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-white/15 bg-white/[0.04] text-[11px] font-mono text-neutral-300">
            <Bot size={13} className="text-white" />
            <span className="font-bold uppercase tracking-wider">
              AI MODEL &amp; AGENT MESH // ORCHESTRATION ARCHITECTURE
            </span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight font-sans">
            Specialized Neural Engines <br />
            <span className="bg-gradient-to-b from-white via-neutral-200 to-neutral-500 bg-clip-text text-transparent">
              Tuned for Autonomous Offensive Security
            </span>
          </h2>

          <p className="text-sm sm:text-base text-neutral-400 font-sans leading-relaxed">
            SentinelAI uses a multi-tier fallback architecture: fast free models for real-time reconnaissance
            and high-parameter reasoning models for complex vulnerability chaining and patch synthesis.
          </p>
        </motion.div>

        {/* Interactive Model Switcher Pills (Converge from top/bottom on scroll) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.7, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          className="flex items-center justify-center flex-wrap gap-2 mb-10 sm:mb-12"
        >
          {AI_MODELS.map((model) => {
            const isSelected = selectedId === model.id

            return (
              <button
                key={model.id}
                type="button"
                onClick={() => setSelectedId(model.id)}
                className={`px-4 py-2.5 rounded-xl text-xs font-mono font-bold transition-all duration-300 cursor-pointer flex items-center gap-2 border ${
                  isSelected
                    ? 'bg-white text-black border-white shadow-[0_0_20px_rgba(255,255,255,0.3)] scale-[1.02]'
                    : 'bg-[#0A0A0A] text-neutral-400 border-white/10 hover:border-white/30 hover:text-white'
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${isSelected ? 'bg-black' : 'bg-neutral-600'}`} />
                <span>{model.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                  isSelected ? 'bg-black/10 text-black' : 'bg-white/5 text-neutral-400'
                }`}>
                  {model.badge}
                </span>
              </button>
            )
          })}
        </motion.div>

        {/* Model Telemetry Card - Glides in on scroll with animated tab switch */}
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.97 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.8, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
        >
          <SpotlightCard className="p-6 sm:p-10 border border-white/15 bg-[#080808]/90">
            <AnimatePresence mode="wait">
              <motion.div
                key={currentModel.id}
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start"
              >
                {/* Left Column: Specifications & Metrics */}
                <div className="lg:col-span-7 space-y-6">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase bg-white/10 text-white border border-white/20">
                        {currentModel.badge}
                      </span>
                      <span className="text-xs font-mono text-neutral-400">{currentModel.provider}</span>
                    </div>
                    <h3 className="text-2xl sm:text-3xl font-extrabold text-white font-sans tracking-tight">
                      {currentModel.name}
                    </h3>
                    <p className="text-xs font-mono text-neutral-400">{currentModel.role}</p>
                  </div>

                  <p className="text-xs sm:text-sm text-neutral-300 leading-relaxed font-sans">
                    {currentModel.description}
                  </p>

                  {/* Comparative Specification Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 p-4 rounded-xl bg-black/60 border border-white/10">
                    {/* Metric 1: Speed / Latency */}
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono text-neutral-500 uppercase flex items-center gap-1">
                        <Zap size={11} className="text-white" />
                        <span>Inference Latency</span>
                      </div>
                      <div className="text-lg font-black text-white font-mono">{currentModel.latency}</div>
                      <div className="text-[10px] font-mono text-neutral-400">{currentModel.latencyRating}</div>
                    </div>

                    {/* Metric 2: Context Window */}
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono text-neutral-500 uppercase flex items-center gap-1">
                        <Layers size={11} className="text-white" />
                        <span>Context Window</span>
                      </div>
                      <div className="text-lg font-black text-white font-mono">{currentModel.contextWindow}</div>
                      <div className="w-full bg-neutral-800 rounded-full h-1 mt-1">
                        <motion.div
                          className="bg-white h-1 rounded-full"
                          initial={{ width: 0 }}
                          animate={{ width: `${currentModel.contextPct}%` }}
                          transition={{ duration: 0.6 }}
                        />
                      </div>
                    </div>

                    {/* Metric 3: Exploit Accuracy */}
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono text-neutral-500 uppercase flex items-center gap-1">
                        <Activity size={11} className="text-white" />
                        <span>Detection Accuracy</span>
                      </div>
                      <div className="text-lg font-black text-white font-mono">{currentModel.accuracy}%</div>
                      <div className="w-full bg-neutral-800 rounded-full h-1 mt-1">
                        <motion.div
                          className="bg-white h-1 rounded-full shadow-[0_0_8px_rgba(255,255,255,0.8)]"
                          initial={{ width: 0 }}
                          animate={{ width: `${currentModel.accuracy}%` }}
                          transition={{ duration: 0.6 }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Supported Environments Badges */}
                  <div className="space-y-2">
                    <span className="text-[10px] font-mono text-neutral-400 uppercase tracking-wider block">
                      SUPPORTED TARGET ENVIRONMENTS &amp; TOOLHOOKS
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {currentModel.environments.map((env, i) => (
                        <span
                          key={i}
                          className="px-2.5 py-1 rounded-lg border border-white/10 bg-white/5 text-[11px] font-mono text-neutral-300 flex items-center gap-1"
                        >
                          <CheckCircle2 size={11} className="text-white" />
                          <span>{env}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right Column: Dynamic Prompt & Output Simulator */}
                <div className="lg:col-span-5 space-y-3 font-mono text-xs">
                  <div className="p-3.5 rounded-xl border border-white/10 bg-black/60 space-y-2">
                    <div className="flex items-center justify-between text-[10px] text-neutral-400 border-b border-white/10 pb-2">
                      <span className="flex items-center gap-1 text-white font-bold">
                        <Terminal size={11} />
                        <span>INFERENCE DISPATCH PROMPT</span>
                      </span>
                      <span className="text-[9px] px-1.5 py-0.2 rounded border border-white/20 bg-white/10 text-white">
                        LIVE
                      </span>
                    </div>
                    <p className="text-neutral-300 leading-relaxed text-[11px]">
                      {currentModel.samplePrompt}
                    </p>
                  </div>

                  <div className="p-3.5 rounded-xl border border-white/20 bg-white/[0.04] space-y-2 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-24 h-24 bg-white/5 rounded-full blur-2xl pointer-events-none" />
                    <div className="flex items-center justify-between text-[10px] text-neutral-400 border-b border-white/10 pb-2">
                      <span className="flex items-center gap-1 text-white font-bold">
                        <Sparkles size={11} />
                        <span>SYNTHESIZED REASONING OUTPUT</span>
                      </span>
                      <span className="text-[9px] text-neutral-400">0% False Positives</span>
                    </div>
                    <p className="text-neutral-200 leading-relaxed text-[11px] font-mono">
                      {currentModel.sampleOutput}
                    </p>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          </SpotlightCard>
        </motion.div>
      </div>
    </section>
  )
}
