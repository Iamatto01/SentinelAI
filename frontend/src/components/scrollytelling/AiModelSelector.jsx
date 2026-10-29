import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bot, Cpu, Zap, Activity, ShieldCheck, DatabaseZap, Terminal,
  Code2, CheckCircle2, ArrowRight, Layers, Sparkles
} from 'lucide-react'
import SpotlightCard from './SpotlightCard.jsx'
import { useTheme } from '../../lib/ThemeContext.jsx'

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
  const { isNight } = useTheme()
  const [selectedId, setSelectedId] = useState('deepseek-v4')
  const currentModel = AI_MODELS.find((m) => m.id === selectedId) || AI_MODELS[0]

  return (
    <section id="models" className={`relative scroll-mt-20 py-24 sm:py-32 border-t overflow-hidden transition-colors duration-500 ${
      isNight ? 'bg-black border-white/10 text-white' : 'bg-[#FAFAFA] border-zinc-200 text-zinc-950'
    }`}>
      {/* Top Overhead Volumetric Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-96 -translate-y-1/2 opacity-25 blur-3xl z-0"
        style={{
          background: isNight
            ? 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.2), transparent)'
            : 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,0,0,0.06), transparent)',
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
          <div className={`inline-flex items-center gap-2 px-3.5 py-1 rounded-full border text-[11px] font-mono ${
            isNight ? 'border-white/15 bg-white/[0.04] text-neutral-300' : 'border-zinc-300 bg-black/5 text-zinc-800'
          }`}>
            <Bot size={13} className={isNight ? 'text-white' : 'text-black'} />
            <span className="font-bold uppercase tracking-wider">
              AI MODEL &amp; AGENT MESH // ORCHESTRATION ARCHITECTURE
            </span>
          </div>

          <h2 className={`text-3xl sm:text-5xl font-extrabold tracking-tight font-sans ${
            isNight ? 'text-white' : 'text-zinc-950'
          }`}>
            Specialized Neural Engines <br />
            <span className={`bg-clip-text text-transparent ${
              isNight
                ? 'bg-gradient-to-b from-white via-neutral-200 to-neutral-500'
                : 'bg-gradient-to-b from-zinc-950 via-zinc-900 to-zinc-600'
            }`}>
              Tuned for Autonomous Offensive Security
            </span>
          </h2>

          <p className={`text-sm sm:text-base font-sans leading-relaxed ${
            isNight ? 'text-neutral-400' : 'text-zinc-600'
          }`}>
            SentinelAI uses a multi-tier fallback architecture: fast free models for real-time reconnaissance
            and high-parameter reasoning models for complex vulnerability chaining and patch synthesis.
          </p>
        </motion.div>

        {/* Interactive Model Switcher Pills */}
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
                    ? isNight
                      ? 'bg-white text-black border-white shadow-[0_0_20px_rgba(255,255,255,0.3)] scale-[1.02]'
                      : 'bg-black text-white border-black shadow-md scale-[1.02]'
                    : isNight
                      ? 'bg-[#0A0A0A] text-neutral-400 border-white/10 hover:border-white/30 hover:text-white'
                      : 'bg-white text-zinc-600 border-zinc-200 hover:border-zinc-400 hover:text-black shadow-sm'
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${
                  isSelected
                    ? isNight ? 'bg-black' : 'bg-white'
                    : isNight ? 'bg-neutral-600' : 'bg-zinc-400'
                }`} />
                <span>{model.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                  isSelected
                    ? isNight ? 'bg-black/10 text-black' : 'bg-white/15 text-white'
                    : isNight ? 'bg-white/5 text-neutral-400' : 'bg-zinc-100 text-zinc-600'
                }`}>
                  {model.badge}
                </span>
              </button>
            )
          })}
        </motion.div>

        {/* Model Telemetry Card */}
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.97 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.8, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
        >
          <SpotlightCard className="p-6 sm:p-10">
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
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase border ${
                        isNight ? 'bg-white/10 text-white border-white/20' : 'bg-black/5 text-black border-zinc-300'
                      }`}>
                        {currentModel.badge}
                      </span>
                      <span className={`text-xs font-mono ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>
                        {currentModel.provider}
                      </span>
                    </div>
                    <h3 className={`text-2xl sm:text-3xl font-extrabold font-sans tracking-tight ${
                      isNight ? 'text-white' : 'text-zinc-950'
                    }`}>
                      {currentModel.name}
                    </h3>
                    <p className={`text-xs font-mono ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>{currentModel.role}</p>
                  </div>

                  <p className={`text-xs sm:text-sm leading-relaxed font-sans ${
                    isNight ? 'text-neutral-300' : 'text-zinc-600'
                  }`}>
                    {currentModel.description}
                  </p>

                  {/* Comparative Specification Grid */}
                  <div className={`grid grid-cols-2 sm:grid-cols-3 gap-3 p-4 rounded-xl border ${
                    isNight ? 'bg-black/60 border-white/10' : 'bg-zinc-50 border-zinc-200'
                  }`}>
                    {/* Metric 1: Speed / Latency */}
                    <div className="space-y-1">
                      <div className={`text-[10px] font-mono uppercase flex items-center gap-1 ${
                        isNight ? 'text-neutral-500' : 'text-zinc-500'
                      }`}>
                        <Zap size={11} className={isNight ? 'text-white' : 'text-black'} />
                        <span>Inference Latency</span>
                      </div>
                      <div className={`text-lg font-black font-mono ${isNight ? 'text-white' : 'text-zinc-950'}`}>{currentModel.latency}</div>
                      <div className={`text-[10px] font-mono ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>{currentModel.latencyRating}</div>
                    </div>

                    {/* Metric 2: Context Window */}
                    <div className="space-y-1">
                      <div className={`text-[10px] font-mono uppercase flex items-center gap-1 ${
                        isNight ? 'text-neutral-500' : 'text-zinc-500'
                      }`}>
                        <Layers size={11} className={isNight ? 'text-white' : 'text-black'} />
                        <span>Context Window</span>
                      </div>
                      <div className={`text-lg font-black font-mono ${isNight ? 'text-white' : 'text-zinc-950'}`}>{currentModel.contextWindow}</div>
                      <div className={`w-full rounded-full h-1 mt-1 ${isNight ? 'bg-neutral-800' : 'bg-zinc-200'}`}>
                        <motion.div
                          className={`h-1 rounded-full ${isNight ? 'bg-white' : 'bg-black'}`}
                          initial={{ width: 0 }}
                          animate={{ width: `${currentModel.contextPct}%` }}
                          transition={{ duration: 0.6 }}
                        />
                      </div>
                    </div>

                    {/* Metric 3: Exploit Accuracy */}
                    <div className="space-y-1">
                      <div className={`text-[10px] font-mono uppercase flex items-center gap-1 ${
                        isNight ? 'text-neutral-500' : 'text-zinc-500'
                      }`}>
                        <Activity size={11} className={isNight ? 'text-white' : 'text-black'} />
                        <span>Detection Accuracy</span>
                      </div>
                      <div className={`text-lg font-black font-mono ${isNight ? 'text-white' : 'text-zinc-950'}`}>{currentModel.accuracy}%</div>
                      <div className={`w-full rounded-full h-1 mt-1 ${isNight ? 'bg-neutral-800' : 'bg-zinc-200'}`}>
                        <motion.div
                          className={`h-1 rounded-full ${
                            isNight
                              ? 'bg-white shadow-[0_0_8px_rgba(255,255,255,0.8)]'
                              : 'bg-black shadow-[0_0_8px_rgba(0,0,0,0.5)]'
                          }`}
                          initial={{ width: 0 }}
                          animate={{ width: `${currentModel.accuracy}%` }}
                          transition={{ duration: 0.6 }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Supported Environments Badges */}
                  <div className="space-y-2">
                    <span className={`text-[10px] font-mono uppercase tracking-wider block ${
                      isNight ? 'text-neutral-400' : 'text-zinc-500'
                    }`}>
                      SUPPORTED TARGET ENVIRONMENTS &amp; TOOLHOOKS
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {currentModel.environments.map((env, i) => (
                        <span
                          key={i}
                          className={`px-2.5 py-1 rounded-lg border text-[11px] font-mono flex items-center gap-1 ${
                            isNight
                              ? 'border-white/10 bg-white/5 text-neutral-300'
                              : 'border-zinc-200 bg-zinc-100 text-zinc-800'
                          }`}
                        >
                          <CheckCircle2 size={11} className={isNight ? 'text-white' : 'text-black'} />
                          <span>{env}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right Column: Dynamic Prompt & Output Simulator */}
                <div className="lg:col-span-5 space-y-3 font-mono text-xs">
                  <div className={`p-3.5 rounded-xl border space-y-2 ${
                    isNight ? 'border-white/10 bg-black/60' : 'border-zinc-200 bg-zinc-50'
                  }`}>
                    <div className={`flex items-center justify-between text-[10px] border-b pb-2 ${
                      isNight ? 'text-neutral-400 border-white/10' : 'text-zinc-500 border-zinc-200'
                    }`}>
                      <span className={`flex items-center gap-1 font-bold ${isNight ? 'text-white' : 'text-black'}`}>
                        <Terminal size={11} />
                        <span>INFERENCE DISPATCH PROMPT</span>
                      </span>
                      <span className={`text-[9px] px-1.5 py-0.2 rounded border ${
                        isNight ? 'border-white/20 bg-white/10 text-white' : 'border-zinc-300 bg-zinc-200 text-black'
                      }`}>
                        LIVE
                      </span>
                    </div>
                    <p className={`leading-relaxed text-[11px] ${isNight ? 'text-neutral-300' : 'text-zinc-700'}`}>
                      {currentModel.samplePrompt}
                    </p>
                  </div>

                  <div className={`p-3.5 rounded-xl border space-y-2 relative overflow-hidden ${
                    isNight ? 'border-white/20 bg-white/[0.04]' : 'border-zinc-300 bg-white shadow-sm'
                  }`}>
                    <div className={`absolute top-0 right-0 w-24 h-24 rounded-full blur-2xl pointer-events-none ${
                      isNight ? 'bg-white/5' : 'bg-black/5'
                    }`} />
                    <div className={`flex items-center justify-between text-[10px] border-b pb-2 ${
                      isNight ? 'text-neutral-400 border-white/10' : 'text-zinc-500 border-zinc-200'
                    }`}>
                      <span className={`flex items-center gap-1 font-bold ${isNight ? 'text-white' : 'text-black'}`}>
                        <Sparkles size={11} />
                        <span>SYNTHESIZED REASONING OUTPUT</span>
                      </span>
                      <span className={`text-[9px] ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>0% False Positives</span>
                    </div>
                    <p className={`leading-relaxed text-[11px] font-mono ${isNight ? 'text-neutral-200' : 'text-zinc-800'}`}>
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
