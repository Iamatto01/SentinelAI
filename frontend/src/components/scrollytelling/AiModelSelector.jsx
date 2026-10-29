import React, { useState } from 'react'
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
    latencyRating: 'Fast Heuristic',
    contextWindow: '64,000 Tokens',
    contextPct: 65,
    accuracy: 99.2,
    environments: ['PostgreSQL', 'MySQL / MariaDB', 'SQLite WAL', 'MSSQL / Oracle'],
    description:
      'Automates boolean-blind, error-based, time-based, and UNION query injection testing. Uses local SQLite FTS5 RAG index of 10,000+ evasion payloads to bypass WAF heuristics safely.',
    samplePrompt: 'Test endpoint /api/search?q=1 with SQLite WAL time-delay payload to verify blind extraction.',
    sampleOutput: '[DB Attacker]: SQLite randomblob(100000000) delay confirmed. Database schema mapped. Safe proof-of-concept validated without data leakage.'
  }
]

export default function AiModelSelector() {
  const [selectedId, setSelectedId] = useState('deepseek-v4')
  const currentModel = AI_MODELS.find((m) => m.id === selectedId) || AI_MODELS[0]

  return (
    <section id="models" className="relative scroll-mt-20 py-24 sm:py-32 bg-black border-t border-white/10">
      {/* Top Volumetric Overhead Spotlight Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-96 -translate-y-1/2 opacity-25 blur-3xl z-0"
        style={{
          background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.2), transparent)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-14 sm:mb-16">
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
        </div>

        {/* Interactive Model Switcher Pills */}
        <div className="flex items-center justify-center flex-wrap gap-2 mb-10 sm:mb-12">
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
        </div>

        {/* Model Telemetry Card */}
        <SpotlightCard className="p-6 sm:p-10 border border-white/15 bg-[#080808]/90">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
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
                    <div
                      className="bg-white h-1 rounded-full transition-all duration-500"
                      style={{ width: `${currentModel.contextPct}%` }}
                    />
                  </div>
                </div>

                {/* Metric 3: Detection Accuracy */}
                <div className="space-y-1 col-span-2 sm:col-span-1">
                  <div className="text-[10px] font-mono text-neutral-500 uppercase flex items-center gap-1">
                    <ShieldCheck size={11} className="text-white" />
                    <span>Exploit Accuracy</span>
                  </div>
                  <div className="text-lg font-black text-white font-mono">{currentModel.accuracy}%</div>
                  <div className="w-full bg-neutral-800 rounded-full h-1 mt-1">
                    <div
                      className="bg-white h-1 rounded-full transition-all duration-500"
                      style={{ width: `${currentModel.accuracy}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Supported Target Environments */}
              <div className="space-y-2">
                <div className="text-[11px] font-mono uppercase tracking-wider text-neutral-400">
                  Supported Target Environments:
                </div>
                <div className="flex flex-wrap gap-2">
                  {currentModel.environments.map((env, i) => (
                    <span
                      key={i}
                      className="px-3 py-1 rounded-lg border border-white/10 bg-white/5 text-neutral-300 text-xs font-mono flex items-center gap-1.5"
                    >
                      <CheckCircle2 size={12} className="text-white" />
                      <span>{env}</span>
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Column: Interactive Prompt & Inference Stream */}
            <div className="lg:col-span-5 rounded-xl border border-white/10 bg-black/80 p-5 space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <span className="text-[10px] text-neutral-400 uppercase tracking-widest font-bold">
                  LIVE INFERENCE TELEMETRY
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-white border border-white/20">
                  ACTIVE
                </span>
              </div>

              <div className="space-y-2">
                <div className="text-[10px] text-neutral-500 uppercase">Input Payload / Staged Prompt:</div>
                <div className="p-3 rounded-lg bg-neutral-950 border border-white/5 text-neutral-300 text-[11px] leading-relaxed">
                  {currentModel.samplePrompt}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-[10px] text-neutral-500 uppercase flex items-center justify-between">
                  <span>Verified Agent Response:</span>
                  <span className="text-white flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                    Consensus 100%
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-neutral-950 border border-white/10 text-white text-[11px] leading-relaxed">
                  {currentModel.sampleOutput}
                </div>
              </div>

              <div className="pt-2 border-t border-white/10 flex items-center justify-between text-[10px] text-neutral-500">
                <span>Multi-LLM Arbiter: ENABLED</span>
                <span className="text-neutral-400">0.00% False Positive Rate</span>
              </div>
            </div>
          </div>
        </SpotlightCard>
      </div>
    </section>
  )
}
