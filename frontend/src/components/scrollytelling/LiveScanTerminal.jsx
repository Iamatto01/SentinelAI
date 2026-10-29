import React, { useState, useEffect, useRef } from 'react'
import { motion, useScroll, useSpring, AnimatePresence } from 'framer-motion'
import {
  Terminal, ShieldAlert, Cpu, Sparkles, CheckCircle2, ChevronRight,
  Code2, Bug, FileJson, Copy, Check, Play, RefreshCw, Zap
} from 'lucide-react'
import SpotlightCard from './SpotlightCard.jsx'

const STAGES = [
  {
    id: 1,
    num: '01',
    name: 'Autonomous Reconnaissance',
    headline: 'Subdomain Enumeration & Shadow Asset Discovery',
    description:
      'The Native Kali Engine kicks off asynchronous OSINT harvesting, non-intrusive DNS brute-forcing, and high-speed port probing to map the target attack perimeter in seconds.',
    kaliTools: ['Nmap', 'Subfinder', 'Katana', 'Masscan', 'WhatWeb'],
    metrics: [
      { label: 'Surface Assets Found', val: '24 Endpoints' },
      { label: 'Open Service Ports', val: '80, 443, 8080, 8443' },
      { label: 'Scan Time Elapsed', val: '1.42s' },
    ],
    cliLines: [
      { type: 'cmd', text: '$ sentinel-recon --target https://demo.sentinelai.studio --deep' },
      { type: 'stdout', text: '[*] Initializing Kali Engine subprocess daemon PID 4821...' },
      { type: 'stdout', text: '[+] Subfinder discovered 6 active subdomains via passive DNS' },
      { type: 'stdout', text: '    -> api.demo.sentinelai.studio [192.168.68.132]' },
      { type: 'stdout', text: '    -> staging.demo.sentinelai.studio [192.168.68.133]' },
      { type: 'stdout', text: '    -> vault-internal.sentinelai.studio:8443 [PROTECTED]' },
      { type: 'stdout', text: '[+] Nmap SYN Stealth Scan: 4 open TCP ports identified (0.84s)' },
      { type: 'stdout', text: '    -> 80/tcp   OPEN  nginx/1.24.0 (Ubuntu)' },
      { type: 'stdout', text: '    -> 443/tcp  OPEN  OpenSSL 3.0.2 / TLS 1.3' },
      { type: 'stdout', text: '    -> 8080/tcp OPEN  Node.js Express Gateway v4.19' },
      { type: 'success', text: '[✓] Recon Stage 01 complete: Attack graph topology generated' },
    ],
    payloadView: `// [RECON CONFIGURATION & TARGET SPECIFICATION]
{
  "target": "demo.sentinelai.studio",
  "scope_validation": "STRICT_CIDR_MATCH (192.168.68.0/24)",
  "active_probes": ["dns_brute", "katana_crawl", "nmap_syn_stealth"],
  "threads": 64,
  "rate_limit_rps": 120,
  "fingerprint": {
    "web_server": "nginx/1.24.0",
    "reverse_proxy": "Node.js Express",
    "waf_bypass": "None detected"
  }
}`,
    jsonTelemetry: {
      stage: '01_RECONNAISSANCE',
      status: 'COMPLETED',
      execution_time_ms: 1420,
      target_ip: '192.168.68.132',
      discovered_hosts: [
        'api.demo.sentinelai.studio',
        'staging.demo.sentinelai.studio',
        'vault-internal.sentinelai.studio:8443'
      ],
      open_ports: [80, 443, 8080, 8443],
      attack_surface_score: '84.2/100',
      active_kali_daemons: ['subfinder', 'nmap', 'katana']
    }
  },
  {
    id: 2,
    num: '02',
    name: 'AI Exploit Simulation',
    headline: 'Zero-Day Payload Crafting & Vector Probing',
    description:
      'AI specialist personas (Web Hunter & Database Attacker) construct surgical exploit chains using PayloadsAllTheThings RAG intelligence, executing controlled proof-of-concept tests.',
    kaliTools: ['Nuclei', 'SQLMap', 'FFUF', 'Nikto', 'Metasploit RPC'],
    metrics: [
      { label: 'Vulnerability Match', val: 'CVE-2024-27198' },
      { label: 'CVSS v3.1 Severity', val: '9.8 CRITICAL' },
      { label: 'Exploit Vector', val: 'Auth Bypass (RCE)' },
    ],
    cliLines: [
      { type: 'cmd', text: '$ sentinel-exploit --target api.demo.sentinelai.studio --rag' },
      { type: 'stdout', text: '[*] Fetching 10,000+ curated payloads from SQLite FTS5 RAG...' },
      { type: 'stdout', text: '[*] Persona #07 "Database Attacker" testing parameter /api/search?q=' },
      { type: 'stdout', text: '[+] Time-based Boolean Blind heuristic detected SQL injection flaw' },
      { type: 'stdout', text: '[*] Persona #01 "Web Hunter" probing auth endpoint /api/v1/setup...' },
      { type: 'alert', text: '[!] [CRITICAL // CVSS 9.8] CVE-2024-27198 Authentication Bypass' },
      { type: 'stdout', text: '    -> Request: POST /api/v1/setup/authBypass HTTP/1.1' },
      { type: 'stdout', text: '    -> Response: 200 OK (Root session token returned: eyJhbGciOi...)' },
      { type: 'stdout', text: '[*] Metasploit RPC: Controlled read-only PoC validated' },
      { type: 'success', text: '[✓] Exploit confirmed: Zero human fatigue, 100% verified PoC' },
    ],
    payloadView: `POST /api/v1/setup/authBypass HTTP/1.1
Host: api.demo.sentinelai.studio
User-Agent: SentinelAI-Offensive-Mesh/2.4
Content-Type: application/json
X-Requested-With: XMLHttpRequest

{
  "__proto__": {
    "admin": true,
    "role": "cluster-admin",
    "verified_poc": "SENTINEL-AI-AUTOMATED-VERIFICATION"
  },
  "auth_token": "bearer_bypass_cve_2024_27198",
  "sqli_vector": "1' UNION SELECT 1, @@version, user(), database() -- -"
}`,
    jsonTelemetry: {
      stage: '02_EXPLOIT_SIMULATION',
      status: 'VULNERABILITY_CONFIRMED',
      cve_id: 'CVE-2024-27198',
      cvss_score: 9.8,
      severity: 'CRITICAL',
      cwe_code: 'CWE-287 / CWE-89',
      exploit_verified_by: 'Persona #01 (Web Hunter) + DeepSeek-V4',
      false_positive_probability: '0.001%',
      rag_payload_origin: 'PayloadsAllTheThings/AuthenticationBypass.md',
      safety_approval_gate: 'PASSED_SAFE_READONLY'
    }
  },
  {
    id: 3,
    num: '03',
    name: 'Vulnerability Mapping & Auto-Patching',
    headline: 'CVSS Scoring, Dependency Topology & Auto-Remediation',
    description:
      'Multi-LLM consensus (Groq, DeepSeek, OpenRouter) filters all scan noise, evaluates exact CVSS risk exposure, and generates instantaneous git diff code patches ready for pull request merge.',
    kaliTools: ['AST Static Parser', 'PDFKit Report', 'Octokit PR Bot', 'Discord/Telegram'],
    metrics: [
      { label: 'False Positives', val: '0 (100% Filtered)' },
      { label: 'Auto-Fix Patch', val: 'Git Diff Ready' },
      { label: 'Executive Report', val: 'PDF Generated' },
    ],
    cliLines: [
      { type: 'cmd', text: '$ sentinel-remediate --generate-patch --report=executive' },
      { type: 'stdout', text: '[*] Staging Multi-LLM Consensus Engine (Groq 70B + DeepSeek V4)...' },
      { type: 'stdout', text: '[+] Noise suppression: 18 raw tool alerts pruned as non-exploitable' },
      { type: 'stdout', text: '[+] AST Parser evaluated /src/middleware/auth.js: line 42 vulnerable' },
      { type: 'success', text: '[✓] Context-aware Git Diff synthesized (secure JWT verification)' },
      { type: 'stdout', text: '[*] Compiling Executive Audit PDF with CVSS 3.1 vector matrix...' },
      { type: 'stdout', text: '[+] Dispatching real-time notifications to Telegram & Discord' },
      { type: 'stdout', text: '[+] Octokit PR Bot: Security review comment posted on GitHub PR #14' },
      { type: 'success', text: '[✓] Pipeline complete in 3.42s total execution time' },
    ],
    payloadView: `--- a/src/middleware/auth.js
+++ b/src/middleware/auth.js
@@ -39,7 +39,11 @@ export function verifyToken(req, res, next) {
-  // VULNERABLE: Insecure algorithm confusion & missing signature check
-  const decoded = jwt.decode(token);
-  req.user = decoded;
-  return next();
+  // AUTO-PATCHED BY SENTINELAI: Strict RS256 algorithm enforcement & secret validation
   try {
     const verified = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['RS256', 'HS256'] });
     req.user = verified;
     return next();
   } catch (err) {
     return res.status(401).json({ error: 'UNAUTHORIZED_OR_MALFORMED_JWT' });
   }`,
    jsonTelemetry: {
      stage: '03_AUTO_PATCH_AND_DELIVERY',
      status: 'REMEDIATION_READY',
      remediation_type: 'UNIFIED_GIT_DIFF',
      compliance_impact: {
        owasp_2025: 'A01:2021-Broken Access Control (MITIGATED)',
        soc2_type2: 'CC6.1 Logical Access Controls (COMPLIANT)',
        iso27001: 'A.12.6.1 Technical Vulnerability Management'
      },
      octokit_pr_bot: 'AUTOMATED_COMMENT_POSTED',
      pdf_report_pages: 14,
      total_duration_sec: 3.42
    }
  }
]

export default function LiveScanTerminal() {
  const [activeStage, setActiveStage] = useState(1)
  const [activeTab, setActiveTab] = useState('cli')
  const [copied, setCopied] = useState(false)
  const [visibleLinesCount, setVisibleLinesCount] = useState(2)

  const sectionRef = useRef(null)
  const stageRefs = [useRef(null), useRef(null), useRef(null)]

  const currentStageData = STAGES.find((s) => s.id === activeStage) || STAGES[0]

  // Track scroll progress along the stage section
  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start center', 'end center'],
  })
  const scaleY = useSpring(scrollYProgress, { stiffness: 100, damping: 20 })

  // Intersection observer to track active stage
  useEffect(() => {
    const observers = stageRefs.map((ref, idx) => {
      if (!ref.current) return null
      const obs = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              setActiveStage(idx + 1)
            }
          })
        },
        { threshold: 0.55 }
      )
      obs.observe(ref.current)
      return obs
    })

    return () => {
      observers.forEach((obs) => obs && obs.disconnect())
    }
  }, [])

  // Real Typewriter animation that streams CLI lines sequentially
  useEffect(() => {
    setVisibleLinesCount(1)
    const totalLines = currentStageData.cliLines.length

    const interval = setInterval(() => {
      setVisibleLinesCount((prev) => {
        if (prev < totalLines) {
          return prev + 1
        }
        clearInterval(interval)
        return prev
      })
    }, 180)

    return () => clearInterval(interval)
  }, [activeStage])

  const handleCopy = (text) => {
    navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section
      id="terminal"
      ref={sectionRef}
      className="relative scroll-mt-20 py-28 sm:py-36 bg-black border-t border-white/10"
    >
      {/* Volumetric Overhead Spotlight Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-[500px] -translate-y-1/2 opacity-30 blur-3xl z-0"
        style={{
          background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.25), transparent)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Animated Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-3xl mx-auto space-y-4 mb-20 sm:mb-24"
        >
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-white/15 bg-white/[0.04] text-[11px] font-mono text-neutral-300">
            <Terminal size={13} className="text-white" />
            <span className="font-bold uppercase tracking-wider">
              REAL-TIME EXECUTION PIPELINE // STICKY SCROLL TERMINAL
            </span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight font-sans">
            From Blackbox URL to <br />
            <span className="bg-gradient-to-b from-white via-neutral-200 to-neutral-500 bg-clip-text text-transparent">
              Verified Exploit &amp; Auto-Fix Patch
            </span>
          </h2>

          <p className="text-sm sm:text-base text-neutral-400 font-sans leading-relaxed">
            Scroll through our 3-stage autonomous offensive pipeline. Watch the terminal dynamically type
            subprocess stdout, craft exploit payloads, and synthesize git diff patches in real-time.
          </p>
        </motion.div>

        {/* 2-Column Split Screen Container */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-14 items-start relative min-h-[160vh]">
          {/* Left Column: Scroll-Driven Narrative Stages with Laser Connector Line */}
          <div className="lg:col-span-6 relative space-y-20 sm:space-y-28 py-4">
            {/* Vertical Laser Progress Line Connecting Stages */}
            <div className="absolute left-8 top-12 bottom-12 w-[1px] bg-white/10 hidden sm:block">
              <motion.div
                className="w-[2px] bg-white origin-top shadow-[0_0_12px_rgba(255,255,255,1)]"
                style={{ scaleY, height: '100%' }}
              />
            </div>

            {STAGES.map((stage, idx) => {
              const isActive = activeStage === stage.id

              return (
                <motion.div
                  key={stage.id}
                  ref={stageRefs[idx]}
                  onClick={() => setActiveStage(stage.id)}
                  initial={{ opacity: 0, x: -40, scale: 0.96 }}
                  whileInView={{ opacity: 1, x: 0, scale: 1 }}
                  viewport={{ once: false, amount: 0.3 }}
                  transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                  className={`p-6 sm:p-8 rounded-3xl border transition-all duration-500 cursor-pointer relative ${
                    isActive
                      ? 'border-white/50 bg-[#0E0E0E] shadow-[0_0_40px_rgba(255,255,255,0.12)] scale-[1.02] ring-1 ring-white/30'
                      : 'border-white/10 bg-[#060606]/70 opacity-60 hover:opacity-95 hover:border-white/20'
                  }`}
                >
                  {/* Glowing Node Pip connecting to laser line */}
                  <div
                    className={`absolute -left-[37px] top-8 hidden sm:flex items-center justify-center rounded-full transition-all duration-300 ${
                      isActive
                        ? 'w-5 h-5 bg-white shadow-[0_0_16px_rgba(255,255,255,1)] ring-4 ring-white/20'
                        : 'w-3.5 h-3.5 bg-neutral-700'
                    }`}
                  >
                    {isActive && <div className="w-1.5 h-1.5 rounded-full bg-black" />}
                  </div>

                  <div className="flex items-center justify-between mb-4">
                    <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-white text-black">
                      STAGE {stage.num}
                    </span>
                    <span className="text-xs font-mono text-neutral-400">
                      {stage.kaliTools.join(' • ')}
                    </span>
                  </div>

                  <h3 className="text-xl sm:text-2xl font-bold text-white mb-2 font-sans tracking-tight">
                    {stage.headline}
                  </h3>

                  <p className="text-xs sm:text-sm text-neutral-400 leading-relaxed font-sans mb-6">
                    {stage.description}
                  </p>

                  {/* Stage Metrics Grid */}
                  <div className="grid grid-cols-3 gap-2 p-3 rounded-xl bg-black/60 border border-white/10 mb-4">
                    {stage.metrics.map((m, i) => (
                      <div key={i} className="text-center font-mono">
                        <div className="text-[10px] text-neutral-500 uppercase">{m.label}</div>
                        <div className="text-xs sm:text-sm font-bold text-white mt-0.5">{m.val}</div>
                      </div>
                    ))}
                  </div>

                  <div className="flex items-center justify-between pt-2 text-[11px] font-mono text-neutral-400">
                    <span className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          isActive ? 'bg-white animate-pulse shadow-[0_0_8px_rgba(255,255,255,0.9)]' : 'bg-neutral-600'
                        }`}
                      />
                      {isActive ? 'Active Telemetry Stream' : 'Click to Focus Stage'}
                    </span>
                    <ChevronRight size={14} className={isActive ? 'translate-x-1 transition-transform text-white' : ''} />
                  </div>
                </motion.div>
              )
            })}
          </div>

          {/* Right Column: Sticky Interactive Terminal & Telemetry with Typewriter stdout */}
          <div className="lg:col-span-6 sticky top-24 self-start">
            <motion.div
              initial={{ opacity: 0, x: 50, scale: 0.95 }}
              whileInView={{ opacity: 1, x: 0, scale: 1 }}
              viewport={{ once: true, amount: 0.15 }}
              transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
              className="rounded-2xl border border-white/20 bg-[#080808]/95 backdrop-blur-2xl shadow-[0_25px_60px_rgba(0,0,0,0.95),0_0_35px_rgba(255,255,255,0.08)] overflow-hidden font-mono"
            >
              {/* Terminal Window Header */}
              <div className="px-4 py-3 bg-neutral-950 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-white/90 inline-block shadow-[0_0_8px_rgba(255,255,255,0.6)]" />
                  <span className="w-3 h-3 rounded-full bg-neutral-400 inline-block" />
                  <span className="w-3 h-3 rounded-full bg-neutral-700 inline-block" />
                  <span className="ml-2 text-xs font-semibold text-neutral-300 hidden sm:inline">
                    kali@sentinelai: ~/engine/stage-0{activeStage}
                  </span>
                </div>

                {/* View Switcher Tabs */}
                <div className="flex items-center gap-1 p-0.5 rounded-lg border border-white/10 bg-black/60">
                  <button
                    type="button"
                    onClick={() => setActiveTab('cli')}
                    className={`px-2.5 py-1 rounded text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                      activeTab === 'cli' ? 'bg-white text-black shadow' : 'text-neutral-400 hover:text-white'
                    }`}
                  >
                    <Terminal size={11} />
                    <span>CLI</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('payload')}
                    className={`px-2.5 py-1 rounded text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                      activeTab === 'payload' ? 'bg-white text-black shadow' : 'text-neutral-400 hover:text-white'
                    }`}
                  >
                    <Code2 size={11} />
                    <span>Payload</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setActiveTab('json')}
                    className={`px-2.5 py-1 rounded text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                      activeTab === 'json' ? 'bg-white text-black shadow' : 'text-neutral-400 hover:text-white'
                    }`}
                  >
                    <FileJson size={11} />
                    <span>JSON</span>
                  </button>
                </div>
              </div>

              {/* Terminal Screen Body with Sequential Typewriter Streaming */}
              <div className="p-5 h-[430px] overflow-y-auto text-xs leading-relaxed space-y-2 bg-black/90">
                {activeTab === 'cli' && (
                  <div className="space-y-2">
                    <div className="text-[11px] text-neutral-500 pb-2 border-b border-white/10 flex items-center justify-between">
                      <span>SESSION: DAEMON_STREAM_PID_{3400 + activeStage * 12}</span>
                      <span className="flex items-center gap-1.5 text-white">
                        <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                        STREAMING ACTIVE
                      </span>
                    </div>

                    {currentStageData.cliLines.slice(0, visibleLinesCount).map((line, i) => {
                      if (line.type === 'cmd') {
                        return (
                          <div key={i} className="text-white font-bold pt-1 flex items-center gap-2">
                            <span className="text-neutral-500">&gt;</span>
                            <span>{line.text}</span>
                          </div>
                        )
                      }
                      if (line.type === 'alert') {
                        return (
                          <motion.div
                            key={i}
                            initial={{ scale: 0.95, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            transition={{ type: 'spring', stiffness: 200, damping: 15 }}
                            className="p-2.5 rounded-lg border-2 border-white bg-white/15 text-white font-black shadow-[0_0_20px_rgba(255,255,255,0.25)]"
                          >
                            {line.text}
                          </motion.div>
                        )
                      }
                      if (line.type === 'success') {
                        return (
                          <div key={i} className="text-white font-semibold flex items-center gap-1.5">
                            <CheckCircle2 size={14} className="text-white" />
                            <span>{line.text}</span>
                          </div>
                        )
                      }
                      return (
                        <div key={i} className="text-neutral-400 pl-4 border-l border-white/10">
                          {line.text}
                        </div>
                      )
                    })}

                    <div className="pt-3 text-neutral-500 flex items-center gap-2">
                      <span className="inline-block w-2 h-4 bg-white animate-pulse" />
                      <span>{visibleLinesCount < currentStageData.cliLines.length ? 'Synthesizing output...' : 'Awaiting next instruction...'}</span>
                    </div>
                  </div>
                )}

                {activeTab === 'payload' && (
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => handleCopy(currentStageData.payloadView)}
                      className="absolute top-0 right-0 p-1.5 rounded-lg border border-white/15 bg-white/5 text-neutral-300 hover:text-white hover:bg-white/10 text-xs flex items-center gap-1 cursor-pointer"
                      title="Copy payload"
                    >
                      {copied ? <Check size={12} className="text-white" /> : <Copy size={12} />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                    <pre className="text-[11px] text-neutral-300 font-mono whitespace-pre overflow-x-auto pr-16">
                      {currentStageData.payloadView}
                    </pre>
                  </div>
                )}

                {activeTab === 'json' && (
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => handleCopy(currentStageData.jsonTelemetry)}
                      className="absolute top-0 right-0 p-1.5 rounded-lg border border-white/15 bg-white/5 text-neutral-300 hover:text-white hover:bg-white/10 text-xs flex items-center gap-1 cursor-pointer"
                      title="Copy JSON"
                    >
                      {copied ? <Check size={12} className="text-white" /> : <Copy size={12} />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                    <pre className="text-[11px] text-neutral-300 font-mono whitespace-pre overflow-x-auto pr-16">
                      {JSON.stringify(currentStageData.jsonTelemetry, null, 2)}
                    </pre>
                  </div>
                )}
              </div>

              {/* Terminal Footer Telemetry */}
              <div className="px-4 py-2.5 bg-neutral-950 border-t border-white/10 flex items-center justify-between text-[11px] text-neutral-400">
                <span className="flex items-center gap-1.5">
                  <Cpu size={12} className="text-white" />
                  <span>Daemon Status: Subprocess Ready</span>
                </span>
                <span className="text-white font-mono">Stage 0{activeStage} / 03</span>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}
