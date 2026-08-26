import React, { useEffect, useRef, useState } from 'react'
import mermaid from 'mermaid'
import { Workflow, ShieldCheck, Cpu, Layers, Sparkles } from 'lucide-react'

const DIAGRAMS = {
  pipeline: {
    id: 'pipeline',
    label: 'End-to-End Execution Pipeline',
    icon: Workflow,
    desc: 'Target Ingestion → Express Gateway → Hexstrike Kali Engine → AI Consensus → Local WAL DB',
    code: `graph TD
    %% 1. Ingestion Layer
    subgraph Ingestion["🌐 1. Target Ingestion & Triggers"]
        A1["🎯 Target URL / IP Scan Submission"]
        A2["🐙 GitHub Push / PR Webhooks"]
        A3["🛡️ CIDR & Domain Scope Validator"]
    end

    %% 2. Express Gateway
    subgraph Gateway["🔐 2. Express API Gateway & Quota"]
        B1["🔑 JWT 12h Token Auth & RBAC Isolation"]
        B2["💳 Quota Gatekeeper: 3 Free Scans / Pro / Enterprise"]
        B3["⚡ Rate Limiting & Target Sanitization"]
    end

    %% 3. Hexstrike Kali Engine
    subgraph Kali["⚡ 3. Hexstrike Kali Engine (:8888)"]
        C1["🔍 Phase 1: Recon - Nmap, Subfinder, Katana"]
        C2["🎯 Phase 2: DAST Dynamic Web - Nuclei, Nikto, SQLMap, FFUF"]
        C3["💻 Phase 3: SAST Static Code - AST Parser (JS, Py, PHP, Java)"]
        C4["⚔️ Phase 4: Exploitation - Metasploit RPC PoC Engine"]
    end

    %% 4. AI Verification
    subgraph AI["🧠 4. Multi-LLM Consensus AI"]
        D1["🤖 51 Specialist Personas (Web Hunter, DB Attacker)"]
        D2["📚 PayloadsAllTheThings RAG FTS5 (10k+ PoC Index)"]
        D3["⚖️ Multi-LLM Consensus (Groq / DeepSeek / OpenRouter)"]
        D4["✨ 0% False-Positive Suppression Filter"]
    end

    %% 5. Local Storage & Report
    subgraph Storage["📄 5. Local Storage & Executive Reports"]
        E1["🗄️ SQLite WAL Local-First Database"]
        E2["📑 Automated PDF Report with CVSS & Business Impact"]
        E3["📡 Real-Time WebSocket Telemetry Stream"]
    end

    A1 --> A3
    A2 --> A3
    A3 --> B1
    B1 --> B2
    B2 --> B3
    B3 --> C1

    C1 --> C2
    C1 --> C3
    C2 --> C4
    C2 --> D1
    C3 --> D1
    C4 --> D1

    D1 --> D2
    D2 --> D3
    D3 --> D4

    D4 --> E1
    E1 --> E2
    E1 --> E3

    E2 --> UI["🖥️ SentinelAI Dashboard & Remediation Hub"]
    E3 --> UI`
  },
  dast_sast: {
    id: 'dast_sast',
    label: 'DAST vs SAST Dual-Engine Flow',
    icon: ShieldCheck,
    desc: 'Dynamic Blackbox Live Probing vs Static Whitebox AST Code Audit',
    code: `graph LR
    subgraph DAST_Engine["🎯 DAST Dynamic Analysis (Blackbox)"]
        D_In["Target Web URL / REST API"]
        D_Recon["1. Recon: Katana & Subfinder"]
        D_Vuln["2. Nuclei YAML Templates & Nikto"]
        D_Fuzz["3. SQLMap Injection & FFUF Fuzzing"]
        D_Out["DAST Raw Findings"]
        D_In --> D_Recon --> D_Vuln --> D_Fuzz --> D_Out
    end

    subgraph SAST_Engine["💻 SAST Static Analysis (Whitebox)"]
        S_In["Repository Source Code / GitHub PR"]
        S_AST["1. AST Multi-Language Parser"]
        S_Rules["2. OWASP Top 10 Security Rules"]
        S_Taint["3. Source-to-Sink Taint Tracking"]
        S_Out["SAST Raw Findings"]
        S_In --> S_AST --> S_Rules --> S_Taint --> S_Out
    end

    subgraph AI_Consensus["🧠 Multi-LLM Consensus Triangulation"]
        Agent["51 Specialist AI Personas"]
        RAG["RAG Exploit Knowledge Base"]
        LLM["Multi-LLM Agreement Gating"]
        Gated["Verified Zero-Noise Report"]
        Agent --> RAG --> LLM --> Gated
    end

    D_Out --> Agent
    S_Out --> Agent`
  },
  ai_engine: {
    id: 'ai_engine',
    label: 'Multi-LLM Consensus & RAG Engine',
    icon: Cpu,
    desc: 'How Groq, DeepSeek, OpenRouter & PayloadsAllTheThings eliminate false positives',
    code: `graph TD
    Raw["Raw Kali Tool Output (Nmap / Nuclei / SQLMap / AST)"]
    Persona["Specialist AI Persona Selection (e.g. SQL Injection Analyst)"]
    RAG["PayloadsAllTheThings Local FTS5 Vector Search"]

    LLM1["Model 1: DeepSeek V3 (Deep Reasoning)"]
    LLM2["Model 2: Groq LLaMA 3.3 (High Speed Triangulation)"]
    LLM3["Model 3: OpenRouter Multi-Model Verify"]

    Vote["Consensus Gating Logic (>= 2/3 Multi-LLM Confidence)"]
    Accepted["✅ Confirmed Finding + Automated AI Fix Diff"]
    Discarded["❌ False Positive Suppressed (0% Noise)"]

    Raw --> Persona
    Persona --> RAG
    RAG --> LLM1 & LLM2 & LLM3
    LLM1 & LLM2 & LLM3 --> Vote
    Vote -->|Consensus Reached| Accepted
    Vote -->|Inconclusive/Noise| Discarded`
  }
}

let mermaidInitialized = false

function ensureMermaidInit() {
  if (!mermaidInitialized) {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'dark',
      darkMode: true,
      securityLevel: 'loose',
      themeVariables: {
        primaryColor: '#0b1437',
        primaryTextColor: '#f1f5f9',
        primaryBorderColor: '#00f2fe',
        lineColor: '#38bdf8',
        secondaryColor: '#0c1a40',
        tertiaryColor: '#060b26',
        fontSize: '12px',
        fontFamily: 'Bricolage Grotesque, system-ui, sans-serif'
      },
      flowchart: { curve: 'basis', useMaxWidth: true },
    })
    mermaidInitialized = true
  }
}

export default function MermaidDiagram() {
  const [activeTab, setActiveTab] = useState('pipeline')
  const containerRef = useRef(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    const id = 'mermaid-flow-' + Math.random().toString(36).slice(2, 9)

    async function render() {
      setLoading(true)
      setError(null)
      try {
        ensureMermaidInit()
        const selectedCode = DIAGRAMS[activeTab].code
        const { svg } = await mermaid.render(id, selectedCode)
        if (!cancelled && containerRef.current) {
          containerRef.current.innerHTML = svg
        }
      } catch (e) {
        console.error('Mermaid render error:', e)
        if (!cancelled) setError(e.message || String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    render()
    return () => { cancelled = true }
  }, [activeTab])

  return (
    <div className="space-y-4">
      {/* Sub-tab switcher */}
      <div className="flex flex-wrap items-center justify-center gap-2">
        {Object.values(DIAGRAMS).map((d) => {
          const Icon = d.icon
          const isActive = activeTab === d.id
          return (
            <button
              key={d.id}
              onClick={() => setActiveTab(d.id)}
              className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 shadow-[0_0_15px_rgba(0,242,254,0.2)]'
                  : 'bg-white/5 text-slate-400 border border-white/10 hover:bg-white/10 hover:text-slate-200'
              }`}
            >
              <Icon size={14} className={isActive ? 'text-cyan-400' : 'text-slate-400'} />
              <span>{d.label}</span>
            </button>
          )
        })}
      </div>

      <p className="text-xs text-center text-slate-400 font-mono">
        {DIAGRAMS[activeTab].desc}
      </p>

      {/* Render Canvas */}
      <div
        className="relative min-h-[360px] p-4 sm:p-8 rounded-3xl overflow-x-auto [&_svg]:mx-auto [&_svg]:max-w-full"
        style={{
          background: 'rgba(6, 11, 38, 0.65)',
          backdropFilter: 'blur(40px) saturate(180%)',
          WebkitBackdropFilter: 'blur(40px) saturate(180%)',
          border: '1px solid rgba(0, 242, 254, 0.2)',
          boxShadow: '0 16px 48px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.08)',
        }}
      >
        {error ? (
          <div className="p-6 rounded-2xl border border-rose-500/30 bg-slate-950/70 text-center">
            <p className="text-xs text-rose-400 font-mono">Failed to render diagram: {error}</p>
          </div>
        ) : (
          <div ref={containerRef} className="w-full flex justify-center" />
        )}
      </div>
    </div>
  )
}
