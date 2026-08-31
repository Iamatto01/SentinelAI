import React, { useState } from 'react'
import { Network, Workflow, GitCommit, Database, RefreshCw, ExternalLink, Download, Layers, ShieldCheck, Sparkles, Maximize2 } from 'lucide-react'

export default function ArchitectureViewer() {
  const [activeTab, setActiveTab] = useState('architecture')

  const diagrams = [
    {
      id: 'architecture',
      title: '01. Enterprise System Architecture',
      subtitle: 'Complete physical topology & service orchestration',
      icon: Network,
      file: '/diagrams/sentinelai-architecture.html',
      badge: 'Topology',
      color: 'from-cyan-500 to-blue-600',
      description: 'Visualizes the relationship between the Vite React frontend, Cloudflare Zero-Trust WAF, Express Core (:5000), 53 AI Consensus Engine, Hexstrike FastMCP server (:8888), and 150+ native Kali Linux security binaries.'
    },
    {
      id: 'workflow',
      title: '02. Autonomous Pentest Workflow',
      subtitle: 'End-to-end multi-stage pipeline flow',
      icon: Workflow,
      file: '/diagrams/sentinelai-workflow.html',
      badge: 'Pipeline',
      color: 'from-emerald-500 to-teal-600',
      description: 'Follows an autonomous security scan from initial analyst trigger, through ScopeGuard whitelist approval, active Kali DAST fuzzing, PayloadsAllTheThings RAG enrichment, to AI multi-model consensus.'
    },
    {
      id: 'sequence',
      title: '03. Real-Time Scan Sequence',
      subtitle: 'Sub-second WebSocket & CLI process trace',
      icon: GitCommit,
      file: '/diagrams/sentinelai-sequence.html',
      badge: 'Sequence',
      color: 'from-purple-500 to-indigo-600',
      description: 'Illustrates sub-second WebSocket room subscriptions, asynchronous child_process spawning on Kali Linux, live stdout chunk streaming, and Telegram / Discord alert dispatching.'
    },
    {
      id: 'dataflow',
      title: '04. Security Intelligence Dataflow',
      subtitle: 'Raw telemetry ingestion & AST patch generation',
      icon: Database,
      file: '/diagrams/sentinelai-dataflow.html',
      badge: 'Data Pipeline',
      color: 'from-amber-500 to-orange-600',
      description: 'Details the transformation of raw scan stdout streams, automated CWE / OWASP classification, PayloadsAllTheThings vector matching, and executive PDF audit report compilation.'
    },
    {
      id: 'lifecycle',
      title: '05. Scan & Finding Lifecycle Machine',
      subtitle: 'Cooperative pause & self-healing retry machine',
      icon: RefreshCw,
      file: '/diagrams/sentinelai-lifecycle.html',
      badge: 'State Machine',
      color: 'from-rose-500 to-pink-600',
      description: 'Represents the 5 primary lifecycle states (Queued, Recon, Scanning, Verifying, Completed) along with cooperative operator pause states, active exploit approval gates, and self-healing retry loops.'
    }
  ]

  const currentDiagram = diagrams.find(d => d.id === activeTab) || diagrams[0]

  return (
    <div className="space-y-6 motion-fade-up pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase font-bold px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
              Archify v2.16 Engine
            </span>
            <span className="text-[10px] font-mono uppercase font-bold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              Showcase Quality Verified
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            System Architecture & Workflows
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Interactive, standalone architecture specifications rendered with pure SVG, motion tracing, dark/light themes, and high-resolution export.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href={currentDiagram.file}
            target="_blank"
            rel="noreferrer"
            className="btn-secondary text-xs flex items-center gap-1.5"
          >
            <Maximize2 size={14} /> Fullscreen
          </a>
          <a
            href="/diagrams/index.html"
            target="_blank"
            rel="noreferrer"
            className="btn-primary text-xs flex items-center gap-1.5"
          >
            <ExternalLink size={14} /> Master Hub
          </a>
        </div>
      </div>

      {/* Diagram Selector Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {diagrams.map((d) => {
          const Icon = d.icon
          const isActive = activeTab === d.id
          return (
            <button
              key={d.id}
              type="button"
              onClick={() => setActiveTab(d.id)}
              className={`p-3.5 rounded-2xl border text-left transition-all flex flex-col justify-between gap-3 cursor-pointer ${
                isActive
                  ? 'border-cyan-400 bg-slate-900/90 shadow-[0_0_20px_rgba(0,242,254,0.25)] ring-1 ring-cyan-400/50'
                  : 'border-white/10 bg-slate-950/60 hover:border-white/30 hover:bg-slate-900/50'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className={`p-2 rounded-xl bg-gradient-to-br ${d.color} text-white shadow-md`}>
                  <Icon size={16} />
                </div>
                <span className={`text-[10px] font-mono uppercase font-bold px-1.5 py-0.5 rounded ${
                  isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-white/5 text-slate-400'
                }`}>
                  {d.badge}
                </span>
              </div>
              <div>
                <h3 className="text-xs font-bold text-white line-clamp-1">{d.title.replace(/^\d+\.\s*/, '')}</h3>
                <p className="text-[10px] text-slate-400 line-clamp-1 mt-0.5">{d.subtitle}</p>
              </div>
            </button>
          )
        })}
      </div>

      {/* Active Diagram Viewer Frame */}
      <div className="card p-4 border-cyan-500/30 bg-slate-950 shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/10">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Sparkles size={16} className="text-cyan-400" />
              {currentDiagram.title}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {currentDiagram.description}
            </p>
          </div>
          <div className="text-[11px] text-cyan-300 font-mono flex items-center gap-2 self-start sm:self-auto bg-cyan-950/40 px-3 py-1.5 rounded-xl border border-cyan-500/30">
            <span>💡 Tip: Click inside diagram to toggle Motion / Themes</span>
          </div>
        </div>

        {/* Embedded Iframe */}
        <div className="w-full h-[650px] rounded-xl overflow-hidden border border-white/10 bg-slate-950 relative">
          <iframe
            key={currentDiagram.file}
            src={currentDiagram.file}
            title={currentDiagram.title}
            className="w-full h-full border-0"
            allow="fullscreen"
          />
        </div>
      </div>
    </div>
  )
}
