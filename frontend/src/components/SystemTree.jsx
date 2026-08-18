import React, { useState } from 'react'
import {
  Server, Terminal, Bot, DatabaseZap, FileText, Globe2, ShieldAlert,
  Sparkles, CheckCircle2, ChevronDown, ChevronRight, Zap, Code2, Network,
  GitBranch, Lock, Cpu, Activity, Info, ExternalLink, Layers, Check
} from 'lucide-react'
import InspectorLogo from './InspectorLogo.jsx'

export default function SystemTree() {
  const [selectedNode, setSelectedNode] = useState(null)
  const [activeLayer, setActiveLayer] = useState('all')
  const [collapsedBranches, setCollapsedBranches] = useState({})

  const toggleBranch = (id, e) => {
    e.stopPropagation()
    setCollapsedBranches(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const TREE_BRANCHES = [
    {
      id: 'frontend',
      title: '1. Frontend UI Layer',
      badge: 'React 18 · Vite 6',
      icon: Code2,
      color: 'cyan',
      border: 'border-cyan-500/40',
      bg: 'from-cyan-950/40 to-slate-900/80',
      glow: 'shadow-cyan-500/20',
      text: 'text-cyan-400',
      tag: 'UI & Visualization',
      summary: 'High-performance dark glassmorphic dashboard with live telemetry and interactive topological attack maps.',
      leaves: [
        { name: 'React 18 SPA (Vision UI)', desc: 'SPA architecture with real-time SSE telemetry & dark mode switch.', tag: 'Vite 6' },
        { name: 'Attack Surface Map', desc: 'Force-directed SVG node graph with saved layout persistence.', tag: 'SVG Force' },
        { name: 'Interactive Finding Drawer', desc: 'Layman English remediation summaries & AI chat assistant tab.', tag: 'Drawer UI' }
      ]
    },
    {
      id: 'backend',
      title: '2. Express API Gateway',
      badge: 'JWT 12h · SQLite WAL',
      icon: Server,
      color: 'purple',
      border: 'border-purple-500/40',
      bg: 'from-purple-950/40 to-slate-900/80',
      glow: 'shadow-purple-500/20',
      text: 'text-purple-400',
      tag: 'API & Orchestrator',
      summary: 'Central coordination layer handling JWT role-based access control, subscription quotas, and scan queues.',
      leaves: [
        { name: 'JWT Auth & RBAC', desc: 'Admin, Security Analyst, and Client portal permission isolation.', tag: 'Auth' },
        { name: 'SQLite WAL Local DB', desc: 'Zero external cloud deps; high-speed embedded DB with auto backups.', tag: 'Better-SQLite3' },
        { name: 'Exploitation State Engine', desc: 'Autonomous exploit campaign state machine & approval gates.', tag: 'AEE State' }
      ]
    },
    {
      id: 'hexstrike',
      title: '3. Hexstrike Kali Engine',
      badge: '150+ Tools · :8888',
      icon: Terminal,
      color: 'red',
      border: 'border-red-500/40',
      bg: 'from-red-950/40 to-slate-900/80',
      glow: 'shadow-red-500/20',
      text: 'text-red-400',
      tag: 'Kali Execution',
      summary: 'Chains 150+ real Kali Linux security tools via REST API and executes AST static code analysis.',
      leaves: [
        { name: 'REST Gateway (127.0.0.1:8888)', desc: 'Orchestrates Nmap, Nuclei, Nikto, Subfinder, FFUF, SQLMap & Hydra.', tag: 'Hexstrike' },
        { name: 'Static Whitebox AST Parser', desc: 'AST regex scanner analyzing JS, Python, PHP, Java for flaws.', tag: 'Code Review' },
        { name: 'Metasploit RPC Bridge', desc: 'Active session handler and reverse TCP meterpreter listeners.', tag: 'msfrpcd' }
      ]
    },
    {
      id: 'ai',
      title: '4. 51 AI Specialist Personas',
      badge: 'Multi-LLM Consensus',
      icon: Bot,
      color: 'amber',
      border: 'border-amber-500/40',
      bg: 'from-amber-950/40 to-slate-900/80',
      glow: 'shadow-amber-500/20',
      text: 'text-amber-400',
      tag: 'AI Verification',
      summary: 'Specialist AI personas verify raw tool outputs, eliminate false-positive noise, and calculate CVSS risk.',
      leaves: [
        { name: 'Web Hunter & Exploit Persona', desc: 'Validates XSS, SQLi, SSRF and generates proof-of-concept steps.', tag: 'Groq / LLaMA' },
        { name: 'False-Positive Elimination', desc: 'Context-aware verification discarding benign scan warnings.', tag: 'AI Filter' },
        { name: 'CVSS v3.1 Risk Calculator', desc: 'Automated base, temporal, and environmental score evaluation.', tag: 'Scoring' }
      ]
    },
    {
      id: 'rag',
      title: '5. Local RAG Exploit Store',
      badge: 'PayloadsAllTheThings FTS5',
      icon: DatabaseZap,
      color: 'emerald',
      border: 'border-emerald-500/40',
      bg: 'from-emerald-950/40 to-slate-900/80',
      glow: 'shadow-emerald-500/20',
      text: 'text-emerald-400',
      tag: 'Knowledge Base',
      summary: 'SQLite FTS5 full-text vector index matching curated security payloads and synthesizing auto-fix code diffs.',
      leaves: [
        { name: 'PayloadsAllTheThings FTS5', desc: 'Searches 10,000+ exploit bypass techniques locally in milliseconds.', tag: 'FTS5 Index' },
        { name: 'Contextual Patch Generator', desc: 'Synthesizes clean git diff patches to fix discovered flaws.', tag: 'Auto-Fix' },
        { name: 'Attack Vector Graph Linker', desc: 'Maps vulnerable endpoints to potential lateral movement nodes.', tag: 'Graph Link' }
      ]
    },
    {
      id: 'devsecops',
      title: '6. CI/CD & Delivery Layer',
      badge: 'GitHub Bot · PDFKit',
      icon: GitBranch,
      color: 'blue',
      border: 'border-blue-500/40',
      bg: 'from-blue-950/40 to-slate-900/80',
      glow: 'shadow-blue-500/20',
      text: 'text-blue-400',
      tag: 'DevSecOps & Reports',
      summary: 'Delivers executive PDF reports, sends real-time webhooks, and posts line-by-line GitHub PR code reviews.',
      leaves: [
        { name: 'GitHub PR Inline Review Bot', desc: 'Posts line-by-line security review comments directly in GitHub PRs.', tag: 'Octokit Bot' },
        { name: 'Executive PDF Generator', desc: 'Renders branded penetration testing reports with risk matrices.', tag: 'PDFKit' },
        { name: 'Multi-Channel Alert Dispatcher', desc: 'Dispatches real-time security alerts via Slack, Discord, and Email.', tag: 'Webhooks' }
      ]
    }
  ]

  const filteredBranches = activeLayer === 'all' 
    ? TREE_BRANCHES 
    : TREE_BRANCHES.filter(b => b.id === activeLayer)

  return (
    <div className="w-full space-y-8">
      {/* ── Filter / Control Bar ── */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-2xl bg-slate-950/80 border border-white/10 shadow-xl backdrop-blur-xl">
        <div className="flex items-center gap-2">
          <Layers size={16} className="text-cyan-400" />
          <span className="text-xs font-bold text-slate-200">System Tree Filter:</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setActiveLayer('all')}
            className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all cursor-pointer ${
              activeLayer === 'all'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/30'
                : 'bg-white/5 text-slate-400 hover:text-white border border-white/10'
            }`}
          >
            All 6 Layers
          </button>
          {TREE_BRANCHES.map(b => (
            <button
              key={b.id}
              onClick={() => setActiveLayer(b.id)}
              className={`px-2.5 py-1 rounded-xl text-[11px] font-semibold transition-all cursor-pointer ${
                activeLayer === b.id
                  ? 'bg-white/20 text-white border border-white/30 font-bold'
                  : 'bg-white/5 text-slate-400 hover:text-white border border-white/5'
              }`}
            >
              {b.title.split('.')[1] || b.title}
            </button>
          ))}
        </div>

        <div className="text-[11px] font-mono text-cyan-400 flex items-center gap-1.5">
          <Sparkles size={13} className="text-cyan-400 animate-spin" />
          <span>Interactive Hierarchy Flow</span>
        </div>
      </div>

      {/* ── GRAND TREE CANVAS CONTAINER ── */}
      <div className="relative p-6 sm:p-10 rounded-3xl bg-slate-950/90 border border-white/15 shadow-2xl overflow-hidden backdrop-blur-2xl">
        {/* Ambient circuit glow lines behind tree */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-900/20 via-transparent to-transparent pointer-events-none" />

        {/* ── 1. ROOT CROWN NODE (Top Center) ── */}
        <div className="flex flex-col items-center justify-center relative z-10 mb-8">
          <div
            onClick={() => setSelectedNode({
              title: 'SentinelAI Core Engine (Unified Pentest Platform)',
              tag: 'System Root Orchestrator',
              badge: 'v2.0 Orchestrator',
              summary: 'Master control coordinator that unites Blackbox live scanning, Whitebox static code audits, 51 AI agent personas, and local-first RAG intelligence into a unified security platform.',
              leaves: [
                { name: 'Hexstrike Kali Engine Link', desc: '150+ security tools automated via local REST bridge.' },
                { name: 'Multi-LLM Consensus Filter', desc: 'Groq, OpenRouter, and DeepSeek AI reasoning agents.' },
                { name: 'Full-Stack Telemetry Bus', desc: 'Real-time WebSocket & SSE event bus streaming to web UI.' }
              ]
            })}
            className="group cursor-pointer p-4 sm:p-5 rounded-3xl bg-gradient-to-b from-cyan-900/60 via-slate-900 to-slate-950 border-2 border-cyan-400/60 shadow-2xl shadow-cyan-500/30 hover:scale-105 transition-all duration-300 max-w-md text-center ring-1 ring-cyan-400/50"
          >
            <div className="flex items-center justify-center gap-3">
              <div className="p-2.5 rounded-2xl bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/40 group-hover:rotate-6 transition-transform">
                <InspectorLogo size={32} />
              </div>
              <div className="text-left">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 font-bold uppercase tracking-wider">
                    SYSTEM ROOT ORCHESTRATOR
                  </span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                </div>
                <h3 className="text-base sm:text-lg font-black text-white group-hover:text-cyan-300 transition-colors">
                  SentinelAI Core Engine
                </h3>
              </div>
            </div>
            <p className="text-xs text-slate-300 mt-2 font-medium">
              Unified Autonomous Penetration Testing Platform & AI Reasoning Core
            </p>
          </div>

          {/* SVG Vertical Root Stem & Branching Curves */}
          <div className="w-full flex justify-center py-2 relative">
            <div className="w-0.5 h-8 bg-gradient-to-b from-cyan-400 to-cyan-500/60 animate-pulse" />
          </div>
        </div>

        {/* ── 2. PRIMARY BRANCHES & LEAF NODES (Tree Grid) ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 relative z-10">
          {filteredBranches.map((branch) => {
            const Icon = branch.icon
            const isCollapsed = collapsedBranches[branch.id]

            return (
              <div
                key={branch.id}
                className="flex flex-col space-y-4 relative group"
              >
                {/* Branch Card (Parent Pillar) */}
                <div
                  onClick={() => setSelectedNode(branch)}
                  className={`p-5 rounded-2xl border bg-gradient-to-b ${branch.bg} ${branch.border} shadow-xl hover:scale-[1.02] transition-all duration-300 cursor-pointer relative overflow-hidden flex flex-col justify-between`}
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-black/40 text-slate-300 border border-white/10">
                        {branch.tag}
                      </span>
                      <button
                        onClick={(e) => toggleBranch(branch.id, e)}
                        title={isCollapsed ? 'Expand Leaf Nodes' : 'Collapse Leaf Nodes'}
                        className="p-1 rounded-lg bg-white/5 hover:bg-white/15 text-slate-400 hover:text-white transition-colors"
                      >
                        {isCollapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
                      </button>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className={`p-2.5 rounded-xl bg-black/50 border border-white/10 ${branch.text} shadow-md`}>
                        <Icon size={20} />
                      </div>
                      <div>
                        <h4 className="text-sm sm:text-base font-extrabold text-white group-hover:text-cyan-300 transition-colors">
                          {branch.title}
                        </h4>
                        <span className="text-[11px] font-mono text-slate-400">
                          {branch.badge}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {branch.summary}
                    </p>
                  </div>

                  <div className="pt-3 border-t border-white/10 flex items-center justify-between text-[11px] font-mono text-slate-400 mt-3">
                    <span>{branch.leaves.length} Sub-modules</span>
                    <span className="text-cyan-400 font-bold group-hover:translate-x-1 transition-transform inline-flex items-center gap-1">
                      Inspect Node <ChevronRight size={12} />
                    </span>
                  </div>
                </div>

                {/* Branch Stem Connecting to Leaves */}
                {!isCollapsed && (
                  <div className="pl-6 space-y-2.5 border-l-2 border-dashed border-cyan-500/30 ml-6 pt-1">
                    {branch.leaves.map((leaf, lIdx) => (
                      <div
                        key={lIdx}
                        onClick={() => setSelectedNode({
                          title: leaf.name,
                          tag: branch.title,
                          badge: leaf.tag,
                          summary: leaf.desc,
                          parentBranch: branch.title
                        })}
                        className="p-3 rounded-xl bg-slate-900/80 border border-white/10 hover:border-cyan-400/50 hover:bg-slate-900 shadow-md transition-all cursor-pointer flex items-start justify-between gap-3 group/leaf"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 group-hover/leaf:scale-150 transition-transform" />
                            <span className="text-xs font-bold text-slate-200 group-hover/leaf:text-cyan-300 transition-colors">
                              {leaf.name}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 leading-snug">
                            {leaf.desc}
                          </p>
                        </div>
                        {leaf.tag && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-slate-400 shrink-0">
                            {leaf.tag}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Slide-in Node Inspector Modal / Drawer ── */}
      {selectedNode && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="card p-6 sm:p-8 max-w-lg w-full border border-cyan-500/50 bg-slate-900/95 rounded-3xl shadow-2xl space-y-6 relative animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-start justify-between border-b border-white/10 pb-4">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 font-bold uppercase">
                  {selectedNode.tag || 'Architecture Node'}
                </span>
                <h3 className="text-lg sm:text-xl font-extrabold text-white mt-1.5">
                  {selectedNode.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white p-1.5 rounded-xl hover:bg-white/10 transition-colors text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-medium">
              {selectedNode.summary}
            </p>

            {selectedNode.leaves && selectedNode.leaves.length > 0 && (
              <div className="space-y-2 pt-2 border-t border-white/10">
                <div className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                  <Sparkles size={13} /> Active Sub-Components:
                </div>
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedNode.leaves.map((l, idx) => (
                    <div key={idx} className="p-2.5 rounded-xl bg-black/40 border border-white/5 text-xs">
                      <div className="font-bold text-slate-200">{l.name}</div>
                      <div className="text-slate-400 text-[11px] mt-0.5">{l.desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedNode(null)}
                className="btn-primary text-xs py-2 px-5 font-bold"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
