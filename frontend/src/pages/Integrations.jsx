import React, { useEffect, useState } from 'react'
import { Loader2, RefreshCw, Cpu, Database, Bot, Sparkles, CheckCircle2, XCircle, Search, X, Shield, ExternalLink, Send, ShieldCheck, Unlink, Play, AlertTriangle } from 'lucide-react'
import { api } from '../lib/api.js'

function StatusDot({ ok }) {
  return ok
    ? <CheckCircle2 size={18} className="text-emerald-400" />
    : <XCircle size={18} className="text-sev-critical" />
}

export default function Integrations() {
  const [status, setStatus] = useState(null)
  const [agents, setAgents] = useState([])
  const [aiData, setAiData] = useState(null)
  const [err, setErr] = useState('')
  const [reindexing, setReindexing] = useState(false)
  const [checkingAi, setCheckingAi] = useState(false)
  const [testingProvider, setTestingProvider] = useState(null)
  const [testResults, setTestResults] = useState({})
  
  // Agent modal & search state
  const [showAgentsModal, setShowAgentsModal] = useState(false)
  const [agentSearch, setAgentSearch] = useState('')
  const [selectedAgent, setSelectedAgent] = useState(null)
  const [teleStatus, setTeleStatus] = useState(null)
  const [pairCode, setPairCode] = useState('')
  const [teleLoading, setTeleLoading] = useState(false)
  const [teleMsg, setTeleMsg] = useState('')
  const [teleErr, setTeleErr] = useState('')

  async function handleRunModelTest(provider) {
    if (testingProvider) return
    setTestingProvider(provider.id)
    setTestResults(prev => ({ ...prev, [provider.id]: null }))
    try {
      const res = await api.testAiProvider({
        provider: provider.id,
        model: provider.model,
        prompt: 'SentinelAI verification test: confirm system readiness.'
      })
      setTestResults(prev => ({
        ...prev,
        [provider.id]: res
      }))
    } catch (e) {
      setTestResults(prev => ({
        ...prev,
        [provider.id]: { success: false, error: e.message }
      }))
    } finally {
      setTestingProvider(null)
    }
  }

  const load = () => {
    api.telegramPairing().then(setTeleStatus).catch(() => {})
    api.status().then(setStatus).catch((e) => setErr(e.message))
    api.agents().then((a) => setAgents(a || [])).catch(() => {})
    loadAiProviders()
  }

  const loadAiProviders = async () => {
    setCheckingAi(true)
    try {
      const data = await api.aiProviders()
      setAiData(data)
    } catch {
      setAiData(null)
    } finally {
      setCheckingAi(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handlePairTelegram(e) {
    e.preventDefault()
    setTeleMsg(''); setTeleErr(''); setTeleLoading(true)
    try {
      const res = await api.pairTelegram(pairCode)
      setTeleMsg(res.message || 'Telegram account paired successfully!')
      setPairCode('')
      api.telegramPairing().then(setTeleStatus).catch(() => {})
    } catch (err) {
      setTeleErr(err.message || 'Failed to pair Telegram account')
    } finally {
      setTeleLoading(false)
    }
  }

  async function handleUnpairChannel(platform) {
    const label = platform === 'discord' ? 'Discord' : 'Telegram'
    if (!window.confirm(`Adakah anda pasti mahu memutuskan sambungan ${label}?`)) return
    setTeleMsg(''); setTeleErr(''); setTeleLoading(true)
    try {
      const res = await api.unpairChannel(platform)
      setTeleMsg(res.message || `${label} unlinked.`)
      api.telegramPairing().then(setTeleStatus).catch(() => {})
    } catch (err) {
      setTeleErr(err.message || `Failed to unlink ${label}`)
    } finally {
      setTeleLoading(false)
    }
  }

  async function reindex() {
    setReindexing(true)
    try { await api.reindexPayloads(); load() } catch (e) { setErr(e.message) }
    setReindexing(false)
  }

  if (!status) return <div className="flex justify-center py-20"><Loader2 className="animate-spin text-accent" size={28} /></div>

  const engine = status.engine || {}
  const rawTools = engine.tools || (typeof engine === 'object' && !('available' in engine) ? engine : {})
  const totalToolsCount = engine.totalTools ?? Object.keys(rawTools).length ?? 0
  const toolsAvailableCount = engine.totalToolsAvailable ?? engine.toolsAvailable ?? Object.values(rawTools).filter(Boolean).length ?? 0
  const isEngineOk = Boolean(engine.available || engine.ok || toolsAvailableCount > 0)
  const rag = status.rag || {}
  const msf = status.msf || {}

  const filteredAgents = agents.filter(a => {
    if (!agentSearch.trim()) return true
    const q = agentSearch.toLowerCase()
    return (a.name || '').toLowerCase().includes(q) || (a.description || '').toLowerCase().includes(q)
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Integrations</h1>
          <p className="text-sm text-slate-500">Engine, knowledge base, {agents.length || 53} specialist agents &amp; AI providers live status</p>
        </div>
        <button onClick={load} className="btn-ghost text-xs">
          <RefreshCw size={14} className={checkingAi ? 'animate-spin' : ''} /> Refresh Status
        </button>
      </div>

      {err && <div className="card p-4 text-sev-critical text-sm">{err}</div>}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        
        {/* Native scanner engine */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Cpu size={18} className="text-accent" /> Native Kali Engine
            </h3>
            <StatusDot ok={isEngineOk} />
          </div>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-slate-500">Status</dt>
              <dd className={isEngineOk ? 'text-emerald-400 font-semibold' : 'text-sev-critical font-semibold'}>
                {isEngineOk ? 'ONLINE' : 'OFFLINE'}
              </dd>
            </div>
            {engine.version && <div className="flex justify-between"><dt className="text-slate-500">Version</dt><dd className="text-slate-300">{engine.version}</dd></div>}
            <div className="flex justify-between">
              <dt className="text-slate-500">Tools available</dt>
              <dd className="text-slate-300 font-mono font-medium">
                {toolsAvailableCount > 0 ? `${toolsAvailableCount} / ${totalToolsCount || toolsAvailableCount}` : '—'}
              </dd>
            </div>
          </dl>
          {!isEngineOk && <p className="mt-3 text-xs text-sev-medium">Tools unavailable — check Kali toolchain installation</p>}
        </div>

        {/* Payloads RAG */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Database size={18} className="text-accent" /> Payloads RAG
            </h3>
            <StatusDot ok={rag.installed && rag.docs > 0} />
          </div>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-slate-500">Corpus installed</dt><dd className="text-slate-300">{rag.installed ? 'yes' : 'no'}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Indexed docs</dt><dd className="text-slate-300">{rag.docs}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-500">Categories</dt><dd className="text-slate-300">{rag.categories?.length ?? 0}</dd></div>
          </dl>
          <button onClick={reindex} disabled={reindexing} className="btn-ghost mt-4 w-full justify-center">
            <RefreshCw size={15} className={reindexing ? 'animate-spin' : ''} /> {reindexing ? 'Reindexing…' : 'Rebuild index'}
          </button>
        </div>

        {/* Metasploit RPC */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Shield size={18} className="text-accent" /> Metasploit RPC
            </h3>
            <StatusDot ok={msf.available} />
          </div>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-slate-500">Status</dt><dd className={msf.available ? 'text-emerald-400 font-semibold' : 'text-sev-critical font-semibold'}>{msf.available ? 'ONLINE' : 'OFFLINE'}</dd></div>
            {msf.version && <div className="flex justify-between"><dt className="text-slate-500">Framework version</dt><dd className="text-slate-300 font-mono text-xs">{msf.version}</dd></div>}
            {!msf.available && msf.error && (
              <div className="mt-2 p-2 rounded bg-red-500/10 border border-red-500/30 text-[11px] text-red-300 font-mono break-all">
                {msf.error}
              </div>
            )}
          </dl>
          {!msf.available && (
            <div className="mt-3 text-xs text-slate-400 space-y-1">
              <p className="font-semibold text-slate-300">Start msfrpcd on Kali:</p>
              <code className="block text-accent bg-ink-950 p-2 rounded text-[11px] font-mono">
                msfrpcd -U msf -P msf -a 127.0.0.1 -p 55553 -S
              </code>
              <p className="text-slate-500 text-[11px]">Or enable the systemd unit: <code className="text-accent">sudo systemctl enable --now msfrpcd</code></p>
            </div>
          )}
        </div>

        {/* Telegram & Discord Channels Card */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Send size={18} className="text-cyan-400" /> Telegram & Discord Pairing
            </h3>
            <StatusDot ok={teleStatus?.telegram?.paired || teleStatus?.discord?.paired} />
          </div>

          <div className="text-xs space-y-2">
            <div className="flex items-center justify-between p-2 rounded-lg bg-[#1c1c1c] border border-white/[0.06]">
              <span className="text-slate-300 flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-cyan-400"></span> Telegram</span>
              {teleStatus?.telegram?.paired ? (
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold text-[11px]">Paired ({teleStatus.telegram.senderName})</span>
                  <button onClick={() => handleUnpairChannel('telegram')} className="text-rose-400 hover:text-rose-300 text-[11px] underline">Unlink</button>
                </div>
              ) : (
                <span className="text-slate-500 text-[11px]">Not Paired</span>
              )}
            </div>

            <div className="flex items-center justify-between p-2 rounded-lg bg-[#1c1c1c] border border-white/[0.06]">
              <span className="text-slate-300 flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-indigo-400"></span> Discord</span>
              {teleStatus?.discord?.paired ? (
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold text-[11px]">Paired ({teleStatus.discord.senderName})</span>
                  <button onClick={() => handleUnpairChannel('discord')} className="text-rose-400 hover:text-rose-300 text-[11px] underline">Unlink</button>
                </div>
              ) : (
                <span className="text-slate-500 text-[11px]">Not Paired</span>
              )}
            </div>
          </div>

          {teleMsg && <div className="p-2 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">{teleMsg}</div>}
          {teleErr && <div className="p-2 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-lg">{teleErr}</div>}

          <form onSubmit={handlePairTelegram} className="space-y-2 pt-1 border-t border-white/10">
            <p className="text-[11px] text-slate-400">
              Masukkan kod 6-digit (Telegram /start atau Discord @Sentinel AI /start):
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                maxLength={10}
                placeholder="Contoh: 141053"
                value={pairCode}
                onChange={(e) => setPairCode(e.target.value)}
                className="input text-xs font-mono tracking-wider text-center"
                required
              />
              <button type="submit" disabled={teleLoading || !pairCode.trim()} className="btn-primary text-xs shrink-0">
                {teleLoading ? <Loader2 size={12} className="animate-spin" /> : 'Approve'}
              </button>
            </div>
          </form>
        </div>

        {/* Specialist Agents Card */}
        <div className="card p-5 flex flex-col h-full">
          <div className="flex items-center justify-between mb-4 shrink-0">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Bot size={18} className="text-accent" /> Specialist Agents ({agents.length || 53})
            </h3>
            <StatusDot ok={agents.length > 0} />
          </div>
          <p className="text-xs text-slate-400 mb-3 shrink-0">
            Loaded domain specialist agent personas:
          </p>
          <div className="flex flex-wrap content-start gap-1.5 overflow-y-auto pr-1 flex-1 min-h-0">
            {agents.map((a) => (
              <span
                key={a.name}
                onClick={() => setSelectedAgent(a)}
                title={a.description || a.name}
                className="chip bg-ink-950 text-slate-300 border border-slate-800 text-[11px] cursor-pointer hover:border-accent hover:text-accent transition-colors"
              >
                {a.name}
              </span>
            ))}
          </div>

          <button
            onClick={() => setShowAgentsModal(true)}
            className="btn-ghost mt-4 w-full justify-center text-xs text-accent border border-accent/30 hover:bg-accent/10 shrink-0"
          >
            Explore All {agents.length || 53} Agent Personas & Prompt Specs →
          </button>
        </div>

        {/* AI Providers Live Status Card */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Sparkles size={18} className="text-accent" /> AI Providers & LLM Fallback Chain
            </h3>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">
                {aiData?.activeCount ?? 0}/{aiData?.totalCount ?? 4} Active
              </span>
              <StatusDot ok={(aiData?.activeCount ?? 0) > 0} />
            </div>
          </div>

          <p className="text-xs text-slate-400">
            Multi-provider automatic failover order:
          </p>

          {!aiData ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="animate-spin text-accent" size={20} />
            </div>
          ) : (
            <div className="space-y-2.5">
              {aiData.providers.map((p) => {
                const isTesting = testingProvider === p.id
                const testResult = testResults[p.id]

                return (
                  <div
                    key={p.id}
                    className={`rounded-lg border p-3 transition-all ${
                      p.online
                        ? 'border-emerald-500/30 bg-emerald-500/5'
                        : 'border-slate-800 bg-ink-950/60'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-slate-200">{p.name}</span>
                          <span className="text-[10px] text-accent/80 bg-accent/10 px-1.5 py-0.2 rounded border border-accent/20">
                            {p.role}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                          Model: <span className="text-slate-200">{p.model}</span>
                        </p>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleRunModelTest(p)}
                          disabled={isTesting}
                          title={`Run live prompt test on ${p.name}`}
                          className="px-2.5 py-1 text-[11px] font-medium rounded-md bg-accent/15 text-accent hover:bg-accent/25 border border-accent/30 flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
                        >
                          {isTesting ? (
                            <>
                              <Loader2 size={11} className="animate-spin" />
                              <span>Testing…</span>
                            </>
                          ) : (
                            <>
                              <Play size={10} className="fill-current" />
                              <span>Run</span>
                            </>
                          )}
                        </button>

                        <span
                          className={`inline-flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded-full ${
                            p.online
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                              : 'bg-red-500/15 text-red-400 border border-red-500/30'
                          }`}
                        >
                          <span className={`h-1.5 w-1.5 rounded-full ${p.online ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
                          {p.status}
                        </span>
                      </div>
                    </div>

                    {/* Live Test Feedback Banner */}
                    {testResult && (
                      <div className={`mt-2.5 p-2 rounded-lg text-[11px] font-mono flex items-start gap-2 border ${
                        testResult.success
                          ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                          : 'bg-red-950/40 border-red-500/30 text-red-300'
                      }`}>
                        {testResult.success ? (
                          <CheckCircle2 size={14} className="text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <AlertTriangle size={14} className="text-red-400 shrink-0 mt-0.5" />
                        )}
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between text-[10px] text-slate-400 mb-0.5">
                            <span>Latency: {testResult.latencyMs}ms</span>
                            <span>{testResult.success ? 'Verified Live' : 'Test Failed'}</span>
                          </div>
                          <p className="line-clamp-2 text-slate-200">
                            {testResult.success ? `"${testResult.reply}"` : testResult.error}
                          </p>
                        </div>
                      </div>
                    )}

                    <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-800/60 pt-1.5">
                      <span className="truncate max-w-[240px]">{p.baseUrl}</span>
                      <span>{p.reason}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

      </div>

      {/* Modal: All Specialist Agent Personas */}
      {showAgentsModal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/75 backdrop-blur-md p-4 animate-in fade-in" onClick={() => setShowAgentsModal(false)}>
          <div className="card w-full max-w-4xl p-6 space-y-4 max-h-[85vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <Bot className="text-accent" size={20} /> {agents.length || 53} Specialist Agent Personas
                </h2>
                <p className="text-xs text-slate-500">Domain-specific offensive AI agent prompts loaded from /agents/</p>
              </div>
              <button onClick={() => setShowAgentsModal(false)} className="text-slate-500 hover:text-slate-200">
                <X size={20} />
              </button>
            </div>

            {/* Search filter */}
            <div className="relative">
              <input
                type="text"
                value={agentSearch}
                onChange={(e) => setAgentSearch(e.target.value)}
                placeholder="Search agent persona by name or capability..."
                className="w-full rounded-lg border border-slate-800 bg-ink-950 px-3 py-2 pl-9 text-xs text-slate-200 focus:border-accent focus:outline-none"
              />
              <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
            </div>

            {/* Agent Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 overflow-y-auto pr-1 flex-1">
              {filteredAgents.map((a) => (
                <div
                  key={a.name}
                  onClick={() => setSelectedAgent(a)}
                  className="rounded-lg border border-slate-800 bg-ink-950 p-3 hover:border-accent cursor-pointer transition-all space-y-1 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200 group-hover:text-accent font-mono">{a.name}</span>
                    <Shield size={13} className="text-slate-600 group-hover:text-accent" />
                  </div>
                  {a.description && (
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                      {a.description}
                    </p>
                  )}
                </div>
              ))}
            </div>

            <div className="border-t border-slate-800 pt-3 flex justify-between items-center text-xs text-slate-500">
              <span>Showing {filteredAgents.length} of {agents.length} Agents</span>
              <button onClick={() => setShowAgentsModal(false)} className="btn-ghost text-xs">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Agent Detail Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/80 backdrop-blur-md p-4" onClick={() => setSelectedAgent(null)}>
          <div className="card w-full max-w-lg p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] uppercase font-bold text-accent tracking-wider">Specialist Persona</span>
                <h3 className="text-lg font-bold text-slate-100 font-mono">{selectedAgent.name}</h3>
              </div>
              <button onClick={() => setSelectedAgent(null)} className="text-slate-500 hover:text-slate-200">
                <X size={18} />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-400">Description / Capability</label>
                <p className="text-xs text-slate-200 bg-ink-950 p-3 rounded-lg border border-slate-800 leading-relaxed mt-1">
                  {selectedAgent.description || 'Specialist AI agent persona for security auditing and vulnerability verification.'}
                </p>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-400">Persona File</label>
                <p className="text-xs text-slate-400 font-mono mt-0.5">/agents/{selectedAgent.name}.md</p>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button onClick={() => setSelectedAgent(null)} className="btn-primary text-xs">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
