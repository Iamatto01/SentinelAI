import React, { useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Loader2, Square, FileDown, ArrowLeft, Terminal, Bug, Pause, Play, Network, FileCode2, Clock, CheckCircle2, XCircle, ChevronDown, ChevronRight, RefreshCw, Volume2 } from 'lucide-react'
import { api } from '../lib/api.js'
import { useScanContext } from '../lib/ScanContext.jsx'
import { subscribeScan } from '../lib/socket.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import FindingDetailDrawer from '../components/FindingDetailDrawer.jsx'
import ReportModal from '../components/ReportModal.jsx'
import StructuralMappingView from '../components/StructuralMappingView.jsx'

export default function ScanDetail() {
  const { id } = useParams()
  const { setScanContext } = useScanContext()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [logs, setLogs] = useState([])
  const [progress, setProgress] = useState(0)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState(null)
  const [showReportModal, setShowReportModal] = useState(false)
  const [showMapping, setShowMapping] = useState(false)
  const [whiteboxMeta, setWhiteboxMeta] = useState(null)
  const [showFiles, setShowFiles] = useState(false)
  const termRef = useRef(null)

  // AI Audio Briefing player state (Fish Audio via OpenRouter) - MUST be declared at top level
  const [audioState, setAudioState] = useState({ loading: false, playing: false, text: '', audio: null, error: '' })
  const audioRef = useRef(null)

  useEffect(() => {
    api.scan(id)
      .then((d) => {
        setScan(d.scan)
        setFindings(d.findings || [])
        setLogs(d.logs || [])
        setProgress(d.scan.progress || 0)
        setWhiteboxMeta(d.whiteboxMeta || null)
        setScanContext({ scan: d.scan, findings: d.findings || [] })
      })
      .catch((e) => setErr(e.message))

    const unsub = subscribeScan(id, {
      onLog: (d) => setLogs((p) => [...p, { level: d.level, message: d.message, ts: d.ts }].slice(-500)),
      onFinding: (d) => setFindings((p) => [...p, d.finding]),
      onUpdate: (d) => setProgress(d.progress ?? 0),
      onDone: (d) => { setProgress(100); setScan((s) => (s ? { ...s, status: d.status || 'done', risk_score: d.riskScore } : s)) },
    })
    // Safety-net poll while the scan is active in case a socket event is missed.
    const poll = setInterval(() => {
      api.scan(id).then((d) => {
        if (!d?.scan) return
        setScan((s) => (s ? { ...s, ...d.scan } : d.scan))
        setProgress((p) => Math.max(p, d.scan.progress || 0))
      }).catch(() => { /* ignore transient poll errors */ })
    }, 5000)
    return () => { unsub(); clearInterval(poll) }
  }, [id])

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [logs])

  async function stop() { await api.stopScan(id); setScan((s) => ({ ...s, status: 'stopped' })) }
  async function pause() { await api.pauseScan(id); setScan((s) => ({ ...s, status: 'paused' })) }
  async function resume() { await api.resumeScan(id); setScan((s) => ({ ...s, status: 'running' })) }

  /** Retry only failed passes/tools in-place (same scan ID). */
  const [retrying, setRetrying] = useState(false)
  async function retryFailed() {
    setRetrying(true)
    try {
      await api.retryFailed(id)
      setScan((s) => ({ ...s, status: 'running' }))
      setProgress(0)
    } catch (e) {
      alert(`Retry failed: ${e.message}`)
    }
    setRetrying(false)
  }

  // Detect if there are failed passes (whitebox) or failed tools (blackbox)
  const hasFailed = whiteboxMeta?.passes?.some(p => p.status === 'failed')
    || logs.some(l => l.level === 'warn' && /failed natively/i.test(l.message))

  if (err) return <div className="card p-6 text-sev-critical">{err}</div>
  if (!scan) return <div className="flex justify-center py-20"><Loader2 className="animate-spin text-accent" size={28} /></div>

  const running = scan.status === 'running'
  const paused = scan.status === 'paused'
  const logColor = { info: 'text-slate-400', success: 'text-emerald-400', warn: 'text-sev-medium', error: 'text-sev-critical' }

  async function playAudioBriefing() {
    if (audioState.audio) {
      if (audioState.playing) {
        audioRef.current?.pause()
        setAudioState(s => ({ ...s, playing: false }))
      } else {
        audioRef.current?.play()
        setAudioState(s => ({ ...s, playing: true }))
      }
      return
    }

    setAudioState(s => ({ ...s, loading: true, error: '' }))
    try {
      const res = await api.audioBriefing(id)
      if (res.audio) {
        const audioObj = new Audio(res.audio)
        audioRef.current = audioObj
        audioObj.onended = () => setAudioState(s => ({ ...s, playing: false }))
        audioObj.play()
        setAudioState({ loading: false, playing: true, text: res.text, audio: res.audio, error: '' })
      } else {
        // Fallback: Web Speech Synthesis if audio generation API note returned
        const synth = window.speechSynthesis
        if (synth && res.text) {
          const utt = new SpeechSynthesisUtterance(res.text)
          utt.onend = () => setAudioState(s => ({ ...s, playing: false }))
          synth.speak(utt)
          setAudioState({ loading: false, playing: true, text: res.text, audio: 'browser-speech', error: '' })
        } else {
          setAudioState({ loading: false, playing: false, text: res.text || '', audio: null, error: res.error || 'Audio generation unavaliable' })
        }
      }
    } catch (e) {
      setAudioState({ loading: false, playing: false, text: '', audio: null, error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4 min-w-0">
          <Link to="/scans" className="text-slate-500 hover:text-slate-200 shrink-0"><ArrowLeft size={20} /></Link>
          <div className="min-w-0">
            <h1 className="text-lg sm:text-xl font-bold text-slate-100 truncate">{scan.target}</h1>
            <p className="text-xs sm:text-sm text-slate-500">{scan.mode} • {scan.status}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 max-w-full">
          {running && <button onClick={pause} className="btn-ghost"><Pause size={15} /> Pause</button>}
          {paused && <button onClick={resume} className="btn-primary"><Play size={15} /> Resume</button>}
          {(running || paused) && <button onClick={stop} className="btn-danger"><Square size={15} /> Stop</button>}
          {!running && !paused && (
            <>
              <button 
                onClick={playAudioBriefing} 
                disabled={audioState.loading} 
                className={`btn-ghost text-cyan-400 hover:text-cyan-300 border-cyan-500/30 flex items-center gap-1.5 ${audioState.playing ? 'bg-cyan-500/10 border-cyan-400' : ''}`}
                title="Hear Fish Audio TTS Summary"
              >
                {audioState.loading ? <Loader2 size={15} className="animate-spin" /> : <Volume2 size={15} className={audioState.playing ? 'animate-pulse text-cyan-400' : ''} />}
                {audioState.playing ? 'Pause Audio' : 'Audio Briefing'}
              </button>

              {hasFailed && (
                <button onClick={retryFailed} disabled={retrying} className="btn-ghost text-amber-400 hover:text-amber-300 border-amber-500/30">
                  <RefreshCw size={15} className={retrying ? 'animate-spin' : ''} /> Retry Failed
                </button>
              )}
              <button onClick={() => setShowMapping(true)} className="btn-ghost">
                <Network size={15} /> Mapping
              </button>
              <button onClick={() => setShowReportModal(true)} className="btn-ghost">
                <FileDown size={15} /> Report
              </button>
            </>
          )}
        </div>
      </div>

      {audioState.text && (
        <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-200 flex items-start gap-2 animate-in fade-in">
          <Volume2 size={16} className="text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-cyan-300 mb-0.5">Fish Audio Executive Briefing Script:</p>
            <p className="text-slate-300 italic">"{audioState.text}"</p>
          </div>
        </div>
      )}

      <div className="card p-4">
        <div className="flex items-center justify-between mb-2 text-xs text-slate-500">
          <span>Progress</span>
          <span>{Math.round(progress)}% • Risk {(scan.risk_score ?? 0).toFixed(1)}/10</span>
        </div>
        <div className="h-2 rounded-full bg-ink-800 overflow-hidden">
          <div className="h-full bg-gradient-to-r from-accent-dim to-accent transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>
      </div>

      {/* ── Whitebox Audit Details ── */}
      {scan.mode === 'whitebox' && whiteboxMeta && (
        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200 mb-4">
            <FileCode2 size={16} className="text-accent" /> Audit Details
          </h3>

          {/* Summary stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            <div className="rounded-lg bg-ink-800/60 border border-ink-700/60 p-3 text-center">
              <p className="text-2xl font-bold text-slate-100">{whiteboxMeta.totalFiles}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">Files Checked</p>
            </div>
            <div className="rounded-lg bg-ink-800/60 border border-ink-700/60 p-3 text-center">
              <p className="text-2xl font-bold text-accent">{whiteboxMeta.passes?.length || 0}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">Passes</p>
            </div>
            <div className="rounded-lg bg-ink-800/60 border border-ink-700/60 p-3 text-center">
              <p className="text-2xl font-bold text-emerald-400">{whiteboxMeta.passes?.filter(p => p.status === 'completed').length || 0}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">Completed</p>
            </div>
            <div className="rounded-lg bg-ink-800/60 border border-ink-700/60 p-3 text-center">
              <p className="text-2xl font-bold text-sev-critical">{whiteboxMeta.passes?.filter(p => p.status === 'failed').length || 0}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">Failed</p>
            </div>
          </div>

          {/* Pass details */}
          <div className="space-y-2 mb-4">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Scan Passes</p>
            {whiteboxMeta.passes?.map((p, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg bg-ink-800/40 border border-ink-700/40 px-4 py-2.5">
                {p.status === 'completed'
                  ? <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                  : <XCircle size={16} className="text-sev-critical shrink-0" />}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200">{p.tool}</p>
                  <p className="text-[11px] text-slate-500">{p.type} • {p.findings} findings</p>
                  {p.error && <p className="text-[11px] text-sev-critical mt-0.5 truncate">{p.error}</p>}
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-500 shrink-0">
                  <Clock size={12} />
                  <span>{(p.durationMs / 1000).toFixed(1)}s</span>
                </div>
              </div>
            ))}
          </div>

          {/* Files checked (collapsible) */}
          <div>
            <button
              onClick={() => setShowFiles(!showFiles)}
              className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wide hover:text-slate-300 transition-colors"
            >
              {showFiles ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Files Checked ({whiteboxMeta.totalFiles})
            </button>
            {showFiles && (
              <div className="mt-2 max-h-48 overflow-auto rounded-lg bg-ink-900/60 border border-ink-700/40">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-ink-700/40 text-slate-500">
                      <th className="text-left py-1.5 px-3 font-medium">File</th>
                      <th className="text-right py-1.5 px-3 font-medium">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {whiteboxMeta.filesChecked?.map((f, i) => (
                      <tr key={i} className="border-b border-ink-800/40 hover:bg-ink-800/30 transition-colors">
                        <td className="py-1.5 px-3 text-slate-300 font-mono truncate max-w-[300px]">{f.path}</td>
                        <td className="py-1.5 px-3 text-slate-500 text-right tabular-nums">{formatBytes(f.size)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200 mb-3">
            <Terminal size={16} className="text-accent" /> Live Output
            {running && <span className="chip bg-accent/15 text-accent border border-accent/40 ml-auto">streaming</span>}
          </h3>
          <div ref={termRef} className="terminal h-96">
            {logs.length === 0 && <p className="text-slate-600">Waiting for output…</p>}
            {logs.map((l, i) => (
              <div key={i} className="flex gap-2">
                <span className="text-slate-600 shrink-0">{new Date(l.ts).toLocaleTimeString()}</span>
                <span className={logColor[l.level] || 'text-slate-400'}>{l.message}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200 mb-3">
            <Bug size={16} className="text-sev-high" /> Findings ({findings.length})
          </h3>
          <div className="space-y-2.5 max-h-96 overflow-auto pr-1">
            {findings.length === 0 && <p className="text-sm text-slate-600 py-10 text-center">No findings yet.</p>}
            {findings.map((f, i) => (
              <div key={f.id || i} onClick={() => setSelected(f)} className="rounded-lg bg-ink-800/60 border border-ink-700/60 p-3.5 cursor-pointer hover:border-ink-500 transition-colors">
                <div className="flex items-start justify-between gap-3">
                  <p className="text-sm font-medium text-slate-200 leading-snug">{f.title}</p>
                  <SeverityBadge severity={f.severity} />
                </div>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {f.owasp_category && <span className="text-[11px] text-accent/80">{f.owasp_category}</span>}
                </div>
                {f.agent_verdict && <p className="mt-1 text-[11px] text-slate-500 italic line-clamp-2">{f.agent_verdict}</p>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {selected && <FindingDetailDrawer finding={selected} onClose={() => setSelected(null)} />}
      <ReportModal isOpen={showReportModal} onClose={() => setShowReportModal(false)} scanId={id} />
      {showMapping && (
        <StructuralMappingView
          scan={scan}
          findings={findings}
          logs={logs}
          onClose={() => setShowMapping(false)}
          onSelectFinding={(f) => {
            setSelected(f)
            setShowMapping(false)
          }}
        />
      )}
    </div>
  )
}

/** Format file size to human-readable string. */
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}
