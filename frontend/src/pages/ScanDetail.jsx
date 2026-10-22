import React, { useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Loader2, Square, FileDown, ArrowLeft, Terminal, Bug, Pause, Play,
  Network, FileCode2, Clock, CheckCircle2, XCircle, ChevronDown, ChevronRight,
  RefreshCw, Volume2
} from 'lucide-react'
import { api } from '../lib/api.js'
import { useScanContext } from '../lib/ScanContext.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'
import { prettifyTitle } from '../lib/formatters.js'

import { subscribeScan } from '../lib/socket.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import FindingDetailDrawer from '../components/FindingDetailDrawer.jsx'
import ReportModal from '../components/ReportModal.jsx'
import StructuralMappingView from '../components/StructuralMappingView.jsx'

export default function ScanDetail() {
  const { id } = useParams()
  const { setScanContext } = useScanContext()
  const { isNight } = useTheme()
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
  const [owaspExpandedKey, setOwaspExpandedKey] = useState(null)
  const termRef = useRef(null)

  // AI Audio Briefing player state (Fish Audio via OpenRouter)
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

  const hasFailed = whiteboxMeta?.passes?.some(p => p.status === 'failed')
    || logs.some(l => l.level === 'warn' && /failed natively/i.test(l.message))

  if (err) return <div className="card p-6 text-sev-critical font-bold">{err}</div>
  if (!scan) return <div className="flex justify-center py-20"><Loader2 className="animate-spin text-cyan-400" size={32} /></div>

  const running = scan.status === 'running'
  const paused = scan.status === 'paused'

  const logColor = {
    info: 'text-slate-100 font-medium',
    success: 'text-emerald-400 font-medium',
    warn: 'text-amber-300 font-medium',
    medium: 'text-amber-300 font-medium',
    high: 'text-orange-400 font-medium',
    critical: 'text-rose-400 font-semibold',
    error: 'text-rose-400 font-semibold',
    low: 'text-cyan-300 font-medium',
  }

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
        const synth = window.speechSynthesis
        if (synth && res.text) {
          const utt = new SpeechSynthesisUtterance(res.text)
          utt.onend = () => setAudioState(s => ({ ...s, playing: false }))
          synth.speak(utt)
          setAudioState({ loading: false, playing: true, text: res.text, audio: 'browser-speech', error: '' })
        } else {
          setAudioState({ loading: false, playing: false, text: res.text || '', audio: null, error: res.error || 'Audio generation unavailable' })
        }
      }
    } catch (e) {
      setAudioState({ loading: false, playing: false, text: '', audio: null, error: e.message })
    }
  }

  return (
    <div className="space-y-6 motion-fade-up">
      {/* Target & Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4 min-w-0">
          <Link
            to="/app/scans"
            className={`p-2 rounded-xl transition-colors shrink-0 ${isNight ? 'text-slate-400 hover:text-white hover:bg-white/10' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200'}`}
            title="Back to Scans"
          >
            <ArrowLeft size={20} />
          </Link>
          <div className="min-w-0">
            <h1 className={`text-xl sm:text-2xl font-extrabold tracking-tight truncate ${isNight ? 'text-white' : 'text-slate-900'}`}>
              {scan.target}
            </h1>
            <p className={`text-xs sm:text-sm font-medium mt-0.5 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
              <span className="capitalize">{scan.mode}</span> • <span className="capitalize">{scan.status}</span>
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2 max-w-full">
          {running && (
            <button onClick={pause} className="btn-ghost text-xs">
              <Pause size={14} /> Pause
            </button>
          )}
          {(paused || scan.status === 'interrupted') && (
            <button onClick={resume} className="btn-primary text-xs shadow-glow">
              <Play size={14} /> Resume Scan
            </button>
          )}
          {(running || paused) && (
            <button onClick={stop} className="btn-danger text-xs">
              <Square size={14} /> Stop
            </button>
          )}
          {!running && !paused && scan.status !== 'interrupted' && (
            <>
              <button 
                onClick={playAudioBriefing} 
                disabled={audioState.loading} 
                className={`text-xs font-semibold px-3 py-2 rounded-xl border flex items-center gap-1.5 transition-all cursor-pointer ${
                  audioState.playing
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400 shadow-[0_0_12px_rgba(0,242,254,0.3)]'
                    : isNight
                      ? 'border-cyan-500/30 text-cyan-300 hover:text-white hover:border-cyan-400 hover:bg-cyan-500/10'
                      : 'border-cyan-600/40 bg-cyan-50/80 hover:bg-cyan-100 text-cyan-700 shadow-sm'
                }`}
                title="Hear AI Audio Summary"
              >
                {audioState.loading ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Volume2 size={14} className={audioState.playing ? 'animate-pulse text-cyan-400' : ''} />
                )}
                {audioState.playing ? 'Pause Audio' : 'Audio Briefing'}
              </button>

              {hasFailed && (
                <button
                  onClick={retryFailed}
                  disabled={retrying}
                  className={`text-xs font-semibold px-3 py-2 rounded-xl border flex items-center gap-1.5 transition-all cursor-pointer ${
                    isNight
                      ? 'border-amber-500/30 text-amber-300 hover:text-white hover:border-amber-400 hover:bg-amber-500/10'
                      : 'border-amber-600/40 bg-amber-50 hover:bg-amber-100 text-amber-700 shadow-sm'
                  }`}
                >
                  <RefreshCw size={14} className={retrying ? 'animate-spin' : ''} /> Retry Failed
                </button>
              )}

              <button
                onClick={() => setShowMapping(true)}
                className={`text-xs font-semibold px-3 py-2 rounded-xl border flex items-center gap-1.5 transition-all cursor-pointer ${
                  isNight
                    ? 'border-white/10 text-slate-300 hover:text-white hover:border-white/25 hover:bg-white/5'
                    : 'border-slate-300 bg-white hover:bg-slate-50 text-slate-800 shadow-sm'
                }`}
              >
                <Network size={14} /> Mapping
              </button>

              <button
                onClick={() => setShowReportModal(true)}
                className={`text-xs font-semibold px-3 py-2 rounded-xl border flex items-center gap-1.5 transition-all cursor-pointer ${
                  isNight
                    ? 'border-white/10 text-slate-300 hover:text-white hover:border-white/25 hover:bg-white/5'
                    : 'border-slate-300 bg-white hover:bg-slate-50 text-slate-800 shadow-sm'
                }`}
              >
                <FileDown size={14} /> Report
              </button>
            </>
          )}
        </div>
      </div>

      {/* Audio Briefing Transcript Box */}
      {audioState.text && (
        <div className={`p-4 rounded-xl border text-xs flex items-start gap-3 animate-in fade-in shadow-sm ${
          isNight ? 'bg-cyan-950/30 border-cyan-500/30 text-cyan-200' : 'bg-cyan-50/80 border-cyan-300 text-cyan-900'
        }`}>
          <Volume2 size={18} className="text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-bold text-cyan-400">Executive Audio Briefing Script:</p>
            <p className={`leading-relaxed italic ${isNight ? 'text-slate-200' : 'text-slate-700'}`}>"{audioState.text}"</p>
          </div>
        </div>
      )}

      {/* Progress Bar Card */}
      <div className="card p-5 shadow-lg">
        <div className="flex items-center justify-between mb-2 text-xs font-bold">
          <span className={isNight ? 'text-slate-300' : 'text-slate-700'}>Scan Execution Progress</span>
          <span className={isNight ? 'text-cyan-300' : 'text-cyan-700'}>
            {Math.round(progress)}% • Risk {(scan.risk_score ?? 0).toFixed(1)}/10
          </span>
        </div>
        <div className={`h-2.5 rounded-full overflow-hidden border ${isNight ? 'bg-slate-900 border-white/10' : 'bg-slate-200 border-slate-300'}`}>
          <div
            className="h-full bg-gradient-to-r from-cyan-400 via-blue-500 to-emerald-400 transition-all duration-500 shadow-[0_0_10px_rgba(0,242,254,0.5)]"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* ── Whitebox Audit Details ── */}
      {scan.mode === 'whitebox' && whiteboxMeta && (
        <div className="card p-6 shadow-xl space-y-5">
          <h3 className={`flex items-center gap-2 text-sm font-bold ${isNight ? 'text-white' : 'text-slate-900'}`}>
            <FileCode2 size={18} className="text-cyan-400" /> Whitebox Source Code Audit Details
          </h3>

          {/* Summary stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className={`rounded-xl border p-4 text-center shadow-sm ${
              isNight ? 'bg-[#131929]/90 border-white/10' : 'bg-slate-50 border-slate-200'
            }`}>
              <p className={`text-2xl font-extrabold ${isNight ? 'text-white' : 'text-slate-900'}`}>{whiteboxMeta.totalFiles}</p>
              <p className={`text-[11px] font-semibold mt-1 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>Files Audited</p>
            </div>
            <div className={`rounded-xl border p-4 text-center shadow-sm ${
              isNight ? 'bg-[#131929]/90 border-white/10' : 'bg-slate-50 border-slate-200'
            }`}>
              <p className="text-2xl font-extrabold text-cyan-400">{whiteboxMeta.passes?.length || 0}</p>
              <p className={`text-[11px] font-semibold mt-1 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>Total Passes</p>
            </div>
            <div className={`rounded-xl border p-4 text-center shadow-sm ${
              isNight ? 'bg-[#131929]/90 border-white/10' : 'bg-slate-50 border-slate-200'
            }`}>
              <p className="text-2xl font-extrabold text-emerald-400">{whiteboxMeta.passes?.filter(p => p.status === 'completed').length || 0}</p>
              <p className={`text-[11px] font-semibold mt-1 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>Completed</p>
            </div>
            <div className={`rounded-xl border p-4 text-center shadow-sm ${
              isNight ? 'bg-[#131929]/90 border-white/10' : 'bg-slate-50 border-slate-200'
            }`}>
              <p className="text-2xl font-extrabold text-rose-400">{whiteboxMeta.passes?.filter(p => p.status === 'failed').length || 0}</p>
              <p className={`text-[11px] font-semibold mt-1 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>Failed</p>
            </div>
          </div>

          {/* Pass details list */}
          <div className="space-y-2">
            <p className={`text-xs font-bold uppercase tracking-wider ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
              Pass Execution Breakdown
            </p>
            {whiteboxMeta.passes?.map((p, i) => (
              <div
                key={i}
                className={`flex items-center gap-3 rounded-xl border px-4 py-3 shadow-sm ${
                  isNight ? 'bg-[#182136] border-white/10' : 'bg-slate-50 border-slate-200'
                }`}
              >
                {p.status === 'completed' ? (
                  <CheckCircle2 size={18} className="text-emerald-400 shrink-0" />
                ) : (
                  <XCircle size={18} className="text-rose-400 shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-bold ${isNight ? 'text-white' : 'text-slate-900'}`}>{p.tool}</p>
                  <p className={`text-xs mt-0.5 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>{p.type} • {p.findings} findings</p>
                  {p.error && <p className="text-xs text-rose-400 mt-1 font-medium truncate">{p.error}</p>}
                </div>
                <div className={`flex items-center gap-1.5 text-xs font-mono shrink-0 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                  <Clock size={13} />
                  <span>{(p.durationMs / 1000).toFixed(1)}s</span>
                </div>
              </div>
            ))}
          </div>

          {/* Files checked (collapsible) */}
          <div>
            <button
              onClick={() => setShowFiles(!showFiles)}
              className={`flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider transition-colors cursor-pointer ${
                isNight ? 'text-slate-400 hover:text-white' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {showFiles ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Files Audited ({whiteboxMeta.totalFiles})
            </button>
            {showFiles && (
              <div className={`mt-3 max-h-48 overflow-auto rounded-xl border shadow-inner ${
                isNight ? 'bg-[#0b101c] border-white/10' : 'bg-slate-50 border-slate-200'
              }`}>
                <table className="w-full text-xs">
                  <thead>
                    <tr className={`border-b ${isNight ? 'border-white/10 text-slate-400' : 'border-slate-200 text-slate-600'}`}>
                      <th className="text-left py-2 px-3.5 font-bold">File Path</th>
                      <th className="text-right py-2 px-3.5 font-bold">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {whiteboxMeta.filesChecked?.map((f, i) => (
                      <tr
                        key={i}
                        className={`border-b transition-colors ${
                          isNight ? 'border-white/5 hover:bg-white/[0.03]' : 'border-slate-100 hover:bg-slate-100'
                        }`}
                      >
                        <td className={`py-2 px-3.5 font-mono truncate max-w-[320px] ${isNight ? 'text-slate-300' : 'text-slate-800'}`}>
                          {f.path}
                        </td>
                        <td className={`py-2 px-3.5 text-right tabular-nums font-mono ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                          {formatBytes(f.size)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Two Column Grid: Live Output & Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Output Terminal */}
        <div className="card p-5 flex flex-col justify-between shadow-xl">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className={`flex items-center gap-2 text-sm font-bold ${isNight ? 'text-white' : 'text-slate-900'}`}>
                <Terminal size={16} className="text-cyan-400" /> Live Engine Output
              </h3>
              {running && (
                <span className="chip bg-cyan-500/20 text-cyan-300 border-cyan-500/40 text-[11px] font-bold animate-pulse">
                  streaming
                </span>
              )}
            </div>

            {/* High-Contrast Cyber Console */}
            <div
              ref={termRef}
              className="h-96 overflow-y-auto p-4 font-mono text-xs space-y-1.5 bg-[#090d16] border border-white/10 rounded-xl shadow-inner select-text"
            >
              {logs.length === 0 && (
                <p className="text-slate-400 italic py-4">Waiting for scan output…</p>
              )}
              {logs.map((l, i) => (
                <div key={i} className="flex items-start gap-2.5 leading-relaxed hover:bg-white/[0.03] px-1 rounded transition-colors">
                  <span className="text-cyan-400 font-mono text-[11px] shrink-0 select-none font-bold">
                    {new Date(l.ts).toLocaleTimeString()}
                  </span>
                  <span className={`flex-1 break-words ${logColor[l.level] || 'text-slate-100 font-medium'}`}>
                    {l.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Findings Accordion */}
        <div className="card p-5 flex flex-col justify-between shadow-xl">
          <div>
            <h3 className={`flex items-center gap-2 text-sm font-bold mb-3 ${isNight ? 'text-white' : 'text-slate-900'}`}>
              <Bug size={16} className="text-rose-400" /> Vulnerability Findings ({findings.length})
            </h3>

            <div className="space-y-3 max-h-[24rem] overflow-auto pr-1">
              {findings.length === 0 && (
                <p className={`text-sm py-12 text-center font-medium ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                  No vulnerability findings detected for this assessment.
                </p>
              )}
              {(() => {
                const OWASP_ORDER = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10', 'OTH']
                const OWASP_NAMES = {
                  A01: 'Broken Access Control',
                  A02: 'Security Misconfiguration',
                  A03: 'Software Supply Chain Failures',
                  A04: 'Cryptographic Failures',
                  A05: 'Injection',
                  A06: 'Insecure Design',
                  A07: 'Authentication Failures',
                  A08: 'Software or Data Integrity Failures',
                  A09: 'Security Logging and Alerting Failures',
                  A10: 'Mishandling of Exceptional Conditions',
                  OTH: 'Other Findings',
                }
                const grouped = {}
                const uncategorized = []
                findings.forEach((f) => {
                  const cat = (f.owasp_category || '').split(':')[0].trim().toUpperCase()
                  if (cat && OWASP_ORDER.includes(cat)) {
                    if (!grouped[cat]) grouped[cat] = []
                    grouped[cat].push(f)
                  } else {
                    uncategorized.push(f)
                  }
                })
                if (uncategorized.length) {
                  grouped['OTH'] = uncategorized
                }

                return OWASP_ORDER.filter((code) => grouped[code]).map((code) => {
                  const items = grouped[code]
                  const isExpanded = owaspExpandedKey === code

                  return (
                    <div
                      key={code}
                      className={`rounded-xl border overflow-hidden transition-all duration-200 ${
                        isNight
                          ? 'bg-[#131929]/90 border-white/10'
                          : 'bg-white border-slate-200 shadow-sm'
                      }`}
                    >
                      <div
                        onClick={() => setOwaspExpandedKey(isExpanded ? null : code)}
                        className={`flex items-center gap-2.5 p-3 cursor-pointer select-none transition-colors ${
                          isNight ? 'hover:bg-white/[0.04]' : 'hover:bg-slate-50'
                        }`}
                      >
                        {isExpanded ? (
                          <ChevronDown size={15} className={isNight ? 'text-cyan-400' : 'text-cyan-600'} />
                        ) : (
                          <ChevronRight size={15} className={isNight ? 'text-slate-400' : 'text-slate-500'} />
                        )}
                        <span className={`text-xs font-extrabold ${isNight ? 'text-cyan-400' : 'text-cyan-600'}`}>{code}</span>
                        <span className={`text-xs font-bold truncate ${isNight ? 'text-slate-100' : 'text-slate-900'}`}>
                          {OWASP_NAMES[code]}
                        </span>
                        <span className={`ml-auto text-[11px] px-2 py-0.5 rounded-full font-bold border shrink-0 ${
                          isNight
                            ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                            : 'bg-cyan-50 text-cyan-700 border-cyan-200'
                        }`}>
                          {items.length}
                        </span>
                      </div>

                      {isExpanded && (
                        <div className="space-y-2 p-3 pt-0">
                          {items.map((f, i) => (
                            <div
                              key={f.id || i}
                              onClick={() => setSelected(f)}
                              className={`rounded-lg p-3.5 cursor-pointer border transition-all ${
                                isNight
                                  ? 'bg-[#182136] border-white/10 hover:border-cyan-400/50 hover:bg-[#1e2945]'
                                  : 'bg-slate-50 border-slate-200 hover:border-cyan-500 hover:bg-white shadow-sm'
                              }`}
                            >
                              <div className="flex items-start justify-between gap-3">
                                <p className={`text-sm font-semibold leading-snug ${isNight ? 'text-slate-100' : 'text-slate-900'}`}>
                                  {prettifyTitle(f.title)}
                                </p>
                                <SeverityBadge severity={f.severity} />
                              </div>
                              {f.agent_verdict && (
                                <p className={`mt-1.5 text-xs italic line-clamp-2 ${isNight ? 'text-slate-300' : 'text-slate-600'}`}>
                                  {f.agent_verdict}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })
              })()}
            </div>
          </div>
        </div>
      </div>

      {/* Drawer & Modals */}
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
