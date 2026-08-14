import React, { useEffect, useState, useRef, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Loader2, Radar, MoreVertical, Play, FileDown, Trash2, RefreshCw, Search, Coins, Sparkles, Activity } from 'lucide-react'
import { api, apiFetch } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'
import { getSocket } from '../lib/socket.js'
import ReportModal from '../components/ReportModal.jsx'

function fmtTokens(raw) {
  if (!raw) return '—'
  let tok
  if (typeof raw === 'object') tok = raw.total_tokens || 0
  else if (typeof raw === 'string') {
    try { tok = JSON.parse(raw).total_tokens || 0 } catch { return '—' }
  } else tok = raw
  if (tok === 0) return '—'
  if (tok >= 1_000_000) return (tok / 1_000_000).toFixed(1) + 'M'
  if (tok >= 1_000) return (tok / 1_000).toFixed(1) + 'K'
  return tok.toString()
}

const STATUS_STYLE = {
  running: 'bg-cyan-500/20 text-cyan-300 border-cyan-400/50 shadow-[0_0_10px_rgba(0,242,254,0.3)] animate-pulse',
  done: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]',
  completed: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]',
  failed: 'bg-rose-500/20 text-rose-400 border-rose-500/50 shadow-[0_0_10px_rgba(244,63,94,0.25)]',
  stopped: 'bg-slate-800/60 text-slate-400 border-white/10',
  interrupted: 'bg-amber-500/20 text-amber-400 border-amber-500/50',
  paused: 'bg-amber-500/20 text-amber-400 border-amber-500/50',
}

export default function Scans() {
  const { user } = useAuth()
  const isClient = user?.role === 'client'
  const [scans, setScans] = useState(null)
  const [err, setErr] = useState('')
  const [activeMenu, setActiveMenu] = useState(null)
  const [actionBusy, setActionBusy] = useState(null)
  const [reportModalScanId, setReportModalScanId] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const nav = useNavigate()
  const menuRef = useRef(null)

  useEffect(() => {
    fetchScans()
    const t = setInterval(fetchScans, 6000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    if (!scans?.length) return
    const s = getSocket()
    const onUpdate = (d) => setScans((prev) =>
      prev ? prev.map((x) => (x.id === d.scanId ? { ...x, progress: d.progress ?? x.progress } : x)) : prev)
    const onDone = (d) => setScans((prev) =>
      prev ? prev.map((x) => (x.id === d.scanId ? { ...x, status: d.status || 'completed', progress: 100, risk_score: d.riskScore ?? x.risk_score } : x)) : prev)
    s.on('scan:update', onUpdate)
    s.on('scan:done', onDone)
    return () => {
      s.off('scan:update', onUpdate)
      s.off('scan:done', onDone)
    }
  }, [scans?.length])

  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setActiveMenu(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  function fetchScans() {
    api.scans()
      .then((res) => {
        if (Array.isArray(res)) {
          setScans(res)
        } else if (res && Array.isArray(res.scans)) {
          setScans(res.scans)
        } else if (res && res.error) {
          setErr(res.error)
          setScans([])
        } else {
          setScans([])
        }
      })
      .catch((e) => {
        setErr(e.message || 'Failed to load scans')
        setScans([])
      })
  }

  async function handleDelete(id, e) {
    if (e) e.stopPropagation()
    if (!window.confirm('Are you sure you want to delete this scan and all its findings?')) return
    setActionBusy(id)
    try {
      await api.deleteScan(id)
      setScans((prev) => (prev || []).filter((s) => s.id !== id))
    } catch (err2) {
      alert(`Delete failed: ${err2.message}`)
    } finally {
      setActionBusy(null)
      setActiveMenu(null)
    }
  }

  async function handleReRun(id, e) {
    if (e) e.stopPropagation()
    setActionBusy(id)
    try {
      const runner = api.reRunScan || ((scanId) => apiFetch(`/api/scans/${scanId}/re-run`, { method: 'POST' }))
      const res = await runner(id)
      if (res.scan?.id) {
        nav(`/app/scans/${res.scan.id}`)
      } else {
        fetchScans()
      }
    } catch (err2) {
      alert(`Re-run failed: ${err2.message}`)
    } finally {
      setActionBusy(null)
      setActiveMenu(null)
    }
  }

  function handleDownloadReport(id, e) {
    e.stopPropagation()
    setActiveMenu(null)
    setReportModalScanId(id)
  }

  const filteredScans = useMemo(() => {
    if (!scans) return null
    if (!searchQuery.trim()) return scans
    const q = searchQuery.toLowerCase()
    return scans.filter((s) => {
      return (
        (s.target || '').toLowerCase().includes(q) ||
        (s.mode || '').toLowerCase().includes(q) ||
        (s.status || '').toLowerCase().includes(q) ||
        (s.template || '').toLowerCase().includes(q)
      )
    })
  }, [scans, searchQuery])

  if (err) return <div className="card p-6 text-rose-400 border border-rose-500/30 bg-rose-500/10">{err}</div>
  if (!scans) return <div className="flex justify-center py-24"><Loader2 className="animate-spin text-cyan-400" size={32} /></div>

  return (
    <div className="space-y-6 motion-fade-up">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Assessments</h1>
          <p className="text-xs text-slate-400">Blackbox REST & Whitebox Code Review Jobs</p>
        </div>
        <button onClick={fetchScans} className="btn-ghost text-xs self-start sm:self-auto">
          <RefreshCw size={14} /> Refresh Matrix
        </button>
      </div>

      {/* Vision UI Search Input */}
      <div className="relative">
        <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter scans by target URL, mode, status, or engine..."
          className="input !pl-10 text-sm"
        />
      </div>

      {filteredScans.length === 0 ? (
        <div className="card p-16 text-center">
          <Radar className="mx-auto text-cyan-400/50 mb-3" size={44} />
          <p className="text-slate-300 font-medium">
            {searchQuery.trim() ? 'No scans match your query.' : 'No active scans yet. Launch a new assessment.'}
          </p>
          {searchQuery.trim() && (
            <button onClick={() => setSearchQuery('')} className="mt-3 text-xs text-cyan-300 font-bold hover:underline">
              Clear Filter
            </button>
          )}
        </div>
      ) : (
        <div className="card overflow-hidden border border-white/15 rounded-2xl shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[760px] glass-table">
              <thead>
                <tr>
                  <th className="px-5 py-4">Target</th>
                  <th className="px-5 py-4">Mode</th>
                  <th className="px-5 py-4">Status</th>
                  <th className="px-5 py-4">Findings</th>
                  <th className="px-5 py-4">Risk Score</th>
                  <th className="px-5 py-4">Tokens</th>
                  <th className="px-5 py-4">Created At</th>
                  <th className="px-5 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((s, idx) => {
                  const isBottomRow = idx >= filteredScans.length - 2 && filteredScans.length > 2
                  return (
                    <tr
                      key={s.id}
                      onClick={() => nav(`/app/scans/${s.id}`)}
                      className="cursor-pointer transition-colors duration-200"
                    >
                      <td className="px-5 py-3.5 max-w-[220px] truncate">
                        <Link to={`/app/scans/${s.id}`} className="text-white hover:text-cyan-300 font-bold transition-colors">
                          {s.target}
                        </Link>
                      </td>
                      <td className="px-5 py-3.5 text-slate-300 font-medium capitalize">{s.mode}</td>
                      <td className="px-5 py-3.5">
                        <span className={`chip text-[10px] border ${STATUS_STYLE[s.status] || STATUS_STYLE.stopped}`}>{s.status}</span>
                        {(s.status === 'running' || s.status === 'paused') && (
                          <div className="mt-1.5 flex items-center gap-2">
                            <div className="h-1.5 w-24 rounded-full bg-slate-900 overflow-hidden border border-white/10">
                              <div
                                className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-500 shadow-[0_0_8px_rgba(0,242,254,0.6)]"
                                style={{ width: `${Math.round(s.progress || 0)}%` }}
                              />
                            </div>
                            <span className="text-[10px] font-bold text-cyan-300">{Math.round(s.progress || 0)}%</span>
                          </div>
                        )}
                      </td>
                      <td className="px-5 py-3.5 text-slate-200 font-bold">{s.findings_count ?? '—'}</td>
                      <td className="px-5 py-3.5 font-extrabold text-white">{(s.risk_score ?? 0).toFixed(1)}</td>
                      <td className="px-5 py-3.5 text-slate-400 text-xs font-mono">{fmtTokens(s.token_usage)}</td>
                      <td className="px-5 py-3.5 text-slate-400 text-xs">{new Date(s.created_at).toLocaleString()}</td>

                      {/* Action Menu */}
                      <td className="px-5 py-3.5 text-right relative">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setActiveMenu(activeMenu === s.id ? null : s.id)
                          }}
                          className="p-1.5 rounded-xl text-slate-400 hover:text-cyan-300 hover:bg-white/10 transition-colors"
                          title="Actions"
                        >
                          {actionBusy === s.id ? <Loader2 size={16} className="animate-spin text-cyan-400" /> : <MoreVertical size={16} />}
                        </button>

                        {activeMenu === s.id && (
                          <div
                            ref={menuRef}
                            className={`absolute right-5 ${isBottomRow ? 'bottom-10' : 'top-12'} z-50 w-48 rounded-xl glass-deep border border-white/20 shadow-2xl p-1.5 space-y-1 text-left backdrop-blur-2xl`}
                          >
                            {!isClient && (
                              <button
                                onClick={(e) => handleReRun(s.id, e)}
                                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-200 hover:bg-white/10 rounded-lg transition-colors font-semibold"
                              >
                                <Play size={14} className="text-cyan-400" /> Run Again
                              </button>
                            )}
                            <button
                              onClick={(e) => handleDownloadReport(s.id, e)}
                              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-200 hover:bg-white/10 rounded-lg transition-colors font-semibold"
                            >
                              <FileDown size={14} className="text-emerald-400" /> Download Report
                            </button>
                            {!isClient && (
                              <>
                                <div className="border-t border-white/10 my-1" />
                                <button
                                  onClick={(e) => handleDelete(s.id, e)}
                                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors font-semibold"
                                >
                                  <Trash2 size={14} /> Delete Scan
                                </button>
                              </>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {reportModalScanId && (
        <ReportModal
          isOpen={Boolean(reportModalScanId)}
          onClose={() => setReportModalScanId(null)}
          scanId={reportModalScanId}
        />
      )}
    </div>
  )
}

