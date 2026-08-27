import React, { useEffect, useState, useRef, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Loader2, Radar, MoreVertical, Play, FileDown, Trash2, RefreshCw, Search,
  Coins, Sparkles, Activity, Folder, FolderPlus, ChevronDown, ChevronRight,
  Plus, Layers, List, Check, ShieldAlert, Bug, Globe, AlertCircle, X
} from 'lucide-react'
import { api, apiFetch } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'
import { getSocket } from '../lib/socket.js'
import { ScanListSkeleton } from '../components/SkeletonLoader.jsx'
import Tooltip from '../components/Tooltip.jsx'
import ReportModal from '../components/ReportModal.jsx'
import NewScanModal from '../components/NewScanModal.jsx'

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
  queued: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/50 shadow-[0_0_10px_rgba(99,102,241,0.25)]',
}

export default function Scans() {
  const { user } = useAuth()
  const isClient = user?.role === 'client'
  const [scans, setScans] = useState(null)
  const [projects, setProjects] = useState([])
  const [err, setErr] = useState('')
  const [activeMenu, setActiveMenu] = useState(null)
  const [actionBusy, setActionBusy] = useState(null)
  const [reportModalScanId, setReportModalScanId] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [viewMode, setViewMode] = useState('folder') // 'folder' | 'table'
  const [openFolders, setOpenFolders] = useState({ _standalone: true })
  
  // Folder Creation Modal State
  const [showFolderModal, setShowFolderModal] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [newFolderDesc, setNewFolderDesc] = useState('')
  const [creatingFolder, setCreatingFolder] = useState(false)
  const [folderErr, setFolderErr] = useState('')

  // New Scan Modal from Scans Page
  const [scanModalOpen, setScanModalOpen] = useState(false)
  const [scanModalFolderId, setScanModalFolderId] = useState('')

  const nav = useNavigate()
  const menuRef = useRef(null)

  useEffect(() => {
    fetchData()
    const t = setInterval(fetchScansOnly, 6000)
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

  function fetchData() {
    api.projects().then((projs) => {
      const pList = Array.isArray(projs) ? projs : []
      setProjects(pList)
      // Open all folders by default
      const initialOpen = { _standalone: true }
      pList.forEach(p => { initialOpen[p.id] = true })
      setOpenFolders(prev => ({ ...initialOpen, ...prev }))
    }).catch(() => {})

    fetchScansOnly()
  }

  function fetchScansOnly() {
    api.scans()
      .then((res) => {
        setErr('')
        if (Array.isArray(res)) {
          setScans(res)
        } else if (res && Array.isArray(res.scans)) {
          setScans(res.scans)
        } else if (res && res.error) {
          setErr(res.error)
          setScans((prev) => prev || [])
        } else {
          setScans((prev) => prev || [])
        }
      })
      .catch((e) => {
        setErr(e.message || 'Failed to load scans')
        setScans((prev) => prev || [])
      })
  }

  function toggleFolder(folderId) {
    setOpenFolders((prev) => ({
      ...prev,
      [folderId]: !prev[folderId]
    }))
  }

  function expandAllFolders() {
    const all = { _standalone: true }
    projects.forEach(p => { all[p.id] = true })
    setOpenFolders(all)
  }

  function collapseAllFolders() {
    setOpenFolders({})
  }

  async function handleCreateNewFolder(e) {
    e.preventDefault()
    if (!newFolderName.trim()) return
    setCreatingFolder(true)
    setFolderErr('')
    try {
      const res = await api.createProject({
        name: newFolderName.trim(),
        description: newFolderDesc.trim()
      })
      if (res && res.id) {
        setProjects((prev) => [res, ...prev])
        setOpenFolders((prev) => ({ ...prev, [res.id]: true }))
        setNewFolderName('')
        setNewFolderDesc('')
        setShowFolderModal(false)
      }
    } catch (e2) {
      setFolderErr(e2.message || 'Failed to create folder')
    } finally {
      setCreatingFolder(false)
    }
  }

  async function handleResume(id, e) {
    if (e) e.stopPropagation()
    setActionBusy(id)
    try {
      await api.resumeScan(id)
      fetchScansOnly()
      nav(`/app/scans/${id}`)
    } catch (err2) {
      alert(`Resume failed: ${err2.message}`)
    } finally {
      setActionBusy(null)
      setActiveMenu(null)
    }
  }

  async function handleDelete(id, e) {
    if (e) e.stopPropagation()
    // Optimistic: remove immediately, restore on failure
    const prevScans = scans
    setScans((prev) => (prev || []).filter((s) => s.id !== id))
    setActiveMenu(null)
    try {
      await api.deleteScan(id)
    } catch (err2) {
      setScans(prevScans)
      alert(`Delete failed: ${err2.message}`)
    } finally {
      setActionBusy(null)
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
        fetchScansOnly()
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

  function handleOpenScanModalForFolder(folderId, e) {
    if (e) e.stopPropagation()
    setScanModalFolderId(folderId || '')
    setScanModalOpen(true)
  }

  async function handleDeleteFolder(folderId, folderName, e) {
    if (e) e.stopPropagation()
    if (!window.confirm(`Are you sure you want to delete folder "${folderName}"? Associated scans will be kept safe as Standalone Scans.`)) return
    try {
      await api.deleteProject(folderId)
      setProjects((prev) => (prev || []).filter((p) => p.id !== folderId))
      fetchScansOnly()
    } catch (err2) {
      alert(`Delete folder failed: ${err2.message}`)
    }
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

  // Group scans by folder / project
  const folderGroups = useMemo(() => {
    if (!filteredScans) return []
    const projectMap = new Map(projects.map(p => [p.id, p]))
    
    // Group scans
    const groups = projects.map(p => ({
      id: p.id,
      name: p.name,
      client: p.client,
      description: p.description,
      isFolder: true,
      scans: filteredScans.filter(s => s.project_id === p.id)
    }))

    // Standalone scans (not assigned to any known folder)
    const standaloneScans = filteredScans.filter(s => !s.project_id || !projectMap.has(s.project_id))
    if (standaloneScans.length > 0 || projects.length === 0) {
      groups.push({
        id: '_standalone',
        name: 'Standalone Assessments (No Folder)',
        client: '',
        description: 'Scans executed outside of project folders',
        isFolder: false,
        scans: standaloneScans
      })
    }

    return groups
  }, [filteredScans, projects])

  if (scans === null && !err) return <ScanListSkeleton />

  // Render a scans table component
  const renderScansTable = (scanList, isSubTable = false) => {
    if (!scanList || scanList.length === 0) {
      return (
        <div className="py-8 text-center text-slate-500 text-xs">
          No assessment scans in this folder yet.
        </div>
      )
    }

    return (
      <div className="overflow-x-auto">
        <table className="w-full text-sm min-w-[760px] glass-table">
          <thead>
            <tr>
              <th className="px-5 py-3.5">Target</th>
              <th className="px-5 py-3.5">Mode</th>
              <th className="px-5 py-3.5">Status</th>
              <th className="px-5 py-3.5">Findings</th>
              <th className="px-5 py-3.5">Risk Score</th>
              <th className="px-5 py-3.5">Tokens</th>
              <th className="px-5 py-3.5">Created At</th>
              <th className="px-5 py-3.5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {scanList.map((s, idx) => {
              const isBottomRow = idx >= scanList.length - 2 && scanList.length > 2
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
                        {(s.status === 'interrupted' || s.status === 'paused') && (
                          <button
                            onClick={(e) => handleResume(s.id, e)}
                            className="w-full flex items-center gap-2 px-3 py-2 text-xs text-amber-300 hover:bg-amber-500/10 rounded-lg transition-colors font-semibold"
                          >
                            <Play size={14} className="text-amber-400" /> Resume Scan
                          </button>
                        )}
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
                          <button
                            onClick={(e) => handleDelete(s.id, e)}
                            className="w-full flex items-center gap-2 px-3 py-2 text-xs text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors font-semibold"
                          >
                            <Trash2 size={14} className="text-rose-400" /> Delete Scan
                          </button>
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
    )
  }

  return (
    <div className="space-y-6 motion-fade-up">
      {/* Top Header Banner with Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Assessments</h1>
          <p className="text-xs text-slate-400">Blackbox REST & Whitebox Code Review Jobs organized by Folder</p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => setShowFolderModal(true)}
            className="btn-secondary text-xs py-2 px-3.5 flex items-center gap-2 border-cyan-400/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-300 font-bold shadow-md transition-all cursor-pointer"
          >
            <FolderPlus size={16} className="text-cyan-400" />
            <span>+ Add New Folder</span>
          </button>

          <button
            type="button"
            onClick={() => handleOpenScanModalForFolder('')}
            className="btn-primary text-xs py-2 px-3.5 shadow-glow flex items-center gap-1.5 font-bold cursor-pointer"
          >
            <Plus size={15} />
            <span>+ New Assessment</span>
          </button>

          <button onClick={fetchData} className="btn-ghost text-xs p-2.5 cursor-pointer" title="Refresh Matrix">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {err && (
        <div className="card p-4 text-rose-300 border border-rose-500/40 bg-rose-500/10 flex items-center justify-between gap-3 shadow-lg animate-in fade-in">
          <div className="flex items-center gap-2.5 text-xs font-semibold">
            <AlertCircle size={18} className="text-rose-400 shrink-0" />
            <span>{err}</span>
          </div>
          <button
            type="button"
            onClick={() => { setErr(''); fetchData() }}
            className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5 border-rose-500/30 text-rose-300 hover:bg-rose-500/20 font-bold cursor-pointer"
          >
            <RefreshCw size={13} /> Retry
          </button>
        </div>
      )}

      {/* Controls Bar: Search & View Switcher */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter scans by target URL, mode, status, or engine..."
            className="input !pl-10 text-sm w-full"
          />
        </div>

        <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
          {viewMode === 'folder' && (
            <div className="flex items-center gap-2 mr-2">
              <button
                onClick={expandAllFolders}
                className="text-[11px] font-semibold text-slate-400 hover:text-cyan-300 transition-colors px-1.5 py-1"
              >
                Expand All
              </button>
              <span className="text-slate-600 text-xs">•</span>
              <button
                onClick={collapseAllFolders}
                className="text-[11px] font-semibold text-slate-400 hover:text-cyan-300 transition-colors px-1.5 py-1"
              >
                Collapse All
              </button>
            </div>
          )}

          <div className="flex rounded-xl bg-slate-900/80 p-1 border border-white/10">
            <button
              onClick={() => setViewMode('folder')}
              title="Folder Grouped View"
              className={`p-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                viewMode === 'folder'
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Layers size={14} />
              <span className="hidden md:inline">Folders</span>
            </button>
            <button
              onClick={() => setViewMode('table')}
              title="Flat Table View"
              className={`p-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                viewMode === 'table'
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20 font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <List size={14} />
              <span className="hidden md:inline">All Scans</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Scans Listing Content */}
      {filteredScans.length === 0 && projects.length === 0 ? (
        <div className="card p-16 text-center">
          <Radar className="mx-auto text-cyan-400/50 mb-3" size={44} />
          <p className="text-slate-300 font-medium">
            {searchQuery.trim() ? 'No scans match your query.' : 'No active scans yet. Create a folder or launch a new assessment.'}
          </p>
          <div className="mt-4 flex items-center justify-center gap-3">
            <button onClick={() => setShowFolderModal(true)} className="btn-ghost text-xs">
              <FolderPlus size={14} /> Create First Folder
            </button>
            <button onClick={() => handleOpenScanModalForFolder('')} className="btn-primary text-xs shadow-glow">
              <Plus size={14} /> Launch Scan
            </button>
          </div>
        </div>
      ) : viewMode === 'folder' ? (
        /* ── Group by Folder (Collapsible Sections) ─────────────────── */
        <div className="space-y-4">
          {folderGroups.map((group) => {
            const isOpen = Boolean(openFolders[group.id])
            const totalFindings = group.scans.reduce((acc, s) => acc + (s.findings_count || 0), 0)

            return (
              <div
                key={group.id}
                className="card overflow-hidden border border-white/15 rounded-2xl shadow-xl transition-all duration-300"
              >
                {/* Collapsible Folder Header Bar */}
                <div
                  onClick={() => toggleFolder(group.id)}
                  className="px-5 py-4 bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-slate-950/90 hover:bg-slate-800/80 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 select-none transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <button
                      type="button"
                      className="p-1 rounded-lg hover:bg-white/10 text-slate-400 hover:text-cyan-300 transition-colors shrink-0"
                      aria-label={isOpen ? "Collapse folder" : "Expand folder"}
                    >
                      {isOpen ? <ChevronDown size={18} className="text-cyan-400" /> : <ChevronRight size={18} />}
                    </button>

                    <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
                      <Folder size={18} />
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h2 className="text-sm sm:text-base font-bold text-white tracking-tight truncate">
                          {group.name}
                        </h2>
                        {group.client && (
                          <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/10 text-slate-300 border border-white/10">
                            {group.client}
                          </span>
                        )}
                      </div>
                      {group.description && (
                        <p className="text-xs text-slate-400 truncate mt-0.5">{group.description}</p>
                      )}
                    </div>
                  </div>

                  {/* Right Badges & Folder Quick Action */}
                  <div className="flex items-center gap-2.5 shrink-0 self-end sm:self-auto" onClick={(e) => e.stopPropagation()}>
                    <span className="chip text-[11px] px-2.5 py-1 bg-slate-950/60 border-white/10 text-slate-300 font-bold">
                      {group.scans.length} {group.scans.length === 1 ? 'Scan' : 'Scans'}
                    </span>

                    {totalFindings > 0 && (
                      <span className="chip text-[11px] px-2.5 py-1 bg-rose-500/15 border-rose-500/30 text-rose-300 font-bold flex items-center gap-1">
                        <Bug size={12} className="text-rose-400" /> {totalFindings} Findings
                      </span>
                    )}

                    <button
                      onClick={(e) => handleOpenScanModalForFolder(group.id === '_standalone' ? '' : group.id, e)}
                      className="btn-ghost text-[11px] py-1.5 px-3 border-cyan-500/30 text-cyan-300 hover:border-cyan-400 hover:bg-cyan-500/20"
                      title="Launch new scan in this folder"
                    >
                      <Plus size={12} /> Launch Scan
                    </button>

                    {!isClient && group.id !== '_standalone' && (
                      <button
                        onClick={(e) => handleDeleteFolder(group.id, group.name, e)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                        title={`Delete folder "${group.name}"`}
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Collapsible Content */}
                {isOpen && (
                  <div className="animate-in fade-in duration-200">
                    {renderScansTable(group.scans, true)}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      ) : (
        /* ── Flat Table View ───────────────────────────────────────── */
        <div className="card overflow-hidden border border-white/15 rounded-2xl shadow-2xl">
          {renderScansTable(filteredScans, false)}
        </div>
      )}

      {/* ── Create New Folder Modal ─────────────────────────────────── */}
      {showFolderModal && (
        <div className="fixed inset-0 z-50 grid place-items-center glass-overlay p-4 overflow-y-auto" onClick={() => setShowFolderModal(false)}>
          <div className="card w-full max-w-md glass-in my-auto shadow-2xl p-6 relative bg-slate-950/90 border border-white/20" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-400">
                  <FolderPlus size={20} />
                </div>
                <h3 className="text-base font-bold text-white">Create New Project Folder</h3>
              </div>
              <button onClick={() => setShowFolderModal(false)} className="text-slate-400 hover:text-white cursor-pointer">
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreateNewFolder} className="space-y-4">
              {folderErr && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                  <AlertCircle size={14} className="shrink-0" />
                  <span>{folderErr}</span>
                </div>
              )}

              <div>
                <label className="label">Folder Name *</label>
                <input
                  type="text"
                  required
                  autoFocus
                  value={newFolderName}
                  onChange={(e) => setNewFolderName(e.target.value)}
                  placeholder="e.g. Production Web App, API Services, E-Commerce"
                  className="input text-sm"
                />
              </div>

              <div>
                <label className="label">Description (Optional)</label>
                <input
                  type="text"
                  value={newFolderDesc}
                  onChange={(e) => setNewFolderDesc(e.target.value)}
                  placeholder="e.g. Monthly vulnerability audit scope"
                  className="input text-sm"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowFolderModal(false)}
                  className="btn-ghost text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingFolder || !newFolderName.trim()}
                  className="btn-primary text-xs shadow-glow"
                >
                  {creatingFolder && <Loader2 size={14} className="animate-spin" />}
                  <span>{creatingFolder ? 'Creating Folder...' : 'Create Folder'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── New Scan Modal ───────────────────────────────────────────── */}
      {scanModalOpen && (
        <NewScanModal
          onClose={() => setScanModalOpen(false)}
          onStarted={(scanId) => {
            setScanModalOpen(false)
            fetchData()
            nav(`/app/scans/${scanId}`)
          }}
          initialProjectId={scanModalFolderId}
        />
      )}

      {/* ── Report Modal ─────────────────────────────────────────────── */}
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
