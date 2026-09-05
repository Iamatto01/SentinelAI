import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Users, Shield, Search, RefreshCw, AlertCircle, CheckCircle2,
  Calendar, Layers, Edit3, X, Loader2, Sparkles, Filter, Check, TrendingUp,
  FolderOpen, FolderPlus, Play, FileText, Download, ExternalLink, Globe, FileCode2,
  Zap, Clock, ArrowRight, ShieldAlert
} from 'lucide-react'
import { api } from '../lib/api.js'

const BLACKBOX_MODULES = ['nmap', 'httpx', 'whatweb', 'wafw00f', 'subfinder', 'amass', 'dnsbrute', 'katana', 'ffuf', 'gobuster', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'arjun', 'wpscan']

export default function ClientsManagement() {
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState([])
  const [overview, setOverview] = useState(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all') // all, active, expired, inactive

  // Customer Folder Drawer / Modal state
  const [folderClient, setFolderClient] = useState(null)
  const [folderData, setFolderData] = useState(null)
  const [folderLoading, setFolderLoading] = useState(false)
  const [folderTab, setFolderTab] = useState('projects') // 'projects' | 'scans' | 'findings' | 'run-scan'

  // Edit Subscription Quota Modal state
  const [editingClient, setEditingClient] = useState(null)
  const [editPlanId, setEditPlanId] = useState('pro')
  const [editQuotaTotal, setEditQuotaTotal] = useState(50)
  const [editStatus, setEditStatus] = useState('active')
  const [editDays, setEditDays] = useState(30)

  // Add Client Project inline form
  const [showAddProject, setShowAddProject] = useState(false)
  const [newProjName, setNewProjName] = useState('')
  const [newProjScope, setNewProjScope] = useState('')
  const [newProjDesc, setNewProjDesc] = useState('')
  const [creatingProj, setCreatingProj] = useState(false)

  // Run Scan on behalf of Client form state
  const [runScanMode, setRunScanMode] = useState('blackbox') // 'blackbox' | 'whitebox'
  const [runScanTarget, setRunScanTarget] = useState('')
  const [runScanProjectId, setRunScanProjectId] = useState('')
  const [runScanDeductQuota, setRunScanDeductQuota] = useState(true)
  const [runScanModules, setRunScanModules] = useState(BLACKBOX_MODULES)
  const [runScanVerify, setRunScanVerify] = useState(true)
  const [runScanBusy, setRunScanBusy] = useState(false)

  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const loadData = async () => {
    setLoading(true)
    setError('')
    try {
      const [clientsRes, overRes] = await Promise.all([
        api.adminClients().catch(e => { throw new Error(e.message || 'Failed to fetch clients') }),
        api.adminOverview().catch(() => null),
      ])
      setClients(clientsRes.clients || [])
      setOverview(overRes)
    } catch (err) {
      setError(err.message || 'Failed to load client management data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  // Open Customer Folder
  const handleOpenFolder = async (c, defaultTab = 'projects') => {
    setFolderClient(c)
    setFolderTab(defaultTab)
    setFolderLoading(true)
    setFolderData(null)
    setShowAddProject(false)
    setError('')
    try {
      const details = await api.adminClientDetails(c.id)
      setFolderData(details)
      if (details.projects && details.projects.length > 0) {
        setRunScanProjectId(details.projects[0].id)
      } else {
        setRunScanProjectId('')
      }
    } catch (err) {
      setError(`Failed to load folder details for ${c.username}: ${err.message}`)
    } finally {
      setFolderLoading(false)
    }
  }

  // Refresh current folder
  const reloadCurrentFolder = async () => {
    if (!folderClient) return
    try {
      const details = await api.adminClientDetails(folderClient.id)
      setFolderData(details)
    } catch { /* ignore */ }
  }

  // Create Project for Client
  const handleCreateClientProject = async (e) => {
    e.preventDefault()
    if (!folderClient || !newProjName.trim()) return
    setCreatingProj(true)
    setError('')
    try {
      await api.adminCreateClientProject(folderClient.id, {
        name: newProjName.trim(),
        scope: newProjScope.trim(),
        description: newProjDesc.trim(),
      })
      setSuccess(`✅ Project "${newProjName}" successfully created for ${folderClient.username}!`)
      setNewProjName('')
      setNewProjScope('')
      setNewProjDesc('')
      setShowAddProject(false)
      await reloadCurrentFolder()
      await loadData()
    } catch (err) {
      setError(err.message || 'Failed to create project for client')
    } finally {
      setCreatingProj(false)
    }
  }

  // Help Run Scan on behalf of Client
  const handleLaunchClientScan = async (e) => {
    e.preventDefault()
    if (!folderClient) return
    if (runScanMode === 'blackbox' && !runScanTarget.trim()) {
      setError('Please enter a target URL / domain for the assessment')
      return
    }

    setRunScanBusy(true)
    setError('')
    setSuccess('')
    try {
      let res
      if (runScanMode === 'blackbox') {
        res = await api.startScan({
          mode: 'blackbox',
          target: runScanTarget.trim(),
          projectId: runScanProjectId || null,
          targetUserId: folderClient.id,
          deductQuota: runScanDeductQuota,
          modules: runScanModules,
          objective: 'offensive',
          depth: 'offensive',
          verify: runScanVerify,
        })
      } else {
        res = await api.startScan({
          mode: 'whitebox',
          target: runScanTarget.trim() || `audit-${folderClient.username}`,
          projectId: runScanProjectId || null,
          targetUserId: folderClient.id,
          deductQuota: runScanDeductQuota,
          files: [{ path: 'app.js', content: '// Source audit placeholder\nconsole.log("Client Codebase Audit");' }],
          language: 'javascript',
          focus: 'security',
          verify: runScanVerify,
          depth: 'offensive',
        })
      }

      setSuccess(`🚀 Scan successfully launched for ${folderClient.username}! (Scan ID: ${res.scan.id})`)
      setRunScanTarget('')
      setFolderTab('scans')
      await reloadCurrentFolder()
      await loadData()
    } catch (err) {
      setError(err.message || 'Failed to launch scan for client')
    } finally {
      setRunScanBusy(false)
    }
  }

  // Edit Subscription Quota
  const handleOpenEdit = (c) => {
    setEditingClient(c)
    setEditPlanId(c.plan_id === 'enterprise' ? 'enterprise' : 'pro')
    setEditQuotaTotal(c.scan_quota_total || 50)
    setEditStatus(c.effective_status === 'expired' ? 'active' : (c.sub_status || 'active'))
    setEditDays(30)
    setError('')
    setSuccess('')
  }

  const handleSaveClient = async (e) => {
    e.preventDefault()
    if (!editingClient) return
    setSaving(true)
    setError('')
    setSuccess('')
    try {
      await api.adminUpdateClientSubscription(editingClient.id, {
        planId: editPlanId,
        quotaTotal: Number(editQuotaTotal),
        status: editStatus,
        extendDays: Number(editDays),
      })
      setSuccess(`✅ Successfully updated subscription for ${editingClient.username}!`)
      setEditingClient(null)
      await loadData()
      if (folderClient && folderClient.id === editingClient.id) {
        await reloadCurrentFolder()
      }
    } catch (err) {
      setError(err.message || 'Failed to update client subscription')
    } finally {
      setSaving(false)
    }
  }

  const toggleRunModule = (m) => {
    setRunScanModules(p => p.includes(m) ? p.filter(x => x !== m) : [...p, m])
  }

  const filtered = clients.filter(c => {
    const term = search.toLowerCase()
    const matchesSearch =
      (c.username || '').toLowerCase().includes(term) ||
      (c.email || '').toLowerCase().includes(term) ||
      (c.github_username || '').toLowerCase().includes(term)

    if (statusFilter === 'active') return matchesSearch && c.effective_status === 'active'
    if (statusFilter === 'expired') return matchesSearch && c.effective_status === 'expired'
    if (statusFilter === 'inactive') return matchesSearch && (c.effective_status === 'inactive' || !c.sub_status)
    return matchesSearch
  })

  return (
    <div className="space-y-6 animate-in fade-in duration-300 pb-16">
      {/* Top Banner */}
      <div className="card p-6 border-white/10 relative overflow-hidden bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-indigo-950/40">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <Users size={160} className="text-cyan-400" />
        </div>

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Users size={22} />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Client Management & Customer Folders</h1>
              <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30 uppercase tracking-wide">
                Admin Control Center
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Inspect customer workspaces, view generated reports, manage scan quotas, and execute automated audits directly on behalf of clients.
            </p>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="btn-secondary text-xs py-2 px-3.5 flex items-center gap-1.5 self-start md:self-auto cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh List
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-slate-400 font-semibold">Total Registered Clients</div>
          <div className="text-2xl font-black text-white mt-1">{clients.length}</div>
        </div>
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-emerald-400 font-semibold">Active Subscriptions</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">
            {clients.filter(c => c.effective_status === 'active').length}
          </div>
        </div>
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-rose-400 font-semibold">Expired / Inactive</div>
          <div className="text-2xl font-black text-rose-400 mt-1">
            {clients.filter(c => c.effective_status === 'expired' || c.effective_status === 'inactive').length}
          </div>
        </div>
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-cyan-400 font-semibold">Total Scans Executed</div>
          <div className="text-2xl font-black text-cyan-300 mt-1">
            {clients.reduce((acc, c) => acc + (Number(c.total_scans) || 0), 0)}
          </div>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 flex items-center gap-3 text-sm">
          <AlertCircle size={18} className="shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}
      {success && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-3 text-sm">
          <CheckCircle2 size={18} className="shrink-0 text-emerald-400" />
          <span>{success}</span>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="card p-4 border-white/10 bg-slate-950/60 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-80">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by username, email, or GitHub..."
            className="input !py-2 !pl-9 text-xs w-full"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-slate-400 font-semibold">Status:</span>
          {['all', 'active', 'expired', 'inactive'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold capitalize transition-all cursor-pointer ${
                statusFilter === st
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                  : 'bg-slate-900 border border-white/10 text-slate-400 hover:text-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Clients Table */}
      <div className="card overflow-hidden border-white/10 bg-slate-950/70">
        <div className="p-4 border-b border-white/10 flex items-center justify-between bg-slate-900/40">
          <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
            <FolderOpen size={16} className="text-cyan-400" />
            <span>Click any client to open their Customer Workspace Folder</span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">Showing {filtered.length} clients</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 border-b border-white/10 text-slate-400 uppercase font-bold text-[10px] tracking-wider">
              <tr>
                <th className="px-5 py-3.5">Client User</th>
                <th className="px-5 py-3.5">Plan & Quota</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5">GitHub Account</th>
                <th className="px-5 py-3.5">Scans Run</th>
                <th className="px-5 py-3.5">Next Expiry</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-5 py-8 text-center text-slate-500">
                    No clients found matching your search criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((c) => {
                  const isUnlimited = (c.scan_quota_total || 0) >= 9000
                  const used = c.scan_quota_used || 0
                  const total = c.scan_quota_total || 0
                  const pct = isUnlimited ? 100 : Math.min(100, Math.round((used / (total || 1)) * 100))

                  return (
                    <tr
                      key={c.id}
                      onClick={() => handleOpenFolder(c)}
                      className="hover:bg-cyan-500/5 transition-all cursor-pointer group"
                    >
                      <td className="px-5 py-4">
                        <div>
                          <div className="font-bold text-white text-sm flex items-center gap-1.5">
                            <span>{c.username}</span>
                            <span className="text-[10px] text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-0.5">
                              <FolderOpen size={12} /> Buka Folder
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400">{c.email || 'No email'}</div>
                          {c.role === 'admin' && (
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30 uppercase mt-0.5 inline-block">
                              Administrator
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <div className="font-bold text-cyan-300">{c.plan_name || 'No Plan'}</div>
                        <div className="text-[11px] text-slate-400 mt-1 font-mono">
                          {isUnlimited ? 'Unlimited' : `${used} / ${total} scans (${c.remaining_quota} left)`}
                        </div>
                        <div className="w-24 h-1.5 bg-slate-900 rounded-full overflow-hidden mt-1 border border-white/10">
                          <div
                            className={`h-full ${pct > 80 ? 'bg-red-500' : 'bg-cyan-400'}`}
                            style={{ width: `${isUnlimited ? 100 : pct}%` }}
                          />
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border ${
                          c.effective_status === 'active'
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                            : c.effective_status === 'expired'
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                            : 'bg-slate-700/30 text-slate-400 border-slate-600/30'
                        }`}>
                          {c.effective_status}
                        </span>
                      </td>

                      <td className="px-5 py-4 font-mono text-slate-300">
                        {c.github_username ? (
                          <span className="text-cyan-400 flex items-center gap-1">
                            @{c.github_username}
                          </span>
                        ) : (
                          <span className="text-slate-600">Not linked</span>
                        )}
                      </td>

                      <td className="px-5 py-4 font-bold text-white">
                        {c.total_scans || 0}
                      </td>

                      <td className="px-5 py-4 text-slate-400">
                        {c.current_period_end ? (
                          <span className={c.isExpired ? 'text-rose-400 font-bold' : ''}>
                            {new Date(c.current_period_end).toLocaleDateString()}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      <td className="px-5 py-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleOpenFolder(c, 'run-scan')}
                            className="btn-primary text-[11px] !py-1.5 !px-2.5 flex items-center gap-1 cursor-pointer bg-gradient-to-r from-cyan-500 to-blue-600"
                            title="Help client launch an assessment"
                          >
                            <Play size={12} fill="currentColor" /> Run Scan
                          </button>
                          <button
                            onClick={() => handleOpenEdit(c)}
                            className="btn-secondary text-[11px] !py-1.5 !px-2.5 hover:border-cyan-400/50 hover:text-cyan-300 inline-flex items-center gap-1 cursor-pointer"
                            title="Edit Plan Quota & Expiry"
                          >
                            <Edit3 size={12} /> Quota
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* CUSTOMER FOLDER MODAL / DRAWER */}
      {/* ========================================================================= */}
      {folderClient && (
        <div
          className="fixed inset-0 z-50 grid place-items-center glass-overlay p-3 sm:p-6 overflow-y-auto"
          onClick={() => setFolderClient(null)}
        >
          <div
            className="card w-full max-w-4xl max-h-[92vh] overflow-hidden glass-in border-cyan-500/30 flex flex-col relative my-auto shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Folder Header */}
            <div className="p-6 border-b border-white/10 bg-slate-900/90 relative">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                    <FolderOpen size={24} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-xl font-bold text-white tracking-tight">{folderClient.username}</h2>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold uppercase">
                        {folderClient.plan_name || 'Starter Plan'}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border ${
                        folderClient.effective_status === 'active'
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      }`}>
                        {folderClient.effective_status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
                      <span>{folderClient.email || 'No email attached'}</span>
                      <span>&bull;</span>
                      <span>Joined: {new Date(folderClient.joined_at || Date.now()).toLocaleDateString()}</span>
                    </p>
                  </div>
                </div>

                {/* Header Action Buttons */}
                <div className="flex items-center gap-2 self-start sm:self-auto">
                  <button
                    onClick={() => setFolderTab('run-scan')}
                    className={`btn-primary text-xs py-2 px-3 flex items-center gap-1.5 cursor-pointer ${
                      folderTab === 'run-scan' ? 'ring-2 ring-cyan-400' : ''
                    }`}
                  >
                    <Play size={13} fill="currentColor" /> Tolong Run Scan
                  </button>
                  <button
                    onClick={() => handleOpenEdit(folderClient)}
                    className="btn-secondary text-xs py-2 px-3 flex items-center gap-1.5 cursor-pointer"
                  >
                    <Edit3 size={13} /> Edit Quota
                  </button>
                  <button
                    onClick={() => setFolderClient(null)}
                    className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors cursor-pointer"
                  >
                    <X size={18} />
                  </button>
                </div>
              </div>

              {/* Folder Navigation Tabs */}
              <div className="flex items-center gap-2 mt-5 pt-3 border-t border-white/10 overflow-x-auto">
                <button
                  onClick={() => setFolderTab('projects')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer shrink-0 ${
                    folderTab === 'projects'
                      ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <FolderOpen size={14} /> Projects & Folders ({folderData?.projects?.length || 0})
                </button>
                <button
                  onClick={() => setFolderTab('scans')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer shrink-0 ${
                    folderTab === 'scans'
                      ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <Shield size={14} /> Scans & Audits ({folderData?.scans?.length || 0})
                </button>
                <button
                  onClick={() => setFolderTab('findings')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer shrink-0 ${
                    folderTab === 'findings'
                      ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                      : 'text-slate-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <ShieldAlert size={14} /> Security Posture & Reports ({folderData?.totalFindings || 0})
                </button>
                <button
                  onClick={() => setFolderTab('run-scan')}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer shrink-0 ml-auto ${
                    folderTab === 'run-scan'
                      ? 'bg-gradient-to-r from-cyan-400 to-blue-500 text-slate-950 font-extrabold shadow-glow'
                      : 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/20'
                  }`}
                >
                  <Zap size={14} /> 🚀 Tolong Run Scan
                </button>
              </div>
            </div>

            {/* Folder Body Content */}
            <div className="p-6 overflow-y-auto max-h-[60vh] space-y-6">
              {folderLoading ? (
                <div className="py-16 text-center space-y-3">
                  <Loader2 size={32} className="animate-spin text-cyan-400 mx-auto" />
                  <p className="text-xs text-slate-400">Loading {folderClient.username}'s workspace folder...</p>
                </div>
              ) : (
                <>
                  {/* TAB 1: PROJECTS & WORKSPACES */}
                  {folderTab === 'projects' && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-bold text-white">Client Projects & Workspaces</h3>
                          <p className="text-xs text-slate-400">Projects owned by or assigned to this customer.</p>
                        </div>
                        <button
                          onClick={() => setShowAddProject(!showAddProject)}
                          className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5 cursor-pointer text-cyan-300 border-cyan-500/30"
                        >
                          <FolderPlus size={14} /> {showAddProject ? 'Cancel' : '+ New Project for Client'}
                        </button>
                      </div>

                      {/* Inline Add Project Form */}
                      {showAddProject && (
                        <form onSubmit={handleCreateClientProject} className="p-4 rounded-2xl bg-slate-900/90 border border-cyan-500/30 space-y-3">
                          <h4 className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                            <FolderPlus size={14} /> Create New Customer Project
                          </h4>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                              <label className="text-[11px] font-semibold text-slate-300 block mb-1">Project Name *</label>
                              <input
                                type="text"
                                className="input text-xs w-full"
                                placeholder="e.g. FMS Production Portal"
                                value={newProjName}
                                onChange={(e) => setNewProjName(e.target.value)}
                                required
                              />
                            </div>
                            <div>
                              <label className="text-[11px] font-semibold text-slate-300 block mb-1">Scope / Target Domains</label>
                              <input
                                type="text"
                                className="input text-xs w-full"
                                placeholder="e.g. https://fms.myces.com"
                                value={newProjScope}
                                onChange={(e) => setNewProjScope(e.target.value)}
                              />
                            </div>
                          </div>
                          <div>
                            <label className="text-[11px] font-semibold text-slate-300 block mb-1">Description / Notes</label>
                            <input
                              type="text"
                              className="input text-xs w-full"
                              placeholder="e.g. Core banking & fleet tracking system"
                              value={newProjDesc}
                              onChange={(e) => setNewProjDesc(e.target.value)}
                            />
                          </div>
                          <div className="flex justify-end gap-2 pt-1">
                            <button
                              type="button"
                              onClick={() => setShowAddProject(false)}
                              className="btn-secondary text-xs py-1.5 px-3 cursor-pointer"
                            >
                              Cancel
                            </button>
                            <button
                              type="submit"
                              disabled={creatingProj}
                              className="btn-primary text-xs py-1.5 px-4 cursor-pointer"
                            >
                              {creatingProj ? 'Creating...' : 'Create & Link Project'}
                            </button>
                          </div>
                        </form>
                      )}

                      {/* Project Cards Grid */}
                      {(!folderData?.projects || folderData.projects.length === 0) ? (
                        <div className="p-8 rounded-2xl bg-slate-900/40 border border-white/5 text-center space-y-3">
                          <FolderOpen size={36} className="text-slate-600 mx-auto" />
                          <p className="text-xs text-slate-400">No projects yet for this client.</p>
                          <button
                            onClick={() => setShowAddProject(true)}
                            className="btn-secondary text-xs py-1.5 px-3 cursor-pointer"
                          >
                            + Create First Project
                          </button>
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          {folderData.projects.map((p) => (
                            <div
                              key={p.id}
                              className="card p-4 bg-slate-900/60 border-white/10 hover:border-cyan-500/40 transition-all space-y-3"
                            >
                              <div className="flex items-start justify-between gap-2">
                                <div className="flex items-center gap-2">
                                  <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                                    <FolderOpen size={18} />
                                  </div>
                                  <div>
                                    <h4 className="font-bold text-white text-sm">{p.name}</h4>
                                    <p className="text-[11px] text-slate-400 font-mono">{p.scope || 'No scope specified'}</p>
                                  </div>
                                </div>
                                <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase border ${
                                  p.risk_level === 'critical' ? 'bg-red-500/20 text-red-300 border-red-500/30' :
                                  p.risk_level === 'high' ? 'bg-orange-500/20 text-orange-300 border-orange-500/30' :
                                  'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                                }`}>
                                  {p.risk_level || 'Normal'}
                                </span>
                              </div>

                              <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-white/5 font-mono">
                                <span>{p.scan_count || 0} Scans</span>
                                <span>{p.finding_count || 0} Findings</span>
                                <button
                                  onClick={() => {
                                    setRunScanProjectId(p.id)
                                    setFolderTab('run-scan')
                                  }}
                                  className="text-cyan-300 hover:underline flex items-center gap-1 font-bold cursor-pointer"
                                >
                                  <Play size={10} fill="currentColor" /> Scan Project
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 2: SCANS & AUDITS */}
                  {folderTab === 'scans' && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-sm font-bold text-white">Scans & Assessment History</h3>
                          <p className="text-xs text-slate-400">All automated pentests and code audits executed for this client.</p>
                        </div>
                        <button
                          onClick={() => setFolderTab('run-scan')}
                          className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5 cursor-pointer"
                        >
                          <Play size={12} fill="currentColor" /> + Launch New Scan
                        </button>
                      </div>

                      {(!folderData?.scans || folderData.scans.length === 0) ? (
                        <div className="p-8 rounded-2xl bg-slate-900/40 border border-white/5 text-center space-y-3">
                          <Shield size={36} className="text-slate-600 mx-auto" />
                          <p className="text-xs text-slate-400">No scans executed yet for this customer.</p>
                          <button
                            onClick={() => setFolderTab('run-scan')}
                            className="btn-primary text-xs py-1.5 px-3 cursor-pointer"
                          >
                            🚀 Tolong Run Scan Pertama
                          </button>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {folderData.scans.map((s) => (
                            <div
                              key={s.id}
                              className="card p-3.5 bg-slate-900/60 border-white/10 hover:border-white/20 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                            >
                              <div className="flex items-center gap-3">
                                <div className="p-2 rounded-xl bg-slate-800 border border-white/10 text-cyan-400">
                                  {s.mode === 'whitebox' ? <FileCode2 size={16} /> : <Globe size={16} />}
                                </div>
                                <div>
                                  <div className="font-bold text-white text-xs flex items-center gap-2">
                                    <span className="text-cyan-300 font-mono">{s.target}</span>
                                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                                      s.status === 'finished' ? 'bg-emerald-500/20 text-emerald-300' :
                                      s.status === 'running' ? 'bg-cyan-500/20 text-cyan-300 animate-pulse' :
                                      'bg-slate-700/30 text-slate-400'
                                    }`}>
                                      {s.status}
                                    </span>
                                  </div>
                                  <div className="text-[10px] text-slate-400 flex items-center gap-2 mt-0.5 font-mono">
                                    <span>{new Date(s.created_at).toLocaleString()}</span>
                                    {s.project_name && <span>&bull; Project: {s.project_name}</span>}
                                    <span>&bull; Findings: <b className="text-rose-400">{s.findings_count || 0}</b></span>
                                  </div>
                                </div>
                              </div>

                              <div className="flex items-center gap-2 shrink-0">
                                <Link
                                  to={`/app/scans/${s.id}`}
                                  className="btn-secondary text-[11px] !py-1 !px-2.5 flex items-center gap-1 hover:text-cyan-300"
                                >
                                  <span>Inspect</span> <ExternalLink size={11} />
                                </Link>
                                <button
                                  onClick={async () => {
                                    try {
                                      const rep = await api.generateReport(s.id, 'low', 'all', 'executive')
                                      if (rep.downloadUrl) window.open(rep.downloadUrl, '_blank')
                                    } catch (e) {
                                      alert(e.message || 'Report generation failed')
                                    }
                                  }}
                                  className="btn-secondary text-[11px] !py-1 !px-2.5 flex items-center gap-1 text-slate-300 hover:text-white"
                                  title="Download Executive PDF Report"
                                >
                                  <Download size={11} /> PDF Report
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB 3: SECURITY POSTURE & FINDINGS */}
                  {folderTab === 'findings' && (
                    <div className="space-y-4">
                      <div>
                        <h3 className="text-sm font-bold text-white">Client Vulnerability Posture</h3>
                        <p className="text-xs text-slate-400">Aggregated security issues found across all projects of {folderClient.username}.</p>
                      </div>

                      {/* Severity Breakdown Badges */}
                      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                        <div className="card p-3 bg-red-950/30 border-red-500/20 text-center">
                          <div className="text-[10px] font-bold uppercase text-red-400">Critical</div>
                          <div className="text-xl font-black text-red-300 mt-1">{folderData?.severityCounts?.critical || 0}</div>
                        </div>
                        <div className="card p-3 bg-orange-950/30 border-orange-500/20 text-center">
                          <div className="text-[10px] font-bold uppercase text-orange-400">High</div>
                          <div className="text-xl font-black text-orange-300 mt-1">{folderData?.severityCounts?.high || 0}</div>
                        </div>
                        <div className="card p-3 bg-yellow-950/30 border-yellow-500/20 text-center">
                          <div className="text-[10px] font-bold uppercase text-yellow-400">Medium</div>
                          <div className="text-xl font-black text-yellow-300 mt-1">{folderData?.severityCounts?.medium || 0}</div>
                        </div>
                        <div className="card p-3 bg-blue-950/30 border-blue-500/20 text-center">
                          <div className="text-[10px] font-bold uppercase text-blue-400">Low</div>
                          <div className="text-xl font-black text-blue-300 mt-1">{folderData?.severityCounts?.low || 0}</div>
                        </div>
                        <div className="card p-3 bg-slate-900/60 border-white/10 text-center col-span-2 sm:col-span-1">
                          <div className="text-[10px] font-bold uppercase text-slate-400">Total Findings</div>
                          <div className="text-xl font-black text-white mt-1">{folderData?.totalFindings || 0}</div>
                        </div>
                      </div>

                      <div className="p-4 rounded-2xl bg-slate-900/60 border border-white/10 flex items-center justify-between">
                        <div>
                          <h4 className="font-bold text-white text-xs">Executive Assessment Summary</h4>
                          <p className="text-[11px] text-slate-400">Download consolidated executive audit reports across all client workspaces.</p>
                        </div>
                        <Link
                          to="/app/findings"
                          className="btn-primary text-xs py-2 px-3.5 flex items-center gap-1.5"
                        >
                          <ShieldAlert size={14} /> Open Findings Center
                        </Link>
                      </div>
                    </div>
                  )}

                  {/* TAB 4: TOLONG RUN SCAN (HELP CLIENT RUN SCAN) */}
                  {folderTab === 'run-scan' && (
                    <form onSubmit={handleLaunchClientScan} className="space-y-4">
                      <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-start gap-3">
                        <Zap size={20} className="text-cyan-400 shrink-0 mt-0.5" />
                        <div className="text-xs">
                          <span className="font-bold text-cyan-300">Run Assessment on Behalf of {folderClient.username}</span>
                          <p className="text-slate-300 mt-0.5">
                            This scan will automatically save into this client's folder, appear in their dashboard, and be tied to their selected project.
                          </p>
                        </div>
                      </div>

                      {/* Mode Selection */}
                      <div className="grid grid-cols-2 gap-3">
                        <button
                          type="button"
                          onClick={() => setRunScanMode('blackbox')}
                          className={`p-3.5 rounded-2xl border text-left transition-all cursor-pointer ${
                            runScanMode === 'blackbox'
                              ? 'border-cyan-400 bg-cyan-500/15 ring-1 ring-cyan-400 shadow-glow'
                              : 'border-white/10 bg-slate-900/60 hover:border-white/20'
                          }`}
                        >
                          <Globe size={18} className={runScanMode === 'blackbox' ? 'text-cyan-400' : 'text-slate-500'} />
                          <div className="text-xs font-bold text-white mt-1.5">Blackbox Pentest</div>
                          <div className="text-[10px] text-slate-400">External URL / Target via Native Kali engine</div>
                        </button>

                        <button
                          type="button"
                          onClick={() => setRunScanMode('whitebox')}
                          className={`p-3.5 rounded-2xl border text-left transition-all cursor-pointer ${
                            runScanMode === 'whitebox'
                              ? 'border-cyan-400 bg-cyan-500/15 ring-1 ring-cyan-400 shadow-glow'
                              : 'border-white/10 bg-slate-900/60 hover:border-white/20'
                          }`}
                        >
                          <FileCode2 size={18} className={runScanMode === 'whitebox' ? 'text-cyan-400' : 'text-slate-500'} />
                          <div className="text-xs font-bold text-white mt-1.5">Whitebox Code Audit</div>
                          <div className="text-[10px] text-slate-400">AI Deep AST Static Analysis & OWASP review</div>
                        </button>
                      </div>

                      {/* Target Client Project */}
                      <div>
                        <label className="text-xs font-bold text-slate-200 block mb-1">
                          Save into Client Project / Folder:
                        </label>
                        <select
                          className="input text-xs w-full"
                          value={runScanProjectId}
                          onChange={(e) => setRunScanProjectId(e.target.value)}
                        >
                          <option value="">-- No Specific Project (Standalone Client Scan) --</option>
                          {(folderData?.projects || []).map(p => (
                            <option key={p.id} value={p.id}>
                              📁 {p.name} {p.scope ? `(${p.scope})` : ''}
                            </option>
                          ))}
                        </select>
                      </div>

                      {/* Target Input */}
                      <div>
                        <label className="text-xs font-bold text-slate-200 block mb-1">
                          {runScanMode === 'blackbox' ? 'Target URL / Hostname *' : 'Codebase Label / Target *'}
                        </label>
                        <input
                          type="text"
                          className="input text-xs w-full"
                          placeholder={runScanMode === 'blackbox' ? 'https://target-client.com or 192.168.1.50' : 'e.g. client-repo-production'}
                          value={runScanTarget}
                          onChange={(e) => setRunScanTarget(e.target.value)}
                          required
                        />
                      </div>

                      {/* QUOTA CHOICE: Pakai Quota Client VS Free Admin Audit */}
                      <div className="p-4 rounded-2xl bg-slate-900/90 border border-white/10 space-y-2">
                        <label className="text-xs font-bold text-slate-200 block">
                          Pilihan Pemotongan Quota (Quota Billing Choice):
                        </label>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <button
                            type="button"
                            onClick={() => setRunScanDeductQuota(true)}
                            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                              runScanDeductQuota
                                ? 'border-cyan-400 bg-cyan-500/15 text-white'
                                : 'border-white/10 bg-slate-950/60 text-slate-400 hover:border-white/20'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold">⚡ Pakai Quota Client</span>
                              {runScanDeductQuota && <Check size={14} className="text-cyan-400" />}
                            </div>
                            <div className="text-[10px] text-slate-400 mt-1">
                              Tolak 1 kuota daripada baki pelanggan ({folderClient.remaining_quota || 0} kuota tinggal).
                            </div>
                          </button>

                          <button
                            type="button"
                            onClick={() => setRunScanDeductQuota(false)}
                            className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                              !runScanDeductQuota
                                ? 'border-emerald-400 bg-emerald-500/15 text-white'
                                : 'border-white/10 bg-slate-950/60 text-slate-400 hover:border-white/20'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-emerald-300">🛡️ Free Admin Audit (X Pakai Quota)</span>
                              {!runScanDeductQuota && <Check size={14} className="text-emerald-400" />}
                            </div>
                            <div className="text-[10px] text-slate-400 mt-1">
                              Scan percuma / bantuan pentadbir tanpa menolak kuota pelanggan.
                            </div>
                          </button>
                        </div>
                      </div>

                      {/* Blackbox Module Chips */}
                      {runScanMode === 'blackbox' && (
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-bold text-slate-300">Offensive Modules ({runScanModules.length}/{BLACKBOX_MODULES.length})</span>
                            <button
                              type="button"
                              onClick={() => setRunScanModules(runScanModules.length === BLACKBOX_MODULES.length ? [] : BLACKBOX_MODULES)}
                              className="text-[11px] text-cyan-300 hover:underline cursor-pointer"
                            >
                              {runScanModules.length === BLACKBOX_MODULES.length ? 'Clear All' : 'Select All'}
                            </button>
                          </div>
                          <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto p-2 rounded-xl bg-slate-950/60 border border-white/5">
                            {BLACKBOX_MODULES.map(m => (
                              <button
                                key={m}
                                type="button"
                                onClick={() => toggleRunModule(m)}
                                className={`text-[10px] px-2 py-0.5 rounded-md uppercase font-mono transition-all cursor-pointer ${
                                  runScanModules.includes(m)
                                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                                    : 'bg-white/5 text-slate-500 border border-white/5'
                                }`}
                              >
                                {m}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* AI Verification Checkbox */}
                      <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer pt-1">
                        <input
                          type="checkbox"
                          checked={runScanVerify}
                          onChange={(e) => setRunScanVerify(e.target.checked)}
                          className="rounded border-white/20 text-cyan-500 focus:ring-0"
                        />
                        <span>Enable DeepSeek AI Vulnerability Verification (Reduces False Positives)</span>
                      </label>

                      {/* Submit Scan Button */}
                      <button
                        type="submit"
                        disabled={runScanBusy}
                        className="btn-primary w-full justify-center py-3 text-xs font-bold shadow-glow hover:scale-[1.01] active:scale-[0.99] transition-all cursor-pointer bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600"
                      >
                        {runScanBusy && <Loader2 size={15} className="animate-spin" />}
                        {runScanBusy
                          ? 'Launching Assessment for Client...'
                          : `🚀 Launch Assessment & Save to ${folderClient.username}'s Folder`}
                      </button>
                    </form>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* EDIT SUBSCRIPTION QUOTA MODAL */}
      {/* ========================================================================= */}
      {editingClient && (
        <div
          className="fixed inset-0 z-50 grid place-items-center glass-overlay p-4"
          onClick={() => setEditingClient(null)}
        >
          <div
            className="card w-full max-w-lg glass-in border-cyan-500/30 p-6 space-y-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <Edit3 size={18} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Manage Subscription & Quota</h3>
                  <p className="text-xs text-slate-400">User: <b className="text-cyan-300">{editingClient.username}</b> ({editingClient.email})</p>
                </div>
              </div>
              <button
                onClick={() => setEditingClient(null)}
                className="text-slate-500 hover:text-white cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveClient} className="space-y-4 text-xs">
              {/* Plan Choice */}
              <div>
                <label className="font-bold text-slate-300 block mb-1.5">Subscription Plan Tier</label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setEditPlanId('pro')
                      setEditQuotaTotal(50)
                    }}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      editPlanId === 'pro'
                        ? 'border-cyan-400 bg-cyan-500/15 text-white'
                        : 'border-white/10 bg-slate-950/60 text-slate-400'
                    }`}
                  >
                    <div className="font-bold text-xs">SentinelAI Pro</div>
                    <div className="text-[10px] text-slate-400 mt-0.5">50 Scans / 5 Repos</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setEditPlanId('enterprise')
                      setEditQuotaTotal(9999)
                    }}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      editPlanId === 'enterprise'
                        ? 'border-emerald-400 bg-emerald-500/15 text-white'
                        : 'border-white/10 bg-slate-950/60 text-slate-400'
                    }`}
                  >
                    <div className="font-bold text-xs">Enterprise</div>
                    <div className="text-[10px] text-slate-400 mt-0.5">Unlimited Scans & Repos</div>
                  </button>
                </div>
              </div>

              {/* Total Quota Allowed */}
              <div>
                <label className="font-bold text-slate-300 block mb-1">Total Scan Quota Allowed</label>
                <input
                  type="number"
                  className="input text-xs w-full"
                  value={editQuotaTotal}
                  onChange={(e) => setEditQuotaTotal(e.target.value)}
                  min="0"
                  max="99999"
                  required
                />
                <p className="text-[10px] text-slate-400 mt-1">Set to 9999 for unlimited scanning.</p>
              </div>

              {/* Status */}
              <div>
                <label className="font-bold text-slate-300 block mb-1">Subscription Status</label>
                <select
                  className="input text-xs w-full"
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                >
                  <option value="active">Active (Full Access)</option>
                  <option value="expired">Expired (Requires Renewal)</option>
                  <option value="inactive">Inactive / Suspended</option>
                </select>
              </div>

              {/* Extend Expiry Days */}
              <div>
                <label className="font-bold text-slate-300 block mb-1">Extend Period (Days from Today)</label>
                <input
                  type="number"
                  className="input text-xs w-full"
                  value={editDays}
                  onChange={(e) => setEditDays(e.target.value)}
                  min="1"
                  max="3650"
                  required
                />
              </div>

              {/* Submit Buttons */}
              <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setEditingClient(null)}
                  className="btn-secondary text-xs py-2 px-4 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="btn-primary text-xs py-2 px-5 cursor-pointer shadow-glow"
                >
                  {saving ? 'Saving Changes...' : 'Save & Update Subscription'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
