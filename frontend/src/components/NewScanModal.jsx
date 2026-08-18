import React, { useEffect, useState } from 'react'
import {
  X, Globe, FileCode2, Loader2, FolderOpen, ChevronRight, ChevronUp, Plus,
  Trash2, Code2, ShieldCheck, Swords, User, Zap, Check, CheckCircle2
} from 'lucide-react'
import { api } from '../lib/api.js'

const BLACKBOX_MODULES = ['nmap', 'httpx', 'whatweb', 'wafw00f', 'subfinder', 'amass', 'dnsbrute', 'katana', 'ffuf', 'gobuster', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'arjun', 'wpscan']

export default function NewScanModal({ onClose, onStarted, initialProjectId = '', initialTarget = '', initialClientId = '' }) {
  const [mode, setMode] = useState('blackbox')
  const [whiteboxMode, setWhiteboxMode] = useState('folder') // 'folder' | 'paste'
  const [projectId, setProjectId] = useState(initialProjectId)
  const [projects, setProjects] = useState([])
  const [clients, setClients] = useState([])
  const [targetClientId, setTargetClientId] = useState(initialClientId)
  const [deductQuota, setDeductQuota] = useState(true)
  const [showCreateFolder, setShowCreateFolder] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [creatingFolder, setCreatingFolder] = useState(false)

  const [target, setTarget] = useState(initialTarget)
  const [objective, setObjective] = useState('offensive')
  const [modules, setModules] = useState(BLACKBOX_MODULES) // all ticked
  const [depth, setDepth] = useState('offensive')
  const [verify, setVerify] = useState(true)
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('app.js')
  const [language, setLanguage] = useState('javascript')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  // Hybrid whitebox: dynamic verification against a live target
  const [dynamicTarget, setDynamicTarget] = useState('')
  const [dynamicModules, setDynamicModules] = useState(['nmap', 'nikto', 'nuclei', 'ffuf', 'whatweb', 'katana', 'arjun', 'dalfox'])
  const DYNAMIC_MODULES = ['nmap', 'nikto', 'nuclei', 'ffuf', 'gobuster', 'whatweb', 'katana', 'arjun', 'dalfox', 'sqlmap', 'wpscan', 'wafw00f', 'subfinder', 'dnsbrute', 'sslscan', 'nmap-script']

  // Folder browser state
  const [folderPaths, setFolderPaths] = useState([])
  const [browsePath, setBrowsePath] = useState('')
  const [browseDirs, setBrowseDirs] = useState([])
  const [browseRoots, setBrowseRoots] = useState([])
  const [browseParent, setBrowseParent] = useState(null)
  const [browseCurrent, setBrowseCurrent] = useState(null)
  const [browseLoading, setBrowseLoading] = useState(false)
  const [scanDepth, setScanDepth] = useState('full')

  const SCAN_DEPTHS = {
    quick:    { label: 'Quick',    maxFiles: 60,  maxBytes: 2_000_000,  desc: '60 files / 2MB — fast triage' },
    standard: { label: 'Standard', maxFiles: 10000, maxBytes: 50_000_000, desc: 'Up to 10000 source files / 50MB — most projects' },
    deep:     { label: 'Deep',     maxFiles: 50000, maxBytes: 150_000_000, desc: 'Up to 50000 files / 150MB — large apps' },
    full:     { label: 'Full',     maxFiles: 100000, maxBytes: 500_000_000, desc: 'All source files (unlimited) / 500MB — slowest, most thorough' },
  }

  useEffect(() => {
    api.projects().then((data) => setProjects(data || [])).catch(() => {})
    api.adminClients().then((res) => setClients(res.clients || [])).catch(() => {})
    loadRoots()
  }, [])

  async function loadRoots() {
    try {
      const data = await api.browseFilesystem()
      setBrowseRoots(data.roots || [])
    } catch { /* ignore */ }
  }

  async function browseTo(path) {
    setBrowseLoading(true)
    setErr('')
    try {
      const data = await api.browseFilesystem(path)
      setBrowseCurrent(data.current)
      setBrowseParent(data.parent)
      setBrowseDirs(data.directories || [])
      setBrowseRoots(data.roots || [])
    } catch (e2) {
      setErr(e2.message)
    } finally {
      setBrowseLoading(false)
    }
  }

  function addFolder(path) {
    if (!path || folderPaths.includes(path)) return
    setFolderPaths((p) => [...p, path])
  }

  function removeFolder(path) {
    setFolderPaths((p) => p.filter((x) => x !== path))
  }

  async function handleCreateFolder() {
    if (!newFolderName.trim()) return
    setCreatingFolder(true)
    try {
      const clientName = selectedClientObj?.username || ''
      const res = await api.createProject({ name: newFolderName.trim(), client: clientName })
      if (res && res.id) {
        setProjects((prev) => [res, ...prev])
        setProjectId(res.id)
        setNewFolderName('')
        setShowCreateFolder(false)
      }
    } catch (e) {
      setErr(e.message || 'Failed to create folder')
    } finally {
      setCreatingFolder(false)
    }
  }

  const toggle = (m) => setModules((p) => (p.includes(m) ? p.filter((x) => x !== m) : [...p, m]))
  const toggleDynamic = (m) => setDynamicModules((p) => (p.includes(m) ? p.filter((x) => x !== m) : [...p, m]))

  // Filter projects if a client is selected
  const selectedClientObj = clients.find(c => c.id === targetClientId)
  const filteredProjects = projects.filter(p => {
    if (!targetClientId) return true
    if (p.client_id === targetClientId || p.user_id === targetClientId) return true
    if (selectedClientObj) {
      const u = (selectedClientObj.username || '').toLowerCase()
      const e = (selectedClientObj.email || '').toLowerCase()
      const pc = (p.client || '').toLowerCase()
      if (pc.includes(u) || (e && pc.includes(e))) return true
    }
    return true
  })

  async function submit(e) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      let body
      let res
      if (mode === 'blackbox') {
        if (!target.trim()) throw new Error('Enter a target URL or host')
        body = {
          mode,
          projectId: projectId || null,
          targetUserId: targetClientId || null,
          deductQuota,
          target: target.trim(),
          objective,
          modules,
          verify,
          depth,
        }
        res = await api.startScan(body)
      } else if (whiteboxMode === 'folder') {
        if (!folderPaths.length) throw new Error('Add at least one folder to scan')
        const sd = SCAN_DEPTHS[scanDepth] || SCAN_DEPTHS.standard
        body = {
          folders: folderPaths.map((dir) => ({ dir, prefix: dir.split(/[\\/]/).pop() || dir })),
          projectId: projectId || null,
          targetUserId: targetClientId || null,
          deductQuota,
          language,
          focus: 'security',
          verify,
          depth,
          maxFiles: sd.maxFiles,
          maxBytes: sd.maxBytes,
          dynamicTarget: dynamicTarget.trim(),
          dynamicModules: dynamicTarget.trim() ? dynamicModules : [],
        }
        res = await api.startWhiteboxFolder(body)
      } else {
        if (!code.trim()) throw new Error('Paste source code to audit')
        body = {
          mode,
          projectId: projectId || null,
          targetUserId: targetClientId || null,
          deductQuota,
          files: [{ path: filename || 'snippet.txt', content: code }],
          language,
          focus: 'security',
          verify,
          depth,
        }
        res = await api.startScan(body)
      }
      onStarted(res.scan.id)
    } catch (e2) {
      setErr(e2.message)
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center glass-overlay p-4 overflow-y-auto" onClick={onClose}>
      <div className="card w-full max-w-2xl max-h-[90vh] overflow-auto glass-in my-auto shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-white/10 px-6 py-4 bg-slate-900/80">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400">
              <Zap size={18} />
            </div>
            <h2 className="text-lg font-bold text-slate-100">New Security Assessment</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200 cursor-pointer"><X size={20} /></button>
        </div>

        <form onSubmit={submit} className="p-6 space-y-5">
          {/* Scan Type Mode Switcher */}
          <div className="grid grid-cols-2 gap-3">
            <button type="button" onClick={() => setMode('blackbox')}
              className={`p-4 rounded-2xl border text-left transition-all duration-200 cursor-pointer ${mode === 'blackbox' ? 'border-cyan-400 bg-cyan-500/15 shadow-glow ring-1 ring-cyan-400' : 'border-white/10 bg-slate-900/60 hover:border-white/20'}`}>
              <Globe className={mode === 'blackbox' ? 'text-cyan-400' : 'text-slate-500'} size={22} />
              <p className="mt-2 font-bold text-slate-100">Blackbox Assessment</p>
              <p className="text-xs text-slate-400">External web & network target via Hexstrike engine</p>
            </button>
            <button type="button" onClick={() => setMode('whitebox')}
              className={`p-4 rounded-2xl border text-left transition-all duration-200 cursor-pointer ${mode === 'whitebox' ? 'border-cyan-400 bg-cyan-500/15 shadow-glow ring-1 ring-cyan-400' : 'border-white/10 bg-slate-900/60 hover:border-white/20'}`}>
              <FileCode2 className={mode === 'whitebox' ? 'text-cyan-400' : 'text-slate-500'} size={22} />
              <p className="mt-2 font-bold text-slate-100">Whitebox Code Audit</p>
              <p className="text-xs text-slate-400">Source code AST audit via Code Auditor specialist agent</p>
            </button>
          </div>

          {/* Client & Project Assignment Block */}
          <div className="p-4 rounded-2xl bg-slate-950/75 border border-white/10 space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                <User size={14} className="text-cyan-400" /> Assign to Client & Project Folder
              </label>
              {targetClientId && (
                <span className="text-[10px] text-cyan-300 font-mono">
                  Client: {selectedClientObj?.username || targetClientId}
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Client Selection (For Admins) */}
              {clients.length > 0 && (
                <div>
                  <label className="text-[11px] font-semibold text-slate-400 block mb-1">Target Client Account</label>
                  <select
                    className="input text-xs w-full"
                    value={targetClientId}
                    onChange={(e) => {
                      setTargetClientId(e.target.value)
                      setProjectId('')
                    }}
                  >
                    <option value="">-- Personal / No Client Assignment --</option>
                    {clients.map((c) => (
                      <option key={c.id} value={c.id}>
                        👤 {c.username} ({c.email || c.plan_name || 'Client'})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Project Selection */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[11px] font-semibold text-slate-400">Project Folder (Optional)</label>
                  <button
                    type="button"
                    onClick={() => setShowCreateFolder(!showCreateFolder)}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 font-bold flex items-center gap-1 hover:underline cursor-pointer"
                  >
                    <Plus size={11} /> {showCreateFolder ? 'Cancel' : 'New Folder'}
                  </button>
                </div>

                {showCreateFolder && (
                  <div className="flex items-center gap-2 mb-2 p-2 rounded-xl bg-cyan-950/30 border border-cyan-500/30 animate-in fade-in">
                    <input
                      type="text"
                      value={newFolderName}
                      onChange={(e) => setNewFolderName(e.target.value)}
                      placeholder="Folder name (e.g. Production Web)..."
                      className="input text-xs !py-1.5 flex-1"
                      autoFocus
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleCreateFolder() } }}
                    />
                    <button
                      type="button"
                      disabled={creatingFolder || !newFolderName.trim()}
                      onClick={handleCreateFolder}
                      className="btn-primary text-[11px] !py-1.5 px-3 whitespace-nowrap"
                    >
                      {creatingFolder ? <Loader2 size={12} className="animate-spin" /> : 'Create'}
                    </button>
                  </div>
                )}

                <select
                  className="input text-xs w-full"
                  value={projectId}
                  onChange={(e) => setProjectId(e.target.value)}
                >
                  <option value="">-- No Project (Standalone Assessment) --</option>
                  {filteredProjects.map((p) => (
                    <option key={p.id} value={p.id}>
                      📁 {p.name} {p.client ? `(${p.client})` : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Quota Deduction Option (When client is selected) */}
            {targetClientId && (
              <div className="pt-2 border-t border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-[11px] text-slate-300 font-semibold">Quota Billing for Client:</span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setDeductQuota(true)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-all cursor-pointer ${
                      deductQuota
                        ? 'border-cyan-400 bg-cyan-500/20 text-cyan-300'
                        : 'border-white/10 bg-slate-900 text-slate-400'
                    }`}
                  >
                    ⚡ Pakai Quota Client
                  </button>
                  <button
                    type="button"
                    onClick={() => setDeductQuota(false)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-all cursor-pointer ${
                      !deductQuota
                        ? 'border-emerald-400 bg-emerald-500/20 text-emerald-300'
                        : 'border-white/10 bg-slate-900 text-slate-400'
                    }`}
                  >
                    🛡️ Free Admin Audit
                  </button>
                </div>
              </div>
            )}
          </div>

          {mode === 'blackbox' ? (
            <>
              <div>
                <label className="label text-xs font-bold text-slate-200">Target URL / Hostname *</label>
                <input
                  className="input text-xs w-full"
                  placeholder="https://example.com or 192.168.1.10"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                />
              </div>

              {/* 2 Simplified Objectives */}
              <div>
                <label className="label text-xs font-bold text-slate-200">Scan Objective</label>
                <div className="grid grid-cols-2 gap-3 mt-1.5">
                  <div
                    onClick={() => {
                      setObjective('comprehensive')
                      setDepth('standard')
                      setModules(BLACKBOX_MODULES)
                    }}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                      objective === 'comprehensive'
                        ? 'bg-cyan-500/15 border-cyan-500/60 ring-2 ring-cyan-500/30'
                        : 'bg-slate-900/80 border-slate-700/60 hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <ShieldCheck className={objective === 'comprehensive' ? 'text-cyan-400' : 'text-slate-400'} size={18} />
                      <span className="font-bold text-xs text-slate-100">Normal</span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Standard vulnerability scanning across <strong>all 16 modules</strong> with stealth & web checks.
                    </p>
                  </div>

                  <div
                    onClick={() => {
                      setObjective('offensive')
                      setDepth('offensive')
                      setModules(BLACKBOX_MODULES)
                    }}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                      objective === 'offensive'
                        ? 'bg-red-500/15 border-red-500/60 ring-2 ring-red-500/30'
                        : 'bg-slate-900/80 border-slate-700/60 hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Swords className={objective === 'offensive' ? 'text-red-400' : 'text-slate-400'} size={18} />
                      <span className="font-bold text-xs text-slate-100">⚔️ Offensive</span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Max aggression across <strong>ALL modules</strong> — NSE vulns, deep SQLi, XSS cookie steals & cred checks.
                    </p>
                  </div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="label text-xs font-bold text-slate-200">Modules ({modules.length}/{BLACKBOX_MODULES.length})</label>
                  <button
                    type="button"
                    onClick={() => setModules(modules.length === BLACKBOX_MODULES.length ? [] : BLACKBOX_MODULES)}
                    className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                  >
                    {modules.length === BLACKBOX_MODULES.length ? 'untick all' : 'tick all'}
                  </button>
                </div>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2.5 rounded-xl bg-slate-950/60 border border-white/10">
                  {BLACKBOX_MODULES.map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => toggle(m)}
                      className={`text-[10px] px-2 py-0.5 rounded-md uppercase font-mono transition-all cursor-pointer ${
                        modules.includes(m)
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                          : 'bg-white/5 text-slate-500 border border-white/5'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <>
              {/* Whitebox Mode Switcher */}
              <div className="flex rounded-xl bg-slate-900 p-1 border border-white/10">
                <button
                  type="button"
                  onClick={() => setWhiteboxMode('folder')}
                  className={`flex-1 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                    whiteboxMode === 'folder'
                      ? 'bg-cyan-500 text-slate-950 shadow-md'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <FolderOpen size={13} className="inline mr-1" /> Local Folders
                </button>
                <button
                  type="button"
                  onClick={() => setWhiteboxMode('paste')}
                  className={`flex-1 py-1.5 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                    whiteboxMode === 'paste'
                      ? 'bg-cyan-500 text-slate-950 shadow-md'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Code2 size={13} className="inline mr-1" /> Paste Snippet
                </button>
              </div>

              {whiteboxMode === 'folder' ? (
                <div className="space-y-3">
                  {/* Selected Folders List */}
                  <div>
                    <label className="text-xs font-bold text-slate-200 block mb-1">Folders to Audit ({folderPaths.length})</label>
                    {folderPaths.length === 0 ? (
                      <p className="text-[11px] text-slate-500 italic">No folders added yet. Pick one below.</p>
                    ) : (
                      <div className="space-y-1.5 max-h-28 overflow-y-auto">
                        {folderPaths.map((p) => (
                          <div key={p} className="flex items-center justify-between p-2 rounded-xl bg-slate-900 border border-white/10 text-xs font-mono text-cyan-300">
                            <span className="truncate">{p}</span>
                            <button type="button" onClick={() => removeFolder(p)} className="text-rose-400 hover:text-rose-300 p-1 cursor-pointer">
                              <Trash2 size={13} />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Folder Browser */}
                  <div className="p-3 rounded-xl bg-slate-950/60 border border-white/10 space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-slate-300">Server Directory Browser</span>
                      {browseParent && (
                        <button type="button" onClick={() => browseTo(browseParent)} className="text-[11px] text-cyan-400 hover:underline cursor-pointer flex items-center gap-0.5">
                          <ChevronUp size={12} /> Up to Parent
                        </button>
                      )}
                    </div>

                    <div className="max-h-36 overflow-y-auto space-y-1 text-xs font-mono">
                      {browseDirs.map((d) => (
                        <div key={d.path} className="flex items-center justify-between p-1.5 rounded-lg hover:bg-white/5">
                          <button type="button" onClick={() => browseTo(d.path)} className="text-left text-slate-300 hover:text-cyan-300 truncate cursor-pointer flex items-center gap-1.5">
                            <FolderOpen size={13} className="text-cyan-400 shrink-0" />
                            <span>{d.name}</span>
                          </button>
                          <button type="button" onClick={() => addFolder(d.path)} className="btn-secondary !py-0.5 !px-2 text-[10px] cursor-pointer">
                            + Add
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <div>
                    <label className="text-xs font-bold text-slate-200 block mb-1">Source Code</label>
                    <textarea
                      className="input text-xs w-full h-36 font-mono"
                      placeholder="// Paste code here..."
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                    />
                  </div>
                </div>
              )}
            </>
          )}

          {/* AI Verification Checkbox */}
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer pt-1">
            <input
              type="checkbox"
              checked={verify}
              onChange={(e) => setVerify(e.target.checked)}
              className="rounded border-white/20 text-cyan-500 focus:ring-0"
            />
            <span>Enable DeepSeek AI Specialist Agent Verification</span>
          </label>

          {err && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
              <X size={14} className="text-red-400 shrink-0" />
              <span>{err}</span>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-3 border-t border-white/10">
            <button type="button" onClick={onClose} className="btn-secondary text-xs py-2 px-4 cursor-pointer">
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="btn-primary text-xs py-2 px-5 cursor-pointer shadow-glow bg-gradient-to-r from-cyan-500 to-blue-600"
            >
              {busy && <Loader2 size={14} className="animate-spin" />}
              {busy ? 'Starting Assessment...' : 'Launch Assessment'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
