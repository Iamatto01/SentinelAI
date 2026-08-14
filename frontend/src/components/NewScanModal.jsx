import React, { useEffect, useState } from 'react'
import { X, Globe, FileCode2, Loader2, FolderOpen, ChevronRight, ChevronUp, Plus, Trash2, Code2, ShieldCheck, Swords } from 'lucide-react'
import { api } from '../lib/api.js'

const BLACKBOX_MODULES = ['nmap', 'httpx', 'whatweb', 'wafw00f', 'subfinder', 'amass', 'dnsbrute', 'katana', 'ffuf', 'gobuster', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'arjun', 'wpscan']

export default function NewScanModal({ onClose, onStarted, initialProjectId = '', initialTarget = '' }) {
  const [mode, setMode] = useState('blackbox')
  const [whiteboxMode, setWhiteboxMode] = useState('folder') // 'folder' | 'paste'
  const [projectId, setProjectId] = useState(initialProjectId)
  const [projects, setProjects] = useState([])
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

  const toggle = (m) => setModules((p) => (p.includes(m) ? p.filter((x) => x !== m) : [...p, m]))
  const toggleDynamic = (m) => setDynamicModules((p) => (p.includes(m) ? p.filter((x) => x !== m) : [...p, m]))

  async function submit(e) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      let body
      let res
      if (mode === 'blackbox') {
        if (!target.trim()) throw new Error('Enter a target URL or host')
        body = { mode, projectId: projectId || null, target: target.trim(), objective, modules, verify, depth }
        res = await api.startScan(body)
      } else if (whiteboxMode === 'folder') {
        if (!folderPaths.length) throw new Error('Add at least one folder to scan')
        const sd = SCAN_DEPTHS[scanDepth] || SCAN_DEPTHS.standard
        body = {
          folders: folderPaths.map((dir) => ({ dir, prefix: dir.split(/[\\/]/).pop() || dir })),
          projectId: projectId || null,
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
        body = { mode, projectId: projectId || null, files: [{ path: filename || 'snippet.txt', content: code }], language, focus: 'security', verify, depth }
        res = await api.startScan(body)
      }
      onStarted(res.scan.id)
    } catch (e2) {
      setErr(e2.message)
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center glass-overlay p-4" onClick={onClose}>
      <div className="card w-full max-w-2xl max-h-[90vh] overflow-auto glass-in" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-white/10 px-6 py-4">
          <h2 className="text-lg font-semibold text-slate-100">New Assessment</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={20} /></button>
        </div>

        <form onSubmit={submit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-3">
            <button type="button" onClick={() => setMode('blackbox')}
              className={`glass-soft p-4 text-left transition-all duration-200 ${mode === 'blackbox' ? 'border-accent/50 glass-glow' : 'hover:border-white/20'}`}>
              <Globe className={mode === 'blackbox' ? 'text-accent' : 'text-slate-500'} size={22} />
              <p className="mt-2 font-semibold text-slate-100">Blackbox</p>
              <p className="text-xs text-slate-500">External target via Hexstrike engine</p>
            </button>
            <button type="button" onClick={() => setMode('whitebox')}
              className={`glass-soft p-4 text-left transition-all duration-200 ${mode === 'whitebox' ? 'border-accent/50 glass-glow' : 'hover:border-white/20'}`}>
              <FileCode2 className={mode === 'whitebox' ? 'text-accent' : 'text-slate-500'} size={22} />
              <p className="mt-2 font-semibold text-slate-100">Whitebox</p>
              <p className="text-xs text-slate-500">Source code audit via code-auditor agent</p>
            </button>
          </div>

          <div>
            <label className="label">Project (Optional)</label>
            <select className="input" value={projectId} onChange={(e) => setProjectId(e.target.value)}>
              <option value="">-- No Project (Standalone Assessment) --</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  📁 {p.name} {p.client ? `(${p.client})` : ''}
                </option>
              ))}
            </select>
          </div>

          {mode === 'blackbox' ? (
            <>
              <div>
                <label className="label">Target</label>
                <input className="input" placeholder="https://example.com or 192.168.1.10" value={target} onChange={(e) => setTarget(e.target.value)} />
              </div>

              {/* 2 Simplified Objectives */}
              <div>
                <label className="label">Scan Objective</label>
                <div className="grid grid-cols-2 gap-3 mt-1.5">
                  <div
                    onClick={() => {
                      setObjective('comprehensive')
                      setDepth('standard')
                      setModules(BLACKBOX_MODULES)
                    }}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      objective === 'comprehensive'
                        ? 'bg-cyan-500/15 border-cyan-500/60 ring-2 ring-cyan-500/30'
                        : 'bg-ink-800/80 border-slate-700/60 hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <ShieldCheck className={objective === 'comprehensive' ? 'text-cyan-400' : 'text-slate-400'} size={20} />
                      <span className="font-bold text-sm text-slate-100">Normal</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Standard vulnerability scanning across <strong>all 16 modules</strong> with stealth & web checks.
                    </p>
                  </div>

                  <div
                    onClick={() => {
                      setObjective('offensive')
                      setDepth('offensive')
                      setModules(BLACKBOX_MODULES)
                    }}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      objective === 'offensive'
                        ? 'bg-red-500/15 border-red-500/60 ring-2 ring-red-500/30'
                        : 'bg-ink-800/80 border-slate-700/60 hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Swords className={objective === 'offensive' ? 'text-red-400' : 'text-slate-400'} size={20} />
                      <span className="font-bold text-sm text-slate-100">⚔️ Offensive</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Max aggression across <strong>ALL modules</strong> — NSE vulns, deep SQLi, XSS cookie steals & cred checks.
                    </p>
                  </div>
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <label className="label">Modules ({modules.length}/{BLACKBOX_MODULES.length})</label>
                  <button type="button" onClick={() => setModules(modules.length === BLACKBOX_MODULES.length ? [] : BLACKBOX_MODULES)}
                    className="text-[11px] text-accent hover:text-accent/80">
                    {modules.length === BLACKBOX_MODULES.length ? 'untick all' : 'tick all'}
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {BLACKBOX_MODULES.map((m) => (
                    <button type="button" key={m} onClick={() => toggle(m)}
                      className={`chip border transition-colors ${modules.includes(m) ? 'bg-accent/15 text-accent border-accent/50' : 'bg-ink-800 text-slate-500 border-ink-600 hover:text-slate-300'}`}>
                      {m}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-[11px] text-slate-500">Comprehensive/offensive auto-ticks every module. Untick any to skip them.</p>
              </div>
            </>
          ) : (
            <>
              {/* Whitebox mode toggle */}
              <div className="flex gap-2 border-b border-white/10 pb-3">
                <button type="button" onClick={() => setWhiteboxMode('folder')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${whiteboxMode === 'folder' ? 'bg-accent/15 text-accent border border-accent/40' : 'bg-ink-800 text-slate-500 border border-ink-600 hover:text-slate-300'}`}>
                  <FolderOpen size={16} /> Scan Folder
                </button>
                <button type="button" onClick={() => setWhiteboxMode('paste')}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${whiteboxMode === 'paste' ? 'bg-accent/15 text-accent border border-accent/40' : 'bg-ink-800 text-slate-500 border border-ink-600 hover:text-slate-300'}`}>
                  <Code2 size={16} /> Paste Code
                </button>
              </div>

              {whiteboxMode === 'folder' ? (
                <>
                  <div>
                    <label className="label">Browse Server Folders</label>
                    <div className="glass-soft p-3 rounded-lg space-y-2 max-h-56 overflow-auto">
                      {/* Roots */}
                      {!browseCurrent && (
                        <div>
                          <p className="text-xs text-slate-500 mb-2">Allowed roots:</p>
                          {browseRoots.map((r) => (
                            <button type="button" key={r.path} onClick={() => browseTo(r.path)}
                              className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded hover:bg-white/5 text-sm text-slate-300">
                              <FolderOpen size={14} className="text-amber-400" />
                              <span className="font-mono text-xs truncate">{r.path}</span>
                            </button>
                          ))}
                        </div>
                      )}

                      {/* Current dir header */}
                      {browseCurrent && (
                        <div className="flex items-center justify-between gap-2 pb-2 border-b border-white/10">
                          <div className="flex items-center gap-2 min-w-0">
                            <FolderOpen size={14} className="text-amber-400 shrink-0" />
                            <span className="font-mono text-xs text-slate-300 truncate">{browseCurrent}</span>
                          </div>
                          <button type="button" onClick={() => addFolder(browseCurrent)}
                            className="btn-ghost text-xs px-2 py-1 shrink-0 flex items-center gap-1">
                            <Plus size={12} /> Add
                          </button>
                        </div>
                      )}

                      {/* Parent */}
                      {browseParent && (
                        <button type="button" onClick={() => browseTo(browseParent)}
                          className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded hover:bg-white/5 text-sm text-slate-400">
                          <ChevronUp size={14} /> ..
                        </button>
                      )}

                      {/* Subdirs */}
                      {browseDirs.map((d) => (
                        <div key={d.path} className="flex items-center justify-between gap-1 group">
                          <button type="button" onClick={() => browseTo(d.path)}
                            className="flex items-center gap-2 flex-1 text-left px-2 py-1.5 rounded hover:bg-white/5 text-sm text-slate-300 min-w-0">
                            <ChevronRight size={14} className="text-slate-500 shrink-0" />
                            <span className="truncate">{d.name}</span>
                          </button>
                          <button type="button" onClick={() => addFolder(d.path)}
                            className="opacity-0 group-hover:opacity-100 text-accent hover:text-accent/80 px-1 transition-opacity">
                            <Plus size={14} />
                          </button>
                        </div>
                      ))}
                      {browseLoading && <p className="text-xs text-slate-500 px-2 py-1">Loading…</p>}
                    </div>
                  </div>

                  {/* Selected folders */}
                  {folderPaths.length > 0 && (
                    <div>
                      <label className="label">Selected Folders ({folderPaths.length})</label>
                      <div className="space-y-1.5">
                        {folderPaths.map((p) => (
                          <div key={p} className="flex items-center justify-between gap-2 glass-soft px-3 py-2 rounded-lg">
                            <span className="font-mono text-xs text-slate-300 truncate">{p}</span>
                            <button type="button" onClick={() => removeFolder(p)} className="text-slate-500 hover:text-sev-critical shrink-0">
                              <Trash2 size={14} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Manual path input */}
                  <div>
                    <label className="label">Or enter path manually</label>
                    <div className="flex gap-2">
                      <input className="input font-mono text-xs" placeholder="/root/FYP2PROJECT/backend"
                        value={browsePath} onChange={(e) => setBrowsePath(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); browseTo(browsePath) } }} />
                      <button type="button" onClick={() => browseTo(browsePath)} className="btn-ghost text-xs px-3">Go</button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="label">Language (hint)</label>
                      <select className="input" value={language} onChange={(e) => setLanguage(e.target.value)}>
                        {['javascript', 'typescript', 'python', 'php', 'java', 'go', 'ruby', 'csharp', 'auto'].map((l) => <option key={l}>{l}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Scan Depth</label>
                      <select className="input" value={scanDepth} onChange={(e) => setScanDepth(e.target.value)}>
                        {Object.entries(SCAN_DEPTHS).map(([k, d]) => (
                          <option key={k} value={k}>{d.label}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="label">Audit Aggression</label>
                    <select className="input" value={depth} onChange={(e) => setDepth(e.target.value)}>
                      <option value="standard">Standard — single AI audit pass</option>
                      <option value="offensive">⚔️ Offensive — 3-pass audit (injection / auth+secrets / logic) + pattern scanner</option>
                    </select>
                  </div>
                  <p className="text-[11px] text-slate-500">
                    {SCAN_DEPTHS[scanDepth].desc}. Files are read directly from server disk (no upload/copy) —
                    the walker auto-skips node_modules, .git, dist, build, .env, lockfiles, and other non-source files.
                    {depth === 'offensive' ? ' Offensive mode runs a fast pattern scanner (secrets, dangerous functions) + 3 specialist AI passes.' : ''}
                  </p>

                  {/* ── Dynamic Verification (Hybrid Whitebox) ── */}
                  <div className="glass-soft p-4 rounded-xl border border-amber-500/30 mt-3">
                    <div className="flex items-center gap-2 mb-3">
                      <Swords size={16} className="text-amber-400" />
                      <span className="font-semibold text-sm text-amber-300">Dynamic Verification (Hybrid Mode)</span>
                      <span className="text-[10px] text-amber-700 bg-amber-500/10 px-1.5 py-0.5 rounded">Optional</span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">
                      After source analysis, run blackbox tools against a live target to confirm vulnerabilities with runtime evidence.
                    </p>
                    <div>
                      <label className="label">Target URL</label>
                      <input className="input font-mono text-xs" placeholder="https://your-app.com or 192.168.1.10"
                        value={dynamicTarget} onChange={(e) => setDynamicTarget(e.target.value)} />
                    </div>
                    {dynamicTarget.trim() && (
                      <div className="mt-3">
                        <div className="flex items-center justify-between">
                          <label className="label">Dynamic Modules ({dynamicModules.length}/{DYNAMIC_MODULES.length})</label>
                          <button type="button" onClick={() => setDynamicModules(dynamicModules.length === DYNAMIC_MODULES.length ? [] : DYNAMIC_MODULES)}
                            className="text-[11px] text-accent hover:text-accent/80">
                            {dynamicModules.length === DYNAMIC_MODULES.length ? 'untick all' : 'tick all'}
                          </button>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {DYNAMIC_MODULES.map((m) => (
                            <button type="button" key={m} onClick={() => toggleDynamic(m)}
                              className={`chip border transition-colors ${dynamicModules.includes(m) ? 'bg-amber-500/15 text-amber-300 border-amber-500/40' : 'bg-ink-800 text-slate-500 border-ink-600 hover:text-slate-300'}`}>
                              {m}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="label">Filename</label>
                      <input className="input" value={filename} onChange={(e) => setFilename(e.target.value)} />
                    </div>
                    <div>
                      <label className="label">Language</label>
                      <select className="input" value={language} onChange={(e) => setLanguage(e.target.value)}>
                        {['javascript', 'typescript', 'python', 'php', 'java', 'go', 'ruby', 'csharp'].map((l) => <option key={l}>{l}</option>)}
                      </select>
                    </div>
                  </div>
                  <div>
                    <label className="label">Source code</label>
                    <textarea className="input font-mono text-xs h-44 resize-y" placeholder="Paste source code here…" value={code} onChange={(e) => setCode(e.target.value)} />
                  </div>
                </>
              )}
            </>
          )}

          <label className="flex items-center gap-2.5 text-sm text-slate-300 cursor-pointer">
            <input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)}
              className="h-4 w-4 rounded border-ink-600 bg-ink-800 text-accent focus:ring-accent/40" />
            AI agent verification (reduce false positives)
          </label>

          {err && (
            <div className="rounded-xl bg-rose-500/10 border border-rose-500/40 p-4 text-xs text-rose-300 space-y-2">
              <p className="font-semibold">{err}</p>
              {(err.includes('quota') || err.includes('subscription') || err.includes('expired') || err.includes('paid')) && (
                <div className="pt-2">
                  <a
                    href="/app/billing"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400 transition-colors"
                  >
                    <span>Upgrade / Renew Plan in Billing</span> →
                  </a>
                </div>
              )}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-1">
            <button type="button" onClick={onClose} className="btn-ghost">Cancel</button>
            <button type="submit" disabled={busy} className="btn-primary">
              {busy ? <Loader2 size={16} className="animate-spin" /> : null}
              {busy ? 'Launching…' : `Launch ${mode === 'blackbox' ? 'Scan' : whiteboxMode === 'folder' ? 'Folder Audit' : 'Code Audit'}`}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
