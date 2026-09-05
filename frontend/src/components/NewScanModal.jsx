import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  X, Globe, FileCode2, Loader2, FolderOpen, ChevronRight, ChevronUp, ChevronDown, Plus,
  Trash2, Code2, ShieldCheck, Swords, User, Zap, Check, CheckCircle2, ShieldAlert
} from 'lucide-react'
import { api } from '../lib/api.js'

const BLACKBOX_MODULES = ['nmap', 'httpx', 'whatweb', 'wafw00f', 'subfinder', 'amass', 'dnsbrute', 'katana', 'ffuf', 'gobuster', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'arjun', 'wpscan']

// ── OWASP Top 10 (2025) Category Definitions ─────────────────────────
const OWASP_CATEGORIES = [
  { code: 'A01', id: 'A01:2025', name: 'Broken Access Control', icon: '🔐', color: 'rose' },
  { code: 'A02', id: 'A02:2025', name: 'Security Misconfiguration', icon: '⚙️', color: 'amber' },
  { code: 'A03', id: 'A03:2025', name: 'Software Supply Chain Failures', icon: '📦', color: 'orange' },
  { code: 'A04', id: 'A04:2025', name: 'Cryptographic Failures', icon: '🔑', color: 'purple' },
  { code: 'A05', id: 'A05:2025', name: 'Injection', icon: '💉', color: 'red' },
  { code: 'A06', id: 'A06:2025', name: 'Insecure Design', icon: '🏗️', color: 'blue' },
  { code: 'A07', id: 'A07:2025', name: 'Authentication Failures', icon: '👤', color: 'cyan' },
  { code: 'A08', id: 'A08:2025', name: 'Software or Data Integrity Failures', icon: '🔄', color: 'teal' },
  { code: 'A09', id: 'A09:2025', name: 'Security Logging and Alerting Failures', icon: '📋', color: 'indigo' },
  { code: 'A10', id: 'A10:2025', name: 'Mishandling of Exceptional Conditions', icon: '⚠️', color: 'yellow' },
]

// Tool → OWASP mapping (blackbox tools)
const OWASP_BLACKBOX_TOOLS = {
  A01: [
    { tool: 'nmap', desc: 'NSE scripts: smb-enum-shares, rdp-vuln, path traversal' },
    { tool: 'ffuf', desc: 'Forced browsing — discovers hidden paths & IDOR endpoints' },
    { tool: 'gobuster', desc: 'Directory/path brute force — exposes restricted areas' },
    { tool: 'katana', desc: 'Crawler — discovers parameterized routes (IDOR surface)' },
    { tool: 'arjun', desc: 'Hidden parameter discovery — access control bypass' },
  ],
  A02: [
    { tool: 'nikto', desc: 'Security headers, debug pages, misconfig checks' },
    { tool: 'nuclei', desc: 'Misconfiguration templates (CORS, debug, exposure)' },
    { tool: 'whatweb', desc: 'Server header / tech stack exposure detection' },
    { tool: 'wafw00f', desc: 'WAF fingerprint & security posture' },
    { tool: 'httpx', desc: 'HTTP probe — banner, response headers' },
    { tool: 'ffuf', desc: 'Directory listing, .htaccess exposure' },
  ],
  A03: [
    { tool: 'nuclei', desc: 'CVE templates for vulnerable components & libraries' },
    { tool: 'nikto', desc: 'Outdated software / server version detection' },
    { tool: 'whatweb', desc: 'Technology fingerprint — identifies dependency versions' },
    { tool: 'nmap', desc: 'Service version detection — flags known-vulnerable versions' },
  ],
  A04: [
    { tool: 'nmap', desc: 'NSE: ssl-cert, ssl-enum-ciphers, weak protocols' },
    { tool: 'nuclei', desc: 'TLS/SSL misconfig & weak cipher templates' },
    { tool: 'whatweb', desc: 'Detects HTTP vs HTTPS, cert validity' },
    { tool: 'wafw00f', desc: 'TLS inspection' },
  ],
  A05: [
    { tool: 'sqlmap', desc: 'SQL injection — automated union-based to time-blind' },
    { tool: 'dalfox', desc: 'XSS — reflected, stored, DOM-based injection' },
    { tool: 'arjun', desc: 'Hidden parameter discovery for injection vectors' },
    { tool: 'nuclei', desc: 'Injection templates (SSTI, SSRF, code injection)' },
    { tool: 'nikto', desc: 'CGI & injection-prone endpoint detection' },
    { tool: 'katana', desc: 'Crawl parameterized URLs for injection testing' },
    { tool: 'ffuf', desc: 'Fuzz parameters for error-based injection' },
  ],
  A06: [
    { tool: 'nikto', desc: 'Default credentials & insecure defaults' },
    { tool: 'nuclei', desc: 'Weak design patterns (missing rate-limit, etc.)' },
    { tool: 'nmap', desc: 'Default-creds NSE scripts across services' },
  ],
  A07: [
    { tool: 'nikto', desc: 'Authentication misconfig & session cookie flags' },
    { tool: 'nuclei', desc: 'Auth bypass, JWT, session templates' },
    { tool: 'nmap', desc: 'Default credentials NSE on SSH/FTP/HTTP' },
    { tool: 'wpscan', desc: 'WordPress auth & user enumeration (WP only)' },
  ],
  A08: [
    { tool: 'nuclei', desc: 'Deserialization & integrity check templates' },
    { tool: 'nikto', desc: 'Unsafe file inclusion / deserialization endpoints' },
    { tool: 'nmap', desc: 'Service-level integrity probing' },
  ],
  A09: [
    { tool: 'nikto', desc: 'Missing security headers (X-Frame, CSP, HSTS)' },
    { tool: 'nuclei', desc: 'Information disclosure & logging failure templates' },
    { tool: 'whatweb', desc: 'Error page & verbose output detection' },
  ],
  A10: [
    { tool: 'nmap', desc: 'NSE: http-errors, service crash, DoS probes' },
    { tool: 'nuclei', desc: 'Error-handling & crash disclosure templates' },
    { tool: 'nikto', desc: 'Verbose error & stack trace exposure' },
  ],
}

// Method → OWASP mapping (whitebox SAST)
const OWASP_WHITEBOX_METHODS = {
  A01: [
    { tool: 'Pattern Scanner', desc: 'Path traversal, IDOR, open redirect, CSRF detection' },
    { tool: 'AI Security Agent', desc: 'Broken access control & business logic analysis' },
  ],
  A02: [
    { tool: 'Pattern Scanner', desc: 'CORS misconfig, debug mode, XXE, file upload detection' },
    { tool: 'AI Security Agent', desc: 'Security headers & misconfiguration review' },
  ],
  A03: [
    { tool: 'Pattern Scanner', desc: 'Dependency version & vulnerable component detection' },
    { tool: 'AI Security Agent', desc: 'Outdated library & supply chain risk analysis' },
  ],
  A04: [
    { tool: 'Pattern Scanner', desc: 'MD5/SHA1, weak crypto, hardcoded keys detection' },
    { tool: 'AI Security Agent', desc: 'Cryptographic failure & TLS misconfig review' },
  ],
  A05: [
    { tool: 'Pattern Scanner', desc: 'SQLi, XSS, SSTI, command injection, eval/exec detection' },
    { tool: 'AI Security Agent', desc: 'Injection flaw & user-input-to-sink tracing' },
  ],
  A06: [
    { tool: 'Pattern Scanner', desc: 'Missing rate limit, weak password policy detection' },
    { tool: 'AI Security Agent', desc: 'Insecure design & business logic review' },
  ],
  A07: [
    { tool: 'Pattern Scanner', desc: 'Hardcoded credentials, JWT misuse detection' },
    { tool: 'AI Security Agent', desc: 'Authentication & session management review' },
  ],
  A08: [
    { tool: 'Pattern Scanner', desc: 'Unsafe deserialization, pickle, yaml.load detection' },
    { tool: 'AI Security Agent', desc: 'Data integrity & untrusted deserialization review' },
  ],
  A09: [
    { tool: 'Pattern Scanner', desc: 'console.log, missing logging, log injection detection' },
    { tool: 'AI Security Agent', desc: 'Security logging & monitoring gap review' },
  ],
  A10: [
    { tool: 'Pattern Scanner', desc: 'Swallowed errors, empty catch detection' },
    { tool: 'AI Security Agent', desc: 'Exception handling & error management review' },
  ],
}

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
  const [owaspCategories, setOwaspCategories] = useState(OWASP_CATEGORIES.map(c => c.code)) // all ticked by default
  const [owaspExpanded, setOwaspExpanded] = useState(null) // which OWASP section is expanded (null = all collapsed)
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

  const toggleOwasp = (code) => setOwaspCategories((p) => p.includes(code) ? p.filter((x) => x !== code) : [...p, code])
  const allOwaspCodes = OWASP_CATEGORIES.map(c => c.code)
  const toggleAllOwasp = () => setOwaspCategories(owaspCategories.length === allOwaspCodes.length ? [] : [...allOwaspCodes])

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
          owaspCategories,
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
          owaspCategories,
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
          owaspCategories,
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

  const modalContent = (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center p-3 sm:p-5 bg-black/85 overflow-hidden" onClick={onClose}>
      <div 
        className="relative w-full max-w-4xl h-[92vh] max-h-[92vh] flex flex-col rounded-2xl sm:rounded-3xl border border-white/[0.07] bg-[#111111] text-slate-100 animate-in fade-in zoom-in-95 duration-200 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-5 sm:px-6 py-4 bg-slate-950 shrink-0 z-10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-slate-950 shadow-md shadow-cyan-500/30">
              <Zap size={18} className="stroke-[2.5]" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-extrabold text-white tracking-tight">New Security Assessment</h2>
              <p className="text-[11px] text-slate-400 font-medium">Configure automated DAST Blackbox or SAST Whitebox vulnerability audit</p>
            </div>
          </div>
          <button type="button" onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors cursor-pointer" title="Close modal"><X size={18} /></button>
        </div>

        <form id="new-scan-form" onSubmit={submit} className="flex-1 min-h-0 overflow-y-auto p-5 sm:p-6 space-y-5 bg-slate-950/70">
          {/* Scan Type Mode Switcher */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <button type="button" onClick={() => setMode('blackbox')}
              className={`p-5 rounded-2xl border text-left transition-all duration-200 cursor-pointer relative overflow-hidden group ${mode === 'blackbox' ? 'border-cyan-400 bg-gradient-to-br from-cyan-950/60 to-slate-900 shadow-xl shadow-cyan-950/50 ring-2 ring-cyan-400/40' : 'border-white/10 bg-slate-950/60 hover:border-white/20 hover:bg-slate-900/60'}`}>
              <div className="flex items-center justify-between">
                <div className={`p-2.5 rounded-xl border ${mode === 'blackbox' ? 'bg-cyan-500 text-slate-950 border-cyan-400' : 'bg-slate-900 border-white/10 text-slate-400'}`}>
                  <Globe size={22} />
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${mode === 'blackbox' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30' : 'bg-white/5 text-slate-400'}`}>
                  DAST Web Engine
                </span>
              </div>
              <p className="mt-3 font-extrabold text-base text-white">Blackbox Assessment</p>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">External live web, API &amp; network target scanning via Native Kali engine</p>
            </button>

            <button type="button" onClick={() => setMode('whitebox')}
              className={`p-5 rounded-2xl border text-left transition-all duration-200 cursor-pointer relative overflow-hidden group ${mode === 'whitebox' ? 'border-cyan-400 bg-gradient-to-br from-cyan-950/60 to-slate-900 shadow-xl shadow-cyan-950/50 ring-2 ring-cyan-400/40' : 'border-white/10 bg-slate-950/60 hover:border-white/20 hover:bg-slate-900/60'}`}>
              <div className="flex items-center justify-between">
                <div className={`p-2.5 rounded-xl border ${mode === 'whitebox' ? 'bg-cyan-500 text-slate-950 border-cyan-400' : 'bg-slate-900 border-white/10 text-slate-400'}`}>
                  <FileCode2 size={22} />
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold uppercase ${mode === 'whitebox' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/30' : 'bg-white/5 text-slate-400'}`}>
                  SAST Code Audit
                </span>
              </div>
              <p className="mt-3 font-extrabold text-base text-white">Whitebox Code Audit</p>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">Source code AST audit, static analysis & auto-patching via Code Auditor agent</p>
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
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-200 flex items-center justify-between">
                  <span>Target URL / IP Address *</span>
                  <span className="text-[10px] text-slate-400 font-mono">e.g. https://target.com, http://192.168.1.1</span>
                </label>
                <div className="relative">
                  <input
                    className="input text-sm w-full !py-3 !pl-10 !pr-4 bg-slate-950/80 border-white/15 focus:border-cyan-400 font-mono text-cyan-300"
                    placeholder="https://example.com or 192.168.1.10"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                  />
                  <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
                </div>
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

              {/* OWASP Top 10 Category Selector — controls which tools run */}
              <div className="rounded-xl bg-slate-950/60 border border-white/10 p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                    <ShieldAlert size={14} className="text-cyan-400" />
                    OWASP Top 10 Categories ({owaspCategories.length}/10)
                  </label>
                  <button
                    type="button"
                    onClick={toggleAllOwasp}
                    className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                  >
                    {owaspCategories.length === allOwaspCodes.length ? 'untick all' : 'tick all'}
                  </button>
                </div>
                <p className="text-[10px] text-slate-500 leading-relaxed">
                  Tick the OWASP categories to scan. Tools under unticked categories will be skipped.
                </p>
                <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
                  {OWASP_CATEGORIES.map((cat) => {
                    const isTicked = owaspCategories.includes(cat.code)
                    const isExpanded = owaspExpanded === cat.code
                    const tools = OWASP_BLACKBOX_TOOLS[cat.code] || []
                    return (
                      <div key={cat.code} className={`rounded-lg border transition-all ${isTicked ? 'border-cyan-500/40 bg-cyan-950/20' : 'border-white/10 bg-slate-900/40'}`}>
                        <div className="flex items-center gap-2 p-2">
                          <button
                            type="button"
                            onClick={() => toggleOwasp(cat.code)}
                            className={`w-5 h-5 rounded-md border flex items-center justify-center transition-all shrink-0 cursor-pointer ${
                              isTicked
                                ? 'bg-cyan-500 border-cyan-400 text-slate-950'
                                : 'border-slate-600 hover:border-slate-400'
                            }`}
                          >
                            {isTicked && <Check size={12} strokeWidth={3} />}
                          </button>
                          <button
                            type="button"
                            onClick={() => setOwaspExpanded(isExpanded ? null : cat.code)}
                            className="flex items-center gap-1.5 flex-1 min-w-0 text-left cursor-pointer"
                          >
                            <span className="text-[14px]">{cat.icon}</span>
                            <span className={`text-[11px] font-bold ${isTicked ? 'text-cyan-300' : 'text-slate-400'}`}>
                              {cat.code}
                            </span>
                            <span className={`text-[11px] truncate ${isTicked ? 'text-slate-200' : 'text-slate-500'}`}>
                              {cat.name}
                            </span>
                            <span className="text-[9px] text-slate-500 ml-auto shrink-0">
                              {tools.length} tools
                            </span>
                            {isExpanded
                              ? <ChevronDown size={12} className="text-slate-500 shrink-0" />
                              : <ChevronRight size={12} className="text-slate-500 shrink-0" />}
                          </button>
                        </div>
                        {isExpanded && (
                          <div className="px-2 pb-2 space-y-1">
                            {tools.map((t, i) => (
                              <div key={i} className="flex items-start gap-1.5 p-1.5 rounded bg-slate-950/40">
                                <span className="text-[10px] font-mono font-bold text-cyan-400 shrink-0">{t.tool}</span>
                                <span className="text-[10px] text-slate-400 leading-snug">{t.desc}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
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

              {/* OWASP Top 10 Category Selector for Whitebox — controls which SAST checks run */}
              <div className="rounded-xl bg-slate-950/60 border border-white/10 p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                    <ShieldAlert size={14} className="text-cyan-400" />
                    OWASP Top 10 Categories ({owaspCategories.length}/10)
                  </label>
                  <button
                    type="button"
                    onClick={toggleAllOwasp}
                    className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                  >
                    {owaspCategories.length === allOwaspCodes.length ? 'untick all' : 'tick all'}
                  </button>
                </div>
                <p className="text-[10px] text-slate-500 leading-relaxed">
                  Tick the OWASP categories to audit. SAST checks under unticked categories will be skipped.
                </p>
                <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
                  {OWASP_CATEGORIES.map((cat) => {
                    const isTicked = owaspCategories.includes(cat.code)
                    const isExpanded = owaspExpanded === cat.code
                    const methods = OWASP_WHITEBOX_METHODS[cat.code] || []
                    return (
                      <div key={cat.code} className={`rounded-lg border transition-all ${isTicked ? 'border-cyan-500/40 bg-cyan-950/20' : 'border-white/10 bg-slate-900/40'}`}>
                        <div className="flex items-center gap-2 p-2">
                          <button
                            type="button"
                            onClick={() => toggleOwasp(cat.code)}
                            className={`w-5 h-5 rounded-md border flex items-center justify-center transition-all shrink-0 cursor-pointer ${
                              isTicked
                                ? 'bg-cyan-500 border-cyan-400 text-slate-950'
                                : 'border-slate-600 hover:border-slate-400'
                            }`}
                          >
                            {isTicked && <Check size={12} strokeWidth={3} />}
                          </button>
                          <button
                            type="button"
                            onClick={() => setOwaspExpanded(isExpanded ? null : cat.code)}
                            className="flex items-center gap-1.5 flex-1 min-w-0 text-left cursor-pointer"
                          >
                            <span className="text-[14px]">{cat.icon}</span>
                            <span className={`text-[11px] font-bold ${isTicked ? 'text-cyan-300' : 'text-slate-400'}`}>
                              {cat.code}
                            </span>
                            <span className={`text-[11px] truncate ${isTicked ? 'text-slate-200' : 'text-slate-500'}`}>
                              {cat.name}
                            </span>
                            <span className="text-[9px] text-slate-500 ml-auto shrink-0">
                              {methods.length} methods
                            </span>
                            {isExpanded
                              ? <ChevronDown size={12} className="text-slate-500 shrink-0" />
                              : <ChevronRight size={12} className="text-slate-500 shrink-0" />}
                          </button>
                        </div>
                        {isExpanded && (
                          <div className="px-2 pb-2 space-y-1">
                            {methods.map((t, i) => (
                              <div key={i} className="flex items-start gap-1.5 p-1.5 rounded bg-slate-950/40">
                                <span className="text-[10px] font-mono font-bold text-cyan-400 shrink-0">{t.tool}</span>
                                <span className="text-[10px] text-slate-400 leading-snug">{t.desc}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
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

        </form>

        {/* Pinned Sticky Footer */}
        <div className="border-t border-white/10 px-5 sm:px-6 py-3.5 bg-slate-900/95 backdrop-blur-lg flex items-center justify-between shrink-0 z-10">
          <button type="button" onClick={onClose} className="btn-ghost text-xs py-2 px-4 cursor-pointer text-slate-400 hover:text-white">
            Cancel
          </button>
          <button
            type="submit"
            form="new-scan-form"
            disabled={busy}
            className="btn-primary text-xs py-2 px-6 cursor-pointer shadow-lg shadow-cyan-500/25 bg-gradient-to-r from-cyan-500 via-cyan-400 to-blue-600 text-slate-950 font-black hover:scale-105 transition-transform flex items-center gap-2"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
            <span>{busy ? 'Starting Assessment...' : 'Launch Assessment'}</span>
          </button>
        </div>
      </div>
    </div>
  )

  return createPortal(modalContent, document.body)
}
