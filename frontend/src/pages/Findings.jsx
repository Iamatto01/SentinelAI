import React, { useEffect, useMemo, useState } from 'react'
import { Loader2, Bug, Trash2, FolderGit2, Radar, Search, Filter, RefreshCw, Flag, Crosshair, Play, Download, Database, Sparkles } from 'lucide-react'
import { FindingSkeleton } from '../components/SkeletonLoader.jsx'
import Tooltip from '../components/Tooltip.jsx'
import { api } from '../lib/api.js'
import { useAi } from '../lib/AiContext.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import FindingDetailDrawer from '../components/FindingDetailDrawer.jsx'
import { prettifyTitle } from '../lib/formatters.js'

const CATEGORY_ORDER = [
  'Web Application Attacks', 'API Security', 'JWT / Token Attacks',
  'SQL Injection', 'NoSQL Injection', 'Cross-Site Scripting (XSS)',
  'Command Injection', 'Path Traversal / LFI', 'SSRF',
  'Business Logic Flaws', 'Broken Access Control / IDOR',
  'Authentication / Credentials', 'Password Attacks', 'Session Management',
  'CORS / CSRF', 'Security Misconfiguration', 'Information Disclosure',
  'Subdomain Enumeration', 'Cloud Security', 'Container Security',
  'Active Directory Security', 'Network Security', 'IoT Security',
  'Mobile Security', 'Wireless Security', 'SCADA / ICS Security',
  'Cryptographic Failures', 'LLM / AI Security', 'Malware Analysis',
  'Reverse Engineering', 'Evasion / OPSEC', 'C2 / Persistence',
  'Phishing / Social Engineering', 'OSINT / Reconnaissance',
  'Compliance / STIG', 'Vulnerable Components', 'Other',
]

function categorizeFinding(f) {
  const t = (f.title || '').toLowerCase()
  if (/jwt|json.web.token/i.test(t)) return 'JWT / Token Attacks'
  if (/sql.injection|sqli/i.test(t)) return 'SQL Injection'
  if (/nosql|mongodb/i.test(t)) return 'NoSQL Injection'
  if (/xss|cross.site.script/i.test(t)) return 'Cross-Site Scripting (XSS)'
  if (/command.injection|rce|remote.code/i.test(t)) return 'Command Injection'
  if (/path.traversal|lfi|file.inclusion/i.test(t)) return 'Path Traversal / LFI'
  if (/ssrf/i.test(t)) return 'SSRF'
  if (/business.logic|race.condition/i.test(t)) return 'Business Logic Flaws'
  if (/idor|broken.access|privesc|privilege.escalation/i.test(t)) return 'Broken Access Control / IDOR'
  if (/brute.?force|password.*spray|credential.*stuff/i.test(t)) return 'Password Attacks'
  if (/auth|login|session|credential|oauth|mfa/i.test(t)) return 'Authentication / Credentials'
  if (/session.*fixation|cookie.*secure/i.test(t)) return 'Session Management'
  if (/cors|csrf/i.test(t)) return 'CORS / CSRF'
  if (/cloud|aws|azure|gcp|s3|kubernetes|k8s|container.*escape|docker/i.test(t)) return 'Cloud Security'
  if (/active.directory|kerberos|ldap|bloodhound/i.test(t)) return 'Active Directory Security'
  if (/nmap|port.*scan|network|heartbleed|ms17/i.test(t)) return 'Network Security'
  if (/iot|firmware|ble|zigbee/i.test(t)) return 'IoT Security'
  if (/mobile|android|ios|apk/i.test(t)) return 'Mobile Security'
  if (/wifi|wpa|wireless|bluetooth/i.test(t)) return 'Wireless Security'
  if (/scada|ics|modbus|plc/i.test(t)) return 'SCADA / ICS Security'
  if (/crypto|md5|sha1|weak.*hash|tls|ssl/i.test(t)) return 'Cryptographic Failures'
  if (/llm|prompt.*inject|jailbreak|ai.*redteam/i.test(t)) return 'LLM / AI Security'
  if (/malware|trojan|ransomware|reverse.*engineer|disassembl/i.test(t)) return 'Malware Analysis'
  if (/evasion|bypass.*av|amsi|opsec|anonymiz/i.test(t)) return 'Evasion / OPSEC'
  if (/c2|persistence|beacon|sliver|mythic/i.test(t)) return 'C2 / Persistence'
  if (/phish|social.*engineer|evilginx/i.test(t)) return 'Phishing / Social Engineering'
  if (/osint|recon|subdomain|dns.*enum/i.test(t)) return 'OSINT / Reconnaissance'
  if (/compliance|stig|pci|hipaa|nist/i.test(t)) return 'Compliance / STIG'
  if (/cve-|outdated|vulnerable.*version/i.test(t)) return 'Vulnerable Components'
  if (/api|graphql|swagger|openapi/i.test(t)) return 'API Security'
  if (/misconfig|missing.*header|hsts|csp|debug|waf/i.test(t)) return 'Security Misconfiguration'
  if (/exposed|disclosure|leak|robots|phpinfo|actuator|backup|dump/i.test(t)) return 'Information Disclosure'
  return 'Other'
}

const SEVS = ['all', 'critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['all', 'open', 'confirmed', 'in-progress', 'fixed', 'accepted', 'false-positive']

export default function Findings() {
  const { drawerFinding, setDrawerFinding, setActiveTabOverride } = useAi()
  const [findings, setFindings] = useState(null)
  const [projects, setProjects] = useState([])
  const [scans, setScans] = useState([])
  
  const [sevFilter, setSevFilter] = useState('all')
  const [projectFilter, setProjectFilter] = useState('all')
  const [scanFilter, setScanFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [backingUp, setBackingUp] = useState(false)
  const [backupMsg, setBackupMsg] = useState('')

  const [exploitingId, setExploitingId] = useState(null)
  const [exploitMessage, setExploitMessage] = useState('')

  useEffect(() => {
    if (drawerFinding) {
      setSelected(drawerFinding)
    }
  }, [drawerFinding])

  async function handleCreateBackup(format = 'json') {
    setBackingUp(true)
    setBackupMsg('')
    try {
      await api.createBackup()
      setBackupMsg(`Database backup created! Downloading ${format.toUpperCase()}...`)
      
      const token = localStorage.getItem('fyp2_token') || ''
      const downloadPath = format === 'db' ? api.rawBackupUrl : api.exportBackupUrl
      const res = await fetch(downloadPath, {
        headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      })
      if (!res.ok) throw new Error(`Download failed (${res.status})`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = format === 'db' ? `sentinelai_backup_${Date.now()}.db` : `sentinelai_findings_backup_${Date.now()}.json`
      document.body.appendChild(a)
      a.click()
      setTimeout(() => { URL.revokeObjectURL(url); document.body.removeChild(a) }, 1000)
    } catch (e) {
      setBackupMsg(`Backup failed: ${e.message}`)
    } finally {
      setBackingUp(false)
      setTimeout(() => setBackupMsg(''), 6000)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setLoading(true)
    setErr('')
    try {
      const [fData, pData, sData] = await Promise.all([
        api.findings(),
        api.projects().catch(() => []),
        api.scans().catch(() => []),
      ])
      setFindings(fData || [])
      setProjects(pData || [])
      setScans(sData || [])
    } catch (e) {
      setErr(e.message)
    } finally {
      setLoading(false)
    }
  }

  function onStatusChange(id, status) {
    // Optimistic: apply immediately, no revert needed for status
    setFindings((p) => p.map((f) => (f.id === id ? { ...f, status } : f)))
    setSelected((s) => (s && s.id === id ? { ...s, status } : s))
    api.setFindingStatus(id, status).catch(() => {
      // Revert on failure
      loadData()
    })
  }

  async function remove(id) {
    // Optimistic: remove immediately, restore on failure
    const prev = findings
    setFindings((p) => p.filter((f) => f.id !== id))
    setSelected((s) => (s && s.id === id ? null : s))
    try {
      await api.deleteFinding(id)
    } catch (e) {
      setFindings(prev)
      alert(`Delete failed: ${e.message}`)
    }
  }

  async function launchExploitFor(findingId) {
    setExploitingId(findingId)
    setExploitMessage('')
    try {
      const result = await api.launchExploitCampaign(findingId)
      const f = findings.find(x => x.id === findingId)
      if (result.campaignId) {
        setExploitMessage(`Campaign launched: ${result.campaignId}`)
        if (f) {
          setSelected(f)
          setActiveTabOverride?.('exploit')
        }
      } else if (result.alreadyExists) {
        setExploitMessage('Campaign already exists — opened exploit console')
        if (f) {
          setSelected(f)
          setActiveTabOverride?.('exploit')
        }
      } else {
        setExploitMessage(`Exploit check: ${result.status || 'no direct automated payload'}`)
        if (f) {
          setSelected(f)
          setActiveTabOverride?.('exploit')
        }
      }
    } catch (e) {
      setExploitMessage(`Exploit check: ${e.message}`)
      const f = findings.find(x => x.id === findingId)
      if (f) {
        setSelected(f)
        setActiveTabOverride?.('exploit')
      }
    } finally {
      setExploitingId(null)
      setTimeout(() => setExploitMessage(''), 8000)
    }
  }

  const availableScans = useMemo(() => {
    if (projectFilter === 'all') return scans
    return scans.filter(s => s.project_id === projectFilter)
  }, [scans, projectFilter])

  const filteredList = useMemo(() => {
    if (!findings) return []
    const filtered = findings.filter((f) => {
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false

      if (projectFilter !== 'all') {
        if (f.project_id !== projectFilter) return false
      }

      if (scanFilter !== 'all') {
        if (f.scan_id !== scanFilter) return false
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const titleMatch = (f.title || '').toLowerCase().includes(q)
        const targetMatch = (f.target || '').toLowerCase().includes(q)
        const descMatch = (f.description || '').toLowerCase().includes(q)
        const owaspMatch = (f.owasp_category || '').toLowerCase().includes(q)
        if (!titleMatch && !targetMatch && !descMatch && !owaspMatch) return false
      }

      if (statusFilter !== 'all' && (f.status || 'open') !== statusFilter) return false

      return true
    })

    const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    return filtered.sort((a, b) => {
      const ca = CATEGORY_ORDER.indexOf(categorizeFinding(a))
      const cb = CATEGORY_ORDER.indexOf(categorizeFinding(b))
      if (ca !== cb) return ca - cb
      return (SEV_ORDER[a.severity] || 99) - (SEV_ORDER[b.severity] || 99)
    })
  }, [findings, sevFilter, projectFilter, scanFilter, searchQuery, statusFilter])

  if (err) return <div className="card p-6 text-rose-400 border border-rose-500/30 bg-rose-500/10">{err}</div>
  if (loading && !findings) return <FindingSkeleton />

  return (
    <div className="space-y-6 motion-fade-up content-fade">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">Discovered Findings</h1>
          <p className="text-xs text-zinc-500">
            Showing {filteredList.length} of {findings.length} total vulnerabilities
          </p>
        </div>

        <div className="flex items-center gap-2">
          {backupMsg && (
            <span className="text-xs text-cyan-300 bg-cyan-500/15 border border-cyan-400/30 px-3 py-1.5 rounded-xl font-bold">
              {backupMsg}
            </span>
          )}
          {exploitMessage && (
            <span className="text-xs text-purple-300 bg-purple-500/15 border border-purple-400/30 px-3 py-1.5 rounded-xl font-bold flex items-center gap-1.5">
              <Crosshair size={13} className="text-purple-400 animate-pulse" />
              {exploitMessage}
            </span>
          )}
          <button
            onClick={() => handleCreateBackup('json')}
            disabled={backingUp}
            className="btn-ghost text-xs border-cyan-400/40 text-cyan-300 hover:bg-cyan-500/15 flex items-center gap-1.5"
            title="Create instant backup and download JSON"
          >
            {backingUp ? <Loader2 size={14} className="animate-spin text-cyan-400" /> : <Database size={14} />}
            Backup Database
          </button>
          <button onClick={loadData} className="btn-ghost text-xs">
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Vision UI Filter Control Bar */}
      <div className="card p-5 space-y-4 shadow-2xl">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="label flex items-center gap-1.5">
              <FolderGit2 size={13} className="text-cyan-400" /> Project Filter
            </label>
            <select
              value={projectFilter}
              onChange={(e) => {
                setProjectFilter(e.target.value)
                setScanFilter('all')
              }}
              className="input text-xs"
            >
              <option value="all">All Projects ({projects.length})</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} {p.client ? `(${p.client})` : ''}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="label flex items-center gap-1.5">
              <Radar size={13} className="text-cyan-400" /> Scan Filter
            </label>
            <select
              value={scanFilter}
              onChange={(e) => setScanFilter(e.target.value)}
              className="input text-xs"
            >
              <option value="all">All Scans ({availableScans.length})</option>
              {availableScans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target || 'Scan'} [{s.mode}] — {new Date(s.created_at).toLocaleDateString('en-GB')}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="label flex items-center gap-1.5">
              <Search size={13} className="text-cyan-400" /> Vulnerability Search
            </label>
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search title, target, OWASP..."
                className="input !pl-9 text-xs"
              />
              <Search size={14} className="absolute left-3 top-3 text-slate-400" />
            </div>
          </div>
        </div>

        {/* Severity Chips */}
        <div className="flex flex-wrap items-center justify-between border-t border-white/10 pt-3 gap-2">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400">
            <Filter size={13} /> Severity:
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SEVS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSevFilter(s)}
                className={`chip border capitalize transition-all text-xs px-3 py-1 rounded-full ${
                  sevFilter === s
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400/60 font-bold shadow-glow'
                    : 'bg-white/5 text-slate-400 border-white/10 hover:text-slate-200'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Status Chips */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400">
            <Flag size={13} /> Status:
          </div>
          {STATUSES.map((st) => (
            <button
              key={st}
              type="button"
              onClick={() => setStatusFilter(st)}
              className={`chip border capitalize transition-all text-xs px-3 py-1 rounded-full ${
                statusFilter === st
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400/60 font-bold shadow-glow'
                  : 'bg-white/5 text-slate-400 border-white/10 hover:text-slate-200'
              }`}
            >
              {st === 'false-positive' ? 'False Positive' : st}
            </button>
          ))}
        </div>
      </div>

      {/* Findings Grid */}
      {filteredList.length === 0 ? (
        <div className="card p-16 text-center">
          <Bug className="mx-auto text-cyan-400/50 mb-3" size={44} />
          <p className="text-slate-300 font-medium">No vulnerabilities match your filter criteria.</p>
          {(projectFilter !== 'all' || scanFilter !== 'all' || sevFilter !== 'all' || searchQuery) && (
            <button
              onClick={() => {
                setProjectFilter('all')
                setScanFilter('all')
                setSevFilter('all')
                setSearchQuery('')
                setStatusFilter('all')
              }}
              className="mt-3 text-xs text-cyan-300 font-bold hover:underline"
            >
              Reset All Filters
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredList.map((f) => (
            <div
              key={f.id}
              onClick={() => setSelected(f)}
              className="card p-5 hover:border-cyan-400/40 hover-lift transition-all duration-300 cursor-pointer relative group space-y-3"
            >
              <div className="flex items-start justify-between gap-3">
                <h3 className="font-bold text-white leading-snug flex-1 min-w-0 break-words group-hover:text-cyan-300 transition-colors">
                  {prettifyTitle(f.title)}
                </h3>
                <div className="flex items-center gap-2 shrink-0">
                  <Tooltip content="Launch AI Exploit Campaign">
                    <button
                      onClick={(e) => { e.stopPropagation(); launchExploitFor(f.id) }}
                      disabled={exploitingId === f.id}
                      className="icon-btn icon-btn-success"
                      aria-label="Launch exploit campaign"
                    >
                      {exploitingId === f.id ? <Loader2 size={13} className="animate-spin" /> : <Crosshair size={13} />}
                    </button>
                  </Tooltip>
                  <SeverityBadge severity={f.severity} />
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-400">
                <span className="truncate max-w-[220px] font-mono text-[11px] text-cyan-300/90">{f.target}</span>
                {f.project_name && (
                  <span className="rounded-md bg-white/5 border border-white/10 px-2 py-0.5 text-[10px] text-slate-300 font-bold">
                    {f.project_name}
                  </span>
                )}
              </div>

              {f.description && (
                <p className="text-xs text-slate-300 line-clamp-3 leading-relaxed font-normal">
                  {f.description}
                </p>
              )}

              <div className="flex flex-wrap gap-1.5 text-[11px] pt-1">
                <span className="chip bg-purple-500/15 text-purple-300 border-purple-500/30 font-bold">
                  {categorizeFinding(f)}
                </span>
                {f.owasp_category && (
                  <span className="chip bg-cyan-500/15 text-cyan-300 border-cyan-400/30 font-bold">
                    {f.owasp_category}
                  </span>
                )}
                {f.cwe_id && (
                  <span className="chip bg-white/5 text-slate-300 border-white/10">
                    {f.cwe_id}
                  </span>
                )}
              </div>

              {f.remediation && (
                <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/30 px-3.5 py-2.5">
                  <p className="text-[10px] font-extrabold uppercase tracking-wider text-emerald-400 mb-0.5">
                    Remediation
                  </p>
                  <p className="text-xs text-emerald-200/90 line-clamp-2">{f.remediation}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {selected && (
        <FindingDetailDrawer
          finding={selected}
          onClose={() => setSelected(null)}
          onStatusChange={onStatusChange}
          onDelete={remove}
        />
      )}
    </div>
  )
}

