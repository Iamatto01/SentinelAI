import React, { useState, useEffect, useMemo } from 'react'
import { FileDown, X, ShieldAlert, AlertTriangle, Info, Check, Flag, Eye, Edit3, Sliders, Sparkles, ShieldCheck } from 'lucide-react'
import { api } from '../lib/api.js'

const SEVERITY_OPTIONS = [
  { id: 'info', label: 'All Findings (Info+)', desc: 'Includes Informational, Low, Medium, High & Critical findings', color: 'border-slate-700 hover:border-slate-500 text-slate-300' },
  { id: 'low', label: 'Low & Above (Low+)', desc: 'Excludes informational notices; includes Low, Medium, High & Critical', color: 'border-blue-500/40 hover:border-blue-400 text-blue-400' },
  { id: 'medium', label: 'Medium & Above (Medium+)', desc: 'Focuses on actionable risks; includes Medium, High & Critical', color: 'border-amber-500/40 hover:border-amber-400 text-amber-400' },
  { id: 'high', label: 'High & Above (High+)', desc: 'Includes High and Critical severity vulnerabilities only', color: 'border-orange-500/40 hover:border-orange-400 text-orange-400' },
  { id: 'critical', label: 'Critical Only', desc: 'Includes only Critical severity vulnerabilities requiring immediate fix', color: 'border-red-500/40 hover:border-red-400 text-red-400' },
]

const STATUS_OPTIONS = [
  { id: 'all', label: 'All Statuses', desc: 'Include findings regardless of status' },
  { id: 'open', label: 'Open', desc: 'Only open findings' },
  { id: 'confirmed', label: 'Confirmed', desc: 'Only confirmed findings' },
  { id: 'fixed', label: 'Fixed', desc: 'Only fixed findings' },
  { id: 'false-positive', label: 'False Positive', desc: 'Only false-positive findings' },
]

const REPORT_TYPES = [
  { id: 'simple', label: '⚡ Simplified Report', desc: 'Concise summary with finding path, root cause, and remediation steps' },
  { id: 'full', label: '📄 Full Technical Report', desc: 'Complete pentest report with executive summary, methodology, evidence, and appendix' },
]

export function extractScannerName(scanObj) {
  if (!scanObj) return 'sentinelai'
  if (scanObj.scanner_name) return scanObj.scanner_name
  let mods = []
  if (Array.isArray(scanObj.modules)) mods = scanObj.modules
  else if (typeof scanObj.modules === 'string') {
    try { mods = JSON.parse(scanObj.modules) } catch {}
  }
  const toolMods = mods.filter(m => m && m !== 'folder-walker')
  if (toolMods.length === 1) return toolMods[0].toLowerCase()
  if (scanObj.template && !['standard', 'deep', 'quick', 'monitor', 'folder', 'code-audit'].includes(scanObj.template)) {
    return scanObj.template.toLowerCase()
  }
  return 'sentinelai'
}

export function extractTargetName(scanObj) {
  if (!scanObj) return 'target'
  let raw = scanObj.target || scanObj.repo_name || 'target'
  if (raw === '(whitebox)' && scanObj.repo_name) raw = scanObj.repo_name
  try {
    if (/^https?:\/\//i.test(raw)) {
      const u = new URL(raw)
      raw = u.hostname + (u.port && !['80', '443'].includes(u.port) ? `-${u.port}` : '')
    }
  } catch {
    raw = raw.replace(/^https?:\/\//i, '')
  }
  if (raw.includes('\\') || (raw.includes('/') && !raw.includes('.'))) {
    const parts = raw.split(/[\\/]/).filter(Boolean)
    if (parts.length > 0) raw = parts[parts.length - 1]
  }
  raw = raw.split('?')[0].split('#')[0].replace(/\/+$/, '')
  raw = raw.replace(/[^a-zA-Z0-9.-]/g, '-')
  raw = raw.replace(/-+/g, '-')
  return raw.replace(/^[-.]+|[-.]+$/g, '') || 'target'
}

export default function ReportModal({ isOpen, onClose, scanId, scan: propScan }) {
  const [activeTab, setActiveTab] = useState('settings') // 'settings' | 'preview'
  const [minSeverity, setMinSeverity] = useState('info')
  const [statusFilter, setStatusFilter] = useState('all')
  const [reportType, setReportType] = useState('full')
  const [filterNoise, setFilterNoise] = useState(false)
  
  // Scan details & filename state
  const [scan, setScan] = useState(propScan || null)
  const [scannerName, setScannerName] = useState(() => extractScannerName(propScan))
  const [targetName, setTargetName] = useState(() => extractTargetName(propScan))

  useEffect(() => {
    if (propScan) {
      setScan(propScan)
      setScannerName(extractScannerName(propScan))
      setTargetName(extractTargetName(propScan))
    } else if (scanId && isOpen) {
      api.scan(scanId).then((data) => {
        if (data?.scan) {
          setScan(data.scan)
          setScannerName(extractScannerName(data.scan))
          setTargetName(extractTargetName(data.scan))
        }
      }).catch(() => {})
    }
  }, [scanId, propScan, isOpen])

  // Computed report filename matching: (scanner_name-target-full/simplify-date.pdf)
  const computedFilename = useMemo(() => {
    const sc = (scannerName || 'sentinelai').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'sentinelai'
    const tg = (targetName || 'target').trim().replace(/[^a-zA-Z0-9.-]/g, '-').replace(/-+/g, '-').replace(/^[-.]+|[-.]+$/g, '') || 'target'
    const tp = (reportType === 'simple' || reportType === 'simplify') ? 'simplify' : 'full'
    let dt = ''
    if (scan?.created_at) {
      try {
        const d = new Date(scan.created_at)
        if (!isNaN(d.getTime())) dt = d.toISOString().slice(0, 10)
      } catch {}
    }
    if (!dt) dt = new Date().toISOString().slice(0, 10)
    return `${sc}-${tg}-${tp}-${dt}.pdf`
  }, [scannerName, targetName, reportType, scan])

  // Custom Editable Fields
  const [customTitle, setCustomTitle] = useState('')
  const [customSummary, setCustomSummary] = useState(
    'This security assessment report summarizes findings detected during automated and AI-assisted vulnerability testing. Recommendations should be validated by qualified security personnel prior to remediation.'
  )
  const [customScope, setCustomScope] = useState('Full Blackbox & Whitebox Target Infrastructure')
  const [customConclusion, setCustomConclusion] = useState(
    'All identified critical and high vulnerabilities should be remediated immediately. Apply patch management and implement secure coding best practices.'
  )

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  if (!isOpen) return null

  async function handleDownload() {
    setLoading(true)
    setError('')
    try {
      const genResult = await api.generateReport(scanId, minSeverity, statusFilter, reportType, {
        scannerName: scannerName.trim() || undefined,
        targetName: targetName.trim() || undefined,
        customTitle: customTitle.trim() || undefined,
        customSummary: customSummary.trim() || undefined,
        customScope: customScope.trim() || undefined,
        customConclusion: customConclusion.trim() || undefined,
        filterNoise,
      })
      if (!genResult?.ok) throw new Error('Report generation failed')
      
      // Secure download: use fetch with Authorization header instead of ?token= query param
      const token = localStorage.getItem('fyp2_token') || ''
      const downloadParams = new URLSearchParams({
        type: reportType,
        ...(scannerName.trim() ? { scanner: scannerName.trim() } : {}),
        ...(targetName.trim() ? { target: targetName.trim() } : {}),
      })
      const res = await fetch(`/api/reports/download/${scanId}?${downloadParams.toString()}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!res.ok) {
        if (res.status === 404) throw new Error('PDF not found — report may have failed to generate. Try again.')
        throw new Error(`Download failed (${res.status})`)
      }
      const blob = await res.blob()
      if (blob.size < 100) throw new Error('Generated PDF is empty — AI may have timed out. Try again.')
      
      let finalFilename = genResult?.filename || computedFilename
      const disposition = res.headers.get('content-disposition')
      if (disposition && disposition.includes('filename=')) {
        const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
        if (match && match[1]) {
          finalFilename = match[1].replace(/['"]/g, '').trim()
        }
      }

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = finalFilename
      document.body.appendChild(a)
      a.click()
      setTimeout(() => { URL.revokeObjectURL(url); document.body.removeChild(a) }, 1000)
      onClose()
    } catch (err) {
      setError(err.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-3 sm:p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl max-h-[92vh] flex flex-col rounded-2xl border border-slate-800 bg-ink-900 shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 p-4 sm:p-5 shrink-0 bg-ink-900">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent/15 text-accent border border-accent/30">
              <FileDown size={22} />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-100">Export & Customise PDF Report</h2>
              <p className="text-xs text-slate-400">Configure filters, preview, & edit report details before download</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-xl p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200">
            <X size={18} />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-ink-950 px-4 pt-2 gap-2 shrink-0">
          <button
            onClick={() => setActiveTab('settings')}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl border-t border-x transition-all ${
              activeTab === 'settings'
                ? 'border-slate-700 bg-ink-900 text-accent font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders size={14} /> Report Filters & Format
          </button>
          <button
            onClick={() => setActiveTab('preview')}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl border-t border-x transition-all ${
              activeTab === 'preview'
                ? 'border-slate-700 bg-ink-900 text-cyan-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Eye size={14} /> Live Text Preview & Editor
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-5">
          {error && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3.5 text-xs text-red-400 font-medium">
              {error}
            </div>
          )}

          {activeTab === 'settings' ? (
            <>
              {/* Report Version / Format */}
              <div className="space-y-2.5">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                  <span>Report Version</span>
                  <span className="text-[10px] text-accent font-bold">Select Simplified or Full</span>
                </div>
                {REPORT_TYPES.map((opt) => {
                  const isSelected = reportType === opt.id
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setReportType(opt.id)}
                      className={`w-full flex items-start gap-3 rounded-xl border p-3 text-left transition-all ${
                        isSelected ? 'border-accent bg-accent/10 ring-1 ring-accent' : 'border-slate-800/80 bg-ink-950/60 hover:bg-ink-800/50'
                      }`}
                    >
                      <div className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${isSelected ? 'border-accent bg-accent text-slate-950' : 'border-slate-700'}`}>
                        {isSelected && <Check size={11} strokeWidth={3} />}
                      </div>
                      <div className="flex-1">
                        <span className="text-xs sm:text-sm font-semibold text-slate-100">{opt.label}</span>
                        <p className="mt-0.5 text-[11px] text-slate-400">{opt.desc}</p>
                      </div>
                    </button>
                  )
                })}
              </div>

              {/* Report Output Filename & Identification */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileDown size={14} className="text-cyan-400" />
                    <span className="text-xs font-bold text-slate-200">Report Download Filename</span>
                  </div>
                  <span className="text-[10px] text-cyan-400/80 font-mono bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                    (scanner-target-full/simplify-date)
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                      Scanner Name
                    </label>
                    <input
                      type="text"
                      value={scannerName}
                      onChange={(e) => setScannerName(e.target.value)}
                      placeholder="e.g. sentinelai, nuclei, nmap"
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-400 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                      Target Name
                    </label>
                    <input
                      type="text"
                      value={targetName}
                      onChange={(e) => setTargetName(e.target.value)}
                      placeholder="e.g. example.com, 192.168.1.1"
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-400 focus:outline-none"
                    />
                  </div>
                </div>

                {/* Live Filename Preview Banner */}
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs">
                  <span className="text-[11px] text-slate-400 shrink-0 font-medium">Download file:</span>
                  <span className="font-mono font-bold text-cyan-300 bg-cyan-950/60 px-2.5 py-1 rounded-md border border-cyan-500/30 truncate max-w-full">
                    {computedFilename}
                  </span>
                </div>
              </div>

              {/* Simplified mode: hide all filters — only important stuff shown */}
              {reportType === 'simple' ? (
                <div className="rounded-xl border border-accent/30 bg-accent/5 p-4 text-xs text-slate-300 space-y-2">
                  <div className="flex items-center gap-2 font-bold text-accent">
                    <Sparkles size={14} /> Simplified Mode Active
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    The simplified report automatically filters out noise (INFO/low findings) and shows only actionable critical, high, and medium issues with plain-language fix cards. No additional configuration needed — just download.
                  </p>
                </div>
              ) : (
                <>
              {/* Severity Options */}
              <div className="space-y-2.5">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Minimum Severity Filter
                </div>
                {SEVERITY_OPTIONS.map((opt) => {
                  const isSelected = minSeverity === opt.id
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setMinSeverity(opt.id)}
                      className={`w-full flex items-start gap-3 rounded-xl border p-3 text-left transition-all ${
                        isSelected
                          ? 'border-accent bg-accent/10 ring-1 ring-accent'
                          : 'border-slate-800/80 bg-ink-950/60 hover:bg-ink-800/50'
                      }`}
                    >
                      <div className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                        isSelected ? 'border-accent bg-accent text-slate-950' : 'border-slate-700'
                      }`}>
                        {isSelected && <Check size={11} strokeWidth={3} />}
                      </div>
                      <div className="flex-1">
                        <span className={`text-xs sm:text-sm font-semibold ${isSelected ? 'text-slate-100' : 'text-slate-200'}`}>
                          {opt.label}
                        </span>
                        <p className="mt-0.5 text-[11px] text-slate-400">{opt.desc}</p>
                      </div>
                    </button>
                  )
                })}
              </div>

              {/* Status Filter */}
              <div className="space-y-2.5">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
                  <Flag size={13} className="text-accent" /> Status Filter
                </div>
                <div className="flex flex-col gap-2">
                  {STATUS_OPTIONS.map((opt) => {
                    const isSelected = statusFilter === opt.id
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => setStatusFilter(opt.id)}
                        className={`flex items-start gap-3 rounded-xl border p-3 text-left transition-all ${
                          isSelected
                            ? 'border-accent bg-accent/10 ring-1 ring-accent'
                            : 'border-slate-800/80 bg-ink-950/60 hover:bg-ink-800/50'
                        }`}
                      >
                        <div className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                          isSelected ? 'border-accent bg-accent text-slate-950' : 'border-slate-700'
                        }`}>
                          {isSelected && <Check size={11} strokeWidth={3} />}
                        </div>
                        <div className="flex-1">
                          <span className={`text-xs sm:text-sm font-semibold ${isSelected ? 'text-slate-100' : 'text-slate-200'}`}>
                            {opt.label}
                          </span>
                          <p className="mt-0.5 text-[11px] text-slate-400">{opt.desc}</p>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Noise Filter Toggle */}
              <div className="rounded-xl border border-slate-800 bg-ink-950/60 p-3.5 flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold text-slate-200">Noise Reduction Filter</span>
                  <p className="text-[11px] text-slate-400 mt-0.5">Exclude unverified version findings and out-of-scope notices</p>
                </div>
                <button
                  type="button"
                  onClick={() => setFilterNoise(!filterNoise)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    filterNoise ? 'bg-accent' : 'bg-slate-700'
                  }`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    filterNoise ? 'translate-x-4.5' : 'translate-x-1'
                  }`} />
                </button>
              </div>
              </>
              )}
            </>
          ) : (
            /* Live Text Editor Tab */
            <div className="space-y-4">
              <div className="flex items-center gap-2 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-3 text-xs text-cyan-300">
                <Edit3 size={15} className="shrink-0" />
                <span>You can edit the report title, executive summary, and recommendations before downloading the PDF.</span>
              </div>

              {/* Report Output Filename & Identification */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileDown size={14} className="text-cyan-400" />
                    <span className="text-xs font-bold text-slate-200">Report Download Filename</span>
                  </div>
                  <span className="text-[10px] text-cyan-400/80 font-mono bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
                    (scanner-target-full/simplify-date)
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                      Scanner Name
                    </label>
                    <input
                      type="text"
                      value={scannerName}
                      onChange={(e) => setScannerName(e.target.value)}
                      placeholder="e.g. sentinelai, nuclei, nmap"
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-400 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] font-semibold text-slate-400 block mb-1">
                      Target Name
                    </label>
                    <input
                      type="text"
                      value={targetName}
                      onChange={(e) => setTargetName(e.target.value)}
                      placeholder="e.g. example.com, 192.168.1.1"
                      className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 font-mono focus:border-cyan-400 focus:outline-none"
                    />
                  </div>
                </div>

                {/* Live Filename Preview Banner */}
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 text-xs">
                  <span className="text-[11px] text-slate-400 shrink-0 font-medium">Download file:</span>
                  <span className="font-mono font-bold text-cyan-300 bg-cyan-950/60 px-2.5 py-1 rounded-md border border-cyan-500/30 truncate max-w-full">
                    {computedFilename}
                  </span>
                </div>
              </div>

              {reportType === 'simple' ? (
                <div className="rounded-xl border border-accent/30 bg-accent/5 p-4 text-xs text-slate-300 space-y-2">
                  <div className="flex items-center gap-2 font-bold text-accent">
                    <Sparkles size={14} /> Simplified Mode Active
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    The simplified report is fully auto-generated from your scan results. It filters out noise and shows only actionable findings with plain-language fix cards. No manual editing needed — just download.
                  </p>
                </div>
              ) : (
                <>
              {/* Custom Report Title */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-300">Custom Report Title</label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder="e.g. Executive Penetration Testing & Vulnerability Assessment Report"
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              {/* Target / Scope Notes */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-300">Assessment Scope Notes</label>
                <input
                  type="text"
                  value={customScope}
                  onChange={(e) => setCustomScope(e.target.value)}
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              {/* Executive Summary */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-300">Executive Summary Text</label>
                <textarea
                  rows={3}
                  value={customSummary}
                  onChange={(e) => setCustomSummary(e.target.value)}
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 p-3 text-xs text-slate-100 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              {/* Conclusion & Recommendations */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-300">Conclusion & Remediation Notes</label>
                <textarea
                  rows={3}
                  value={customConclusion}
                  onChange={(e) => setCustomConclusion(e.target.value)}
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 p-3 text-xs text-slate-100 focus:border-cyan-400 focus:outline-none"
                />
              </div>
              </>
              )}

              {/* Live Formatted PDF Card Preview */}
              <div className="space-y-2 border-t border-slate-800 pt-4">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Sparkles size={13} className="text-accent" /> Live PDF Cover & Summary Preview
                  </span>
                  <span className="font-mono text-[10px] text-cyan-400 truncate max-w-[260px]">
                    {computedFilename}
                  </span>
                </div>
                <div className="rounded-2xl border border-slate-700 bg-slate-950 p-5 space-y-3 font-sans text-left shadow-inner">
                  <div className="border-b border-slate-800 pb-3">
                    <span className="text-[10px] uppercase font-bold text-accent tracking-widest">
                      {reportType === 'simple' ? 'SIMPLIFIED REPORT PREVIEW' : 'FULL TECHNICAL REPORT PREVIEW'}
                    </span>
                    <h3 className="text-sm font-extrabold text-white mt-1">
                      {reportType === 'simple' ? 'Simplified Security Assessment Summary' : (customTitle.trim() || 'Full Vulnerability Assessment & Penetration Test')}
                    </h3>
                    <p className="text-[11px] text-slate-400 mt-0.5">Scope: {reportType === 'simple' ? 'Auto-detected from scan' : (customScope || 'Default Scan Target')}</p>
                  </div>
                  {reportType === 'simple' ? (
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">Action Items Preview</span>
                      <p className="text-xs text-slate-300 leading-relaxed italic bg-slate-900/60 p-3 rounded-xl border border-white/5">
                        Auto-generated fix cards will appear here based on scan findings. Only critical, high, and medium issues are shown — noise is filtered out automatically.
                      </p>
                    </div>
                  ) : (
                    <>
                  <div className="space-y-1.5">
                    <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider">Executive Summary</span>
                    <p className="text-xs text-slate-300 leading-relaxed italic bg-slate-900/60 p-3 rounded-xl border border-white/5">
                      "{customSummary}"
                    </p>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider">Conclusion</span>
                    <p className="text-[11px] text-slate-400">{customConclusion}</p>
                  </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions — Sticky & Always Accessible */}
        <div className="flex items-center justify-between border-t border-slate-800 p-4 shrink-0 bg-ink-950/90 backdrop-blur-md">
          <button
            type="button"
            onClick={() => setActiveTab(activeTab === 'settings' ? 'preview' : 'settings')}
            className="flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-semibold text-cyan-400 hover:bg-cyan-500/10 transition-colors"
          >
            {activeTab === 'settings' ? (
              <> <Eye size={14} /> Preview & Edit Text </>
            ) : (
              <> <Sliders size={14} /> Back to Filters </>
            )}
          </button>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="rounded-xl px-4 py-2.5 text-xs font-semibold text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleDownload}
              disabled={loading}
              className="flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-xs font-bold text-slate-950 hover:bg-accent/90 disabled:opacity-50 shadow-glow transition-all"
            >
              {loading ? (
                <>
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                  Generating PDF...
                </>
              ) : (
                <>
                  <FileDown size={16} />
                  Download PDF ({reportType === 'simple' ? 'Simplified' : 'Full'})
                </>
              )}
            </button>
          </div>
        </div>

      </div>
    </div>
  )
}
