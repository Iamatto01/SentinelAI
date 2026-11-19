import React, { useState, useEffect, useMemo } from 'react'
import { FileDown, X, Check, Flag, Sparkles } from 'lucide-react'
import { api, getToken } from '../lib/api.js'
import { useTheme } from '../lib/ThemeContext.jsx'

const SEVERITY_OPTIONS = [
  { id: 'info', label: 'All Findings (Info+)', desc: 'Includes Informational, Low, Medium, High & Critical findings' },
  { id: 'low', label: 'Low & Above (Low+)', desc: 'Excludes informational notices; includes Low, Medium, High & Critical' },
  { id: 'medium', label: 'Medium & Above (Medium+)', desc: 'Focuses on actionable risks; includes Medium, High & Critical' },
  { id: 'high', label: 'High & Above (High+)', desc: 'Includes High and Critical severity vulnerabilities only' },
  { id: 'critical', label: 'Critical Only', desc: 'Includes only Critical severity vulnerabilities requiring immediate fix' },
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
  const { isNight } = useTheme()
  const [minSeverity, setMinSeverity] = useState('info')
  const [statusFilter, setStatusFilter] = useState('all')
  const [reportType, setReportType] = useState('full')
  const [filterNoise, setFilterNoise] = useState(false)
  
  // Scan details & filename state
  const [scan, setScan] = useState(propScan || null)
  const [scannerName, setScannerName] = useState(() => extractScannerName(propScan))
  const [targetName, setTargetName] = useState(() => extractTargetName(propScan))

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

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

  if (!isOpen) return null

  async function handleDownload() {
    setLoading(true)
    setError('')
    try {
      const genResult = await api.generateReport(scanId, minSeverity, statusFilter, reportType, {
        scannerName: scannerName.trim() || undefined,
        targetName: targetName.trim() || undefined,
        filterNoise,
      })
      if (!genResult?.ok) throw new Error('Report generation failed')
      
      // Secure download: use getToken() from api.js (supports sentinel_auth_token & legacy keys)
      const token = getToken() || ''
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

      const pdfBlob = new Blob([blob], { type: 'application/pdf' })

      // Strategy 1: Mobile Web Share API (Android & iOS)
      // Allows user on phone to Save to Files, Open in PDF Viewer, or Share
      if (typeof navigator !== 'undefined' && navigator.canShare) {
        try {
          const fileObj = new File([pdfBlob], finalFilename, { type: 'application/pdf' })
          if (navigator.canShare({ files: [fileObj] })) {
            await navigator.share({
              files: [fileObj],
              title: finalFilename,
              text: 'SentinelAI Security Assessment Report',
            })
            onClose()
            return
          }
        } catch (shareErr) {
          if (shareErr.name === 'AbortError') {
            // User dismissed share dialog
            onClose()
            return
          }
          console.warn('[WebShare fallback to browser download]:', shareErr)
        }
      }

      // Strategy 2: Reliable Cross-Platform Anchor Download
      const url = URL.createObjectURL(pdfBlob)
      const a = document.createElement('a')
      a.href = url
      a.download = finalFilename
      a.rel = 'noopener'
      a.target = '_blank'
      document.body.appendChild(a)
      a.click()

      // Strategy 3: Mobile fallback — if on mobile browser and download is sandboxed, also trigger window.open
      const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent)
      if (isMobile) {
        setTimeout(() => {
          try { window.open(url, '_blank') } catch {}
        }, 300)
      }

      // Keep blob URL active for 60 seconds so mobile PDF viewer can load fully before revoking
      setTimeout(() => {
        try { document.body.removeChild(a) } catch {}
        URL.revokeObjectURL(url)
      }, 60000)

      onClose()
    } catch (err) {
      setError(err.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={`fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 animate-in fade-in duration-200 ${
      isNight ? 'bg-black/80 backdrop-blur-md' : 'bg-slate-900/50 backdrop-blur-sm'
    }`}>
      <div className={`relative w-full max-w-xl max-h-[92vh] flex flex-col rounded-2xl border shadow-2xl overflow-hidden transition-colors ${
        isNight
          ? 'border-slate-800 bg-ink-900 text-slate-100'
          : 'border-slate-200 bg-white text-slate-800 shadow-xl'
      }`}>
        
        {/* Header */}
        <div className={`flex items-center justify-between border-b p-4 sm:p-5 shrink-0 transition-colors ${
          isNight ? 'border-slate-800 bg-ink-900' : 'border-slate-200 bg-slate-50/80'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 items-center justify-center rounded-xl border ${
              isNight ? 'bg-accent/15 text-accent border-accent/30' : 'bg-purple-100 text-purple-700 border-purple-200'
            }`}>
              <FileDown size={22} />
            </div>
            <div>
              <h2 className={`text-base sm:text-lg font-bold ${isNight ? 'text-slate-100' : 'text-slate-900'}`}>
                Export PDF Report
              </h2>
              <p className={`text-xs ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>
                Configure filters and export your assessment report
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className={`rounded-xl p-1.5 transition-colors ${
              isNight
                ? 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                : 'text-slate-500 hover:bg-slate-200/70 hover:text-slate-800'
            }`}
          >
            <X size={18} />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className={`flex-1 overflow-y-auto p-4 sm:p-5 space-y-4 ${isNight ? 'bg-ink-900' : 'bg-white'}`}>
          {error && (
            <div className={`rounded-xl border p-3.5 text-xs font-medium ${
              isNight ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-red-200 bg-red-50 text-red-700'
            }`}>
              {error}
            </div>
          )}

          {/* Report Version / Format */}
          <div className="space-y-2">
            <div className={`text-xs font-bold uppercase tracking-wider flex items-center justify-between ${
              isNight ? 'text-slate-400' : 'text-slate-600'
            }`}>
              <span>Report Version</span>
              <span className={`text-[10px] font-bold ${isNight ? 'text-accent' : 'text-purple-600'}`}>Select Simplified or Full</span>
            </div>
            {REPORT_TYPES.map((opt) => {
              const isSelected = reportType === opt.id
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setReportType(opt.id)}
                  className={`w-full flex items-start gap-3 rounded-xl border p-3 text-left transition-all ${
                    isSelected
                      ? isNight
                        ? 'border-accent bg-accent/10 ring-1 ring-accent'
                        : 'border-purple-500 bg-purple-50/70 ring-1 ring-purple-500/50 shadow-xs'
                      : isNight
                        ? 'border-slate-800/80 bg-ink-950/60 hover:bg-ink-800/50'
                        : 'border-slate-200 bg-slate-50/60 hover:bg-slate-100 hover:border-slate-300'
                  }`}
                >
                  <div className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
                    isSelected
                      ? isNight
                        ? 'border-accent bg-accent text-slate-950'
                        : 'border-purple-600 bg-purple-600 text-white'
                      : isNight
                        ? 'border-slate-700'
                        : 'border-slate-300 bg-white'
                  }`}>
                    {isSelected && <Check size={11} strokeWidth={3} />}
                  </div>
                  <div className="flex-1">
                    <span className={`text-xs sm:text-sm font-semibold ${
                      isSelected
                        ? isNight ? 'text-slate-100' : 'text-slate-900 font-bold'
                        : isNight ? 'text-slate-200' : 'text-slate-700'
                    }`}>{opt.label}</span>
                    <p className={`mt-0.5 text-[11px] ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>{opt.desc}</p>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Report Output Filename & Identification */}
          <div className={`rounded-xl border p-3.5 space-y-3 transition-colors ${
            isNight ? 'border-slate-800 bg-slate-950/70' : 'border-slate-200 bg-slate-50/70 shadow-xs'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileDown size={14} className={isNight ? 'text-cyan-400' : 'text-cyan-600'} />
                <span className={`text-xs font-bold ${isNight ? 'text-slate-200' : 'text-slate-800'}`}>Report Filename</span>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                isNight
                  ? 'text-cyan-400/80 bg-cyan-950/40 border-cyan-800/40'
                  : 'text-cyan-700 bg-cyan-100/70 border-cyan-200'
              }`}>
                (scanner-target-type-date)
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className={`text-[11px] font-semibold block mb-1 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                  Scanner Name
                </label>
                <input
                  type="text"
                  value={scannerName}
                  onChange={(e) => setScannerName(e.target.value)}
                  placeholder="e.g. sentinelai, nuclei, nmap"
                  className={`w-full rounded-lg border px-3 py-1.5 text-xs font-mono focus:outline-none transition-colors ${
                    isNight
                      ? 'border-slate-700 bg-slate-900 text-slate-100 focus:border-cyan-400'
                      : 'border-slate-300 bg-white text-slate-900 focus:border-cyan-600 focus:ring-1 focus:ring-cyan-500/30'
                  }`}
                />
              </div>

              <div>
                <label className={`text-[11px] font-semibold block mb-1 ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                  Target Name
                </label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  placeholder="e.g. example.com, 192.168.1.1"
                  className={`w-full rounded-lg border px-3 py-1.5 text-xs font-mono focus:outline-none transition-colors ${
                    isNight
                      ? 'border-slate-700 bg-slate-900 text-slate-100 focus:border-cyan-400'
                      : 'border-slate-300 bg-white text-slate-900 focus:border-cyan-600 focus:ring-1 focus:ring-cyan-500/30'
                  }`}
                />
              </div>
            </div>

            {/* Live Filename Banner */}
            <div className={`flex items-center gap-2 pt-2 border-t text-xs ${
              isNight ? 'border-slate-800/80' : 'border-slate-200'
            }`}>
              <span className={`text-[11px] shrink-0 font-medium ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>Output file:</span>
              <span className={`font-mono font-bold px-2 py-0.5 rounded-md border truncate max-w-full text-[11px] ${
                isNight
                  ? 'text-cyan-300 bg-cyan-950/60 border-cyan-500/30'
                  : 'text-cyan-800 bg-cyan-50 border-cyan-200 shadow-xs'
              }`}>
                {computedFilename}
              </span>
            </div>
          </div>

          {/* Simplified mode notice */}
          {reportType === 'simple' ? (
            <div className={`rounded-xl border p-3.5 text-xs space-y-1.5 ${
              isNight
                ? 'border-accent/30 bg-accent/5 text-slate-300'
                : 'border-purple-200 bg-purple-50/80 text-purple-900'
            }`}>
              <div className={`flex items-center gap-2 font-bold ${isNight ? 'text-accent' : 'text-purple-700'}`}>
                <Sparkles size={14} /> Simplified IT Action Guide Mode
              </div>
              <p className={`leading-relaxed text-[11px] ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                Automatically prioritizes critical, high, and medium issues with plain-language fix cards and verified reproduction steps. Scanner noise is filtered automatically.
              </p>
            </div>
          ) : (
            <>
              {/* Severity Options */}
              <div className="space-y-2">
                <div className={`text-xs font-bold uppercase tracking-wider ${isNight ? 'text-slate-400' : 'text-slate-600'}`}>
                  Minimum Severity Filter
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {SEVERITY_OPTIONS.map((opt) => {
                    const isSelected = minSeverity === opt.id
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => setMinSeverity(opt.id)}
                        className={`flex items-center gap-2.5 rounded-xl border p-2.5 text-left transition-all ${
                          isSelected
                            ? isNight
                              ? 'border-accent bg-accent/10 ring-1 ring-accent'
                              : 'border-purple-500 bg-purple-50/70 ring-1 ring-purple-500/50 shadow-xs'
                            : isNight
                              ? 'border-slate-800/80 bg-ink-950/60 hover:bg-ink-800/50'
                              : 'border-slate-200 bg-slate-50/60 hover:bg-slate-100 hover:border-slate-300'
                        }`}
                      >
                        <div className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full border ${
                          isSelected
                            ? isNight ? 'border-accent bg-accent text-slate-950' : 'border-purple-600 bg-purple-600 text-white'
                            : isNight ? 'border-slate-700' : 'border-slate-300 bg-white'
                        }`}>
                          {isSelected && <Check size={9} strokeWidth={3} />}
                        </div>
                        <span className={`text-xs font-medium truncate ${
                          isSelected
                            ? isNight ? 'text-slate-100 font-bold' : 'text-slate-900 font-bold'
                            : isNight ? 'text-slate-300' : 'text-slate-700'
                        }`}>
                          {opt.label}
                        </span>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Status Filter */}
              <div className="space-y-2">
                <div className={`flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider ${
                  isNight ? 'text-slate-400' : 'text-slate-600'
                }`}>
                  <Flag size={12} className={isNight ? 'text-accent' : 'text-purple-600'} /> Status Filter
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {STATUS_OPTIONS.map((opt) => {
                    const isSelected = statusFilter === opt.id
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => setStatusFilter(opt.id)}
                        className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                          isSelected
                            ? isNight
                              ? 'border-accent bg-accent/15 text-accent font-bold'
                              : 'border-purple-600 bg-purple-50 text-purple-700 font-bold shadow-xs'
                            : isNight
                              ? 'border-slate-800 bg-ink-950/60 text-slate-400 hover:text-slate-200'
                              : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'
                        }`}
                      >
                        {opt.label}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Noise Filter Toggle */}
              <div className={`rounded-xl border p-3 flex items-center justify-between ${
                isNight ? 'border-slate-800 bg-ink-950/60' : 'border-slate-200 bg-slate-50/70 shadow-xs'
              }`}>
                <div>
                  <span className={`text-xs font-semibold ${isNight ? 'text-slate-200' : 'text-slate-800'}`}>Noise Reduction Filter</span>
                  <p className={`text-[11px] ${isNight ? 'text-slate-400' : 'text-slate-500'}`}>Exclude unverified and out-of-scope notices</p>
                </div>
                <button
                  type="button"
                  onClick={() => setFilterNoise(!filterNoise)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    filterNoise
                      ? isNight ? 'bg-accent' : 'bg-purple-600'
                      : isNight ? 'bg-slate-700' : 'bg-slate-300'
                  }`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    filterNoise ? 'translate-x-4.5' : 'translate-x-1'
                  }`} />
                </button>
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className={`flex items-center justify-between border-t p-4 shrink-0 transition-colors ${
          isNight
            ? 'border-slate-800 bg-ink-950/90 backdrop-blur-md'
            : 'border-slate-200 bg-slate-50/90 backdrop-blur-md'
        }`}>
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className={`rounded-xl px-4 py-2.5 text-xs font-semibold transition-colors ${
              isNight
                ? 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                : 'text-slate-600 hover:bg-slate-200/80 hover:text-slate-900'
            }`}
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleDownload}
            disabled={loading}
            className={`flex items-center gap-2 rounded-xl px-5 py-2.5 text-xs font-bold disabled:opacity-50 transition-all ${
              isNight
                ? 'bg-accent text-slate-950 hover:bg-accent/90 shadow-glow'
                : 'bg-purple-600 text-white hover:bg-purple-700 shadow-sm active:scale-95'
            }`}
          >
            {loading ? (
              <>
                <div className={`h-4 w-4 animate-spin rounded-full border-2 border-t-transparent ${
                  isNight ? 'border-slate-950' : 'border-white'
                }`} />
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
  )
}
