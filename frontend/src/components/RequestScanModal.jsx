import React, { useState, useEffect } from 'react'
import { X, Send, ShieldAlert, CheckCircle2 } from 'lucide-react'
import { api } from '../lib/api.js'

export default function RequestScanModal({ onClose, defaultProjectId = '', projects = [] }) {
  const [target, setTarget] = useState('')
  const [projectId, setProjectId] = useState(defaultProjectId)
  const [scanType, setScanType] = useState('Full Penetration Test')
  const [notes, setNotes] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  useEffect(() => {
    if (defaultProjectId) {
      setProjectId(defaultProjectId)
    } else if (projects.length > 0) {
      setProjectId(projects[0].id)
    }
  }, [defaultProjectId, projects])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!target.trim()) {
      setError('Target Scope / URL is required')
      return
    }
    setLoading(true)
    setError('')
    setSuccessMsg('')

    try {
      const res = await api.req('/api/scans/request', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          projectId,
          scanType,
          notes: notes.trim(),
        }),
      })

      if (res?.success) {
        setSuccessMsg('Scan request submitted! Notification sent to muhammadsaifudinmj@gmail.com')
        setTimeout(() => {
          onClose()
        }, 1800)
      } else {
        setError(res?.error || 'Failed to submit scan request')
      }
    } catch (err) {
      setError(err?.message || 'Failed to submit request')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-200">
      <div className="card w-full max-w-lg p-6 space-y-5 border border-cyan-500/30 shadow-glow relative bg-ink-950">
        <div className="flex items-center justify-between border-b border-white/10 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Send size={20} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-slate-100">Ask for New Scan</h3>
              <p className="text-xs text-slate-400">Request pentest execution from Security Team</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-100 p-1.5 rounded-lg hover:bg-white/10 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl bg-red-500/15 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
            <ShieldAlert size={16} className="shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="p-3.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 size={16} className="shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
              Target Scope / URL <span className="text-cyan-400">*</span>
            </label>
            <input
              type="text"
              className="input w-full font-mono text-sm"
              placeholder="e.g. https://fms.myces.com or 192.168.1.100"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
            />
          </div>

          {projects.length > 0 && (
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Target Project
              </label>
              <select
                className="input w-full text-sm bg-slate-900"
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.client || 'Client'})
                  </option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
              Requested Scan Profile
            </label>
            <select
              className="input w-full text-sm bg-slate-900"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="Full Penetration Test">Full Security Assessment (Deep Pentest)</option>
              <option value="Web Application Vulnerability Scan">Web Application Scan (OWASP Top 10)</option>
              <option value="Infrastructure & Network Audit">Infrastructure & Network Audit</option>
              <option value="Quick Security Check">Quick Health Check</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
              Additional Notes / Instructions
            </label>
            <textarea
              className="input w-full text-sm h-20"
              placeholder="Specify preferred timing, scope boundaries, or testing credentials..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>

          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-xs text-cyan-300 flex items-start gap-2">
            <span className="text-base leading-none">📧</span>
            <span>
              Submitting this request will automatically send an email notification to <strong>muhammadsaifudinmj@gmail.com</strong>.
            </span>
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-white/10">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary text-xs"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50"
            >
              <Send size={14} />
              {loading ? 'Sending Request...' : 'Send Scan Request'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
