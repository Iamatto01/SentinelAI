import React, { useEffect, useState } from 'react'
import { Loader2, Plus, Trash2, Activity, X, Power, AlertTriangle, CheckCircle2, Info, Play, Shield, Clock, User, Fingerprint } from 'lucide-react'
import { api, apiFetch } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'

const KIND = {
  alert: { icon: AlertTriangle, cls: 'text-sev-high' },
  error: { icon: AlertTriangle, cls: 'text-sev-critical' },
  ok: { icon: CheckCircle2, cls: 'text-emerald-400' },
  info: { icon: Info, cls: 'text-slate-400' },
}

export default function Monitoring() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [monitors, setMonitors] = useState(null)
  const [events, setEvents] = useState([])
  const [showNew, setShowNew] = useState(false)
  const [selected, setSelected] = useState(null)
  const [triggering, setTriggering] = useState({})
  const [form, setForm] = useState({ name: '', target: '', intervalMin: 60 })
  const [err, setErr] = useState('')
  const [auditLogs, setAuditLogs] = useState([])

  const load = () => api.monitors().then((mList) => {
    setMonitors(mList)
    if (selected) {
      api.monitor(selected).then(d => setEvents(d.events || [])).catch(() => {})
    }
  }).catch((e) => setErr(e.message))

  useEffect(() => {
    load()
    if (isAdmin) {
      api.auditLogs(20).then(setAuditLogs).catch(() => {})
    }
    const timer = setInterval(load, 5000)
    return () => clearInterval(timer)
  }, [selected])

  async function create(e) {
    e.preventDefault()
    try {
      await api.createMonitor(form)
      setShowNew(false)
      setForm({ name: '', target: '', intervalMin: 60 })
      load()
    } catch (e2) { setErr(e2.message) }
  }

  async function toggle(m) { await api.setMonitorEnabled(m.id, !m.enabled); load() }
  async function remove(id) { await api.deleteMonitor(id); if (selected === id) { setSelected(null); setEvents([]) } load() }
  
  async function runNow(id) {
    setTriggering(prev => ({ ...prev, [id]: true }))
    try {
      if (typeof api?.triggerMonitor === 'function') {
        await api.triggerMonitor(id)
      } else {
        await apiFetch(`/api/monitors/${id}/trigger`, { method: 'POST' })
      }
      setSelected(id)
      setTimeout(load, 1000)
    } catch (e2) { setErr(e2.message) }
    finally {
      setTriggering(prev => ({ ...prev, [id]: false }))
    }
  }

  async function view(id) {
    setSelected(id)
    const d = await api.monitor(id)
    setEvents(d.events || [])
  }

  if (!monitors) return <div className="flex justify-center py-20"><Loader2 className="animate-spin text-accent" size={28} /></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Monitoring</h1>
          <p className="text-sm text-slate-500">Scheduled recurring scans & alerts</p>
        </div>
        <button onClick={() => setShowNew(true)} className="btn-primary"><Plus size={16} /> New Monitor</button>
      </div>

      {err && <div className="card p-4 text-sev-critical text-sm">{err}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-3">
          {monitors.length === 0 && (
            <div className="card p-16 text-center">
              <Activity className="mx-auto text-slate-600 mb-3" size={40} />
              <p className="text-slate-400">No monitors yet.</p>
            </div>
          )}
          {monitors.map((m) => (
            <button key={m.id} onClick={() => view(m.id)}
              className={`card p-4 w-full text-left transition-colors ${selected === m.id ? 'border-accent/50' : 'hover:border-ink-500'}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-semibold text-slate-100 truncate">{m.name}</p>
                  <p className="text-xs text-slate-500 font-mono truncate">{m.target}</p>
                </div>
                <div className="flex items-center gap-2">
                  {m.status === 'running' && (
                    <span className="flex items-center gap-1 text-[11px] text-accent font-semibold animate-pulse">
                      <Loader2 size={12} className="animate-spin" /> running
                    </span>
                  )}
                  <span className={`chip border text-[10px] ${m.enabled ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-ink-700 text-slate-500 border-ink-600'}`}>
                    {m.enabled ? 'active' : 'paused'}
                  </span>
                </div>
              </div>
              <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500">
                <span>every {m.interval_min}m · risk {(m.last_risk ?? 0).toFixed(1)}</span>
                <span className="flex gap-1">
                  <span onClick={(e) => { e.stopPropagation(); runNow(m.id) }} className="p-1 rounded hover:bg-ink-700 text-accent hover:text-accent/80" title="Run Scan Now">
                    {triggering[m.id] ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                  </span>
                  <span onClick={(e) => { e.stopPropagation(); toggle(m) }} className="p-1 rounded hover:bg-ink-700 text-slate-400 hover:text-slate-200" title={m.enabled ? 'Disable' : 'Enable'}>
                    <Power size={14} />
                  </span>
                  <span onClick={(e) => { e.stopPropagation(); remove(m.id) }} className="p-1 rounded hover:bg-ink-700 text-slate-500 hover:text-sev-critical" title="Delete">
                    <Trash2 size={14} />
                  </span>
                </span>
              </div>
              {m.last_run && <p className="mt-1 text-[10px] text-slate-600">last run {new Date(m.last_run).toLocaleString()} · {m.last_status || '—'}</p>}
            </button>
          ))}
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">Events {selected ? '' : '(select a monitor)'}</h3>
          <div className="space-y-2 max-h-[500px] overflow-auto pr-1">
            {!selected && <p className="text-sm text-slate-600 py-10 text-center">Choose a monitor to view its event history.</p>}
            {selected && events.length === 0 && <p className="text-sm text-slate-600 py-10 text-center">No events yet.</p>}
            {events.map((ev) => {
              const K = KIND[ev.kind] || KIND.info
              const Icon = K.icon
              return (
                <div key={ev.id} className="flex gap-3 rounded-lg bg-ink-800/50 border border-ink-700/50 p-3">
                  <Icon size={16} className={`${K.cls} shrink-0 mt-0.5`} />
                  <div className="min-w-0">
                    <p className="text-sm text-slate-200">{ev.message}</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">{new Date(ev.created_at).toLocaleString()}</p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {isAdmin && (
        <div className="card p-5 mt-8 border border-accent/20">
          <div className="flex items-center justify-between mb-4">
            <h3 className="flex items-center gap-2 font-semibold text-slate-100">
              <Fingerprint size={18} className="text-accent" /> System Audit Logs
            </h3>
            <span className="text-xs text-slate-500">Last 20 Actions</span>
          </div>
          <div className="space-y-3">
            {auditLogs.length === 0 && (
              <p className="text-sm text-slate-600 py-6 text-center">No audit events recorded yet.</p>
            )}
            {auditLogs.map(log => (
              <div key={log.id} className="p-3 bg-ink-900/50 rounded-lg border border-white/5 flex flex-col md:flex-row md:items-center gap-3 md:gap-6 text-sm">
                <div className="flex-1">
                  <p className="text-slate-200 font-medium">{log.action}</p>
                  {log.detail && <p className="text-slate-500 text-xs mt-0.5 truncate max-w-[300px]">{log.detail}</p>}
                </div>
                <div className="flex items-center gap-4 text-xs text-slate-400 shrink-0">
                  <span className="flex items-center gap-1"><User size={12} className={log.actor === 'admin' ? 'text-accent' : ''} /> {log.actor || 'system'}</span>
                  <span className="flex items-center gap-1"><Clock size={12} /> {new Date(log.ts).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {showNew && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm p-4" onClick={() => setShowNew(false)}>
          <form onSubmit={create} className="card w-full max-w-md p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-slate-100">New Monitor</h2>
              <button type="button" onClick={() => setShowNew(false)} className="text-slate-500 hover:text-slate-200"><X size={20} /></button>
            </div>
            <div><label className="label">Name *</label><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
            <div><label className="label">Target *</label><input className="input font-mono text-sm" placeholder="https://example.com" value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} required /></div>
            <div><label className="label">Interval (minutes, min 5)</label><input type="number" min="5" className="input" value={form.intervalMin} onChange={(e) => setForm({ ...form, intervalMin: Number(e.target.value) })} /></div>
            <div className="flex justify-end gap-3 pt-1">
              <button type="button" onClick={() => setShowNew(false)} className="btn-ghost">Cancel</button>
              <button type="submit" className="btn-primary">Create</button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
