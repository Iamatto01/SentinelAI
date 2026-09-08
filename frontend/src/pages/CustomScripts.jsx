import React, { useEffect, useState } from 'react'
import {
  Loader2, RefreshCw, FileCode, Plus, Trash2, Pencil, Play, ToggleLeft, ToggleRight,
  CheckCircle2, XCircle, AlertTriangle, Terminal, Info
} from 'lucide-react'
import { api } from '../lib/api.js'

const LANGS = [
  { value: 'bash', label: 'Bash' },
  { value: 'python', label: 'Python 3' },
  { value: 'node', label: 'Node.js' },
]
const TRIGGERS = [
  { value: 'post-recon', label: 'Pipeline (post-recon)' },
  { value: 'post-scan', label: 'Pipeline (post-scan)' },
  { value: 'manual-only', label: 'Manual only (test button)' },
]
const SEV_FLOORS = ['info', 'low', 'medium', 'high', 'critical']

const EXAMPLE_BASH = `# Example: probe for exposed .git directory
# Env vars available: TARGET, SCAN_ID, DEPTH
RESP=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/.git/HEAD")
if [ "$RESP" = "200" ]; then
  echo '{"title":"Exposed .git directory","severity":"high","description":".git/HEAD is readable — source & history disclosure possible","cweId":"CWE-548","owaspCategory":"A05:2025-Security Misconfiguration"}'
fi`

const EXAMPLE_PYTHON = `import json, os, urllib.request
target = os.environ.get("TARGET", "")
# Example: check for missing security headers
req = urllib.request.Request(target, method="HEAD")
resp = urllib.request.urlopen(req, timeout=15)
missing = [h for h in ("X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security") if h not in resp.headers]
if missing:
    print(json.dumps({
        "title": "Missing security headers: " + ", ".join(missing),
        "severity": "medium",
        "description": "Response lacks hardening headers",
        "remediation": "Add the missing headers at the web server / reverse proxy layer",
        "owaspCategory": "A05:2025-Security Misconfiguration"
    }))`

const emptyForm = { name: '', description: '', language: 'bash', command: '', trigger_point: 'post-scan', enabled: 1, severity_floor: 'info' }

export default function CustomScripts() {
  const [scripts, setScripts] = useState([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState(null) // script object being edited
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [formErr, setFormErr] = useState('')
  // Test-run state
  const [testingId, setTestingId] = useState(null)
  const [testTarget, setTestTarget] = useState('')
  const [testResult, setTestResult] = useState(null)

  const load = () => {
    setLoading(true)
    api.customScripts()
      .then((d) => setScripts(d.scripts || []))
      .catch((e) => setErr(e.message))
      .finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const openCreate = () => { setEditing(null); setForm(emptyForm); setFormErr(''); setShowForm(true) }
  const openEdit = (s) => {
    setEditing(s)
    setForm({ name: s.name, description: s.description || '', language: s.language, command: s.command, trigger_point: s.trigger_point, enabled: s.enabled, severity_floor: s.severity_floor || 'info' })
    setFormErr(''); setShowForm(true)
  }

  async function save(e) {
    e.preventDefault()
    setSaving(true); setFormErr('')
    try {
      if (editing) await api.updateCustomScript(editing.id, form)
      else await api.createCustomScript(form)
      setShowForm(false)
      load()
    } catch (e2) { setFormErr(e2.message) } finally { setSaving(false) }
  }

  async function toggleEnabled(s) {
    try {
      await api.updateCustomScript(s.id, { enabled: s.enabled ? 0 : 1 })
      load()
    } catch (e) { setErr(e.message) }
  }

  async function remove(s) {
    if (!window.confirm(`Delete script "${s.name}"?`)) return
    try { await api.deleteCustomScript(s.id); load() } catch (e) { setErr(e.message) }
  }

  async function startTest(s) {
    setTestResult({ scriptId: s.id, scriptName: s.name, running: true })
    setTestingId(s.id)
    try {
      const r = await api.testCustomScript(s.id, testTarget.trim())
      setTestResult({ ...r, scriptId: s.id, scriptName: s.name })
    } catch (e) { setTestResult({ error: e.message, scriptId: s.id, scriptName: s.name }) } finally { setTestingId(null) }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <FileCode size={24} className="text-accent" /> Custom Scripts
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Write your own scanning scripts (bash / python / node). They run as a pipeline stage and report findings as JSON lines.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="btn-ghost flex items-center gap-2" disabled={loading}>
            {loading ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />} Refresh
          </button>
          <button onClick={openCreate} className="btn-primary flex items-center gap-2">
            <Plus size={16} /> New Script
          </button>
        </div>
      </div>

      {err && (
        <div className="card border-red-500/30 p-3 flex items-center gap-2 text-sm text-red-300">
          <AlertTriangle size={16} /> {err}
        </div>
      )}

      {/* Test target bar */}
      <div className="card p-4">
        <label className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Default test target</label>
        <input
          type="url"
          placeholder="http://target.example.com"
          value={testTarget}
          onChange={(e) => setTestTarget(e.target.value)}
          className="input mt-2 font-mono text-sm"
        />
        <p className="text-xs text-slate-500 mt-2 flex items-start gap-1.5">
          <Info size={14} className="shrink-0 mt-0.5" />
          Used by the Test button on each script. Scripts also receive <code className="text-accent">TARGET</code>, <code className="text-accent">SCAN_ID</code> and <code className="text-accent">DEPTH</code> as environment variables during real scans.
        </p>
      </div>

      {/* Script list */}
      {loading ? (
        <div className="card p-8 grid place-items-center text-slate-400"><Loader2 className="animate-spin" /></div>
      ) : scripts.length === 0 ? (
        <div className="card p-8 text-center text-slate-400 space-y-2">
          <Terminal size={32} className="mx-auto text-slate-600" />
          <p>No custom scripts yet.</p>
          <p className="text-xs">Create one to extend the scanner with your own detection logic — e.g. niche CVE checks, custom header audits, business-logic probes.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {scripts.map((s) => (
            <div key={s.id} className="card p-4 space-y-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-slate-100">{s.name}</span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-accent/15 text-accent border border-accent/30">{s.language}</span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-slate-700/50 text-slate-300 border border-slate-600/50">{s.trigger_point}</span>
                    {s.severity_floor !== 'info' && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-500/15 text-amber-300 border border-amber-500/30">floor: {s.severity_floor}</span>
                    )}
                  </div>
                  {s.description && <p className="text-sm text-slate-400 mt-1">{s.description}</p>}
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button onClick={() => toggleEnabled(s)} title={s.enabled ? 'Disable' : 'Enable'} className="p-2 rounded-lg hover:bg-slate-700/50 text-slate-300">
                    {s.enabled ? <ToggleRight size={22} className="text-emerald-400" /> : <ToggleLeft size={22} className="text-slate-500" />}
                  </button>
                  <button onClick={() => startTest(s)} disabled={testingId === s.id} title="Test run" className="p-2 rounded-lg hover:bg-slate-700/50 text-slate-300 disabled:opacity-50">
                    {testingId === s.id ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} className="text-emerald-400" />}
                  </button>
                  <button onClick={() => openEdit(s)} title="Edit" className="p-2 rounded-lg hover:bg-slate-700/50 text-slate-300">
                    <Pencil size={16} />
                  </button>
                  <button onClick={() => remove(s)} title="Delete" className="p-2 rounded-lg hover:bg-red-500/10 text-red-400">
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
              <pre className="text-xs font-mono bg-black/40 border border-slate-700/50 rounded-lg p-3 overflow-auto max-h-40 text-slate-300 whitespace-pre-wrap">{s.command}</pre>
            </div>
          ))}
        </div>
      )}

      {/* Test result panel */}
      {testResult && (
        <div className="card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-slate-100 flex items-center gap-2">
              <Play size={16} className="text-emerald-400" />
              Test result{testResult.scriptName ? ` — ${testResult.scriptName}` : ''}
            </h3>
            <button onClick={() => setTestResult(null)} className="text-slate-500 hover:text-slate-300 text-sm">✕</button>
          </div>
          {testResult.error ? (
            <div className="flex items-center gap-2 text-sm text-red-300"><XCircle size={16} /> {testResult.error}</div>
          ) : testResult.running ? (
            <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 size={16} className="animate-spin" /> Running…</div>
          ) : (
            <>
              <div className="flex flex-wrap gap-4 text-sm">
                <span className="flex items-center gap-1.5">
                  {testResult.success ? <CheckCircle2 size={16} className="text-emerald-400" /> : <XCircle size={16} className="text-sev-critical" />}
                  exit {testResult.exitCode}
                </span>
                <span className="text-slate-400">{Math.round((testResult.durationMs || 0) / 100) / 10}s</span>
                <span className="text-slate-400">{(testResult.findings || []).length} finding(s)</span>
              </div>
              {(testResult.findings || []).length > 0 && (
                <div className="space-y-2">
                  {testResult.findings.map((f, i) => (
                    <div key={i} className="border border-slate-700/50 rounded-lg p-3 bg-black/20">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase sev-${f.severity}`}>{f.severity}</span>
                        <span className="font-medium text-slate-100 text-sm">{f.title}</span>
                      </div>
                      {f.description && <p className="text-xs text-slate-400 mt-1.5">{f.description}</p>}
                    </div>
                  ))}
                </div>
              )}
              {testResult.stdout && (
                <details>
                  <summary className="text-xs text-slate-400 cursor-pointer hover:text-slate-200">Raw stdout</summary>
                  <pre className="text-xs font-mono bg-black/40 border border-slate-700/50 rounded-lg p-3 mt-2 overflow-auto max-h-60 text-slate-300 whitespace-pre-wrap">{testResult.stdout}</pre>
                </details>
              )}
              {testResult.stderr && (
                <details>
                  <summary className="text-xs text-slate-400 cursor-pointer hover:text-slate-200">Raw stderr</summary>
                  <pre className="text-xs font-mono bg-black/40 border border-slate-700/50 rounded-lg p-3 mt-2 overflow-auto max-h-40 text-red-300/80 whitespace-pre-wrap">{testResult.stderr}</pre>
                </details>
              )}
            </>
          )}
        </div>
      )}

      {/* Create / Edit modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" onClick={() => setShowForm(false)}>
          <div className="card w-full max-w-3xl max-h-[90vh] overflow-auto p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-slate-100">{editing ? 'Edit Script' : 'New Custom Script'}</h2>

            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-400 uppercase">Name *</label>
                <input className="input mt-1" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Git directory exposure check" required />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-400 uppercase">Language *</label>
                <select className="input mt-1" value={form.language} onChange={(e) => setForm({ ...form, language: e.target.value })}>
                  {LANGS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-400 uppercase">Description</label>
              <input className="input mt-1" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="What this script detects" />
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-slate-400 uppercase">Trigger point</label>
                <select className="input mt-1" value={form.trigger_point} onChange={(e) => setForm({ ...form, trigger_point: e.target.value })}>
                  {TRIGGERS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-400 uppercase">Severity floor</label>
                <select className="input mt-1" value={form.severity_floor} onChange={(e) => setForm({ ...form, severity_floor: e.target.value })}>
                  {SEV_FLOORS.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <p className="text-xs text-slate-500 mt-1">Findings below this severity are dropped (noise control).</p>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-400 uppercase">Script body *</label>
                <div className="flex gap-2">
                  <button type="button" className="text-xs text-accent hover:underline" onClick={() => setForm({ ...form, language: 'bash', command: EXAMPLE_BASH })}>Insert bash example</button>
                  <button type="button" className="text-xs text-accent hover:underline" onClick={() => setForm({ ...form, language: 'python', command: EXAMPLE_PYTHON })}>Insert python example</button>
                </div>
              </div>
              <textarea
                className="input mt-1 font-mono text-xs h-64"
                value={form.command}
                onChange={(e) => setForm({ ...form, command: e.target.value })}
                placeholder={'# Env: TARGET, SCAN_ID, DEPTH\n# Print one JSON object per line for each finding:\n# {"title":"...","severity":"high","description":"..."}'}
                required
              />
              <p className="text-xs text-slate-500 mt-1">
                Output contract: print one JSON object per line (<code className="text-accent">title</code> required; optional <code className="text-accent">severity</code>, <code className="text-accent">description</code>, <code className="text-accent">remediation</code>, <code className="text-accent">cweId</code>, <code className="text-accent">owaspCategory</code>, <code className="text-accent">evidence</code>). Non-JSON lines are ignored.
              </p>
            </div>

            <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input type="checkbox" checked={!!form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked ? 1 : 0 })} className="accent-emerald-500" />
              Enabled (runs during scans)
            </label>

            {formErr && <div className="text-sm text-red-300 flex items-center gap-2"><AlertTriangle size={14} /> {formErr}</div>}

            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={() => setShowForm(false)} className="btn-ghost">Cancel</button>
              <button type="submit" onClick={save} disabled={saving} className="btn-primary flex items-center gap-2">
                {saving && <Loader2 size={16} className="animate-spin" />} {editing ? 'Save changes' : 'Create script'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
