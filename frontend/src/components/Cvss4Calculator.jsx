import React, { useState, useMemo } from 'react'
import { calculateBaseScoreV4, humanizeScore } from 'cvss4'
import { Copy, Check, Save, RotateCcw, ShieldCheck, Sparkles, AlertCircle } from 'lucide-react'
import { api } from '../lib/api.js'

const SEV_COLORS = {
  critical: 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-[0_0_15px_rgba(244,63,94,0.3)]',
  high: 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.3)]',
  medium: 'bg-purple-500/20 text-purple-200 border-purple-500/40 shadow-[0_0_15px_rgba(168,85,247,0.3)]',
  low: 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40 shadow-[0_0_15px_rgba(0,242,254,0.3)]',
  none: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
  info: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
}

const PRESETS = [
  { label: 'Remote Code Execution (RCE)', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H' },
  { label: 'SQL Injection (SQLi)', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' },
  { label: 'Auth Bypass / SSRF', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N' },
  { label: 'Cross-Site Scripting (XSS)', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N' },
  { label: 'Missing Security Header', vector: 'CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N' },
  { label: 'Informational / Recon Port', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N' },
]

const METRIC_GROUPS = [
  {
    title: '1. Exploitability (Attack Preconditions)',
    metrics: [
      {
        id: 'AV',
        name: 'Attack Vector (AV)',
        desc: 'Context by which vulnerability exploitation is possible.',
        options: [
          { value: 'N', label: 'Network [N]', hint: 'Remotely exploitable over internet' },
          { value: 'A', label: 'Adjacent [A]', hint: 'Local subnet, Wi-Fi, VPN' },
          { value: 'L', label: 'Local [L]', hint: 'Shell or local user account required' },
          { value: 'P', label: 'Physical [P]', hint: 'Physical contact with device required' },
        ],
      },
      {
        id: 'AC',
        name: 'Attack Complexity (AC)',
        desc: 'Evasion or conditions beyond attacker control.',
        options: [
          { value: 'L', label: 'Low [L]', hint: 'Specialized access conditions not required' },
          { value: 'H', label: 'High [H]', hint: 'Requires bypass of defense/race condition' },
        ],
      },
      {
        id: 'AT',
        name: 'Attack Requirements (AT)',
        desc: 'Deployment or execution prerequisites.',
        options: [
          { value: 'N', label: 'None [N]', hint: 'Attacks target in default configuration' },
          { value: 'P', label: 'Present [P]', hint: 'Specific non-default setting/state required' },
        ],
      },
      {
        id: 'PR',
        name: 'Privileges Required (PR)',
        desc: 'Level of privileges attacker must possess.',
        options: [
          { value: 'N', label: 'None [N]', hint: 'Unauthenticated / public attacker' },
          { value: 'L', label: 'Low [L]', hint: 'Standard non-privileged user access' },
          { value: 'H', label: 'High [H]', hint: 'Administrative or elevated privileges' },
        ],
      },
      {
        id: 'UI',
        name: 'User Interaction (UI)',
        desc: 'Requirement for a human user to participate.',
        options: [
          { value: 'N', label: 'None [N]', hint: 'No user interaction needed' },
          { value: 'P', label: 'Passive [P]', hint: 'Victim must visit link or view page' },
          { value: 'A', label: 'Active [A]', hint: 'Victim must perform specific sensitive action' },
        ],
      },
    ],
  },
  {
    title: '2. Vulnerable System Impact (Direct Consequences)',
    metrics: [
      {
        id: 'VC',
        name: 'Confidentiality Impact (VC)',
        desc: 'Impact to secrecy of data on vulnerable component.',
        options: [
          { value: 'H', label: 'High [H]', hint: 'Total disclosure of confidential data' },
          { value: 'L', label: 'Low [L]', hint: 'Partial or non-critical disclosure' },
          { value: 'N', label: 'None [N]', hint: 'No confidentiality loss' },
        ],
      },
      {
        id: 'VI',
        name: 'Integrity Impact (VI)',
        desc: 'Impact to trustworthiness of vulnerable component.',
        options: [
          { value: 'H', label: 'High [H]', hint: 'Total modification or deletion of data' },
          { value: 'L', label: 'Low [L]', hint: 'Minor modification permitted' },
          { value: 'N', label: 'None [N]', hint: 'No integrity modification' },
        ],
      },
      {
        id: 'VA',
        name: 'Availability Impact (VA)',
        desc: 'Impact to uptime and access to vulnerable component.',
        options: [
          { value: 'H', label: 'High [H]', hint: 'Complete shutdown or denial of service' },
          { value: 'L', label: 'Low [L]', hint: 'Intermittent slowdown or partial outage' },
          { value: 'N', label: 'None [N]', hint: 'No loss of availability' },
        ],
      },
    ],
  },
  {
    title: '3. Subsequent System Impact (Downstream Systems)',
    metrics: [
      {
        id: 'SC',
        name: 'Subsequent Confidentiality (SC)',
        desc: 'Loss of confidentiality in downstream / peer systems.',
        options: [
          { value: 'H', label: 'High [H]', hint: 'Full data breach of downstream assets' },
          { value: 'L', label: 'Low [L]', hint: 'Partial exposure of downstream assets' },
          { value: 'N', label: 'None [N]', hint: 'No downstream confidentiality impact' },
        ],
      },
      {
        id: 'SI',
        name: 'Subsequent Integrity (SI)',
        desc: 'Loss of integrity in downstream / peer systems.',
        options: [
          { value: 'H', label: 'High [H]', hint: 'Full compromise of downstream system integrity' },
          { value: 'L', label: 'Low [L]', hint: 'Partial downstream alteration' },
          { value: 'N', label: 'None [N]', hint: 'No downstream integrity impact' },
        ],
      },
      {
        id: 'SA',
        name: 'Subsequent Availability (SA)',
        desc: 'Loss of availability in downstream / peer systems.',
        options: [
          { value: 'H', label: 'High [H]', hint: 'Complete denial of downstream service' },
          { value: 'L', label: 'Low [L]', hint: 'Reduced performance on downstream service' },
          { value: 'N', label: 'None [N]', hint: 'No downstream availability impact' },
        ],
      },
    ],
  },
  {
    title: '4. Threat Metrics (Real-World Exploit Maturity)',
    metrics: [
      {
        id: 'E',
        name: 'Exploit Maturity (E)',
        desc: 'Current state of exploit technique / code in the wild.',
        options: [
          { value: 'X', label: 'Not Defined [X]', hint: 'Assume worst-case / default' },
          { value: 'A', label: 'Attacked [A]', hint: 'Active reported exploitation in wild' },
          { value: 'P', label: 'PoC [P]', hint: 'Functional proof-of-concept available' },
          { value: 'U', label: 'Unreported [U]', hint: 'No public exploit code available' },
        ],
      },
    ],
  },
]

function parseVector(vecStr) {
  const defaults = {
    AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
    VC: 'H', VI: 'H', VA: 'H',
    SC: 'N', SI: 'N', SA: 'N',
    E: 'X',
  }
  if (!vecStr || typeof vecStr !== 'string') return defaults
  const parts = vecStr.trim().split('/')
  const res = { ...defaults }
  for (const part of parts) {
    if (part.includes(':')) {
      const [k, v] = part.split(':')
      const key = k?.toUpperCase()
      const val = v?.toUpperCase()
      if (key && val && key !== 'CVSS') {
        res[key] = val
      }
    }
  }
  return res
}

function buildVector(m) {
  const parts = ['CVSS:4.0']
  const baseKeys = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']
  for (const k of baseKeys) {
    if (m[k]) parts.push(`${k}:${m[k]}`)
  }
  if (m.E && m.E !== 'X') parts.push(`E:${m.E}`)
  return parts.join('/')
}

export default function Cvss4Calculator({ initialVector, findingId, onUpdate }) {
  const [metrics, setMetrics] = useState(() => parseVector(initialVector))
  const [copied, setCopied] = useState(false)
  const [saving, setSaving] = useState(false)
  const [savedSuccess, setSavedSuccess] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)

  const vectorString = useMemo(() => buildVector(metrics), [metrics])

  const { score, rating, severityKey } = useMemo(() => {
    try {
      const s = calculateBaseScoreV4(vectorString)
      const rounded = Math.round(s * 10) / 10
      const r = humanizeScore(rounded)
      const sevKey = r ? r.toLowerCase() : 'info'
      return { score: rounded, rating: r || 'None', severityKey: sevKey }
    } catch (e) {
      return { score: 0.0, rating: 'Error', severityKey: 'info' }
    }
  }, [vectorString])

  const handleCopy = () => {
    navigator.clipboard.writeText(vectorString)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleSetMetric = (metricId, val) => {
    setMetrics(prev => ({ ...prev, [metricId]: val }))
    setSavedSuccess(false)
  }

  const handleLoadPreset = (vec) => {
    setMetrics(parseVector(vec))
    setSavedSuccess(false)
  }

  const handleSave = async () => {
    if (!findingId) return
    setSaving(true)
    setErrorMsg(null)
    try {
      const res = await api.setFindingCvss(findingId, vectorString)
      setSavedSuccess(true)
      if (onUpdate) onUpdate(res)
      setTimeout(() => setSavedSuccess(false), 3000)
    } catch (err) {
      setErrorMsg(err.message || 'Failed to save CVSS 4.0 vector')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-5 text-slate-200">
      {/* Top Banner: Score & Qualitative Rating */}
      <div className="p-4 rounded-2xl glass-deep border border-white/10 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
            <ShieldCheck size={26} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black tracking-tight text-white">{score.toFixed(1)}</span>
              <span className="text-xs text-slate-400">/ 10.0</span>
              <span className={`px-2.5 py-0.5 text-xs font-bold uppercase rounded-md border ${SEV_COLORS[severityKey] || SEV_COLORS.info}`}>
                {rating}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">FIRST CVSS v4.0 Standard Score</p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 transition"
            title="Copy CVSS 4.0 vector string"
          >
            {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
            {copied ? 'Copied' : 'Copy Vector'}
          </button>

          {findingId && (
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 transition disabled:opacity-50"
            >
              {savedSuccess ? <Check size={13} className="text-emerald-400" /> : <Save size={13} />}
              {saving ? 'Saving...' : savedSuccess ? 'Saved!' : 'Save Score'}
            </button>
          )}
        </div>
      </div>

      {/* Vector String Box */}
      <div className="p-3 rounded-xl bg-black/40 border border-white/5 font-mono text-xs text-cyan-300/90 break-all select-all flex items-center justify-between gap-2">
        <span>{vectorString}</span>
      </div>

      {errorMsg && (
        <div className="p-3 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle size={14} className="shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Quick Presets */}
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
          <Sparkles size={12} className="text-accent" /> Quick Archetype Templates
        </p>
        <div className="flex flex-wrap gap-1.5">
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleLoadPreset(p.vector)}
              className="px-2.5 py-1 text-[11px] rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 transition hover:border-cyan-500/40"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Interactive Metric Selectors */}
      <div className="space-y-4">
        {METRIC_GROUPS.map((grp, gIdx) => (
          <div key={gIdx} className="p-4 rounded-2xl glass-deep border border-white/10 space-y-3.5">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 border-b border-white/10 pb-2">
              {grp.title}
            </h4>

            <div className="space-y-3">
              {grp.metrics.map(m => (
                <div key={m.id} className="space-y-1.5">
                  <div className="flex items-baseline justify-between text-xs">
                    <span className="font-semibold text-slate-200">{m.name}</span>
                    <span className="text-[10px] text-slate-500">{m.desc}</span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                    {m.options.map(opt => {
                      const selected = metrics[m.id] === opt.value
                      return (
                        <button
                          key={opt.value}
                          onClick={() => handleSetMetric(m.id, opt.value)}
                          className={`px-2.5 py-1.5 rounded-lg text-left transition border ${
                            selected
                              ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/50 shadow-[0_0_10px_rgba(0,242,254,0.15)] font-bold'
                              : 'bg-white/5 text-slate-400 border-white/5 hover:bg-white/10 hover:text-slate-300'
                          }`}
                        >
                          <div className="text-[11px] leading-tight">{opt.label}</div>
                          <div className="text-[9px] opacity-70 truncate mt-0.5">{opt.hint}</div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
