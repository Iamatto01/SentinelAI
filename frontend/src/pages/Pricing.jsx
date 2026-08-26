import React, { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, CheckCircle2, XCircle, Sparkles, Calculator,
  HelpCircle, ChevronDown
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'

const GLASS_CARD = {
  background: 'rgba(255, 255, 255, 0.04)',
  backdropFilter: 'blur(40px) saturate(180%)',
  WebkitBackdropFilter: 'blur(40px) saturate(180%)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.06)',
}

// ── Feature Comparison Matrix (20+ rows) ─────────────────────────────────────
const FEATURE_MATRIX = [
  ['AI Code Audits', '50 / month', 'Unlimited'],
  ['GitHub Repositories', '5 linked repos', 'Unlimited'],
  ['Blackbox URL / IP Scans', true, true],
  ['Continuous Push & PR Webhooks', true, true],
  ['Automated Email PDF Reports', true, true],
  ['AI Auto-Fix Remediation Diffs', true, true],
  ['GitHub PR Inline Bot Review', false, true],
  ['Slack / Discord Webhook Alerts', false, true],
  ['Telegram Bot Alerting', false, true],
  ['Metasploit AEE Exploit Campaigns', false, true],
  ['Manual Approval Safety Gates', false, true],
  ['Executive White-label PDF Reports', false, true],
  ['PayloadsAllTheThings RAG PoC Samples', 'Standard index', 'Full 10k+ index'],
  ['51 AI Specialist Personas', 'Core personas', 'All personas'],
  ['Multi-LLM Consensus Verification', true, true],
  ['24/7 Surface Monitoring', false, true],
  ['Scan History & Re-run', '30 days', 'Unlimited'],
  ['Expert Consultation Hours', '—', '4 hours / month'],
  ['Virtual CISO Advisory', false, true],
  ['OWASP Top 10 2025 Compliance Audit', false, true],
  ['Priority Support SLA', 'Email (48h)', 'Dedicated (4h)'],
  ['Local-First Zero-Cloud Storage', true, true],
]

const FAQS = [
  {
    q: 'What payment methods do you accept?',
    a: 'Subscriptions are billed in USD via standard card payment. Annual billing saves you roughly 17% compared to the monthly rate on both Pro and Enterprise tiers.',
  },
  {
    q: 'Can I cancel at any time?',
    a: 'Yes. Both plans are cancel-anytime — your plan stays active until the end of the current billing period, and no further charges are made. Your scan history remains exportable.',
  },
  {
    q: 'What happens if I hit my scan quota?',
    a: 'Pro plans include 50 AI code audits per month. When the quota is reached, scans pause until the next cycle or an instant upgrade to Enterprise (unlimited audits). You are notified before any quota is exhausted.',
  },
  {
    q: 'Is my source code and scan data safe?',
    a: 'Absolutely. SentinelAI is local-first and zero-cloud by design: all findings, audit logs, and repository data live in a local SQLite WAL database on your own infrastructure. Nothing is shared with third parties.',
  },
  {
    q: 'Do exploit campaigns run automatically without my knowledge?',
    a: 'No. The Autonomous Exploitation Engine uses safe read-only verification for proof-of-concept steps, and any critical or destructive action requires explicit manual approval through safety gates.',
  },
  {
    q: 'How does SentinelAI compare to hiring a pentest firm?',
    a: 'A single traditional blackbox engagement typically costs $15,000+ with multi-week turnaround. SentinelAI delivers continuous autonomous assessment from $19/month — see the ROI calculator below.',
  },
]

function Cell({ value }) {
  if (value === true) return <CheckCircle2 size={16} className="text-emerald-400 mx-auto" />
  if (value === false) return <XCircle size={16} className="text-slate-600 mx-auto" />
  return <span className="text-[11px] text-slate-300 font-semibold">{value}</span>
}

export default function Pricing() {
  const [interval, setInterval] = useState('monthly')
  const [openFaq, setOpenFaq] = useState(null)

  // ── ROI Calculator state ────────────────────────────────────────────────
  const [auditsPerYear, setAuditsPerYear] = useState(4)
  const [costPerAudit, setCostPerAudit] = useState(15000)

  const roi = useMemo(() => {
    const traditionalCost = auditsPerYear * costPerAudit
    const sentinelCost = interval === 'yearly' ? 790 : 79 * 12
    const savings = Math.max(0, traditionalCost - sentinelCost)
    const pct = traditionalCost > 0 ? Math.round((savings / traditionalCost) * 100) : 0
    return { traditionalCost, sentinelCost, savings, pct }
  }, [auditsPerYear, costPerAudit, interval])

  return (
    <PublicLayout>
      <div className="max-w-6xl mx-auto px-4 sm:px-8 pt-16 sm:pt-24 pb-12 space-y-24">
        {/* ── Hero + Billing Toggle ────────────────────────────────────────── */}
        <section className="text-center space-y-6">
          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            Simple Plans, <span className="at-home__gradient-text">Enterprise Power</span>
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Subscribe to unlock autonomous AI code audits, Kali Linux vulnerability scans, continuous
            GitHub webhooks, and executive PDF reports.
          </p>

          {/* Monthly / Yearly Switch */}
          <div className="flex items-center justify-center gap-3 pt-2">
            <span className={`text-xs font-semibold ${interval === 'monthly' ? 'text-white' : 'text-slate-500'}`}>Monthly Billing</span>
            <button
              onClick={() => setInterval(interval === 'monthly' ? 'yearly' : 'monthly')}
              className="w-12 h-6 rounded-full bg-slate-900 border border-white/20 p-0.5 relative transition-colors cursor-pointer"
              aria-label="Toggle billing interval"
            >
              <div className={`w-5 h-5 rounded-full bg-cyan-400 transition-transform duration-200 ${interval === 'yearly' ? 'translate-x-6' : 'translate-x-0'}`} />
            </button>
            <span className={`text-xs font-semibold flex items-center gap-1.5 ${interval === 'yearly' ? 'text-white' : 'text-slate-500'}`}>
              Yearly Billing
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                Save 17%
              </span>
            </span>
          </div>
        </section>

        {/* ── Plan Cards ───────────────────────────────────────────────────── */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-10 max-w-4xl mx-auto">
          {/* Pro Card */}
          <div className="card p-8 sm:p-9 border-cyan-500/50 bg-gradient-to-b from-slate-900/90 via-slate-900/80 to-cyan-950/30 shadow-2xl shadow-cyan-950/40 ring-1 ring-cyan-400/40 relative flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 text-slate-950 font-extrabold text-[10px] tracking-wider uppercase shadow-lg shadow-cyan-500/30 flex items-center gap-1">
              <Sparkles size={10} className="fill-slate-950" /> Most Popular
            </div>

            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-extrabold text-white">SentinelAI Pro</h3>
                <div className="mt-3 flex items-baseline gap-1">
                  <span className="text-4xl font-black text-white">${interval === 'yearly' ? '190' : '19'}</span>
                  <span className="text-xs text-slate-400 font-medium">{interval === 'yearly' ? '/year' : '/month'}</span>
                </div>
                <p className="text-xs text-slate-400 mt-2">
                  Ideal for active developers and software teams needing continuous audit automation.
                </p>
              </div>
              <div className="h-px bg-white/10" />
              <ul className="space-y-3 text-xs text-slate-300">
                {[
                  ['50 AI Code Audits', ' / month'],
                  ['5 Linked Repositories', ' (Public & Private)'],
                  ['', 'Continuous Webhooks (Push & PR triggers)'],
                  ['', 'Automated Email PDF Delivery on every commit'],
                  ['', 'AI Auto-Fix & Remediation Diffs'],
                ].map(([b, rest], i) => (
                  <li key={i} className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-cyan-400 shrink-0" />
                    <span>{b && <strong>{b}</strong>}{rest}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="pt-8">
              <Link
                to={`/login?mode=register&plan=pro&interval=${interval}`}
                className="btn-shine w-full justify-center py-3.5 text-xs font-extrabold"
              >
                <span>Subscribe to SentinelAI Pro</span> <ArrowRight size={14} />
              </Link>
            </div>
          </div>

          {/* Enterprise Card */}
          <div className="card p-8 sm:p-9 border-white/10 bg-slate-950/70 hover:border-white/20 flex flex-col justify-between hover:scale-[1.02] transition-transform duration-300">
            <div className="space-y-6">
              <div>
                <h3 className="text-xl font-extrabold text-white">SentinelAI Enterprise</h3>
                <div className="mt-3 flex items-baseline gap-1">
                  <span className="text-4xl font-black text-white">${interval === 'yearly' ? '790' : '79'}</span>
                  <span className="text-xs text-slate-400 font-medium">{interval === 'yearly' ? '/year' : '/month'}</span>
                </div>
                <p className="text-xs text-slate-400 mt-2">
                  Full continuous DevSecOps pipeline for organizations requiring unlimited audits &amp; compliance.
                </p>
              </div>
              <div className="h-px bg-white/10" />
              <ul className="space-y-3 text-xs text-slate-300">
                {[
                  ['Unlimited AI Code Audits', ''],
                  ['Unlimited GitHub Repositories', ''],
                  ['', 'GitHub PR Bot Inline Code Review'],
                  ['', 'Real-time Slack / Discord Webhook Alerts'],
                  ['', 'Executive White-label PDF Reports & SLA'],
                ].map(([b, rest], i) => (
                  <li key={i} className="flex items-center gap-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span>{b && <strong>{b}</strong>}{rest}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="pt-8">
              <Link
                to={`/login?mode=register&plan=enterprise&interval=${interval}`}
                className="btn-neon-draw w-full justify-center py-3.5 text-xs font-extrabold"
              >
                <span>Subscribe to Enterprise</span> <ArrowRight size={14} />
              </Link>
            </div>
          </div>
        </section>

        {/* ── Detailed Feature Comparison Matrix ───────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Feature Comparison Matrix</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              Full side-by-side breakdown of Pro, Enterprise, and what a conventional pentest firm delivers.
            </p>
          </div>

          <div className="rounded-3xl overflow-hidden border border-white/10" style={GLASS_CARD}>
            <div className="overflow-x-auto">
              <table className="w-full text-left min-w-[640px]">
                <thead>
                  <tr className="border-b border-white/10 bg-black/30">
                    <th className="py-4 px-5 text-[11px] font-extrabold uppercase tracking-wider text-slate-400">Feature</th>
                    <th className="py-4 px-4 text-center text-[11px] font-extrabold uppercase tracking-wider text-cyan-300">Pro</th>
                    <th className="py-4 px-4 text-center text-[11px] font-extrabold uppercase tracking-wider text-emerald-300">Enterprise</th>
                    <th className="py-4 px-4 text-center text-[11px] font-extrabold uppercase tracking-wider text-slate-500">Traditional Firm</th>
                  </tr>
                </thead>
                <tbody>
                  {FEATURE_MATRIX.map(([feature, pro, ent]) => (
                    <tr key={feature} className="border-b border-white/5 last:border-0 hover:bg-white/[0.03] transition-colors">
                      <td className="py-3 px-5 text-xs font-semibold text-slate-200">{feature}</td>
                      <td className="py-3 px-4 text-center"><Cell value={pro} /></td>
                      <td className="py-3 px-4 text-center"><Cell value={ent} /></td>
                      <td className="py-3 px-4 text-center"><span className="text-[11px] text-slate-500">$15k+ / engagement</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* ── Interactive ROI Calculator ───────────────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-400/30 text-emerald-300 text-xs font-bold uppercase tracking-wider">
              <Calculator size={13} className="text-emerald-400" /> Cost Savings Calculator
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Interactive ROI Calculator</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              Drag the sliders to compare your annual security spend against SentinelAI Enterprise.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Sliders */}
            <div className="p-7 rounded-3xl space-y-8" style={GLASS_CARD}>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <label htmlFor="roi-audits" className="text-xs font-bold text-slate-200">Pentests per year</label>
                  <span className="text-sm font-black text-cyan-400">{auditsPerYear}&times;</span>
                </div>
                <input
                  id="roi-audits"
                  type="range"
                  min="1"
                  max="12"
                  value={auditsPerYear}
                  onChange={(e) => setAuditsPerYear(Number(e.target.value))}
                  className="w-full accent-cyan-400 cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-500"><span>1</span><span>12</span></div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <label htmlFor="roi-cost" className="text-xs font-bold text-slate-200">Cost per traditional engagement</label>
                  <span className="text-sm font-black text-amber-400">${costPerAudit.toLocaleString()}</span>
                </div>
                <input
                  id="roi-cost"
                  type="range"
                  min="5000"
                  max="50000"
                  step="1000"
                  value={costPerAudit}
                  onChange={(e) => setCostPerAudit(Number(e.target.value))}
                  className="w-full accent-amber-400 cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-500"><span>$5,000</span><span>$50,000</span></div>
              </div>

              <p className="text-[11px] text-slate-500 leading-relaxed border-t border-white/10 pt-4">
                Industry benchmark: a single external blackbox penetration test from a conventional
                security firm averages $15,000&ndash;$30,000 with multi-week turnaround.
              </p>
            </div>

            {/* Results */}
            <div className="p-7 rounded-3xl space-y-5 border border-emerald-400/25" style={{ ...GLASS_CARD, background: 'rgba(6, 40, 28, 0.25)' }}>
              <h3 className="text-sm font-extrabold uppercase tracking-wider text-emerald-300">Your Annual Comparison</h3>

              <div className="space-y-3">
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-black/40 border border-white/10">
                  <span className="text-xs text-slate-400">Traditional firm ({auditsPerYear}&times;/yr)</span>
                  <span className="text-base font-black text-rose-400">${roi.traditionalCost.toLocaleString()}</span>
                </div>
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-black/40 border border-white/10">
                  <span className="text-xs text-slate-400">SentinelAI Enterprise ({interval})</span>
                  <span className="text-base font-black text-cyan-400">${roi.sentinelCost.toLocaleString()}</span>
                </div>
              </div>

              <div className="p-5 rounded-2xl bg-emerald-500/10 border border-emerald-400/30 text-center space-y-1">
                <div className="text-[11px] font-bold uppercase tracking-wider text-emerald-300">You Save</div>
                <div className="text-3xl font-black text-emerald-400">${roi.savings.toLocaleString()}</div>
                <div className="text-xs text-slate-400">{roi.pct}% cheaper than traditional consulting</div>
              </div>

              <Link
                to="/login?mode=register&plan=enterprise&interval=yearly"
                className="btn-gradient-flow w-full justify-center py-3.5 text-xs font-extrabold"
              >
                Start Saving Now <ArrowRight size={14} />
              </Link>
            </div>
          </div>
        </section>

        {/* ── Billing FAQ ──────────────────────────────────────────────────── */}
        <section className="space-y-8">
          <div className="text-center space-y-2">
            <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-indigo-500/10 border border-indigo-400/30 text-indigo-300 text-xs font-bold uppercase tracking-wider">
              <HelpCircle size={13} className="text-indigo-400" /> Answers
            </div>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Billing FAQ</h2>
          </div>

          <div className="max-w-3xl mx-auto space-y-3">
            {FAQS.map((f, i) => {
              const open = openFaq === i
              return (
                <div key={f.q} className="rounded-2xl overflow-hidden border border-white/10" style={GLASS_CARD}>
                  <button
                    onClick={() => setOpenFaq(open ? null : i)}
                    className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left cursor-pointer hover:bg-white/[0.03] transition-colors"
                  >
                    <span className="text-xs sm:text-sm font-bold text-slate-100">{f.q}</span>
                    <ChevronDown size={16} className={`text-cyan-400 shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
                  </button>
                  {open && (
                    <div className="px-5 pb-4 text-xs text-slate-400 leading-relaxed border-t border-white/5 pt-3">
                      {f.a}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </section>

        {/* ── CTA ──────────────────────────────────────────────────────────── */}
        <section className="card p-10 sm:p-14 border border-cyan-500/30 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 text-center rounded-3xl shadow-2xl space-y-6">
          <h2 className="text-2xl sm:text-3xl font-bold text-white">Still Deciding?</h2>
          <p className="text-slate-400 text-xs sm:text-sm max-w-xl mx-auto leading-relaxed">
            Book a free consultation with the Security Architect to find the right fit for your organization.
          </p>
          <div className="flex justify-center gap-4">
            <Link to="/contact" className="btn-border-beam btn-lg">
              Talk to Us <ArrowRight size={16} />
            </Link>
          </div>
        </section>
      </div>
    </PublicLayout>
  )
}
