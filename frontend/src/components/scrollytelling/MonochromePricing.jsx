import React, { useState, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  CheckCircle2, XCircle, Sparkles, ArrowRight, QrCode, CreditCard,
  Zap, Calculator, ChevronDown, ChevronUp, ShieldCheck
} from 'lucide-react'
import SpotlightCard from './SpotlightCard.jsx'

const FEATURE_MATRIX = [
  ['AI Code Audits', '3 (Trial)', '1 / credit', '50 / month', 'Unlimited'],
  ['GitHub Repositories', '1 repo', '1 repo', '5 linked repos', 'Unlimited'],
  ['Blackbox URL / IP Scans', true, true, true, true],
  ['Continuous Push & PR Webhooks', false, false, true, true],
  ['Automated Email PDF Reports', true, true, true, true],
  ['AI Auto-Fix Remediation Diffs', false, false, true, true],
  ['GitHub PR Inline Bot Review', false, false, false, true],
  ['Slack / Discord Webhook Alerts', false, false, false, true],
  ['Telegram Bot Alerting', false, false, false, true],
  ['Metasploit AEE Exploit Campaigns', false, false, false, true],
  ['Manual Approval Safety Gates', true, true, true, true],
  ['Executive White-label PDF Reports', false, false, false, true],
  ['PayloadsAllTheThings RAG Index', 'Basic', 'Standard', 'Standard', 'Full 10k+ Index'],
  ['53 AI Specialist Personas', '3 personas', 'Core personas', 'Core personas', 'All 53 personas'],
  ['Multi-LLM Consensus Verification', true, true, true, true],
  ['24/7 Surface Monitoring', false, false, false, true],
  ['Scan History & Audit Logs', '7 days', '14 days', '30 days', 'Unlimited'],
  ['Expert Consultation Hours', '—', '—', '—', '4 hours / month'],
  ['Virtual CISO Advisory', false, false, false, true],
  ['OWASP Top 10 2025 Compliance', false, false, true, true],
  ['Priority Support SLA', 'Community', 'Standard', 'Email (48h)', 'Dedicated (4h)'],
  ['Local-First Zero-Cloud Storage', true, true, true, true],
]

export default function MonochromePricing() {
  const [interval, setInterval] = useState('monthly') // 'monthly' | 'yearly'
  const [plans, setPlans] = useState([])
  const [showMatrix, setShowMatrix] = useState(false)

  // ROI Calculator
  const [auditsPerYear, setAuditsPerYear] = useState(4)
  const [costPerAudit, setCostPerAudit] = useState(15000)

  useEffect(() => {
    fetch('/api/billing/plans')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.plans?.length) setPlans(d.plans)
      })
      .catch(() => {})
  }, [])

  const proPlan = plans.find((p) => p.id === 'pro') || { priceMonthly: 20, priceYearly: 200 }
  const entPlan = plans.find((p) => p.id === 'enterprise') || { priceMonthly: 80, priceYearly: 800 }
  const ppsPlan = plans.find((p) => p.id === 'pay_per_scan') || { priceMonthly: 3 }

  const roi = useMemo(() => {
    const traditionalCost = auditsPerYear * costPerAudit
    const entCost = interval === 'yearly' ? entPlan.priceYearly : entPlan.priceMonthly * 12
    const savings = Math.max(0, traditionalCost - entCost)
    const pct = traditionalCost > 0 ? Math.round((savings / traditionalCost) * 100) : 0
    return { traditionalCost, sentinelCost: entCost, savings, pct }
  }, [auditsPerYear, costPerAudit, interval, entPlan])

  return (
    <section id="pricing" className="relative scroll-mt-20 py-28 sm:py-36 bg-black border-t border-white/10 text-white">
      {/* Top Overhead Volumetric Spotlight Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-[480px] -translate-y-1/2 opacity-35 blur-3xl z-0"
        style={{
          background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.22), transparent)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4 mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-white/15 bg-white/[0.04] text-[11px] font-mono text-neutral-300">
            <Sparkles size={13} className="text-white" />
            <span className="font-bold uppercase tracking-wider">
              SUBSCRIPTION &amp; QUOTA TIERS // ZERO COMMISSIONS
            </span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight font-sans">
            Transparent Pricing <br />
            <span className="bg-gradient-to-b from-white via-neutral-200 to-neutral-500 bg-clip-text text-transparent">
              Engineered for Developers &amp; Red Teams
            </span>
          </h2>

          <p className="text-sm sm:text-base text-neutral-400 font-sans leading-relaxed">
            Subscribe to unlock autonomous AI code audits, Kali Linux vulnerability scans, continuous
            GitHub webhooks, and executive PDF reports. Every new account starts with 3 free trial audits.
          </p>

          {/* Payment Gateways Badges */}
          <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-xs font-mono">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-white/10 bg-white/[0.03] text-neutral-300">
              <QrCode size={13} className="text-white" /> DuitNow QR (All Banks &amp; eWallets)
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-white/10 bg-white/[0.03] text-neutral-300">
              <CreditCard size={13} className="text-white" /> Stripe (Cards / Apple Pay / Google Pay)
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-white/10 bg-white/[0.03] text-neutral-300">
              <Zap size={13} className="text-white" /> FPX Online Banking
            </span>
          </div>

          {/* Monthly / Yearly Switch */}
          <div className="flex items-center justify-center gap-3 pt-4">
            <span className={`text-xs font-mono font-semibold ${interval === 'monthly' ? 'text-white' : 'text-neutral-500'}`}>
              Monthly Billing
            </span>
            <button
              type="button"
              onClick={() => setInterval(interval === 'monthly' ? 'yearly' : 'monthly')}
              className="w-12 h-6 rounded-full bg-neutral-900 border border-white/20 p-0.5 relative transition-colors cursor-pointer"
              aria-label="Toggle billing interval"
            >
              <div
                className={`w-5 h-5 rounded-full bg-white transition-transform duration-200 ${
                  interval === 'yearly' ? 'translate-x-6' : 'translate-x-0'
                }`}
              />
            </button>
            <span className={`text-xs font-mono font-semibold flex items-center gap-1.5 ${interval === 'yearly' ? 'text-white' : 'text-neutral-500'}`}>
              <span>Yearly Billing</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-white text-black font-bold uppercase">
                Save 17%
              </span>
            </span>
          </div>
        </div>

        {/* 4-Column Tiered Pricing Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16 sm:mb-20">
          {/* TIER 1: Free Trial */}
          <SpotlightCard className="p-6 sm:p-7 flex flex-col justify-between">
            <div className="space-y-6">
              <div>
                <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border border-white/20 bg-white/5 text-neutral-300">
                  FREE TRIAL
                </span>
                <h3 className="text-xl font-extrabold text-white mt-3 font-sans">Explorer</h3>
                <div className="mt-3 flex items-baseline gap-1 font-mono">
                  <span className="text-3xl font-black text-white">RM 0</span>
                  <span className="text-xs text-neutral-400">/ forever</span>
                </div>
                <p className="text-xs text-neutral-400 mt-2 font-sans">
                  Kickstart your security assessment. Test any domain or code repo with 3 full trial scans.
                </p>
              </div>

              <div className="h-px bg-white/10" />

              <ul className="space-y-2.5 text-xs text-neutral-300 font-sans">
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span><strong>3 Full Security Scans</strong> included</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>150+ Toolchain (DAST &amp; SAST)</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Live Terminal stdout stream</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Executive PDF Report</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>No credit card required</span>
                </li>
              </ul>
            </div>

            <div className="pt-8">
              <Link
                to="/login?mode=register&plan=trial"
                className="w-full py-2.5 px-4 rounded-xl border border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10 text-xs font-mono font-bold flex items-center justify-center transition-all"
              >
                Start Free Trial
              </Link>
            </div>
          </SpotlightCard>

          {/* TIER 2: Pay-Per-Scan Credit */}
          <SpotlightCard className="p-6 sm:p-7 flex flex-col justify-between">
            <div className="space-y-6">
              <div>
                <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border border-white/20 bg-white/5 text-neutral-300">
                  ON-DEMAND TOP-UP
                </span>
                <h3 className="text-xl font-extrabold text-white mt-3 font-sans">Pay-Per-Scan</h3>
                <div className="mt-3 flex items-baseline gap-1 font-mono">
                  <span className="text-3xl font-black text-white">RM {ppsPlan.priceMonthly}</span>
                  <span className="text-xs text-neutral-400">/ scan</span>
                </div>
                <p className="text-xs text-neutral-400 mt-2 font-sans">
                  Top-up single autonomous scans on demand. No recurring monthly commitment.
                </p>
              </div>

              <div className="h-px bg-white/10" />

              <ul className="space-y-2.5 text-xs text-neutral-300 font-sans">
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span><strong>1 Full Security Scan</strong> credit</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Full 150+ Toolchain access</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Live stdout terminal telemetry</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Instant downloadable PDF Report</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Credits never expire</span>
                </li>
              </ul>
            </div>

            <div className="pt-8">
              <Link
                to="/login?mode=register&plan=pay_per_scan"
                className="w-full py-2.5 px-4 rounded-xl border border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10 text-xs font-mono font-bold flex items-center justify-center transition-all"
              >
                Buy Credit (RM {ppsPlan.priceMonthly})
              </Link>
            </div>
          </SpotlightCard>

          {/* TIER 3: SentinelAI Pro (HIGHLIGHTED "MOST POPULAR") */}
          <div className="relative rounded-2xl border-2 border-white bg-gradient-to-b from-[#141414] via-[#0A0A0A] to-black p-6 sm:p-7 flex flex-col justify-between shadow-[0_0_40px_rgba(255,255,255,0.18)] ring-1 ring-white/50 lg:-translate-y-2">
            {/* Top Glowing Tag */}
            <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-white text-black font-mono font-black text-[10px] tracking-widest uppercase shadow-[0_0_15px_rgba(255,255,255,0.6)] flex items-center gap-1">
              <Sparkles size={11} className="fill-black stroke-black" />
              <span>MOST POPULAR</span>
            </div>

            <div className="space-y-6 pt-1">
              <div>
                <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border border-white/40 bg-white/10 text-white">
                  AUTONOMOUS PENTESTER
                </span>
                <h3 className="text-xl font-extrabold text-white mt-3 font-sans">SentinelAI Pro</h3>
                <div className="mt-3 flex items-baseline gap-1 font-mono">
                  <span className="text-4xl font-black text-white">
                    RM {interval === 'yearly' ? proPlan.priceYearly : proPlan.priceMonthly}
                  </span>
                  <span className="text-xs text-neutral-400">
                    {interval === 'yearly' ? '/ year' : '/ month'}
                  </span>
                </div>
                <p className="text-xs text-neutral-300 mt-2 font-sans">
                  Ideal for active developers and software teams needing continuous audit automation.
                </p>
              </div>

              <div className="h-px bg-white/20" />

              <ul className="space-y-2.5 text-xs text-neutral-200 font-sans">
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span><strong>50 AI Code Audits</strong> / month</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span><strong>5 Linked Repositories</strong></span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Continuous GitHub Push/PR Webhooks</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Automated Email PDF Delivery</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>AI Auto-Fix &amp; Remediation Diffs</span>
                </li>
              </ul>
            </div>

            <div className="pt-8">
              <Link
                to={`/login?mode=register&plan=pro&interval=${interval}`}
                className="w-full py-3 px-4 rounded-xl bg-white text-black hover:bg-neutral-200 text-xs font-mono font-black uppercase tracking-wider flex items-center justify-center gap-1.5 shadow-[0_0_20px_rgba(255,255,255,0.4)] transition-all hover:scale-[1.02]"
              >
                <span>Subscribe to Pro</span>
                <ArrowRight size={14} />
              </Link>
            </div>
          </div>

          {/* TIER 4: SentinelAI Enterprise */}
          <SpotlightCard className="p-6 sm:p-7 flex flex-col justify-between">
            <div className="space-y-6">
              <div>
                <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border border-white/20 bg-white/5 text-neutral-300">
                  RED TEAM VIP
                </span>
                <h3 className="text-xl font-extrabold text-white mt-3 font-sans">Enterprise</h3>
                <div className="mt-3 flex items-baseline gap-1 font-mono">
                  <span className="text-4xl font-black text-white">
                    RM {interval === 'yearly' ? entPlan.priceYearly : entPlan.priceMonthly}
                  </span>
                  <span className="text-xs text-neutral-400">
                    {interval === 'yearly' ? '/ year' : '/ month'}
                  </span>
                </div>
                <p className="text-xs text-neutral-400 mt-2 font-sans">
                  Full continuous DevSecOps pipeline for organizations requiring unlimited audits &amp; vCISO.
                </p>
              </div>

              <div className="h-px bg-white/10" />

              <ul className="space-y-2.5 text-xs text-neutral-300 font-sans">
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span><strong>Unlimited AI Code Audits</strong></span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span><strong>Unlimited GitHub Repos</strong></span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>1-on-1 Certified Consultant Advisory</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Slack / Discord / Telegram Relays</span>
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-white shrink-0" />
                  <span>Dedicated 4h SLA &amp; White-label PDF</span>
                </li>
              </ul>
            </div>

            <div className="pt-8">
              <Link
                to={`/login?mode=register&plan=enterprise&interval=${interval}`}
                className="w-full py-2.5 px-4 rounded-xl border border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10 text-xs font-mono font-bold flex items-center justify-center transition-all"
              >
                Subscribe to Enterprise
              </Link>
            </div>
          </SpotlightCard>
        </div>

        {/* ── Interactive ROI Savings Calculator ── */}
        <div className="mb-16 rounded-2xl border border-white/15 bg-[#080808]/90 p-6 sm:p-8 font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-white/10 gap-2">
            <div className="flex items-center gap-2">
              <Calculator size={18} className="text-white" />
              <h3 className="text-base font-bold text-white font-sans">
                Interactive Enterprise ROI Calculator
              </h3>
            </div>
            <span className="text-xs text-neutral-400">
              Traditional Pentest Firm vs. SentinelAI Enterprise
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 my-6">
            <div className="space-y-5">
              <div>
                <div className="flex justify-between text-xs text-neutral-300 mb-2">
                  <span>Traditional Audits per Year:</span>
                  <span className="font-bold text-white">{auditsPerYear} audits</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="12"
                  value={auditsPerYear}
                  onChange={(e) => setAuditsPerYear(Number(e.target.value))}
                  className="w-full accent-white cursor-pointer"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs text-neutral-300 mb-2">
                  <span>Average Cost per Pentest Engagement:</span>
                  <span className="font-bold text-white">RM {costPerAudit.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="5000"
                  max="50000"
                  step="2500"
                  value={costPerAudit}
                  onChange={(e) => setCostPerAudit(Number(e.target.value))}
                  className="w-full accent-white cursor-pointer"
                />
              </div>
            </div>

            <div className="p-5 rounded-xl bg-black/60 border border-white/10 flex flex-col justify-between space-y-4">
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div>
                  <div className="text-neutral-500 uppercase text-[10px]">Traditional Firm Cost</div>
                  <div className="text-lg font-bold text-neutral-400 mt-1 line-through">
                    RM {roi.traditionalCost.toLocaleString()}
                  </div>
                </div>
                <div>
                  <div className="text-neutral-500 uppercase text-[10px]">SentinelAI Enterprise</div>
                  <div className="text-lg font-bold text-white mt-1">
                    RM {roi.sentinelCost.toLocaleString()}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-white/10 flex items-baseline justify-between">
                <div>
                  <span className="text-xs text-neutral-400">Estimated Annual Savings:</span>
                  <div className="text-2xl font-black text-white mt-0.5">
                    RM {roi.savings.toLocaleString()}
                  </div>
                </div>
                <span className="px-2.5 py-1 rounded bg-white text-black font-extrabold text-xs">
                  {roi.pct}% SAVED
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Expandable Feature Comparison Table ── */}
        <div className="text-center">
          <button
            type="button"
            onClick={() => setShowMatrix(!showMatrix)}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl border border-white/20 bg-white/5 text-xs font-mono font-bold text-white hover:bg-white/10 transition-colors cursor-pointer"
          >
            <span>{showMatrix ? 'Collapse Feature Matrix' : 'View Full Technical Feature Matrix (22 Rows)'}</span>
            {showMatrix ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>

          {showMatrix && (
            <div className="mt-8 rounded-2xl border border-white/15 bg-[#080808] overflow-hidden text-left font-mono text-xs">
              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-white/15 bg-neutral-950 text-neutral-400 uppercase text-[10px]">
                      <th className="p-4 text-left">Platform Capabilities</th>
                      <th className="p-4 text-center">Free Trial</th>
                      <th className="p-4 text-center">Pay-Per-Scan</th>
                      <th className="p-4 text-center text-white bg-white/5">Pro Plan</th>
                      <th className="p-4 text-center">Enterprise</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-neutral-300">
                    {FEATURE_MATRIX.map(([name, trial, pps, pro, ent], idx) => (
                      <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                        <td className="p-3.5 font-sans font-medium text-white">{name}</td>
                        <td className="p-3.5 text-center">
                          {typeof trial === 'boolean' ? (
                            trial ? <CheckCircle2 size={14} className="text-white mx-auto" /> : <XCircle size={14} className="text-neutral-700 mx-auto" />
                          ) : (
                            <span className="text-[11px] text-neutral-400">{trial}</span>
                          )}
                        </td>
                        <td className="p-3.5 text-center">
                          {typeof pps === 'boolean' ? (
                            pps ? <CheckCircle2 size={14} className="text-white mx-auto" /> : <XCircle size={14} className="text-neutral-700 mx-auto" />
                          ) : (
                            <span className="text-[11px] text-neutral-400">{pps}</span>
                          )}
                        </td>
                        <td className="p-3.5 text-center bg-white/[0.03]">
                          {typeof pro === 'boolean' ? (
                            pro ? <CheckCircle2 size={14} className="text-white mx-auto" /> : <XCircle size={14} className="text-neutral-700 mx-auto" />
                          ) : (
                            <span className="text-[11px] text-white font-bold">{pro}</span>
                          )}
                        </td>
                        <td className="p-3.5 text-center">
                          {typeof ent === 'boolean' ? (
                            ent ? <CheckCircle2 size={14} className="text-white mx-auto" /> : <XCircle size={14} className="text-neutral-700 mx-auto" />
                          ) : (
                            <span className="text-[11px] text-neutral-300 font-bold">{ent}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}
