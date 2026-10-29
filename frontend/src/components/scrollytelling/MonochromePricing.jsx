import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  CheckCircle2, Sparkles, ArrowRight, ArrowUpRight, Zap,
  ShieldCheck, HelpCircle, ChevronDown, ChevronUp, Layers, Check
} from 'lucide-react'
import SpotlightCard from './SpotlightCard.jsx'
import { useTheme } from '../../lib/ThemeContext.jsx'

const COMPARISON_ROWS = [
  { feature: 'Autonomous Blackbox URL Assessment', trial: '3 scans', pps: '1 scan / credit', pro: '50 scans / mo', ent: 'Unlimited' },
  { feature: 'Whitebox SAST Code Audit (JS/Py/PHP/Java)', trial: 'Basic', pps: 'Full AST', pro: 'Full AST + Taint', ent: 'Full AST + Custom' },
  { feature: '150+ Native Kali Toolchain Execution', trial: '✓', pps: '✓', pro: '✓', ent: '✓' },
  { feature: '53 Specialist AI Personas Consensus', trial: 'Standard', pps: 'Standard', pro: 'DeepSeek-V4 Pro', ent: 'Dedicated Finetune' },
  { feature: 'PayloadsAllTheThings RAG (FTS5 SQLite)', trial: '✓', pps: '✓', pro: '✓', ent: '✓' },
  { feature: 'Automated Git Diff Code Patch Synthesis', trial: 'Preview', pps: '✓', pro: '✓', ent: '✓' },
  { feature: 'GitHub Octokit PR Review Bot Integration', trial: '—', pps: '—', pro: '✓', ent: '✓' },
  { feature: 'Executive Audit PDF Report (ISO/OWASP)', trial: '✓', pps: '✓', pro: '✓ (Custom logo)', ent: '✓ (White-label)' },
  { feature: 'SARIF 2.1 & CycloneDX 1.5 JSON Exports', trial: '—', pps: '✓', pro: '✓', ent: '✓' },
  { feature: 'Telegram & Discord Real-time Alert Relays', trial: '—', pps: '—', pro: '✓', ent: '✓' },
  { feature: 'Local-First SQLite WAL Zero-Cloud Isolation', trial: '✓', pps: '✓', pro: '✓', ent: '✓' },
  { feature: 'Concurrent Autonomous Scans', trial: '1', pps: '1', pro: '3 concurrent', ent: '10 concurrent' },
  { feature: 'Vulnerability SLA Verification Engine', trial: '—', pps: '—', pro: '✓', ent: '✓' },
  { feature: 'Dedicated Pentest Architect Advisory', trial: '—', pps: '—', pro: 'Community', ent: 'Direct WhatsApp/SLA' },
]

export default function MonochromePricing() {
  const { isNight } = useTheme()
  const [interval, setInterval] = useState('monthly') // 'monthly' | 'yearly'
  const [showMatrix, setShowMatrix] = useState(false)
  const [plans, setPlans] = useState([])

  useEffect(() => {
    fetch('/api/billing/plans')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d?.plans?.length) setPlans(d.plans)
      })
      .catch(() => {})
  }, [])

  const findPlan = (id, fallback) => {
    return plans.find((p) => p.id === id) || fallback
  }

  const trialPlan = findPlan('trial', { id: 'trial', name: 'Free Assessment', priceMonthly: 0, priceYearly: 0 })
  const ppsPlan = findPlan('pay_per_scan', { id: 'pay_per_scan', name: 'Pay-Per-Scan', priceMonthly: 3, priceYearly: 3 })
  const proPlan = findPlan('pro', { id: 'pro', name: 'Pro Pentester', priceMonthly: 20, priceYearly: 200 })
  const entPlan = findPlan('enterprise', { id: 'enterprise', name: 'Enterprise Fleet', priceMonthly: 80, priceYearly: 800 })

  const isYearly = interval === 'yearly'
  const proPrice = isYearly ? Math.round(proPlan.priceYearly / 12) : proPlan.priceMonthly
  const entPrice = isYearly ? Math.round(entPlan.priceYearly / 12) : entPlan.priceMonthly

  return (
    <section id="pricing" className={`relative scroll-mt-20 py-28 sm:py-36 border-t overflow-hidden transition-colors duration-500 ${
      isNight ? 'bg-black border-white/10 text-white' : 'bg-[#FAFAFA] border-zinc-200 text-zinc-950'
    }`}>
      {/* Top Volumetric Overhead Spotlight Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-[500px] -translate-y-1/2 opacity-30 blur-3xl z-0"
        style={{
          background: isNight
            ? 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.25), transparent)'
            : 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,0,0,0.06), transparent)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Animated Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-3xl mx-auto space-y-4 mb-16 sm:mb-20"
        >
          <div className={`inline-flex items-center gap-2 px-3.5 py-1 rounded-full border text-[11px] font-mono ${
            isNight ? 'border-white/15 bg-white/[0.04] text-neutral-300' : 'border-zinc-300 bg-black/5 text-zinc-800'
          }`}>
            <Sparkles size={13} className={isNight ? 'text-white' : 'text-black'} />
            <span className="font-bold uppercase tracking-wider">
              PRICING TIERS // ZERO CLOUD RISK &bull; BILLING IN MYR
            </span>
          </div>

          <h2 className={`text-3xl sm:text-5xl font-extrabold tracking-tight font-sans ${
            isNight ? 'text-white' : 'text-zinc-950'
          }`}>
            Transparent Autonomous Security <br />
            <span className={`bg-clip-text text-transparent ${
              isNight
                ? 'bg-gradient-to-b from-white via-neutral-200 to-neutral-500'
                : 'bg-gradient-to-b from-zinc-950 via-zinc-900 to-zinc-600'
            }`}>
              Predictable Credits, No Human Markup
            </span>
          </h2>

          <p className={`text-sm sm:text-base font-sans leading-relaxed ${
            isNight ? 'text-neutral-400' : 'text-zinc-600'
          }`}>
            Traditional blackbox engagements cost RM 15,000+ per engagement. SentinelAI gives you continuous,
            automated offensive coverage starting at RM 0 for trials, RM 3 per single credit, or RM 20/month for unlimited pipelines.
          </p>

          {/* Billing Interval Switcher */}
          <div className="flex items-center justify-center gap-3 pt-4">
            <div className={`flex items-center p-1 rounded-xl border font-mono text-xs ${
              isNight ? 'border-white/10 bg-black/60' : 'border-zinc-300 bg-zinc-100'
            }`}>
              <button
                type="button"
                onClick={() => setInterval('monthly')}
                className={`px-4 py-2 rounded-lg font-bold transition-all cursor-pointer ${
                  interval === 'monthly'
                    ? isNight ? 'bg-white text-black shadow' : 'bg-black text-white shadow'
                    : isNight ? 'text-neutral-400 hover:text-white' : 'text-zinc-600 hover:text-black'
                }`}
              >
                Monthly Billing
              </button>
              <button
                type="button"
                onClick={() => setInterval('yearly')}
                className={`px-4 py-2 rounded-lg font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                  interval === 'yearly'
                    ? isNight ? 'bg-white text-black shadow' : 'bg-black text-white shadow'
                    : isNight ? 'text-neutral-400 hover:text-white' : 'text-zinc-600 hover:text-black'
                }`}
              >
                <span>Annual Billing</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-black ${
                  interval === 'yearly'
                    ? isNight ? 'bg-black text-white' : 'bg-white text-black'
                    : isNight ? 'bg-white/10 text-white' : 'bg-zinc-200 text-zinc-900'
                }`}>
                  SAVE 17%
                </span>
              </button>
            </div>
          </div>
        </motion.div>

        {/* 4-Column Tier Deck with Move & Combine Scroll Physics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 items-stretch">
          {/* TIER 1: Free Assessment */}
          <motion.div
            initial={{ opacity: 0, x: -60, scale: 0.95 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          >
            <SpotlightCard className="p-6 sm:p-7 flex flex-col justify-between h-full">
              <div className="space-y-6">
                <div>
                  <span className={`text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border ${
                    isNight ? 'border-white/20 bg-white/5 text-neutral-300' : 'border-zinc-300 bg-zinc-100 text-zinc-700'
                  }`}>
                    FREE TIER
                  </span>
                  <h3 className={`text-xl font-extrabold mt-3 font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                    Free Trial
                  </h3>
                  <div className="mt-3 flex items-baseline gap-1 font-mono">
                    <span className={`text-3xl font-black ${isNight ? 'text-white' : 'text-zinc-950'}`}>RM 0</span>
                    <span className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>/ forever</span>
                  </div>
                  <p className={`text-xs mt-2 font-sans ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                    Kickstart your security assessment. Test any domain or code repo with 3 full trial scans.
                  </p>
                </div>

                <div className={`h-px ${isNight ? 'bg-white/10' : 'bg-zinc-200'}`} />

                <ul className={`space-y-2.5 text-xs font-sans ${isNight ? 'text-neutral-300' : 'text-zinc-700'}`}>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span><strong>3 Full Security Scans</strong> included</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>150+ Toolchain (DAST &amp; SAST)</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Live Terminal stdout stream</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Executive PDF Report</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>No credit card required</span>
                  </li>
                </ul>
              </div>

              <div className="pt-8">
                <Link
                  to="/login?mode=register&plan=trial"
                  className={`w-full py-2.5 px-4 rounded-xl border text-xs font-mono font-bold flex items-center justify-center transition-all ${
                    isNight
                      ? 'border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10'
                      : 'border-zinc-300 bg-zinc-100 text-zinc-800 hover:text-black hover:bg-zinc-200'
                  }`}
                >
                  Start Free Trial
                </Link>
              </div>
            </SpotlightCard>
          </motion.div>

          {/* TIER 2: Pay-Per-Scan Credit */}
          <motion.div
            initial={{ opacity: 0, x: -30, scale: 0.95 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.7, delay: 0.12, ease: [0.16, 1, 0.3, 1] }}
          >
            <SpotlightCard className="p-6 sm:p-7 flex flex-col justify-between h-full">
              <div className="space-y-6">
                <div>
                  <span className={`text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border ${
                    isNight ? 'border-white/20 bg-white/5 text-neutral-300' : 'border-zinc-300 bg-zinc-100 text-zinc-700'
                  }`}>
                    ON-DEMAND TOP-UP
                  </span>
                  <h3 className={`text-xl font-extrabold mt-3 font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                    Pay-Per-Scan
                  </h3>
                  <div className="mt-3 flex items-baseline gap-1 font-mono">
                    <span className={`text-3xl font-black ${isNight ? 'text-white' : 'text-zinc-950'}`}>RM {ppsPlan.priceMonthly}</span>
                    <span className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>/ scan</span>
                  </div>
                  <p className={`text-xs mt-2 font-sans ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                    Top-up single autonomous scans on demand. No recurring monthly commitment.
                  </p>
                </div>

                <div className={`h-px ${isNight ? 'bg-white/10' : 'bg-zinc-200'}`} />

                <ul className={`space-y-2.5 text-xs font-sans ${isNight ? 'text-neutral-300' : 'text-zinc-700'}`}>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span><strong>1 Full Security Scan</strong> credit</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Full 150+ Toolchain access</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Live stdout terminal telemetry</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Full Executive PDF Audit Report</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Instant FPX / DuitNow activation</span>
                  </li>
                </ul>
              </div>

              <div className="pt-8">
                <Link
                  to="/login?mode=register&plan=pay_per_scan"
                  className={`w-full py-2.5 px-4 rounded-xl border text-xs font-mono font-bold flex items-center justify-center transition-all ${
                    isNight
                      ? 'border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10'
                      : 'border-zinc-300 bg-zinc-100 text-zinc-800 hover:text-black hover:bg-zinc-200'
                  }`}
                >
                  Buy Single Credit
                </Link>
              </div>
            </SpotlightCard>
          </motion.div>

          {/* TIER 3: PRO PENTESTER (HIGHLIGHTED // ELEVATED) */}
          <motion.div
            initial={{ opacity: 0, y: -40, scale: 0.95 }}
            whileInView={{ opacity: 1, y: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.75, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="relative -translate-y-2"
          >
            <div className={`h-full rounded-2xl border-2 p-6 sm:p-7 flex flex-col justify-between relative overflow-hidden transition-all duration-300 ${
              isNight
                ? 'border-white bg-[#0E0E0E] shadow-[0_0_50px_rgba(255,255,255,0.18)]'
                : 'border-black bg-white shadow-2xl'
            }`}>
              {/* Top Accent Beam */}
              <div
                className="pointer-events-none absolute inset-x-0 top-0 h-32 opacity-40 blur-xl"
                style={{
                  background: isNight
                    ? 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.4), transparent)'
                    : 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,0,0,0.15), transparent)',
                }}
              />

              <div className="space-y-6 relative z-10">
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-mono font-black uppercase tracking-wider px-2.5 py-0.5 rounded ${
                    isNight ? 'bg-white text-black' : 'bg-black text-white'
                  }`}>
                    MOST POPULAR // PRO
                  </span>
                  <span className={`text-[10px] font-mono ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>50 AUDITS / MO</span>
                </div>

                <div>
                  <h3 className={`text-xl font-black mt-2 font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                    Pro Pentester
                  </h3>
                  <div className="mt-3 flex items-baseline gap-1 font-mono">
                    <span className={`text-4xl font-black ${isNight ? 'text-white' : 'text-zinc-950'}`}>RM {proPrice}</span>
                    <span className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>/ mo</span>
                  </div>
                  <p className={`text-xs mt-2 font-sans ${isNight ? 'text-neutral-300' : 'text-zinc-600'}`}>
                    Continuous autonomous security for security teams, researchers, and SaaS companies.
                  </p>
                </div>

                <div className={`h-px ${isNight ? 'bg-white/20' : 'bg-zinc-200'}`} />

                <ul className={`space-y-2.5 text-xs font-sans ${isNight ? 'text-neutral-200' : 'text-zinc-800'}`}>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span><strong>50 Autonomous Scans</strong> every month</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span><strong>DeepSeek-V4 Pro</strong> reasoning engine</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Automated Git Diff patch PR comments</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>GitHub Octokit CI/CD bot integration</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Priority Discord &amp; Telegram relays</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Cancel anytime &bull; Instant activation</span>
                  </li>
                </ul>
              </div>

              <div className="pt-8 relative z-10">
                <Link
                  to={`/login?mode=register&plan=pro&interval=${interval}`}
                  className={`w-full py-3 px-4 rounded-xl text-xs font-mono font-black uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:scale-[1.02] active:scale-[0.98] ${
                    isNight
                      ? 'bg-white text-black hover:bg-neutral-200 shadow-[0_0_25px_rgba(255,255,255,0.3)]'
                      : 'bg-black text-white hover:bg-zinc-800 shadow-[0_0_20px_rgba(0,0,0,0.25)]'
                  }`}
                >
                  <span>Deploy Pro Engine</span>
                  <ArrowRight size={14} className="stroke-[2.5]" />
                </Link>
              </div>
            </div>
          </motion.div>

          {/* TIER 4: Enterprise Fleet */}
          <motion.div
            initial={{ opacity: 0, x: 60, scale: 0.95 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.2 }}
            transition={{ duration: 0.7, delay: 0.28, ease: [0.16, 1, 0.3, 1] }}
          >
            <SpotlightCard className="p-6 sm:p-7 flex flex-col justify-between h-full">
              <div className="space-y-6">
                <div>
                  <span className={`text-[10px] font-mono font-extrabold uppercase tracking-wider px-2 py-0.5 rounded border ${
                    isNight ? 'border-white/20 bg-white/5 text-neutral-300' : 'border-zinc-300 bg-zinc-100 text-zinc-700'
                  }`}>
                    UNLIMITED FLEET
                  </span>
                  <h3 className={`text-xl font-extrabold mt-3 font-sans ${isNight ? 'text-white' : 'text-zinc-950'}`}>
                    Enterprise Fleet
                  </h3>
                  <div className="mt-3 flex items-baseline gap-1 font-mono">
                    <span className={`text-3xl font-black ${isNight ? 'text-white' : 'text-zinc-950'}`}>RM {entPrice}</span>
                    <span className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-500'}`}>/ mo</span>
                  </div>
                  <p className={`text-xs mt-2 font-sans ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                    Dedicated multi-node infrastructure for red teams, SOCs, and enterprises.
                  </p>
                </div>

                <div className={`h-px ${isNight ? 'bg-white/10' : 'bg-zinc-200'}`} />

                <ul className={`space-y-2.5 text-xs font-sans ${isNight ? 'text-neutral-300' : 'text-zinc-700'}`}>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span><strong>Unlimited Autonomous Scans</strong></span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>10 Concurrent pipeline executions</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>White-label executive PDF reports</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Self-hosted on-premise SQLite option</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle2 size={15} className={`shrink-0 ${isNight ? 'text-white' : 'text-black'}`} />
                    <span>Direct Lead Dev SLA support</span>
                  </li>
                </ul>
              </div>

              <div className="pt-8">
                <Link
                  to={`/login?mode=register&plan=enterprise&interval=${interval}`}
                  className={`w-full py-2.5 px-4 rounded-xl border text-xs font-mono font-bold flex items-center justify-center transition-all ${
                    isNight
                      ? 'border-white/20 bg-white/5 text-neutral-200 hover:text-white hover:bg-white/10'
                      : 'border-zinc-300 bg-zinc-100 text-zinc-800 hover:text-black hover:bg-zinc-200'
                  }`}
                >
                  Deploy Enterprise
                </Link>
              </div>
            </SpotlightCard>
          </motion.div>
        </div>

        {/* ── EXPANDABLE DETAILED COMPARISON TABLE ── */}
        <div className="mt-16 sm:mt-20">
          <div className="text-center mb-6">
            <button
              type="button"
              onClick={() => setShowMatrix(!showMatrix)}
              className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-xl border text-xs font-mono font-bold transition-all cursor-pointer ${
                isNight
                  ? 'border-white/20 bg-white/5 hover:bg-white/10 text-neutral-200 hover:text-white'
                  : 'border-zinc-300 bg-zinc-100 hover:bg-zinc-200 text-zinc-800 hover:text-black'
              }`}
            >
              <Layers size={14} className={isNight ? 'text-white' : 'text-black'} />
              <span>{showMatrix ? 'Hide Technical Specification Matrix' : 'Compare All 14 Platform Specifications'}</span>
              {showMatrix ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
          </div>

          {showMatrix && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.4 }}
              className={`rounded-2xl border overflow-x-auto ${
                isNight ? 'border-white/15 bg-[#080808]' : 'border-zinc-200 bg-white shadow-sm'
              }`}
            >
              <table className="w-full text-left font-mono text-xs border-collapse min-w-[650px]">
                <thead>
                  <tr className={`border-b text-[11px] ${
                    isNight ? 'border-white/10 bg-black/80 text-neutral-400' : 'border-zinc-200 bg-zinc-50 text-zinc-600'
                  }`}>
                    <th className="p-4 uppercase font-extrabold">Capability &amp; Architecture</th>
                    <th className="p-4 text-center">Trial</th>
                    <th className="p-4 text-center">Pay-Per-Scan</th>
                    <th className={`p-4 text-center ${isNight ? 'text-white bg-white/5 font-extrabold' : 'text-black bg-zinc-100 font-extrabold'}`}>
                      Pro
                    </th>
                    <th className="p-4 text-center">Enterprise</th>
                  </tr>
                </thead>
                <tbody className={`divide-y ${isNight ? 'divide-white/5 text-neutral-300' : 'divide-zinc-200 text-zinc-700'}`}>
                  {COMPARISON_ROWS.map((row, idx) => (
                    <tr key={idx} className={isNight ? 'hover:bg-white/[0.02]' : 'hover:bg-zinc-50'}>
                      <td className={`p-4 font-sans font-medium text-xs ${isNight ? 'text-neutral-200' : 'text-zinc-900'}`}>{row.feature}</td>
                      <td className="p-4 text-center">{row.trial}</td>
                      <td className="p-4 text-center">{row.pps}</td>
                      <td className={`p-4 text-center font-bold ${
                        isNight ? 'text-white bg-white/5' : 'text-black bg-zinc-100'
                      }`}>
                        {row.pro}
                      </td>
                      <td className="p-4 text-center">{row.ent}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </motion.div>
          )}
        </div>
      </div>
    </section>
  )
}
