import React from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, Globe2, GitBranch, Swords, Users, BellRing,
  ShieldCheck, CheckCircle2
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'

const GLASS_CARD = {
  background: 'rgba(255, 255, 255, 0.04)',
  backdropFilter: 'blur(40px) saturate(180%)',
  WebkitBackdropFilter: 'blur(40px) saturate(180%)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.06)',
}

const SERVICES = [
  {
    id: 'blackbox',
    icon: Globe2,
    color: 'text-cyan-400',
    badge: 'bg-cyan-500/15 text-cyan-300 border-cyan-400/30',
    title: 'Autonomous Blackbox Pentesting',
    tagline: 'External attack-surface assessment with zero prior knowledge.',
    features: [
      'Domain, IP range & web URL scan targets',
      'Automated recon → probing → exploitation pipeline',
      'CVSS v3.1 risk scoring with AI verification',
      'Executive PDF report with plain-English summaries',
    ],
  },
  {
    id: 'whitebox',
    icon: GitBranch,
    color: 'text-emerald-400',
    badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/30',
    title: 'Whitebox & GitHub Continuous DevSecOps',
    tagline: 'Security woven directly into your development workflow.',
    features: [
      'GitHub webhook integration on push & pull requests',
      'AST static code audit (JS, TS, Python, PHP, Java, Go)',
      'Inline PR review — bot comments on vulnerable lines',
      'Auto-fix remediation diffs ready to commit',
    ],
  },
  {
    id: 'aee',
    icon: Swords,
    color: 'text-rose-400',
    badge: 'bg-rose-500/15 text-rose-300 border-rose-400/30',
    title: 'Autonomous Exploitation Engine (AEE)',
    tagline: 'Validated multi-step attack chains — safely executed.',
    features: [
      'Autonomous chaining of isolated vulnerabilities into full paths',
      'Safe read-only PoC verification before any aggressive action',
      'Manual approval gates for critical / destructive steps',
      'Loot capture & live execution log for every campaign step',
    ],
  },
  {
    id: 'advisory',
    icon: Users,
    color: 'text-amber-400',
    badge: 'bg-amber-500/15 text-amber-300 border-amber-400/30',
    title: 'Certified 1-on-1 Security Advisory & Virtual CISO',
    tagline: 'Expert human guidance on top of autonomous findings.',
    features: [
      'Scheduled consultation slots with the Security Architect',
      'Guided code remediation walkthroughs (fix-with-me sessions)',
      'OWASP Top 10 2025 compliance auditing',
      'Architecture threat modeling & security roadmap planning',
    ],
  },
  {
    id: 'monitoring',
    icon: BellRing,
    color: 'text-indigo-400',
    badge: 'bg-indigo-500/15 text-indigo-300 border-indigo-400/30',
    title: '24/7 Surface Monitoring & Multi-Channel Alerting',
    tagline: 'Continuous watch with instant notification delivery.',
    features: [
      'Round-the-clock attack surface monitoring',
      'Instant Telegram Bot notifications',
      'Discord Webhook alert gateway',
      'Email delivery of executive PDF reports on every event',
    ],
  },
]

export default function Services() {
  return (
    <PublicLayout>
      <div className="max-w-6xl mx-auto px-4 sm:px-8 pt-16 sm:pt-24 pb-12 space-y-24">
        {/* ── Hero ─────────────────────────────────────────────────────────── */}
        <section className="text-center space-y-5">
          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            Security Solutions <span className="at-home__gradient-text">Built for Scale</span>
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            From one-off blackbox assessments to fully continuous DevSecOps pipelines — SentinelAI covers
            the entire offensive and defensive lifecycle autonomously.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <Link to="/pricing" className="btn-shine btn-lg">
              View Pricing Plans <ArrowRight size={15} />
            </Link>
            <Link to="/contact" className="btn-neon-draw btn-lg">
              Book a Consultation
            </Link>
          </div>
        </section>

        {/* ── Service Cards ────────────────────────────────────────────────── */}
        <section className="space-y-8">
          {SERVICES.map((s, idx) => {
            const Icon = s.icon
            const reversed = idx % 2 === 1
            return (
              <div
                key={s.id}
                className={`p-7 sm:p-9 rounded-3xl grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-7 items-start transition-all duration-300 hover:border-cyan-400/25 ${reversed ? 'lg:grid-cols-[1fr_auto]' : ''}`}
                style={GLASS_CARD}
              >
                <div className={`shrink-0 flex ${reversed ? 'lg:order-2' : ''}`}>
                  <div className={`p-4 rounded-2xl bg-black/50 border border-white/10 ${s.color}`}>
                    <Icon size={34} />
                  </div>
                </div>

                <div className={`space-y-4 min-w-0 ${reversed ? 'lg:order-1' : ''}`}>
                  <div className="space-y-2">
                    <span className={`inline-block px-2.5 py-0.5 rounded-full border text-[10px] font-extrabold uppercase tracking-wider ${s.badge}`}>
                      Service {String(idx + 1).padStart(2, '0')}
                    </span>
                    <h2 className="text-lg sm:text-xl font-extrabold text-white tracking-tight">{s.title}</h2>
                    <p className="text-xs text-slate-400">{s.tagline}</p>
                  </div>

                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5">
                    {s.features.map((f) => (
                      <li key={f} className="flex items-start gap-2 text-xs text-slate-300">
                        <CheckCircle2 size={14} className={`${s.color} shrink-0 mt-0.5`} />
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )
          })}
        </section>

        {/* ── How It Works Strip ───────────────────────────────────────────── */}
        <section className="space-y-6">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">How Engagements Run</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { n: '01', t: 'Scope & Connect', d: 'Submit a URL/IP target or link your GitHub repositories via secure webhook.' },
              { n: '02', t: 'Autonomous Scan', d: 'Hexstrike chains 150+ Kali tools; AI personas verify every raw finding.' },
              { n: '03', t: 'Review & Approve', d: 'Inspect verified findings; approve exploit-chain steps through safety gates.' },
              { n: '04', t: 'Report & Remediate', d: 'Receive executive PDF reports, inline PR fixes, and guided advisory.' },
            ].map((step) => (
              <div key={step.n} className="p-5 rounded-2xl space-y-2 relative overflow-hidden" style={GLASS_CARD}>
                <span className="text-3xl font-black text-cyan-500/20 absolute top-2 right-4 select-none">{step.n}</span>
                <h3 className="text-sm font-bold text-white relative">{step.t}</h3>
                <p className="text-[11px] text-slate-400 leading-relaxed relative">{step.d}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── CTA ──────────────────────────────────────────────────────────── */}
        <section className="card p-10 sm:p-14 border border-cyan-500/30 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 text-center rounded-3xl shadow-2xl space-y-6">
          <ShieldCheck className="mx-auto text-cyan-400" size={36} />
          <h2 className="text-2xl sm:text-3xl font-bold text-white">Ready to Secure Your Stack?</h2>
          <p className="text-slate-400 text-xs sm:text-sm max-w-xl mx-auto leading-relaxed">
            Start with a free assessment or talk directly to the Security Architect about your environment.
          </p>
          <div className="flex justify-center items-center flex-wrap gap-4">
            <Link to="/login?mode=register&plan=trial" className="btn-concept-12">
              <span className="btn-concept-12__text">Start Free Assessment</span>
              <span className="btn-concept-12__icon">
                <ShieldCheck size={18} />
              </span>
            </Link>
            <a href="mailto:muhammadsaifudinmj@gmail.com" className="btn-thin py-3 px-6 text-xs font-bold hover:border-cyan-400/50">
              Contact Us
            </a>
          </div>
        </section>
      </div>
    </PublicLayout>
  )
}
