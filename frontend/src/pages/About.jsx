import React from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, ShieldCheck, Database, FileText, GraduationCap,
  GitBranch, Target, Eye, Lock, Users
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'

const GLASS_CARD = {
  background: 'rgba(255, 255, 255, 0.04)',
  backdropFilter: 'blur(40px) saturate(180%)',
  WebkitBackdropFilter: 'blur(40px) saturate(180%)',
  border: '1px solid rgba(255, 255, 255, 0.08)',
  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.06)',
}

const PHILOSOPHY = [
  {
    icon: Lock,
    color: 'text-emerald-400',
    title: 'Local-First Zero-Cloud Privacy',
    desc: 'All security data, findings, and audit logs are stored in a local SQLite WAL database. No scan results or client source code ever leave your infrastructure — zero third-party leakage by design.',
  },
  {
    icon: ShieldCheck,
    color: 'text-cyan-400',
    title: 'Multi-LLM Consensus Verification',
    desc: 'Every raw tool finding passes through staged AI verification across multiple LLM providers (Groq, OpenRouter, DeepSeek). Consensus gating eliminates false positives before they ever reach your report.',
  },
  {
    icon: FileText,
    color: 'text-amber-400',
    title: 'Layman-Friendly Executive Delivery',
    desc: 'Automated PDF reports translate technical CVSS findings into plain-English business risk summaries — understandable by management and engineering teams alike.',
  },
]

export default function About() {
  return (
    <PublicLayout>
      <div className="max-w-6xl mx-auto px-4 sm:px-8 pt-16 sm:pt-24 pb-12 space-y-24">
        {/* ── Hero ─────────────────────────────────────────────────────────── */}
        <section className="text-center space-y-5">
          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            Autonomous Security, <span className="at-home__gradient-text">Researched &amp; Engineered</span>
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            SentinelAI was built to automate penetration testing with AI — eliminating human fatigue
            and cutting traditional consulting costs by up to 90%, without sacrificing depth or accuracy.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <Link to="/services" className="btn-neon-draw btn-lg">
              Explore Services <ArrowRight size={15} />
            </Link>
            <Link to="/tools" className="btn-swipe btn-lg">
              Browse the Tool Arsenal
            </Link>
          </div>
        </section>

        {/* ── Mission & Vision ─────────────────────────────────────────────── */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-7 rounded-3xl space-y-3" style={GLASS_CARD}>
            <Target className="text-cyan-400 mb-1" size={30} />
            <h2 className="text-lg font-bold text-white">Our Mission</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              To democratize enterprise-grade penetration testing by orchestrating 150+ real Kali Linux
              tools and 53 specialist AI personas into a single autonomous pipeline — making continuous,
              high-quality security assessment affordable for teams of every size.
            </p>
          </div>
          <div className="p-7 rounded-3xl space-y-3" style={GLASS_CARD}>
            <Eye className="text-amber-400 mb-1" size={30} />
            <h2 className="text-lg font-bold text-white">Our Vision</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              A world where security audits run continuously — not annually — where every commit is
              verified by AI consensus, every exploit chain is validated safely, and every executive
              receives reports they can actually act on.
            </p>
          </div>
        </section>

        {/* ── FYP2 Academic Origin ─────────────────────────────────────────── */}
        <section className="space-y-6">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Academic Origin</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              SentinelAI is researched and developed as a Final Year Project 2 (FYP2) thesis.
            </p>
          </div>

          <div className="p-7 sm:p-9 rounded-3xl relative overflow-hidden" style={{ ...GLASS_CARD, border: '1px solid rgba(0, 242, 254, 0.15)' }}>
            <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-6 items-start">
              {/* Creator Photo */}
              <div className="relative shrink-0 flex flex-col items-center mx-auto md:mx-0">
                <div
                  className="rounded-2xl overflow-hidden border-2 border-cyan-400/40 shadow-lg shadow-cyan-950/40 bg-slate-900 ring-2 ring-cyan-500/20"
                  style={{ width: '120px', height: '120px', minWidth: '120px', minHeight: '120px', maxWidth: '120px', maxHeight: '120px' }}
                >
                  <img
                    src="/saif.png"
                    alt="Muhammad Saifudin"
                    style={{ width: '100%', height: '100%', objectFit: 'cover', objectPosition: '85% 85%', display: 'block' }}
                    onError={(e) => { e.currentTarget.src = '/fyp2_presenter.png' }}
                  />
                </div>
                <span className="mt-1.5 px-2 py-0.5 rounded-full bg-cyan-500 text-slate-950 text-[9px] font-black uppercase tracking-wider shadow">
                  Lead Dev
                </span>
              </div>

              {/* Bio */}
              <div className="space-y-3 text-center md:text-left">
                <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 font-bold border border-indigo-500/30 flex items-center gap-1">
                    <GraduationCap size={11} /> FYP 2 Research Project
                  </span>
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 font-bold border border-cyan-500/30">
                    IIUM &bull; KICT
                  </span>
                </div>
                <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">Muhammad Saifudin</h3>
                <p className="text-xs font-semibold text-cyan-400">Lead Security Architect &amp; Creator</p>
                <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                  Researched and engineered the full SentinelAI stack — from the Hexstrike Kali tool
                  orchestration engine and multi-LLM consensus verification, to the PayloadsAllTheThings
                  RAG knowledge base and autonomous exploitation pipeline. Developed at the
                  Kulliyyah of Information and Communication Technology (KICT), International Islamic
                  University Malaysia (IIUM).
                </p>
                <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 pt-1">
                  <a
                    href="https://github.com/Iamatto01"
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/15 hover:border-cyan-400/60 text-slate-200 hover:text-cyan-300 text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <GitBranch size={13} className="text-cyan-400" /> GitHub: @Iamatto01
                  </a>
                  <a
                    href="https://www.linkedin.com/in/muhammad-saifudin"
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-white/15 hover:border-blue-400/60 text-slate-200 hover:text-blue-300 text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <svg className="w-3.5 h-3.5 fill-blue-400" viewBox="0 0 24 24">
                      <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.67a1.66 1.66 0 0 0-1.66 1.66c0 .92.74 1.66 1.66 1.66a1.66 1.66 0 0 0 1.66-1.66c0-.92-.74-1.66-1.66-1.66Z" />
                    </svg>
                    LinkedIn
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── Core Design Philosophy ───────────────────────────────────────── */}
        <section className="space-y-6">
          <div className="text-center space-y-2">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Core Design Philosophy</h2>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              Three principles govern every architectural decision in SentinelAI.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {PHILOSOPHY.map((p) => {
              const Icon = p.icon
              return (
                <div key={p.title} className="p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300 hover:border-cyan-400/30" style={GLASS_CARD}>
                  <Icon className={`${p.color} mb-3`} size={30} />
                  <h3 className="text-base font-bold text-white mb-2">{p.title}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{p.desc}</p>
                </div>
              )
            })}
          </div>
        </section>

        {/* ── Stats Strip ──────────────────────────────────────────────────── */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { v: '150+', l: 'Kali Tools Orchestrated', c: 'text-cyan-400' },
            { v: '53', l: 'Specialist AI Personas', c: 'text-amber-400' },
            { v: '10k+', l: 'RAG PoC Payloads Indexed', c: 'text-emerald-400' },
            { v: '~90%', l: 'Cost vs Traditional Pentest', c: 'text-indigo-400' },
          ].map((s) => (
            <div key={s.l} className="p-5 rounded-2xl text-center space-y-1" style={GLASS_CARD}>
              <div className={`text-2xl font-black ${s.c}`}>{s.v}</div>
              <div className="text-[11px] text-slate-400 font-semibold">{s.l}</div>
            </div>
          ))}
        </section>

        {/* ── CTA ──────────────────────────────────────────────────────────── */}
        <section className="card p-10 sm:p-14 border border-cyan-500/30 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 text-center rounded-3xl shadow-2xl space-y-6">
          <Users className="mx-auto text-cyan-400" size={36} />
          <h2 className="text-2xl sm:text-3xl font-bold text-white">Join the Autonomous Security Revolution</h2>
          <p className="text-slate-400 text-xs sm:text-sm max-w-xl mx-auto leading-relaxed">
            See how SentinelAI's research-driven pipeline can secure your codebase and infrastructure continuously.
          </p>
          <div className="flex justify-center items-center flex-wrap gap-4">
            <Link to="/pricing" className="btn-concept-12">
              <span className="btn-concept-12__text">View Pricing</span>
              <span className="btn-concept-12__icon">
                <ShieldCheck size={18} />
              </span>
            </Link>
            <a href="mailto:muhammadsaifudinmj@gmail.com" className="btn-thin py-3 px-6 text-xs font-bold hover:border-cyan-400/50">
              Talk to Us
            </a>
          </div>
        </section>
      </div>
    </PublicLayout>
  )
}
