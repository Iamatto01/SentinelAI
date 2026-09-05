import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight, Mail, Send, MessageCircle, Github, CalendarClock,
  ShieldAlert, CheckCircle2, Loader2
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'

const GLASS_CARD = {
  background: '#161616',
  border: '1px solid rgba(255, 255, 255, 0.06)',
}

const CHANNELS = [
  {
    icon: Mail,
    color: 'text-emerald-400',
    border: 'hover:border-emerald-400/50',
    label: 'Official Email',
    value: 'muhammadsaifudinmj@gmail.com',
    href: 'mailto:muhammadsaifudinmj@gmail.com',
  },
  {
    icon: Send,
    color: 'text-cyan-400',
    border: 'hover:border-cyan-400/50',
    label: 'Telegram Community & Bot Pairing',
    value: '@sentinelai_telebot',
    href: 'https://t.me/sentinelai_telebot',
  },
  {
    icon: MessageCircle,
    color: 'text-indigo-400',
    border: 'hover:border-indigo-400/50',
    label: 'Discord Alert Gateway',
    value: 'Invite SentinelAI Bot',
    href: 'https://discord.com/oauth2/authorize?client_id=1539651318648545420',
  },
  {
    icon: Github,
    color: 'text-slate-300',
    border: 'hover:border-white/40',
    label: 'GitHub Repository',
    value: '@Iamatto01',
    href: 'https://github.com/Iamatto01',
  },
]

export default function Contact() {
  const [form, setForm] = useState({ name: '', email: '', type: 'inquiry', message: '' })
  const [status, setStatus] = useState('idle') // idle | sending | sent | error

  const update = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const submit = async (e) => {
    e.preventDefault()
    setStatus('sending')
    try {
      // Route through the existing scan-request notification endpoint when available;
      // fall back to a mailto handoff so the inquiry is never silently dropped.
      const res = await fetch('/api/scans/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: form.email,
          name: form.name,
          subject: `[Contact Portal] ${form.type}`,
          message: form.message,
        }),
      })
      if (!res.ok) throw new Error('request failed')
      setStatus('sent')
      setForm({ name: '', email: '', type: 'inquiry', message: '' })
    } catch {
      setStatus('error')
    }
  }

  return (
    <PublicLayout>
      <div className="max-w-6xl mx-auto px-4 sm:px-8 pt-16 sm:pt-24 pb-12 space-y-24">
        {/* ── Hero ─────────────────────────────────────────────────────────── */}
        <section className="text-center space-y-5">
          <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
            Let&apos;s Secure <span className="at-home__gradient-text">Your Stack Together</span>
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Questions about security posture, feature requests, demo access, or a direct consultation —
            every channel below reaches the team.
          </p>
        </section>

        {/* ── Communication Channels ───────────────────────────────────────── */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {CHANNELS.map((c) => {
            const Icon = c.icon
            return (
              <a
                key={c.label}
                href={c.href}
                target={c.href.startsWith('http') ? '_blank' : undefined}
                rel="noreferrer"
                className={`p-5 rounded-2xl space-y-2 transition-all duration-300 hover:-translate-y-1 ${c.border}`}
                style={GLASS_CARD}
              >
                <Icon size={24} className={c.color} />
                <div className="text-[10px] font-extrabold uppercase tracking-wider text-slate-500">{c.label}</div>
                <div className={`text-xs font-bold break-all ${c.color}`}>{c.value}</div>
              </a>
            )
          })}
        </section>

        {/* ── Inquiry Form + Consultation Booking ──────────────────────────── */}
        <section className="grid grid-cols-1 lg:grid-cols-[3fr_2fr] gap-8 items-start">
          {/* Interactive Inquiries Form */}
          <div className="p-7 sm:p-9 rounded-3xl space-y-6" style={GLASS_CARD}>
            <div className="space-y-1.5">
              <h2 className="text-lg font-extrabold text-white">Send an Inquiry</h2>
              <p className="text-xs text-slate-400">
                Security questions, feature suggestions, or demo requests — we reply within one business day.
              </p>
            </div>

            {status === 'sent' ? (
              <div className="p-6 rounded-2xl bg-emerald-500/10 border border-emerald-400/30 text-center space-y-3">
                <CheckCircle2 size={32} className="mx-auto text-emerald-400" />
                <h3 className="text-sm font-bold text-emerald-300">Message received!</h3>
                <p className="text-xs text-slate-400">Thanks for reaching out — the team will get back to you shortly.</p>
                <button onClick={() => setStatus('idle')} className="text-xs font-bold text-cyan-400 hover:text-cyan-300 cursor-pointer">
                  Send another message
                </button>
              </div>
            ) : (
              <form onSubmit={submit} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label htmlFor="ct-name" className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Name</label>
                    <input
                      id="ct-name"
                      required
                      value={form.name}
                      onChange={update('name')}
                      placeholder="Your full name"
                      className="w-full px-4 py-2.5 rounded-xl bg-slate-950/70 border border-white/15 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/30 transition-colors"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label htmlFor="ct-email" className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Email</label>
                    <input
                      id="ct-email"
                      type="email"
                      required
                      value={form.email}
                      onChange={update('email')}
                      placeholder="you@company.com"
                      className="w-full px-4 py-2.5 rounded-xl bg-slate-950/70 border border-white/15 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/30 transition-colors"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="ct-type" className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Inquiry Type</label>
                  <select
                    id="ct-type"
                    value={form.type}
                    onChange={update('type')}
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950/70 border border-white/15 text-sm text-slate-200 focus:outline-none focus:border-cyan-400/60 transition-colors cursor-pointer"
                  >
                    <option value="inquiry">General Security Inquiry</option>
                    <option value="demo">Request a Demo</option>
                    <option value="feature">Feature Suggestion</option>
                    <option value="consultation">Consultation Booking</option>
                    <option value="vulnerability">Responsible Vulnerability Disclosure</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="ct-msg" className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Message</label>
                  <textarea
                    id="ct-msg"
                    required
                    rows={5}
                    value={form.message}
                    onChange={update('message')}
                    placeholder="Tell us about your environment, targets, or question…"
                    className="w-full px-4 py-2.5 rounded-xl bg-slate-950/70 border border-white/15 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/60 focus:ring-1 focus:ring-cyan-400/30 transition-colors resize-y"
                  />
                </div>

                {status === 'error' && (
                  <p className="text-xs text-rose-400 flex items-center gap-1.5">
                    <ShieldAlert size={13} /> Could not submit right now — please email us directly instead.
                  </p>
                )}

                <button
                  type="submit"
                  disabled={status === 'sending'}
                  className="btn-swipe w-full justify-center py-3.5 text-xs font-extrabold disabled:opacity-60 cursor-pointer"
                >
                  {status === 'sending'
                    ? (<><Loader2 size={14} className="animate-spin" /> Sending…</>)
                    : (<>Send Message <ArrowRight size={14} /></>)}
                </button>
              </form>
            )}
          </div>

          {/* Direct Consultation Request */}
          <div className="space-y-6">
            <div className="p-7 rounded-3xl space-y-4 border border-cyan-400/25" style={{ ...GLASS_CARD, background: 'rgba(6, 30, 48, 0.35)' }}>
              <CalendarClock size={28} className="text-cyan-400" />
              <h2 className="text-base font-extrabold text-white">Book a Consultation Slot</h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                Reserve a 1-on-1 security discussion with the Lead Security Architect — architecture review,
                remediation guidance, or compliance planning.
              </p>
              <ul className="space-y-2 text-xs text-slate-300">
                {['45-minute focused session', 'Guided code remediation walkthrough', 'OWASP Top 10 2025 readiness check'].map((x) => (
                  <li key={x} className="flex items-center gap-2">
                    <CheckCircle2 size={13} className="text-emerald-400 shrink-0" /> {x}
                  </li>
                ))}
              </ul>
              <Link to="/login?mode=register&plan=enterprise" className="btn-border-beam w-full justify-center py-3 text-xs font-extrabold">
                Request a Slot <ArrowRight size={13} />
              </Link>
            </div>

            {/* Responsible Disclosure */}
            <div className="p-7 rounded-3xl space-y-3" style={GLASS_CARD}>
              <ShieldAlert size={24} className="text-amber-400" />
              <h2 className="text-sm font-extrabold text-white">Responsible Vulnerability Disclosure</h2>
              <p className="text-xs text-slate-400 leading-relaxed">
                Found a security issue in SentinelAI itself? Email us with reproduction steps and we&apos;ll
                acknowledge within 48 hours and remediate on a best-effort SLA. Please avoid automated
                scanning against our infrastructure without prior coordination.
              </p>
            </div>
          </div>
        </section>
      </div>
    </PublicLayout>
  )
}
