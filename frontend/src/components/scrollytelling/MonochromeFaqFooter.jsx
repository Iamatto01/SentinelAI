import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  ChevronDown, ChevronUp, ArrowRight, ArrowUpRight, ShieldCheck,
  Github, Send, MessageCircle, Mail, Terminal, Database, Cpu,
  Lock, CheckCircle2, Sparkles, Activity
} from 'lucide-react'
import InspectorLogo from '../InspectorLogo.jsx'

const FAQS = [
  {
    q: 'What payment methods do you accept?',
    a: 'Subscriptions and on-demand scan credits are billed in MYR (Ringgit Malaysia) via Stripe live checkout. We support all major Credit/Debit cards (Visa, Mastercard), Apple Pay, Google Pay, DuitNow QR, and FPX Online Banking with instant automated activation.',
  },
  {
    q: 'Can I cancel at any time?',
    a: 'Yes. Both monthly and yearly plans are cancel-anytime — your plan stays active until the end of the current billing period, and no further charges are made. Your scan history and executive PDF reports remain exportable forever.',
  },
  {
    q: 'What happens if I hit my scan quota?',
    a: 'Pro plans include 50 AI code audits per month. When the quota is reached, you can either top up single credits via Pay-Per-Scan (RM 3/scan) or upgrade to Enterprise (unlimited audits). You are proactively notified before any quota is exhausted.',
  },
  {
    q: 'Is my source code and scan data safe?',
    a: 'Absolutely. SentinelAI is local-first and zero-cloud by design: all findings, audit logs, and repository code live in a local SQLite WAL database on your own infrastructure. Nothing is shared with third parties or external model training pipelines.',
  },
  {
    q: 'Do exploit campaigns run automatically without my knowledge?',
    a: 'No. The Autonomous Exploitation Engine uses safe read-only verification for proof-of-concept steps. Any critical or potentially disruptive action requires explicit manual approval through cryptographic safety gates.',
  },
  {
    q: 'How does SentinelAI compare to hiring a traditional pentest firm?',
    a: 'A single traditional blackbox engagement typically costs RM 15,000+ with multi-week turnaround and human fatigue errors. SentinelAI delivers continuous autonomous assessment starting from RM 3 per scan or RM 20/month with zero false positives.',
  },
]

export default function MonochromeFaqFooter() {
  const [openFaq, setOpenFaq] = useState(null)

  const toggleFaq = (index) => {
    setOpenFaq(openFaq === index ? null : index)
  }

  return (
    <section id="faq" className="relative scroll-mt-20 py-24 sm:py-32 bg-black border-t border-white/10 text-white overflow-hidden">
      {/* Top Overhead Volumetric Beam */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-96 -translate-y-1/2 opacity-25 blur-3xl z-0"
        style={{
          background: 'radial-gradient(ellipse 80% 50% at 50% -20%, rgba(255,255,255,0.18), transparent)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 35 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-3xl mx-auto space-y-4 mb-16 sm:mb-20"
        >
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-white/15 bg-white/[0.04] text-[11px] font-mono text-neutral-300">
            <Lock size={13} className="text-white" />
            <span className="font-bold uppercase tracking-wider">
              TRUST, GOVERNANCE &amp; FREQUENTLY ASKED QUESTIONS
            </span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight font-sans">
            Frequently Asked Questions
          </h2>

          <p className="text-sm sm:text-base text-neutral-400 font-sans leading-relaxed">
            Everything you need to know about autonomous penetration testing, local-first zero-cloud data
            isolation, billing quotas, and safe proof-of-concept execution.
          </p>
        </motion.div>

        {/* Clean Minimalist Bottom-Bordered Accordion with Scroll Entrance */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.8, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          className="max-w-3xl mx-auto divide-y divide-white/10 border-y border-white/10 mb-24 sm:mb-32"
        >
          {FAQS.map((faq, idx) => {
            const isOpen = openFaq === idx

            return (
              <div key={idx} className="py-5 sm:py-6">
                <button
                  type="button"
                  onClick={() => toggleFaq(idx)}
                  className="w-full flex items-center justify-between text-left gap-4 group cursor-pointer focus:outline-none"
                >
                  <span className="text-base sm:text-lg font-bold font-sans text-neutral-200 group-hover:text-white transition-colors">
                    {faq.q}
                  </span>
                  <div className="p-1 rounded-md border border-white/10 text-neutral-400 group-hover:text-white group-hover:border-white/30 transition-all shrink-0">
                    {isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </button>

                {isOpen && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.3 }}
                    className="mt-3 text-xs sm:text-sm text-neutral-400 font-sans leading-relaxed pr-6"
                  >
                    {faq.a}
                  </motion.div>
                )}
              </div>
            )
          })}
        </motion.div>

        {/* ── FINAL CTA BANNER (High-Contrast Spotlight Box) ── */}
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.96 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.85, ease: [0.16, 1, 0.3, 1] }}
          className="relative rounded-3xl border border-white/20 bg-gradient-to-b from-[#141414] via-[#090909] to-black p-8 sm:p-14 text-center overflow-hidden shadow-[0_0_60px_rgba(255,255,255,0.12)] mb-24 sm:mb-32"
        >
          <div
            className="pointer-events-none absolute inset-x-0 top-0 h-48 opacity-40 blur-2xl"
            style={{
              background: 'radial-gradient(ellipse 70% 60% at 50% -20%, rgba(255,255,255,0.4), transparent)',
            }}
          />

          <div className="relative z-10 max-w-2xl mx-auto space-y-6">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-white/20 bg-white/5 text-[10px] font-mono uppercase tracking-widest text-neutral-300">
              <Sparkles size={11} className="text-white" />
              <span>3 Free Trial Scans &bull; No Credit Card Required</span>
            </div>

            <h3 className="text-2xl sm:text-4xl font-black text-white font-sans tracking-tight">
              Ready to Audit Your Targets?
            </h3>

            <p className="text-xs sm:text-sm text-neutral-400 font-sans leading-relaxed">
              Log in to deploy your first autonomous Kali pentest scan, launch automated AST whitebox code audits,
              or configure continuous GitHub pull request webhooks in under 60 seconds.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
              <Link
                to="/login?mode=register&plan=trial"
                className="w-full sm:w-auto px-6 py-3 rounded-xl bg-white text-black hover:bg-neutral-200 font-mono text-xs font-black uppercase tracking-wider flex items-center justify-center gap-2 shadow-[0_0_25px_rgba(255,255,255,0.35)] transition-all hover:scale-[1.02]"
              >
                <span>Deploy Autonomous Pentest</span>
                <ArrowRight size={14} className="stroke-[2.5]" />
              </Link>
              <Link
                to="/login"
                className="w-full sm:w-auto px-6 py-3 rounded-xl border border-white/20 bg-white/5 hover:bg-white/10 text-white font-mono text-xs font-bold transition-all"
              >
                Sign In to Platform
              </Link>
            </div>
          </div>
        </motion.div>

        {/* ── FOOTER: COMPLETE SITEMAP, STATUS & ATTRIBUTION ── */}
        <motion.footer
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true, amount: 0.1 }}
          transition={{ duration: 0.8 }}
          className="pt-16 border-t border-white/10"
        >
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-10 pb-12">
            {/* Col 1: Brand & Status */}
            <div className="lg:col-span-2 space-y-4">
              <Link to="/" className="flex items-center gap-2.5">
                <div className="p-1 rounded-lg border border-white/20 bg-white/5">
                  <InspectorLogo size={24} variant="base" className="text-white" />
                </div>
                <span className="font-extrabold text-white text-base tracking-tight font-sans">
                  Sentinel<span className="text-neutral-400">AI</span>
                </span>
              </Link>

              <p className="text-xs text-neutral-400 font-sans leading-relaxed max-w-sm">
                Autonomous AI-driven penetration testing and vulnerability mapping platform. Chains 150+
                real Kali Linux tools, 53 specialist AI personas, and local-first SQLite WAL intelligence.
              </p>

              {/* Status Indicator */}
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg border border-white/15 bg-white/[0.03] text-[11px] font-mono text-neutral-300">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-white" />
                </span>
                <span className="font-bold tracking-wider">[ ALL SYSTEMS OPERATIONAL ]</span>
              </div>

              {/* Social Links */}
              <div className="flex items-center gap-2 pt-2">
                <a
                  href="https://github.com/Iamatto01"
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 rounded-lg border border-white/10 bg-white/5 text-neutral-300 hover:text-white hover:border-white/30 transition-colors"
                  aria-label="GitHub"
                >
                  <Github size={14} />
                </a>
                <a
                  href="https://www.linkedin.com/in/saifudinjamal/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2 rounded-lg border border-white/10 bg-white/5 text-neutral-300 hover:text-white hover:border-white/30 transition-colors"
                  aria-label="LinkedIn"
                >
                  <svg className="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
                    <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 10.9v8.37H9.2V10.9H6.46M7.83 6.67a1.66 1.66 0 0 0-1.66 1.66c0 .92.74 1.66 1.66 1.66a1.66 1.66 0 0 0 1.66-1.66c0-.92-.74-1.66-1.66-1.66Z" />
                  </svg>
                </a>
                <a
                  href="https://t.me/sentinelai_telebot"
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 rounded-lg border border-white/10 bg-white/5 text-neutral-300 hover:text-white hover:border-white/30 transition-colors"
                  aria-label="Telegram"
                >
                  <Send size={14} />
                </a>
                <a
                  href="https://discord.com/oauth2/authorize?client_id=1539651318648545420"
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 rounded-lg border border-white/10 bg-white/5 text-neutral-300 hover:text-white hover:border-white/30 transition-colors"
                  aria-label="Discord"
                >
                  <MessageCircle size={14} />
                </a>
                <a
                  href="mailto:muhammadsaifudinmj@gmail.com"
                  className="p-2 rounded-lg border border-white/10 bg-white/5 text-neutral-300 hover:text-white hover:border-white/30 transition-colors"
                  aria-label="Email"
                >
                  <Mail size={14} />
                </a>
              </div>
            </div>

            {/* Col 2: Platform Links */}
            <div className="space-y-3 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider text-[11px]">
                Platform
              </span>
              <ul className="space-y-2 text-neutral-400">
                <li><a href="#platform" className="hover:text-white transition-colors">Overview</a></li>
                <li><a href="#terminal" className="hover:text-white transition-colors">Live CLI Terminal</a></li>
                <li><a href="#models" className="hover:text-white transition-colors">AI Pentest Engines</a></li>
                <li><a href="#matrix" className="hover:text-white transition-colors">Vulnerability Matrix</a></li>
                <li><a href="#architecture" className="hover:text-white transition-colors">System Blueprint</a></li>
                <li><a href="#pricing" className="hover:text-white transition-colors">Subscription Plans</a></li>
              </ul>
            </div>

            {/* Col 3: Modules & Arsenal */}
            <div className="space-y-3 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider text-[11px]">
                Arsenal
              </span>
              <ul className="space-y-2 text-neutral-400">
                <li><Link to="/tools" className="hover:text-white transition-colors">150+ Kali Tools</Link></li>
                <li><Link to="/tools" className="hover:text-white transition-colors">53 AI Specialist Personas</Link></li>
                <li><Link to="/services" className="hover:text-white transition-colors">Blackbox Assessment</Link></li>
                <li><Link to="/services" className="hover:text-white transition-colors">DevSecOps GitHub CI</Link></li>
                <li><Link to="/services" className="hover:text-white transition-colors">Virtual CISO Advisory</Link></li>
                <li><Link to="/about" className="hover:text-white transition-colors">Local-First Architecture</Link></li>
              </ul>
            </div>

            {/* Col 4: Tech Infrastructure */}
            <div className="space-y-3 font-mono text-xs">
              <span className="font-bold text-white uppercase tracking-wider text-[11px]">
                Core Engine
              </span>
              <ul className="space-y-2 text-neutral-400">
                <li className="flex items-center gap-1.5"><Terminal size={12} className="text-white" /> Native Kali Linux</li>
                <li className="flex items-center gap-1.5"><Database size={12} className="text-white" /> SQLite WAL Zero-Cloud</li>
                <li className="flex items-center gap-1.5"><Cpu size={12} className="text-white" /> DeepSeek V4 / Groq</li>
                <li className="flex items-center gap-1.5"><ShieldCheck size={12} className="text-white" /> React 18 + Vite</li>
                <li className="pt-2">
                  <Link to="/contact" className="text-neutral-300 hover:text-white underline">
                    Contact Research Lead
                  </Link>
                </li>
              </ul>
            </div>
          </div>

          {/* Bottom Copyright & Attribution Bar */}
          <div className="pt-8 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-neutral-500">
            <span>
              &copy; {new Date().getFullYear()} SentinelAI &mdash; Muhammad Saifudin. All rights reserved.
            </span>
            <span className="flex items-center gap-1.5 text-neutral-400">
              <ShieldCheck size={13} className="text-white" />
              <span>Academic Pentest Platform &mdash; IIUM KICT Final Year Project 2</span>
            </span>
          </div>
        </motion.footer>
      </div>
    </section>
  )
}
