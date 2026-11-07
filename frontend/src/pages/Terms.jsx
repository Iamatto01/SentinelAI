import React from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldAlert, Lock, ShieldCheck, Terminal, Ban, Scale, FileText,
  AlertTriangle, Cpu, CheckCircle2, ArrowRight
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function Terms() {
  const { isNight } = useTheme()

  const cardBg = isNight
    ? 'bg-neutral-900/60 border-white/10 text-white'
    : 'bg-white border-zinc-200 text-zinc-950 shadow-sm'

  return (
    <PublicLayout>
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 sm:pt-28 pb-20 space-y-16 font-sans">
        {/* ── Header ────────────────────────────────────────────────────────── */}
        <section className="text-center space-y-4 max-w-3xl mx-auto">
          <div
            className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-[11px] font-mono uppercase tracking-wider ${
              isNight ? 'border-white/15 bg-white/[0.04] text-neutral-300' : 'border-zinc-300 bg-zinc-100 text-zinc-800'
            }`}
          >
            <Scale size={13} />
            <span>LEGAL CONTRACT &bull; RULES OF ENGAGEMENT &bull; IP PROTECTION</span>
          </div>

          <h1 className={`text-3xl sm:text-5xl font-extrabold tracking-tight ${isNight ? 'text-white' : 'text-zinc-950'}`}>
            Terms of Service &amp; Usage Policy
          </h1>

          <p className={`text-sm sm:text-base leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
            Please read these terms carefully before accessing or using SentinelAI. By accessing the platform,
            initiating scans, or using our AI agent orchestration engine, you agree to be bound by this legally
            binding agreement.
          </p>

          <div className="flex items-center justify-center gap-4 text-[11px] font-mono opacity-60">
            <span>Effective Date: 2026-11-01</span>
            <span>&bull;</span>
            <span>Version 2.4 (Enterprise &amp; Academic Protection)</span>
          </div>
        </section>

        {/* ── HIGHLIGHT BANNER: ANTI-REVERSE ENGINEERING ───────────────────── */}
        <section
          className={`p-6 sm:p-8 rounded-3xl border relative overflow-hidden transition-all ${
            isNight
              ? 'bg-gradient-to-br from-rose-950/40 via-neutral-950 to-neutral-900 border-rose-500/30 text-white shadow-xl shadow-rose-950/20'
              : 'bg-gradient-to-br from-rose-50 via-white to-zinc-50 border-rose-300 text-zinc-950 shadow-md'
          }`}
        >
          <div className="flex flex-col sm:flex-row items-start gap-5">
            <div
              className={`p-3.5 rounded-2xl border shrink-0 ${
                isNight ? 'bg-rose-500/10 border-rose-500/30 text-rose-400' : 'bg-rose-100 border-rose-300 text-rose-700'
              }`}
            >
              <Ban size={28} className="stroke-[2.5]" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-md text-[10px] font-mono font-bold uppercase tracking-wider bg-rose-500 text-white">
                  STRICT ENFORCEMENT
                </span>
                <h2 className="text-lg sm:text-xl font-extrabold tracking-tight">
                  Strict Prohibition of Reverse Engineering (Anti-RE Protocol)
                </h2>
              </div>
              <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-300' : 'text-zinc-700'}`}>
                Users are strictly and unequivocally prohibited from decompiling, disassembling, reverse engineering,
                unpacking, extracting, scraping, or attempting to reconstruct the source code, AI agent system personas,
                verification algorithms, exploitation orchestration models, or internal database architectures of SentinelAI.
                Any unauthorized extraction or imitation of this proprietary engine is an infringement of intellectual property
                rights and subject to immediate legal action.
              </p>
            </div>
          </div>
        </section>

        {/* ── Section Blocks ────────────────────────────────────────────────── */}
        <div className="space-y-10">
          {/* Section 1 */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-white' : 'bg-zinc-100 border-zinc-200 text-zinc-900'}`}>
                <FileText size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">1. Scope, Acceptance &amp; Academic Provenance</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              SentinelAI is an autonomous cyber-security assessment and penetration testing platform engineered by
              Muhammad Saifudin as an IIUM KICT Final Year Project 2 (FYP 2) advanced research project. By creating an
              account, connecting repositories, or initiating blackbox/whitebox assessments, you enter into a binding
              agreement. If you represent an organization, you certify that you possess the full legal authority to bind that
              entity to these terms.
            </p>
          </article>

          {/* Section 2: Detailed Anti-RE & Intellectual Property */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-rose-400' : 'bg-zinc-100 border-zinc-200 text-rose-600'}`}>
                <ShieldAlert size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">2. Intellectual Property, Trade Secrets &amp; Anti-Tampering</h3>
            </div>
            <div className={`text-xs sm:text-sm leading-relaxed space-y-3 ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              <p>
                All rights, title, and interest in and to SentinelAI — including but not limited to the underlying code,
                53 specialist AI agent prompt instructions, custom vulnerability correlation engines, CVSS v4.0 scoring matrices,
                report-contract mechanisms, and UI interfaces — remain the exclusive intellectual property of the author.
              </p>
              <ul className="list-disc list-inside space-y-1.5 pl-2 font-mono text-[11px] sm:text-xs">
                <li><strong className={isNight ? 'text-white' : 'text-black'}>No Copying or Duplication:</strong> You may not copy, clone, mirror, rent, lease, sublicense, distribute, or create derivative works based upon SentinelAI or any part thereof.</li>
                <li><strong className={isNight ? 'text-white' : 'text-black'}>No Prompt / Weight Scraping:</strong> You may not inspect, extract, jailbreak, or scrape the system instructions or prompt chains used by our specialist AI personas.</li>
                <li><strong className={isNight ? 'text-white' : 'text-black'}>No Tampering with Safety Gates:</strong> You may not bypass, disable, circumvent, or tamper with the cryptographic safety approval gates that protect proof-of-concept exploit steps.</li>
                <li><strong className={isNight ? 'text-white' : 'text-black'}>Commercial Prohibition:</strong> You may not resell or repackage scan outputs to power a competing autonomous scanner or SaaS platform without prior written authorization.</li>
              </ul>
            </div>
          </article>

          {/* Section 3: Authorized Pentest & Rules of Engagement */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-cyan-400' : 'bg-zinc-100 border-zinc-200 text-cyan-700'}`}>
                <Terminal size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">3. Authorized Penetration Testing &amp; Rules of Engagement (ROE)</h3>
            </div>
            <div className={`text-xs sm:text-sm leading-relaxed space-y-3 ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              <p>
                SentinelAI bundles real offensive cybersecurity utilities (including Nmap, Nuclei, Sqlmap, Dalfox, Ffuf, and Kali Linux toolchains).
                You represent and warrant that:
              </p>
              <div className={`p-4 rounded-xl border text-xs font-mono space-y-2 ${isNight ? 'bg-black/40 border-white/10' : 'bg-zinc-50 border-zinc-200'}`}>
                <div className="flex items-start gap-2">
                  <CheckCircle2 size={14} className="shrink-0 text-emerald-400 mt-0.5" />
                  <span>You possess explicit, written authorization from the owner of every target host, IP address, domain, or codebase you test.</span>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 size={14} className="shrink-0 text-emerald-400 mt-0.5" />
                  <span>You will NOT target critical national infrastructure, military, healthcare, public utility, or government systems without proper clearance.</span>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 size={14} className="shrink-0 text-emerald-400 mt-0.5" />
                  <span>You will abide by the Computer Crimes Act 1997 (Malaysia) and all relevant local cyber laws where tests are executed.</span>
                </div>
              </div>
            </div>
          </article>

          {/* Section 4: Safe Exploitation Engine */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-amber-400' : 'bg-zinc-100 border-zinc-200 text-amber-700'}`}>
                <AlertTriangle size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">4. Autonomous Exploitation Safeguards &amp; Approval Gates</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              The Autonomous Exploitation Engine utilizes safe, read-only proof-of-concept verification by default.
              Any action that modifies server data, writes files, triggers state changes, or risks service denial
              is locked behind a mandatory manual approval gate. SentinelAI is designed to avoid Denial-of-Service (DoS)
              conditions; however, users are solely responsible for coordinating test schedules during authorized maintenance windows.
            </p>
          </article>

          {/* Section 5: Limitation of Liability */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-white' : 'bg-zinc-100 border-zinc-200 text-zinc-900'}`}>
                <Scale size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">5. Limitation of Liability &amp; Indemnification</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              Under no circumstances shall the author, developers, contributors, or the International Islamic University Malaysia (IIUM)
              be held liable for any damages, service disruptions, loss of data, legal repercussions, or penalties resulting from
              the misuse, unauthorized execution, or malicious deployment of SentinelAI by third parties. You agree to defend, indemnify,
              and hold harmless the platform creator from any claims arising out of your scanning activities.
            </p>
          </article>

          {/* Section 6: Account Termination */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-rose-400' : 'bg-zinc-100 border-zinc-200 text-rose-600'}`}>
                <Ban size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">6. Violations &amp; Immediate Revocation</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              Any violation of the Anti-Reverse Engineering clauses, unauthorized scanning of unpermitted hosts, or
              attempts to tamper with platform security controls will result in immediate, non-negotiable termination of your account,
              revocation of API keys, IP blacklisting, and where warranted, referral to relevant law enforcement authorities.
            </p>
          </article>
        </div>

        {/* ── Footer Link to Privacy ────────────────────────────────────────── */}
        <div
          className={`p-6 rounded-2xl border flex flex-col sm:flex-row items-center justify-between gap-4 ${
            isNight ? 'bg-white/[0.03] border-white/10' : 'bg-zinc-100 border-zinc-200'
          }`}
        >
          <div className="space-y-0.5 text-center sm:text-left">
            <h4 className="text-xs sm:text-sm font-bold">Looking for Data Governance &amp; Cookies?</h4>
            <p className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              Read our local-first Zero-Cloud Privacy &amp; Cookie Policy.
            </p>
          </div>
          <Link
            to="/privacy"
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
              isNight ? 'bg-white text-black hover:bg-neutral-200' : 'bg-black text-white hover:bg-zinc-800'
            }`}
          >
            <span>Read Privacy Policy</span>
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </PublicLayout>
  )
}
