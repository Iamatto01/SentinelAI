import React from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, Lock, Database, Cookie, EyeOff, Server,
  Sliders, ArrowRight, CheckCircle2, AlertCircle, Ban
} from 'lucide-react'
import PublicLayout from '../components/PublicLayout.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function Privacy() {
  const { isNight } = useTheme()

  const openCookieModal = () => {
    window.dispatchEvent(new Event('sentinel_open_cookie_preferences'))
  }

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
            <Lock size={13} />
            <span>LOCAL-FIRST ZERO-CLOUD ARCHITECTURE &bull; PDPA COMPLIANT</span>
          </div>

          <h1 className={`text-3xl sm:text-5xl font-extrabold tracking-tight ${isNight ? 'text-white' : 'text-zinc-950'}`}>
            Privacy Policy &amp; Cookie Governance
          </h1>

          <p className={`text-sm sm:text-base leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
            SentinelAI is engineered on a strict <strong>local-first, zero-cloud data isolation principle</strong>.
            Your security assessment logs, target code, and penetration findings remain entirely on your infrastructure.
          </p>

          <div className="flex items-center justify-center gap-4 text-[11px] font-mono opacity-60">
            <span>Last Updated: November 2026</span>
            <span>&bull;</span>
            <span>Malaysian PDPA &amp; GDPR Standard</span>
          </div>
        </section>

        {/* ── Quick Reconfigure Button Banner ──────────────────────────────── */}
        <section
          className={`p-5 sm:p-6 rounded-2xl border flex flex-col sm:flex-row items-center justify-between gap-4 ${
            isNight ? 'bg-white/[0.03] border-white/15 text-white' : 'bg-zinc-100 border-zinc-300 text-zinc-950'
          }`}
        >
          <div className="flex items-center gap-3.5 text-center sm:text-left">
            <div className={`p-2.5 rounded-xl border shrink-0 ${isNight ? 'bg-white/5 border-white/10' : 'bg-white border-zinc-300'}`}>
              <Sliders size={20} />
            </div>
            <div>
              <h3 className="text-sm font-bold">Manage Cookie &amp; Storage Settings</h3>
              <p className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
                Review or re-adjust your consent preferences at any time.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={openCookieModal}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all cursor-pointer ${
              isNight ? 'bg-white text-black hover:bg-neutral-200 shadow-md' : 'bg-black text-white hover:bg-zinc-800'
            }`}
          >
            Open Cookie Manager
          </button>
        </section>

        {/* ── Policy Sections ──────────────────────────────────────────────── */}
        <div className="space-y-10">
          {/* Section 1: Local-First Core */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-emerald-400' : 'bg-zinc-100 border-zinc-200 text-emerald-700'}`}>
                <Database size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">1. Zero-Cloud Data Isolation (Local-First Architecture)</h3>
            </div>
            <div className={`text-xs sm:text-sm leading-relaxed space-y-3 ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              <p>
                Unlike conventional SaaS scanners that upload your sensitive source code, network topologies, and vulnerability
                inventories to multi-tenant cloud storage, SentinelAI operates on a <strong>local-first paradigm</strong>:
              </p>
              <ul className="list-disc list-inside space-y-1.5 pl-2 font-mono text-[11px] sm:text-xs">
                <li><strong className={isNight ? 'text-white' : 'text-black'}>Local SQLite WAL Database:</strong> All scan targets, findings, CVE mappings, and executive PDF reports reside in your local encrypted SQLite instance on your own machine or VM.</li>
                <li><strong className={isNight ? 'text-white' : 'text-black'}>No AI Training on Your Code:</strong> Code uploaded for static whitebox analysis is streamed exclusively through private API completion tunnels. Your proprietary code is NEVER stored, pooled, or used to fine-tune AI models.</li>
                <li><strong className={isNight ? 'text-white' : 'text-black'}>No 3rd-Party Telemetry:</strong> No analytics trackers, Google Tag Manager, or third-party telemetry scripts are embedded in the platform.</li>
              </ul>
            </div>
          </article>

          {/* Section 2: Detailed Cookie & Storage Inventory */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-amber-400' : 'bg-zinc-100 border-zinc-200 text-amber-700'}`}>
                <Cookie size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">2. Complete Inventory of Cookies &amp; Local Storage</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              SentinelAI uses the absolute minimum browser storage required for secure application operation.
              Below is the comprehensive, transparent schedule of all stored keys:
            </p>

            <div className="overflow-x-auto">
              <table className={`w-full text-left text-xs font-mono border rounded-xl overflow-hidden ${isNight ? 'border-white/10' : 'border-zinc-200'}`}>
                <thead className={isNight ? 'bg-white/5 text-neutral-300' : 'bg-zinc-100 text-zinc-800'}>
                  <tr>
                    <th className="p-3 border-b border-inherit">Key / Name</th>
                    <th className="p-3 border-b border-inherit">Storage Type</th>
                    <th className="p-3 border-b border-inherit">Classification</th>
                    <th className="p-3 border-b border-inherit">Purpose &amp; Data Held</th>
                  </tr>
                </thead>
                <tbody className={`divide-y ${isNight ? 'divide-white/10' : 'divide-zinc-200'}`}>
                  <tr>
                    <td className="p-3 font-bold text-cyan-400">authToken</td>
                    <td className="p-3">localStorage</td>
                    <td className="p-3"><span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400">Strictly Essential</span></td>
                    <td className="p-3">Cryptographically signed JWT bearer token used to authenticate API calls and enforce Role-Based Access Control (RBAC).</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-bold text-cyan-400">theme / sentinelai_bg_config</td>
                    <td className="p-3">localStorage</td>
                    <td className="p-3"><span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400">User Preference</span></td>
                    <td className="p-3">Remembers your display settings: Night Mode (pitch black) or Day Mode (minimalist light), plus background wallpaper style.</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-bold text-cyan-400">sentinel_cookie_consent</td>
                    <td className="p-3">localStorage</td>
                    <td className="p-3"><span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400">Strictly Essential</span></td>
                    <td className="p-3">Stores your consent decision (<code>'accepted'</code> or <code>'essential'</code>) so the banner is not displayed repeatedly.</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-bold text-cyan-400">sentinel_gate_trigger</td>
                    <td className="p-3">sessionStorage</td>
                    <td className="p-3"><span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400">Security Gate</span></td>
                    <td className="p-3">Session-scoped cryptographic gate flag ensuring fresh authentication upon browser restart.</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-bold text-cyan-400">sentinel_billing_interval</td>
                    <td className="p-3">localStorage</td>
                    <td className="p-3"><span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400">User Preference</span></td>
                    <td className="p-3">Retains monthly vs. yearly subscription toggle in billing views.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </article>

          {/* Section 3: Information We Collect */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-cyan-400' : 'bg-zinc-100 border-zinc-200 text-cyan-700'}`}>
                <EyeOff size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">3. Personal &amp; Account Data Governance</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              We collect only the bare essential information needed to provide the service: your username, email address,
              and bcrypt-hashed passwords. We do not sell, rent, trade, or share this data with third parties or advertising brokers.
              All billing transactions are processed through Stripe with end-to-end PCI-DSS compliance; no credit card numbers
              ever touch our database.
            </p>
          </article>

          {/* Section 4: Anti-RE & System Integrity Notice */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-rose-400' : 'bg-zinc-100 border-zinc-200 text-rose-600'}`}>
                <Ban size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">4. System Protection &amp; Anti-Reverse Engineering</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              While your private scan data is protected with utmost confidentiality, our platform infrastructure and
              algorithms are protected by strict intellectual property laws. Attempting to reverse engineer our multi-LLM consensus
              routing, extract specialist agent prompt definitions, or tamper with execution gates is strictly forbidden under our{' '}
              <Link to="/terms" className="underline font-bold text-cyan-400">Terms of Service</Link>.
            </p>
          </article>

          {/* Section 5: Rights & Erasure */}
          <article className={`p-6 sm:p-8 rounded-2xl border space-y-4 ${cardBg}`}>
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-xl border ${isNight ? 'bg-white/5 border-white/10 text-white' : 'bg-zinc-100 border-zinc-200 text-zinc-900'}`}>
                <ShieldCheck size={18} />
              </div>
              <h3 className="text-base sm:text-lg font-bold">5. Right to Erasure &amp; Data Export</h3>
            </div>
            <p className={`text-xs sm:text-sm leading-relaxed ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              In accordance with the Malaysian Personal Data Protection Act 2010 (PDPA) and international standards, you have the right
              to request permanent deletion of your account and all associated assessment records. You may also export your findings
              and executive audit reports at any time in industry-standard PDF or JSON formats.
            </p>
          </article>
        </div>

        {/* ── Footer Link to Terms ─────────────────────────────────────────── */}
        <div
          className={`p-6 rounded-2xl border flex flex-col sm:flex-row items-center justify-between gap-4 ${
            isNight ? 'bg-white/[0.03] border-white/10' : 'bg-zinc-100 border-zinc-200'
          }`}
        >
          <div className="space-y-0.5 text-center sm:text-left">
            <h4 className="text-xs sm:text-sm font-bold">Have questions about Rules of Engagement?</h4>
            <p className={`text-xs ${isNight ? 'text-neutral-400' : 'text-zinc-600'}`}>
              Review our Terms of Service &amp; Anti-Reverse Engineering policies.
            </p>
          </div>
          <Link
            to="/terms"
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold transition-all ${
              isNight ? 'bg-white text-black hover:bg-neutral-200' : 'bg-black text-white hover:bg-zinc-800'
            }`}
          >
            <span>Read Terms of Service</span>
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </PublicLayout>
  )
}
