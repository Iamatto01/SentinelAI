import React, { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  UserCheck, Shield, Award, Calendar, Clock, Video, MessageSquare,
  Sparkles, CheckCircle2, AlertTriangle, ArrowRight, ExternalLink,
  Plus, Users, Star, Layers, RefreshCw, Loader2, ChevronRight,
  FileText, Globe, Lock, Briefcase, Zap, HelpCircle, X
} from 'lucide-react'
import { api } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'

const EXPERTS = [
  {
    id: 'exp_saifudin',
    name: 'Muhammad Saifudin',
    role: 'Lead AI Security Architect & FYP Researcher',
    certs: ['Offensive AI Security', 'Full-Stack Pentest Architect', 'IIUM KICT'],
    exp: 'Lead System Developer',
    rating: 5.0,
    reviewsCount: 48,
    avatarBg: 'from-cyan-500 to-blue-600',
    avatarUrl: '/saif.png',
    specialties: ['Autonomous AI Penetration Testing', 'DAST & SAST Dual-Engine Remediation', 'Kali Toolchain & Exploit Orchestration'],
    bio: 'Lead creator of SentinelAI and cybersecurity researcher at IIUM KICT. Specializing in autonomous multi-agent vulnerability assessment, live exploitation validation, and full-stack security architecture.',
    available: true,
  },
]

const PACKAGES = [
  {
    id: 'pkg_remediation',
    title: '1-on-1 Guided Vulnerability Remediation',
    duration: '1 Hour Live Session',
    badge: 'Most Popular',
    badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-400/30',
    includedInEnterprise: true,
    description: 'Direct interactive walkthrough with an OSCP/OSWE certified pentester to analyze your recent scan findings and implement code-level fixes.',
    highlights: [
      'Line-by-line code review of identified vulnerabilities',
      'Step-by-step guidance on patch implementation',
      'Verification scan trigger following fixes',
      'Custom remediation guidance document'
    ]
  },
  {
    id: 'pkg_cloud',
    title: 'Cloud & Infrastructure Architecture Review',
    duration: '2 Hours Deep Dive',
    badge: 'Enterprise Architecture',
    badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-400/30',
    includedInEnterprise: true,
    description: 'Comprehensive review of your AWS, Azure, GCP, or Kubernetes infrastructure for privilege leakage, exposed endpoints, and misconfigurations.',
    highlights: [
      'IAM least-privilege policy evaluation',
      'Kubernetes cluster & ingress security audit',
      'Storage bucket & database exposure checks',
      'Architecture hardening blueprint'
    ]
  },
  {
    id: 'pkg_ciso',
    title: 'Executive Debrief & Boardroom Risk Summary',
    duration: '1.5 Hours Presentation',
    badge: 'Virtual CISO',
    badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-400/30',
    includedInEnterprise: true,
    description: 'A Virtual CISO presents a business-focused overview of your security posture, regulatory compliance alignment, and strategic risk roadmap.',
    highlights: [
      'Executive-level risk score justification',
      'Compliance gap analysis (ISO 27001, SOC2, PCI-DSS)',
      'Strategic 90-day cyber roadmap',
      'Q&A session with your stakeholders'
    ]
  },
  {
    id: 'pkg_custom',
    title: 'Custom Advisory & Dedicated Pentest Scope',
    duration: 'Tailored Scope',
    badge: 'Custom Engagement',
    badgeColor: 'bg-slate-700 text-slate-300 border-white/10',
    includedInEnterprise: false,
    description: 'Custom security consulting, specialized manual exploit testing, or dedicated incident response retainer tailored to your organization.',
    highlights: [
      'Tailored scope of work (SOW)',
      'Dedicated primary consultant assignment',
      'Continuous Slack / Discord channel support',
      'Formal signed verification certificate'
    ]
  }
]

export default function Consultants() {
  const { user } = useAuth()
  const nav = useNavigate()
  const isAdmin = user?.role === 'admin'
  const isClient = user?.role === 'client'

  const [subscription, setSubscription] = useState(null)
  const [consultations, setConsultations] = useState([])
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const [showModal, setShowModal] = useState(false)
  const [selectedPackage, setSelectedPackage] = useState('')
  const [selectedExpert, setSelectedExpert] = useState('')
  const [selectedScanId, setSelectedScanId] = useState('')
  const [preferredDate, setPreferredDate] = useState('')
  const [preferredTime, setPreferredTime] = useState('')
  const [channel, setChannel] = useState('Google Meet')
  const [notes, setNotes] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const [editingId, setEditingId] = useState(null)
  const [adminStatus, setAdminStatus] = useState('confirmed')
  const [adminMeetingLink, setAdminMeetingLink] = useState('')
  const [adminNotes, setAdminNotes] = useState('')
  const [updatingStatus, setUpdatingStatus] = useState(false)

  const isEnterprise = subscription?.plan_id === 'enterprise' && subscription?.status === 'active'

  useEffect(() => {
    fetchData()
  }, [])

  async function fetchData() {
    setLoading(true)
    try {
      const [subRes, consRes, scansRes] = await Promise.allSettled([
        api.billingSubscription(),
        api.consultations(),
        api.scans()
      ])

      if (subRes.status === 'fulfilled') setSubscription(subRes.value)
      if (consRes.status === 'fulfilled') setConsultations(consRes.value?.consultations || [])
      if (scansRes.status === 'fulfilled') {
        const sList = Array.isArray(scansRes.value) ? scansRes.value : (scansRes.value?.scans || [])
        setScans(sList)
      }
    } catch (e) {
      setErr('Failed to load consultation data')
    } finally {
      setLoading(false)
    }
  }

  function openBookingModal(pkgTitle = '', expertName = '') {
    setSelectedPackage(pkgTitle || PACKAGES[0].title)
    setSelectedExpert(expertName || 'Any Available Specialist')
    setShowModal(true)
  }

  async function handleBookConsultation(e) {
    e.preventDefault()
    if (!selectedPackage) return
    setSubmitting(true)
    setMsg('')
    setErr('')

    try {
      const res = await api.createConsultation({
        serviceType: selectedPackage,
        consultantName: selectedExpert,
        scanId: selectedScanId || null,
        preferredDate: preferredDate || null,
        preferredTime: preferredTime || null,
        channel,
        notes: notes.trim()
      })

      if (res && res.success) {
        setMsg('Your consultation booking request has been submitted! Our specialist will confirm the schedule and send the meeting link.')
        setShowModal(false)
        setNotes('')
        setSelectedScanId('')
        const updated = await api.consultations()
        setConsultations(updated?.consultations || [])
      }
    } catch (err2) {
      setErr(err2.message || 'Failed to submit consultation request')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleAdminUpdate(id) {
    setUpdatingStatus(true)
    try {
      await api.updateConsultation(id, {
        status: adminStatus,
        meetingLink: adminMeetingLink.trim(),
        adminNotes: adminNotes.trim()
      })
      setEditingId(null)
      const updated = await api.consultations()
      setConsultations(updated?.consultations || [])
      setMsg('Consultation session status updated successfully.')
    } catch (err2) {
      setErr(err2.message || 'Failed to update consultation')
    } finally {
      setUpdatingStatus(false)
    }
  }

  return (
    <div className="space-y-8 motion-fade-up pb-16">
      {/* ── Top Hero Header ─────────────────────────────────────────── */}
      <div className="card p-8 bg-[#161616] border-cyan-500/30 relative overflow-hidden">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-extrabold tracking-wider px-2.5 py-1 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 flex items-center gap-1.5">
                <Sparkles size={12} className="animate-spin-slow" /> Certified Security Advisory
              </span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2.5 py-1 rounded-full bg-purple-500/20 text-purple-300 border border-purple-400/30">
                1-on-1 Live Guidance
              </span>
            </div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">
              Hire Certified Security Professionals
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Get direct 1-on-1 guidance with certified cybersecurity specialists to remediate vulnerabilities, review cloud architecture, and prepare executive audit reports.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-start md:items-center gap-3 shrink-0">
            <button
              onClick={() => openBookingModal()}
              className="btn-primary text-xs py-2.5 px-4 shadow-glow flex items-center gap-2 font-bold cursor-pointer"
            >
              <Calendar size={15} />
              <span>Book Consultation Session</span>
            </button>
            <button
              onClick={fetchData}
              className="btn-ghost text-xs p-2.5 cursor-pointer"
              title="Refresh Data"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>
      </div>

      {msg && (
        <div className="card p-4 text-emerald-400 text-xs font-bold flex items-center gap-3 border-emerald-500/30 bg-emerald-500/10">
          <CheckCircle2 size={18} className="shrink-0" />
          <span>{msg}</span>
        </div>
      )}
      {err && (
        <div className="card p-4 text-rose-400 text-xs font-bold flex items-center gap-3 border-rose-500/30 bg-rose-500/10">
          <AlertTriangle size={18} className="shrink-0" />
          <span>{err}</span>
        </div>
      )}

      {/* ── Enterprise Plan VIP Benefit Banner ───────────────────────── */}
      <div className={`card p-6 border transition-all duration-300 ${
        isEnterprise
          ? 'border-emerald-500/40 bg-emerald-950/20 shadow-[0_0_20px_rgba(16,185,129,0.15)]'
          : 'border-amber-500/40 bg-slate-900/70 shadow-xl'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-5">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <div className={`p-2 rounded-xl border ${
                isEnterprise
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-400/30'
                  : 'bg-amber-500/20 text-amber-300 border-amber-400/30'
              }`}>
                <Award size={20} />
              </div>
              <div>
                <h3 className="text-base font-extrabold text-white flex items-center gap-2">
                  {isEnterprise ? '👑 Enterprise VIP Advisory Benefit Active' : '⭐ SentinelAI Enterprise Plan (Premium Advisory)'}
                </h3>
                <p className="text-xs text-slate-400">
                  {isEnterprise
                    ? 'Your account includes full access to 4 hours of dedicated consultation & Virtual CISO advisory each month at no extra charge.'
                    : '1-on-1 consultation sessions with security specialists are included for FREE in the SentinelAI Enterprise plan ($79/mo).'}
                </p>
              </div>
            </div>
          </div>

          <div className="shrink-0 flex items-center gap-3">
            {isEnterprise ? (
              <button
                onClick={() => openBookingModal()}
                className="btn-primary text-xs py-2 px-4 flex items-center gap-2 font-bold shadow-glow cursor-pointer"
              >
                <Zap size={14} className="text-amber-300" />
                <span>Use Consultation Quota</span>
              </button>
            ) : (
              <Link
                to="/app/billing"
                className="btn-primary text-xs py-2 px-4 flex items-center gap-2 font-bold shadow-glow bg-gradient-to-r from-amber-500 to-rose-600 border-amber-400/40 cursor-pointer"
              >
                <span>Upgrade to Enterprise</span>
                <ArrowRight size={14} />
              </Link>
            )}
          </div>
        </div>
      </div>

      {/* ── Certified Specialists Roster ────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Users size={18} className="text-cyan-400" />
              Certified Security Specialists
            </h2>
            <p className="text-xs text-slate-400">Consult with the system architect & offensive AI researcher</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {EXPERTS.map((exp) => (
            <div
              key={exp.id}
              className="card p-6 space-y-4 border border-cyan-500/30 hover:border-cyan-400/60 transition-all duration-300 flex flex-col justify-between group bg-slate-900/70 shadow-xl"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="relative shrink-0">
                    <div className="w-16 h-16 rounded-2xl overflow-hidden border-2 border-cyan-400/40 shadow-lg shadow-cyan-950/40 bg-slate-900 ring-2 ring-cyan-500/20">
                      <img
                        src={exp.avatarUrl || '/saif.png'}
                        alt={exp.name}
                        className="w-full h-full object-cover"
                        style={{ objectPosition: '85% 85%' }}
                        onError={(e) => { e.currentTarget.src = '/fyp2_presenter.png' }}
                      />
                    </div>
                    <span className="absolute -bottom-1 -right-1 px-1.5 py-0.5 rounded-full bg-cyan-500 text-slate-950 text-[8px] font-black uppercase tracking-wider shadow">
                      Lead
                    </span>
                  </div>
                  <div className="flex items-center gap-1 bg-amber-500/10 border border-amber-500/30 px-2.5 py-0.5 rounded-full text-xs font-bold text-amber-300">
                    <Star size={13} className="fill-amber-400 text-amber-400" />
                    <span>{exp.rating.toFixed(1)}</span>
                    <span className="text-slate-500 text-[10px]">({exp.reviewsCount} verified)</span>
                  </div>
                </div>

                <div>
                  <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition-colors">
                    {exp.name}
                  </h3>
                  <p className="text-xs font-semibold text-cyan-400">{exp.role}</p>
                  <p className="text-[11px] text-slate-400 mt-0.5">{exp.exp}</p>
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {exp.certs.map((c) => (
                    <span
                      key={c}
                      className="text-[10px] font-extrabold px-2 py-0.5 rounded bg-black/50 text-cyan-300 border border-cyan-500/30"
                    >
                      {c}
                    </span>
                  ))}
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {exp.bio}
                </p>

                <div className="space-y-1.5 pt-2 border-t border-white/10">
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Core Specialties:</span>
                  <ul className="text-xs text-slate-200 space-y-1">
                    {exp.specialties.map((s, idx) => (
                      <li key={idx} className="flex items-center gap-2">
                        <CheckCircle2 size={13} className="text-emerald-400 shrink-0" />
                        <span>{s}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <button
                type="button"
                onClick={() => openBookingModal(PACKAGES[0].title, exp.name)}
                className="btn-primary w-full text-xs py-2.5 mt-3 flex items-center justify-center gap-2 font-bold shadow-glow cursor-pointer"
              >
                <Calendar size={14} />
                <span>Select & Book Session</span>
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* ── Consultation Packages Catalog ──────────────────────────── */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Briefcase size={18} className="text-cyan-400" />
            Consultation Packages & Services
          </h2>
          <p className="text-xs text-slate-400">Choose the engagement scope tailored to your technical or compliance requirements</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PACKAGES.map((pkg) => (
            <div
              key={pkg.id}
              className="card p-6 space-y-4 border border-white/10 hover:border-cyan-400/30 transition-all duration-300 bg-slate-900/60 flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className={`text-[10px] uppercase font-extrabold px-2.5 py-0.5 rounded-full border ${pkg.badgeColor}`}>
                    {pkg.badge}
                  </span>
                  <span className="text-xs font-bold text-slate-400 flex items-center gap-1">
                    <Clock size={12} className="text-cyan-400" /> {pkg.duration}
                  </span>
                </div>

                <div>
                  <h3 className="text-base font-bold text-white">{pkg.title}</h3>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">{pkg.description}</p>
                </div>

                <div className="space-y-2 pt-2 border-t border-white/5">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">What's Included:</span>
                  <div className="grid grid-cols-1 gap-1.5">
                    {pkg.highlights.map((h, i) => (
                      <div key={i} className="text-xs text-slate-300 flex items-start gap-2">
                        <CheckCircle2 size={13} className="text-emerald-400 shrink-0 mt-0.5" />
                        <span>{h}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-white/5 flex items-center justify-between gap-3">
                <span className="text-xs font-semibold text-cyan-300">
                  {pkg.includedInEnterprise ? '✨ Included in Enterprise Plan' : '💡 Custom Scope Quoting'}
                </span>
                <button
                  type="button"
                  onClick={() => openBookingModal(pkg.title)}
                  className="btn-primary text-xs py-2 px-3.5 flex items-center gap-1.5 shadow-glow cursor-pointer"
                >
                  <Calendar size={13} />
                  <span>Request Package</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── My Consultation Bookings & Status ───────────────────────── */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Calendar size={18} className="text-cyan-400" />
              {isAdmin ? 'All Client Consultation Bookings' : 'Your Consultation Bookings & Status'}
            </h2>
            <p className="text-xs text-slate-400">
              {isAdmin ? 'Manage and schedule consultation sessions with clients' : 'Track schedule confirmation and meeting links for your live sessions'}
            </p>
          </div>
        </div>

        {consultations.length === 0 ? (
          <div className="card p-10 text-center space-y-3 bg-slate-900/40">
            <UserCheck className="mx-auto text-slate-600" size={36} />
            <p className="text-xs text-slate-400">
              No active consultation bookings recorded yet.
            </p>
            <button
              onClick={() => openBookingModal()}
              className="btn-ghost text-xs border border-cyan-500/30 text-cyan-300 cursor-pointer"
            >
              Book Your First Session Now
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {consultations.map((c) => {
              const isConfirmed = c.status === 'confirmed'
              const isCompleted = c.status === 'completed'
              const isPending = c.status === 'pending'

              return (
                <div
                  key={c.id}
                  className="card p-5 border border-white/10 bg-slate-900/70 space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white">{c.service_type}</span>
                        <span className={`text-[10px] uppercase font-extrabold px-2 py-0.5 rounded-full border ${
                          isConfirmed
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                            : isCompleted
                            ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                            : 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse'
                        }`}>
                          {c.status}
                        </span>
                        {c.plan_tier === 'enterprise' && (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-400/30">
                            Enterprise VIP
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-400">
                        Advisor: <strong className="text-slate-200">{c.consultant_name}</strong> | Platform: <strong className="text-slate-200">{c.channel}</strong> | Client: <span className="font-mono text-cyan-300">{c.username || c.email}</span>
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      {c.meeting_link && (
                        <a
                          href={c.meeting_link.startsWith('http') ? c.meeting_link : `https://${c.meeting_link}`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 border-emerald-400/40 shadow-glow"
                        >
                          <Video size={13} />
                          <span>Join Meeting</span>
                          <ExternalLink size={11} />
                        </a>
                      )}
                      {isAdmin && (
                        <button
                          type="button"
                          onClick={() => {
                            setEditingId(c.id)
                            setAdminStatus(c.status || 'confirmed')
                            setAdminMeetingLink(c.meeting_link || '')
                            setAdminNotes(c.admin_notes || '')
                          }}
                          className="btn-ghost text-xs py-1.5 px-3 border border-white/10 cursor-pointer"
                        >
                          Edit Status
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs text-slate-300">
                    <div>
                      <span className="text-slate-500 text-[11px] block">Requested Date & Time:</span>
                      <span className="font-semibold">{c.preferred_date || 'Flexible'} {c.preferred_time ? `(${c.preferred_time})` : ''}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[11px] block">Linked Assessment:</span>
                      <span className="font-mono text-cyan-400">{c.scan_id ? c.scan_id.slice(0, 16) : '—'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[11px] block">Submitted At:</span>
                      <span>{new Date(c.created_at).toLocaleString()}</span>
                    </div>
                  </div>

                  {c.notes && (
                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 text-xs text-slate-300">
                      <strong className="text-slate-400 text-[11px]">Notes / Inquiry:</strong> {c.notes}
                    </div>
                  )}

                  {/* Admin inline edit modal/drawer */}
                  {isAdmin && editingId === c.id && (
                    <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/40 space-y-3 mt-2">
                      <div className="text-xs font-bold text-cyan-300">Update Session #{c.id.slice(0, 8)}:</div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="text-[11px] font-bold text-slate-400 block mb-1">Session Status</label>
                          <select
                            value={adminStatus}
                            onChange={(e) => setAdminStatus(e.target.value)}
                            className="input text-xs w-full"
                          >
                            <option value="pending">Pending</option>
                            <option value="confirmed">Confirmed & Scheduled</option>
                            <option value="completed">Completed</option>
                            <option value="cancelled">Cancelled</option>
                          </select>
                        </div>
                        <div>
                          <label className="text-[11px] font-bold text-slate-400 block mb-1">Meeting Link (Google Meet / Zoom)</label>
                          <input
                            type="text"
                            placeholder="https://meet.google.com/xyz-abcd-efg"
                            value={adminMeetingLink}
                            onChange={(e) => setAdminMeetingLink(e.target.value)}
                            className="input text-xs w-full"
                          />
                        </div>
                      </div>
                      <div className="flex justify-end gap-2 pt-2">
                        <button
                          type="button"
                          onClick={() => setEditingId(null)}
                          className="btn-ghost text-xs py-1 px-3 cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          disabled={updatingStatus}
                          onClick={() => handleAdminUpdate(c.id)}
                          className="btn-primary text-xs py-1 px-3 cursor-pointer"
                        >
                          {updatingStatus ? <Loader2 size={12} className="animate-spin" /> : 'Save Changes'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* ── Booking Request Modal ───────────────────────────────────── */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in">
          <div className="card p-6 w-full max-w-xl border border-cyan-500/40 bg-slate-900/95 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
                  <Calendar size={18} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Book Expert Security Consultation</h3>
                  <p className="text-[11px] text-slate-400">1-on-1 Guided Security Advisory</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleBookConsultation} className="space-y-4">
              {/* Package Selection */}
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">Package / Service Type</label>
                <select
                  value={selectedPackage}
                  onChange={(e) => setSelectedPackage(e.target.value)}
                  className="input text-xs w-full"
                  required
                >
                  {PACKAGES.map((p) => (
                    <option key={p.id} value={p.title}>
                      {p.title} ({p.duration})
                    </option>
                  ))}
                </select>
              </div>

              {/* Expert Selection */}
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">Preferred Specialist Advisor</label>
                <select
                  value={selectedExpert}
                  onChange={(e) => setSelectedExpert(e.target.value)}
                  className="input text-xs w-full"
                >
                  {EXPERTS.map((exp) => (
                    <option key={exp.id} value={exp.name}>
                      {exp.name} — {exp.role} ({exp.certs.join(', ')})
                    </option>
                  ))}
                </select>
              </div>

              {/* Link to Recent Scan */}
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">Link to Assessment Scan (Optional)</label>
                <select
                  value={selectedScanId}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="input text-xs w-full"
                >
                  <option value="">-- No Linked Scan / General Advisory --</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} (Risk: {(s.risk_score || 0).toFixed(1)} | {new Date(s.created_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
                <p className="text-[10px] text-slate-400 mt-1">Our specialists will review this assessment report in advance prior to the session.</p>
              </div>

              {/* Date, Time & Platform */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-300 block mb-1">Preferred Date</label>
                  <input
                    type="date"
                    value={preferredDate}
                    onChange={(e) => setPreferredDate(e.target.value)}
                    className="input text-xs w-full"
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-300 block mb-1">Preferred Time</label>
                  <input
                    type="time"
                    value={preferredTime}
                    onChange={(e) => setPreferredTime(e.target.value)}
                    className="input text-xs w-full"
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-300 block mb-1">Meeting Platform</label>
                  <select
                    value={channel}
                    onChange={(e) => setChannel(e.target.value)}
                    className="input text-xs w-full"
                  >
                    <option value="Google Meet">Google Meet</option>
                    <option value="Microsoft Teams">Microsoft Teams</option>
                    <option value="Zoom">Zoom</option>
                    <option value="Discord Voice">Discord Voice</option>
                  </select>
                </div>
              </div>

              {/* Notes */}
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">Scope of Inquiry / Specific Objectives</label>
                <textarea
                  rows={3}
                  placeholder="Example: We need assistance remediating SQL Injection & CORS misconfigurations on /api/auth endpoints..."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="input text-xs w-full"
                />
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-white/10">
                <div className="text-[11px] text-slate-400">
                  {isEnterprise ? (
                    <span className="text-emerald-400 font-bold">✨ Included in Enterprise quota</span>
                  ) : (
                    <span className="text-slate-400">Confirmed within 24 hours</span>
                  )}
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    className="btn-ghost text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="btn-primary text-xs shadow-glow flex items-center gap-2 cursor-pointer"
                  >
                    {submitting ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
                    <span>Submit Booking Request</span>
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
