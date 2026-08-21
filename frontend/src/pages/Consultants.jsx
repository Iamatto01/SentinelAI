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
    id: 'exp_faris',
    name: 'Muhammad Faris',
    role: 'Lead Virtual CISO & Strategic Risk Advisor',
    certs: ['CISSP', 'CISM', 'OSCP'],
    exp: '12+ Years Experience',
    rating: 4.98,
    reviewsCount: 84,
    avatarBg: 'from-cyan-500 to-blue-600',
    specialties: ['Compliance (ISO 27001, SOC2, PCI-DSS)', 'Executive Risk Debriefs', 'Cloud Security Architecture'],
    bio: 'Former Big 4 Security Director specializing in cyber risk governance, incident response readiness, and translating technical vulnerabilities into executive action plans.',
    available: true,
  },
  {
    id: 'exp_alex',
    name: 'Alex Chen',
    role: 'Principal Web & API Security Specialist',
    certs: ['OSWE', 'CREST CCT', 'eWPTX'],
    exp: '9+ Years Experience',
    rating: 4.95,
    reviewsCount: 112,
    avatarBg: 'from-purple-500 to-indigo-600',
    specialties: ['Guided Zero-Day & Logic Flaw Fixes', 'OAuth2 / JWT Deep Dives', 'Whitebox Code Audit Walkthroughs'],
    bio: 'Specialist in offensive application security and secure SDLC. Assists engineering teams in resolving complex architectural flaws and verifying zero-trust API boundaries.',
    available: true,
  },
  {
    id: 'exp_sarah',
    name: 'Sarah Jenkins',
    role: 'Senior Red Team & Exploit Defense Lead',
    certs: ['CRTO', 'OSCP', 'GXPN'],
    exp: '8+ Years Experience',
    rating: 4.97,
    reviewsCount: 76,
    avatarBg: 'from-rose-500 to-amber-600',
    specialties: ['Active Directory Hardening', 'Privilege Escalation Defense', 'EDR Evasion Remediation'],
    bio: 'Offensive security researcher and Red Team operator with deep expertise in adversary emulation, perimeter defense, and internal network segmentation.',
    available: true,
  },
  {
    id: 'exp_zikri',
    name: 'Ahmad Zikri',
    role: 'Cloud & DevSecOps Security Architect',
    certs: ['AWS Security Specialist', 'CKS', 'CCSP'],
    exp: '7+ Years Experience',
    rating: 4.92,
    reviewsCount: 65,
    avatarBg: 'from-emerald-500 to-teal-600',
    specialties: ['Kubernetes & Container Hardening', 'CI/CD Pipeline Security', 'Terraform & Cloud IAM Audits'],
    bio: 'DevSecOps practitioner focused on shifting security left. Helps teams automate infrastructure-as-code scanning, secret detection, and runtime container defense.',
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
        setMsg('Permohonan sesi konsultasi anda berjaya dihantar! Pasukan pakar kami akan mengesahkan jadual dan menghantar pautan mesyuarat.')
        setShowModal(false)
        setNotes('')
        setSelectedScanId('')
        const updated = await api.consultations()
        setConsultations(updated?.consultations || [])
      }
    } catch (err2) {
      setErr(err2.message || 'Gagal menghantar permohonan konsultasi')
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
      setMsg('Status sesi konsultasi berjaya dikemaskini.')
    } catch (err2) {
      setErr(err2.message || 'Failed to update consultation')
    } finally {
      setUpdatingStatus(false)
    }
  }

  return (
    <div className="space-y-8 motion-fade-up pb-16">
      {/* ── Top Hero Header ─────────────────────────────────────────── */}
      <div className="card p-8 bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-cyan-950/40 border-cyan-500/30 relative overflow-hidden shadow-2xl">
        <div className="absolute -right-12 -bottom-12 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
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
              Dapatkan bimbingan terus secara 1-on-1 bersama pakar keselamatan siber bertauliah (CREST, OSCP, CISSP) untuk membaiki kelemahan sistem, menyemak seni bina awan, dan menyediakan laporan audit eksekutif.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row items-start md:items-center gap-3 shrink-0">
            <button
              onClick={() => openBookingModal()}
              className="btn-primary text-xs py-2.5 px-4 shadow-glow flex items-center gap-2 font-bold cursor-pointer"
            >
              <Calendar size={15} />
              <span>Tempah Sesi Konsultasi</span>
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
                  {isEnterprise ? '👑 Enterprise VIP Advisory Benefit Active' : '⭐ Pelan SentinelAI Enterprise (Pakej Premium)'}
                </h3>
                <p className="text-xs text-slate-400">
                  {isEnterprise
                    ? 'Akaun anda mempunyai akses penuh kepada 4 jam sesi konsultasi & Virtual CISO setiap bulan tanpa caj tambahan.'
                    : 'Sesi konsultasi 1-on-1 bersama pakar pentest disertakan secara PERCUMA dalam pelan SentinelAI Enterprise ($79/bln).'}
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
                <span>Gunakan Kuota Konsultasi</span>
              </button>
            ) : (
              <Link
                to="/app/billing"
                className="btn-primary text-xs py-2 px-4 flex items-center gap-2 font-bold shadow-glow bg-gradient-to-r from-amber-500 to-rose-600 border-amber-400/40 cursor-pointer"
              >
                <span>Upgrade ke Enterprise</span>
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
              Pakar Keselamatan Siber Bertauliah
            </h2>
            <p className="text-xs text-slate-400">Pilih perunding bertauliah untuk mengendalikan sesi anda</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {EXPERTS.map((exp) => (
            <div
              key={exp.id}
              className="card p-5 space-y-4 border border-white/10 hover:border-cyan-400/40 transition-all duration-300 flex flex-col justify-between group bg-slate-900/60"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className={`w-12 h-12 rounded-2xl bg-gradient-to-tr ${exp.avatarBg} p-0.5 shadow-lg flex items-center justify-center text-white font-extrabold text-lg`}>
                    {exp.name.split(' ').map(n => n[0]).join('')}
                  </div>
                  <div className="flex items-center gap-1 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded-full text-[11px] font-bold text-amber-300">
                    <Star size={12} className="fill-amber-400 text-amber-400" />
                    <span>{exp.rating}</span>
                    <span className="text-slate-500 text-[10px]">({exp.reviewsCount})</span>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                    {exp.name}
                  </h3>
                  <p className="text-[11px] font-semibold text-cyan-400">{exp.role}</p>
                  <p className="text-[10px] text-slate-400 mt-0.5">{exp.exp}</p>
                </div>

                <div className="flex flex-wrap gap-1">
                  {exp.certs.map((c) => (
                    <span
                      key={c}
                      className="text-[9px] font-extrabold px-1.5 py-0.5 rounded bg-black/40 text-slate-300 border border-white/10"
                    >
                      {c}
                    </span>
                  ))}
                </div>

                <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed">
                  {exp.bio}
                </p>

                <div className="space-y-1 pt-1 border-t border-white/5">
                  <span className="text-[10px] uppercase font-bold text-slate-500">Kepakaran Utama:</span>
                  <ul className="text-[11px] text-slate-300 space-y-0.5">
                    {exp.specialties.slice(0, 2).map((s, idx) => (
                      <li key={idx} className="flex items-center gap-1.5 truncate">
                        <CheckCircle2 size={11} className="text-emerald-400 shrink-0" />
                        <span className="truncate">{s}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <button
                type="button"
                onClick={() => openBookingModal(PACKAGES[0].title, exp.name)}
                className="btn-secondary w-full text-xs py-2 mt-2 flex items-center justify-center gap-1.5 font-bold border-cyan-500/30 hover:border-cyan-400 text-cyan-300 cursor-pointer"
              >
                <Calendar size={13} />
                <span>Pilih & Tempah</span>
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
            Pakej & Perkhidmatan Konsultasi
          </h2>
          <p className="text-xs text-slate-400">Pilih skop bantuan mengikut keperluan teknikal atau pematuhan organisasi anda</p>
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
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Perkara Yang Disertakan:</span>
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
                  {pkg.includedInEnterprise ? '✨ Termasuk dlm Pelan Enterprise' : '💡 Sebut Harga Mengikut Skop'}
                </span>
                <button
                  type="button"
                  onClick={() => openBookingModal(pkg.title)}
                  className="btn-primary text-xs py-2 px-3.5 flex items-center gap-1.5 shadow-glow cursor-pointer"
                >
                  <Calendar size={13} />
                  <span>Mohon Pakej Ini</span>
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
              {isAdmin ? 'Semua Permohonan Konsultasi Klien' : 'Rekod & Status Tempahan Konsultasi Anda'}
            </h2>
            <p className="text-xs text-slate-400">
              {isAdmin ? 'Urus dan sahkan jadual sesi konsultasi bersama klien' : 'Pantau status pengesahan dan pautan mesyuarat sesi anda'}
            </p>
          </div>
        </div>

        {consultations.length === 0 ? (
          <div className="card p-10 text-center space-y-3 bg-slate-900/40">
            <UserCheck className="mx-auto text-slate-600" size={36} />
            <p className="text-xs text-slate-400">
              Tiada rekod permohonan konsultasi aktif setakat ini.
            </p>
            <button
              onClick={() => openBookingModal()}
              className="btn-ghost text-xs border border-cyan-500/30 text-cyan-300 cursor-pointer"
            >
              Tempah Sesi Pertama Sekarang
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
                        Pakar: <strong className="text-slate-200">{c.consultant_name}</strong> | Platform: <strong className="text-slate-200">{c.channel}</strong> | Klien: <span className="font-mono text-cyan-300">{c.username || c.email}</span>
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
                          <span>Sertai Mesyuarat</span>
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
                      <span className="text-slate-500 text-[11px] block">Tarikh & Masa Dimohon:</span>
                      <span className="font-semibold">{c.preferred_date || 'Fleksibel'} {c.preferred_time ? `(${c.preferred_time})` : ''}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[11px] block">Scan Terpaut:</span>
                      <span className="font-mono text-cyan-400">{c.scan_id ? c.scan_id.slice(0, 16) : '—'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[11px] block">Dihantar Pada:</span>
                      <span>{new Date(c.created_at).toLocaleString()}</span>
                    </div>
                  </div>

                  {c.notes && (
                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 text-xs text-slate-300">
                      <strong className="text-slate-400 text-[11px]">Nota / Pertanyaan:</strong> {c.notes}
                    </div>
                  )}

                  {/* Admin inline edit modal/drawer */}
                  {isAdmin && editingId === c.id && (
                    <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/40 space-y-3 mt-2">
                      <div className="text-xs font-bold text-cyan-300">Kemaskini Sesi #{c.id.slice(0, 8)}:</div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="text-[11px] font-bold text-slate-400 block mb-1">Status Sesi</label>
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
                          <label className="text-[11px] font-bold text-slate-400 block mb-1">Pautan Mesyuarat (Google Meet / Zoom)</label>
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
                          Batal
                        </button>
                        <button
                          type="button"
                          disabled={updatingStatus}
                          onClick={() => handleAdminUpdate(c.id)}
                          className="btn-primary text-xs py-1 px-3 cursor-pointer"
                        >
                          {updatingStatus ? <Loader2 size={12} className="animate-spin" /> : 'Simpan Perubahan'}
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
                  <h3 className="text-base font-bold text-white">Tempah Sesi Bimbingan Pakar</h3>
                  <p className="text-[11px] text-slate-400">1-on-1 Guided Security Consultation</p>
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
                <label className="text-xs font-bold text-slate-300 block mb-1">Pakej / Jenis Servis</label>
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
                <label className="text-xs font-bold text-slate-300 block mb-1">Pilihan Pakar Perunding</label>
                <select
                  value={selectedExpert}
                  onChange={(e) => setSelectedExpert(e.target.value)}
                  className="input text-xs w-full"
                >
                  <option value="Any Available Specialist">Mana-mana Pakar Sesuai (Auto-Match)</option>
                  {EXPERTS.map((exp) => (
                    <option key={exp.id} value={exp.name}>
                      {exp.name} — {exp.role} ({exp.certs.join(', ')})
                    </option>
                  ))}
                </select>
              </div>

              {/* Link to Recent Scan */}
              <div>
                <label className="text-xs font-bold text-slate-300 block mb-1">Pautkan Bersama Imbasan (Pilihan)</label>
                <select
                  value={selectedScanId}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="input text-xs w-full"
                >
                  <option value="">-- Tiada Scan Terpaut / Konsultasi Umum --</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} (Risk: {(s.risk_score || 0).toFixed(1)} | {new Date(s.created_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
                <p className="text-[10px] text-slate-500 mt-1">Pakar kami akan meneliti dapatan imbasan ini terlebih dahulu sebelum sesi bermula.</p>
              </div>

              {/* Date, Time & Platform */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-300 block mb-1">Tarikh Cadangan</label>
                  <input
                    type="date"
                    value={preferredDate}
                    onChange={(e) => setPreferredDate(e.target.value)}
                    className="input text-xs w-full"
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-300 block mb-1">Masa Cadangan</label>
                  <input
                    type="time"
                    value={preferredTime}
                    onChange={(e) => setPreferredTime(e.target.value)}
                    className="input text-xs w-full"
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-300 block mb-1">Platform Mesyuarat</label>
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
                <label className="text-xs font-bold text-slate-300 block mb-1">Skop Masalah / Soalan Khusus</label>
                <textarea
                  rows={3}
                  placeholder="Contoh: Kami perlukan bantuan untuk membaiki kerentanan SQL Injection & CORS pada endpoint /api/auth..."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="input text-xs w-full"
                />
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-white/10">
                <div className="text-[11px] text-slate-400">
                  {isEnterprise ? (
                    <span className="text-emerald-400 font-bold">✨ Termasuk dlm kuota Enterprise</span>
                  ) : (
                    <span className="text-slate-400">Sesi disahkan dalam 24 jam</span>
                  )}
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    className="btn-ghost text-xs cursor-pointer"
                  >
                    Batal
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="btn-primary text-xs shadow-glow flex items-center gap-2 cursor-pointer"
                  >
                    {submitting ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
                    <span>Hantar Permohonan Sesi</span>
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
