import React, { useEffect, useState } from 'react'
import { X, Loader2, ShieldAlert, BookOpen, StickyNote, Send, ExternalLink, Trash2, Bot, Sparkles, AlertTriangle, Target, Wrench, Crosshair, Bug, Play, Pause, Square, ChevronRight, CheckCircle, XCircle, Clock } from 'lucide-react'
import { api } from '../lib/api.js'
import { useAi } from '../lib/AiContext.jsx'
import SeverityBadge from './SeverityBadge.jsx'

function safeParse(j, fallback) {
  if (!j) return fallback
  if (typeof j === 'object') return j
  try { return JSON.parse(j) } catch { return fallback }
}

// ── Plain-English summary generator ─────────────────────────────────────────
// Turns technical finding fields into a simple "what / why dangerous / what to do"
// explanation that non-security people can understand. No AI call needed.
const VULN_EXPLAIN = [
  { match: /(git|svn)[/\s]?(config|entries|exposure|repository)/i, what: 'Folder kawalan versi (git/svn) tersedar kepada umum.', why: 'Attacker boleh download keseluruhan source code termasuk password, API keys, dan sejarah perubahan — ibarat bagi kunci rumah beserta pelan lantai.', fix: 'Sekat akses ke /.git dan /.svn di web server. Keluarkan folder ini dari root web.' },
  { match: /(backup|dump|\.sql|\.bak|database)/i, what: 'Fail backup atau dump database boleh diakses dari internet.', why: 'Semua data (pengguna, kata laluan, rekod perniagaan) boleh dimuat turun terus. Ini punca utama kebocoran data besar.', fix: 'Alihkan fail backup keluar dari root web. Sekat akses, atau padamkan.' },
  { match: /(heartbleed|CVE-2014-0160)/i, what: 'Server SSL/TLS ada kelemahan Heartbleed.', why: 'Attacker boleh curi ingatan server — termasuk kunci peribadi SSL, kata laluan pengguna, dan token sesi — tanpa tinggal jejak.', fix: 'Kemas kini OpenSSL ke versi patch. Batalkan & jana semula sijil SSL.' },
  { match: /(eternalblue|ms17-010|CVE-2017-0144)/i, what: 'Perkhidmatan Windows SMB terdedah kepada exploit EternalBlue.', why: 'Ini exploit yang sama digunakan oleh ransomware WannaCry — attacker boleh ambil alih server sepenuhnya dari jauh.', fix: 'Pasang patch Microsoft MS17-010 segera. Sekat port 445 di firewall.' },
  { match: /(anonymous\s+ftp|ftp-anon)/i, what: 'Pelayan FTP benarkan log masuk tanpa kata laluan (anonymous).', why: 'Sesiapa sahaja boleh muat turun atau muat naik fail ke server anda.', fix: 'Matikan log masuk anonymous dalam konfigurasi FTP.' },
  { match: /(shellshock|CVE-2014-6271)/i, what: 'Server web terdedah kepada Shellshock (Bash bug).', why: 'Attacker boleh jalankan sebarang arahan di server melalui header HTTP — ambil alih penuh mesin.', fix: 'Kemas kini Bash. Sekat atau tapis CGI scripts.' },
  { match: /(sql\s*injection|sqli|CWE-89)/i, what: 'Aplikasi terima input pengguna terus ke dalam arahan SQL (SQL Injection).', why: 'Attacker boleh baca, ubah, atau padam keseluruhan database — termasuk senarai pengguna dan kata laluan.', fix: 'Guna prepared statements / parameterized queries. Jangan gabungkan input pengguna terus ke SQL.' },
  { match: /(xss|cross[- ]site\s*scripting|CWE-79)/i, what: 'Aplikasi paparkan input pengguna tanpa tapisan (Cross-Site Scripting).', why: 'Attacker boleh tanam script jahat yang mencuri sesi/kuki pengguna lain — boleh ambil alih akaun tanpa tahu kata laluan.', fix: 'Encode semua output HTML. Guna Content Security Policy (CSP).' },
  { match: /(command\s*injection|CWE-78|remote\s*code)/i, what: 'Aplikasi benarkan input pengguna dijalankan sebagai arahan sistem.', why: 'Attacker boleh kawal penuh server — paling bahaya dari semua jenis kerentanan.', fix: 'Jangan hantar input pengguna ke shell. Guna whitelist input yang ketat.' },
  { match: /(directory\s*traversal|path\s*traversal|CWE-22)/i, what: 'Aplikasi benarkan akses fail di luar folder yang dibenarkan (Path Traversal).', why: 'Attacker boleh baca fail sensitif server seperti /etc/passwd atau fail konfigurasi.', fix: 'Sahkan dan hadkan input path. Guna whitelist nama fail.' },
  { match: /(ssrf|server[- ]side\s*request|CWE-918)/i, what: 'Server boleh dipaksa membuat request ke destinasi dalaman (SSRF).', why: 'Attacker boleh akses perkhidmatan dalaman (database, metadata cloud) yang sepatutnya tersembunyi dari internet.', fix: 'Sahkan dan whitelist semua URL yang server akan panggil.' },
  { match: /(deserialization|CWE-502|unserialize|pickle|yaml\.load)/i, what: 'Aplikasi deserialize data tak dipercayai (Insecure Deserialization).', why: 'Attacker boleh laksanakan kod hasad semasa proses deserialize — ambil alih server.', fix: 'Jangan deserialize data dari pengguna. Guna format selamat seperti JSON.' },
  { match: /(hardcoded|secret|api[\s_-]?key|password|credential|CWE-798)/i, what: 'Kata laluan atau kunci API ditulis terus dalam kod (hardcoded secret).', why: 'Sesiapa yang nampak kod boleh guna kunci ini untuk akses servis/database anda.', fix: 'Pindahkan secrets ke environment variables atau vault. Batalkan kunci yang bocor.' },
  { match: /(weak\s*(crypto|hash|cipher)|md5|sha1|CWE-327|CWE-338)/i, what: 'Aplikasi guna algoritma kripto yang lemah/lapuk.', why: 'Kata laluan atau data yang di-hash boleh dipecahkan dengan mudah menggunakan rainbow tables.', fix: 'Guna algoritma moden: bcrypt/Argon2 untuk kata laluan, SHA-256+ untuk hashing.' },
  { match: /(jwt|token|CWE-347)/i, what: 'Token sesi (JWT) tidak disahkan dengan betul.', why: 'Attacker boleh palsukan token untuk jadi mana-mana pengguna termasuk admin.', fix: 'Sahkan signature JWT di server. Jangan terima algoritma "none".' },
  { match: /(cors|cross[- ]origin|CWE-942)/i, what: 'Polisi CORS terlalu longgar (benarkan mana-mana origin).', why: 'Laman web jahat boleh baca data pengguna dari aplikasi ini melalui browser mangsa.', fix: 'Hadkan CORS kepada domain yang dipercayai sahaja.' },
  { match: /(phpinfo|server-status|debug|actuator|info\s*leak|disclosure)/i, what: 'Server dedahkan maklumat dalaman (konfigurasi, versi, env).', why: 'Attacker dapat peta lengkap sistem — versi software, path, env variables — untuk rancang serangan yang lebih tepat.', fix: 'Matikan halaman debug/info di production.' },
  { match: /(directory\s*listing|open\s*directory)/i, what: 'Server paparkan senarai fail dalam folder (directory listing).', why: 'Attacker nampak semua fail — senang cari backup, config, atau data sensitif.', fix: 'Matikan autoindex/Options Indexes di web server.' },
  { match: /(login|admin|portal|dashboard|panel)\s*(page|surface|endpoint)?/i, what: 'Halaman log masuk/panel admin dijumpai dan boleh diakses.', why: 'Ini sasaran utama untuk brute-force kata laluan. Kalau guna password lemah, attacker masuk terus.', fix: 'Hadkan akses panel admin (VPN/IP whitelist). Kuatkuasakan 2FA dan lockout.' },
  { match: /(clickjacking|frame)/i, what: 'Halaman boleh dimuatkan dalam iframe laman lain (Clickjacking).', why: 'Attacker boleh tipu pengguna klik butang tanpa sedar — contoh: tukar kata laluan atau buat pembayaran.', fix: 'Tambah header X-Frame-Options: DENY atau CSP frame-ancestors.' },
  { match: /(waf|firewall)\s*(not|missing|detected)/i, what: 'Tiada Web Application Firewall (WAF) dikesan di hadapan aplikasi.', why: 'Serangan biasa (SQLi, XSS) sampai terus ke aplikasi tanpa tapisan pertama.', fix: 'Pertimbangkan WAF seperti Cloudflare, ModSecurity, atau AWS WAF.' },
]

function buildSummary(f, evidence) {
  const text = [f.title, f.description, f.module, f.cwe_id].filter(Boolean).join(' ')
  for (const rule of VULN_EXPLAIN) {
    if (rule.match.test(text)) return rule
  }
  // Generic fallback using severity
  const sev = (f.severity || 'info').toLowerCase()
  const sevWord = { critical: 'SANGAT KRITIKAL', high: 'berbahaya', medium: 'sederhana', low: 'rendah', info: 'maklumat sahaja' }[sev] || 'perlu perhatian'
  return {
    what: `${f.title || 'Isu keselamatan'} ditemui pada ${f.target || 'sasaran'}.`,
    why: `Isu ini diklasifikasikan sebagai ${sevWord}. ${f.description || 'Semak bukti (evidence) untuk butiran teknikal.'}`,
    fix: f.remediation || 'Rujuk bahagian Remediation di bawah untuk langkah pembaikan.',
  }
}

export default function FindingDetailDrawer({ finding, onClose, onStatusChange, onDelete, onSeverityChange }) {
  const { getFindingChat, sendFindingAiQuery, activeTasks, activeTabOverride, setActiveTabOverride } = useAi()
  const [tab, setTab] = useState('overview')
  const [notes, setNotes] = useState([])
  const [noteText, setNoteText] = useState('')
  const [cve, setCve] = useState(null)
  const [cveBusy, setCveBusy] = useState(false)
  const [status, setStatus] = useState(finding?.status || 'open')

  // Local input state
  const [chatInput, setChatInput] = useState('')

  // ── Exploit State ──
  const [exploitCheck, setExploitCheck] = useState(null)     // result of /api/exploits/check
  const [exploitChecking, setExploitChecking] = useState(false)
  const [exploitCampaign, setExploitCampaign] = useState(null) // active campaign for this finding
  const [exploitLaunching, setExploitLaunching] = useState(false)
  const [exploitError, setExploitError] = useState('')

  useEffect(() => {
    if (!finding) return
    setStatus(finding.status || 'open')
    if (activeTabOverride) {
      setTab(activeTabOverride)
      setActiveTabOverride(null)
    } else {
      setTab('overview')
    }
    setCve(null)
    setExploitCheck(null)
    setExploitCampaign(null)
    setExploitError('')
    api.findingNotes(finding.id).then(setNotes).catch(() => setNotes([]))

    // Auto-check exploitability
    checkExploitability()
  }, [finding, activeTabOverride])

  if (!finding) return null

  const chatMessages = getFindingChat(finding)
  const chatBusy = activeTasks[finding?.id]?.busy

  const evidence = safeParse(finding.evidence, {})
  const poc = safeParse(finding.poc, {})
  const verdict = safeParse(finding.agent_verdict, null)
  const cveId = finding.cve_id || (finding.title.match(/CVE-\d{4}-\d{4,}/i)?.[0])

  async function loadCve() {
    if (!cveId) return
    setCveBusy(true)
    try { setCve(await api.cve(cveId)) } catch (e) { setCve({ error: e.message }) }
    setCveBusy(false)
  }

  async function saveStatus(s) {
    setStatus(s)
    try { await api.setFindingStatus(finding.id, s); onStatusChange?.(finding.id, s) } catch { /* noop */ }
  }

  async function addNote(e) {
    e.preventDefault()
    if (!noteText.trim()) return
    const n = await api.addFindingNote(finding.id, noteText.trim())
    setNotes((p) => [...p, n])
    setNoteText('')
  }

  function handleSendAi(customMsg) {
    const query = customMsg || chatInput
    if (!query.trim() || chatBusy) return
    sendFindingAiQuery(finding, query.trim())
    if (!customMsg) setChatInput('')
  }

  // ── Exploit Functions ──
  async function checkExploitability() {
    if (!finding?.id) return
    setExploitChecking(true)
    setExploitError('')
    try {
      const result = await api.checkExploit(finding.id)
      setExploitCheck(result)
      // If a campaign already exists, fetch it
      if (result.alreadyExists) {
        setExploitCampaign(result)
        // Switch to exploit tab
      }
    } catch (e) {
      setExploitError(e.message)
    } finally {
      setExploitChecking(false)
    }
  }

  async function launchExploit() {
    if (!finding?.id) return
    setExploitLaunching(true)
    setExploitError('')
    try {
      const result = await api.launchExploitCampaign(finding.id)
      setExploitCampaign(result)
      setExploitCheck(prev => prev ? { ...prev, ...result } : result)
      setTab('exploit')
    } catch (e) {
      setExploitError(e.message)
    } finally {
      setExploitLaunching(false)
    }
  }

  async function approveExploitStep(stepId) {
    if (!exploitCampaign?.campaign?.id) return
    setExploitError('')
    try {
      await api.approveExploitStep(exploitCampaign.campaign.id, stepId)
      // Refresh campaign data
      const updated = await api.exploitCampaign(exploitCampaign.campaign.id)
      setExploitCampaign(updated)
    } catch (e) {
      setExploitError(e.message)
    }
  }

  async function denyExploitStep(stepId) {
    if (!exploitCampaign?.campaign?.id) return
    setExploitError('')
    try {
      await api.denyExploitStep(exploitCampaign.campaign.id, stepId)
      const updated = await api.exploitCampaign(exploitCampaign.campaign.id)
      setExploitCampaign(updated)
    } catch (e) {
      setExploitError(e.message)
    }
  }

  // ── Campaign Control Functions ──
  async function startCampaign(campaignId) {
    setExploitError('')
    try {
      await api.resumeExploitCampaign(campaignId)
      const updated = await api.exploitCampaign(campaignId)
      setExploitCampaign(updated)
    } catch (e) {
      setExploitError(e.message)
    }
  }

  async function pauseCampaign(campaignId) {
    setExploitError('')
    try {
      await api.pauseExploitCampaign(campaignId)
      const updated = await api.exploitCampaign(campaignId)
      setExploitCampaign(updated)
    } catch (e) {
      setExploitError(e.message)
    }
  }

  async function resumeCampaign(campaignId) {
    setExploitError('')
    try {
      await api.resumeExploitCampaign(campaignId)
      const updated = await api.exploitCampaign(campaignId)
      setExploitCampaign(updated)
    } catch (e) {
      setExploitError(e.message)
    }
  }

  async function abortCampaign(campaignId) {
    setExploitError('')
    try {
      await api.abortExploitCampaign(campaignId)
      const updated = await api.exploitCampaign(campaignId)
      setExploitCampaign(updated)
    } catch (e) {
      setExploitError(e.message)
    }
  }

  // Auto-refresh campaign when it's running or awaiting approval
  useEffect(() => {
    if (!exploitCampaign?.campaign?.id) return
    const status = exploitCampaign.campaign.status
    if (['running', 'awaiting_approval', 'paused'].includes(status)) {
      const interval = setInterval(async () => {
        try {
          const updated = await api.exploitCampaign(exploitCampaign.campaign.id)
          setExploitCampaign(updated)
        } catch { /* ignore */ }
      }, 3000)
      return () => clearInterval(interval)
    }
  }, [exploitCampaign?.campaign?.id, exploitCampaign?.campaign?.status])

  const TABS = [
    { id: 'overview', label: 'Overview', icon: ShieldAlert },
    { id: 'exploit', label: 'Exploit', icon: Crosshair },
    { id: 'ai', label: 'AI Assistant', icon: Bot },
    { id: 'poc', label: 'PoC / Evidence', icon: BookOpen },
    { id: 'cve', label: 'CVE', icon: ExternalLink },
    { id: 'notes', label: `Notes (${notes.length})`, icon: StickyNote },
  ]

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-end p-0 sm:p-4 glass-overlay" onClick={onClose}>
      <div className="w-full max-w-xl max-h-[92vh] flex flex-col glass sm:rounded-3xl border border-white/15 shadow-2xl overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="sticky top-0 z-10 glass-deep border-b border-white/10 p-5 shrink-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="text-lg font-bold text-slate-100 leading-snug">{finding.title}</h2>
              <p className="text-xs text-slate-500 mt-1">{finding.target || finding.module}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <SeverityBadge severity={finding.severity} onChange={onSeverityChange} />
              <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={20} /></button>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <label className="text-[11px] uppercase tracking-wider text-slate-500">Status</label>
            <select value={status} onChange={(e) => saveStatus(e.target.value)} className="input py-1 px-2 text-xs w-auto">
              {['open', 'confirmed', 'in-progress', 'fixed', 'accepted', 'false-positive'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="mt-4 flex gap-1 border-b border-ink-700 -mb-5">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button key={id} onClick={() => setTab(id)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors ${tab === id ? 'border-accent text-accent' : 'border-transparent text-slate-500 hover:text-slate-300'}`}>
                <Icon size={13} /> {label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto flex-1">
          {tab === 'overview' && (
            <>
              <div className="flex flex-wrap gap-2 text-[11px]">
                {finding.owasp_category && <span className="chip bg-accent/10 text-accent border border-accent/30">{finding.owasp_category}</span>}
                {finding.cwe_id && <span className="chip bg-ink-700 text-slate-300 border border-ink-600">{finding.cwe_id}</span>}
                {cveId && <span className="chip bg-sev-high/10 text-sev-high border border-sev-high/30">{cveId}</span>}
                {finding.cvss != null && <span className="chip bg-ink-700 text-slate-300 border border-ink-600">CVSS {finding.cvss}</span>}
              </div>
              {/* Plain-English summary — auto-generated from finding data */}
              {(() => {
                const s = buildSummary(finding, evidence)
                return (
                  <div className="rounded-xl border border-accent/25 bg-accent/[0.06] p-4 space-y-3">
                    <p className="text-[11px] uppercase tracking-wider text-accent font-semibold flex items-center gap-1.5">
                      <Sparkles size={12} /> Ringkasan Mudah Faham
                    </p>
                    <div className="flex gap-2.5">
                      <Target size={15} className="text-sky-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[11px] font-semibold text-sky-300 uppercase tracking-wide">Apa masalahnya?</p>
                        <p className="text-sm text-slate-200 leading-relaxed">{s.what}</p>
                      </div>
                    </div>
                    <div className="flex gap-2.5">
                      <AlertTriangle size={15} className="text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[11px] font-semibold text-amber-300 uppercase tracking-wide">Kenapa bahaya?</p>
                        <p className="text-sm text-slate-200 leading-relaxed">{s.why}</p>
                      </div>
                    </div>
                    <div className="flex gap-2.5">
                      <Wrench size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[11px] font-semibold text-emerald-300 uppercase tracking-wide">Apa nak buat?</p>
                        <p className="text-sm text-slate-200 leading-relaxed">{s.fix}</p>
                      </div>
                    </div>
                  </div>
                )
              })()}
              {finding.description && (
                <div><p className="label">Technical Description</p><p className="text-sm text-slate-300 whitespace-pre-wrap">{finding.description}</p></div>
              )}
              {verdict && (
                <div className="rounded-lg bg-accent/5 border border-accent/20 p-3">
                  <p className="text-[11px] uppercase tracking-wider text-accent/80 mb-1">Agent Verdict · {verdict.agent} · {Math.round((verdict.confidence || 0) * 100)}%</p>
                  <p className="text-xs text-slate-300 whitespace-pre-wrap">{verdict.reasoning}</p>
                </div>
              )}
              {finding.remediation && (
                <div className="rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-3">
                  <p className="text-[11px] uppercase tracking-wider text-emerald-400/80 mb-1">Remediation</p>
                  <p className="text-sm text-emerald-100/90 whitespace-pre-wrap">{finding.remediation}</p>
                </div>
              )}
            </>
          )}

          {tab === 'exploit' && (
            <div className="space-y-4">
              {/* Exploit Check Status */}
              {exploitChecking && (
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Loader2 size={14} className="animate-spin" /> Checking exploitability...
                </div>
              )}

              {!exploitChecking && exploitCheck && !exploitCampaign && (
                <div className="space-y-4">
                  <div className={`rounded-xl border p-4 ${exploitCheck.exploitable ? 'border-red-500/30 bg-red-500/5' : 'border-slate-700/50 bg-slate-800/30'}`}>
                    <div className="flex items-center gap-2 mb-2">
                      <Crosshair size={16} className={exploitCheck.exploitable ? 'text-red-400' : 'text-slate-500'} />
                      <span className={`text-sm font-semibold ${exploitCheck.exploitable ? 'text-red-300' : 'text-slate-400'}`}>
                        {exploitCheck.exploitable ? `${exploitCheck.matchCount} exploit strategy available` : 'No exploit strategy available'}
                      </span>
                      <span className={`text-[11px] px-2 py-0.5 rounded-full font-medium ${exploitCheck.risk === 'critical' ? 'bg-red-500/20 text-red-400' : exploitCheck.risk === 'high' ? 'bg-orange-500/20 text-orange-400' : exploitCheck.risk === 'medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'}`}>
                        {exploitCheck.risk?.toUpperCase()}
                      </span>
                    </div>

                    {exploitCheck.strategies?.map((s, i) => (
                      <div key={i} className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                        <ChevronRight size={12} />
                        <span className="font-mono">{s.id}</span>
                        <span className="text-slate-600">|</span>
                        <span>{s.techniqueCount} techniques</span>
                        <span className="text-slate-600">|</span>
                        <span>Post: {s.postExploit?.join(', ')}</span>
                      </div>
                    ))}

                    {exploitCheck.exploitable && (
                      <button
                        onClick={launchExploit}
                        disabled={exploitLaunching}
                        className="btn-primary w-full mt-4 text-sm flex items-center justify-center gap-2"
                      >
                        {exploitLaunching ? (
                          <><Loader2 size={14} className="animate-spin" /> Launching...</>
                        ) : (
                          <><Play size={14} /> Launch Exploit Campaign</>
                        )}
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* Active Campaign View */}
              {exploitCampaign && (
                <div className="space-y-4">
                  {/* Campaign Header with Controls */}
                  <div className={`rounded-xl border p-4 ${exploitCampaign.campaign?.status === 'completed' ? 'border-green-500/30 bg-green-500/5' : exploitCampaign.campaign?.status === 'failed' ? 'border-red-500/30 bg-red-500/5' : exploitCampaign.campaign?.status === 'awaiting_approval' ? 'border-amber-500/30 bg-amber-500/5' : 'border-accent/30 bg-accent/5'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Crosshair size={16} className="text-accent" />
                        <span className="text-sm font-semibold text-slate-200">Campaign</span>
                        <span className={`text-[11px] px-2 py-0.5 rounded-full font-medium ${
                          exploitCampaign.campaign?.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                          exploitCampaign.campaign?.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                          exploitCampaign.campaign?.status === 'awaiting_approval' ? 'bg-amber-500/20 text-amber-400' :
                          exploitCampaign.campaign?.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                          'bg-slate-500/20 text-slate-400'
                        }`}>
                          {exploitCampaign.campaign?.status || 'unknown'}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {exploitCampaign.campaign?.id && (
                          <span className="text-[10px] font-mono text-slate-600 truncate ml-2 max-w-[120px]">{exploitCampaign.campaign.id}</span>
                        )}
                        {/* Campaign Controls */}
                        {exploitCampaign.campaign?.status === 'queued' && (
                          <button
                            onClick={() => startCampaign(exploitCampaign.campaign.id)}
                            className="btn-primary text-xs flex items-center gap-1"
                          >
                            <Play size={12} /> Start
                          </button>
                        )}
                        {exploitCampaign.campaign?.status === 'running' && (
                          <button
                            onClick={() => pauseCampaign(exploitCampaign.campaign.id)}
                            className="btn-secondary text-xs flex items-center gap-1"
                          >
                            <Pause size={12} /> Pause
                          </button>
                        )}
                        {exploitCampaign.campaign?.status === 'paused' && (
                          <button
                            onClick={() => resumeCampaign(exploitCampaign.campaign.id)}
                            className="btn-primary text-xs flex items-center gap-1"
                          >
                            <Play size={12} /> Resume
                          </button>
                        )}
                        {['running', 'paused', 'awaiting_approval'].includes(exploitCampaign.campaign?.status) && (
                          <button
                            onClick={() => abortCampaign(exploitCampaign.campaign.id)}
                            className="btn-secondary text-xs !border-red-500/30 !text-red-400 hover:!bg-red-500/10 flex items-center gap-1"
                          >
                            <Square size={12} /> Abort
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Step Timeline */}
                  {exploitCampaign.steps?.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Attack Steps</p>
                      {exploitCampaign.steps.map((step) => (
                        <div key={step.id} className={`rounded-lg border p-3 ${
                          step.status === 'success' ? 'border-green-500/20 bg-green-500/5' :
                          step.status === 'failed' ? 'border-red-500/20 bg-red-500/5' :
                          step.status === 'awaiting_approval' ? 'border-amber-500/30 bg-amber-500/5' :
                          step.status === 'running' ? 'border-blue-500/20 bg-blue-500/5' :
                          'border-slate-700/50 bg-slate-800/20'
                        }`}>
                          <div className="flex items-center gap-2">
                            {step.status === 'success' ? <CheckCircle size={14} className="text-green-400" /> :
                             step.status === 'failed' ? <XCircle size={14} className="text-red-400" /> :
                             step.status === 'awaiting_approval' ? <AlertTriangle size={14} className="text-amber-400" /> :
                             step.status === 'running' ? <Loader2 size={14} className="text-blue-400 animate-spin" /> :
                             <Clock size={14} className="text-slate-500" />}
                            <span className="text-xs font-medium text-slate-300">
                              Step {step.step_order}: {step.step_type}
                            </span>
                            <span className="text-[11px] text-slate-500">({step.tool_name})</span>
                          </div>

                          {step.command && (
                            <pre className="mt-2 text-[11px] text-slate-400 font-mono bg-black/30 rounded p-2 overflow-auto max-h-20">
                              {step.command}
                            </pre>
                          )}

                          {step.output && (
                            <pre className="mt-2 text-[11px] text-slate-400 font-mono bg-black/30 rounded p-2 overflow-auto max-h-32">
                              {(() => { try { return JSON.stringify(JSON.parse(step.output), null, 2) } catch { return step.output } })()}
                            </pre>
                          )}

                          {/* Approval buttons */}
                          {step.status === 'awaiting_approval' && (
                            <div className="flex gap-2 mt-3">
                              <button
                                onClick={() => approveExploitStep(step.id)}
                                className="btn-primary text-xs !bg-green-600 hover:!bg-green-500 flex items-center gap-1"
                              >
                                <CheckCircle size={12} /> Approve
                              </button>
                              <button
                                onClick={() => denyExploitStep(step.id)}
                                className="btn-secondary text-xs !border-red-500/30 !text-red-400 hover:!bg-red-500/10 flex items-center gap-1"
                              >
                                <XCircle size={12} /> Deny
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Loot */}
                  {exploitCampaign.loot?.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Loot Collected</p>
                      {exploitCampaign.loot.map((l) => (
                        <div key={l.id} className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3">
                          <div className="flex items-center gap-2">
                            <Bug size={14} className="text-yellow-400" />
                            <span className="text-xs text-slate-300">{l.label || l.loot_type}</span>
                          </div>
                          <pre className="mt-2 text-[11px] text-slate-400 font-mono bg-black/30 rounded p-2 overflow-auto max-h-24">
                            {(() => { try { return JSON.stringify(JSON.parse(l.data), null, 2) } catch { return l.data } })()}
                          </pre>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* No campaign yet */}
                  {exploitCampaign.alreadyExists && !exploitCampaign.steps?.length && !exploitCheck?.exploitable && (
                    <div className="text-center py-4">
                      <p className="text-sm text-slate-500">No exploit steps available for this finding.</p>
                    </div>
                  )}
                </div>
              )}

              {!exploitChecking && !exploitCheck && !exploitCampaign && (
                <div className="text-center py-4">
                  <p className="text-sm text-slate-500">Checking exploitability...</p>
                </div>
              )}

              {exploitError && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3">
                  <p className="text-xs text-red-400">{exploitError}</p>
                </div>
              )}
            </div>
          )}

          {tab === 'ai' && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <button 
                  type="button" 
                  onClick={() => handleSendAi('Apa yang bahaya pasal finding ni?')}
                  className="btn-ghost text-xs border border-accent/30 text-accent hover:bg-accent/10 flex items-center gap-1"
                >
                  <Sparkles size={12} /> Apa yang bahaya ni?
                </button>
                <button 
                  type="button" 
                  onClick={() => handleSendAi('Macam mana nak fix / remediate kerentanan ni?')}
                  className="btn-ghost text-xs border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 flex items-center gap-1"
                >
                  <Sparkles size={12} /> How to fix this?
                </button>
              </div>

              <div className="rounded-xl bg-ink-900/80 border border-ink-700/80 p-4 space-y-3 max-h-80 overflow-y-auto">
                {chatMessages.map((m, i) => (
                  <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-[85%] rounded-lg p-3 text-xs leading-relaxed ${m.role === 'user' ? 'bg-accent text-white' : 'bg-ink-800 text-slate-200 border border-ink-700'}`}>
                      <p className="whitespace-pre-wrap">{m.text}</p>
                    </div>
                  </div>
                ))}
                {chatBusy && (
                  <div className="flex justify-start">
                    <div className="bg-ink-800 rounded-lg p-3 text-xs text-slate-400 flex items-center gap-2">
                      <Loader2 size={14} className="animate-spin text-accent" /> AI thinking in background...
                    </div>
                  </div>
                )}
              </div>

              <div className="flex gap-2 items-end">
                <textarea 
                  className="input flex-1 text-xs resize-none min-h-[42px] max-h-32 py-2" 
                  rows={2}
                  placeholder="Ask AI about this finding… (Enter = newline, Click Send to submit)" 
                  value={chatInput} 
                  onChange={(e) => setChatInput(e.target.value)} 
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey) {
                      // Pressing Enter alone creates a newline (moves down) and does NOT submit!
                      e.stopPropagation()
                    } else if (e.key === 'Enter' && (e.shiftKey || e.ctrlKey)) {
                      // Shift+Enter or Ctrl+Enter submits
                      e.preventDefault()
                      handleSendAi()
                    }
                  }}
                />
                <button 
                  type="button" 
                  onClick={() => handleSendAi()} 
                  disabled={chatBusy} 
                  className="btn-primary px-3.5 py-3.5 h-[42px] flex items-center justify-center shrink-0"
                  title="Send Question"
                >
                  <Send size={14} />
                </button>
              </div>
            </div>
          )}

          {tab === 'poc' && (
            <>
              {Object.keys(evidence).length === 0 && Object.keys(poc).length === 0 && (
                <p className="text-sm text-slate-500">No evidence or PoC captured for this finding.</p>
              )}
              {Object.keys(evidence).length > 0 && (
                <div><p className="label">Evidence</p>
                  <pre className="terminal text-xs whitespace-pre-wrap">{JSON.stringify(evidence, null, 2)}</pre></div>
              )}
              {Object.keys(poc).length > 0 && (
                <div><p className="label">PoC / Payloads</p>
                  <pre className="terminal text-xs whitespace-pre-wrap">{JSON.stringify(poc, null, 2)}</pre></div>
              )}
            </>
          )}

          {tab === 'cve' && (
            <>
              {!cveId ? <p className="text-sm text-slate-500">No CVE associated with this finding.</p> : (
                <>
                  <button onClick={loadCve} disabled={cveBusy} className="btn-ghost">
                    {cveBusy ? <Loader2 size={15} className="animate-spin" /> : <ExternalLink size={15} />} Lookup {cveId} (NVD)
                  </button>
                  {cve && (
                    cve.error ? <p className="text-sm text-sev-critical">{cve.error}</p> : (
                      <div className="space-y-3">
                        <div className="flex items-center gap-3">
                          <h3 className="text-base font-bold text-slate-100">{cve.id}</h3>
                          {cve.cvss?.score != null && <SeverityBadge severity={(cve.severity || '').toLowerCase()} />}
                          {cve.cvss?.score != null && <span className="text-sm text-slate-300">{cve.cvss.score}/10</span>}
                          {cve.cached && <span className="text-[10px] text-slate-600">(cached)</span>}
                        </div>
                        <p className="text-sm text-slate-300 whitespace-pre-wrap">{cve.description}</p>
                        {cve.cvss?.vector && <p className="text-xs font-mono text-slate-500">{cve.cvss.vector}</p>}
                        {cve.weaknesses?.length > 0 && <div className="flex flex-wrap gap-1.5">{cve.weaknesses.map((w) => <span key={w} className="chip bg-ink-700 text-slate-300 border border-ink-600 text-[11px]">{w}</span>)}</div>}
                        {cve.references?.length > 0 && (
                          <div><p className="label">References</p>
                            <ul className="space-y-1">{cve.references.map((r) => <li key={r}><a href={r} target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline break-all">{r}</a></li>)}</ul></div>
                        )}
                      </div>
                    )
                  )}
                </>
              )}
            </>
          )}

          {tab === 'notes' && (
            <>
              <div className="space-y-3">
                {notes.length === 0 && <p className="text-sm text-slate-500">No notes yet.</p>}
                {notes.map((n) => (
                  <div key={n.id} className="rounded-lg bg-ink-800/60 border border-ink-700/60 p-3">
                    <p className="text-[11px] text-slate-500 mb-1">{n.author} · {new Date(n.ts).toLocaleString()}</p>
                    <p className="text-sm text-slate-200 whitespace-pre-wrap">{n.note}</p>
                  </div>
                ))}
              </div>
              <form onSubmit={addNote} className="flex gap-2">
                <input className="input flex-1" placeholder="Add a note…" value={noteText} onChange={(e) => setNoteText(e.target.value)} />
                <button type="submit" className="btn-primary px-3"><Send size={15} /></button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
