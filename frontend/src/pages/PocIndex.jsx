import React, { useEffect, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import {
  Flame, Search, RefreshCw, Loader2, ShieldAlert, Zap, Star, ExternalLink,
  Terminal, Database, Bug, Box, Sparkles, X, ChevronLeft, ChevronRight, AlertTriangle, CheckCircle2
} from 'lucide-react'
import { api } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low']
const SOURCES = [
  { id: 'all', label: 'All Sources' },
  { id: 'github', label: 'GitHub PoCs' },
  { id: 'edb', label: 'Exploit-DB' },
  { id: 'nuclei', label: 'Nuclei' },
  { id: 'msf', label: 'Metasploit' },
  { id: 'vulhub', label: 'Vulhub' },
]
const SORTS = [
  { id: 'relevance', label: 'Relevance / Modified' },
  { id: 'epss', label: 'Highest EPSS %' },
  { id: 'cvss', label: 'Highest CVSS (Upstream)' },
  { id: 'stars', label: 'Most GitHub Stars' },
  { id: 'pocs', label: 'Most PoC Sources' },
  { id: 'newest', label: 'Newest Published' },
]

function sevBadgeClass(sev) {
  const s = String(sev || '').toUpperCase()
  if (s === 'CRITICAL') return 'bg-red-500/20 text-red-300 border-red-500/40'
  if (s === 'HIGH') return 'bg-orange-500/20 text-orange-300 border-orange-500/40'
  if (s === 'MEDIUM') return 'bg-amber-500/20 text-amber-300 border-amber-500/40'
  if (s === 'LOW') return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
  return 'bg-white/10 text-slate-300 border-white/15'
}

function formatPct(score) {
  if (score == null || !Number.isFinite(Number(score))) return null
  const pct = Number(score) * 100
  return pct >= 10 ? `${pct.toFixed(1)}%` : pct >= 1 ? `${pct.toFixed(2)}%` : `${pct.toFixed(3)}%`
}

export default function PocIndex() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [tab, setTab] = useState('search') // search | trending | landed
  const [status, setStatus] = useState(null)
  const [stats, setStats] = useState(null)
  const [trendingData, setTrendingData] = useState(null)

  // Search state
  const [query, setQuery] = useState('')
  const [submittedQuery, setSubmittedQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [source, setSource] = useState('all')
  const [kevOnly, setKevOnly] = useState(false)
  const [hasPocOnly, setHasPocOnly] = useState(false)
  const [sort, setSort] = useState('relevance')
  const [page, setPage] = useState(1)

  const [searchResult, setSearchResult] = useState({ available: true, items: [], total: 0, page: 1, totalPages: 0 })
  const [loading, setLoading] = useState(false)
  const [syncBusy, setSyncBusy] = useState(false)
  const [err, setErr] = useState('')

  // Detail modal state
  const [selectedCveId, setSelectedCveId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)

  const loadMeta = useCallback(async () => {
    try {
      const [st, sData, tr] = await Promise.all([
        api.pocindexStatus().catch(() => null),
        api.pocindexStats().catch(() => null),
        api.pocindexTrending().catch(() => null),
      ])
      if (st) setStatus(st)
      if (sData) setStats(sData)
      if (tr) setTrendingData(tr)
    } catch { /* ignore */ }
  }, [])

  const runSearch = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const res = await api.pocindexSearch({
        q: submittedQuery,
        severity: severity !== 'all' ? severity : undefined,
        source: source !== 'all' ? source : undefined,
        kev: kevOnly || undefined,
        hasPoc: hasPocOnly || undefined,
        sort,
        page,
        limit: 20,
      })
      setSearchResult(res)
    } catch (e) {
      setErr(e.message || 'Search failed')
    } finally {
      setLoading(false)
    }
  }, [submittedQuery, severity, source, kevOnly, hasPocOnly, sort, page])

  useEffect(() => { loadMeta() }, [loadMeta])
  useEffect(() => {
    if (tab === 'search') runSearch()
  }, [tab, runSearch])

  // Poll status while a sync is running
  useEffect(() => {
    if (!status?.syncing) return
    const id = setInterval(() => {
      api.pocindexStatus().then((st) => {
        setStatus(st)
        if (!st.syncing) {
          loadMeta()
          runSearch()
        }
      }).catch(() => {})
    }, 3000)
    return () => clearInterval(id)
  }, [status?.syncing, loadMeta, runSearch])

  async function handleTriggerSync() {
    if (syncBusy || status?.syncing) return
    setSyncBusy(true)
    setErr('')
    try {
      await api.pocindexSync({ force: false, full: true })
      const st = await api.pocindexStatus()
      setStatus(st)
    } catch (e) {
      setErr(e.message || 'Failed to trigger PoC Index sync')
    } finally {
      setSyncBusy(false)
    }
  }

  async function openCveDetail(cveId) {
    if (!cveId) return
    setSelectedCveId(cveId)
    setDetail(null)
    setDetailLoading(true)
    try {
      const res = await api.pocindexCve(cveId).catch(async () => {
        const nvd = await api.cve(cveId)
        return nvd && !nvd.error ? {
          cveId: nvd.id,
          description: nvd.description,
          published: nvd.published,
          modified: nvd.lastModified,
          upstreamCvss: nvd.cvss,
          kev: nvd.pocindex?.kev || null,
          epss: nvd.pocindex?.epss || null,
          nuclei: nvd.pocindex?.nuclei || null,
          pocs: nvd.pocindex?.pocs || { github: [], edb: [], nuclei: [], msf: [], vulhub: [], collections: [] },
          advisories: (nvd.references || []).map(u => ({ url: u, tags: ['Reference'] })),
        } : null
      })
      setDetail(res)
    } catch {
      setDetail(null)
    } finally {
      setDetailLoading(false)
    }
  }

  function handleSearchSubmit(e) {
    e.preventDefault()
    setPage(1)
    setSubmittedQuery(query)
  }

  const upstream = stats?.upstream || {}
  const trendingItems = Array.isArray(trendingData?.items) ? trendingData.items : []
  const landedItems = Array.isArray(trendingData?.landed) ? trendingData.landed : []

  return (
    <div className="space-y-6 motion-fade-up content-fade">
      {/* Hero / Radar Header */}
      <div className="card p-6 bg-gradient-to-br from-slate-900/90 via-[#131722] to-rose-950/20 border-white/15 shadow-2xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-400">
                <Flame size={20} />
              </div>
              <div>
                <h1 className="text-2xl font-extrabold text-white tracking-tight">PoC Index &amp; Threat Intelligence</h1>
                <p className="text-xs text-slate-400">
                  Local FTS5 mirror of 0xMarcio/pocindex — Public PoCs, CISA KEV, FIRST EPSS, Nuclei, Metasploit &amp; Exploit-DB
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${
              status?.syncing
                ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                : status?.dbReady
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                  : 'bg-slate-800 text-slate-300 border-white/10'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                status?.syncing ? 'bg-amber-400 animate-ping' : status?.dbReady ? 'bg-emerald-400' : 'bg-slate-500'
              }`} />
              {status?.syncing ? 'SYNCING FEEDS' : status?.dbReady ? 'INDEX ONLINE' : 'PENDING INITIAL SYNC'}
            </span>

            {isAdmin && (
              <button
                type="button"
                onClick={handleTriggerSync}
                disabled={syncBusy || status?.syncing}
                className="btn-ghost text-xs py-1.5 px-3 border-cyan-400/30 text-cyan-300 hover:bg-cyan-500/10"
              >
                {syncBusy || status?.syncing ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                <span>{status?.syncing ? 'Syncing…' : 'Sync Index'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Telemetry Counters */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-5 pt-4 border-t border-white/10">
          <div className="rounded-xl bg-black/25 border border-white/10 p-3">
            <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">Indexed CVEs w/ PoCs</p>
            <p className="text-lg font-extrabold text-white font-mono mt-0.5">
              {(stats?.indexedCves || upstream?.with_pocs || 0).toLocaleString()}
            </p>
          </div>
          <div className="rounded-xl bg-black/25 border border-white/10 p-3">
            <p className="text-[10px] uppercase tracking-wider text-rose-400 font-bold">CISA KEV Catalog</p>
            <p className="text-lg font-extrabold text-rose-300 font-mono mt-0.5">
              {(stats?.kevCount || upstream?.kev || 0).toLocaleString()}
            </p>
          </div>
          <div className="rounded-xl bg-black/25 border border-white/10 p-3">
            <p className="text-[10px] uppercase tracking-wider text-cyan-400 font-bold">Nuclei Templates</p>
            <p className="text-lg font-extrabold text-cyan-300 font-mono mt-0.5">
              {(stats?.nucleiCount || 0).toLocaleString()}
            </p>
          </div>
          <div className="rounded-xl bg-black/25 border border-white/10 p-3">
            <p className="text-[10px] uppercase tracking-wider text-purple-400 font-bold">Metasploit Modules</p>
            <p className="text-lg font-extrabold text-purple-300 font-mono mt-0.5">
              {(stats?.msfCount || 0).toLocaleString()}
            </p>
          </div>
          <div className="rounded-xl bg-black/25 border border-white/10 p-3">
            <p className="text-[10px] uppercase tracking-wider text-amber-400 font-bold">Exploit-DB Entries</p>
            <p className="text-lg font-extrabold text-amber-300 font-mono mt-0.5">
              {(stats?.edbCount || 0).toLocaleString()}
            </p>
          </div>
          <div className="rounded-xl bg-black/25 border border-white/10 p-3">
            <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">Upstream NVD Total</p>
            <p className="text-lg font-extrabold text-slate-200 font-mono mt-0.5">
              {(upstream?.total_cves || 0).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Mode Switcher Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-2">
          {[
            { id: 'search', label: 'Search Explorer', icon: Search },
            { id: 'trending', label: `Trending PoCs (${trendingItems.length})`, icon: Flame },
            { id: 'landed', label: `Just Landed (${landedItems.length})`, icon: Zap },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${
                tab === id
                  ? 'bg-white text-slate-950 border-white shadow-lg'
                  : 'bg-white/5 text-slate-300 border-white/10 hover:bg-white/10'
              }`}
            >
              <Icon size={14} /> {label}
            </button>
          ))}
        </div>

        <span className="text-[11px] text-slate-500">
          Note: Upstream NVD scores shown for intelligence only — finding prioritization still uses SentinelAI CVSS v4.0.
        </span>
      </div>

      {err && (
        <div className="card p-4 border-red-500/30 bg-red-500/10 text-red-300 text-xs flex items-center gap-2">
          <AlertTriangle size={15} /> {err}
        </div>
      )}

      {/* TAB 1: SEARCH EXPLORER */}
      {tab === 'search' && (
        <div className="space-y-4">
          <form onSubmit={handleSearchSubmit} className="card p-5 space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search size={15} className="absolute left-3.5 top-3 text-slate-400" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search CVE, product, vendor, keyword — exclude terms with -windows (e.g. apache -wordpress)"
                  className="input !pl-10 text-sm"
                />
              </div>
              <select
                value={sort}
                onChange={(e) => { setSort(e.target.value); setPage(1) }}
                className="input text-xs sm:w-52"
              >
                {SORTS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
              <button type="submit" className="btn-primary text-xs px-5 justify-center">
                Search Index
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-white/10">
              <button
                type="button"
                onClick={() => { setKevOnly(v => !v); setPage(1) }}
                className={`chip border text-xs px-3 py-1 rounded-full cursor-pointer transition-all ${
                  kevOnly
                    ? 'bg-rose-500/25 text-rose-200 border-rose-400 font-bold'
                    : 'bg-white/5 text-slate-400 border-white/10 hover:text-slate-200'
                }`}
              >
                🔥 CISA KEV Only
              </button>
              <button
                type="button"
                onClick={() => { setHasPocOnly(v => !v); setPage(1) }}
                className={`chip border text-xs px-3 py-1 rounded-full cursor-pointer transition-all ${
                  hasPocOnly
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-400 font-bold'
                    : 'bg-white/5 text-slate-400 border-white/10 hover:text-slate-200'
                }`}
              >
                Has Public PoC
              </button>

              <span className="text-slate-600">|</span>

              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map(s => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => { setSeverity(s); setPage(1) }}
                    className={`chip border capitalize text-[11px] px-2.5 py-1 rounded-full cursor-pointer ${
                      severity === s
                        ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400/60 font-bold'
                        : 'bg-white/5 text-slate-400 border-white/10 hover:text-slate-200'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>

              <span className="text-slate-600">|</span>

              <div className="flex flex-wrap gap-1.5">
                {SOURCES.map(src => (
                  <button
                    key={src.id}
                    type="button"
                    onClick={() => { setSource(src.id); setPage(1) }}
                    className={`chip border text-[11px] px-2.5 py-1 rounded-full cursor-pointer ${
                      source === src.id
                        ? 'bg-purple-500/20 text-purple-300 border-purple-400/60 font-bold'
                        : 'bg-white/5 text-slate-400 border-white/10 hover:text-slate-200'
                    }`}
                  >
                    {src.label}
                  </button>
                ))}
              </div>
            </div>
          </form>

          {!searchResult.available && !loading && (
            <div className="card p-8 text-center space-y-3 border-amber-500/30 bg-amber-500/5">
              <Database className="mx-auto text-amber-400" size={32} />
              <h3 className="text-base font-bold text-white">Local PoC Index Database Not Built Yet</h3>
              <p className="text-xs text-slate-400 max-w-lg mx-auto">
                The background synchronizer builds `pocindex.db` automatically from 0xMarcio/pocindex feeds. You can explore Trending PoCs and Just Landed tabs right away or trigger a sync now.
              </p>
              {isAdmin && (
                <button type="button" onClick={handleTriggerSync} disabled={syncBusy || status?.syncing} className="btn-primary text-xs mx-auto">
                  <RefreshCw size={14} className={status?.syncing ? 'animate-spin' : ''} /> Trigger Initial Sync
                </button>
              )}
            </div>
          )}

          {loading ? (
            <div className="flex justify-center py-16"><Loader2 className="animate-spin text-accent" size={28} /></div>
          ) : searchResult.available && (
            <>
              <div className="flex items-center justify-between text-xs text-slate-400 px-1">
                <span>Showing <strong className="text-white">{searchResult.total.toLocaleString()}</strong> matching CVE records</span>
                {searchResult.totalPages > 1 && (
                  <span>Page {searchResult.page} of {searchResult.totalPages.toLocaleString()}</span>
                )}
              </div>

              {searchResult.items.length === 0 ? (
                <div className="card p-12 text-center text-slate-400 text-sm">
                  No CVEs matched your search or filter criteria.
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3">
                  {searchResult.items.map((item) => {
                    const epssPct = formatPct(item.epss?.score)
                    return (
                      <div
                        key={item.cveId}
                        onClick={() => openCveDetail(item.cveId)}
                        className="card p-4 hover:border-cyan-400/40 cursor-pointer transition-all space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono font-extrabold text-sm text-cyan-300">{item.cveId}</span>
                            {item.upstreamCvss?.score != null && (
                              <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${sevBadgeClass(item.upstreamCvss.severity)}`}>
                                CVSS {item.upstreamCvss.score} {item.upstreamCvss.severity || ''}
                              </span>
                            )}
                            {item.kev && (
                              <span className="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-red-500/25 text-red-200 border border-red-400/50">
                                CISA KEV {item.kev.added ? `(${item.kev.added})` : ''}
                              </span>
                            )}
                            {epssPct && (
                              <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${
                                item.epss.score >= 0.5
                                  ? 'bg-orange-500/25 text-orange-200 border-orange-400/50'
                                  : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                              }`}>
                                EPSS {epssPct} · P{Math.round((item.epss.percentile || 0) * 100)}
                              </span>
                            )}
                          </div>

                          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                            {item.topStars > 0 && (
                              <span className="chip bg-amber-500/10 text-amber-300 border-amber-400/30 py-0.5 px-2">
                                <Star size={11} className="fill-amber-400 text-amber-400" /> {item.topStars.toLocaleString()}
                              </span>
                            )}
                            {item.counts?.github > 0 && (
                              <span className="chip bg-white/5 text-slate-200 border-white/15 py-0.5 px-2">
                                GitHub ({item.counts.github})
                              </span>
                            )}
                            {item.counts?.nuclei > 0 && (
                              <span className="chip bg-cyan-500/15 text-cyan-300 border-cyan-500/30 py-0.5 px-2">
                                Nuclei ({item.counts.nuclei})
                              </span>
                            )}
                            {item.counts?.edb > 0 && (
                              <span className="chip bg-rose-500/15 text-rose-300 border-rose-500/30 py-0.5 px-2">
                                EDB ({item.counts.edb})
                              </span>
                            )}
                            {item.counts?.msf > 0 && (
                              <span className="chip bg-purple-500/15 text-purple-300 border-purple-500/30 py-0.5 px-2">
                                MSF ({item.counts.msf})
                              </span>
                            )}
                            {item.counts?.vulhub > 0 && (
                              <span className="chip bg-emerald-500/15 text-emerald-300 border-emerald-500/30 py-0.5 px-2">
                                Vulhub ({item.counts.vulhub})
                              </span>
                            )}
                          </div>
                        </div>

                        {item.title && <p className="text-xs font-semibold text-white">{item.title}</p>}
                        <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">{item.description || 'No description available.'}</p>

                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 pt-1">
                          <div className="flex flex-wrap gap-1.5">
                            {item.vendors?.slice(0, 3).map(v => (
                              <span key={v} className="px-2 py-0.5 rounded bg-white/5 text-slate-400">{v}</span>
                            ))}
                            {item.products?.slice(0, 3).map(p => (
                              <span key={p} className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300">{p}</span>
                            ))}
                          </div>
                          <span>Published {item.published || '—'} · Modified {item.modified || '—'}</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}

              {searchResult.totalPages > 1 && (
                <div className="flex items-center justify-center gap-3 pt-2">
                  <button
                    type="button"
                    disabled={page <= 1}
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    className="btn-ghost text-xs py-1.5 px-3"
                  >
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <span className="text-xs text-slate-400 font-mono">
                    {page} / {searchResult.totalPages}
                  </span>
                  <button
                    type="button"
                    disabled={page >= searchResult.totalPages}
                    onClick={() => setPage(p => p + 1)}
                    className="btn-ghost text-xs py-1.5 px-3"
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* TAB 2: TRENDING POCS */}
      {tab === 'trending' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {trendingItems.length === 0 ? (
            <div className="card p-12 text-center text-slate-400 text-sm col-span-2">No trending PoC entries available yet.</div>
          ) : trendingItems.map((it, idx) => (
            <div
              key={`${it.cve}-${it.url}-${idx}`}
              onClick={() => openCveDetail(it.cve)}
              className="card p-4 hover:border-rose-400/40 cursor-pointer transition-all space-y-2.5"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-mono text-slate-500">#{idx + 1}</span>
                  <span className="font-mono font-extrabold text-sm text-rose-300">{it.cve}</span>
                  {it.kev && (
                    <span className="text-[10px] font-extrabold px-2 py-0.5 rounded-full bg-red-500/25 text-red-200 border border-red-400/50">
                      CISA KEV
                    </span>
                  )}
                  {it.basis && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/5 text-slate-400 border border-white/10">
                      {it.basis}
                    </span>
                  )}
                </div>
                <span className="chip bg-amber-500/15 text-amber-300 border-amber-400/30 text-xs py-0.5 px-2">
                  <Star size={12} className="fill-amber-400 text-amber-400" /> {(it.stars || 0).toLocaleString()}
                </span>
              </div>

              <p className="text-sm font-bold text-white truncate">{it.name || it.url}</p>
              {it.desc && <p className="text-xs text-slate-300 line-clamp-2">{it.desc}</p>}

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-white/5">
                <a
                  href={it.url}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="text-cyan-400 hover:underline inline-flex items-center gap-1 truncate max-w-[70%]"
                >
                  <ExternalLink size={11} /> {it.url}
                </a>
                <span>{it.pushed ? new Date(it.pushed).toLocaleDateString() : (it.released ? new Date(it.released).toLocaleDateString() : '')}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 3: JUST LANDED */}
      {tab === 'landed' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {landedItems.length === 0 ? (
            <div className="card p-12 text-center text-slate-400 text-sm col-span-2">No just-landed PoCs available yet.</div>
          ) : landedItems.map((it, idx) => (
            <div
              key={`${it.cve}-${it.url}-${idx}`}
              onClick={() => openCveDetail(it.cve)}
              className="card p-4 hover:border-cyan-400/40 cursor-pointer transition-all space-y-2.5"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-extrabold text-sm text-cyan-300">{it.cve}</span>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-400/40">
                    JUST LANDED
                  </span>
                  {it.kev && (
                    <span className="text-[10px] font-extrabold px-2 py-0.5 rounded-full bg-red-500/25 text-red-200 border border-red-400/50">
                      CISA KEV
                    </span>
                  )}
                </div>
                <span className="chip bg-amber-500/15 text-amber-300 border-amber-400/30 text-xs py-0.5 px-2">
                  <Star size={12} className="fill-amber-400 text-amber-400" /> {(it.stars || 0).toLocaleString()}
                </span>
              </div>

              <p className="text-sm font-bold text-white truncate">{it.name || it.url}</p>
              {it.desc && <p className="text-xs text-slate-300 line-clamp-2">{it.desc}</p>}

              <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-white/5">
                <a
                  href={it.url}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="text-cyan-400 hover:underline inline-flex items-center gap-1 truncate max-w-[70%]"
                >
                  <ExternalLink size={11} /> {it.url}
                </a>
                <span>{it.released ? new Date(it.released).toLocaleString() : ''}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* CVE DETAIL MODAL (portaled to body so .motion-fade-up transform never offsets fixed overlay) */}
      {selectedCveId && createPortal(
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`CVE details for ${selectedCveId}`}
          className="fixed inset-0 z-[75] grid place-items-center bg-black/75 backdrop-blur-md p-4"
          onClick={() => setSelectedCveId(null)}
        >
          <div
            className="card w-full max-w-3xl max-h-[88vh] flex flex-col border border-white/15 shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-5 border-b border-white/10 flex items-start justify-between gap-3 bg-slate-950/60">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-xl font-extrabold text-white font-mono">{selectedCveId}</h2>
                  {detail?.upstreamCvss?.score != null && (
                    <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${sevBadgeClass(detail.upstreamCvss.severity)}`}>
                      Upstream CVSS {detail.upstreamCvss.score} ({detail.upstreamCvss.severity})
                    </span>
                  )}
                  {detail?.kev && (
                    <span className="text-xs font-extrabold px-2.5 py-0.5 rounded-full bg-red-500/25 text-red-200 border border-red-400/50">
                      CISA KEV · Added {detail.kev.added}
                    </span>
                  )}
                  {detail?.epss && (
                    <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-orange-500/20 text-orange-300 border border-orange-400/40">
                      EPSS {formatPct(detail.epss.score)} (P{Math.round((detail.epss.percentile || 0) * 100)})
                    </span>
                  )}
                </div>
                {detail?.title && <p className="text-xs font-semibold text-slate-300">{detail.title}</p>}
              </div>
              <button type="button" aria-label="Close CVE details" onClick={() => setSelectedCveId(null)} className="icon-btn">
                <X size={16} />
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-5 flex-1">
              {detailLoading ? (
                <div className="flex justify-center py-12"><Loader2 className="animate-spin text-accent" size={26} /></div>
              ) : !detail ? (
                <p className="text-sm text-slate-400">
                  Detailed metadata for {selectedCveId} is not yet in the local index (try syncing first or view the external reference on pocindex.io).
                </p>
              ) : (
                <>
                  <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">{detail.description}</p>

                  {detail.nuclei?.available && (
                    <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-3.5 text-xs space-y-1">
                      <p className="font-bold text-cyan-300 flex items-center gap-1.5">
                        <Terminal size={14} /> Nuclei Detection Template Available
                        {detail.nuclei.severity && <span className="uppercase">({detail.nuclei.severity})</span>}
                        {detail.nuclei.cwe && <span className="font-mono text-cyan-200">· {detail.nuclei.cwe}</span>}
                      </p>
                      <div className="space-y-1">
                        {(detail.pocs?.nuclei || detail.nuclei.templates || []).map((u) => (
                          <a key={u} href={u} target="_blank" rel="noreferrer" className="block text-cyan-200 hover:underline break-all">
                            {u}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Grouped PoC Sources */}
                  {detail.pocs?.github?.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                        GitHub PoC Repositories ({detail.pocs.github.length})
                      </h4>
                      <div className="space-y-1.5">
                        {detail.pocs.github.map((g) => (
                          <a
                            key={g.url}
                            href={g.url}
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center justify-between gap-2 p-2.5 rounded-lg bg-white/[0.03] border border-white/10 hover:border-cyan-400/40 text-xs transition-colors"
                          >
                            <span className="text-cyan-300 font-mono truncate">{g.repo || g.url}</span>
                            <div className="flex items-center gap-2 shrink-0 text-[11px] text-slate-400">
                              {g.stars > 0 && (
                                <span className="inline-flex items-center gap-1 text-amber-300 font-semibold">
                                  <Star size={11} className="fill-amber-400 text-amber-400" /> {g.stars.toLocaleString()}
                                </span>
                              )}
                              <ExternalLink size={12} />
                            </div>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {[
                    { key: 'edb', label: 'Exploit-DB', color: 'text-rose-300' },
                    { key: 'msf', label: 'Metasploit Framework Modules', color: 'text-purple-300' },
                    { key: 'vulhub', label: 'Vulhub Lab Environments', color: 'text-emerald-300' },
                    { key: 'collections', label: 'PoC Collections', color: 'text-slate-300' },
                  ].map(({ key, label, color }) => (
                    detail.pocs?.[key]?.length > 0 && (
                      <div key={key} className="space-y-1.5">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                          {label} ({detail.pocs[key].length})
                        </h4>
                        <div className="space-y-1">
                          {detail.pocs[key].map((u) => (
                            <a key={u} href={u} target="_blank" rel="noreferrer" className={`block text-xs ${color} hover:underline break-all`}>
                              {u}
                            </a>
                          ))}
                        </div>
                      </div>
                    )
                  ))}

                  {detail.advisories?.length > 0 && (
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Vendor Advisories &amp; References</h4>
                      <ul className="space-y-1 text-xs">
                        {detail.advisories.slice(0, 12).map((a, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <a href={a.url} target="_blank" rel="noreferrer" className="text-slate-300 hover:text-cyan-300 hover:underline break-all">
                              {a.url}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}
