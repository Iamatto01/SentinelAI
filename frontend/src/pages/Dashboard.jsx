import React from 'react'
import { Link } from 'react-router-dom'
import { Radar, Bug, FolderKanban, Activity, ShieldAlert, Cpu, Sparkles, ArrowUpRight, Zap, CheckCircle2, GitBranch, CreditCard, Sun, Moon } from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { api } from '../lib/api.js'
import { useQuery } from '../lib/cache.js'
import { useTheme } from '../lib/ThemeContext.jsx'
import StatCard from '../components/StatCard.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { DashboardSkeleton } from '../components/SkeletonLoader.jsx'

const SEV_COLORS = { critical: '#f43f5e', high: '#f59e0b', medium: '#a855f7', low: '#00f2fe', info: '#10b981' }

export default function Dashboard() {
  const { isNight, toggleNightMode } = useTheme()
  const { data, loading, error } = useQuery('dashboard', () => api.dashboard(), [], 30_000)

  if (error) return <div className="card p-6 text-rose-400 border border-rose-500/30 bg-rose-500/10">{error.message}</div>
  if (loading && !data) return <DashboardSkeleton />

  const sevData = Object.entries(data?.severity || {})
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const totalFindings = data?.totals?.findings || 0
  const criticalCount = data?.severity?.critical || 0
  const healthScore = totalFindings === 0 ? 100 : Math.max(10, 100 - (criticalCount * 15 + (data?.severity?.high || 0) * 5))

  return (
    <div className="space-y-6 motion-fade-up content-fade">
      {/* Vision UI Header Banner */}
      <div className="card p-6 border border-white/15 relative overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="z-10 flex items-center gap-3.5">
          <Link to="/app/consultants" title="Consult Lead Security Architect" className="relative shrink-0 group">
            <div className="w-13 h-13 sm:w-14 sm:h-14 rounded-2xl overflow-hidden border-2 border-cyan-400/40 shadow-lg bg-slate-900 ring-2 ring-cyan-500/20 group-hover:border-cyan-300 transition-all">
              <img
                src="/saif.png"
                alt="Muhammad Saifudin"
                className="w-full h-full object-cover"
                style={{ objectPosition: '85% 85%' }}
                onError={(e) => { e.currentTarget.src = '/fyp2_presenter.png' }}
              />
            </div>
            <span className="absolute -bottom-1 -right-1 px-1.5 py-0.5 rounded-full bg-cyan-500 text-slate-950 text-[8px] font-black uppercase tracking-wider shadow">
              Lead
            </span>
          </Link>
          <div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Security Overview &amp; Threat Matrix
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              Real-time assessment intelligence powered by Native Kali Engine &amp; {data?.agentsCount || 53} AI Agent Personas
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 z-10 shrink-0">
          {data?.runningScans > 0 ? (
            <span className="chip bg-emerald-500/20 text-emerald-300 border border-emerald-400/50 shadow-[0_0_12px_rgba(16,185,129,0.4)] animate-pulse px-3.5 py-1.5 text-xs font-extrabold flex items-center">
              <span className="relative flex h-2 w-2 mr-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              {data.runningScans} Scans Running
            </span>
          ) : (
            <span className="chip bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-3.5 py-1.5 text-xs font-bold flex items-center shadow-sm">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse" />
              Engines Ready
            </span>
          )}
          {/* Quick Theme Toggle Button right on Dashboard */}
          <button
            onClick={toggleNightMode}
            className="flex items-center gap-2 px-3 py-2 rounded-xl border border-white/15 hover:border-cyan-400/50 bg-slate-900/80 hover:bg-slate-800 text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm text-xs font-bold active:scale-95"
            title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            aria-label="Toggle Theme"
          >
            {isNight ? (
              <>
                <Sun size={14} className="text-amber-400 animate-spin-slow" />
                <span className="hidden sm:inline">Light Mode</span>
              </>
            ) : (
              <>
                <Moon size={14} className="text-cyan-400" />
                <span className="hidden sm:inline">Dark Mode</span>
              </>
            )}
          </button>

          <Link to="/app/findings" className="btn-primary text-xs py-2 px-4 shadow-glow flex items-center gap-1.5">
            <Bug size={14} /> Vulnerability Findings
          </Link>
        </div>
      </div>

      {/* Quick Launch Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-5 border-cyan-500/30 hover:border-cyan-400/60 hover-lift transition-all flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Radar size={18} />
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30 uppercase">
                Blackbox
              </span>
            </div>
            <h3 className="font-bold text-white text-sm">Scan Website URL</h3>
            <p className="text-xs text-slate-400">
              Run automated Kali toolchains (Nmap, Nuclei, Nikto, SQLmap, FFUF) against any live URL or IP.
            </p>
          </div>
          <div className="pt-4 mt-2 border-t border-white/5">
            <Link to="/app/scans" className="btn-primary text-xs py-2 w-full justify-center shadow-glow active-press">
              Launch URL Scan →
            </Link>
          </div>
        </div>

        <div className="card p-5 border-purple-500/30 hover:border-purple-400/60 hover-lift transition-all flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <GitBranch size={18} />
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30 uppercase">
                Continuous CI/CD
              </span>
            </div>
            <h3 className="font-bold text-white text-sm">GitHub Automation</h3>
            <p className="text-xs text-slate-400">
              Link private/public GitHub repositories for automatic audit on every Push & Pull Request.
            </p>
          </div>
          <div className="pt-4 mt-2 border-t border-white/5">
            <Link to="/app/github" className="btn-secondary text-xs py-2 w-full justify-center border-purple-500/30 text-purple-300 hover:text-white active-press">
              Connect Repository →
            </Link>
          </div>
        </div>

        <div className="card p-5 border-emerald-500/30 hover:border-emerald-400/60 hover-lift transition-all flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <CreditCard size={18} />
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30 uppercase">
                Subscription
              </span>
            </div>
            <h3 className="font-bold text-white text-sm">Billing & Quota Management</h3>
            <p className="text-xs text-slate-400">
              Check your remaining monthly audit quota, download invoices, or upgrade your plan.
            </p>
          </div>
          <div className="pt-4 mt-2 border-t border-white/5">
            <Link to="/app/billing" className="btn-secondary text-xs py-2 w-full justify-center border-emerald-500/30 text-emerald-300 hover:text-white active-press">
              View Billing & Quota →
            </Link>
          </div>
        </div>
      </div>

      {/* Stat Cards - Equal Dimensions & Live Green Pulse */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 items-stretch">
        <div className="motion-fade-up motion-delay-1 h-full">
          <StatCard
            icon={FolderKanban}
            label="Total Scans Executed"
            value={data?.totals?.scans || 0}
            tone="cyan"
            trend="+12%"
            sub={`${data?.totals?.projects || 0} Project Folders • All-Time`}
          />
        </div>
        <div className="motion-fade-up motion-delay-2 h-full">
          <StatCard
            icon={Bug}
            label="Discovered Findings"
            value={data?.totals?.findings || 0}
            tone="critical"
            sub={`${criticalCount} Critical Vulnerabilities`}
          />
        </div>
        <div className="motion-fade-up motion-delay-3 h-full">
          <StatCard
            icon={Activity}
            label="Active Engine Scans"
            value={data?.runningScans || 0}
            tone="emerald"
            trend={data?.runningScans > 0 ? "Live" : "Idle"}
            sub={data?.runningScans > 0 ? `${data.runningScans} Live Assessment(s) Active` : "All Toolchains Standby"}
          />
        </div>
        <div className="motion-fade-up motion-delay-4 h-full">
          <StatCard
            icon={Cpu}
            label="AI Agents Online"
            value={data?.agentsCount || 53}
            tone="purple"
            sub="53 Active Specialist Personas"
          />
        </div>
      </div>

      {/* Charts & Security Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Donut */}
        <div className="card p-6 hover:border-cyan-400/40 hover-lift transition-all duration-300 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-white">Severity Breakdown</h3>
                <p className="text-xs text-slate-400">Vulnerability risk levels</p>
              </div>
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            </div>

            {sevData.length ? (
              <div className="relative">
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={85} paddingAngle={4}>
                      {sevData.map((e) => <Cell key={e.name} fill={SEV_COLORS[e.name]} stroke="rgba(6, 11, 38, 0.8)" strokeWidth={2} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: 'rgba(6, 11, 38, 0.95)', border: '1px solid rgba(0,242,254,0.3)', borderRadius: 16, fontSize: 12, backdropFilter: 'blur(16px)', color: '#fff' }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-extrabold text-white count-up">{totalFindings}</span>
                  <span className="text-[10px] uppercase tracking-widest text-slate-400">Findings</span>
                </div>
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500 text-xs">
                No vulnerabilities detected yet.
              </div>
            )}
          </div>

          <div className="mt-4 pt-4 border-t border-white/10 grid grid-cols-5 gap-1 text-center">
            {Object.keys(SEV_COLORS).map((s) => (
              <div key={s} className="hover:scale-105 transition-transform cursor-default">
                <div className="mx-auto h-1.5 w-6 rounded-full" style={{ background: SEV_COLORS[s], boxShadow: `0 0 8px ${SEV_COLORS[s]}` }} />
                <p className="mt-1 text-[9px] uppercase font-extrabold tracking-wider text-slate-400">{s.slice(0, 4)}</p>
                <p className="text-xs font-bold text-white">{data?.severity?.[s] || 0}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Security Health */}
        <div className="card p-6 hover:border-cyan-400/40 hover-lift transition-all duration-300 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-base font-bold text-white">Security Health Index</h3>
              <div className="icon-box icon-box-cyan !p-2">
                <ShieldAlert size={18} />
              </div>
            </div>

            <div className="my-4 text-center">
              <div className="text-4xl font-extrabold text-white tracking-tight count-up">{healthScore}%</div>
              <p className="text-xs font-semibold text-cyan-300 mt-1">
                {healthScore > 80 ? 'Optimal Posture' : healthScore > 50 ? 'Requires Attention' : 'Critical Action Required'}
              </p>
            </div>

            <div className="w-full bg-slate-900/80 rounded-full h-3 p-0.5 border border-white/10 my-4 overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 h-full rounded-full transition-all duration-700 shadow-[0_0_12px_rgba(0,242,254,0.5)]"
                style={{ width: `${healthScore}%` }}
              />
            </div>

            <div className="space-y-2 text-xs font-medium text-slate-300 pt-2">
              <div className="flex items-center justify-between p-2 rounded-xl bg-white/[0.03]">
                <span className="flex items-center gap-2">
                  <CheckCircle2 size={14} className="text-emerald-400" /> Native Kali Engine
                </span>
                <span className="text-emerald-400 font-bold">Connected</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded-xl bg-white/[0.03]">
                <span className="flex items-center gap-2">
                  <Cpu size={14} className="text-purple-400" /> AI Agent Mesh
                </span>
                <span className="text-purple-300 font-bold">{data?.agentsCount || 53} Active Personas</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-white/10">
            <Link to="/app/findings" className="btn-ghost w-full justify-center text-xs active-press">
              Audit Vulnerabilities →
            </Link>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="card p-6 lg:col-span-1 hover:border-cyan-400/40 hover-lift transition-all duration-300 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-white">Recent Scans</h3>
                <p className="text-xs text-slate-400">Latest target assessments</p>
              </div>
              <Link to="/app/scans" className="text-xs font-bold text-cyan-300 hover:text-cyan-200 flex items-center gap-1">
                View all <ArrowUpRight size={14} />
              </Link>
            </div>

            <div className="space-y-2.5">
              {(data?.recentScans || []).length === 0 && (
                <div className="text-xs text-slate-500 py-12 text-center">No scans recorded yet.</div>
              )}
              {(data?.recentScans || []).slice(0, 4).map((s) => (
                <Link
                  key={s.id}
                  to={`/app/scans/${s.id}`}
                  className="flex items-center justify-between rounded-xl border border-white/10 bg-slate-900/50 hover:bg-cyan-500/10 hover:border-cyan-400/40 p-3 transition-all duration-200 group"
                >
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors truncate">{s.target}</p>
                    <p className="text-[10px] text-slate-400 uppercase font-semibold">{s.mode} • {new Date(s.created_at).toLocaleDateString()}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`chip text-[10px] border ${
                      s.status === 'running' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400/50 animate-pulse' :
                      s.status === 'done' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50' : 'bg-white/5 text-slate-400 border-white/10'
                    }`}>
                      {s.status}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-white/10">
            <Link to="/app/scans" className="btn-primary w-full justify-center text-xs active-press">
              View All Assessments
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
