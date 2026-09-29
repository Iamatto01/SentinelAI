import React from 'react'
import { Link } from 'react-router-dom'
import {
  Radar, Bug, FolderKanban, Activity, Cpu,
  ArrowUpRight, CheckCircle2, GitBranch, Crosshair, UserCheck,
  Shield, ArrowRight, Sparkles, Terminal, Zap, ShieldCheck, Server
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { api } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'
import { useQuery } from '../lib/cache.js'
import StatCard from '../components/StatCard.jsx'
import { DashboardSkeleton } from '../components/SkeletonLoader.jsx'

const SEV_CONFIG = [
  { key: 'critical', label: 'Critical', color: '#f43f5e', barBg: 'from-rose-500 to-rose-600', shadow: 'shadow-rose-500/30' },
  { key: 'high', label: 'High', color: '#f59e0b', barBg: 'from-amber-500 to-amber-600', shadow: 'shadow-amber-500/30' },
  { key: 'medium', label: 'Medium', color: '#a855f7', barBg: 'from-purple-500 to-purple-600', shadow: 'shadow-purple-500/30' },
  { key: 'low', label: 'Low', color: '#00f2fe', barBg: 'from-cyan-400 to-cyan-500', shadow: 'shadow-cyan-500/30' },
  { key: 'info', label: 'Informational', color: '#10b981', barBg: 'from-emerald-400 to-emerald-500', shadow: 'shadow-emerald-500/30' },
]

export default function Dashboard() {
  const { user } = useAuth()
  const isClient = user?.role === 'client'
  const { data, loading, error } = useQuery('dashboard', () => api.dashboard(), [], 30_000)
  const { data: subData } = useQuery('billingSub', () => api.billingSubscription().catch(() => null), [], 30_000)

  if (error) return <div className="rounded-3xl p-6 text-rose-400 border border-rose-500/30 bg-rose-500/10 backdrop-blur-xl">{error.message}</div>
  if (loading && !data) return <DashboardSkeleton />

  const totalFindings = data?.totals?.findings || 0
  const criticalCount = data?.severity?.critical || 0
  const highCount = data?.severity?.high || 0
  const sevData = SEV_CONFIG
    .map(c => ({
      name: c.label,
      value: data?.severity?.[c.key] || 0,
      color: c.color,
      key: c.key
    }))
    .filter(d => d.value > 0)

  return (
    <div className="space-y-6 motion-fade-up content-fade">
      {/* Executive SOC Header — Sleek Floating Glass Pod with Clean Layout */}
      <div className="rounded-3xl p-6 sm:p-7 border border-purple-500/20 bg-gradient-to-r from-slate-950/95 via-slate-900/80 to-slate-950/95 backdrop-blur-2xl shadow-[0_12px_40px_rgba(0,0,0,0.6)] relative overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
        {/* Soft Ambient Aura Glows */}
        <div className="absolute -top-24 -left-24 w-60 h-60 rounded-full bg-purple-500/10 blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 right-10 w-52 h-52 rounded-full bg-indigo-500/10 blur-3xl pointer-events-none" />

        <div className="relative z-10">
          <div className="flex items-center gap-2 mb-1">
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-purple-500/15 text-purple-300 border border-purple-500/30">
              {isClient ? 'Client Security Portal' : 'Security Operations Center'}
            </span>
            <span className="text-[11px] text-slate-500 font-mono">•</span>
            <span className="text-[11px] text-slate-400 font-medium">
              {isClient ? (user?.email || user?.username) : 'Kali N100 Autonomous Mesh'}
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
            {isClient ? 'Vulnerability Matrix & Security Overview' : 'Offensive Operations & Threat Matrix'}
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {isClient
              ? 'Continuous vulnerability assessments, source audits & compliance posture'
              : 'Autonomous Kali Linux toolchain telemetry & AI multi-agent offensive orchestration'}
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0 relative z-10">
          {data?.runningScans > 0 ? (
            <span className="px-4 py-2 rounded-full bg-purple-500/20 text-purple-300 border border-purple-400/50 shadow-[0_0_16px_rgba(168,85,247,0.35)] animate-pulse text-xs font-extrabold flex items-center">
              <span className="relative flex h-2 w-2 mr-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-purple-500"></span>
              </span>
              {data.runningScans} {data.runningScans === 1 ? 'Scan Active' : 'Scans Active'}
            </span>
          ) : (
            <span className="px-3.5 py-1.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-xs font-bold flex items-center shadow-[0_0_12px_rgba(16,185,129,0.2)]">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse" />
              Kali Engine Ready
            </span>
          )}

          <Link
            to="/app/scans"
            className="px-4 py-2 rounded-full bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-extrabold text-xs shadow-[0_0_20px_rgba(168,85,247,0.35)] transition-all duration-200 flex items-center gap-1.5 active:scale-95"
          >
            <Radar size={14} /> Launch Scan
          </Link>
        </div>
      </div>

      {/* Top Row: 4 High-Impact KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 items-stretch">
        <div className="motion-fade-up motion-delay-1 h-full">
          <StatCard
            icon={FolderKanban}
            label="Total Scans Executed"
            value={data?.totals?.scans || 0}
            tone="purple"
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
            trend={criticalCount > 0 ? `${criticalCount} Crit` : undefined}
            sub={`${criticalCount} Critical • ${highCount} High`}
          />
        </div>
        <div className="motion-fade-up motion-delay-3 h-full">
          <StatCard
            icon={Activity}
            label="Active Engine Scans"
            value={data?.runningScans || 0}
            tone="emerald"
            trend={data?.runningScans > 0 ? "Live" : "Idle"}
            sub={data?.runningScans > 0 ? `${data.runningScans} Live Assessment(s)` : "All Toolchains Standby"}
          />
        </div>
        <div className="motion-fade-up motion-delay-4 h-full">
          {isClient ? (
            <StatCard
              icon={Zap}
              label="Available Scan Quota"
              value={subData?.isUnlimited ? 'Unlimited' : `${subData?.remainingQuota ?? 0}`}
              tone="purple"
              trend={subData?.remainingQuota !== undefined ? `${subData.remainingQuota} Left` : undefined}
              sub={`Plan: ${subData?.plan_name || 'Free Trial'} • ${subData?.scan_quota_used || 0} Used`}
            />
          ) : (
            <StatCard
              icon={Terminal}
              label="Kali Toolchain Health"
              value="25 / 25"
              tone="emerald"
              trend="100% Ready"
              sub="Nmap • Nuclei • Nikto • SQLmap • Zap"
            />
          )}
        </div>
      </div>

      {/* Balanced 2/3 and 1/3 Command Center Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Column (2/3 width): Main Operational Threat Metrics & Feed */}
        <div className="lg:col-span-2 space-y-6">
          {/* Threat & Severity Distribution Card (Rounded 3xl Glass Pod) */}
          <div className="rounded-3xl border border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 backdrop-blur-xl p-6 sm:p-7 relative overflow-hidden hover:border-purple-400/30 transition-all duration-300 shadow-xl">
            {/* Soft Ambient Glow */}
            <div className="absolute top-0 right-1/4 w-40 h-40 rounded-full bg-purple-500/10 blur-3xl pointer-events-none" />

            <div className="flex items-center justify-between mb-6 pb-4 border-b border-white/5 relative z-10">
              <div>
                <h2 className="text-base font-bold text-white tracking-tight">Vulnerability Threat Distribution</h2>
                <p className="text-xs text-slate-400 mt-0.5">Classification by CVSS severity impact</p>
              </div>
              <Link to="/app/findings" className="text-xs font-bold text-purple-300 hover:text-purple-200 flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 transition-all">
                Audit Findings <ArrowUpRight size={14} />
              </Link>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center relative z-10">
              {/* Donut Chart inside a sleek circular pod */}
              <div className="md:col-span-5 flex flex-col items-center justify-center">
                {sevData.length > 0 ? (
                  <div className="relative w-52 h-52 sm:w-56 sm:h-56 p-2 rounded-full bg-slate-950/70 border border-white/5 shadow-inner flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={sevData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={66}
                          outerRadius={92}
                          paddingAngle={3}
                          strokeWidth={2}
                          stroke="#0a0a0a"
                        >
                          {sevData.map((e) => (
                            <Cell key={e.name} fill={e.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: 'rgba(10, 15, 29, 0.95)',
                            border: '1px solid rgba(168,85,247,0.35)',
                            borderRadius: 16,
                            fontSize: 12,
                            backdropFilter: 'blur(16px)',
                            color: '#fff',
                            boxShadow: '0 8px 32px rgba(0,0,0,0.5)'
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <span className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight count-up">{totalFindings}</span>
                      <span className="text-[10px] uppercase font-bold tracking-widest text-slate-400">Total Flaws</span>
                    </div>
                  </div>
                ) : (
                  <div className="py-12 flex flex-col items-center justify-center text-center">
                    <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-2 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
                      <CheckCircle2 size={26} />
                    </div>
                    <p className="text-xs font-bold text-white">Zero Findings Detected</p>
                    <p className="text-[11px] text-slate-400 mt-1">All scanned endpoints currently clear</p>
                  </div>
                )}
              </div>

              {/* Horizontal Severity Meters (Curved Floating Pods) */}
              <div className="md:col-span-7 space-y-2.5">
                {SEV_CONFIG.map((cfg) => {
                  const count = data?.severity?.[cfg.key] || 0
                  const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0

                  return (
                    <Link
                      key={cfg.key}
                      to="/app/findings"
                      className="block group p-3 rounded-2xl bg-white/[0.02] hover:bg-white/[0.06] border border-white/5 hover:border-purple-400/30 transition-all duration-300"
                    >
                      <div className="flex items-center justify-between text-xs mb-1.5">
                        <span className="flex items-center gap-2 font-bold text-slate-200 group-hover:text-white">
                          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cfg.color, boxShadow: `0 0 8px ${cfg.color}` }} />
                          {cfg.label}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-extrabold text-white">{count}</span>
                          <span className="text-[11px] font-semibold text-slate-400 w-10 text-right">{pct}%</span>
                        </div>
                      </div>
                      <div className="w-full bg-slate-950/80 rounded-full h-2 overflow-hidden border border-white/5">
                        <div
                          className={`h-full rounded-full bg-gradient-to-r ${cfg.barBg} transition-all duration-700 ${cfg.shadow}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </Link>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Recent Target Assessments Card (Rounded 3xl with Curved Pod Rows) */}
          <div className="rounded-3xl border border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 backdrop-blur-xl p-6 sm:p-7 relative overflow-hidden hover:border-purple-400/30 transition-all duration-300 shadow-xl">
            <div className="flex items-center justify-between mb-5 pb-4 border-b border-white/5">
              <div>
                <h2 className="text-base font-bold text-white tracking-tight">Recent Target Assessments</h2>
                <p className="text-xs text-slate-400 mt-0.5">Execution logs from autonomous security scans</p>
              </div>
              <Link to="/app/scans" className="text-xs font-bold text-purple-300 hover:text-purple-200 flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 transition-all">
                View All ({data?.totals?.scans || 0}) <ArrowUpRight size={14} />
              </Link>
            </div>

            <div className="space-y-3">
              {(data?.recentScans || []).length === 0 ? (
                <div className="py-12 text-center rounded-3xl border border-dashed border-white/10 p-6">
                  <p className="text-xs text-slate-400">No assessments executed yet.</p>
                  <Link to="/app/scans" className="btn-primary text-xs py-2 px-4 rounded-full mt-3 inline-flex">
                    Launch Your First Scan
                  </Link>
                </div>
              ) : (
                (data?.recentScans || []).slice(0, 5).map((s) => (
                  <Link
                    key={s.id}
                    to={`/app/scans/${s.id}`}
                    className="flex items-center justify-between rounded-2xl border border-white/10 bg-slate-900/50 hover:bg-purple-500/[0.08] hover:border-purple-400/40 p-4 transition-all duration-300 group hover:shadow-[0_4px_20px_rgba(168,85,247,0.1)]"
                  >
                    <div className="flex items-center gap-3.5 min-w-0 pr-2">
                      <div className="w-11 h-11 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-slate-300 group-hover:text-purple-300 group-hover:border-purple-500/30 transition-colors shrink-0">
                        {s.repo_name ? <GitBranch size={18} /> : <Radar size={18} />}
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs sm:text-sm font-bold text-white group-hover:text-purple-300 transition-colors truncate">
                          {s.target}
                        </p>
                        <p className="text-[10px] text-slate-400 uppercase font-semibold flex items-center gap-1.5 mt-0.5">
                          <span className="text-purple-400 font-bold">{s.mode || 'Blackbox'}</span>
                          <span>•</span>
                          <span>{s.created_at ? new Date(s.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Recent'}</span>
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span className={`px-3 py-1 rounded-full text-[10px] font-bold border ${
                        s.status === 'running'
                          ? 'bg-purple-500/20 text-purple-300 border-purple-400/50 animate-pulse'
                          : s.status === 'done'
                          ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
                          : s.status === 'failed'
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/50'
                          : 'bg-white/5 text-slate-400 border-white/10'
                      }`}>
                        {s.status === 'running' ? 'Running' : s.status === 'done' ? 'Completed' : s.status}
                      </span>
                      <div className="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 group-hover:text-purple-300 group-hover:bg-purple-500/15 group-hover:translate-x-0.5 transition-all">
                        <ArrowRight size={15} />
                      </div>
                    </div>
                  </Link>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column (1/3 width): Health Gauge, Quick Tools, Advisory Card */}
        <div className="lg:col-span-1 space-y-6">
          {/* Role-Aware Right Column Hub (Admin: Infrastructure & Toolchain Telemetry | Client: Subscription & Quota Allocation) */}
          {isClient ? (
            <div className="rounded-3xl border border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 backdrop-blur-xl p-6 sm:p-7 relative overflow-hidden hover:border-purple-400/30 transition-all duration-300 shadow-xl flex flex-col justify-between">
              <div className="absolute top-0 right-0 w-36 h-36 rounded-full bg-purple-500/10 blur-3xl pointer-events-none" />

              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/5">
                  <div>
                    <h2 className="text-base font-bold text-white tracking-tight">Active Plan &amp; Quota</h2>
                    <p className="text-xs text-slate-400 mt-0.5">Enterprise security allocation</p>
                  </div>
                  <span className="px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border text-purple-300 bg-purple-500/15 border-purple-500/40 shadow-[0_0_12px_rgba(168,85,247,0.25)]">
                    {subData?.plan_name || 'Standard Tier'}
                  </span>
                </div>

                {/* Quota Progress Meter */}
                <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5 my-3">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <span className="font-bold text-slate-300">Scan Usage</span>
                    <span className="font-mono font-extrabold text-white">
                      {subData?.isUnlimited
                        ? `${subData?.scan_quota_used || 0} Scans Used (Unlimited)`
                        : `${subData?.scan_quota_used || 0} / ${subData?.scan_quota_total || 3} Used`}
                    </span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-white/10">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-purple-500 to-indigo-500 transition-all duration-700 shadow-[0_0_10px_rgba(168,85,247,0.4)]"
                      style={{
                        width: subData?.isUnlimited
                          ? '100%'
                          : `${Math.min(100, Math.round(((subData?.scan_quota_used || 0) / Math.max(1, subData?.scan_quota_total || 3)) * 100))}%`
                      }}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                    <span>Available Balance</span>
                    <span className="font-bold text-purple-300">
                      {subData?.isUnlimited ? 'Unlimited Active' : `${subData?.remainingQuota ?? 0} Scans Left`}
                    </span>
                  </div>
                </div>

                {/* Client Operational Scope Rows */}
                <div className="space-y-2 pt-1 text-xs">
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <CheckCircle2 size={15} className="text-emerald-400 shrink-0" /> Target Protection Scope
                    </span>
                    <span className="text-emerald-400 font-bold text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30">
                      Active
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <GitBranch size={15} className="text-cyan-400 shrink-0" /> GitHub CI/CD Automated
                    </span>
                    <span className="text-cyan-400 font-bold text-[11px] px-2 py-0.5 rounded-full bg-cyan-500/15 border border-cyan-500/30">
                      Webhooks Ready
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <ShieldCheck size={15} className="text-purple-400 shrink-0" /> Executive PDF Delivery
                    </span>
                    <span className="text-purple-300 font-bold text-[11px] px-2 py-0.5 rounded-full bg-purple-500/15 border border-purple-500/30">
                      Instant
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-white/10 relative z-10 flex gap-2">
                <Link
                  to="/app/billing"
                  className="flex-1 py-2 px-3 rounded-full bg-purple-600 hover:bg-purple-500 text-white font-extrabold text-xs text-center shadow-[0_0_15px_rgba(168,85,247,0.3)] transition-all"
                >
                  Top-Up / Upgrade Plan
                </Link>
                <Link
                  to="/app/consultants"
                  className="py-2 px-3 rounded-full border border-white/15 hover:border-purple-400/40 bg-white/[0.03] text-slate-200 hover:text-white text-xs font-bold text-center transition-all"
                >
                  Advisory
                </Link>
              </div>
            </div>
          ) : (
            <div className="rounded-3xl border border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 backdrop-blur-xl p-6 sm:p-7 relative overflow-hidden hover:border-purple-400/30 transition-all duration-300 shadow-xl flex flex-col justify-between">
              <div className="absolute top-0 right-0 w-36 h-36 rounded-full bg-purple-500/10 blur-3xl pointer-events-none" />

              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/5">
                  <div>
                    <h2 className="text-base font-bold text-white tracking-tight">Kali Engine &amp; Ops</h2>
                    <p className="text-xs text-slate-400 mt-0.5">Autonomous execution node &amp; daemons</p>
                  </div>
                  <span className="px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border text-emerald-300 bg-emerald-500/15 border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.25)]">
                    Live Node
                  </span>
                </div>

                {/* Subsystem Health Status Rows (Curved Pill Strips) */}
                <div className="space-y-2.5 pt-1 text-xs">
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <CheckCircle2 size={15} className="text-emerald-400 shrink-0" /> Kali N100 Engine
                    </span>
                    <span className="text-emerald-400 font-bold text-[11px] px-2 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30">
                      Connected
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <Crosshair size={15} className="text-rose-400 shrink-0" /> MSF RPC Bridge
                    </span>
                    <span className="text-rose-300 font-bold text-[11px] px-2 py-0.5 rounded-full bg-rose-500/15 border border-rose-500/30">
                      Port 55553
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <Terminal size={15} className="text-cyan-400 shrink-0" /> Zero Trust Tunnel
                    </span>
                    <span className="text-cyan-400 font-bold text-[11px] px-2 py-0.5 rounded-full bg-cyan-500/15 border border-cyan-500/30">
                      Encrypted
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-white/[0.02] border border-white/5">
                    <span className="flex items-center gap-2 text-slate-300 font-medium">
                      <Cpu size={15} className="text-purple-400 shrink-0" /> Toolchain Suite
                    </span>
                    <span className="text-purple-300 font-bold text-[11px] px-2 py-0.5 rounded-full bg-purple-500/15 border border-purple-500/30">
                      25 Active Tools
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-white/10 relative z-10 flex gap-2">
                <Link
                  to="/app/kali-control"
                  className="flex-1 py-2 px-3 rounded-full bg-purple-600 hover:bg-purple-500 text-white font-extrabold text-xs text-center shadow-[0_0_15px_rgba(168,85,247,0.3)] transition-all flex items-center justify-center gap-1.5"
                >
                  <Terminal size={13} /> Kali Terminal
                </Link>
                <Link
                  to="/app/settings"
                  className="py-2 px-3 rounded-full border border-white/15 hover:border-purple-400/40 bg-white/[0.03] text-slate-200 hover:text-white text-xs font-bold text-center transition-all"
                >
                  Plans &amp; Config
                </Link>
              </div>
            </div>
          )}

          {/* Quick Launch Hub (Curved 2x2 Squircle Pods) */}
          <div className="rounded-3xl border border-white/10 bg-gradient-to-b from-slate-900/90 via-slate-900/60 to-slate-950/90 backdrop-blur-xl p-6 sm:p-7 relative overflow-hidden hover:border-purple-400/30 transition-all duration-300 shadow-xl">
            <div className="mb-4 pb-3 border-b border-white/5">
              <h2 className="text-base font-bold text-white tracking-tight">Security Tooling</h2>
              <p className="text-xs text-slate-400 mt-0.5">Fast-access operational modules</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Link
                to="/app/scans"
                className="p-4 rounded-2xl bg-white/[0.02] hover:bg-purple-500/10 border border-white/5 hover:border-purple-400/40 transition-all duration-300 group flex flex-col justify-between hover:shadow-[0_6px_20px_rgba(168,85,247,0.1)]"
              >
                <div className="w-10 h-10 rounded-2xl bg-purple-500/15 text-purple-400 border border-purple-500/30 flex items-center justify-center mb-2.5 group-hover:scale-110 transition-transform">
                  <Radar size={18} />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white group-hover:text-purple-300 transition-colors">Target Scan</h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">Blackbox Pentest</p>
                </div>
              </Link>

              <Link
                to="/app/github"
                className="p-4 rounded-2xl bg-white/[0.02] hover:bg-purple-500/10 border border-white/5 hover:border-purple-400/40 transition-all duration-300 group flex flex-col justify-between hover:shadow-[0_6px_20px_rgba(168,85,247,0.1)]"
              >
                <div className="w-10 h-10 rounded-2xl bg-purple-500/15 text-purple-400 border border-purple-500/30 flex items-center justify-center mb-2.5 group-hover:scale-110 transition-transform">
                  <GitBranch size={18} />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white group-hover:text-purple-300 transition-colors">GitHub CI/CD</h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">Continuous Audit</p>
                </div>
              </Link>

              <Link
                to="/app/exploits"
                className="p-4 rounded-2xl bg-white/[0.02] hover:bg-rose-500/10 border border-white/5 hover:border-rose-400/40 transition-all duration-300 group flex flex-col justify-between hover:shadow-[0_6px_20px_rgba(244,63,94,0.1)]"
              >
                <div className="w-10 h-10 rounded-2xl bg-rose-500/15 text-rose-400 border border-rose-500/30 flex items-center justify-center mb-2.5 group-hover:scale-110 transition-transform">
                  <Crosshair size={18} />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white group-hover:text-rose-300 transition-colors">Exploit Lab</h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">PoC Verification</p>
                </div>
              </Link>

              <Link
                to="/app/consultants"
                className="p-4 rounded-2xl bg-white/[0.02] hover:bg-emerald-500/10 border border-white/5 hover:border-emerald-400/40 transition-all duration-300 group flex flex-col justify-between hover:shadow-[0_6px_20px_rgba(16,185,129,0.1)]"
              >
                <div className="w-10 h-10 rounded-2xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center justify-center mb-2.5 group-hover:scale-110 transition-transform">
                  <UserCheck size={18} />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white group-hover:text-emerald-300 transition-colors">Consultants</h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">Expert Advisory</p>
                </div>
              </Link>
            </div>
          </div>

          {/* Lead Architect & Advisory Banner (Organic Squircle Shape with Aura) */}
          <div className="rounded-3xl p-6 border border-purple-500/30 bg-gradient-to-br from-purple-950/30 via-slate-900/80 to-slate-950/90 backdrop-blur-2xl hover:border-purple-400/50 shadow-[0_12px_32px_rgba(0,0,0,0.5)] transition-all duration-300 relative overflow-hidden group">
            <div className="absolute -bottom-10 -right-10 w-32 h-32 rounded-full bg-purple-500/10 blur-2xl pointer-events-none" />

            <div className="flex items-center gap-3.5 mb-3.5 relative z-10">
              <div className="w-14 h-14 rounded-2xl overflow-hidden border-2 border-purple-400/60 shadow-[0_0_20px_rgba(168,85,247,0.25)] shrink-0 bg-slate-900 ring-4 ring-purple-500/20">
                <img
                  src="/saif.png"
                  alt="Muhammad Saifudin"
                  className="w-full h-full object-cover"
                  style={{ objectPosition: '85% 85%' }}
                  onError={(e) => { e.currentTarget.src = '/fyp2_presenter.png' }}
                />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <h3 className="text-xs sm:text-sm font-bold text-white truncate">Muhammad Saifudin</h3>
                  <span className="px-2 py-0.5 text-[9px] font-black uppercase tracking-wider rounded-full bg-purple-500 text-slate-950 shadow">
                    Lead
                  </span>
                </div>
                <p className="text-[11px] text-purple-300 font-semibold mt-0.5">Lead Security Architect</p>
              </div>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4 relative z-10">
              Need custom red-team verification, manual validation, or zero-day remediation?
            </p>
            <Link
              to="/app/consultants"
              className="py-2.5 px-4 rounded-full border border-purple-500/40 bg-purple-500/10 text-purple-300 hover:bg-purple-500/20 hover:text-white group-hover:border-purple-400/70 shadow-[0_0_15px_rgba(168,85,247,0.15)] transition-all flex items-center justify-center gap-1.5 text-xs font-bold relative z-10"
            >
              <span>Consult Security Architect</span>
              <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
