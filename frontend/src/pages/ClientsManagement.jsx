import React, { useState, useEffect } from 'react'
import {
  Users, Shield, Search, RefreshCw, AlertCircle, CheckCircle2,
  Calendar, Layers, Edit3, X, Loader2, Sparkles, Filter, Check, TrendingUp, CreditCard
} from 'lucide-react'
import { api } from '../lib/api.js'

export default function ClientsManagement() {
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState([])
  const [overview, setOverview] = useState(null)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all') // all, active, expired, inactive
  const [editingClient, setEditingClient] = useState(null)
  const [editPlanId, setEditPlanId] = useState('pro')
  const [editQuotaTotal, setEditQuotaTotal] = useState(50)
  const [editStatus, setEditStatus] = useState('active')
  const [editDays, setEditDays] = useState(30)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const loadData = async () => {
    setLoading(true)
    setError('')
    try {
      const [clientsRes, overRes] = await Promise.all([
        api.adminClients().catch(e => { throw new Error(e.message || 'Failed to fetch clients') }),
        api.adminOverview().catch(() => null),
      ])
      setClients(clientsRes.clients || [])
      setOverview(overRes)
    } catch (err) {
      setError(err.message || 'Failed to load client management data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleOpenEdit = (c) => {
    setEditingClient(c)
    setEditPlanId(c.plan_id === 'enterprise' ? 'enterprise' : 'pro')
    setEditQuotaTotal(c.scan_quota_total || 50)
    setEditStatus(c.effective_status === 'expired' ? 'active' : (c.sub_status || 'active'))
    setEditDays(30)
    setError('')
    setSuccess('')
  }

  const handleSaveClient = async (e) => {
    e.preventDefault()
    if (!editingClient) return
    setSaving(true)
    setError('')
    setSuccess('')
    try {
      await api.adminUpdateClientSubscription(editingClient.id, {
        planId: editPlanId,
        quotaTotal: Number(editQuotaTotal),
        status: editStatus,
        extendDays: Number(editDays),
      })
      setSuccess(`✅ Successfully updated subscription for ${editingClient.username}!`)
      setEditingClient(null)
      await loadData()
    } catch (err) {
      setError(err.message || 'Failed to update client subscription')
    } finally {
      setSaving(false)
    }
  }

  const filtered = clients.filter(c => {
    const term = search.toLowerCase()
    const matchesSearch =
      (c.username || '').toLowerCase().includes(term) ||
      (c.email || '').toLowerCase().includes(term) ||
      (c.github_username || '').toLowerCase().includes(term)

    if (statusFilter === 'active') return matchesSearch && c.effective_status === 'active'
    if (statusFilter === 'expired') return matchesSearch && c.effective_status === 'expired'
    if (statusFilter === 'inactive') return matchesSearch && (c.effective_status === 'inactive' || !c.sub_status)
    return matchesSearch
  })

  return (
    <div className="space-y-6 animate-in fade-in duration-300 pb-16">
      {/* Top Banner */}
      <div className="card p-6 border-white/10 relative overflow-hidden bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-indigo-950/40">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <Users size={160} className="text-cyan-400" />
        </div>

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Users size={22} />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Client Management & Subscriptions</h1>
              <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30 uppercase tracking-wide">
                Admin Control
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Monitor registered clients, manage scan quotas, extend subscription periods, and inspect automated audit activity across SentinelAI.
            </p>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="btn-secondary text-xs py-2 px-3.5 flex items-center gap-1.5 self-start md:self-auto"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh List
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-slate-400 font-semibold">Total Registered Clients</div>
          <div className="text-2xl font-black text-white mt-1">{clients.length}</div>
        </div>
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-emerald-400 font-semibold">Active Subscriptions</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">
            {clients.filter(c => c.effective_status === 'active').length}
          </div>
        </div>
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-rose-400 font-semibold">Expired / Inactive</div>
          <div className="text-2xl font-black text-rose-400 mt-1">
            {clients.filter(c => c.effective_status === 'expired' || c.effective_status === 'inactive').length}
          </div>
        </div>
        <div className="card p-4 border-white/10 bg-slate-950/60">
          <div className="text-xs text-cyan-400 font-semibold">Total Scans Executed</div>
          <div className="text-2xl font-black text-cyan-300 mt-1">
            {clients.reduce((acc, c) => acc + (Number(c.total_scans) || 0), 0)}
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 flex items-center gap-3 text-sm">
          <AlertCircle size={18} className="shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}
      {success && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-3 text-sm">
          <CheckCircle2 size={18} className="shrink-0 text-emerald-400" />
          <span>{success}</span>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="card p-4 border-white/10 bg-slate-950/60 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-80">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by username, email, or GitHub..."
            className="input !py-2 !pl-9 text-xs w-full"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs text-slate-400 font-semibold">Status:</span>
          {['all', 'active', 'expired', 'inactive'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold capitalize transition-all cursor-pointer ${
                statusFilter === st
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                  : 'bg-slate-900 border border-white/10 text-slate-400 hover:text-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Clients Table */}
      <div className="card overflow-hidden border-white/10 bg-slate-950/70">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 border-b border-white/10 text-slate-400 uppercase font-bold text-[10px] tracking-wider">
              <tr>
                <th className="px-5 py-3.5">Client User</th>
                <th className="px-5 py-3.5">Plan & Quota</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5">GitHub Account</th>
                <th className="px-5 py-3.5">Scans Run</th>
                <th className="px-5 py-3.5">Next Expiry</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-5 py-8 text-center text-slate-500">
                    No clients found matching your search criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((c) => {
                  const isUnlimited = (c.scan_quota_total || 0) >= 9000
                  const used = c.scan_quota_used || 0
                  const total = c.scan_quota_total || 0
                  const pct = isUnlimited ? 100 : Math.min(100, Math.round((used / (total || 1)) * 100))

                  return (
                    <tr key={c.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-bold text-white text-sm">{c.username}</div>
                        <div className="text-[11px] text-slate-400">{c.email || 'No email'}</div>
                        {c.role === 'admin' && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30 uppercase mt-1 inline-block">
                            Administrator
                          </span>
                        )}
                      </td>

                      <td className="px-5 py-4">
                        <div className="font-bold text-cyan-300">{c.plan_name || 'No Plan'}</div>
                        <div className="text-[11px] text-slate-400 mt-1 font-mono">
                          {isUnlimited ? 'Unlimited' : `${used} / ${total} scans (${c.remaining_quota} left)`}
                        </div>
                        <div className="w-24 h-1.5 bg-slate-900 rounded-full overflow-hidden mt-1 border border-white/10">
                          <div
                            className={`h-full ${pct > 80 ? 'bg-red-500' : 'bg-cyan-400'}`}
                            style={{ width: `${isUnlimited ? 100 : pct}%` }}
                          />
                        </div>
                      </td>

                      <td className="px-5 py-4">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border ${
                          c.effective_status === 'active'
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                            : c.effective_status === 'expired'
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                            : 'bg-slate-700/30 text-slate-400 border-slate-600/30'
                        }`}>
                          {c.effective_status}
                        </span>
                      </td>

                      <td className="px-5 py-4 font-mono text-slate-300">
                        {c.github_username ? (
                          <span className="text-cyan-400 flex items-center gap-1">
                            @{c.github_username}
                          </span>
                        ) : (
                          <span className="text-slate-600">Not linked</span>
                        )}
                      </td>

                      <td className="px-5 py-4 font-bold text-white">
                        {c.total_scans || 0}
                      </td>

                      <td className="px-5 py-4 text-slate-400">
                        {c.current_period_end ? (
                          <span className={c.isExpired ? 'text-rose-400 font-bold' : ''}>
                            {new Date(c.current_period_end).toLocaleDateString()}
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      <td className="px-5 py-4 text-right">
                        <button
                          onClick={() => handleOpenEdit(c)}
                          className="btn-secondary text-[11px] py-1.5 px-3 hover:border-cyan-400/50 hover:text-cyan-300 inline-flex items-center gap-1.5"
                        >
                          <Edit3 size={13} /> Manage Quota
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Quota / Subscription Modal */}
      {editingClient && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="glass rounded-3xl border border-white/20 p-6 sm:p-7 w-full max-w-md shadow-2xl relative space-y-5">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <h3 className="font-extrabold text-white text-base flex items-center gap-2">
                  <Shield size={18} className="text-cyan-400" /> Manage Client Subscription
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Update plan, scan quota, or extend duration for <strong>{editingClient.username}</strong>
                </p>
              </div>
              <button
                onClick={() => setEditingClient(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveClient} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="font-bold text-slate-300 uppercase">Subscription Plan</label>
                <select
                  className="input !py-2 text-xs w-full"
                  value={editPlanId}
                  onChange={(e) => {
                    setEditPlanId(e.target.value)
                    if (e.target.value === 'enterprise') setEditQuotaTotal(9999)
                    else setEditQuotaTotal(50)
                  }}
                >
                  <option value="pro">SentinelAI Pro (50 Scans)</option>
                  <option value="enterprise">SentinelAI Enterprise (Unlimited Scans)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-bold text-slate-300 uppercase">Total Scan Quota</label>
                  <input
                    type="number"
                    min="1"
                    className="input !py-2 text-xs w-full font-mono"
                    value={editQuotaTotal}
                    onChange={(e) => setEditQuotaTotal(e.target.value)}
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="font-bold text-slate-300 uppercase">Account Status</label>
                  <select
                    className="input !py-2 text-xs w-full"
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value)}
                  >
                    <option value="active">Active (Permitted)</option>
                    <option value="expired">Expired (Locked)</option>
                    <option value="inactive">Inactive</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="font-bold text-slate-300 uppercase">Extend Expiration By (Days)</label>
                <input
                  type="number"
                  min="1"
                  className="input !py-2 text-xs w-full font-mono"
                  value={editDays}
                  onChange={(e) => setEditDays(e.target.value)}
                  required
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setEditingClient(null)}
                  className="btn-secondary text-xs py-2 px-4"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="btn-primary text-xs py-2 px-4 shadow-glow flex items-center gap-1.5"
                >
                  {saving && <Loader2 size={13} className="animate-spin" />}
                  {saving ? 'Saving...' : 'Save & Update Client'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
