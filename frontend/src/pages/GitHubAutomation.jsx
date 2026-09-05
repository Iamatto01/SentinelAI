import React, { useState, useEffect } from 'react'
import {
  GitBranch, GitPullRequest, GitCommit, Shield, CheckCircle2, XCircle, AlertTriangle,
  Play, RefreshCw, ExternalLink, Lock, Unlock, Mail, Settings, Zap, ArrowRight,
  Search, Key, Check, Copy, FileCode, Layers, Loader2, Sparkles, PlusCircle, Trash2
} from 'lucide-react'
import { api } from '../lib/api.js'
import { useNavigate } from 'react-router-dom'

export default function GitHubAutomation() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [ghStatus, setGhStatus] = useState(null)
  const [subscription, setSubscription] = useState(null)
  const [repos, setRepos] = useState([])
  const [search, setSearch] = useState('')
  const [filterTracked, setFilterTracked] = useState('all') // all, tracked, untracked
  const [tokenInput, setTokenInput] = useState('')
  const [connecting, setConnecting] = useState(false)
  const [scanningRepo, setScanningRepo] = useState(null)
  const [savingRepo, setSavingRepo] = useState(null)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')
  const [showWebhookGuide, setShowWebhookGuide] = useState(false)
  const [copiedWebhook, setCopiedWebhook] = useState(false)

  const loadData = async () => {
    setLoading(true)
    setError('')
    try {
      const [statusRes, subRes] = await Promise.all([
        api.githubStatus().catch(() => ({ connected: false })),
        api.billingSubscription().catch(() => null),
      ])
      setGhStatus(statusRes)
      setSubscription(subRes)

      if (statusRes.connected) {
        const repoRes = await api.githubRepos().catch(e => {
          setError(`Could not list repositories: ${e.message}`)
          return { repos: [] }
        })
        setRepos(repoRes.repos || [])
      }
    } catch (err) {
      setError(err.message || 'Failed to load GitHub automation status')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleConnect = async (e) => {
    e.preventDefault()
    if (!tokenInput.trim()) return
    setConnecting(true)
    setError('')
    setSuccessMsg('')
    try {
      await api.githubConnect(tokenInput.trim())
      setSuccessMsg('GitHub account successfully connected!')
      setTokenInput('')
      await loadData()
    } catch (err) {
      setError(err.message || 'Failed to connect GitHub token')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async () => {
    if (!window.confirm('Are you sure you want to unlink your GitHub account?')) return
    setLoading(true)
    try {
      await api.githubDisconnect()
      setGhStatus({ connected: false })
      setRepos([])
      setSuccessMsg('GitHub account unlinked.')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const toggleRepoTracking = async (repo, updateFields = {}) => {
    setSavingRepo(repo.full_name)
    try {
      const isCurrentlyTracked = repo.isTracked
      const nextTracked = updateFields.isTracked !== undefined ? updateFields.isTracked : !isCurrentlyTracked

      await api.githubTrackRepo({
        repoFullName: repo.full_name,
        repoUrl: repo.html_url,
        defaultBranch: repo.default_branch,
        isPrivate: repo.is_private,
        isTracked: nextTracked,
        autoScanPush: updateFields.autoScanPush !== undefined ? updateFields.autoScanPush : (repo.autoScanPush ? 1 : 0),
        autoScanPr: updateFields.autoScanPr !== undefined ? updateFields.autoScanPr : (repo.autoScanPr ? 1 : 0),
        emailReport: updateFields.emailReport !== undefined ? updateFields.emailReport : (repo.emailReport ? 1 : 0),
      })

      // Update local state
      setRepos(prev => prev.map(r => {
        if (r.full_name === repo.full_name) {
          return {
            ...r,
            isTracked: nextTracked,
            ...updateFields,
          }
        }
        return r
      }))
    } catch (err) {
      setError(`Failed to update settings for ${repo.full_name}: ${err.message}`)
    } finally {
      setSavingRepo(null)
    }
  }

  const handleTriggerScan = async (repo) => {
    if (!subscription?.isSubscribed) {
      setError('An active SentinelAI paid subscription is required to run scans. Please choose a plan in Billing.')
      navigate('/app/billing')
      return
    }

    setScanningRepo(repo.full_name)
    setError('')
    setSuccessMsg('')
    try {
      const res = await api.githubScanRepo(repo.full_name, repo.default_branch)
      setSuccessMsg(`🚀 Audit started for ${repo.full_name} (${res.filesCount} files analyzed). Report will be emailed automatically.`)
      setTimeout(() => {
        navigate(`/app/scans/${res.scanId}`)
      }, 1500)
    } catch (err) {
      if (err.data?.upgradeRequired) {
        setError(`Subscription required or quota exceeded: ${err.message}. Please upgrade your plan in Billing.`)
        navigate('/app/billing')
      } else {
        setError(`Scan trigger failed: ${err.message}`)
      }
    } finally {
      setScanningRepo(null)
    }
  }

  const filteredRepos = repos.filter(r => {
    const matchesSearch = r.full_name.toLowerCase().includes(search.toLowerCase()) || (r.language || '').toLowerCase().includes(search.toLowerCase())
    if (filterTracked === 'tracked') return matchesSearch && r.isTracked
    if (filterTracked === 'untracked') return matchesSearch && !r.isTracked
    return matchesSearch
  })

  const webhookUrl = `${window.location.origin}/api/github/webhook`

  const copyWebhook = () => {
    navigator.clipboard.writeText(webhookUrl)
    setCopiedWebhook(true)
    setTimeout(() => setCopiedWebhook(false), 2500)
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-300 pb-16">
      {/* Top Banner Header */}
      <div className="card p-6 border-white/[0.07] relative overflow-hidden bg-[#161616]">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <GitBranch size={160} className="text-cyan-400" />
        </div>

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <GitBranch size={22} />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">SentinelAI GitHub Automation</h1>
              <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30 uppercase tracking-wide">
                Continuous Audit
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Connect your repositories to automatically pull source code, run AI security audits, generate executive PDF reports, and deliver findings to your email on every <code className="text-cyan-300 font-mono bg-white/5 px-1.5 py-0.5 rounded">git push</code> or Pull Request.
            </p>
          </div>

          {subscription && (
            <div className={`flex items-center gap-4 border p-3.5 rounded-2xl ${
              subscription.isSubscribed
                ? 'bg-slate-950/60 border-white/10'
                : 'bg-amber-950/30 border-amber-500/30'
            }`}>
              <div className="space-y-0.5">
                <div className="text-xs text-slate-400">Plan Status</div>
                <div className="text-sm font-bold text-white flex items-center gap-1.5">
                  <Sparkles size={14} className="text-cyan-400" /> {subscription.isSubscribed ? subscription.plan?.name : 'No Active Plan'}
                </div>
              </div>
              <div className="h-8 w-px bg-white/10" />
              <div className="space-y-0.5">
                <div className="text-xs text-slate-400">Quota</div>
                <div className={`text-sm font-mono font-bold ${subscription.isSubscribed ? 'text-cyan-300' : 'text-amber-400'}`}>
                  {subscription.isSubscribed ? (subscription.isUnlimited ? 'Unlimited' : `${subscription.remainingQuota} left`) : 'Subscription Required'}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Subscription Callout Banner if Inactive */}
      {subscription && !subscription.isSubscribed && (
        <div className="card p-4 border-amber-500/40 bg-amber-500/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle size={20} className="text-amber-400 shrink-0" />
            <div>
              <div className="text-sm font-bold text-amber-200">SentinelAI Paid Subscription Required</div>
              <div className="text-xs text-amber-300/80">Subscribe to a plan to unlock automated code audits, GitHub continuous webhooks, and PDF email reporting.</div>
            </div>
          </div>
          <button
            onClick={() => navigate('/app/billing')}
            className="btn-primary text-xs py-2 px-4 shadow-glow flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
          >
            <Zap size={14} /> Subscribe in Billing
          </button>
        </div>
      )}

      {/* Messages */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 flex items-center gap-3 text-sm animate-in fade-in">
          <AlertTriangle size={18} className="shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-3 text-sm animate-in fade-in">
          <CheckCircle2 size={18} className="shrink-0 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Connection State Card */}
      {!ghStatus?.connected ? (
        <div className="card p-8 border-cyan-500/30 bg-gradient-to-b from-slate-900/80 to-slate-950/80 space-y-6">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-2xl bg-cyan-500/20 text-cyan-400 grid place-items-center border border-cyan-500/30">
              <Key size={20} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Connect Your GitHub Account</h2>
              <p className="text-xs text-slate-400">Provide a GitHub Personal Access Token (classic or fine-grained) to link your repositories.</p>
            </div>
          </div>

          <form onSubmit={handleConnect} className="space-y-4 max-w-xl">
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>GitHub Personal Access Token (PAT)</span>
                <a
                  href="https://github.com/settings/tokens/new?scopes=repo,read:user"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                >
                  Generate Token on GitHub <ExternalLink size={12} />
                </a>
              </label>
              <input
                type="password"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-400 font-mono transition-colors"
                required
              />
              <p className="text-[11px] text-slate-500">
                Required Scopes: <code className="text-slate-400 bg-white/5 px-1 py-0.5 rounded">repo</code> (Full control of private repositories) or <code className="text-slate-400 bg-white/5 px-1 py-0.5 rounded">read:user</code>.
              </p>
            </div>

            <button
              type="submit"
              disabled={connecting}
              className="btn-primary py-2.5 px-6 rounded-xl flex items-center gap-2 text-sm font-semibold shadow-glow"
            >
              {connecting ? <Loader2 size={16} className="animate-spin" /> : <Zap size={16} />}
              {connecting ? 'Verifying Token...' : 'Connect GitHub Account'}
            </button>
          </form>
        </div>
      ) : (
        /* Connected Profile Bar & Controls */
        <div className="space-y-6">
          <div className="card p-5 border-white/10 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60">
            <div className="flex items-center gap-3.5">
              {ghStatus.integration?.avatar_url ? (
                <img
                  src={ghStatus.integration.avatar_url}
                  alt={ghStatus.integration.github_username}
                  className="w-11 h-11 rounded-2xl border border-cyan-500/40 p-0.5 bg-slate-950"
                />
              ) : (
                <div className="w-11 h-11 rounded-2xl bg-cyan-500/20 text-cyan-400 grid place-items-center border border-cyan-500/40 font-bold text-lg">
                  {ghStatus.integration?.github_username?.[0]?.toUpperCase() || 'G'}
                </div>
              )}
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white text-base">@{ghStatus.integration?.github_username}</span>
                  <span className="flex items-center gap-1 text-[10px] bg-emerald-500/20 text-emerald-300 font-semibold px-2 py-0.5 rounded-full border border-emerald-500/30">
                    <CheckCircle2 size={10} /> Connected
                  </span>
                </div>
                <p className="text-xs text-slate-400">
                  {repos.length} total repositories loaded &bull; {repos.filter(r => r.isTracked).length} tracked for auto-audits
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowWebhookGuide(!showWebhookGuide)}
                className="btn-secondary text-xs py-2 px-3.5 flex items-center gap-1.5"
              >
                <Layers size={14} /> Webhook Setup
              </button>
              <button
                onClick={loadData}
                disabled={loading}
                className="btn-secondary text-xs py-2 px-3 flex items-center gap-1.5"
                title="Refresh Repositories"
              >
                <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
              </button>
              <button
                onClick={handleDisconnect}
                className="p-2 rounded-xl bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors text-xs"
                title="Disconnect Account"
              >
                <Trash2 size={16} />
              </button>
            </div>
          </div>

          {/* Webhook Guide Modal / Drawer */}
          {showWebhookGuide && (
            <div className="card p-5 border-cyan-500/30 bg-slate-950/90 space-y-4 animate-in fade-in">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-white text-sm">
                  <Zap size={16} className="text-cyan-400" />
                  GitHub Webhook Auto-Trigger Setup
                </div>
                <button
                  onClick={() => setShowWebhookGuide(false)}
                  className="text-slate-400 hover:text-white text-xs"
                >
                  Close
                </button>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                To trigger instant security scans automatically whenever code is pushed or a PR is created on GitHub, add this Webhook URL to your repository's <strong>Settings &gt; Webhooks</strong> on GitHub.
              </p>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={webhookUrl}
                  className="bg-slate-900 border border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-cyan-300 flex-1 select-all"
                />
                <button
                  onClick={copyWebhook}
                  className="btn-primary text-xs py-2 px-4 flex items-center gap-1.5 shrink-0"
                >
                  {copiedWebhook ? <Check size={14} /> : <Copy size={14} />}
                  {copiedWebhook ? 'Copied' : 'Copy URL'}
                </button>
              </div>
              <div className="text-[11px] text-slate-500 flex items-center gap-4">
                <span>&bull; Content type: <strong>application/json</strong></span>
                <span>&bull; Events: <strong>Pushes</strong> and <strong>Pull requests</strong></span>
              </div>
            </div>
          )}

          {/* Repositories Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search repositories by name or language..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900/90 border border-white/15 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 transition-colors"
              />
            </div>

            <div className="flex items-center gap-1 bg-slate-900/90 border border-white/10 p-1 rounded-xl">
              <button
                onClick={() => setFilterTracked('all')}
                className={`px-3 py-1 text-xs rounded-lg font-medium transition-colors ${filterTracked === 'all' ? 'bg-cyan-500/20 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                All ({repos.length})
              </button>
              <button
                onClick={() => setFilterTracked('tracked')}
                className={`px-3 py-1 text-xs rounded-lg font-medium transition-colors ${filterTracked === 'tracked' ? 'bg-cyan-500/20 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Tracked ({repos.filter(r => r.isTracked).length})
              </button>
              <button
                onClick={() => setFilterTracked('untracked')}
                className={`px-3 py-1 text-xs rounded-lg font-medium transition-colors ${filterTracked === 'untracked' ? 'bg-cyan-500/20 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-slate-200'}`}
              >
                Untracked ({repos.filter(r => !r.isTracked).length})
              </button>
            </div>
          </div>

          {/* Repositories Table / Grid */}
          {loading ? (
            <div className="py-16 grid place-items-center">
              <Loader2 size={32} className="text-cyan-400 animate-spin" />
            </div>
          ) : filteredRepos.length === 0 ? (
            <div className="card p-12 text-center border-dashed border-white/10 space-y-3">
              <FileCode size={36} className="text-slate-600 mx-auto" />
              <div className="text-sm font-semibold text-slate-300">No repositories found matching your search.</div>
              <p className="text-xs text-slate-500">Try adjusting your search filter or refreshing the list.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {filteredRepos.map((repo) => {
                const isScanning = scanningRepo === repo.full_name
                const isSaving = savingRepo === repo.full_name

                return (
                  <div
                    key={repo.id}
                    className={`card p-5 border transition-all duration-200 ${
                      repo.isTracked ? 'border-cyan-500/30 bg-slate-900/80 shadow-lg shadow-cyan-950/20' : 'border-white/10 bg-slate-950/60 opacity-80 hover:opacity-100'
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                      {/* Repo Info */}
                      <div className="space-y-1.5 min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <a
                            href={repo.html_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-base font-bold text-white hover:text-cyan-400 transition-colors flex items-center gap-1.5 truncate"
                          >
                            {repo.full_name}
                            <ExternalLink size={13} className="text-slate-500 shrink-0" />
                          </a>

                          {repo.is_private ? (
                            <span className="text-[10px] px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/20 font-semibold flex items-center gap-1">
                              <Lock size={10} /> Private
                            </span>
                          ) : (
                            <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-white/10 font-semibold flex items-center gap-1">
                              <Unlock size={10} /> Public
                            </span>
                          )}

                          {repo.language && (
                            <span className="text-[10px] px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-mono">
                              {repo.language}
                            </span>
                          )}

                          <span className="text-xs text-slate-500 font-mono">
                            branch: {repo.default_branch}
                          </span>
                        </div>

                        {repo.description && (
                          <p className="text-xs text-slate-400 line-clamp-1">{repo.description}</p>
                        )}

                        {repo.lastScanAt && (
                          <div className="text-[11px] text-slate-500 flex items-center gap-2">
                            <span>Last audited: {new Date(repo.lastScanAt).toLocaleString()}</span>
                            {repo.lastRiskScore != null && (
                              <span className="font-semibold text-cyan-400">
                                &bull; Risk Score: {Number(repo.lastRiskScore).toFixed(1)}/10
                              </span>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Controls & Triggers */}
                      <div className="flex flex-wrap items-center gap-3 lg:self-center">
                        {/* Automation Switches */}
                        {repo.isTracked && (
                          <div className="flex items-center gap-3 bg-slate-950/80 border border-white/10 px-3 py-1.5 rounded-xl text-xs">
                            <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white" title="Auto scan on git push">
                              <input
                                type="checkbox"
                                checked={repo.autoScanPush}
                                onChange={(e) => toggleRepoTracking(repo, { autoScanPush: e.target.checked ? 1 : 0 })}
                                className="accent-cyan-400 rounded"
                              />
                              <GitCommit size={13} className="text-cyan-400" /> Push
                            </label>

                            <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white" title="Auto scan on pull request">
                              <input
                                type="checkbox"
                                checked={repo.autoScanPr}
                                onChange={(e) => toggleRepoTracking(repo, { autoScanPr: e.target.checked ? 1 : 0 })}
                                className="accent-cyan-400 rounded"
                              />
                              <GitPullRequest size={13} className="text-cyan-400" /> PR
                            </label>

                            <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white" title="Send email report on completion">
                              <input
                                type="checkbox"
                                checked={repo.emailReport}
                                onChange={(e) => toggleRepoTracking(repo, { emailReport: e.target.checked ? 1 : 0 })}
                                className="accent-cyan-400 rounded"
                              />
                              <Mail size={13} className="text-emerald-400" /> Email PDF
                            </label>
                          </div>
                        )}

                        {/* Track Toggle */}
                        <button
                          onClick={() => toggleRepoTracking(repo)}
                          disabled={isSaving}
                          className={`text-xs py-2 px-3.5 rounded-xl font-semibold transition-colors flex items-center gap-1.5 ${
                            repo.isTracked
                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-red-500/20 hover:text-red-300 hover:border-red-500/30'
                              : 'btn-secondary'
                          }`}
                        >
                          {isSaving ? <Loader2 size={13} className="animate-spin" /> : repo.isTracked ? <Check size={13} /> : <PlusCircle size={13} />}
                          {repo.isTracked ? 'Tracked' : 'Enable Auto-Audit'}
                        </button>

                        {/* Scan Now Button */}
                        <button
                          onClick={() => handleTriggerScan(repo)}
                          disabled={isScanning}
                          className="btn-primary text-xs py-2 px-4 rounded-xl flex items-center gap-1.5 shadow-glow"
                        >
                          {isScanning ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
                          {isScanning ? 'Pulling & Scanning...' : 'Audit Repo Now'}
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
