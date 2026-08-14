const TOKEN_KEY = 'fyp2_token'

export const getToken = () => localStorage.getItem(TOKEN_KEY)
export const setToken = (t) => (t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY))

/** Authenticated fetch wrapper for the backend API. */
export async function apiFetch(path, { method = 'GET', body, headers = {} } = {}) {
  const token = getToken()
  const res = await fetch(path, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`)
    err.status = res.status
    err.data = data
    if (res.status === 401) setToken(null)
    throw err
  }
  return data
}

export const api = {
  login: (username, password) => apiFetch('/api/auth/login', { method: 'POST', body: { username, password } }),
  me: () => apiFetch('/api/users/me'),
  updateMe: (body) => apiFetch('/api/users/me', { method: 'PUT', body }),
  changePassword: (currentPassword, newPassword) => apiFetch('/api/users/me/password', { method: 'POST', body: { currentPassword, newPassword } }),
  status: () => apiFetch('/api/status'),
  dashboard: () => apiFetch('/api/dashboard'),
  projects: () => apiFetch('/api/projects'),
  createProject: (p) => apiFetch('/api/projects', { method: 'POST', body: p }),
  updateProject: (id, p) => apiFetch(`/api/projects/${id}`, { method: 'PUT', body: p }),
  deleteProject: (id) => apiFetch(`/api/projects/${id}`, { method: 'DELETE' }),
  projectCredentials: (id) => apiFetch(`/api/projects/${id}/credentials`),
  addProjectCredential: (id, cred) => apiFetch(`/api/projects/${id}/credentials`, { method: 'POST', body: cred }),
  updateProjectCredential: (id, credId, cred) => apiFetch(`/api/projects/${id}/credentials/${credId}`, { method: 'PUT', body: cred }),
  deleteProjectCredential: (id, credId) => apiFetch(`/api/projects/${id}/credentials/${credId}`, { method: 'DELETE' }),
  scans: () => apiFetch('/api/scans'),
  scan: (id) => apiFetch(`/api/scans/${id}`),
  startScan: (body) => apiFetch('/api/scans', { method: 'POST', body }),
  stopScan: (id) => apiFetch(`/api/scans/${id}/stop`, { method: 'POST' }),
  pauseScan: (id) => apiFetch(`/api/scans/${id}/pause`, { method: 'POST' }),
  resumeScan: (id) => apiFetch(`/api/scans/${id}/resume`, { method: 'POST' }),
  deleteScan: (id) => apiFetch(`/api/scans/${id}`, { method: 'DELETE' }),
  reRunScan: (id) => apiFetch(`/api/scans/${id}/re-run`, { method: 'POST' }),
  retryFailed: (id) => apiFetch(`/api/scans/${id}/retry-failed`, { method: 'POST' }),
  generateReport: (id, minSeverity, statusFilter, reportType, customOpts = {}) => apiFetch('/api/reports/generate', { method: 'POST', body: { scanId: id, minSeverity, statusFilter, reportType, ...customOpts } }),
  findings: () => apiFetch('/api/findings'),
  deleteFinding: (id) => apiFetch(`/api/findings/${id}`, { method: 'DELETE' }),
  setFindingStatus: (id, status) => apiFetch(`/api/findings/${id}/status`, { method: 'PUT', body: { status } }),
  setFindingSeverity: (id, severity) => apiFetch(`/api/findings/${id}/severity`, { method: 'PUT', body: { severity } }),
  findingNotes: (id) => apiFetch(`/api/findings/${id}/notes`),
  addFindingNote: (id, note) => apiFetch(`/api/findings/${id}/notes`, { method: 'POST', body: { note } }),
  cve: (id) => apiFetch(`/api/cve/${encodeURIComponent(id)}`),
  monitors: () => apiFetch('/api/monitors'),
  monitor: (id) => apiFetch(`/api/monitors/${id}`),
  createMonitor: (body) => apiFetch('/api/monitors', { method: 'POST', body }),
  setMonitorEnabled: (id, enabled) => apiFetch(`/api/monitors/${id}`, { method: 'PUT', body: { enabled } }),
  triggerMonitor: (id) => apiFetch(`/api/monitors/${id}/trigger`, { method: 'POST' }),
  deleteMonitor: (id) => apiFetch(`/api/monitors/${id}`, { method: 'DELETE' }),
  agents: () => apiFetch('/api/agents'),
  aiProviders: () => apiFetch('/api/ai/providers'),
  saveAiSettings: (body) => apiFetch('/api/settings/ai', { method: 'POST', body }),
  testAiProvider: (provider, key, model) => apiFetch('/api/ai/test', { method: 'POST', body: { provider, key, model } }),
  agentChat: (message, agent, history) => apiFetch('/api/agents/chat', { method: 'POST', body: { message, agent, history } }),
  payloadsStatus: () => apiFetch('/api/payloads/status'),
  reindexPayloads: () => apiFetch('/api/payloads/reindex', { method: 'POST' }),
  searchPayloads: (q) => apiFetch(`/api/payloads/search?q=${encodeURIComponent(q)}`),
  engineStatus: () => apiFetch('/api/engine/status'),
  analyzeTarget: (target) => apiFetch('/api/engine/analyze', { method: 'POST', body: { target } }),
  audioBriefing: (scanId) => apiFetch(`/api/scans/${scanId}/audio-briefing`, { method: 'POST' }),
  browseFilesystem: (path) => apiFetch(`/api/filesystem/browse${path ? `?path=${encodeURIComponent(path)}` : ''}`),
  startWhiteboxFolder: (body) => apiFetch('/api/scans/whitebox-folder', { method: 'POST', body }),

  // ── Exploit Engine ──
  msfStatus: () => apiFetch('/api/exploits/msf/status'),
  msfSessions: () => apiFetch('/api/exploits/msf/sessions'),
  msfSession: (id) => apiFetch(`/api/exploits/msf/sessions/${id}`),
  msfSessionCommand: (id, command) => apiFetch(`/api/exploits/msf/sessions/${id}/command`, { method: 'POST', body: { command } }),
  msfKillSession: (id) => apiFetch(`/api/exploits/msf/sessions/${id}`, { method: 'DELETE' }),
  exploitCampaigns: () => apiFetch('/api/exploits/campaigns'),
  exploitCampaign: (id) => apiFetch(`/api/exploits/campaigns/${id}`),
  launchExploitCampaign: (findingId) => apiFetch('/api/exploits/campaigns', { method: 'POST', body: { findingId } }),
  approveExploitStep: (campaignId, stepId) => apiFetch(`/api/exploits/campaigns/${campaignId}/approve`, { method: 'POST', body: { stepId } }),
  denyExploitStep: (campaignId, stepId) => apiFetch(`/api/exploits/campaigns/${campaignId}/deny`, { method: 'POST', body: { stepId } }),
  pauseExploitCampaign: (campaignId) => apiFetch(`/api/exploits/campaigns/${campaignId}/pause`, { method: 'POST' }),
  resumeExploitCampaign: (campaignId) => apiFetch(`/api/exploits/campaigns/${campaignId}/resume`, { method: 'POST' }),
  abortExploitCampaign: (campaignId) => apiFetch(`/api/exploits/campaigns/${campaignId}/abort`, { method: 'POST' }),
  checkExploit: (findingId) => apiFetch('/api/exploits/check', { method: 'POST', body: { findingId } }),
  createBackup: () => apiFetch('/api/backup/create', { method: 'POST' }),
  exportBackupUrl: '/api/backup/export',
  auditLogs: (limit = 50) => apiFetch(`/api/audit?limit=${limit}`),

  // ── Auth & Registration ──
  register: (body) => apiFetch('/api/auth/register', { method: 'POST', body }),

  // ── GitHub Automation ──
  githubStatus: () => apiFetch('/api/github/status'),
  githubConnect: (token) => apiFetch('/api/github/connect', { method: 'POST', body: { token } }),
  githubDisconnect: () => apiFetch('/api/github/disconnect', { method: 'DELETE' }),
  githubRepos: () => apiFetch('/api/github/repos'),
  githubTrackRepo: (body) => apiFetch('/api/github/repos/track', { method: 'POST', body }),
  githubScanRepo: (repoFullName, branch = 'main') => apiFetch('/api/github/scan', { method: 'POST', body: { repoFullName, branch } }),

  // ── Billing & Subscriptions ──
  billingPlans: () => apiFetch('/api/billing/plans'),
  billingSubscription: () => apiFetch('/api/billing/subscription'),
  billingCheckout: (planId, billingInterval = 'monthly') => apiFetch('/api/billing/checkout', { method: 'POST', body: { planId, billingInterval } }),
  billingHistory: () => apiFetch('/api/billing/history'),

  // ── Admin Panel ──
  adminClients: () => apiFetch('/api/admin/clients'),
  adminUpdateClientSubscription: (id, body) => apiFetch(`/api/admin/clients/${id}/subscription`, { method: 'POST', body }),
  adminOverview: () => apiFetch('/api/admin/overview'),
}

export default api
