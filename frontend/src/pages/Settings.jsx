import React, { useEffect, useState } from 'react'
import { Loader2, Save, KeyRound, UserCircle, CheckCircle2, Database, Bell, Building2, Moon, Upload, Sparkles } from 'lucide-react'
import { api } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'

export default function Settings() {
  const { user, setUser } = useAuth()
  const [email, setEmail] = useState('')
  const [pw, setPw] = useState({ currentPassword: '', newPassword: '', confirm: '' })
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const isAdmin = user?.role === 'admin'
  const isClient = user?.role === 'client'

  const [apiKeys, setApiKeys] = useState({ 
    groq: '', groqModel: 'llama-3.3-70b-versatile', 
    openrouter: '', openrouterModel: 'inclusionai/ling-3.0-flash:free',
    bandelbanget: '', bandelbangetModel: 'deepseek-v4-pro'
  })
  const [testResults, setTestResults] = useState({})
  const [notifs, setNotifs] = useState({ scanFinish: true, criticalAlert: true, dnd: false })
  const [branding, setBranding] = useState({ companyName: '', logo: '' })

  useEffect(() => {
    api.me().then((u) => setEmail(u.email || '')).catch(() => {})
    if (isAdmin) {
      api.aiProviders().then((data) => {
        const p = data.providers || []
        const groq = p.find(x => x.id === 'groq') || {}
        const opr = p.find(x => x.id === 'openrouter') || {}
        const ban = p.find(x => x.id === 'bandelbanget') || {}
        setApiKeys({
          groq: groq.key || '', groqModel: groq.model || 'llama-3.3-70b-versatile',
          openrouter: opr.key || '', openrouterModel: opr.model || 'inclusionai/ling-3.0-flash:free',
          bandelbanget: ban.key || '', bandelbangetModel: ban.model || 'deepseek-v4-pro'
        })
      }).catch(() => {})
    }
  }, [isAdmin])

  async function saveProfile(e) {
    e.preventDefault(); setMsg(''); setErr('')
    try { const u = await api.updateMe({ email }); setUser?.(u); setMsg('Profile saved.') }
    catch (e2) { setErr(e2.message) }
  }

  async function savePassword(e) {
    e.preventDefault(); setMsg(''); setErr('')
    if (pw.newPassword !== pw.confirm) { setErr('New passwords do not match'); return }
    try { await api.changePassword(pw.currentPassword, pw.newPassword); setMsg('Password changed.'); setPw({ currentPassword: '', newPassword: '', confirm: '' }) }
    catch (e2) { setErr(e2.message) }
  }

  async function saveApiKeys(e) { 
    e.preventDefault(); 
    setMsg(''); setErr('')
    try {
      await api.saveAiSettings(apiKeys)
      setMsg('AI Settings updated successfully.')
    } catch(err) {
      setErr(err.message)
    }
  }

  async function testProvider(provider, key, model) {
    if (!key) return setTestResults(prev => ({ ...prev, [provider]: { error: 'Please enter a key first' } }))
    setTestResults(prev => ({ ...prev, [provider]: { loading: true } }))
    try {
      const res = await api.testAiProvider(provider, key, model)
      if (res.success) {
        setTestResults(prev => ({ ...prev, [provider]: { success: true, reply: res.reply, loading: false } }))
      } else {
        setTestResults(prev => ({ ...prev, [provider]: { error: res.error, loading: false } }))
      }
    } catch(err) {
      setTestResults(prev => ({ ...prev, [provider]: { error: err.message, loading: false } }))
    }
  }
  
  function saveNotifs(e) { e.preventDefault(); setMsg('Notification preferences saved.'); setErr('') }
  function saveBranding(e) { e.preventDefault(); setMsg('Company branding updated.'); setErr('') }

  return (
    <div className="space-y-8 motion-fade-up">
      <div className="flex flex-col gap-2 pb-4 border-b border-white/10">
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          System & Account Settings
        </h1>
        <p className="text-xs text-slate-400 max-w-xl">
          Configure profile details, AI provider API keys, security credentials, and platform notifications.
        </p>
      </div>

      {msg && <div className="card p-4 text-emerald-400 text-xs font-bold flex items-center gap-3 border-emerald-500/30 bg-emerald-500/10"><CheckCircle2 size={18} /> {msg}</div>}
      {err && <div className="card p-4 text-rose-400 text-xs font-bold flex items-center gap-3 border-rose-500/30 bg-rose-500/10">{err}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
        {/* LEFT COLUMN */}
        <div className="space-y-8">
          <form onSubmit={saveProfile} className="card p-6 space-y-5 hover:border-cyan-400/40 transition-all duration-300">
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-base font-bold text-white"><UserCircle size={18} className="text-cyan-400" /> User Profile</h3>
              <span className="chip bg-cyan-500/15 text-cyan-300 border-cyan-400/30">{user?.role}</span>
            </div>
            <div className="space-y-4">
              <div><label className="label">Username</label><input className="input !bg-white/5 opacity-80" value={user?.username || ''} disabled /></div>
              <div><label className="label">Email Address</label><input className="input" value={email} onChange={(e) => setEmail(e.target.value)} /></div>
            </div>
            <div className="flex justify-end pt-2"><button type="submit" className="btn-primary text-xs"><Save size={15} /> Save Profile</button></div>
          </form>

          <form onSubmit={savePassword} className="card p-6 space-y-5 hover:border-cyan-400/40 transition-all duration-300">
            <h3 className="flex items-center gap-2 text-base font-bold text-white"><KeyRound size={18} className="text-purple-400" /> Security Credentials</h3>
            <div className="space-y-4">
              <div><label className="label">Current password</label><input type="password" className="input" value={pw.currentPassword} onChange={(e) => setPw({ ...pw, currentPassword: e.target.value })} required /></div>
              <div><label className="label">New password</label><input type="password" className="input" value={pw.newPassword} onChange={(e) => setPw({ ...pw, newPassword: e.target.value })} required /></div>
              <div><label className="label">Confirm new password</label><input type="password" className="input" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} required /></div>
            </div>
            <div className="flex justify-end pt-2"><button type="submit" className="btn-primary text-xs"><Save size={15} /> Update Password</button></div>
          </form>
        </div>

        {/* RIGHT COLUMN */}
        <div className="space-y-8">
          {isAdmin && (
            <form onSubmit={saveApiKeys} className="card p-6 space-y-5 hover:border-cyan-400/40 transition-all duration-300 border-cyan-500/20">
              <div>
                <h3 className="flex items-center gap-2 text-base font-bold text-white"><Database size={18} className="text-cyan-400" /> AI Provider API Keys</h3>
                <p className="text-xs text-slate-400 mt-1">Configure specialist AI LLM providers.</p>
              </div>
              <div className="space-y-5">
                {/* Groq */}
                <div className="space-y-2 p-4 bg-slate-900/60 rounded-xl border border-white/10">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="text-xs font-bold text-white">Groq Cloud AI</h4>
                    <button type="button" onClick={() => testProvider('groq', apiKeys.groq, apiKeys.groqModel)} className="btn-ghost text-xs py-1 px-2.5">
                      {testResults.groq?.loading ? <Loader2 size={12} className="animate-spin text-cyan-400" /> : 'Test Model'}
                    </button>
                  </div>
                  <div><label className="text-[10px] text-slate-400 uppercase font-bold">API Key</label><input type="password" className="input text-xs" placeholder="gsk_..." value={apiKeys.groq} onChange={(e) => setApiKeys({...apiKeys, groq: e.target.value})} /></div>
                  <div><label className="text-[10px] text-slate-400 uppercase font-bold">Model</label><input type="text" className="input text-xs" value={apiKeys.groqModel} onChange={(e) => setApiKeys({...apiKeys, groqModel: e.target.value})} /></div>
                  {testResults.groq?.success && <p className="text-xs text-emerald-400 mt-2 p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">{testResults.groq.reply}</p>}
                  {testResults.groq?.error && <p className="text-xs text-rose-400 mt-2 p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">{testResults.groq.error}</p>}
                </div>

                {/* OpenRouter */}
                <div className="space-y-2 p-4 bg-slate-900/60 rounded-xl border border-white/10">
                  <div className="flex items-center justify-between mb-1">
                    <h4 className="text-xs font-bold text-white">OpenRouter AI</h4>
                    <button type="button" onClick={() => testProvider('openrouter', apiKeys.openrouter, apiKeys.openrouterModel)} className="btn-ghost text-xs py-1 px-2.5">
                      {testResults.openrouter?.loading ? <Loader2 size={12} className="animate-spin text-cyan-400" /> : 'Test Model'}
                    </button>
                  </div>
                  <div><label className="text-[10px] text-slate-400 uppercase font-bold">API Key</label><input type="password" className="input text-xs" placeholder="sk-or-v1-..." value={apiKeys.openrouter} onChange={(e) => setApiKeys({...apiKeys, openrouter: e.target.value})} /></div>
                  <div><label className="text-[10px] text-slate-400 uppercase font-bold">Model</label><input type="text" className="input text-xs" value={apiKeys.openrouterModel} onChange={(e) => setApiKeys({...apiKeys, openrouterModel: e.target.value})} /></div>
                  {testResults.openrouter?.success && <p className="text-xs text-emerald-400 mt-2 p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">{testResults.openrouter.reply}</p>}
                  {testResults.openrouter?.error && <p className="text-xs text-rose-400 mt-2 p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">{testResults.openrouter.error}</p>}
                </div>
              </div>
              <div className="flex justify-end pt-2"><button type="submit" className="btn-primary text-xs"><Save size={15} /> Save API Keys</button></div>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}

