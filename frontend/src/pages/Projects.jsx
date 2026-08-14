import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, Plus, Trash2, FolderKanban, X, Radar, Edit, Sparkles, ExternalLink, Play, Upload, Image } from 'lucide-react'
import { api } from '../lib/api.js'
import { useAuth } from '../lib/AuthContext.jsx'
import NewScanModal from '../components/NewScanModal.jsx'
import RequestScanModal from '../components/RequestScanModal.jsx'

const COVER_OPTIONS = [
  { id: '/project-covers/cyber_shield.png', label: 'Cyber Shield', desc: 'Futuristic dark neon digital shield' },
  { id: '/project-covers/quantum_encryption.png', label: 'Quantum Encryption', desc: 'Glowing cyan crystal lattice & laser mesh' },
  { id: '/project-covers/threat_intelligence.png', label: 'Threat Intelligence', desc: 'Global threat radar with red & cyan SOC HUD' },
  { id: '/project-covers/zero_trust_vault.png', label: 'Zero-Trust Vault', desc: 'Hexagonal digital vault gate & neon lock' },
  { id: '/project-covers/ai_sentinel_eye.png', label: 'AI Sentinel Eye', desc: 'Glowing cyan AI sentinel core & circuit HUD' },
  { id: '/project-covers/network_matrix.png', label: 'Network Matrix', desc: 'Cybersecurity node network mesh' },
  { id: '/project-covers/code_audit.png', label: 'Code Vault', desc: 'Binary matrix code auditing vault' },
  { id: '/project-covers/hacker_terminal.png', label: 'Hacker Terminal', desc: 'Matrix green & cyan binary code rain' },
  { id: '/project-covers/red_team_ops.png', label: 'Red Team Ops', desc: 'Crimson offensive cyber SOC HUD' },
  { id: '/project-covers/cloud_security.png', label: 'Cloud Security', desc: 'Cloud infrastructure security pipeline' },
  { id: '/project-covers/mobile_pentest.png', label: 'Mobile Pentest', desc: 'Smartphone app security testing' },
  { id: '/project-covers/api_security.png', label: 'API Security', desc: 'REST API security mesh & lock' },
]

export default function Projects() {
  const { user } = useAuth()
  const isClient = user?.role === 'client'
  const [projects, setProjects] = useState(null)
  const [showNew, setShowNew] = useState(false)
  const [editingProject, setEditingProject] = useState(null)
  const [selected, setSelected] = useState(null)
  const [scanProject, setScanProject] = useState(null)
  const [reqScanModal, setReqScanModal] = useState(false)
  const [form, setForm] = useState({ name: '', client: '', description: '', scope: '', cover: COVER_OPTIONS[0].id })
  const [err, setErr] = useState('')
  const nav = useNavigate()

  function handleCustomCoverUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.type.startsWith('image/')) {
      alert('Please select an image file (PNG, JPG, WebP, etc.)')
      return
    }
    const reader = new FileReader()
    reader.onload = (event) => {
      const dataUrl = event.target?.result
      if (typeof dataUrl === 'string') {
        setForm(prev => ({ ...prev, cover: dataUrl }))
      }
    }
    reader.readAsDataURL(file)
  }

  const load = () => api.projects().then(setProjects).catch((e) => setErr(e.message))
  useEffect(() => { load() }, [])

  async function create(e) {
    e.preventDefault()
    try {
      if (editingProject) {
        await api.updateProject(editingProject.id, form)
        setEditingProject(null)
      } else {
        await api.createProject(form)
        setShowNew(false)
      }
      setForm({ name: '', client: '', description: '', scope: '', cover: COVER_OPTIONS[0].id })
      load()
    } catch (e2) { setErr(e2.message) }
  }

  function openEdit(project, e) {
    if (e) e.stopPropagation()
    setEditingProject(project)
    setForm({
      name: project.name || '',
      client: project.client || '',
      description: project.description || '',
      scope: project.scope || '',
      cover: project.cover || COVER_OPTIONS[0].id,
    })
  }

  async function remove(id) {
    if (!window.confirm('Are you sure you want to delete this project?')) return
    await api.deleteProject(id)
    if (selected?.id === id) setSelected(null)
    load()
  }

  function getProjectCover(project, idx) {
    if (project.cover) return project.cover
    return COVER_OPTIONS[idx % COVER_OPTIONS.length].id
  }

  if (!projects) return <div className="flex justify-center py-20"><Loader2 className="animate-spin text-accent" size={28} /></div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Projects</h1>
          <p className="text-sm text-slate-500">Client engagements, scope & target environments</p>
        </div>
        {isClient ? (
          <button onClick={() => setReqScanModal(true)} className="btn-primary flex items-center gap-2">
            <Radar size={16} /> Ask for New Scan
          </button>
        ) : (
          <button onClick={() => {
            setForm({ name: '', client: '', description: '', scope: '', cover: COVER_OPTIONS[0].id })
            setShowNew(true)
          }} className="btn-primary flex items-center gap-2">
            <Plus size={16} /> New Project
          </button>
        )}
      </div>

      {err && <div className="card p-4 text-sev-critical text-sm">{err}</div>}

      {projects.length === 0 ? (
        <div className="card p-16 text-center">
          <FolderKanban className="mx-auto text-slate-600 mb-3" size={40} />
          <p className="text-slate-400">No projects yet.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {projects.map((p, idx) => {
            const coverUrl = getProjectCover(p, idx)
            return (
              <div
                key={p.id}
                onClick={() => setSelected(p)}
                className="card overflow-hidden cursor-pointer hover:border-accent/60 transition-all duration-300 group flex flex-col justify-between"
              >
                {/* AI Cover Image Header */}
                <div className="relative h-36 w-full overflow-hidden bg-slate-900">
                  <img
                    src={coverUrl}
                    alt={p.name}
                    className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-ink-900 via-ink-900/60 to-transparent" />
                  
                  {/* Floating Action Buttons */}
                  {!isClient && (
                    <div className="absolute top-3 right-3 flex items-center gap-1.5">
                      <button
                        onClick={(e) => openEdit(p, e)}
                        title="Edit project"
                        className="rounded-lg bg-black/60 p-1.5 text-slate-300 backdrop-blur-md hover:bg-cyan-500/20 hover:text-cyan-300 transition-colors"
                      >
                        <Edit size={14} />
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); remove(p.id) }}
                        title="Delete project"
                        className="rounded-lg bg-black/60 p-1.5 text-slate-400 backdrop-blur-md hover:bg-red-500/20 hover:text-red-400 transition-colors"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  )}

                  {/* Title overlay */}
                  <div className="absolute bottom-3 left-4 right-4">
                    <h3 className="text-lg font-bold text-slate-100 drop-shadow-md group-hover:text-accent transition-colors">
                      {p.name}
                    </h3>
                    {p.client && (
                      <span className="inline-block mt-0.5 rounded bg-accent/20 px-2 py-0.5 text-[10px] font-semibold text-accent backdrop-blur-md border border-accent/30">
                        Client: {p.client}
                      </span>
                    )}
                  </div>
                </div>

                {/* Card Body */}
                <div className="p-4 space-y-3 flex-1 flex flex-col justify-between">
                  <div>
                    {p.description && (
                      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                        {p.description}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center justify-between border-t border-slate-800/80 pt-3 text-[11px]">
                    <span className="uppercase tracking-wider font-semibold text-slate-500">
                      {p.status || 'ACTIVE'} • {p.risk_level || 'MEDIUM'}
                    </span>
                    <span className="flex items-center gap-1 text-accent hover:underline text-xs font-medium">
                      View Scans <ExternalLink size={12} />
                    </span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {selected && (
        <ProjectDetail
          project={selected}
          onClose={() => setSelected(null)}
          onDelete={remove}
          onEdit={(p) => openEdit(p)}
          onLaunchScan={(p) => setScanProject(p)}
          nav={nav}
        />
      )}

      {/* Launch Scan Modal for Project */}
      {scanProject && (
        <NewScanModal
          initialProjectId={scanProject.id}
          initialTarget={scanProject.scope || ''}
          onClose={() => setScanProject(null)}
          onStarted={(scanId) => {
            setScanProject(null)
            nav(`/app/scans/${scanId}`)
          }}
        />
      )}

      {/* New & Edit Project Modal */}
      {(showNew || editingProject) && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in overflow-y-auto"
          onClick={() => { setShowNew(false); setEditingProject(null) }}
        >
          <form
            onSubmit={create}
            className="card w-full max-w-xl p-6 space-y-4 my-8"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-lg font-bold text-slate-100">
                {editingProject ? 'Edit Project' : 'Create New Project'}
              </h2>
              <button
                type="button"
                onClick={() => { setShowNew(false); setEditingProject(null) }}
                className="text-slate-500 hover:text-slate-200"
              >
                <X size={18} />
              </button>
            </div>

            <div>
              <label className="label">Project Name *</label>
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. FMS Web Portal" required />
            </div>

            <div>
              <label className="label">Client Name</label>
              <input className="input" value={form.client} onChange={(e) => setForm({ ...form, client: e.target.value })} placeholder="e.g. MyCES" />
            </div>

            {/* Background Cover Selector & Custom Upload */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="label flex items-center gap-1.5 !mb-0">
                  <Sparkles size={14} className="text-accent" /> Select Cover Image or Upload Custom
                </label>
                <label className="btn-ghost text-xs px-2.5 py-1 flex items-center gap-1 text-cyan-300 border-cyan-500/30 hover:border-cyan-400 cursor-pointer">
                  <Upload size={13} />
                  <span>Upload Custom</span>
                  <input type="file" accept="image/*" className="hidden" onChange={handleCustomCoverUpload} />
                </label>
              </div>

              <div className="grid grid-cols-4 gap-2 max-h-56 overflow-y-auto p-1 rounded-xl bg-ink-950 border border-slate-800">
                {/* Custom Uploaded Image Preview if active */}
                {form.cover && form.cover.startsWith('data:') && (
                  <div
                    onClick={() => {}}
                    className="relative h-20 rounded-lg overflow-hidden border border-cyan-400 ring-2 ring-cyan-400 cursor-pointer transition-all col-span-2"
                  >
                    <img src={form.cover} alt="Custom uploaded cover" className="h-full w-full object-cover" />
                    <div className="absolute inset-0 bg-black/40 p-1 flex items-end justify-between">
                      <span className="text-[10px] font-bold text-cyan-300 drop-shadow flex items-center gap-1">
                        <Image size={12} /> Custom Uploaded
                      </span>
                    </div>
                  </div>
                )}

                {COVER_OPTIONS.map((c) => {
                  const isSelected = form.cover === c.id
                  return (
                    <div
                      key={c.id}
                      onClick={() => setForm({ ...form, cover: c.id })}
                      className={`relative h-20 rounded-lg overflow-hidden border cursor-pointer transition-all ${
                        isSelected ? 'border-accent ring-2 ring-accent' : 'border-slate-800 opacity-60 hover:opacity-100'
                      }`}
                    >
                      <img src={c.id} alt={c.label} className="h-full w-full object-cover" />
                      <div className="absolute inset-0 bg-black/50 p-1 flex items-end">
                        <span className="text-[9px] font-bold text-white drop-shadow leading-tight line-clamp-1">{c.label}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            <div>
              <label className="label">Description</label>
              <textarea className="input h-16" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Project goals and target details..." />
            </div>

            <div>
              <label className="label">Target Scope</label>
              <input className="input font-mono text-xs" placeholder="*.myces-fms.com, 192.168.1.0/24" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => { setShowNew(false); setEditingProject(null) }}
                className="btn-ghost"
              >
                Cancel
              </button>
              <button type="submit" className="btn-primary">
                {editingProject ? 'Save Changes' : 'Create Project'}
              </button>
            </div>
          </form>
        </div>
      )}

      {reqScanModal && (
        <RequestScanModal
          onClose={() => setReqScanModal(false)}
          defaultProjectId={projects && projects.length > 0 ? projects[0].id : ''}
          projects={projects || []}
        />
      )}
    </div>
  )
}

function ProjectDetail({ project, onClose, onDelete, onEdit, onLaunchScan, nav }) {
  const { user } = useAuth()
  const isClient = user?.role === 'client'
  const [scans, setScans] = useState(null)
  const [creds, setCreds] = useState([])
  const [showAddCred, setShowAddCred] = useState(false)
  const [editingCred, setEditingCred] = useState(null)
  const [credForm, setCredForm] = useState({ email: '', password: '', note: '' })
  const [credErr, setCredErr] = useState('')

  const loadCreds = () => api.projectCredentials(project.id).then(setCreds).catch(() => setCreds([]))

  useEffect(() => {
    api.scans()
      .then((all) => setScans((all || []).filter((s) => s.project_id === project.id)))
      .catch(() => setScans([]))
    loadCreds()
  }, [project.id])

  async function handleSaveCred(e) {
    e.preventDefault()
    setCredErr('')
    try {
      if (editingCred) {
        await api.updateProjectCredential(project.id, editingCred.id, credForm)
      } else {
        await api.addProjectCredential(project.id, credForm)
      }
      setCredForm({ email: '', password: '', note: '' })
      setShowAddCred(false)
      setEditingCred(null)
      loadCreds()
    } catch (err) {
      setCredErr(err.message)
    }
  }

  async function handleDeleteCred(credId) {
    if (!window.confirm('Delete this client portal credential?')) return
    await api.deleteProjectCredential(project.id, credId)
    loadCreds()
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="card w-full max-w-2xl overflow-hidden max-h-[88vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        
        {/* Cover Header */}
        <div className="relative h-36 w-full bg-slate-900">
          <img src={project.cover || '/project-covers/cyber_shield.png'} alt={project.name} className="h-full w-full object-cover" />
          <div className="absolute inset-0 bg-gradient-to-t from-ink-900 via-ink-900/60 to-transparent" />
          
          <button onClick={onClose} className="absolute top-3 right-3 rounded-lg bg-black/60 p-1.5 text-slate-300 backdrop-blur-md hover:bg-slate-800">
            <X size={18} />
          </button>

          <div className="absolute bottom-3 left-6 right-6 flex items-end justify-between">
            <div>
              <h2 className="text-xl font-bold text-slate-100">{project.name}</h2>
              {project.client && <p className="text-xs text-accent font-medium mt-0.5">{project.client}</p>}
            </div>

            <button
              onClick={() => {
                onClose()
                onLaunchScan(project)
              }}
              className="btn-primary text-xs flex items-center gap-1.5 shadow-lg"
            >
              <Play size={14} /> Launch Scan
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 overflow-y-auto flex-1">
          {project.description && <p className="text-sm text-slate-300">{project.description}</p>}
          {project.scope && <p className="text-xs text-slate-400 font-mono bg-ink-950 p-2.5 rounded border border-slate-800">Scope: {project.scope}</p>}

          {/* Client Portal Credentials Section */}
          <div className="rounded-xl border border-white/10 bg-slate-950/60 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                🔑 Client Portal Logins ({creds.length})
              </h3>
              <button
                onClick={() => {
                  setCredForm({ email: '', password: '', note: '' })
                  setEditingCred(null)
                  setShowAddCred(true)
                }}
                className="btn-ghost text-xs px-2.5 py-1 text-cyan-300 border-cyan-500/30 hover:border-cyan-400"
              >
                + Add Client Login
              </button>
            </div>

            {/* Credential Form Modal/Inline */}
            {(showAddCred || editingCred) && (
              <form onSubmit={handleSaveCred} className="space-y-3 p-3 rounded-lg bg-white/[0.04] border border-cyan-500/30">
                <p className="text-xs font-bold text-cyan-300">{editingCred ? 'Edit Client Portal Login' : 'New Client Portal Login'}</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <input
                    className="input text-xs"
                    placeholder="Client Email (e.g. client@myces.com)"
                    value={credForm.email}
                    onChange={(e) => setCredForm({ ...credForm, email: e.target.value })}
                    required
                  />
                  <input
                    className="input text-xs"
                    placeholder="Password"
                    value={credForm.password}
                    onChange={(e) => setCredForm({ ...credForm, password: e.target.value })}
                    required
                  />
                </div>
                <input
                  className="input text-xs"
                  placeholder="Notes (e.g. CEO Login / Staging Access)"
                  value={credForm.note}
                  onChange={(e) => setCredForm({ ...credForm, note: e.target.value })}
                />
                {credErr && <p className="text-xs text-red-400">{credErr}</p>}
                <div className="flex justify-end gap-2 pt-1">
                  <button type="button" onClick={() => { setShowAddCred(false); setEditingCred(null) }} className="btn-ghost text-xs py-1">Cancel</button>
                  <button type="submit" className="btn-primary text-xs py-1">Save Credential</button>
                </div>
              </form>
            )}

            {/* Credentials List */}
            {creds.length === 0 ? (
              <p className="text-xs text-slate-500 py-2 text-center">No client portal credentials added for this project yet.</p>
            ) : (
              <div className="space-y-2">
                {creds.map((c) => (
                  <div key={c.id} className="flex items-center justify-between p-2.5 rounded-lg bg-black/40 border border-white/5 text-xs">
                    <div className="space-y-0.5">
                      <p className="font-mono font-semibold text-cyan-300">{c.email}</p>
                      <p className="font-mono text-slate-400">Password: <span className="text-slate-200">{c.password}</span> {c.note && <span className="text-slate-500 font-sans">({c.note})</span>}</p>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => {
                          setEditingCred(c)
                          setCredForm({ email: c.email, password: c.password, note: c.note || '' })
                        }}
                        className="p-1 text-slate-400 hover:text-cyan-300"
                        title="Edit credential"
                      >
                        <Edit size={13} />
                      </button>
                      <button
                        onClick={() => handleDeleteCred(c.id)}
                        className="p-1 text-slate-400 hover:text-red-400"
                        title="Delete credential"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2">
              <Radar size={16} className="text-accent" /> Associated Scans ({scans?.length ?? 0})
            </h3>
            {!scans ? (
              <div className="py-6 flex justify-center"><Loader2 className="animate-spin text-accent" size={20} /></div>
            ) : scans.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center border border-dashed border-slate-800 rounded-lg">No scans under this project yet.</p>
            ) : (
              <div className="space-y-2">
                {scans.map((s) => (
                  <div key={s.id} onClick={() => { onClose(); nav(`/app/scans/${s.id}`) }} className="flex items-center justify-between rounded-lg border border-slate-800 bg-ink-950 p-3 hover:border-accent cursor-pointer transition-colors">
                    <div>
                      <p className="text-xs font-semibold text-slate-200">{s.target}</p>
                      <p className="text-[10px] text-slate-500">{s.mode} • {s.status}</p>
                    </div>
                    <span className="text-xs text-accent font-medium">View Scan →</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-ink-950 flex justify-between items-center">
          <div className="flex gap-2">
            {!isClient && (
              <>
                <button onClick={() => { onClose(); onEdit(project) }} className="btn-ghost text-xs flex items-center gap-1.5">
                  <Edit size={14} /> Edit Project
                </button>
                <button onClick={() => onDelete(project.id)} className="btn-danger text-xs flex items-center gap-1.5">
                  <Trash2 size={14} /> Delete Project
                </button>
              </>
            )}
          </div>
          <button onClick={onClose} className="btn-ghost text-xs">Close</button>
        </div>

      </div>
    </div>
  )
}
