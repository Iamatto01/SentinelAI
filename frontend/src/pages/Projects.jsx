import { useEffect, useState } from 'react';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import ActionMenu from '../components/ActionMenu.jsx';
import ProjectDetailModal from '../components/ProjectDetailModal.jsx';
import { apiFetch, getStoredUser, updateProject, deleteProject } from '../lib/api.js';

function severityBadge(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'severity-critical';
  if (s === 'high') return 'severity-high';
  if (s === 'low') return 'severity-low';
  return 'severity-medium';
}

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'active') return 'status-active';
  if (s === 'completed') return 'status-completed';
  return 'status-planned';
}

export default function Projects() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [projects, setProjects] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('date');
  const [showModal, setShowModal] = useState(false);
  const [editProject, setEditProject] = useState(null);
  const [detailProject, setDetailProject] = useState(null);
  const toast = useToast();

  async function loadProjects() {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/api/projects');
      setProjects(data?.projects || []);
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProjects();
  }, []);

  const filtered = projects
    .filter((p) => {
      const name = (p.name || '').toLowerCase();
      const desc = (p.description || '').toLowerCase();
      const term = searchTerm.toLowerCase();
      if (term && !name.includes(term) && !desc.includes(term)) return false;
      if (statusFilter !== 'all' && (p.status || 'active').toLowerCase() !== statusFilter) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'name') return (a.name || '').localeCompare(b.name || '');
      if (sortBy === 'risk') {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[(a.riskLevel || 'medium').toLowerCase()] ?? 2) - (order[(b.riskLevel || 'medium').toLowerCase()] ?? 2);
      }
      if (sortBy === 'status') return (a.status || '').localeCompare(b.status || '');
      return 0;
    });

  async function handleCreateProject(e) {
    e.preventDefault();
    const form = e.target;
    const get = (name) => form.elements[name]?.value?.trim() || '';
    try {
      const user = getStoredUser();
      await apiFetch('/api/projects', {
        method: 'POST',
        body: {
          name: get('name'),
          client: get('client'),
          owner: user?.username || 'Security Analyst',
          description: get('description'),
          startDate: get('startDate'),
          endDate: get('endDate'),
          scope: get('scope'),
          clientEmails: get('clientEmails').split(',').map((e) => e.trim()).filter(Boolean),
          riskLevel: 'medium',
        },
      });
      setShowModal(false);
      toast('Project created successfully!');
      await loadProjects();
    } catch (err) {
      toast(`Create failed: ${err.message}`);
    }
  }

  async function handleEditProject(e) {
    e.preventDefault();
    if (!editProject) return;
    const form = e.target;
    const get = (name) => form.elements[name]?.value?.trim() || '';
    try {
      await updateProject(editProject.id, {
        name: get('name'),
        client: get('client'),
        description: get('description'),
        startDate: get('startDate'),
        endDate: get('endDate'),
        scope: get('scope'),
        clientEmails: get('clientEmails').split(',').map((e) => e.trim()).filter(Boolean),
      });
      setEditProject(null);
      toast('Project updated successfully!');
      await loadProjects();
    } catch (err) {
      toast(`Update failed: ${err.message}`);
    }
  }

  async function handleDeleteProject(project) {
    if (!confirm(`Delete project "${project.name}"? This cannot be undone.`)) return;
    try {
      await deleteProject(project.id);
      toast('Project deleted');
      await loadProjects();
    } catch (err) {
      toast(`Delete failed: ${err.message}`);
    }
  }

  const statuses = ['all', 'active', 'completed', 'planned'];
  const isEditing = !!editProject;
  const modalOpen = showModal || isEditing;

  return (
    <Shell
      title="Projects"
      subtitle="Manage penetration testing engagements"
      actions={
        <button
          className="px-6 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium"
          onClick={() => setShowModal(true)}
        >
          + New Project
        </button>
      }
    >
      {error ? (
        <div className="glassmorphism p-4 rounded border border-white/10 text-sm text-gray-200 mb-6">
          {error}
        </div>
      ) : null}

      <div className="mb-6 border-b border-white/10 pb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <input
                type="text"
                placeholder="Search projects..."
                className="search-input w-64 px-4 py-2 rounded-lg placeholder-gray-400"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              <span className="absolute right-3 top-2.5 text-gray-400">&#x1F50D;</span>
            </div>

            <div className="flex items-center space-x-2">
              {statuses.map((s) => (
                <button
                  key={s}
                  className={`filter-button px-4 py-2 rounded-lg text-sm ${statusFilter === s ? 'active' : ''}`}
                  onClick={() => setStatusFilter(s)}
                >
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">Sort by:</span>
            <select
              className="search-input px-3 py-2 rounded text-sm"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="date" className="text-black">Last Updated</option>
              <option value="name" className="text-black">Name</option>
              <option value="risk" className="text-black">Risk Level</option>
              <option value="status" className="text-black">Status</option>
            </select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="glassmorphism p-6 rounded border border-white/10 text-gray-300">Loading...</div>
        ) : null}

        {!loading && filtered.length === 0 ? (
          <div className="glassmorphism p-6 rounded border border-white/10 text-gray-300">
            No projects found.
          </div>
        ) : null}

        {filtered.map((p) => {
          const status = (p.status || 'active').toLowerCase();
          const risk = (p.riskLevel || 'medium').toLowerCase();
          return (
            <div
              key={p.id}
              className="card-hover p-6 rounded-lg cursor-pointer"
              onClick={() => setDetailProject(p)}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-2">
                  <span className={`${statusBadge(status)} px-3 py-1 rounded-full text-xs font-medium`}>
                    {status.charAt(0).toUpperCase() + status.slice(1)}
                  </span>
                  <span className={`${severityBadge(risk)} px-2 py-1 rounded text-xs`}>
                    {risk.charAt(0).toUpperCase() + risk.slice(1)} Risk
                  </span>
                </div>
                <ActionMenu
                  items={[
                    { label: 'View Details', onClick: () => setDetailProject(p) },
                    { label: 'Edit Project', onClick: () => setEditProject(p) },
                    { divider: true },
                    { label: 'Delete Project', onClick: () => handleDeleteProject(p), danger: true },
                  ]}
                />
              </div>

              <h3 className="text-xl font-semibold mb-2">{p.name || 'Untitled Project'}</h3>
              <p className="text-gray-400 text-sm mb-4">{p.description || 'No description provided.'}</p>

              <div className="space-y-2 mb-4 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Client:</span>
                  <span>{p.client || '\u2014'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Owner:</span>
                  <span>{p.owner || 'Security Analyst'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Scans:</span>
                  <span>{p.scanCount ?? 0}</span>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="text-xs text-gray-400">
                  {p.startDate && p.endDate ? `${p.startDate} - ${p.endDate}` : '\u2014'}
                </div>
                <div className="text-xs text-gray-400">Vulns: {p.vulnerabilityCount ?? 0}</div>
              </div>
            </div>
          );
        })}
      </div>

      {modalOpen ? (
        <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center">
          <div className="modal-content w-full max-w-2xl mx-4 rounded-lg p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-2xl font-bold">{isEditing ? 'Edit Project' : 'Create New Project'}</h3>
              <button
                className="text-gray-400 hover:text-white text-xl"
                onClick={() => { setShowModal(false); setEditProject(null); }}
              >
                &#x2715;
              </button>
            </div>

            <form className="space-y-6" onSubmit={isEditing ? handleEditProject : handleCreateProject}>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium mb-2">Project Name</label>
                  <input
                    type="text"
                    name="name"
                    className="search-input w-full px-4 py-3 rounded-lg"
                    placeholder="Enter project name"
                    defaultValue={editProject?.name || ''}
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Client</label>
                  <input
                    type="text"
                    name="client"
                    className="search-input w-full px-4 py-3 rounded-lg"
                    placeholder="Client organization"
                    defaultValue={editProject?.client || ''}
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Description</label>
                <textarea
                  name="description"
                  className="search-input w-full px-4 py-3 rounded-lg h-24"
                  placeholder="Project description and objectives"
                  defaultValue={editProject?.description || ''}
                  required
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium mb-2">Start Date</label>
                  <input
                    type="date"
                    name="startDate"
                    className="search-input w-full px-4 py-3 rounded-lg"
                    defaultValue={editProject?.startDate || ''}
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">End Date</label>
                  <input
                    type="date"
                    name="endDate"
                    className="search-input w-full px-4 py-3 rounded-lg"
                    defaultValue={editProject?.endDate || ''}
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Scope</label>
                <textarea
                  name="scope"
                  className="search-input w-full px-4 py-3 rounded-lg h-20"
                  placeholder="Define testing scope and boundaries"
                  defaultValue={editProject?.scope || ''}
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Client Portal Emails</label>
                <input
                  type="text"
                  name="clientEmails"
                  className="search-input w-full px-4 py-3 rounded-lg"
                  placeholder="client1@company.com, client2@company.com"
                  defaultValue={(editProject?.clientEmails || []).join(', ')}
                />
                <p className="text-xs text-gray-400 mt-1">
                  Comma-separated. These users can log in to view this project read-only.
                </p>
              </div>

              <div className="flex justify-end space-x-4">
                <button
                  type="button"
                  className="px-6 py-3 border border-white/30 rounded hover:bg-white/10 transition-all"
                  onClick={() => { setShowModal(false); setEditProject(null); }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-6 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium"
                >
                  {isEditing ? 'Save Changes' : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      <ProjectDetailModal
        open={!!detailProject}
        project={detailProject}
        onClose={() => setDetailProject(null)}
      />
    </Shell>
  );
}
