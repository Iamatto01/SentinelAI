import { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api.js';

const TEMPLATES = [
  { id: 'quick', name: 'Quick Scan', desc: 'Headers + SSL only', modules: { headers: true, ssl: true, paths: false, dns: false, cors: false, tech: false, nmap: false, nuclei: false } },
  { id: 'standard', name: 'Standard Scan', desc: 'All web modules', modules: { headers: true, ssl: true, paths: true, dns: true, cors: true, tech: true, nmap: false, nuclei: false } },
  { id: 'full', name: 'Full Scan', desc: 'All modules + nmap & nuclei', modules: { headers: true, ssl: true, paths: true, dns: true, cors: true, tech: true, nmap: true, nuclei: true } },
];

const MODULE_INFO = {
  headers: 'HTTP security headers, cookies, info leakage',
  ssl: 'TLS certificate, protocol version, cipher strength',
  paths: 'Exposed files (.env, .git, backups, admin panels)',
  dns: 'DNS records, SPF, DMARC, mail server config',
  cors: 'Cross-origin resource sharing misconfigurations',
  tech: 'Technology stack fingerprinting & detection',
  nmap: 'Port scanning & service detection (requires nmap)',
  nuclei: 'Template-based vulnerability scan (requires nuclei)',
};

export default function NewScanModal({ open, onClose, onStarted }) {
  const [target, setTarget] = useState('');
  const [template, setTemplate] = useState('standard');
  const [modules, setModules] = useState({ headers: true, ssl: true, paths: true, dns: true, cors: true, tech: true, nmap: false, nuclei: false });
  const [projectId, setProjectId] = useState('');
  const [projects, setProjects] = useState([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (open) {
      apiFetch('/api/projects').then((d) => setProjects(d?.projects || [])).catch(() => {});
    }
  }, [open]);

  function selectTemplate(id) {
    setTemplate(id);
    const t = TEMPLATES.find((t) => t.id === id);
    if (t) setModules({ ...t.modules });
  }

  function toggleModule(key) {
    setModules((prev) => ({ ...prev, [key]: !prev[key] }));
    setTemplate('custom');
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    const trimmed = target.trim();
    if (!trimmed) { setError('Target URL is required'); return; }

    try { new URL(trimmed); } catch { setError('Enter a valid URL (e.g. https://example.com)'); return; }

    setSubmitting(true);
    try {
      const res = await apiFetch('/api/scan/start', {
        method: 'POST',
        body: { target: trimmed, template, modules, projectId: projectId || undefined },
      });
      onStarted?.(res?.scan);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  if (!open) return null;

  return (
    <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" onClick={onClose}>
      <div className="modal-content w-full max-w-2xl mx-4 rounded-lg p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-2xl font-bold">New Scan</h3>
          <button className="text-gray-400 hover:text-white text-xl" onClick={onClose}>&#x2715;</button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target URL */}
          <div>
            <label className="block text-sm font-medium mb-2">Target URL</label>
            <input
              type="text"
              className="search-input w-full px-4 py-3 rounded-lg"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoFocus
            />
          </div>

          {/* Template Selection */}
          <div>
            <label className="block text-sm font-medium mb-3">Scan Template</label>
            <div className="grid grid-cols-3 gap-3">
              {TEMPLATES.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className={`p-3 rounded-lg text-left border transition-all ${template === t.id ? 'border-white bg-white/10' : 'border-white/10 hover:border-white/30'}`}
                  onClick={() => selectTemplate(t.id)}
                >
                  <p className="font-medium text-sm">{t.name}</p>
                  <p className="text-xs text-gray-400 mt-1">{t.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Module Checkboxes */}
          <div>
            <label className="block text-sm font-medium mb-3">Modules</label>
            <div className="space-y-2">
              {Object.entries(MODULE_INFO).map(([key, desc]) => (
                <label key={key} className="flex items-center space-x-3 cursor-pointer p-2 rounded hover:bg-white/5">
                  <input
                    type="checkbox"
                    className="filter-checkbox"
                    checked={modules[key] || false}
                    onChange={() => toggleModule(key)}
                  />
                  <div>
                    <span className="text-sm font-medium">{key.charAt(0).toUpperCase() + key.slice(1)}</span>
                    <span className="text-xs text-gray-400 ml-2">{desc}</span>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Project Association */}
          <div>
            <label className="block text-sm font-medium mb-2">Associate with Project (optional)</label>
            <select
              className="search-input w-full px-4 py-3 rounded-lg"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            >
              <option value="" className="text-black">None</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id} className="text-black">{p.name}</option>
              ))}
            </select>
          </div>

          {error && <div className="text-red-400 text-sm">{error}</div>}

          <div className="flex justify-end space-x-4">
            <button
              type="button"
              className="px-6 py-3 border border-white/30 rounded hover:bg-white/10 transition-all"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-6 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium disabled:opacity-50"
            >
              {submitting ? 'Starting...' : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
