import { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api.js';

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'active') return 'status-active';
  if (s === 'completed') return 'status-completed';
  return 'status-planned';
}

export default function ProjectDetailModal({ open, project, onClose }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !project?.id) return;
    setLoading(true);
    apiFetch(`/api/projects/${project.id}`)
      .then((d) => setScans(d?.scans || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [open, project?.id]);

  if (!open || !project) return null;

  const status = (project.status || 'active').toLowerCase();

  return (
    <div className="fixed inset-0 modal-backdrop z-50 flex items-center justify-center" onClick={onClose}>
      <div className="modal-content w-full max-w-3xl mx-4 rounded-lg p-6 max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <span className={`${statusBadge(status)} px-3 py-1 rounded-full text-xs font-medium`}>
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </span>
            <h3 className="text-2xl font-bold">{project.name || 'Project Detail'}</h3>
          </div>
          <button className="text-gray-400 hover:text-white text-xl" onClick={onClose}>&#x2715;</button>
        </div>

        <div className="space-y-6">
          {/* Overview */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Client</p>
              <p className="font-medium text-sm">{project.client || '\u2014'}</p>
            </div>
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Owner</p>
              <p className="font-medium text-sm">{project.owner || '\u2014'}</p>
            </div>
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Scans</p>
              <p className="font-medium text-sm">{project.scanCount ?? 0}</p>
            </div>
            <div className="p-3 bg-white/5 rounded-lg">
              <p className="text-xs text-gray-400">Vulnerabilities</p>
              <p className="font-medium text-sm">{project.vulnerabilityCount ?? 0}</p>
            </div>
          </div>

          {/* Description */}
          {project.description && (
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-2">Description</h4>
              <div className="p-4 bg-white/5 rounded-lg text-sm text-gray-200">{project.description}</div>
            </div>
          )}

          {/* Scope */}
          {project.scope && (
            <div>
              <h4 className="text-sm font-medium text-gray-300 mb-2">Scope</h4>
              <div className="p-4 bg-white/5 rounded-lg text-sm text-gray-200 font-mono">{project.scope}</div>
            </div>
          )}

          {/* Duration */}
          {(project.startDate || project.endDate) && (
            <div className="flex items-center space-x-4 text-sm text-gray-300">
              <span>Start: {project.startDate || '\u2014'}</span>
              <span>End: {project.endDate || '\u2014'}</span>
            </div>
          )}

          {/* Associated Scans */}
          <div>
            <h4 className="text-sm font-medium text-gray-300 mb-3">Associated Scans</h4>
            {loading ? (
              <div className="text-sm text-gray-400">Loading scans...</div>
            ) : scans.length === 0 ? (
              <div className="text-sm text-gray-400 p-4 bg-white/5 rounded-lg">No scans attached to this project.</div>
            ) : (
              <div className="space-y-3">
                {scans.map((s) => (
                  <div key={s.id} className="p-3 bg-white/5 rounded-lg flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">{s.target || 'Unknown'}</p>
                      <p className="text-xs text-gray-400">{s.template} &bull; {s.status} &bull; {s.vulnerabilitiesFound ?? 0} findings</p>
                    </div>
                    <div className="text-right text-xs text-gray-400">
                      {s.startTime ? new Date(s.startTime).toLocaleDateString() : '\u2014'}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="flex justify-end mt-6">
          <button className="px-6 py-3 border border-white/30 rounded hover:bg-white/10 transition-all" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
