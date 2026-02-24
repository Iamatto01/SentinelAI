import { useEffect, useState } from 'react';
import { useAuth } from '../lib/AuthContext.jsx';
import { apiFetch } from '../lib/api.js';
import VulnDetailModal from '../components/VulnDetailModal.jsx';

function severityBadge(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'severity-critical';
  if (s === 'high') return 'severity-high';
  if (s === 'medium') return 'severity-medium';
  if (s === 'low') return 'severity-low';
  return 'severity-info';
}

function statusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'active') return 'status-active';
  if (s === 'completed') return 'status-completed';
  return 'status-planned';
}

export default function ClientPortal() {
  const { user, logout } = useAuth();
  const [projects, setProjects] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [projectScans, setProjectScans] = useState({});
  const [scanVulns, setScanVulns] = useState({});
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const data = await apiFetch('/api/projects');
        setProjects(data?.projects || []);
      } catch (e) {
        setError(e?.message || String(e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  async function toggleProject(projectId) {
    if (expandedId === projectId) {
      setExpandedId(null);
      return;
    }
    setExpandedId(projectId);
    if (!projectScans[projectId]) {
      try {
        const data = await apiFetch(`/api/scans?projectId=${encodeURIComponent(projectId)}`);
        setProjectScans((prev) => ({ ...prev, [projectId]: data?.scans || [] }));
      } catch {
        setProjectScans((prev) => ({ ...prev, [projectId]: [] }));
      }
    }
  }

  async function loadVulns(scanId) {
    if (scanVulns[scanId]) {
      setScanVulns((prev) => {
        const copy = { ...prev };
        delete copy[scanId];
        return copy;
      });
      return;
    }
    try {
      const data = await apiFetch(`/api/scan/results?scanId=${encodeURIComponent(scanId)}`);
      setScanVulns((prev) => ({ ...prev, [scanId]: data?.vulnerabilities || [] }));
    } catch {
      setScanVulns((prev) => ({ ...prev, [scanId]: [] }));
    }
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header */}
      <header className="border-b border-white/10 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <img src="/resources/logo.svg" alt="SentinelAI" className="w-8 h-8" />
            <div>
              <h1 className="text-lg font-bold">SentinelAI</h1>
              <p className="text-xs text-gray-400">Client Portal</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-400">{user?.email || user?.username}</span>
            <button
              className="px-4 py-2 border border-white/20 rounded text-sm hover:bg-white/10 transition-all"
              onClick={logout}
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-6xl mx-auto px-6 py-8">
        <h2 className="text-2xl font-bold mb-6">Your Projects</h2>

        {loading && (
          <div className="glassmorphism p-6 rounded border border-white/10 text-gray-300">Loading...</div>
        )}

        {error && (
          <div className="glassmorphism p-4 rounded border border-white/10 text-sm text-gray-200 mb-6">
            {error}
          </div>
        )}

        {!loading && projects.length === 0 && (
          <div className="glassmorphism p-8 rounded border border-white/10 text-center text-gray-400">
            No projects assigned to your account.
          </div>
        )}

        <div className="space-y-4">
          {projects.map((p) => {
            const isExpanded = expandedId === p.id;
            const scans = projectScans[p.id] || [];
            const status = (p.status || 'active').toLowerCase();
            const risk = (p.riskLevel || 'medium').toLowerCase();

            return (
              <div key={p.id} className="glassmorphism rounded-lg border border-white/10 overflow-hidden">
                {/* Project Header (clickable) */}
                <button
                  className="w-full text-left px-6 py-4 flex items-center justify-between hover:bg-white/5 transition-all"
                  onClick={() => toggleProject(p.id)}
                >
                  <div className="flex items-center space-x-3">
                    <span className={`${statusBadge(status)} px-3 py-1 rounded-full text-xs font-medium`}>
                      {status.charAt(0).toUpperCase() + status.slice(1)}
                    </span>
                    <span className={`${severityBadge(risk)} px-2 py-1 rounded text-xs`}>
                      {risk.charAt(0).toUpperCase() + risk.slice(1)} Risk
                    </span>
                    <h3 className="text-lg font-semibold">{p.name || 'Untitled Project'}</h3>
                  </div>
                  <span className="text-gray-400 text-lg">{isExpanded ? '\u25B2' : '\u25BC'}</span>
                </button>

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="px-6 pb-6 border-t border-white/10">
                    {/* Project Details */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 mb-6">
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Client</p>
                        <p className="text-sm">{p.client || '\u2014'}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Owner</p>
                        <p className="text-sm">{p.owner || 'Security Analyst'}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Timeline</p>
                        <p className="text-sm">
                          {p.startDate && p.endDate ? `${p.startDate} \u2192 ${p.endDate}` : '\u2014'}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Vulnerabilities</p>
                        <p className="text-sm">{p.vulnerabilityCount ?? 0}</p>
                      </div>
                    </div>

                    {p.description && (
                      <div className="mb-4">
                        <p className="text-xs text-gray-400 mb-1">Description</p>
                        <p className="text-sm text-gray-200">{p.description}</p>
                      </div>
                    )}

                    {p.scope && (
                      <div className="mb-6">
                        <p className="text-xs text-gray-400 mb-1">Scope</p>
                        <p className="text-sm text-gray-200">{p.scope}</p>
                      </div>
                    )}

                    {/* Scans Table */}
                    <h4 className="text-sm font-medium text-gray-300 mb-3">Scans</h4>
                    {scans.length === 0 ? (
                      <p className="text-sm text-gray-500">No scans found for this project.</p>
                    ) : (
                      <div className="space-y-2">
                        {scans.map((scan) => {
                          const vulns = scanVulns[scan.id];
                          return (
                            <div key={scan.id} className="bg-white/5 rounded-lg overflow-hidden">
                              <div className="flex items-center justify-between px-4 py-3">
                                <div className="flex items-center space-x-3">
                                  <span className="text-sm font-medium">{scan.target || scan.id}</span>
                                  <span className="text-xs text-gray-400">
                                    {scan.status || 'completed'}
                                  </span>
                                  {scan.startedAt && (
                                    <span className="text-xs text-gray-500">
                                      {new Date(scan.startedAt).toLocaleDateString()}
                                    </span>
                                  )}
                                </div>
                                <button
                                  className="px-3 py-1 text-xs border border-white/20 rounded hover:bg-white/10 transition-all"
                                  onClick={() => loadVulns(scan.id)}
                                >
                                  {vulns ? 'Hide Vulnerabilities' : 'View Vulnerabilities'}
                                </button>
                              </div>

                              {/* Vulnerabilities List */}
                              {vulns && (
                                <div className="border-t border-white/10 px-4 py-3">
                                  {vulns.length === 0 ? (
                                    <p className="text-xs text-gray-500">No vulnerabilities found.</p>
                                  ) : (
                                    <div className="space-y-2">
                                      {vulns.map((v) => (
                                        <button
                                          key={v.id}
                                          className="w-full text-left flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition-all"
                                          onClick={() => setSelectedVuln(v)}
                                        >
                                          <div className="flex items-center space-x-3">
                                            <span
                                              className={`${severityBadge(v.severity)} px-2 py-0.5 rounded text-xs font-medium`}
                                            >
                                              {(v.severity || 'info').toUpperCase()}
                                            </span>
                                            <span className="text-sm">{v.title || 'Untitled'}</span>
                                          </div>
                                          <span className="text-xs text-gray-400">
                                            CVSS {v.cvss ?? 'N/A'}
                                          </span>
                                        </button>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </main>

      <VulnDetailModal
        open={!!selectedVuln}
        vuln={selectedVuln}
        onClose={() => setSelectedVuln(null)}
        readOnly
      />
    </div>
  );
}
