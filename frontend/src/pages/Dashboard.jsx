import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import NewScanModal from '../components/NewScanModal.jsx';
import VulnDetailModal from '../components/VulnDetailModal.jsx';
import ReportConfigModal from '../components/ReportConfigModal.jsx';
import { apiFetch } from '../lib/api.js';

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function severityBadge(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'severity-critical';
  if (s === 'high') return 'severity-high';
  if (s === 'medium') return 'severity-medium';
  if (s === 'low') return 'severity-low';
  return 'severity-info';
}

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [vulns, setVulns] = useState([]);
  const [scans, setScans] = useState([]);
  const [runningCount, setRunningCount] = useState(0);
  const [showScanModal, setShowScanModal] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [showNotifications, setShowNotifications] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();

  async function loadData() {
    setLoading(true);
    setError('');
    try {
      const [vulnData, scansData] = await Promise.all([
        apiFetch('/api/vulnerabilities'),
        apiFetch('/api/scans'),
      ]);
      const list = vulnData?.vulnerabilities || [];
      setVulns(list);
      const allScans = scansData?.scans || [];
      setScans(allScans);
      setRunningCount(allScans.filter((s) => s.status === 'running').length);
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const metrics = useMemo(() => {
    const critical = vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length;
    const high = vulns.filter((v) => (v.severity || '').toLowerCase() === 'high').length;
    const avg = vulns.length
      ? Math.round((vulns.reduce((sum, v) => sum + (v.aiConfidence || 0), 0) / vulns.length) * 100)
      : 0;
    return { critical, high, ai: clamp(avg, 0, 100) };
  }, [vulns]);

  function handleScanStarted(scan) {
    toast('Scan started successfully!');
    loadData();
    if (scan?.id) navigate('/scan');
  }

  function handleVulnStatusChange(vulnId, status) {
    setVulns((prev) => prev.map((v) => (v.id === vulnId ? { ...v, status } : v)));
    setSelectedVuln((prev) => (prev && prev.id === vulnId ? { ...prev, status } : prev));
    toast(`Status updated to ${status}`);
  }

  return (
    <Shell
      title="Security Dashboard"
      subtitle="Real-time penetration testing orchestration"
      actions={
        <>
          <div className="relative">
            <button
              className="relative p-2 glassmorphism rounded-lg hover:bg-white/10 transition-all"
              onClick={() => setShowNotifications(!showNotifications)}
            >
              <span className="text-lg">&#x1F514;</span>
              {vulns.filter((v) => (v.status || 'open') === 'open').length > 0 && (
                <span className="notification-badge absolute -top-1 -right-1 w-5 h-5 rounded-full text-xs flex items-center justify-center">
                  {vulns.filter((v) => (v.status || 'open') === 'open').length}
                </span>
              )}
            </button>
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 glassmorphism rounded-lg border border-white/10 shadow-xl z-50 overflow-hidden">
                <div className="p-3 border-b border-white/10 flex items-center justify-between">
                  <span className="text-sm font-semibold">Notifications</span>
                  <button className="text-xs text-gray-400 hover:text-white" onClick={() => { setShowNotifications(false); navigate('/vulnerabilities'); }}>View All</button>
                </div>
                <div className="max-h-72 overflow-y-auto">
                  {vulns.filter((v) => (v.status || 'open') === 'open').length === 0 ? (
                    <div className="p-4 text-sm text-gray-400 text-center">No open findings</div>
                  ) : (
                    vulns.filter((v) => (v.status || 'open') === 'open').slice(0, 8).map((v) => (
                      <div
                        key={v.id}
                        className="p-3 border-b border-white/5 hover:bg-white/5 cursor-pointer"
                        onClick={() => { setShowNotifications(false); setSelectedVuln(v); }}
                      >
                        <div className="flex items-center space-x-2">
                          <span className={`${severityBadge(v.severity)} px-1.5 py-0.5 rounded text-[10px]`}>{(v.severity || 'info').toUpperCase()}</span>
                          <span className="text-sm truncate">{v.title || 'Untitled'}</span>
                        </div>
                        <p className="text-xs text-gray-400 mt-1 truncate">{v.asset || 'Unknown asset'}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
          <button
            className="p-2 glassmorphism rounded-lg hover:bg-white/10 transition-all"
            onClick={() => navigate('/settings')}
          >
            <span className="text-lg">&#x2699;&#xFE0F;</span>
          </button>
        </>
      }
    >
      {error ? (
        <div className="glassmorphism p-4 rounded border border-white/10 text-sm text-gray-200 mb-6">
          {error}
        </div>
      ) : null}

      <div className="space-y-8">
        {/* Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div
            className="metric-card p-6 rounded-lg cursor-pointer"
            onClick={() => navigate('/vulnerabilities')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Critical Vulnerabilities</p>
                <p className="text-3xl font-bold white-glow-text">{loading ? '\u2014' : metrics.critical}</p>
              </div>
              <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center">
                <span className="text-2xl">&#x1F6A8;</span>
              </div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className="progress-bar h-2 rounded-full" style={{ width: loading ? '0%' : '85%' }} />
              </div>
              <p className="text-xs text-gray-400 mt-1">From all scans</p>
            </div>
          </div>

          <div
            className="metric-card p-6 rounded-lg cursor-pointer"
            onClick={() => navigate('/vulnerabilities')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">High Risk Issues</p>
                <p className="text-3xl font-bold text-gray-300">{loading ? '\u2014' : metrics.high}</p>
              </div>
              <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center">
                <span className="text-2xl">&#x26A0;&#xFE0F;</span>
              </div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className="bg-gray-400 h-2 rounded-full" style={{ width: loading ? '0%' : '65%' }} />
              </div>
              <p className="text-xs text-gray-400 mt-1">From all scans</p>
            </div>
          </div>

          <div
            className="metric-card p-6 rounded-lg cursor-pointer"
            onClick={() => navigate('/scan')}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Active Scans</p>
                <p className="text-3xl font-bold text-gray-300">{loading ? '\u2014' : runningCount}</p>
              </div>
              <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center">
                <span className="text-2xl">&#x1F50D;</span>
              </div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className="bg-gray-500 h-2 rounded-full" style={{ width: loading ? '0%' : '45%' }} />
              </div>
              <p className="text-xs text-gray-400 mt-1">Running right now</p>
            </div>
          </div>

          <div className="metric-card p-6 rounded-lg cursor-pointer" onClick={() => navigate('/vulnerabilities')}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">AI Confidence</p>
                <p className="text-3xl font-bold ai-high">{loading ? '\u2014' : `${metrics.ai}%`}</p>
              </div>
              <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center">
                <span className="text-2xl">&#x1F916;</span>
              </div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div className="bg-white h-2 rounded-full" style={{ width: loading ? '0%' : `${metrics.ai}%` }} />
              </div>
              <p className="text-xs text-gray-400 mt-1">Average across findings</p>
            </div>
          </div>
        </div>

        {/* Recent Scans and AI Insights */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 glassmorphism p-6 rounded-lg">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold white-glow-text">Recent Scans</h3>
              <button
                className="px-4 py-2 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium"
                onClick={() => setShowScanModal(true)}
              >
                New Scan
              </button>
            </div>

            <div className="space-y-4">
              {scans.length === 0 && !loading ? (
                <div className="text-center py-8">
                  <p className="text-gray-400 text-sm mb-4">No scans yet. Start your first scan!</p>
                  <button
                    className="px-6 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium"
                    onClick={() => setShowScanModal(true)}
                  >
                    Start First Scan
                  </button>
                </div>
              ) : null}

              {scans.slice(0, 5).map((s) => {
                const isRunning = s.status === 'running';
                const pct = clamp(s.progress || 0, 0, 100);
                return (
                  <div
                    key={s.id}
                    className={`p-4 rounded-lg cursor-pointer card-hover ${isRunning ? 'status-active' : 'bg-white/5 border border-white/10'}`}
                    onClick={() => navigate('/scan')}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <div className={`w-3 h-3 rounded-full ${isRunning ? 'bg-white animate-pulse' : 'bg-gray-400'}`} />
                        <div>
                          <p className="font-medium">{s.target || 'Unknown target'}</p>
                          <p className="text-sm text-gray-400">
                            {s.template || 'scan'} &bull; {s.vulnerabilitiesFound ?? 0} findings
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <div className="text-right">
                          <p className="text-sm font-medium">{isRunning ? `${pct}%` : s.status}</p>
                          <p className="text-xs text-gray-400">{s.startTime ? new Date(s.startTime).toLocaleDateString() : ''}</p>
                        </div>
                        {isRunning ? (
                          <div className="w-24 bg-gray-800 rounded-full h-2">
                            <div className="progress-bar h-2 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* AI Insights Panel */}
          <div className="glassmorphism p-6 rounded-lg">
            <h3 className="text-xl font-semibold white-glow-text mb-6">AI Insights</h3>
            <div className="space-y-4">
              {vulns.length === 0 ? (
                <p className="text-sm text-gray-400">Run a scan to see AI-powered insights about your findings.</p>
              ) : (
                <>
                  {vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length > 0 && (
                    <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="ai-high">&#x25CF;</span>
                        <span className="text-sm font-medium">Critical Findings Detected</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length} critical vulnerabilities require immediate attention.
                      </p>
                    </div>
                  )}
                  {vulns.length > 0 && (
                    <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="ai-medium">&#x25CF;</span>
                        <span className="text-sm font-medium">Scan Summary</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {vulns.length} total findings across {scans.length} scans. Average AI confidence: {metrics.ai}%.
                      </p>
                    </div>
                  )}
                  {vulns.filter((v) => (v.status || 'open') === 'open').length > 0 && (
                    <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="ai-high">&#x25CF;</span>
                        <span className="text-sm font-medium">Open Issues</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {vulns.filter((v) => (v.status || 'open') === 'open').length} vulnerabilities remain open and need to be addressed.
                      </p>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {/* Latest Findings Table */}
        <div className="glassmorphism p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-semibold white-glow-text">Latest Findings</h3>
            <span className="text-xs text-gray-400">Showing {loading ? '\u2026' : Math.min(vulns.length, 8)} of {vulns.length}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="text-gray-400">
                <tr className="border-b border-white/10">
                  <th className="text-left py-2 pr-4">Title</th>
                  <th className="text-left py-2 pr-4">Severity</th>
                  <th className="text-left py-2 pr-4">Asset</th>
                  <th className="text-left py-2 pr-4">Status</th>
                  <th className="text-left py-2 pr-4">CVSS</th>
                </tr>
              </thead>
              <tbody>
                {(vulns || []).slice(0, 8).map((v) => (
                  <tr
                    key={v.id}
                    className="border-b border-white/5 hover:bg-white/5 cursor-pointer"
                    onClick={() => setSelectedVuln(v)}
                  >
                    <td className="py-3 pr-4">{v.title || 'Untitled finding'}</td>
                    <td className="py-3 pr-4">
                      <span className={`${severityBadge(v.severity)} px-2 py-1 rounded text-xs`}>
                        {(v.severity || 'info').toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-gray-300 max-w-xs truncate">{v.asset || '\u2014'}</td>
                    <td className="py-3 pr-4 text-gray-300">{(v.status || 'open').toUpperCase()}</td>
                    <td className="py-3 pr-4 text-gray-300">{v.cvss ?? '\u2014'}</td>
                  </tr>
                ))}
                {!loading && vulns.length === 0 ? (
                  <tr>
                    <td className="py-4 text-gray-400" colSpan={5}>
                      No findings yet. Start a scan to discover vulnerabilities.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <button
            className="card-hover p-6 glassmorphism rounded-lg text-left transition-all"
            onClick={() => setShowScanModal(true)}
          >
            <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center mb-4">
              <span className="text-2xl">&#x1F50D;</span>
            </div>
            <h4 className="text-lg font-semibold mb-2">New Scan</h4>
            <p className="text-sm text-gray-400">
              Start a new vulnerability scan by providing a target URL.
            </p>
          </button>

          <button
            className="card-hover p-6 glassmorphism rounded-lg text-left transition-all"
            onClick={() => navigate('/vulnerabilities')}
          >
            <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center mb-4">
              <span className="text-2xl">&#x1F6E1;&#xFE0F;</span>
            </div>
            <h4 className="text-lg font-semibold mb-2">View Findings</h4>
            <p className="text-sm text-gray-400">
              Analyze and prioritize vulnerability findings with AI-powered insights.
            </p>
          </button>

          <button
            className="card-hover p-6 glassmorphism rounded-lg text-left transition-all"
            onClick={() => setShowReportModal(true)}
          >
            <div className="w-12 h-12 bg-white/10 rounded-lg flex items-center justify-center mb-4">
              <span className="text-2xl">&#x1F4C4;</span>
            </div>
            <h4 className="text-lg font-semibold mb-2">Generate Report</h4>
            <p className="text-sm text-gray-400">
              Generate a professional PDF security report with executive summary and detailed findings.
            </p>
          </button>
        </div>
      </div>

      <NewScanModal
        open={showScanModal}
        onClose={() => setShowScanModal(false)}
        onStarted={handleScanStarted}
      />

      <VulnDetailModal
        open={!!selectedVuln}
        vuln={selectedVuln}
        onClose={() => setSelectedVuln(null)}
        onStatusChange={handleVulnStatusChange}
      />

      <ReportConfigModal
        open={showReportModal}
        onClose={() => setShowReportModal(false)}
      />
    </Shell>
  );
}
