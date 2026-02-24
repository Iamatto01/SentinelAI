import { useEffect, useMemo, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import NewScanModal from '../components/NewScanModal.jsx';
import VulnDetailModal from '../components/VulnDetailModal.jsx';
import { apiFetch } from '../lib/api.js';

function fmt(dt) {
  try {
    return new Date(dt).toLocaleString();
  } catch {
    return String(dt || '');
  }
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function moduleClass(status) {
  const s = (status || '').toLowerCase();
  if (s === 'running') return 'module-running';
  if (s === 'completed') return 'module-completed';
  if (s === 'failed') return 'module-failed';
  if (s === 'skipped') return 'module-failed';
  return 'module-queued';
}

function logLevelClass(level) {
  const l = (level || '').toLowerCase();
  if (l === 'warn') return 'log-warn';
  if (l === 'error') return 'log-error';
  if (l === 'success') return 'log-success';
  return 'log-info';
}

function severityBadge(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'severity-critical';
  if (s === 'high') return 'severity-high';
  if (s === 'medium') return 'severity-medium';
  if (s === 'low') return 'severity-low';
  return 'severity-info';
}

export default function Scan() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [scans, setScans] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);
  const [scan, setScan] = useState(null);
  const [logs, setLogs] = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [duration, setDuration] = useState('00:00:00');
  const [showScanModal, setShowScanModal] = useState(false);
  const [vulnList, setVulnList] = useState([]);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const logRef = useRef(null);
  const socketRef = useRef(null);
  const toast = useToast();

  async function loadScans() {
    setLoading(true);
    setError('');
    try {
      const data = await apiFetch('/api/scans');
      const allScans = data?.scans || [];
      setScans(allScans);

      const running = allScans.find((s) => s.status === 'running');
      const target = running || allScans[0] || null;
      if (target) {
        setActiveScanId(target.id);
        setScan(target);
        const logsData = await apiFetch(`/api/scan/logs?scanId=${encodeURIComponent(target.id)}`);
        setLogs(logsData?.logs || []);
      }
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (!activeScanId) return;

    const socket = io({ transports: ['websocket', 'polling'] });
    socketRef.current = socket;

    socket.on('connect', () => {
      socket.emit('scan:join', activeScanId);
    });
    socket.on('scan:update', (payload) => {
      setScan(payload?.scan || null);
      setLogs(payload?.logs || []);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [activeScanId]);

  useEffect(() => {
    if (!scan?.startTime) return;
    const endTime = scan.endTime ? new Date(scan.endTime).getTime() : null;
    const tick = () => {
      const start = new Date(scan.startTime).getTime();
      const end = endTime || Date.now();
      const diff = end - start;
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setDuration(
        `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
      );
    };
    tick();
    if (!endTime) {
      const id = setInterval(tick, 1000);
      return () => clearInterval(id);
    }
  }, [scan?.startTime, scan?.endTime]);

  useEffect(() => {
    if (autoScroll && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const progress = useMemo(() => clamp(scan?.progress ?? 0, 0, 100), [scan]);

  const moduleStats = useMemo(() => {
    const modules = scan?.modules || [];
    return {
      completed: modules.filter((m) => ['completed', 'skipped'].includes((m.status || '').toLowerCase())).length,
      running: modules.filter((m) => (m.status || '').toLowerCase() === 'running').length,
      queued: modules.filter((m) => !['completed', 'running', 'failed', 'skipped'].includes((m.status || '').toLowerCase())).length,
    };
  }, [scan]);

  const [findings, setFindings] = useState({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  useEffect(() => {
    if (!scan?.id) return;
    apiFetch(`/api/scan/results?scanId=${encodeURIComponent(scan.id)}`)
      .then((r) => {
        const vulns = r?.vulnerabilities || [];
        setVulnList(vulns);
        setFindings({
          critical: vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length,
          high: vulns.filter((v) => (v.severity || '').toLowerCase() === 'high').length,
          medium: vulns.filter((v) => (v.severity || '').toLowerCase() === 'medium').length,
          low: vulns.filter((v) => (v.severity || '').toLowerCase() === 'low').length,
          info: vulns.filter((v) => (v.severity || '').toLowerCase() === 'info').length,
        });
      })
      .catch(() => {});
  }, [scan?.id, scan?.progress]);

  async function pause() {
    if (!scan?.id) return;
    try {
      await apiFetch('/api/scan/pause', { method: 'POST', body: { scanId: scan.id } });
      toast('Scan paused');
    } catch (e) {
      toast(`Pause failed: ${e.message}`);
    }
  }

  async function stop() {
    if (!scan?.id) return;
    try {
      await apiFetch('/api/scan/stop', { method: 'POST', body: { scanId: scan.id } });
      toast('Scan stopped');
    } catch (e) {
      toast(`Stop failed: ${e.message}`);
    }
  }

  function handleScanStarted(newScan) {
    toast('Scan started!');
    if (newScan?.id) {
      setActiveScanId(newScan.id);
      setScan(newScan);
      setLogs([]);
      setVulnList([]);
      setFindings({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    }
  }

  function selectScan(s) {
    if (socketRef.current && activeScanId) {
      socketRef.current.emit('scan:leave', activeScanId);
    }
    setActiveScanId(s.id);
    setScan(s);
    setLogs([]);
    setVulnList([]);
    apiFetch(`/api/scan/logs?scanId=${encodeURIComponent(s.id)}`)
      .then((r) => setLogs(r?.logs || []))
      .catch(() => {});
  }

  function exportLogs() {
    const text = logs.map((l) => `[${l.timestamp}] [${l.level}] ${l.message}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-logs-${scan?.id || 'unknown'}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Logs exported');
  }

  if (!loading && scans.length === 0) {
    return (
      <Shell
        title="Live Scan Monitor"
        subtitle="Real-time penetration testing orchestration"
        actions={
          <button
            className="px-4 py-2 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium"
            onClick={() => setShowScanModal(true)}
          >
            + New Scan
          </button>
        }
      >
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-20 h-20 bg-white/10 rounded-full flex items-center justify-center mb-6">
            <span className="text-4xl">&#x1F50D;</span>
          </div>
          <h3 className="text-2xl font-bold mb-2">No Scans Yet</h3>
          <p className="text-gray-400 mb-6">Start your first vulnerability scan by providing a target URL.</p>
          <button
            className="px-8 py-3 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium text-lg"
            onClick={() => setShowScanModal(true)}
          >
            Start New Scan
          </button>
        </div>

        <NewScanModal open={showScanModal} onClose={() => setShowScanModal(false)} onStarted={handleScanStarted} />
      </Shell>
    );
  }

  return (
    <Shell
      title="Live Scan Monitor"
      subtitle="Real-time penetration testing orchestration"
      actions={
        <>
          {scan?.status === 'running' && (
            <>
              <button className="control-button px-4 py-2 rounded hover:bg-white/10 transition-all" onClick={pause}>
                &#x23F8;&#xFE0F; Pause
              </button>
              <button className="control-button px-4 py-2 rounded hover:bg-white/10 transition-all" onClick={stop}>
                &#x23F9;&#xFE0F; Stop
              </button>
            </>
          )}
          <button
            className="px-4 py-2 bg-white text-black rounded hover:bg-gray-200 transition-all font-medium"
            onClick={() => setShowScanModal(true)}
          >
            + New Scan
          </button>
        </>
      }
    >
      {error ? (
        <div className="glassmorphism p-4 rounded border border-white/10 text-sm text-gray-200 mb-6">
          {error}
        </div>
      ) : null}

      <div className="space-y-6">
        {scans.length > 1 && (
          <div className="glassmorphism p-4 rounded-lg">
            <div className="flex items-center space-x-2 overflow-x-auto scrollbar-hide">
              {scans.slice(0, 10).map((s) => (
                <button
                  key={s.id}
                  className={`flex-shrink-0 px-4 py-2 rounded text-sm transition-all ${
                    activeScanId === s.id ? 'bg-white text-black font-medium' : 'border border-white/20 hover:bg-white/10'
                  }`}
                  onClick={() => selectScan(s)}
                >
                  {(s.target || 'scan').replace(/^https?:\/\//, '').slice(0, 30)}
                  {s.status === 'running' && ' (running)'}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="scan-info-card p-4 rounded-lg">
            <p className="text-sm text-gray-400 mb-1">Target</p>
            <p className="font-semibold white-glow-text truncate">{scan?.target || '\u2014'}</p>
          </div>
          <div className="scan-info-card p-4 rounded-lg">
            <p className="text-sm text-gray-400 mb-1">Start Time</p>
            <p className="font-semibold">{scan?.startTime ? fmt(scan.startTime) : '\u2014'}</p>
          </div>
          <div className="scan-info-card p-4 rounded-lg">
            <p className="text-sm text-gray-400 mb-1">Duration</p>
            <p className="font-semibold">{duration}</p>
          </div>
          <div className="scan-info-card p-4 rounded-lg">
            <p className="text-sm text-gray-400 mb-1">Progress</p>
            <p className="font-semibold white-glow-text">{loading ? '\u2014' : `${progress}%`}</p>
          </div>
        </div>

        <div className="glassmorphism p-6 rounded-lg">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold">Scan Progress</h3>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-white rounded-full animate-pulse" />
                <span className="text-sm">Running</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-gray-400 rounded-full" />
                <span className="text-sm">Completed</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-gray-600 rounded-full" />
                <span className="text-sm">Queued</span>
              </div>
            </div>
          </div>

          <div className="w-full bg-gray-800 rounded-full h-4 mb-4">
            <div className="progress-bar h-4 rounded-full transition-all" style={{ width: `${progress}%` }} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <p className="text-2xl font-bold text-white">{moduleStats.completed}</p>
              <p className="text-sm text-gray-400">Modules Completed</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-yellow-400">{moduleStats.running}</p>
              <p className="text-sm text-gray-400">Modules Running</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-400">{moduleStats.queued}</p>
              <p className="text-sm text-gray-400">Modules Queued</p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="glassmorphism p-6 rounded-lg">
            <h3 className="text-xl font-semibold mb-6">Module Status</h3>
            <div className="space-y-4">
              {(scan?.modules || []).map((m) => {
                const st = (m.status || 'queued').toLowerCase();
                const mp = clamp(m.progress || 0, 0, 100);
                return (
                  <div key={m.name} className={`${moduleClass(st)} p-4 rounded-lg`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">{m.name}</span>
                      {st === 'completed' ? (
                        <span className="text-sm text-green-400">&#x2713; Complete</span>
                      ) : st === 'skipped' ? (
                        <span className="text-sm text-yellow-400">Skipped</span>
                      ) : st === 'failed' ? (
                        <span className="text-sm text-red-400">Failed</span>
                      ) : (
                        <span className="text-sm text-gray-400">{mp}%</span>
                      )}
                    </div>
                    {st === 'running' ? (
                      <div className="w-full bg-gray-800 rounded-full h-2">
                        <div className="progress-bar h-2 rounded-full" style={{ width: `${mp}%` }} />
                      </div>
                    ) : null}
                    <p className="text-xs text-gray-400 mt-2">Status: {st}</p>
                  </div>
                );
              })}
              {!loading && (!scan?.modules || scan.modules.length === 0) ? (
                <div className="text-sm text-gray-400">No modules.</div>
              ) : null}
            </div>
          </div>

          <div className="glassmorphism p-6 rounded-lg">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold">Live Logs</h3>
              <div className="flex items-center space-x-2">
                <button
                  className="control-button px-3 py-1 rounded text-sm"
                  onClick={() => { setLogs([]); toast('Logs cleared'); }}
                >
                  Clear
                </button>
                <button
                  className="control-button px-3 py-1 rounded text-sm"
                  onClick={() => setAutoScroll((v) => !v)}
                >
                  Auto-scroll {autoScroll ? 'ON' : 'OFF'}
                </button>
                <button
                  className="control-button px-3 py-1 rounded text-sm"
                  onClick={exportLogs}
                >
                  Export
                </button>
              </div>
            </div>

            <div
              ref={logRef}
              className="terminal-output p-4 rounded h-96 overflow-y-auto scrollbar-hide"
            >
              {logs.map((l, idx) => (
                <div key={`${l.timestamp}-${idx}`} className="log-line">
                  <span className="log-timestamp">
                    [{new Date(l.timestamp || Date.now()).toLocaleTimeString()}]
                  </span>{' '}
                  <span className={logLevelClass(l.level)}>
                    [{(l.level || 'info').toUpperCase()}]
                  </span>{' '}
                  <span>{l.message}</span>
                </div>
              ))}
              {!loading && logs.length === 0 ? (
                <div className="text-gray-400">Waiting for logs...</div>
              ) : null}
            </div>
          </div>
        </div>

        <div className="glassmorphism p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-6">Real-time Findings</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-6">
            <div className="text-center p-4 bg-black border-2 border-white rounded-lg">
              <p className="text-3xl font-bold text-white">{findings.critical}</p>
              <p className="text-sm text-gray-400">Critical</p>
            </div>
            <div className="text-center p-4 bg-gray-800 rounded-lg">
              <p className="text-3xl font-bold text-white">{findings.high}</p>
              <p className="text-sm text-gray-400">High</p>
            </div>
            <div className="text-center p-4 bg-gray-600 rounded-lg">
              <p className="text-3xl font-bold text-white">{findings.medium}</p>
              <p className="text-sm text-gray-400">Medium</p>
            </div>
            <div className="text-center p-4 bg-gray-500 rounded-lg">
              <p className="text-3xl font-bold text-black">{findings.low}</p>
              <p className="text-sm text-gray-600">Low</p>
            </div>
            <div className="text-center p-4 bg-gray-400 rounded-lg">
              <p className="text-3xl font-bold text-black">{findings.info}</p>
              <p className="text-sm text-gray-600">Info</p>
            </div>
          </div>
        </div>

        {/* Vulnerability Results Table */}
        <div className="glassmorphism p-6 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-semibold">Scan Results</h3>
            <span className="text-xs text-gray-400">
              {vulnList.length} {vulnList.length === 1 ? 'finding' : 'findings'}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="text-gray-400">
                <tr className="border-b border-white/10">
                  <th className="text-left py-2 pr-4">Title</th>
                  <th className="text-left py-2 pr-4">Severity</th>
                  <th className="text-left py-2 pr-4">Asset</th>
                  <th className="text-left py-2 pr-4">Module</th>
                  <th className="text-left py-2 pr-4">CVSS</th>
                </tr>
              </thead>
              <tbody>
                {vulnList.map((v) => (
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
                    <td className="py-3 pr-4 text-gray-300">{v.module || '\u2014'}</td>
                    <td className="py-3 pr-4 text-gray-300">{v.cvss ?? '\u2014'}</td>
                  </tr>
                ))}
                {!loading && vulnList.length === 0 ? (
                  <tr>
                    <td className="py-4 text-gray-400" colSpan={5}>
                      No findings yet. Results will appear here as modules discover vulnerabilities.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <NewScanModal open={showScanModal} onClose={() => setShowScanModal(false)} onStarted={handleScanStarted} />

      <VulnDetailModal
        open={!!selectedVuln}
        vuln={selectedVuln}
        onClose={() => setSelectedVuln(null)}
        onStatusChange={(vulnId, status) => {
          setVulnList((prev) => prev.map((v) => (v.id === vulnId ? { ...v, status } : v)));
          setSelectedVuln((prev) => (prev && prev.id === vulnId ? { ...prev, status } : prev));
          toast(`Status updated to ${status}`);
        }}
      />
    </Shell>
  );
}
