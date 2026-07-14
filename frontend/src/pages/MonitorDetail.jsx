import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import { apiFetch } from '../lib/api.js';
import { fadeInUp } from '../lib/animations.js';
import { ArrowLeft, Activity, Clock, Shield, AlertTriangle, FileText, CheckCircle, XCircle, Pause, Play, RefreshCw } from 'lucide-react';

const healthColors = {
  healthy: { bg: 'bg-emerald-500/15', text: 'text-emerald-400', dot: 'bg-emerald-400', label: 'Healthy' },
  degraded: { bg: 'bg-amber-500/15', text: 'text-amber-400', dot: 'bg-amber-400', label: 'Degraded' },
  critical: { bg: 'bg-red-500/15', text: 'text-red-400', dot: 'bg-red-400', label: 'Critical' },
  down: { bg: 'bg-red-800/20', text: 'text-red-300', dot: 'bg-red-600', label: 'Down' },
  unknown: { bg: 'bg-gray-500/15', text: 'text-gray-400', dot: 'bg-gray-500', label: 'Pending' },
};

function timeAgo(dateStr) {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString();
}

export default function MonitorDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const [monitor, setMonitor] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('timeline');

  const loadData = useCallback(async () => {
    try {
      const [monData, evtData, alertData, rptData] = await Promise.all([
        apiFetch(`/api/monitors/${id}`),
        apiFetch(`/api/monitors/${id}/events?limit=100`),
        apiFetch(`/api/monitors/${id}/alerts`),
        apiFetch(`/api/monitors/${id}/reports`),
      ]);
      setMonitor(monData?.monitor);
      setEvents(evtData?.events || []);
      setAlerts(alertData?.alerts || []);
      setReports(rptData?.reports || []);
    } catch (e) {
      toast.error(e?.message || 'Failed to load monitor');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 20000);
    return () => clearInterval(interval);
  }, [loadData]);

  async function toggleStatus() {
    if (!monitor) return;
    try {
      await apiFetch(`/api/monitors/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: monitor.status === 'active' ? 'paused' : 'active' }),
      });
      toast.success(monitor.status === 'active' ? 'Monitor paused' : 'Monitor resumed');
      loadData();
    } catch (e) {
      toast.error(e?.message || 'Failed');
    }
  }

  async function ackAlert(alertId) {
    try {
      await apiFetch(`/api/monitors/${id}/alerts/${alertId}/ack`, { method: 'POST' });
      toast.success('Alert acknowledged');
      loadData();
    } catch (e) {
      toast.error(e?.message || 'Failed');
    }
  }

  if (loading) {
    return (
      <Shell title="Monitor Detail" subtitle="Loading...">
        <div className="flex items-center justify-center py-20">
          <div className="w-10 h-10 border-2 border-white/30 border-t-white rounded-full animate-spin" />
        </div>
      </Shell>
    );
  }

  if (!monitor) {
    return (
      <Shell title="Monitor Not Found">
        <div className="text-center py-20">
          <p className="text-gray-400 mb-4">This monitor does not exist or you don't have access.</p>
          <button onClick={() => navigate('/monitoring')} className="btn-primary">Back to Monitoring</button>
        </div>
      </Shell>
    );
  }

  const health = healthColors[monitor.healthStatus] || healthColors.unknown;
  const unacknowledged = alerts.filter(a => !a.acknowledged);
  const tabs = [
    { key: 'timeline', label: 'Timeline', icon: Clock, count: events.length },
    { key: 'alerts', label: 'Alerts', icon: AlertTriangle, count: unacknowledged.length },
    { key: 'reports', label: 'Reports', icon: FileText, count: reports.length },
  ];

  return (
    <Shell
      title={
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/monitoring')} className="p-1.5 rounded-lg hover:bg-white/10 transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <span className="truncate">{monitor.target}</span>
        </div>
      }
      subtitle={`Schedule: every ${monitor.schedule} · ${monitor.totalChecks} checks completed`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={toggleStatus} className="btn-secondary flex items-center gap-2 text-sm">
            {monitor.status === 'active' ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            {monitor.status === 'active' ? 'Pause' : 'Resume'}
          </button>
          <button onClick={loadData} className="btn-secondary p-2" title="Refresh">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      }
    >
      <div className="space-y-6">

        {/* ── Status Cards ──────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <motion.div variants={fadeInUp} initial="hidden" animate="show" className="glassmorphism rounded-2xl p-4 border border-white/10">
            <p className="text-xs text-gray-400 mb-2">Health Status</p>
            <div className={`flex items-center gap-2 ${health.text}`}>
              <div className={`w-3 h-3 rounded-full ${health.dot} ${monitor.healthStatus !== 'unknown' ? 'animate-pulse' : ''}`} />
              <span className="text-lg font-bold">{health.label}</span>
            </div>
          </motion.div>

          <motion.div variants={fadeInUp} initial="hidden" animate="show" className="glassmorphism rounded-2xl p-4 border border-white/10">
            <p className="text-xs text-gray-400 mb-2">Last Check</p>
            <p className="text-lg font-bold">{timeAgo(monitor.lastCheckAt)}</p>
            <p className="text-xs text-gray-500">{formatDate(monitor.lastCheckAt)}</p>
          </motion.div>

          <motion.div variants={fadeInUp} initial="hidden" animate="show" className="glassmorphism rounded-2xl p-4 border border-white/10">
            <p className="text-xs text-gray-400 mb-2">Total Checks</p>
            <p className="text-lg font-bold">{monitor.totalChecks}</p>
          </motion.div>

          <motion.div variants={fadeInUp} initial="hidden" animate="show" className="glassmorphism rounded-2xl p-4 border border-white/10">
            <p className="text-xs text-gray-400 mb-2">Open Alerts</p>
            <p className={`text-lg font-bold ${unacknowledged.length > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {unacknowledged.length}
            </p>
          </motion.div>
        </div>

        {/* ── Tabs ──────────────────────────────────────────────────── */}
        <div className="flex gap-1 p-1 rounded-xl bg-white/[0.04] w-fit">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-all ${
                tab === t.key ? 'bg-white/[0.12] text-white' : 'text-gray-400 hover:text-white hover:bg-white/[0.06]'
              }`}
            >
              <t.icon className="w-4 h-4" />
              {t.label}
              {t.count > 0 && (
                <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                  tab === t.key ? 'bg-white/20' : 'bg-white/10'
                }`}>{t.count}</span>
              )}
            </button>
          ))}
        </div>

        {/* ── Timeline Tab ─────────────────────────────────────────── */}
        {tab === 'timeline' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glassmorphism rounded-2xl border border-white/10 p-5">
            {events.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <Clock className="w-10 h-10 mx-auto mb-3 opacity-50" />
                <p>No events yet. The first check will run shortly.</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[500px] overflow-y-auto">
                {events.map((evt) => {
                  const sevClass = (evt.severity || '') === 'critical' ? 'border-l-red-500' :
                    evt.severity === 'high' ? 'border-l-orange-500' :
                    evt.severity === 'medium' ? 'border-l-amber-500' :
                    evt.severity === 'low' ? 'border-l-blue-400' : 'border-l-gray-600';
                  return (
                    <div key={evt.id} className={`p-3 rounded-xl bg-white/[0.03] border-l-2 ${sevClass}`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium">{evt.title}</span>
                        <span className="text-xs text-gray-500">{timeAgo(evt.createdAt)}</span>
                      </div>
                      {evt.aiSummary && (
                        <p className="text-xs text-gray-400 mt-1 leading-relaxed">{evt.aiSummary}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}

        {/* ── Alerts Tab ───────────────────────────────────────────── */}
        {tab === 'alerts' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glassmorphism rounded-2xl border border-white/10 p-5">
            {alerts.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <Shield className="w-10 h-10 mx-auto mb-3 opacity-50" />
                <p>No alerts triggered. All clear!</p>
              </div>
            ) : (
              <div className="space-y-2">
                {alerts.map((alert) => {
                  const sev = (alert.severity || 'info').toLowerCase();
                  const sevClass = sev === 'critical' ? 'text-red-400' : sev === 'high' ? 'text-orange-400' : sev === 'medium' ? 'text-amber-400' : 'text-gray-400';
                  return (
                    <div key={alert.id} className={`p-3 rounded-xl flex items-center justify-between ${alert.acknowledged ? 'bg-white/[0.02] opacity-60' : 'bg-white/[0.05]'}`}>
                      <div className="flex items-center gap-3 min-w-0">
                        {alert.acknowledged ? <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" /> : <XCircle className={`w-4 h-4 flex-shrink-0 ${sevClass}`} />}
                        <div className="min-w-0">
                          <p className="text-sm truncate">{alert.title}</p>
                          <p className="text-xs text-gray-500">{formatDate(alert.createdAt)}{alert.acknowledgedBy ? ` · Acked by ${alert.acknowledgedBy}` : ''}</p>
                        </div>
                      </div>
                      {!alert.acknowledged && (
                        <button onClick={() => ackAlert(alert.id)} className="text-xs px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 transition-colors whitespace-nowrap ml-3">
                          Acknowledge
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}

        {/* ── Reports Tab ──────────────────────────────────────────── */}
        {tab === 'reports' && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glassmorphism rounded-2xl border border-white/10 p-5">
            {reports.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
                <p>No reports generated yet. Reports are auto-generated periodically.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {reports.map((rpt) => (
                  <div key={rpt.id} className="p-4 rounded-xl bg-white/[0.04] hover:bg-white/[0.07] transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-blue-400" />
                        <span className="text-sm font-medium capitalize">{rpt.type} Report</span>
                      </div>
                      <span className="text-xs text-gray-500">{rpt.period}</span>
                    </div>
                    {rpt.summary && (
                      <p className="text-xs text-gray-400 leading-relaxed">{rpt.summary}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}

        {/* ── Configuration ─────────────────────────────────────────── */}
        <motion.div variants={fadeInUp} initial="hidden" animate="show" className="glassmorphism rounded-2xl border border-white/10 p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Configuration</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <p className="text-xs text-gray-500">Schedule</p>
              <p className="font-medium">Every {monitor.schedule}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Status</p>
              <p className={`font-medium ${monitor.status === 'active' ? 'text-emerald-400' : 'text-amber-400'}`}>
                {monitor.status === 'active' ? '● Active' : '⏸ Paused'}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Modules</p>
              <p className="font-medium">{(monitor.modules || []).join(', ')}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500">Created</p>
              <p className="font-medium">{formatDate(monitor.createdAt)}</p>
            </div>
          </div>
        </motion.div>
      </div>
    </Shell>
  );
}
