import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import MonitorSetupModal from '../components/MonitorSetupModal.jsx';
import { apiFetch } from '../lib/api.js';
import { staggerContainer, fadeInUp } from '../lib/animations.js';
import { Activity, Shield, AlertTriangle, Plus, Pause, Play, Trash2, Eye, Clock, CheckCircle, XCircle, RefreshCw, FileText } from 'lucide-react';

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

export default function Monitoring() {
  const [fleet, setFleet] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showSetup, setShowSetup] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();

  const [logs, setLogs] = useState([]);

  const loadLogs = useCallback(async () => {
    try {
      const data = await apiFetch('/api/logs?limit=15');
      setLogs(data?.logs || []);
    } catch (e) {
      // Ignore background log fetch errors
    }
  }, []);

  const loadFleet = useCallback(async () => {
    try {
      const data = await apiFetch('/api/fleet/overview');
      setFleet(data);
    } catch (e) {
      toast.error(e?.message || 'Failed to load fleet data');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadFleet();
    loadLogs();
    const interval = setInterval(() => {
      loadFleet();
      loadLogs();
    }, 15000);
    return () => clearInterval(interval);
  }, [loadFleet, loadLogs]);

  async function toggleMonitor(id, currentStatus) {
    try {
      await apiFetch(`/api/monitors/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: currentStatus === 'active' ? 'paused' : 'active' }),
      });
      toast.success(currentStatus === 'active' ? 'Monitor paused' : 'Monitor resumed');
      loadFleet();
    } catch (e) {
      toast.error(e?.message || 'Failed to update monitor');
    }
  }

  async function deleteMonitor(id) {
    if (!confirm('Delete this monitor and all its data?')) return;
    try {
      await apiFetch(`/api/monitors/${id}`, { method: 'DELETE' });
      toast.success('Monitor deleted');
      loadFleet();
    } catch (e) {
      toast.error(e?.message || 'Failed to delete monitor');
    }
  }

  async function acknowledgeAlert(monitorId, alertId) {
    try {
      await apiFetch(`/api/monitors/${monitorId}/alerts/${alertId}/ack`, { method: 'POST' });
      toast.success('Alert acknowledged');
      loadFleet();
    } catch (e) {
      toast.error(e?.message || 'Failed to acknowledge alert');
    }
  }

  const hc = fleet?.healthCounts || {};

  return (
    <Shell
      title="Monitoring"
      subtitle="SIEM — Continuous security monitoring for all sites"
      actions={
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="btn-primary flex items-center gap-2"
          onClick={() => setShowSetup(true)}
        >
          <Plus className="w-4 h-4" />
          <span className="hidden sm:inline">New Monitor</span>
        </motion.button>
      }
    >
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-10 h-10 border-2 border-white/30 border-t-white rounded-full animate-spin" />
        </div>
      ) : (
        <motion.div variants={staggerContainer} initial="hidden" animate="show" className="space-y-6">

          {/* ── Fleet Overview Cards ──────────────────────────────────── */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Total Monitors', value: fleet?.totalMonitors || 0, icon: Activity, color: 'text-blue-400' },
              { label: 'Healthy', value: hc.healthy || 0, icon: CheckCircle, color: 'text-emerald-400' },
              { label: 'Degraded / Critical', value: (hc.degraded || 0) + (hc.critical || 0) + (hc.down || 0), icon: AlertTriangle, color: 'text-amber-400' },
              { label: 'Open Alerts', value: fleet?.unacknowledgedAlerts || 0, icon: Shield, color: 'text-red-400' },
            ].map((card, i) => (
              <motion.div
                key={card.label}
                variants={fadeInUp}
                className="glassmorphism rounded-2xl p-4 border border-white/10"
              >
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-xl bg-white/5 ${card.color}`}>
                    <card.icon className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{card.value}</p>
                    <p className="text-xs text-gray-400">{card.label}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          {/* ── Alert Feed ────────────────────────────────────────────── */}
          {fleet?.recentAlerts?.length > 0 && (
            <motion.div variants={fadeInUp} className="glassmorphism rounded-2xl border border-white/10 p-5">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                Unacknowledged Alerts
              </h3>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {fleet.recentAlerts.map((alert) => {
                  const sev = (alert.severity || 'info').toLowerCase();
                  const sevClass = sev === 'critical' ? 'text-red-400' : sev === 'high' ? 'text-orange-400' : sev === 'medium' ? 'text-amber-400' : 'text-gray-400';
                  return (
                    <div key={alert.id} className="flex items-center justify-between p-3 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] transition-colors">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className={`text-xs font-bold uppercase ${sevClass}`}>{sev}</span>
                        <span className="text-sm truncate">{alert.title}</span>
                        <span className="text-xs text-gray-500">{timeAgo(alert.createdAt)}</span>
                      </div>
                      <button
                        onClick={() => acknowledgeAlert(alert.monitorId, alert.id)}
                        className="text-xs px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 transition-colors whitespace-nowrap"
                      >
                        Acknowledge
                      </button>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}

          {/* ── Monitor Grid ─────────────────────────────────────────── */}
          {fleet?.monitors?.length === 0 ? (
            <motion.div variants={fadeInUp} className="glassmorphism rounded-2xl border border-white/10 p-12 text-center">
              <Activity className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <h3 className="text-xl font-semibold mb-2">No monitors yet</h3>
              <p className="text-gray-400 mb-6">Set up continuous monitoring for your client websites</p>
              <button onClick={() => setShowSetup(true)} className="btn-primary">
                <Plus className="w-4 h-4 mr-2 inline" />
                Create First Monitor
              </button>
            </motion.div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {fleet?.monitors?.map((m) => {
                const health = healthColors[m.healthStatus] || healthColors.unknown;
                return (
                  <motion.div
                    key={m.id}
                    variants={fadeInUp}
                    whileHover={{ y: -2 }}
                    className="glassmorphism rounded-2xl border border-white/10 p-5 cursor-pointer group"
                    onClick={() => navigate(`/monitoring/${m.id}`)}
                  >
                    {/* Header */}
                    <div className="flex items-start justify-between mb-4">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold truncate group-hover:text-white transition-colors">{m.target}</p>
                        <p className="text-xs text-gray-500 mt-1">Every {m.schedule} · {m.totalChecks} checks</p>
                      </div>
                      <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${health.bg} ${health.text}`}>
                        <div className={`w-2 h-2 rounded-full ${health.dot} ${m.healthStatus === 'unknown' ? '' : 'animate-pulse'}`} />
                        {health.label}
                      </div>
                    </div>

                    {/* Last check */}
                    <div className="flex items-center gap-2 text-xs text-gray-400 mb-4">
                      <Clock className="w-3.5 h-3.5" />
                      <span>Last check: {timeAgo(m.lastCheckAt)}</span>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => toggleMonitor(m.id, m.status)}
                        className="p-2 rounded-lg bg-white/5 hover:bg-white/15 transition-colors"
                        title={m.status === 'active' ? 'Pause' : 'Resume'}
                      >
                        {m.status === 'active' ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                      </button>
                      <button
                        onClick={() => navigate(`/monitoring/${m.id}`)}
                        className="p-2 rounded-lg bg-white/5 hover:bg-white/15 transition-colors"
                        title="View details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteMonitor(m.id)}
                        className="p-2 rounded-lg bg-white/5 hover:bg-red-500/20 hover:text-red-400 transition-colors ml-auto"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}

          {/* ── Live Log Feed ───────────────────────────────────────── */}
          <motion.div variants={fadeInUp} className="glassmorphism rounded-2xl border border-white/10 p-5 mt-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <FileText className="w-5 h-5 text-gray-400" />
                Live Log Feed
              </h3>
              <button onClick={() => navigate('/logs')} className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                View All Logs
              </button>
            </div>
            <div className="space-y-2 max-h-[300px] overflow-y-auto font-mono text-xs pr-2 scrollbar-hide">
              {logs.length === 0 ? (
                <div className="text-gray-500 text-center py-4">Waiting for logs...</div>
              ) : (
                logs.map((log) => (
                  <div key={log.id} className="flex gap-3 p-2 rounded bg-black/20 hover:bg-black/40 border border-white/5 transition-colors">
                    <span className="text-gray-500 min-w-[60px] md:min-w-[100px] shrink-0">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`uppercase font-bold w-12 shrink-0 ${
                      log.level === 'error' ? 'text-red-400' : 
                      log.level === 'warning' ? 'text-amber-400' : 
                      log.level === 'debug' ? 'text-blue-400' : 'text-gray-400'
                    }`}>
                      {log.level}
                    </span>
                    <span className="text-emerald-400 w-16 md:w-24 truncate shrink-0" title={log.source}>
                      {log.source}
                    </span>
                    <span className="text-gray-300 break-all">{log.message}</span>
                  </div>
                ))
              )}
            </div>
          </motion.div>

        </motion.div>
      )}

      <AnimatePresence>
        {showSetup && (
          <MonitorSetupModal
            onClose={() => setShowSetup(false)}
            onCreated={() => { setShowSetup(false); loadFleet(); }}
          />
        )}
      </AnimatePresence>
    </Shell>
  );
}
