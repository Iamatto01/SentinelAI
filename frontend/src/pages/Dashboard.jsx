import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Shell from '../components/Shell.jsx';
import { useToast } from '../components/Toast.jsx';
import NewScanModal from '../components/NewScanModal.jsx';
import VulnDetailModal from '../components/VulnDetailModal.jsx';
import ReportConfigModal from '../components/ReportConfigModal.jsx';
import { apiFetch } from '../lib/api.js';
import { 
  staggerContainer, 
  fadeInUp, 
  fadeInLeft, 
  fadeInRight,
  metricCardVariant,
  glassCardHover,
  buttonTap,
  notificationPop 
} from '../lib/animations.js';

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
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="relative p-2 glass-button rounded-xl"
              onClick={() => setShowNotifications(!showNotifications)}
            >
              <span className="text-lg">&#x1F514;</span>
              {vulns.filter((v) => (v.status || 'open') === 'open').length > 0 && (
                <motion.span 
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  className="notification-badge absolute -top-1 -right-1 w-5 h-5 rounded-full text-xs flex items-center justify-center"
                >
                  {vulns.filter((v) => (v.status || 'open') === 'open').length}
                </motion.span>
              )}
            </motion.button>
            <AnimatePresence>
              {showNotifications && (
                <motion.div 
                  variants={notificationPop}
                  initial="hidden"
                  animate="show"
                  exit="exit"
                  className="absolute right-0 mt-2 w-80 glassmorphism rounded-2xl border border-white/10 shadow-xl z-50 overflow-hidden"
                >
                  <div className="p-3 border-b border-white/10 flex items-center justify-between">
                    <span className="text-sm font-semibold">Notifications</span>
                    <button className="text-xs text-gray-400 hover:text-white transition-colors" onClick={() => { setShowNotifications(false); navigate('/vulnerabilities'); }}>View All</button>
                  </div>
                  <div className="max-h-72 overflow-y-auto">
                    {vulns.filter((v) => (v.status || 'open') === 'open').length === 0 ? (
                      <div className="p-4 text-sm text-gray-400 text-center">No open findings</div>
                    ) : (
                      vulns.filter((v) => (v.status || 'open') === 'open').slice(0, 8).map((v, index) => (
                        <motion.div
                          key={v.id}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.05 }}
                          className="p-3 border-b border-white/5 hover:bg-white/5 cursor-pointer transition-colors"
                          onClick={() => { setShowNotifications(false); setSelectedVuln(v); }}
                        >
                          <div className="flex items-center space-x-2">
                            <span className={`${severityBadge(v.severity)} px-1.5 py-0.5 rounded text-[10px]`}>{(v.severity || 'info').toUpperCase()}</span>
                            <span className="text-sm truncate">{v.title || 'Untitled'}</span>
                          </div>
                          <p className="text-xs text-gray-400 mt-1 truncate">{v.asset || 'Unknown asset'}</p>
                        </motion.div>
                      ))
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          <motion.button
            whileHover={{ scale: 1.05, rotate: 90 }}
            whileTap={{ scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 400 }}
            className="p-2 glass-button rounded-xl"
            onClick={() => navigate('/settings')}
          >
            <span className="text-lg">&#x2699;&#xFE0F;</span>
          </motion.button>
        </>
      }
    >
      {error ? (
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glassmorphism p-4 rounded-xl border border-white/10 text-sm text-gray-200 mb-6"
        >
          {error}
        </motion.div>
      ) : null}

      <div className="space-y-8">
        {/* Metric Cards with staggered entry from different directions */}
        <motion.div 
          variants={staggerContainer}
          initial="hidden"
          animate="show"
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        >
          {[
            { 
              label: 'Critical Vulnerabilities', 
              value: loading ? '\u2014' : metrics.critical, 
              icon: '🚨', 
              glow: true,
              progress: 85,
              onClick: () => navigate('/vulnerabilities')
            },
            { 
              label: 'High Risk Issues', 
              value: loading ? '\u2014' : metrics.high, 
              icon: '⚠️',
              progress: 65,
              onClick: () => navigate('/vulnerabilities')
            },
            { 
              label: 'Active Scans', 
              value: loading ? '\u2014' : runningCount, 
              icon: '🔍',
              progress: 45,
              onClick: () => navigate('/scan')
            },
            { 
              label: 'AI Confidence', 
              value: loading ? '\u2014' : `${metrics.ai}%`, 
              icon: '🤖',
              glow: true,
              progress: metrics.ai,
              onClick: () => navigate('/vulnerabilities')
            }
          ].map((card, index) => (
            <motion.div
              key={card.label}
              custom={index}
              variants={metricCardVariant(index)}
              whileHover={{ scale: 1.03, y: -6 }}
              whileTap={{ scale: 0.98 }}
              className="metric-card p-6 rounded-2xl cursor-pointer"
              onClick={card.onClick}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm">{card.label}</p>
                  <p className={`text-3xl font-bold ${card.glow ? 'white-glow-text' : 'text-gray-300'}`}>
                    {card.value}
                  </p>
                </div>
                <motion.div 
                  whileHover={{ scale: 1.2, rotate: 10 }}
                  className="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center"
                >
                  <span className="text-2xl">{card.icon}</span>
                </motion.div>
              </div>
              <div className="mt-4">
                <div className="w-full bg-gray-800/50 rounded-full h-2 overflow-hidden">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: loading ? '0%' : `${card.progress}%` }}
                    transition={{ duration: 1, delay: index * 0.1 + 0.5, ease: 'easeOut' }}
                    className="progress-bar h-2 rounded-full" 
                  />
                </div>
                <p className="text-xs text-gray-400 mt-1">
                  {card.label === 'Active Scans' ? 'Running right now' : 
                   card.label === 'AI Confidence' ? 'Average across findings' : 'From all scans'}
                </p>
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Recent Scans and AI Insights */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <motion.div 
            variants={fadeInLeft}
            initial="hidden"
            animate="show"
            className="lg:col-span-2 glassmorphism p-6 rounded-2xl"
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold white-glow-text">Recent Scans</h3>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="px-4 py-2 glass-button-primary rounded-xl font-medium"
                onClick={() => setShowScanModal(true)}
              >
                New Scan
              </motion.button>
            </div>

            <motion.div 
              variants={staggerContainer}
              initial="hidden"
              animate="show"
              className="space-y-4"
            >
              {scans.length === 0 && !loading ? (
                <div className="text-center py-8">
                  <p className="text-gray-400 text-sm mb-4">No scans yet. Start your first scan!</p>
                  <motion.button
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    className="px-6 py-3 glass-button-primary rounded-xl font-medium"
                    onClick={() => setShowScanModal(true)}
                  >
                    Start First Scan
                  </motion.button>
                </div>
              ) : null}

              {scans.slice(0, 5).map((s, index) => {
                const isRunning = s.status === 'running';
                const pct = clamp(s.progress || 0, 0, 100);
                return (
                  <motion.div
                    key={s.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    whileHover={{ scale: 1.01, x: 4 }}
                    className={`p-4 rounded-xl cursor-pointer card-hover ${isRunning ? 'status-active' : 'bg-white/5 border border-white/10'}`}
                    onClick={() => navigate('/scan')}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <motion.div 
                          animate={isRunning ? { scale: [1, 1.2, 1] } : {}}
                          transition={{ repeat: Infinity, duration: 1.5 }}
                          className={`w-3 h-3 rounded-full ${isRunning ? 'bg-white' : 'bg-gray-400'}`} 
                        />
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
                          <div className="w-24 bg-gray-800/50 rounded-full h-2 overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${pct}%` }}
                              className="progress-bar h-2 rounded-full" 
                            />
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </motion.div>
          </motion.div>

          {/* AI Insights Panel */}
          <motion.div 
            variants={fadeInRight}
            initial="hidden"
            animate="show"
            className="glassmorphism p-6 rounded-2xl"
          >
            <h3 className="text-xl font-semibold white-glow-text mb-6">AI Insights</h3>
            <motion.div 
              variants={staggerContainer}
              initial="hidden"
              animate="show"
              className="space-y-4"
            >
              {vulns.length === 0 ? (
                <p className="text-sm text-gray-400">Run a scan to see AI-powered insights about your findings.</p>
              ) : (
                <>
                  {vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length > 0 && (
                    <motion.div 
                      variants={fadeInUp}
                      whileHover={{ scale: 1.02 }}
                      className="p-4 bg-white/5 rounded-xl border border-white/10"
                    >
                      <div className="flex items-center space-x-2 mb-2">
                        <motion.span 
                          animate={{ scale: [1, 1.3, 1] }}
                          transition={{ repeat: Infinity, duration: 2 }}
                          className="ai-high"
                        >●</motion.span>
                        <span className="text-sm font-medium">Critical Findings Detected</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {vulns.filter((v) => (v.severity || '').toLowerCase() === 'critical').length} critical vulnerabilities require immediate attention.
                      </p>
                    </motion.div>
                  )}
                  {vulns.length > 0 && (
                    <motion.div 
                      variants={fadeInUp}
                      whileHover={{ scale: 1.02 }}
                      className="p-4 bg-white/5 rounded-xl border border-white/10"
                    >
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="ai-medium">●</span>
                        <span className="text-sm font-medium">Scan Summary</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {vulns.length} total findings across {scans.length} scans. Average AI confidence: {metrics.ai}%.
                      </p>
                    </motion.div>
                  )}
                  {vulns.filter((v) => (v.status || 'open') === 'open').length > 0 && (
                    <motion.div 
                      variants={fadeInUp}
                      whileHover={{ scale: 1.02 }}
                      className="p-4 bg-white/5 rounded-xl border border-white/10"
                    >
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="ai-high">●</span>
                        <span className="text-sm font-medium">Open Issues</span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {vulns.filter((v) => (v.status || 'open') === 'open').length} vulnerabilities remain open and need to be addressed.
                      </p>
                    </motion.div>
                  )}
                </>
              )}
            </motion.div>
          </motion.div>
        </div>

        {/* Latest Findings Table */}
        <motion.div 
          variants={fadeInUp}
          initial="hidden"
          animate="show"
          className="glassmorphism p-6 rounded-2xl"
        >
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
                {(vulns || []).slice(0, 8).map((v, index) => (
                  <motion.tr
                    key={v.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 }}
                    whileHover={{ backgroundColor: 'rgba(255,255,255,0.05)' }}
                    className="border-b border-white/5 cursor-pointer transition-colors"
                    onClick={() => setSelectedVuln(v)}
                  >
                    <td className="py-3 pr-4">{v.title || 'Untitled finding'}</td>
                    <td className="py-3 pr-4">
                      <span className={`${severityBadge(v.severity)} px-2 py-1 rounded-lg text-xs`}>
                        {(v.severity || 'info').toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-gray-300 max-w-xs truncate">{v.asset || '\u2014'}</td>
                    <td className="py-3 pr-4 text-gray-300">{(v.status || 'open').toUpperCase()}</td>
                    <td className="py-3 pr-4 text-gray-300">{v.cvss ?? '\u2014'}</td>
                  </motion.tr>
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
        </motion.div>

        {/* Quick Actions */}
        <motion.div 
          variants={staggerContainer}
          initial="hidden"
          animate="show"
          className="grid grid-cols-1 md:grid-cols-3 gap-6"
        >
          {[
            { 
              icon: '🔍', 
              title: 'New Scan', 
              description: 'Start a new vulnerability scan by providing a target URL.',
              onClick: () => setShowScanModal(true)
            },
            { 
              icon: '🛡️', 
              title: 'View Findings', 
              description: 'Analyze and prioritize vulnerability findings with AI-powered insights.',
              onClick: () => navigate('/vulnerabilities')
            },
            { 
              icon: '📄', 
              title: 'Generate Report', 
              description: 'Generate a professional PDF security report with executive summary.',
              onClick: () => setShowReportModal(true)
            }
          ].map((action, index) => (
            <motion.button
              key={action.title}
              variants={fadeInUp}
              whileHover={{ scale: 1.03, y: -4 }}
              whileTap={{ scale: 0.98 }}
              className="card-hover p-6 glassmorphism rounded-2xl text-left"
              onClick={action.onClick}
            >
              <motion.div 
                whileHover={{ scale: 1.1, rotate: 5 }}
                className="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center mb-4"
              >
                <span className="text-2xl">{action.icon}</span>
              </motion.div>
              <h4 className="text-lg font-semibold mb-2">{action.title}</h4>
              <p className="text-sm text-gray-400">{action.description}</p>
            </motion.button>
          ))}
        </motion.div>
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
