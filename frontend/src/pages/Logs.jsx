import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, AlertTriangle, ShieldAlert, FileText, Database } from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, Cell 
} from 'recharts';
import { format } from 'date-fns';
import Shell from '../components/Shell.jsx';
import { apiFetch } from '../lib/api.js';
import { fadeInUp, staggerContainer } from '../lib/animations.js';

function LogLevelBadge({ level }) {
  let color = 'bg-gray-500/20 text-gray-300 border-gray-500/30';
  if (level === 'error') color = 'bg-red-500/20 text-red-400 border-red-500/30';
  if (level === 'warning') color = 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  if (level === 'debug') color = 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  
  return (
    <span className={`px-2 py-0.5 rounded text-xs uppercase font-semibold border ${color}`}>
      {level}
    </span>
  );
}

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState([]);
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('');
  const [loading, setLoading] = useState(true);

  async function loadData() {
    try {
      setLoading(true);
      const query = new URLSearchParams();
      if (search) query.set('search', search);
      if (levelFilter) query.set('level', levelFilter);
      query.set('limit', '50');

      const [logsRes, statsRes] = await Promise.all([
        apiFetch(`/api/logs?${query.toString()}`),
        apiFetch(`/api/logs/stats`)
      ]);

      setLogs(logsRes.logs || []);
      setStats(statsRes.stats || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    // Auto-refresh every 10 seconds for real-time observability
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [search, levelFilter]);

  // Aggregate stats for the chart
  const chartData = [
    { name: 'Error', count: stats.find(s => s.level === 'error')?.count || 0, color: '#f87171' },
    { name: 'Warning', count: stats.find(s => s.level === 'warning')?.count || 0, color: '#facc15' },
    { name: 'Info', count: stats.find(s => s.level === 'info')?.count || 0, color: '#3b82f6' },
  ];

  const anomalies = logs.filter(l => l.anomalyScore >= 0.7);

  return (
    <Shell
      title="Log Explorer"
      subtitle="Universal Observability & AI Log Analysis"
    >
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        
        {/* Left Column: Search & Stats */}
        <div className="lg:col-span-1 space-y-6">
          <motion.div 
            initial="hidden" animate="show" variants={fadeInUp}
            className="glassmorphism p-5 rounded-2xl border border-white/10"
          >
            <h3 className="text-lg font-semibold white-glow-text mb-4 flex items-center gap-2">
              <Search size={18} /> Search (SPL-lite)
            </h3>
            <div className="space-y-4">
              <input 
                type="text" 
                placeholder="Search logs (e.g., 'timeout')" 
                className="w-full bg-black/30 border border-white/10 rounded-xl px-4 py-2 text-sm focus:outline-none focus:border-primary-500"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && loadData()}
              />
              <select 
                className="w-full bg-black/30 border border-white/10 rounded-xl px-4 py-2 text-sm focus:outline-none"
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
              >
                <option value="">All Levels</option>
                <option value="error">Error</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
              </select>
            </div>
          </motion.div>

          <motion.div 
            initial="hidden" animate="show" variants={fadeInUp}
            className="glassmorphism p-5 rounded-2xl border border-white/10"
          >
            <h3 className="text-lg font-semibold white-glow-text mb-4 flex items-center gap-2">
              <Database size={18} /> Volume (24h)
            </h3>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" tick={{fill: '#9ca3af', fontSize: 12}} />
                  <YAxis tick={{fill: '#9ca3af', fontSize: 12}} />
                  <RechartsTooltip 
                    cursor={{fill: 'rgba(255,255,255,0.05)'}} 
                    contentStyle={{backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px'}} 
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          {anomalies.length > 0 && (
            <motion.div 
              initial="hidden" animate="show" variants={fadeInUp}
              className="bg-red-500/10 border border-red-500/30 p-5 rounded-2xl"
            >
              <h3 className="text-lg font-semibold text-red-400 mb-2 flex items-center gap-2">
                <ShieldAlert size={18} /> AI Threat Detected
              </h3>
              <p className="text-sm text-gray-300">
                AI Log Analyzer found <strong>{anomalies.length}</strong> anomalies in the current view.
              </p>
            </motion.div>
          )}
        </div>

        {/* Right Column: Log Feed */}
        <div className="lg:col-span-3">
          <motion.div 
            initial="hidden" animate="show" variants={fadeInUp}
            className="glassmorphism rounded-2xl border border-white/10 h-[calc(100vh-160px)] overflow-hidden flex flex-col"
          >
            <div className="p-4 border-b border-white/10 bg-black/20 flex justify-between items-center">
              <h3 className="text-lg font-semibold white-glow-text flex items-center gap-2">
                <FileText size={18} /> Live Log Feed
              </h3>
              <span className="text-xs text-gray-400">
                {loading ? 'Refreshing...' : `Showing ${logs.length} events`}
              </span>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-sm">
              {logs.length === 0 && !loading && (
                <div className="text-center text-gray-500 mt-10">
                  No logs found matching criteria.
                </div>
              )}
              
              <AnimatePresence>
                {logs.map((log) => (
                  <motion.div
                    key={log.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="p-3 rounded-xl border border-white/5 bg-black/40 hover:bg-black/60 transition-colors"
                  >
                    <div className="flex justify-between items-start mb-1">
                      <div className="flex items-center gap-3">
                        <LogLevelBadge level={log.level} />
                        <span className="text-gray-500 text-xs">
                          {format(new Date(log.timestamp), 'MMM dd, HH:mm:ss')}
                        </span>
                        <span className="text-primary-400 text-xs">
                          {log.source}
                        </span>
                      </div>
                      {log.anomalyScore >= 0.7 && (
                        <div className="flex items-center gap-1 text-red-400 text-xs font-sans font-bold bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                          <AlertTriangle size={12} /> AI ANOMALY ({log.anomalyScore.toFixed(1)})
                        </div>
                      )}
                    </div>
                    <div className="text-gray-300 break-all pl-1">
                      {log.message}
                    </div>
                    
                    {log.aiAnalysis && log.aiAnalysis !== 'Standard informational log.' && (
                      <div className="mt-2 pl-3 ml-1 border-l-2 border-primary-500/30 text-xs text-gray-400 font-sans">
                        <strong className="text-primary-400">AI Insight:</strong> {log.aiAnalysis}
                      </div>
                    )}
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </motion.div>
        </div>

      </div>
    </Shell>
  );
}
