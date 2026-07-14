import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, Activity, Clock, Cpu } from 'lucide-react';
import { apiFetch } from '../lib/api.js';
import { useToast } from './Toast.jsx';

const SCHEDULE_OPTIONS = [
  { value: '5m', label: 'Every 5 minutes', desc: 'Lightweight checks only' },
  { value: '15m', label: 'Every 15 minutes', desc: 'Lightweight checks only' },
  { value: '30m', label: 'Every 30 minutes', desc: 'Recommended for most sites' },
  { value: '1h', label: 'Every 1 hour', desc: 'Default — balanced coverage' },
  { value: '6h', label: 'Every 6 hours', desc: 'Standard modules' },
  { value: '12h', label: 'Every 12 hours', desc: 'Full module coverage' },
  { value: '24h', label: 'Every 24 hours', desc: 'Full deep scan' },
];

const MODULE_OPTIONS = [
  { key: 'headers', label: 'HTTP Headers', desc: 'Security header analysis', light: true },
  { key: 'ssl', label: 'SSL/TLS', desc: 'Certificate & cipher check', light: true },
  { key: 'paths', label: 'Exposed Paths', desc: 'Sensitive file detection', light: true },
  { key: 'cors', label: 'CORS', desc: 'Misconfiguration check', light: true },
  { key: 'tech', label: 'Technology', desc: 'Tech stack fingerprinting', light: false },
  { key: 'info', label: 'Info Disclosure', desc: 'Leaked data detection', light: false },
  { key: 'api', label: 'API Security', desc: 'API endpoint scanning', light: false },
  { key: 'secrets', label: 'Client Secrets', desc: 'Exposed keys & tokens', light: false },
  { key: 'dns', label: 'DNS Recon', desc: 'DNS record analysis', light: false },
];

export default function MonitorSetupModal({ onClose, onCreated }) {
  const [target, setTarget] = useState('');
  const [schedule, setSchedule] = useState('1h');
  const [modules, setModules] = useState(['headers', 'ssl', 'paths', 'cors']);
  const [projectId, setProjectId] = useState('');
  const [projects, setProjects] = useState([]);
  const [creating, setCreating] = useState(false);
  const toast = useToast();

  useEffect(() => {
    apiFetch('/api/projects').then(d => setProjects(d?.projects || [])).catch(() => {});
  }, []);

  function toggleModule(key) {
    setModules(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]);
  }

  async function handleCreate() {
    if (!target.trim()) {
      toast.error('Target URL is required');
      return;
    }
    try { new URL(target) } catch {
      toast.error('Please enter a valid URL (e.g. https://example.com)');
      return;
    }

    setCreating(true);
    try {
      await apiFetch('/api/monitors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          schedule,
          modules,
          projectId: projectId || null,
        }),
      });
      toast.success('Monitor created! First check will run shortly.');
      onCreated?.();
    } catch (e) {
      toast.error(e?.message || 'Failed to create monitor');
    } finally {
      setCreating(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        className="glassmorphism border border-white/15 rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-500/15">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">New Monitor</h2>
              <p className="text-xs text-gray-400">Set up continuous monitoring</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg hover:bg-white/10 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Target URL */}
          <div>
            <label className="block text-sm font-medium mb-2">Target URL</label>
            <input
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-4 py-2.5 rounded-xl bg-white/[0.06] border border-white/10 focus:border-blue-500/50 focus:outline-none text-sm transition-colors"
            />
          </div>

          {/* Project */}
          <div>
            <label className="block text-sm font-medium mb-2">Link to Project (optional)</label>
            <select
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl bg-white/[0.06] border border-white/10 focus:border-blue-500/50 focus:outline-none text-sm transition-colors"
            >
              <option value="">No project</option>
              {projects.map(p => (
                <option key={p.id} value={p.id}>{p.name} — {p.client}</option>
              ))}
            </select>
          </div>

          {/* Schedule */}
          <div>
            <label className="block text-sm font-medium mb-2 flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-400" />
              Check Frequency
            </label>
            <div className="grid grid-cols-2 gap-2">
              {SCHEDULE_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setSchedule(opt.value)}
                  className={`p-3 rounded-xl text-left text-sm transition-all border ${
                    schedule === opt.value
                      ? 'bg-blue-500/15 border-blue-500/30 text-white'
                      : 'bg-white/[0.03] border-white/5 text-gray-400 hover:bg-white/[0.06] hover:text-white'
                  }`}
                >
                  <p className="font-medium">{opt.label}</p>
                  <p className="text-xs opacity-60 mt-0.5">{opt.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Modules */}
          <div>
            <label className="block text-sm font-medium mb-2 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-gray-400" />
              Scan Modules
            </label>
            <div className="space-y-1.5">
              {MODULE_OPTIONS.map((mod) => (
                <label
                  key={mod.key}
                  className={`flex items-center gap-3 p-2.5 rounded-xl cursor-pointer transition-colors ${
                    modules.includes(mod.key) ? 'bg-white/[0.08]' : 'bg-white/[0.02] hover:bg-white/[0.05]'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={modules.includes(mod.key)}
                    onChange={() => toggleModule(mod.key)}
                    className="w-4 h-4 rounded border-white/20 bg-white/5 accent-blue-500"
                  />
                  <div className="flex-1 min-w-0">
                    <span className="text-sm">{mod.label}</span>
                    {mod.light && <span className="ml-2 text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded-full">Lightweight</span>}
                  </div>
                  <span className="text-xs text-gray-500">{mod.desc}</span>
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-5 border-t border-white/10">
          <button onClick={onClose} className="btn-secondary px-5 py-2 text-sm">Cancel</button>
          <button
            onClick={handleCreate}
            disabled={creating}
            className="btn-primary px-5 py-2 text-sm flex items-center gap-2"
          >
            {creating ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Activity className="w-4 h-4" />}
            {creating ? 'Creating...' : 'Start Monitoring'}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}
