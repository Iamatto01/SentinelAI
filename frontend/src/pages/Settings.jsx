import { useEffect, useState } from 'react';
import Shell from '../components/Shell.jsx';
import { useAuth } from '../lib/AuthContext.jsx';
import { apiFetch } from '../lib/api.js';
import { useToast } from '../components/Toast.jsx';
import { motion } from 'framer-motion';

export default function Settings() {
  const { user } = useAuth();
  const toast = useToast();
  
  const [loading, setLoading] = useState(true);
  const [savingUser, setSavingUser] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const [settings, setSettings] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);

  useEffect(() => {
    if (user) {
      setEmail(user.email || '');
    }

    if (user?.role === 'client') {
      setLoading(false);
      return;
    }

    setLoading(true);
    Promise.all([
      apiFetch('/api/settings'),
      apiFetch('/api/audit/logs'),
    ])
      .then(([settingsData, auditData]) => {
        setSettings(settingsData?.settings || null);
        setAuditLogs(auditData?.logs || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [user]);

  async function handleSaveProfile(e) {
    e.preventDefault();
    setSavingUser(true);
    try {
      await apiFetch('/api/users/me', {
        method: 'PUT',
        body: JSON.stringify({ email, password })
      });
      toast('Profile updated successfully!');
      setPassword(''); // clear password box on success
    } catch (err) {
      toast(err?.message || 'Failed to update profile');
    } finally {
      setSavingUser(false);
    }
  }

  async function handleSaveSettings(e) {
    e.preventDefault();
    if (!settings) return;
    setSavingSettings(true);
    try {
      await apiFetch('/api/settings', {
        method: 'PUT',
        body: JSON.stringify(settings)
      });
      toast('Global configurations saved!');
    } catch (err) {
      toast(err?.message || 'Failed to save configurations');
    } finally {
      setSavingSettings(false);
    }
  }

  function handleModuleToggle(key) {
    setSettings(prev => ({
      ...prev,
      modules: { ...prev.modules, [key]: !prev.modules[key] }
    }));
  }

  return (
    <Shell title="Settings" subtitle="Application configuration and account settings">
      <div className="space-y-8">
        
        {/* User Profile - Editable for all roles */}
        <div className="glassmorphism p-6 rounded-2xl">
          <h3 className="text-xl font-semibold mb-6 white-glow-text">User Profile</h3>
          <form onSubmit={handleSaveProfile} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Username (Immutable)</label>
                <input 
                  type="text" 
                  disabled 
                  value={user?.username || ''} 
                  className="search-input w-full px-4 py-3 rounded-xl opacity-50 cursor-not-allowed"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Role</label>
                <input 
                  type="text" 
                  disabled 
                  value={user?.role || ''} 
                  className="search-input w-full px-4 py-3 rounded-xl opacity-50 cursor-not-allowed capitalize"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Email Address</label>
                <input 
                  type="email" 
                  required
                  value={email}
                  onChange={e => setEmail(e.target.value)} 
                  className="search-input w-full px-4 py-3 rounded-xl"
                  placeholder="name@company.com"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Reset Password</label>
                <input 
                  type="password" 
                  value={password}
                  onChange={e => setPassword(e.target.value)} 
                  className="search-input w-full px-4 py-3 rounded-xl"
                  placeholder="Enter new password (optional)"
                />
              </div>
            </div>
            <div className="flex justify-end">
              <motion.button
                type="submit"
                disabled={savingUser}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="px-6 py-3 glass-button-primary rounded-xl font-medium disabled:opacity-50"
              >
                {savingUser ? 'Saving...' : 'Update Profile'}
              </motion.button>
            </div>
          </form>
        </div>

        {/* Global Settings - Admin/Analyst only */}
        {user?.role !== 'client' && settings && (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glassmorphism p-6 rounded-2xl"
          >
            <h3 className="text-xl font-semibold mb-6 white-glow-text">Global Scan Configuration</h3>
            <form onSubmit={handleSaveSettings} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">AI Execution Mode</label>
                  <select 
                    value={settings.aiMode}
                    onChange={e => setSettings({...settings, aiMode: e.target.value})}
                    className="search-input w-full px-4 py-3 rounded-xl"
                  >
                    <option value="assist">Assist (Human in the loop)</option>
                    <option value="autonomous">Autonomous (Fully Automated)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">API Endpoint URL</label>
                  <input 
                    type="text" 
                    value={settings.apiEndpoint}
                    onChange={e => setSettings({...settings, apiEndpoint: e.target.value})}
                    className="search-input w-full px-4 py-3 rounded-xl"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Rate Limit (req/s)</label>
                  <input 
                    type="number" 
                    min="1"
                    value={settings.rateLimit}
                    onChange={e => setSettings({...settings, rateLimit: e.target.value})}
                    className="search-input w-full px-4 py-3 rounded-xl"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Concurrency Threads</label>
                  <input 
                    type="number" 
                    min="1"
                    value={settings.concurrency}
                    onChange={e => setSettings({...settings, concurrency: e.target.value})}
                    className="search-input w-full px-4 py-3 rounded-xl"
                  />
                </div>
              </div>

              <div>
                <h4 className="text-sm font-medium mt-6 mb-4 text-gray-300">Default Tool Modules</h4>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  {Object.entries(settings.modules || {}).map(([key, enabled]) => (
                    <motion.div
                      key={key}
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      onClick={() => handleModuleToggle(key)}
                      className={`cursor-pointer p-4 rounded-xl border transition-colors ${
                        enabled
                          ? 'border-cyan-500/50 bg-cyan-500/10 shadow-[0_0_15px_rgba(74,209,255,0.1)]'
                          : 'border-white/10 bg-white/5 opacity-60 hover:opacity-100 text-gray-400'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="capitalize font-medium text-sm">
                          {key.replace(/([A-Z])/g, ' $1').trim()}
                        </span>
                        <div className={`w-4 h-4 rounded-full border-2 ${enabled ? 'border-cyan-400 bg-cyan-400' : 'border-gray-500'} flex items-center justify-center`} />
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
              
              <div className="flex justify-end pt-4">
                <motion.button
                  type="submit"
                  disabled={savingSettings}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="px-6 py-3 glass-button-primary rounded-xl font-medium disabled:opacity-50"
                >
                  {savingSettings ? 'Saving...' : 'Save Global Config'}
                </motion.button>
              </div>
            </form>
          </motion.div>
        )}

        {/* Audit Log - Admin/Analyst only */}
        {user?.role !== 'client' && (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glassmorphism p-6 rounded-2xl"
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold white-glow-text">System Audit Log</h3>
              <span className="text-xs text-gray-400">
                Displaying last {Math.min(auditLogs.length, 20)} events
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="text-gray-400">
                  <tr className="border-b border-white/10">
                    <th className="text-left font-medium py-3 pr-4">Timestamp</th>
                    <th className="text-left font-medium py-3 pr-4">Triggered By</th>
                    <th className="text-left font-medium py-3 pr-4">Action Event</th>
                    <th className="text-left font-medium py-3 pr-4">Log Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.slice(0, 20).map((log) => (
                    <motion.tr 
                      key={log.id} 
                      whileHover={{ backgroundColor: 'rgba(255,255,255,0.03)' }}
                      className="border-b border-white/5 transition-colors"
                    >
                      <td className="py-4 pr-4 text-gray-400 whitespace-nowrap">
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : '\u2014'}
                      </td>
                      <td className="py-4 pr-4 font-medium text-gray-200">{log.user}</td>
                      <td className="py-4 pr-4">
                        <span className="px-3 py-1 bg-white/10 border border-white/5 rounded-full text-xs font-semibold tracking-wide text-cyan-100">
                          {log.action}
                        </span>
                      </td>
                      <td className="py-4 pr-4 text-gray-400 max-w-md truncate">{log.details}</td>
                    </motion.tr>
                  ))}
                  {!loading && auditLogs.length === 0 && (
                    <tr>
                      <td className="py-8 text-center text-gray-500" colSpan={4}>
                        No administrative events recorded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

      </div>
    </Shell>
  );
}
