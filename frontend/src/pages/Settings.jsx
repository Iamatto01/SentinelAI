import { useEffect, useState } from 'react';
import Shell from '../components/Shell.jsx';
import { useAuth } from '../lib/AuthContext.jsx';
import { apiFetch } from '../lib/api.js';
import { useToast } from '../components/Toast.jsx';

export default function Settings() {
  const { user } = useAuth();
  const toast = useToast();
  const [settings, setSettings] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
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
  }, []);

  return (
    <Shell title="Settings" subtitle="Application configuration and account settings">
      <div className="space-y-8">
        {/* User Profile */}
        <div className="glassmorphism p-6 rounded-lg">
          <h3 className="text-xl font-semibold mb-6">User Profile</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Username</label>
              <div className="search-input px-4 py-3 rounded-lg">{user?.username || '\u2014'}</div>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Email</label>
              <div className="search-input px-4 py-3 rounded-lg">{user?.email || '\u2014'}</div>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Role</label>
              <div className="search-input px-4 py-3 rounded-lg capitalize">{user?.role || '\u2014'}</div>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Permissions</label>
              <div className="search-input px-4 py-3 rounded-lg">
                {user?.permissions?.join(', ') || '\u2014'}
              </div>
            </div>
          </div>
        </div>

        {/* Scan Configuration */}
        {settings && (
          <div className="glassmorphism p-6 rounded-lg">
            <h3 className="text-xl font-semibold mb-6">Scan Configuration</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm text-gray-400 mb-1">AI Mode</label>
                <div className="search-input px-4 py-3 rounded-lg capitalize">{settings.aiMode}</div>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Rate Limit</label>
                <div className="search-input px-4 py-3 rounded-lg">{settings.rateLimit} req/s</div>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Concurrency</label>
                <div className="search-input px-4 py-3 rounded-lg">{settings.concurrency} threads</div>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">API Endpoint</label>
                <div className="search-input px-4 py-3 rounded-lg text-sm">{settings.apiEndpoint}</div>
              </div>
            </div>

            <h4 className="text-sm font-medium mt-6 mb-4 text-gray-300">Default Modules</h4>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {Object.entries(settings.modules || {}).map(([key, enabled]) => (
                <div
                  key={key}
                  className={`p-3 rounded-lg border text-sm ${
                    enabled
                      ? 'border-white/30 bg-white/10'
                      : 'border-white/10 bg-white/5 text-gray-500'
                  }`}
                >
                  <span className="capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                  <span className="ml-2 text-xs">{enabled ? 'ON' : 'OFF'}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Audit Log */}
        <div className="glassmorphism p-6 rounded-lg">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold">Audit Log</h3>
            <span className="text-xs text-gray-400">
              Showing {Math.min(auditLogs.length, 20)} of {auditLogs.length}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="text-gray-400">
                <tr className="border-b border-white/10">
                  <th className="text-left py-2 pr-4">Time</th>
                  <th className="text-left py-2 pr-4">User</th>
                  <th className="text-left py-2 pr-4">Action</th>
                  <th className="text-left py-2 pr-4">Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.slice(0, 20).map((log) => (
                  <tr key={log.id} className="border-b border-white/5">
                    <td className="py-3 pr-4 text-gray-400 whitespace-nowrap">
                      {log.timestamp ? new Date(log.timestamp).toLocaleString() : '\u2014'}
                    </td>
                    <td className="py-3 pr-4">{log.user}</td>
                    <td className="py-3 pr-4">
                      <span className="px-2 py-1 bg-white/10 rounded text-xs">{log.action}</span>
                    </td>
                    <td className="py-3 pr-4 text-gray-300 max-w-md truncate">{log.details}</td>
                  </tr>
                ))}
                {!loading && auditLogs.length === 0 ? (
                  <tr>
                    <td className="py-4 text-gray-400" colSpan={4}>
                      No audit logs yet.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Shell>
  );
}
