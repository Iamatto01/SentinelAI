import { useState } from 'react';
import { useAuth } from '../lib/AuthContext.jsx';

export default function Login() {
  const { login, clientLogin } = useAuth();
  const [tab, setTab] = useState('admin'); // 'admin' | 'client'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [clientEmail, setClientEmail] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleAdminSubmit(e) {
    e.preventDefault();
    setError('');
    if (!username.trim() || !password) {
      setError('Username and password are required');
      return;
    }
    setSubmitting(true);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setSubmitting(false);
    }
  }

  async function handleClientSubmit(e) {
    e.preventDefault();
    setError('');
    if (!clientEmail.trim()) {
      setError('Email is required');
      return;
    }
    setSubmitting(true);
    try {
      await clientLogin(clientEmail.trim());
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-black text-white">
      <div className="w-full max-w-md mx-4">
        <div className="text-center mb-8">
          <img src="/resources/logo.svg" alt="SentinelAI" className="w-16 h-16 mx-auto mb-4" />
          <h1 className="text-3xl font-bold white-glow-text">SentinelAI</h1>
          <p className="text-gray-400 mt-2">Sign in to continue</p>
        </div>

        <div className="glassmorphism rounded-lg p-8">
          {/* Tab Switcher */}
          <div className="flex mb-6 border border-white/10 rounded-lg overflow-hidden">
            <button
              type="button"
              className={`flex-1 px-4 py-2.5 text-sm font-medium transition-all ${
                tab === 'admin'
                  ? 'bg-white text-black'
                  : 'bg-transparent text-gray-400 hover:text-white hover:bg-white/5'
              }`}
              onClick={() => { setTab('admin'); setError(''); }}
            >
              Admin / Analyst
            </button>
            <button
              type="button"
              className={`flex-1 px-4 py-2.5 text-sm font-medium transition-all ${
                tab === 'client'
                  ? 'bg-white text-black'
                  : 'bg-transparent text-gray-400 hover:text-white hover:bg-white/5'
              }`}
              onClick={() => { setTab('client'); setError(''); }}
            >
              Client Portal
            </button>
          </div>

          {/* Admin/Analyst Login */}
          {tab === 'admin' && (
            <form onSubmit={handleAdminSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium mb-2">Username</label>
                <input
                  type="text"
                  className="search-input w-full px-4 py-3 rounded-lg"
                  placeholder="Enter username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoFocus
                  autoComplete="username"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Password</label>
                <input
                  type="password"
                  className="search-input w-full px-4 py-3 rounded-lg"
                  placeholder="Enter password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </div>

              {error && (
                <div className="text-red-400 text-sm p-3 bg-white/5 rounded-lg border border-white/10">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full px-6 py-3 bg-white text-black rounded-lg hover:bg-gray-200 transition-all font-medium disabled:opacity-50"
              >
                {submitting ? 'Signing in...' : 'Sign In'}
              </button>

              <div className="p-3 bg-white/5 rounded-lg border border-white/10">
                <p className="text-xs text-gray-400 text-center">
                  Default credentials: admin / admin
                </p>
              </div>
            </form>
          )}

          {/* Client Email Login */}
          {tab === 'client' && (
            <form onSubmit={handleClientSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium mb-2">Email Address</label>
                <input
                  type="email"
                  className="search-input w-full px-4 py-3 rounded-lg"
                  placeholder="Enter your email"
                  value={clientEmail}
                  onChange={(e) => setClientEmail(e.target.value)}
                  autoFocus
                  autoComplete="email"
                />
              </div>

              <p className="text-xs text-gray-400">
                Enter the email address your security analyst assigned to your project.
              </p>

              {error && (
                <div className="text-red-400 text-sm p-3 bg-white/5 rounded-lg border border-white/10">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full px-6 py-3 bg-white text-black rounded-lg hover:bg-gray-200 transition-all font-medium disabled:opacity-50"
              >
                {submitting ? 'Signing in...' : 'Access Client Portal'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
