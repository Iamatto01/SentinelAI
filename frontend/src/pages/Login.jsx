import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../lib/AuthContext.jsx';
import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';

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
    <div className="min-h-screen flex items-center justify-center bg-black text-white relative overflow-hidden">
      {/* Animated background */}
      <div className="animated-bg" />
      <div className="floating-orb orb-1" />
      <div className="floating-orb orb-2" />
      <div className="floating-orb orb-3" />
      
      <Link 
        to="/" 
        className="absolute top-6 left-6 md:top-8 md:left-8 z-20 flex items-center gap-2 text-gray-400 hover:text-white transition-all duration-300 bg-white/5 backdrop-blur-md px-4 py-2 rounded-full border border-white/10 hover:border-cyan-500/50 hover:shadow-[0_0_15px_rgba(74,209,255,0.2)]"
      >
        <ArrowLeft size={16} />
        <span className="text-sm font-medium">Back to Home</span>
      </Link>

      <motion.div 
        initial={{ opacity: 0, y: 40 }}

        animate={{ opacity: 1, y: 0 }}
        transition={{ type: 'spring', damping: 20, stiffness: 100 }}
        className="w-full max-w-md mx-4 relative z-10"
      >
        <motion.div 
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.2, type: 'spring', damping: 15 }}
          className="text-center mb-8"
        >
          <motion.img 
            src="/resources/logo.svg" 
            alt="SentinelAI" 
            className="w-16 h-16 mx-auto mb-4"
          />
          <h1 className="text-3xl font-bold white-glow-text">SentinelAI</h1>
          <p className="text-gray-400 mt-2">Sign in to continue</p>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3, type: 'spring', damping: 20 }}
          className="glassmorphism rounded-2xl p-8"
        >
          {/* Tab Switcher */}
          <div className="flex mb-6 border border-white/10 rounded-xl overflow-hidden p-1 bg-white/5">
            {['admin', 'client'].map((t) => (
              <motion.button
                key={t}
                type="button"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className={`flex-1 px-4 py-2.5 text-sm font-medium rounded-lg transition-all ${
                  tab === t
                    ? 'glass-button-primary'
                    : 'bg-transparent text-gray-400 hover:text-white'
                }`}
                onClick={() => { setTab(t); setError(''); }}
              >
                {t === 'admin' ? 'Admin / Analyst' : 'Client Portal'}
              </motion.button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {/* Admin/Analyst Login */}
            {tab === 'admin' && (
              <motion.form 
                key="admin"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.2 }}
                onSubmit={handleAdminSubmit} 
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium mb-2">Username</label>
                  <motion.input
                    whileFocus={{ scale: 1.01 }}
                    type="text"
                    className="search-input w-full px-4 py-3 rounded-xl"
                    placeholder="Enter username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoFocus
                    autoComplete="username"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Password</label>
                  <motion.input
                    whileFocus={{ scale: 1.01 }}
                    type="password"
                    className="search-input w-full px-4 py-3 rounded-xl"
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                  />
                </div>

                <AnimatePresence>
                  {error && (
                    <motion.div 
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="text-red-400 text-sm p-3 bg-red-500/10 rounded-xl border border-red-500/20"
                    >
                      {error}
                    </motion.div>
                  )}
                </AnimatePresence>

                <motion.button
                  type="submit"
                  disabled={submitting}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full px-6 py-3 glass-button-primary rounded-xl font-medium disabled:opacity-50"
                >
                  {submitting ? (
                    <span className="flex items-center justify-center gap-2">
                      <motion.span
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                        className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full"
                      />
                      Signing in...
                    </span>
                  ) : 'Sign In'}
                </motion.button>

                <div className="p-3 bg-white/5 rounded-xl border border-white/10">
                  <p className="text-xs text-gray-400 text-center">
                    Default credentials: admin / admin
                  </p>
                </div>
              </motion.form>
            )}

            {/* Client Email Login */}
            {tab === 'client' && (
              <motion.form 
                key="client"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.2 }}
                onSubmit={handleClientSubmit} 
                className="space-y-6"
              >
                <div>
                  <label className="block text-sm font-medium mb-2">Email Address</label>
                  <motion.input
                    whileFocus={{ scale: 1.01 }}
                    type="email"
                    className="search-input w-full px-4 py-3 rounded-xl"
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

                <AnimatePresence>
                  {error && (
                    <motion.div 
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="text-red-400 text-sm p-3 bg-red-500/10 rounded-xl border border-red-500/20"
                    >
                      {error}
                    </motion.div>
                  )}
                </AnimatePresence>

                <motion.button
                  type="submit"
                  disabled={submitting}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full px-6 py-3 glass-button-primary rounded-xl font-medium disabled:opacity-50"
                >
                  {submitting ? (
                    <span className="flex items-center justify-center gap-2">
                      <motion.span
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                        className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full"
                      />
                      Signing in...
                    </span>
                  ) : 'Access Client Portal'}
                </motion.button>
              </motion.form>
            )}
          </AnimatePresence>
        </motion.div>
      </motion.div>
    </div>
  );
}
