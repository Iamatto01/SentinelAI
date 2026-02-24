import { useState } from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/AuthContext.jsx';

function NavItem({ to, label, icon, onClick }) {
  return (
    <NavLink
      to={to}
      onClick={onClick}
      className={({ isActive }) =>
        `nav-item flex items-center space-x-3 px-4 py-3 rounded ${isActive ? 'active' : ''}`
      }
    >
      <span className="text-lg">{icon}</span>
      <span>{label}</span>
    </NavLink>
  );
}

export default function Shell({ title, subtitle, actions, children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  function handleLogout() {
    logout();
    navigate('/login');
  }

  function closeSidebar() {
    setSidebarOpen(false);
  }

  return (
    <div className="text-white">
      {/* Mobile top bar */}
      <div className="md:hidden fixed top-0 left-0 right-0 z-50 glassmorphism border-b border-white/10 flex items-center px-4 py-3">
        <button
          className="p-2 hover:bg-white/10 rounded transition-all"
          onClick={() => setSidebarOpen(!sidebarOpen)}
        >
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            {sidebarOpen ? (
              <path d="M6 6l12 12M6 18L18 6" />
            ) : (
              <path d="M3 6h18M3 12h18M3 18h18" />
            )}
          </svg>
        </button>
        <Link to="/" className="flex items-center space-x-2 ml-3" onClick={closeSidebar}>
          <img src="/resources/logo.svg" alt="SentinelAI" className="w-8 h-8" />
          <span className="font-bold white-glow-text">SentinelAI</span>
        </Link>
      </div>

      {/* Backdrop overlay for mobile */}
      {sidebarOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/60 z-40"
          onClick={closeSidebar}
        />
      )}

      {/* Sidebar */}
      <nav className={`fixed left-0 top-0 h-full w-64 glassmorphism z-50 border-r border-white/10 flex flex-col transition-transform duration-300 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0`}>
        <div className="p-6 flex-1">
          <Link to="/" className="flex items-center space-x-3 mb-8" onClick={closeSidebar}>
            <img src="/resources/logo.svg" alt="SentinelAI" className="w-10 h-10" />
            <h1 className="text-xl font-bold white-glow-text">SentinelAI</h1>
          </Link>

          <div className="space-y-2">
            <NavItem to="/" icon="&#x1F4CA;" label="Dashboard" onClick={closeSidebar} />
            <NavItem to="/projects" icon="&#x1F4C1;" label="Projects" onClick={closeSidebar} />
            <NavItem to="/scan" icon="&#x1F50D;" label="Live Scan" onClick={closeSidebar} />
            <NavItem to="/vulnerabilities" icon="&#x1F6E1;&#xFE0F;" label="Vulnerabilities" onClick={closeSidebar} />
          </div>
        </div>

        <div className="p-6 space-y-3 border-t border-white/10">
          <NavLink
            to="/settings"
            onClick={closeSidebar}
            className={({ isActive }) =>
              `flex items-center space-x-3 px-4 py-2 rounded text-sm transition-all ${
                isActive ? 'bg-white/10 border-l-2 border-white' : 'hover:bg-white/5'
              }`
            }
          >
            <span>&#x2699;&#xFE0F;</span>
            <span>Settings</span>
          </NavLink>

          <button
            onClick={handleLogout}
            className="flex items-center space-x-3 px-4 py-2 rounded text-sm w-full text-left hover:bg-white/5 transition-all text-gray-400 hover:text-white"
          >
            <span>&#x1F6AA;</span>
            <span>Sign Out</span>
          </button>

          <div className="flex items-center space-x-3 p-3 glassmorphism rounded">
            <div className="w-8 h-8 rounded-full bg-white/20 flex items-center justify-center text-sm font-bold">
              {(user?.username || '?')[0].toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium truncate">{user?.username || 'User'}</p>
              <p className="text-xs text-gray-400 truncate">{user?.email || ''}</p>
            </div>
          </div>
        </div>
      </nav>

      <main className="md:ml-64 min-h-screen pt-14 md:pt-0">
        <header className="glassmorphism border-b border-white/10 p-4 md:p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <h2 className="text-xl md:text-3xl font-bold white-glow-text">{title}</h2>
              {subtitle ? <p className="text-gray-400 mt-1 text-sm md:text-base">{subtitle}</p> : null}
            </div>
            <div className="flex items-center space-x-2 md:space-x-4 flex-wrap">{actions}</div>
          </div>
        </header>

        <div className="p-4 md:p-6">{children}</div>
      </main>
    </div>
  );
}
