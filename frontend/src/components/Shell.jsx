import { useState } from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/AuthContext.jsx';
import { Menu, LayoutDashboard, FolderOpen, Radar, ShieldAlert, Settings, LogOut } from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/projects', icon: FolderOpen, label: 'Projects' },
  { to: '/scan', icon: Radar, label: 'Live Scan' },
  { to: '/vulnerabilities', icon: ShieldAlert, label: 'Vulnerabilities' },
];

export default function Shell({ title, subtitle, actions, children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  function handleLogout() {
    logout();
    navigate('/login');
  }

  function closeMobile() {
    setMobileOpen(false);
  }

  return (
    <div className="text-white">
      {/* Mobile top bar */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 glassmorphism border-b border-white/10 flex items-center px-4 py-3">
        <button
          className="p-2 hover:bg-white/10 rounded-xl transition-colors"
          onClick={() => setMobileOpen(!mobileOpen)}
        >
          <Menu className="w-5 h-5" />
        </button>
        <Link to="/" className="flex items-center space-x-2 ml-3" onClick={closeMobile}>
          <img src="/resources/logo.svg" alt="SentinelAI" className="w-8 h-8" />
          <span className="font-bold white-glow-text">SentinelAI</span>
        </Link>
      </div>

      {/* Mobile backdrop */}
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 bg-black/60 z-40" onClick={closeMobile} />
      )}

      {/* ── Glass Sidebar ─────────────────────────────────────────── */}
      <nav
        className={`
          glass-sidebar
          fixed left-3 top-3 bottom-3 z-50
          flex flex-col overflow-hidden
          bg-white/[0.06] backdrop-blur-2xl
          border border-white/[0.12]
          shadow-[0_8px_30px_rgb(0,0,0,0.4)]
          rounded-3xl
          transition-all duration-300 ease-in-out
          w-[68px] hover:w-64 group
          max-lg:hidden
        `}
      >
        {/* Logo / Menu toggle area */}
        <div className="flex items-center h-14 px-[18px] mx-2 mt-4 rounded-xl cursor-pointer hover:bg-white/[0.08] transition-colors flex-shrink-0">
          <img src="/resources/logo.svg" alt="SentinelAI" className="w-7 h-7 flex-shrink-0" />
          <span className="ml-3 font-semibold text-lg white-glow-text whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-300 delay-75">
            SentinelAI
          </span>
        </div>

        {/* Navigation links */}
        <div className="flex-1 py-4 flex flex-col gap-1 overflow-y-auto overflow-x-hidden mt-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `
                glass-nav-item flex items-center px-[18px] py-3 mx-2 rounded-xl
                transition-all group/item
                ${isActive
                  ? 'bg-white/[0.14] text-white shadow-[0_0_15px_rgba(255,255,255,0.08)]'
                  : 'text-gray-400 hover:bg-white/[0.08] hover:text-white'
                }
              `}
            >
              <item.icon className="w-5 h-5 flex-shrink-0 group-hover/item:scale-110 transition-transform duration-200" />
              <span className="ml-3 font-medium whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-300 delay-75 text-sm">
                {item.label}
              </span>
            </NavLink>
          ))}
        </div>

        {/* Bottom: Settings, Logout, User */}
        <div className="pb-4 pt-2 space-y-1">
          <NavLink
            to="/settings"
            className={({ isActive }) => `
              glass-nav-item flex items-center px-[18px] py-3 mx-2 rounded-xl
              transition-all group/item
              ${isActive
                ? 'bg-white/[0.14] text-white shadow-[0_0_15px_rgba(255,255,255,0.08)]'
                : 'text-gray-400 hover:bg-white/[0.08] hover:text-white'
              }
            `}
          >
            <Settings className="w-5 h-5 flex-shrink-0 group-hover/item:scale-110 transition-transform duration-200" />
            <span className="ml-3 font-medium whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-300 delay-75 text-sm">
              Settings
            </span>
          </NavLink>

          <button
            onClick={handleLogout}
            className="flex items-center px-[18px] py-3 mx-2 rounded-xl text-gray-400 hover:bg-red-500/15 hover:text-red-400 transition-all w-[calc(100%-16px)] group/item"
          >
            <LogOut className="w-5 h-5 flex-shrink-0 group-hover/item:scale-110 transition-transform duration-200" />
            <span className="ml-3 font-medium whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-300 delay-75 text-sm">
              Sign Out
            </span>
          </button>

          {/* User avatar (visible on hover) */}
          <div className="mx-2 px-[18px] py-2 flex items-center overflow-hidden">
            <div className="w-8 h-8 rounded-full bg-white/15 flex items-center justify-center text-xs font-bold flex-shrink-0">
              {(user?.username || '?')[0].toUpperCase()}
            </div>
            <div className="ml-3 min-w-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 delay-75">
              <p className="text-sm font-medium truncate">{user?.username || 'User'}</p>
              <p className="text-[11px] text-gray-500 truncate">{user?.role || ''}</p>
            </div>
          </div>
        </div>
      </nav>

      {/* ── Mobile Sidebar (slide-in) ─────────────────────────────── */}
      <nav
        className={`
          lg:hidden fixed left-0 top-0 h-full w-72 z-50
          bg-black/90 backdrop-blur-xl
          border-r border-white/10
          flex flex-col
          transition-transform duration-300
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        <div className="p-6 flex-1">
          <Link to="/" className="flex items-center space-x-3 mb-8" onClick={closeMobile}>
            <img src="/resources/logo.svg" alt="SentinelAI" className="w-10 h-10" />
            <h1 className="text-xl font-bold white-glow-text">SentinelAI</h1>
          </Link>

          <div className="space-y-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                onClick={closeMobile}
                className={({ isActive }) => `
                  flex items-center space-x-3 px-4 py-3 rounded-xl transition-all
                  ${isActive
                    ? 'bg-white/[0.12] text-white'
                    : 'text-gray-400 hover:bg-white/[0.08] hover:text-white'
                  }
                `}
              >
                <item.icon className="w-5 h-5" />
                <span className="font-medium text-sm">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </div>

        <div className="p-6 space-y-2 border-t border-white/10">
          <NavLink
            to="/settings"
            onClick={closeMobile}
            className={({ isActive }) => `
              flex items-center space-x-3 px-4 py-2.5 rounded-xl text-sm transition-all
              ${isActive ? 'bg-white/10 text-white' : 'text-gray-400 hover:bg-white/[0.08] hover:text-white'}
            `}
          >
            <Settings className="w-5 h-5" />
            <span>Settings</span>
          </NavLink>

          <button
            onClick={handleLogout}
            className="flex items-center space-x-3 px-4 py-2.5 rounded-xl text-sm w-full text-left text-gray-400 hover:bg-red-500/15 hover:text-red-400 transition-all"
          >
            <LogOut className="w-5 h-5" />
            <span>Sign Out</span>
          </button>

          <div className="flex items-center space-x-3 p-3 bg-white/[0.06] rounded-xl mt-2">
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

      {/* ── Main content ──────────────────────────────────────────── */}
      <main className="lg:ml-[80px] min-h-screen pt-14 lg:pt-0">
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
