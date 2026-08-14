import React, { useState } from 'react'
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Radar, Bug, FolderKanban, Plug, LogOut, Shield, Plus, Hexagon, Activity, Settings as SettingsIcon, Crosshair, Menu, X, ChevronLeft, ChevronRight, Send, Search, Bell, Sparkles, GitBranch, CreditCard
} from 'lucide-react'
import { useAuth } from '../lib/AuthContext.jsx'
import NewScanModal from './NewScanModal.jsx'
import RequestScanModal from './RequestScanModal.jsx'
import InspectorLogo from './InspectorLogo.jsx'
import AIChatWidget from './AIChatWidget.jsx'

const NAV = [
  { to: '/app/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/app/scans', label: 'Scans', icon: Radar },
  { to: '/app/github', label: 'GitHub Auto', icon: GitBranch },
  { to: '/app/billing', label: 'Billing & Plans', icon: CreditCard },
  { to: '/app/exploits', label: 'Exploits', icon: Crosshair },
  { to: '/app/findings', label: 'Findings', icon: Bug },
  { to: '/app/projects', label: 'Projects', icon: FolderKanban },
  { to: '/app/monitoring', label: 'Monitoring', icon: Activity },
  { to: '/app/integrations', label: 'Integrations', icon: Plug },
  { to: '/app/settings', label: 'Settings', icon: SettingsIcon },
]

export default function Shell() {
  const { user, logout } = useAuth()
  const nav = useNavigate()
  const location = useLocation()
  const [showNew, setShowNew] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [pinned, setPinned] = useState(false)
  const [isHovered, setIsHovered] = useState(false)

  const isClient = user?.role === 'client'
  const isExpanded = pinned || isHovered

  // Current section title for Vision UI top navbar breadcrumb
  const currentNav = NAV.find(n => location.pathname.startsWith(n.to)) || { label: 'Platform' }

  return (
    <div className="min-h-screen grid-bg relative selection:bg-cyan-500 selection:text-slate-950">
      {/* Mobile Top App Bar */}
      <header className="lg:hidden sticky top-0 z-30 flex items-center justify-between px-4 py-3 bg-slate-950/80 backdrop-blur-2xl border-b border-white/10">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileOpen(true)}
            className="p-2 rounded-xl bg-white/5 border border-white/10 text-slate-200 hover:text-white"
            aria-label="Open Navigation"
          >
            <Menu size={20} />
          </button>
          <div className="flex items-center gap-2">
            <InspectorLogo size={28} />
            <span className="font-bold text-slate-100 text-base">SentinelAI</span>
          </div>
        </div>

        <button
          onClick={() => setShowNew(true)}
          className="btn-primary text-xs py-1.5 px-3.5 shadow-glow flex items-center gap-1.5"
        >
          {isClient ? <Send size={14} /> : <Plus size={14} />} {isClient ? 'Ask Scan' : 'Scan'}
        </button>
      </header>

      {/* Mobile Drawer Overlay Backdrop */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-40 lg:hidden transition-opacity"
        />
      )}

      {/* Vision UI Floating Sidebar */}
      <aside
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        className={`fixed inset-y-0 left-0 lg:left-3 lg:inset-y-3 glass rounded-none lg:rounded-3xl flex flex-col z-50 overflow-hidden transition-all duration-300 ease-in-out shadow-2xl border border-white/15 ${
          isExpanded ? 'w-64 lg:w-60 shadow-cyan-950/40' : 'w-64 lg:w-20'
        } ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Sidebar Brand Header */}
        <div className={`flex items-center h-16 border-b border-white/10 transition-all duration-300 ${!isExpanded ? 'lg:justify-center lg:px-2 px-4 justify-between' : 'justify-between px-4'}`}>
          <div className="flex items-center gap-2.5 min-w-0">
            <InspectorLogo size={32} />
            {isExpanded && (
              <div className="min-w-0 animate-in fade-in duration-200">
                <p className="text-sm font-extrabold text-white tracking-tight truncate">SentinelAI</p>
                <p className="text-[9px] uppercase tracking-widest text-cyan-400 font-bold truncate flex items-center gap-1">
                  <Sparkles size={10} className="animate-spin" /> Vision UI Edition
                </p>
              </div>
            )}
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => setPinned(!pinned)}
              title={pinned ? "Unpin sidebar" : "Pin sidebar expanded"}
              className="hidden lg:flex items-center justify-center p-1.5 rounded-xl text-slate-400 hover:bg-white/10 hover:text-cyan-300 transition-colors"
            >
              {pinned ? <ChevronLeft size={18} className="text-cyan-400" /> : <ChevronRight size={18} />}
            </button>
            <button
              onClick={() => setMobileOpen(false)}
              className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-lg"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Action Button */}
        <div className="p-3">
          <button
            onClick={() => { setShowNew(true); setMobileOpen(false) }}
            title={isClient ? "Ask for New Scan" : "New Scan"}
            className={`btn-primary w-full justify-center ${!isExpanded ? 'lg:!px-0' : ''}`}
          >
            {isClient ? <Send size={16} /> : <Plus size={16} />}
            {isExpanded && <span>{isClient ? 'Ask for Scan' : 'New Scan'}</span>}
          </button>
        </div>

        {/* Vision Navigation Links */}
        <nav className="flex-1 px-3 space-y-1.5 overflow-y-auto">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              title={!isExpanded ? label : undefined}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3.5 rounded-2xl py-2.5 text-sm font-semibold transition-all duration-200 ${
                  !isExpanded ? 'lg:justify-center lg:px-0 px-3' : 'px-3.5'
                } ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/25 to-blue-600/25 text-cyan-300 border border-cyan-400/40 glass-glow'
                    : 'text-slate-400 border border-transparent hover:bg-white/[0.06] hover:text-slate-100'
                }`
              }
            >
              <div className={`p-1.5 rounded-xl transition-colors ${location.pathname.startsWith(to) ? 'bg-cyan-500 text-slate-950' : 'bg-white/5 text-slate-300'}`}>
                <Icon size={16} />
              </div>
              {isExpanded && <span className="truncate">{label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* User Info Footer */}
        <div className="p-3 border-t border-white/10">
          <div className={`flex items-center rounded-2xl glass-soft py-2.5 ${!isExpanded ? 'lg:justify-center lg:px-0 px-3 justify-between' : 'justify-between px-3'}`}>
            {isExpanded && (
              <div className="min-w-0 pr-2">
                <p className="text-sm font-bold text-slate-100 truncate">{user?.username}</p>
                <p className="text-[10px] uppercase tracking-wider font-extrabold text-cyan-400">{user?.role}</p>
              </div>
            )}
            <button
              onClick={() => { logout(); nav('/login') }}
              title="Sign out"
              className="text-slate-400 hover:text-rose-400 transition-colors shrink-0 p-1.5 rounded-xl hover:bg-rose-500/10"
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className={`transition-all duration-300 ${pinned ? 'pl-0 lg:pl-[264px]' : 'pl-0 lg:pl-[104px]'} pr-0 lg:pr-3`}>
        {/* Desktop Top Header Bar (Vision UI Style) */}
        <header className="hidden lg:flex items-center justify-between mx-auto max-w-7xl px-6 pt-5 pb-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-400">
            <span>Pages</span>
            <span>/</span>
            <span className="text-cyan-300 font-bold">{currentNav.label}</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative w-64">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search scans, CVEs..."
                className="input !py-1.5 !pl-9 !text-xs !rounded-full"
              />
            </div>
            <div className="chip bg-cyan-500/15 text-cyan-300 border-cyan-400/30 text-xs px-3 py-1 font-bold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" /> Hexstrike Engine Active
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-7xl px-3 sm:px-6 py-4 sm:py-6">
          <Outlet />
        </div>
      </main>

      {showNew && (
        isClient ? (
          <RequestScanModal onClose={() => setShowNew(false)} />
        ) : (
          <NewScanModal
            onClose={() => setShowNew(false)}
            onStarted={(id) => { setShowNew(false); nav(`/app/scans/${id}`) }}
          />
        )
      )}
      <AIChatWidget />
    </div>
  )
}


