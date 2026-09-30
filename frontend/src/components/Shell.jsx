import React, { useState, useEffect } from 'react'
import { NavLink, Outlet, useNavigate, useLocation, Link } from 'react-router-dom'
import {
  LayoutDashboard, Radar, Bug, FolderKanban, Plug, LogOut, Shield, Plus,
  Hexagon, Activity, Settings as SettingsIcon, Crosshair, Menu, X,
  ChevronLeft, ChevronRight, Search, Bell, Sparkles, GitBranch, CreditCard,
  Users, AlertTriangle, UserCheck, Briefcase, Award, ArrowRight, Lock, CheckCircle2, Zap, Terminal,
  Sun, Moon, FileCode
} from 'lucide-react'
import { useAuth } from '../lib/AuthContext.jsx'
import { api } from '../lib/api.js'
import NewScanModal from './NewScanModal.jsx'
import InspectorLogo from './InspectorLogo.jsx'
import AIChatWidget from './AIChatWidget.jsx'
import Tooltip from './Tooltip.jsx'
import AIBackgroundCanvas from './AIBackgroundCanvas.jsx'
import CyberDoorTransition from './CyberDoorTransition.jsx'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function Shell() {
  const { user, logout } = useAuth()
  const { randomizeNow, isNight, toggleNightMode } = useTheme()
  const nav = useNavigate()
  const location = useLocation()
  const [showGate, setShowGate] = useState(() => {
    const trigger = sessionStorage.getItem('sentinel_gate_trigger') === 'true'
    if (trigger) {
      sessionStorage.removeItem('sentinel_gate_trigger')
      return true
    }
    return false
  })
  const [showNew, setShowNew] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [pinned, setPinned] = useState(() => {
    return localStorage.getItem('sentinel_sidebar_pinned') === 'true'
  })
  const [isHovered, setIsHovered] = useState(false)
  const [subscription, setSubscription] = useState(null)
  const [loadingSub, setLoadingSub] = useState(true)

  // Strict Role Check: Admin vs Client
  const isAdmin = user?.role === 'admin'
  const isClient = user?.role === 'client'
  const isExpanded = pinned || isHovered
  const showLabels = isExpanded || mobileOpen

  // Load subscription status to enforce strict paywall
  useEffect(() => {
    if (user) {
      setLoadingSub(true)
      api.billingSubscription()
        .then(sub => setSubscription(sub))
        .catch(() => {})
        .finally(() => setLoadingSub(false))
    }
  }, [user, location.pathname])

  const adminSections = [
    {
      title: 'Operations',
      items: [
        { to: '/app/dashboard', label: 'Dashboard', icon: LayoutDashboard },
        {
          to: '/app/scans',
          label: 'Security Scans',
          icon: Radar,
          subItems: [
            { to: '/app/scans', label: 'Target Scans' },
            { to: '/app/github', label: 'GitHub CI/CD' },
          ]
        },
        { to: '/app/findings', label: 'Findings', icon: Bug },
        { to: '/app/exploits', label: 'Exploit Lab', icon: Crosshair },
      ]
    },
    {
      title: 'Kali Engine',
      items: [
        {
          to: '/app/kali-control',
          label: 'Kali Console',
          icon: Terminal,
          subItems: [
            { to: '/app/kali-control', label: 'Host & Terminal' },
            { to: '/app/custom-scripts', label: 'Custom Scripts' },
          ]
        },
        { to: '/app/monitoring', label: 'Telemetry', icon: Activity },
      ]
    },
    {
      title: 'Management',
      items: [
        {
          to: '/app/clients',
          label: 'Clients & Advisory',
          icon: Users,
          subItems: [
            { to: '/app/clients', label: 'Client Accounts' },
            { to: '/app/consultants', label: 'Consultations' },
          ]
        },
        {
          to: '/app/settings',
          label: 'Settings',
          icon: SettingsIcon,
          subItems: [
            { to: '/app/settings', label: 'General & AI' },
            { to: '/app/integrations', label: 'Integrations' },
            { to: '/app/billing', label: 'Billing & Plans' },
          ]
        },
      ]
    }
  ]

  const clientSections = [
    {
      title: 'Operations',
      items: [
        { to: '/app/dashboard', label: 'Dashboard', icon: LayoutDashboard },
        {
          to: '/app/scans',
          label: 'My Scans',
          icon: Radar,
          subItems: [
            { to: '/app/scans', label: 'Target Scans' },
            { to: '/app/github', label: 'GitHub CI/CD' },
          ]
        },
        { to: '/app/findings', label: 'Findings', icon: Bug },
      ]
    },
    {
      title: 'Account & Advisory',
      items: [
        { to: '/app/consultants', label: 'Hire Expert', icon: UserCheck },
        { to: '/app/billing', label: 'Billing & Quota', icon: CreditCard },
        { to: '/app/settings', label: 'Settings', icon: SettingsIcon },
      ]
    }
  ]

  const navSections = isAdmin ? adminSections : clientSections
  const allNavItems = navSections.flatMap(s => s.items)
  const allSubItems = allNavItems.flatMap(n => n.subItems || [])
  const currentNav = allSubItems.find(sub => location.pathname === sub.to) || allNavItems.find(n => location.pathname.startsWith(n.to)) || { label: 'Platform' }

  // Paywall Condition: Client has expired subscription or exhausted trial quota
  // Community Open Access Switch: Set to true so community members can freely test without being locked out
  const COMMUNITY_FREE_ACCESS_MODE = true

  const isTrial = isClient && subscription?.plan_id === 'trial'
  const isTrialExhausted = !COMMUNITY_FREE_ACCESS_MODE && isTrial && (subscription?.remainingQuota <= 0 || (subscription?.scan_quota_used >= subscription?.scan_quota_total))
  const isPaidExpired = !COMMUNITY_FREE_ACCESS_MODE && isClient && !isTrial && (
    subscription?.isSubscribed === false ||
    subscription?.isExpired ||
    subscription?.status === 'expired' ||
    subscription?.status === 'inactive' ||
    subscription?.plan_id === 'none'
  )
  const isSubscriptionExpired = isTrialExhausted || isPaidExpired

  const isAllowedPathWhenExpired = location.pathname.startsWith('/app/billing') || location.pathname.startsWith('/app/settings') || location.pathname.startsWith('/app/consultants')

  const handleScanButtonClick = () => {
    if (isSubscriptionExpired) {
      nav('/app/billing')
    } else {
      setShowNew(true)
    }
    setMobileOpen(false)
  }

  return (
    <div className="min-h-screen relative selection:bg-cyan-500 selection:text-slate-950">
      {/* Cinematic Cyber Gate Transition (after successful login) */}
      {showGate && (
        <CyberDoorTransition onComplete={() => setShowGate(false)} />
      )}

      {/* Dynamic Background Canvas (Wallpaper + Minimalist Overlay) */}
      <AIBackgroundCanvas />

      {/* Expired / Inactive / Trial Exhausted Alert Banner (Only when paywall is active) */}
      {isSubscriptionExpired && (
        <div className="sticky top-0 z-50 bg-gradient-to-r from-amber-600 via-rose-600 to-red-600 text-white px-4 py-2 text-xs font-bold shadow-xl flex items-center justify-between">
          <div className="flex items-center gap-2 max-w-4xl">
            <AlertTriangle size={16} className="shrink-0 animate-bounce text-amber-200" />
            <span>
              <strong>{isTrial ? 'Free Trial Limit Reached (3/3 Scans Used):' : 'Subscription Inactive or Expired:'}</strong> {isTrial ? 'Upgrade to Pro or Enterprise to continue launching autonomous AI pentest audits.' : 'Your account is locked until a subscription is activated.'}
            </span>
          </div>
          <Link
            to="/app/billing"
            className="px-3 py-1 rounded-full bg-slate-950/80 hover:bg-slate-950 text-cyan-300 font-extrabold text-[11px] border border-white/20 transition-all flex items-center gap-1 shrink-0 ml-3"
          >
            <span>Upgrade Now</span> <ArrowRight size={12} />
          </Link>
        </div>
      )}

      {/* Mobile Top App Bar */}
      <header className="lg:hidden sticky top-0 z-30 flex items-center justify-between px-4 py-3 bg-[#111111] border-b border-white/[0.07]">
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

        <div className="flex items-center gap-2">
          {/* Prominent Theme Toggle Button (Mobile) */}
          <button
            onClick={toggleNightMode}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/15 text-xs font-bold text-slate-200 hover:text-white cursor-pointer transition-all active:scale-95"
            title={isNight ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            aria-label="Toggle Theme"
          >
            {isNight ? (
              <>
                <Sun size={14} className="text-amber-400" />
                <span className="text-[11px] font-extrabold hidden sm:inline">Light</span>
              </>
            ) : (
              <>
                <Moon size={14} className="text-purple-400" />
                <span className="text-[11px] font-extrabold hidden sm:inline">Dark</span>
              </>
            )}
          </button>
          <button
            onClick={handleScanButtonClick}
            className="btn-primary text-xs py-1.5 px-3.5 shadow-glow flex items-center gap-1.5"
          >
            {isSubscriptionExpired ? <Lock size={14} /> : <Plus size={14} />}
            <span>{isSubscriptionExpired ? 'Subscribe' : 'New Scan'}</span>
          </button>
        </div>
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
        className={`fixed inset-y-0 left-0 flex flex-col z-50 overflow-hidden transition-all duration-300 ease-in-out shadow-2xl border-r border-white/10 bg-slate-950/95 backdrop-blur-xl ${
          isExpanded ? 'w-64 shadow-purple-950/40' : 'w-64 lg:w-20'
        } ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Sidebar Brand Header */}
        <div className={`flex items-center h-16 border-b border-white/10 transition-all duration-300 ${!showLabels ? 'lg:justify-center lg:px-2 px-4 justify-between' : 'justify-between px-4'}`}>
          <div className="flex items-center gap-2.5 min-w-0">
            <InspectorLogo size={32} />
            {showLabels && (
              <div className="min-w-0 animate-in fade-in duration-200">
                <p className="text-sm font-extrabold text-white tracking-tight truncate">SentinelAI</p>
                <p className="text-[9px] uppercase tracking-widest text-purple-400 font-bold truncate flex items-center gap-1">
                  <Sparkles size={10} className="animate-spin" /> {isAdmin ? 'Admin Portal' : isClient ? 'Client Portal' : 'Analyst Portal'}
                </p>
              </div>
            )}
          </div>

          <div className="flex items-center gap-1">
            {showLabels && (
              <button
                onClick={() => {
                  const next = !pinned
                  setPinned(next)
                  localStorage.setItem('sentinel_sidebar_pinned', String(next))
                }}
                title={pinned ? "Collapse Sidebar" : "Pin Sidebar Expanded"}
                className="hidden lg:flex p-1.5 text-slate-400 hover:text-purple-300 hover:bg-white/5 rounded-lg transition-colors"
              >
                <ChevronLeft size={16} className={`transition-transform duration-300 ${pinned ? '' : 'rotate-180'}`} />
              </button>
            )}
            <button
              onClick={() => setMobileOpen(false)}
              className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-lg"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Scan Action Button */}
        <div className="p-3 flex justify-center">
          <button
            onClick={handleScanButtonClick}
            title={isSubscriptionExpired ? "Subscribe to Launch Scans" : "Launch New Security Audit"}
            className={`btn-primary active-press transition-all duration-300 ${
              !showLabels
                ? 'w-11 h-11 p-0 rounded-2xl flex items-center justify-center'
                : 'w-full py-2.5 px-4 rounded-2xl justify-center'
            } ${
              !isSubscriptionExpired && isTrial && (subscription?.remainingQuota ?? 3) <= 1 ? 'ring-urgent' : ''
            }`}
          >
            {isSubscriptionExpired ? <Lock size={18} /> : <Plus size={18} />}
            {showLabels && <span className="font-bold text-sm">{isSubscriptionExpired ? 'Subscribe to Scan' : 'Launch Scan'}</span>}
          </button>
        </div>

        {/* Vision Navigation Links - Grouped & Categorized */}
        <nav className="flex-1 px-3 space-y-3 overflow-y-auto">
          {navSections.map((section, sIdx) => (
            <div key={section.title || sIdx} className="space-y-1">
              {/* Category Header (when expanded) or subtle divider (when collapsed) */}
              {showLabels ? (
                <div className="px-3 pt-2 pb-1 text-[10px] font-extrabold uppercase tracking-widest text-slate-500 flex items-center justify-between">
                  <span>{section.title}</span>
                </div>
              ) : sIdx > 0 ? (
                <div className="border-t border-white/5 my-2 mx-1" />
              ) : null}

              {section.items.map((item) => {
                const isSubActive = item.subItems && item.subItems.some(sub => location.pathname === sub.to || location.pathname.startsWith(sub.to + '/'))
                const isItemActive = location.pathname === item.to || isSubActive
                const isLocked = isSubscriptionExpired && !item.to.startsWith('/app/billing') && !item.to.startsWith('/app/settings')
                const Icon = item.icon

                const navItem = (
                  <div key={item.to} className="space-y-0.5">
                    <NavLink
                      to={item.to}
                      onClick={() => setMobileOpen(false)}
                      className={() => {
                        return !showLabels
                          ? `w-11 h-11 mx-auto rounded-2xl flex items-center justify-center transition-all duration-200 relative group ${
                              isItemActive
                                ? 'bg-gradient-to-tr from-purple-500/25 to-violet-600/35 text-purple-300 border border-purple-400/50 shadow-[0_0_16px_rgba(168,85,247,0.3)]'
                                : isLocked
                                ? 'text-slate-500 opacity-60 border border-transparent'
                                : 'text-slate-400 hover:text-white hover:bg-white/[0.08] border border-transparent'
                            }`
                          : `flex items-center gap-3 px-3 py-2 rounded-2xl text-sm font-semibold transition-all duration-200 relative group ${
                              isItemActive
                                ? 'bg-gradient-to-r from-purple-500/15 via-violet-500/10 to-transparent text-purple-200 border border-purple-400/30 shadow-[0_0_15px_rgba(168,85,247,0.15)]'
                                : isLocked
                                ? 'text-slate-500 hover:text-slate-400 opacity-60 border border-transparent'
                                : 'text-slate-400 border border-transparent hover:bg-white/[0.04] hover:text-slate-100'
                            }`
                      }}
                    >
                      <>
                        {isItemActive && (
                          <span className={`absolute bg-purple-400 rounded-r-full shadow-[0_0_8px_#a855f7] ${
                            !showLabels ? '-left-3 top-2.5 bottom-2.5 w-1' : 'left-0 top-2 bottom-2 w-1'
                          }`} />
                        )}

                        {!showLabels ? (
                          isLocked ? <Lock size={16} className="text-amber-400" /> : <Icon size={18} className={isItemActive ? 'text-purple-300 drop-shadow-[0_0_6px_rgba(168,85,247,0.6)]' : 'group-hover:scale-110 transition-transform'} />
                        ) : (
                          <>
                            <div className={`p-1.5 rounded-xl transition-colors ${
                              isItemActive
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-400/30 shadow-[0_0_8px_rgba(168,85,247,0.25)]'
                                : 'bg-white/[0.03] text-slate-400 group-hover:text-slate-200'
                            }`}>
                              {isLocked ? <Lock size={15} className="text-amber-400" /> : <Icon size={15} />}
                            </div>
                            <span className="truncate flex items-center justify-between flex-1">
                              <span className={isItemActive ? 'font-bold text-white' : 'text-slate-300 group-hover:text-white'}>{item.label}</span>
                              {isLocked && <Lock size={12} className="text-amber-400" />}
                            </span>
                          </>
                        )}
                      </>
                    </NavLink>

                    {/* Sub-items (when parent group is active and sidebar is expanded) */}
                    {showLabels && item.subItems && isItemActive && (
                      <div className="ml-7 pl-2.5 border-l border-white/10 space-y-0.5 pt-0.5">
                        {item.subItems.map((sub) => {
                          const isSubDirectActive = location.pathname === sub.to || location.pathname.startsWith(sub.to + '/')
                          return (
                            <NavLink
                              key={sub.to}
                              to={sub.to}
                              onClick={() => setMobileOpen(false)}
                              className={`block text-xs py-1 px-2.5 rounded-lg transition-colors ${
                                isSubDirectActive
                                  ? 'text-purple-300 font-bold bg-purple-500/10'
                                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]'
                              }`}
                            >
                              {sub.label}
                            </NavLink>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )

                // When sidebar is collapsed, wrap in tooltip for accessibility
                return !showLabels
                  ? <Tooltip key={item.to} content={isLocked ? `${item.label} (Locked — Upgrade to unlock)` : item.label}>{navItem}</Tooltip>
                  : <React.Fragment key={item.to}>{navItem}</React.Fragment>
              })}
            </div>
          ))}
        </nav>

        {/* User Info Footer */}
        <div className="p-3 border-t border-white/10">
          <div className={`flex items-center rounded-2xl glass-soft py-2.5 ${!showLabels ? 'lg:justify-center lg:px-0 px-3 justify-between' : 'justify-between px-3'}`}>
            {showLabels && (
              <div className="min-w-0 pr-2">
                <p className="text-sm font-bold text-slate-100 truncate">{user?.username}</p>
                <p className="text-[10px] uppercase tracking-wider font-extrabold text-purple-400">{user?.role}</p>
              </div>
            )}
            <Tooltip content="Sign Out">
              <button
                onClick={() => { logout(); nav('/login') }}
                title="Sign out"
                className="text-slate-400 hover:text-rose-400 transition-colors shrink-0 p-1.5 rounded-xl hover:bg-rose-500/10"
              >
                <LogOut size={17} />
              </button>
            </Tooltip>
          </div>
        </div>
      </aside>

      {/* Main Content Area: smooth rightward push on expand */}
      <main className={`relative z-10 transition-all duration-300 ease-in-out ${isExpanded ? 'pl-0 lg:pl-64' : 'pl-0 lg:pl-20'}`}>
        {/* Desktop Top Header Bar (Vision UI Style) */}
        <header className="hidden lg:flex items-center justify-between px-6 pt-5 pb-2">
          <div className="flex items-center gap-2 text-xs font-semibold px-3 py-1.5 rounded-xl bg-slate-900/80 border border-white/15 text-slate-200 shadow-md backdrop-blur-md">
            <span className="text-slate-300 font-medium">Portal</span>
            <span className="text-slate-500 font-bold">/</span>
            <span className="text-purple-300 font-extrabold tracking-wide">
              {currentNav.label}
            </span>
          </div>

          <div className="flex items-center gap-3">
            {isClient && subscription && (
              <Link
                to="/app/billing"
                className={`chip text-xs px-3 py-1 font-bold flex items-center gap-2 transition-colors ${
                  isSubscriptionExpired
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                    : 'bg-slate-900/80 border-white/10 hover:border-purple-400/50 text-slate-300'
                }`}
              >
                <CreditCard size={13} className={isSubscriptionExpired ? 'text-rose-400' : 'text-purple-400'} />
                <span>
                  {isSubscriptionExpired ? (
                    <strong className="text-rose-300">Subscription Inactive</strong>
                  ) : (
                    <>Quota: <strong className="text-purple-300">{subscription.isUnlimited ? 'Unlimited' : `${subscription.scan_quota_used}/${subscription.scan_quota_total}`}</strong></>
                  )}
                </span>
              </Link>
            )}

            {/* Dark / Light Mode Toggle */}
            {/* Prominent Dark / Light Mode Pill Toggle */}
            <button
              onClick={toggleNightMode}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl border border-white/15 hover:border-purple-400/50 bg-slate-900/80 hover:bg-slate-800 text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm group active:scale-95"
              title={isNight ? 'Click to switch to Light Mode' : 'Click to switch to Dark Mode'}
              aria-label="Toggle Theme"
            >
              {isNight ? (
                <>
                  <Sun size={15} className="text-amber-400 group-hover:rotate-90 transition-transform duration-300" />
                  <span className="text-xs font-bold text-slate-200 group-hover:text-white">Light Mode</span>
                </>
              ) : (
                <>
                  <Moon size={15} className="text-purple-400 group-hover:-rotate-12 transition-transform duration-300" />
                  <span className="text-xs font-bold text-slate-200 group-hover:text-white">Dark Mode</span>
                </>
              )}
            </button>
          </div>
        </header>

        <div className="px-3 sm:px-6 py-4 sm:py-6">
          {/* Paywall Gate: If client has no subscription and tries to view dashboard/scans, show Paywall Card */}
          {isSubscriptionExpired && !isAllowedPathWhenExpired ? (
            <div className="space-y-6 animate-in fade-in duration-300 py-6">
              <div className="glass rounded-3xl border border-rose-500/30 p-8 sm:p-12 text-center max-w-3xl mx-auto shadow-2xl relative overflow-hidden bg-slate-950/80">
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-rose-500/10 rounded-full blur-[100px] pointer-events-none" />

                <div className="relative z-10 space-y-4">
                  <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-rose-500/20 to-amber-500/20 border border-rose-500/40 flex items-center justify-center mx-auto shadow-lg shadow-rose-500/20">
                    <Lock size={32} className="text-rose-400" />
                  </div>

                  <div className="space-y-1.5">
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-rose-500/10 text-rose-300 text-xs font-extrabold border border-rose-500/30 uppercase tracking-wide">
                      Access Locked
                    </span>
                    <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                      Active Subscription Required
                    </h2>
                    <p className="text-sm text-slate-300 max-w-lg mx-auto">
                      Your SentinelAI account currently does not have an active subscription. Choose a plan to unlock autonomous AI audits, Kali vulnerability scans, and GitHub automation.
                    </p>
                  </div>

                  {/* Plan Selection Cards Preview */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-left pt-6 max-w-xl mx-auto">
                    <div className="p-5 rounded-2xl border border-purple-500/40 bg-purple-950/20 flex flex-col justify-between space-y-4">
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="font-extrabold text-white text-base">SentinelAI Pro</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold">Popular</span>
                        </div>
                        <div className="text-2xl font-black text-purple-300 mt-1">$19<span className="text-xs text-slate-400 font-normal">/mo</span></div>
                        <ul className="text-xs text-slate-300 space-y-1.5 mt-3">
                          <li className="flex items-center gap-2"><CheckCircle2 size={14} className="text-purple-400 shrink-0" /> 50 AI Code Audits / mo</li>
                          <li className="flex items-center gap-2"><CheckCircle2 size={14} className="text-purple-400 shrink-0" /> 5 Linked Repositories</li>
                          <li className="flex items-center gap-2"><CheckCircle2 size={14} className="text-purple-400 shrink-0" /> Automated Email PDF</li>
                        </ul>
                      </div>
                      <Link to="/app/billing" className="btn-primary text-xs py-2 w-full justify-center shadow-glow">
                        Subscribe to Pro ($19)
                      </Link>
                    </div>

                    <div className="p-5 rounded-2xl border border-emerald-500/40 bg-emerald-950/20 flex flex-col justify-between space-y-4">
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="font-extrabold text-white text-base">Enterprise</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">Unlimited</span>
                        </div>
                        <div className="text-2xl font-black text-emerald-300 mt-1">$79<span className="text-xs text-slate-400 font-normal">/mo</span></div>
                        <ul className="text-xs text-slate-300 space-y-1.5 mt-3">
                          <li className="flex items-center gap-2"><CheckCircle2 size={14} className="text-emerald-400 shrink-0" /> Unlimited AI Code Audits</li>
                          <li className="flex items-center gap-2"><CheckCircle2 size={14} className="text-emerald-400 shrink-0" /> Unlimited GitHub Repos</li>
                          <li className="flex items-center gap-2"><CheckCircle2 size={14} className="text-emerald-400 shrink-0" /> Dedicated SLA & PR Bot</li>
                        </ul>
                      </div>
                      <Link to="/app/billing" className="btn-secondary text-xs py-2 w-full justify-center border-emerald-500/40 text-emerald-300 hover:text-white">
                        Subscribe to Enterprise ($79)
                      </Link>
                    </div>
                  </div>

                  <div className="pt-4">
                    <Link
                      to="/app/billing"
                      className="text-xs font-bold text-slate-400 hover:text-purple-300 transition-colors inline-flex items-center gap-1.5"
                    >
                      <CreditCard size={14} /> Go to Billing & Payment Management Center →
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <Outlet />
          )}
        </div>
      </main>

      {/* Universal Direct Scan Modal */}
      {showNew && (
        <NewScanModal
          onClose={() => setShowNew(false)}
          onStarted={(id) => { setShowNew(false); nav(`/app/scans/${id}`) }}
        />
      )}
      <AIChatWidget />
    </div>
  )
}
