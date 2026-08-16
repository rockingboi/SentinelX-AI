import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Search, FileText,
  Settings, Activity, ChevronLeft, ChevronRight,
  LogOut, Zap, Upload, Globe, ShieldAlert, BarChart3, BookOpen
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const NAV_ITEMS = [
  { to: '/dashboard',    icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/logs/upload',  icon: Upload,          label: 'Log Analysis' },
  { to: '/iocs',         icon: Globe,           label: 'IOC Explorer' },
  { to: '/incidents',    icon: ShieldAlert,      label: 'Incidents' },
  { to: '/statistics',   icon: BarChart3,        label: 'Statistics' },
  { to: '/knowledge',    icon: BookOpen,         label: 'Knowledge' },
  { to: '/status',       icon: Activity,        label: 'System Status' },
  { to: '/settings',     icon: Settings,        label: 'Settings' },
]

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <aside
      className={`relative flex flex-col h-screen bg-sentinel-900 border-r border-white/5
                  transition-all duration-300 ease-in-out
                  ${collapsed ? 'w-16' : 'w-60'}`}
    >
      {/* ── Logo ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-white/5">
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600
                        flex items-center justify-center shadow-lg shadow-cyan-500/30">
          <Zap className="w-4 h-4 text-white" />
        </div>
        {!collapsed && (
          <div className="animate-fade-in overflow-hidden">
            <p className="text-sm font-bold gradient-text">SentinelX AI</p>
            <p className="text-xs text-slate-500">Cyber Investigation</p>
          </div>
        )}
      </div>

      {/* ── Navigation ────────────────────────────────────────── */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `nav-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center px-2' : ''}`
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            {!collapsed && <span className="animate-fade-in">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* ── User section ──────────────────────────────────────── */}
      <div className="border-t border-white/5 p-3 space-y-1">
        {!collapsed && user && (
          <div className="px-2 py-2 animate-fade-in">
            <p className="text-xs font-medium text-slate-300 truncate">{user.username}</p>
            <p className="text-xs text-slate-500 truncate">{user.email}</p>
            <span className="inline-block mt-1 text-xs px-1.5 py-0.5 rounded
                             bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 capitalize">
              {user.role}
            </span>
          </div>
        )}
        <button
          onClick={handleLogout}
          className={`nav-link w-full text-red-400 hover:text-red-300 hover:bg-red-500/10
                      ${collapsed ? 'justify-center px-2' : ''}`}
        >
          <LogOut className="w-4 h-4 flex-shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>

      {/* ── Collapse toggle ────────────────────────────────────── */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-6 w-6 h-6 rounded-full
                   bg-sentinel-800 border border-white/10
                   flex items-center justify-center
                   text-slate-400 hover:text-slate-200
                   transition-colors shadow-lg"
      >
        {collapsed
          ? <ChevronRight className="w-3 h-3" />
          : <ChevronLeft className="w-3 h-3" />
        }
      </button>
    </aside>
  )
}
