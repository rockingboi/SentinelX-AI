import { useLocation } from 'react-router-dom'
import { Bell, RefreshCw } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

const BREADCRUMBS = {
  '/dashboard': 'Dashboard',
  '/investigations': 'Investigations',
  '/threats': 'Threat Intelligence',
  '/reports': 'Reports',
  '/status': 'System Status',
  '/settings': 'Settings',
}

export default function Navbar({ onRefresh, refreshing }) {
  const { user } = useAuth()
  const location = useLocation()
  const pageTitle = BREADCRUMBS[location.pathname] || 'SentinelX AI'

  return (
    <header className="h-14 flex items-center justify-between px-6
                        bg-sentinel-900/50 backdrop-blur-sm
                        border-b border-white/5 flex-shrink-0">
      {/* ── Breadcrumb ─────────────────────────────────────── */}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-slate-500">SentinelX</span>
        <span className="text-slate-600">/</span>
        <span className="text-slate-200 font-medium">{pageTitle}</span>
      </div>

      {/* ── Actions ────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-200
                       hover:bg-white/5 transition-colors disabled:opacity-50"
            title="Refresh data"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        )}

        <button className="relative p-2 rounded-lg text-slate-400
                           hover:text-slate-200 hover:bg-white/5 transition-colors">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5
                           rounded-full bg-cyan-400" />
        </button>

        {/* ── Avatar ─────────────────────────────────────── */}
        <div className="flex items-center gap-2 pl-3 border-l border-white/10">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600
                          flex items-center justify-center text-xs font-bold text-white
                          shadow-lg shadow-cyan-500/20">
            {user?.username?.[0]?.toUpperCase() ?? 'U'}
          </div>
          <div className="hidden sm:block">
            <p className="text-xs font-medium text-slate-200">{user?.username}</p>
            <p className="text-xs text-slate-500 capitalize">{user?.role}</p>
          </div>
        </div>
      </div>
    </header>
  )
}
