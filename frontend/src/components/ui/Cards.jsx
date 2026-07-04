// StatusCard — shows health of a single service
export function StatusCard({ name, status, message, version, icon: Icon }) {
  const statusConfig = {
    healthy: {
      dot: 'healthy',
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      label: 'Healthy',
    },
    unhealthy: {
      dot: 'unhealthy',
      badge: 'bg-red-500/10 text-red-400 border-red-500/20',
      label: 'Unhealthy',
    },
    degraded: {
      dot: 'degraded',
      badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      label: 'Degraded',
    },
    unavailable: {
      dot: 'unavailable',
      badge: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
      label: 'Unavailable',
    },
  }

  const cfg = statusConfig[status] || statusConfig.unavailable

  return (
    <div className="glass-card p-4 flex items-start gap-4 transition-all duration-200
                    hover:border-white/20 hover:bg-white/8">
      <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-white/5
                      flex items-center justify-center">
        {Icon && <Icon className="w-5 h-5 text-slate-400" />}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2 mb-1">
          <p className="text-sm font-semibold text-slate-200">{name}</p>
          <span className={`flex-shrink-0 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full
                            text-xs font-medium border ${cfg.badge}`}>
            <span className={`status-dot ${cfg.dot}`} />
            {cfg.label}
          </span>
        </div>
        <p className="text-xs text-slate-500 truncate">{message}</p>
        {version && (
          <p className="text-xs text-slate-600 mt-0.5 font-mono">v{version}</p>
        )}
      </div>
    </div>
  )
}

// MetricCard — displays a numbered metric
export function MetricCard({ label, value, sublabel, icon: Icon, gradient, trend }) {
  return (
    <div className={`glass-card p-5 relative overflow-hidden group
                     hover:border-white/20 transition-all duration-200`}>
      {/* Background gradient orb */}
      <div className={`absolute -top-4 -right-4 w-20 h-20 rounded-full opacity-10
                        blur-xl transition-opacity group-hover:opacity-20 ${gradient}`} />

      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">
            {label}
          </p>
          <p className="text-3xl font-bold text-slate-100">{value}</p>
          {sublabel && (
            <p className="text-xs text-slate-500 mt-1">{sublabel}</p>
          )}
          {trend !== undefined && (
            <p className={`text-xs mt-1 ${trend >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
              {trend >= 0 ? '↑' : '↓'} {Math.abs(trend)}% vs last week
            </p>
          )}
        </div>
        {Icon && (
          <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-white/5
                          flex items-center justify-center">
            <Icon className="w-5 h-5 text-slate-400" />
          </div>
        )}
      </div>
    </div>
  )
}
