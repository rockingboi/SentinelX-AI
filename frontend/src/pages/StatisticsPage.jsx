import { useState, useEffect, useCallback } from 'react'
import {
  BarChart3, RefreshCw, TrendingUp, Shield, Globe,
  AlertTriangle, Zap, FileText, Clock, ShieldAlert
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { statisticsAPI, SEVERITY_CONFIG, LOG_TYPE_LABELS } from '../api/logs'

// ── Mini stat card ────────────────────────────────────────────────────────────

function StatCard({ label, value, sublabel, icon: Icon, gradient, color = 'text-slate-100' }) {
  return (
    <div className="glass-card p-5 relative overflow-hidden group hover:border-white/20 transition-all">
      <div className={`absolute -top-4 -right-4 w-20 h-20 rounded-full opacity-10
                        blur-xl transition-opacity group-hover:opacity-20 ${gradient || 'bg-cyan-500'}`} />
      <div className="relative flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">{label}</p>
          <p className={`text-3xl font-bold ${color}`}>{value ?? '—'}</p>
          {sublabel && <p className="text-xs text-slate-500 mt-1">{sublabel}</p>}
        </div>
        {Icon && (
          <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center">
            <Icon className="w-5 h-5 text-slate-400" />
          </div>
        )}
      </div>
    </div>
  )
}

// ── Horizontal bar chart (CSS-only) ──────────────────────────────────────────

function BarRow({ label, value, max, color = 'bg-cyan-500' }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-slate-400 w-28 flex-shrink-0 truncate">{label}</span>
      <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-slate-400 w-10 text-right flex-shrink-0">{value}</span>
    </div>
  )
}

// ── Severity distribution ─────────────────────────────────────────────────────

function SeverityChart({ counts = {} }) {
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
  const BAR_COLORS = {
    critical: 'bg-red-500', high: 'bg-orange-500',
    medium: 'bg-amber-500', low: 'bg-blue-500', info: 'bg-slate-500',
  }
  const max = Math.max(...SEV_ORDER.map(s => counts[s] || 0), 1)
  return (
    <div className="glass-card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <ShieldAlert className="w-4 h-4 text-amber-400" />
        <h3 className="text-sm font-semibold text-slate-200">Events by Severity</h3>
      </div>
      <div className="space-y-3">
        {SEV_ORDER.map(s => (
          <div key={s} className="space-y-1">
            <BarRow
              label={s.charAt(0).toUpperCase() + s.slice(1)}
              value={counts[s] || 0}
              max={max}
              color={BAR_COLORS[s]}
            />
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Log type distribution ─────────────────────────────────────────────────────

function LogTypeChart({ counts = {} }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1])
  const max = Math.max(...entries.map(([, v]) => v), 1)
  const COLORS = ['bg-cyan-500', 'bg-blue-500', 'bg-purple-500', 'bg-teal-500', 'bg-indigo-500']
  return (
    <div className="glass-card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <FileText className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-semibold text-slate-200">Logs by Type</h3>
      </div>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-600 py-4 text-center">No log data yet.</p>
      ) : (
        <div className="space-y-3">
          {entries.map(([type, count], i) => (
            <BarRow
              key={type}
              label={LOG_TYPE_LABELS[type] || type}
              value={count}
              max={max}
              color={COLORS[i % COLORS.length]}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Top IOC types ─────────────────────────────────────────────────────────────

function IOCTypeChart({ counts = {} }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8)
  const max = Math.max(...entries.map(([, v]) => v), 1)
  return (
    <div className="glass-card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <Globe className="w-4 h-4 text-purple-400" />
        <h3 className="text-sm font-semibold text-slate-200">IOC Types</h3>
      </div>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-600 py-4 text-center">No IOC data yet.</p>
      ) : (
        <div className="space-y-3">
          {entries.map(([type, count]) => (
            <BarRow key={type} label={type.toUpperCase()} value={count} max={max} color="bg-purple-500" />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Top MITRE tactics ─────────────────────────────────────────────────────────

function MITREChart({ tactics = {} }) {
  const entries = Object.entries(tactics).sort((a, b) => b[1] - a[1]).slice(0, 6)
  const max = Math.max(...entries.map(([, v]) => v), 1)
  return (
    <div className="glass-card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <Shield className="w-4 h-4 text-rose-400" />
        <h3 className="text-sm font-semibold text-slate-200">Top MITRE Tactics</h3>
      </div>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-600 py-4 text-center">No threat data yet.</p>
      ) : (
        <div className="space-y-3">
          {entries.map(([tactic, count]) => (
            <BarRow key={tactic} label={tactic} value={count} max={max} color="bg-rose-500" />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function StatisticsPage() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)

  const fetchStats = useCallback(() => {
    setLoading(true)
    setError(null)
    statisticsAPI.get()
      .then(({ data }) => {
        setStats(data.data)
        setLastUpdated(new Date())
      })
      .catch(err => setError(err.response?.data?.error?.message || 'Failed to load statistics.'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchStats()
    const t = setInterval(fetchStats, 60_000)
    return () => clearInterval(t)
  }, [fetchStats])

  const s = stats || {}

  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto space-y-6">

        {/* ── Header ─────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-teal-500 to-cyan-600
                            flex items-center justify-center shadow-lg shadow-teal-500/25">
              <BarChart3 className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-100">Statistics</h1>
              <p className="text-xs text-slate-500">
                {lastUpdated
                  ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
                  : 'Platform-wide analytics'}
              </p>
            </div>
          </div>
          <button
            id="refresh-stats-btn"
            onClick={fetchStats}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {error && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/5 border border-red-500/20">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
        )}

        {/* ── Key metrics ─────────────────────────────────── */}
        {loading && !stats ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-6 h-6 border-2 border-teal-500/30 border-t-teal-500 rounded-full animate-spin" />
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <StatCard label="Total Logs" value={s.total_logs} icon={FileText}
                gradient="bg-cyan-500" color="text-cyan-300" />
              <StatCard label="Events Parsed" value={s.total_events} icon={Zap}
                gradient="bg-blue-500" color="text-blue-300" />
              <StatCard label="Threats Detected" value={s.total_threats} icon={ShieldAlert}
                gradient="bg-red-500" color="text-red-300" />
              <StatCard label="Unique IOCs" value={s.total_iocs} icon={Globe}
                gradient="bg-purple-500" color="text-purple-300" />
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <StatCard label="Critical Events" value={s.critical_events} icon={AlertTriangle}
                gradient="bg-rose-500" color="text-rose-300" />
              <StatCard label="Open Incidents" value={s.open_incidents} icon={Clock}
                gradient="bg-orange-500" color="text-orange-300" />
              <StatCard label="Avg. Proc. Time" value={s.avg_processing_ms ? `${s.avg_processing_ms}ms` : '—'}
                icon={TrendingUp} gradient="bg-teal-500" color="text-teal-300" />
              <StatCard label="IOC Hit Rate" value={s.ioc_hit_rate ? `${Math.round(s.ioc_hit_rate * 100)}%` : '—'}
                icon={Shield} gradient="bg-indigo-500" color="text-indigo-300" />
            </div>

            {/* ── Charts ──────────────────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <SeverityChart counts={s.severity_counts} />
              <LogTypeChart counts={s.log_type_counts} />
              <IOCTypeChart counts={s.ioc_type_counts} />
              <MITREChart tactics={s.tactic_counts} />
            </div>
          </>
        )}
      </div>
    </AppLayout>
  )
}
