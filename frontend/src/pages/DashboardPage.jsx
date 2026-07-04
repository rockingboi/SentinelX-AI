import { useState, useEffect, useCallback } from 'react'
import {
  Database, Cpu, Activity, Network, Shield,
  Zap, Search, FileText, Users, TrendingUp
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { StatusCard } from '../components/ui/Cards'
import { MetricCard } from '../components/ui/Cards'
import { dashboardAPI } from '../api/client'
import { useAuth } from '../context/AuthContext'

const SERVICE_ICONS = {
  postgres: Database,
  redis: Zap,
  neo4j: Network,
  qdrant: Cpu,
}

export default function DashboardPage() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [error, setError] = useState(null)

  const fetchDashboard = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true)
    else setLoading(true)
    setError(null)

    try {
      const { data: response } = await dashboardAPI.getStatus()
      setData(response.data)
      setLastUpdated(new Date())
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Failed to load dashboard data.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchDashboard()
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => fetchDashboard(true), 30000)
    return () => clearInterval(interval)
  }, [fetchDashboard])

  const services = data?.services ?? {}
  const metrics = data?.metrics ?? {}
  const overallStatus = data?.status ?? 'unavailable'

  const overallConfig = {
    healthy: { color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', label: 'All Systems Operational' },
    degraded: { color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20', label: 'Degraded Performance' },
    unhealthy: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', label: 'System Unhealthy' },
    unavailable: { color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/20', label: 'Status Unknown' },
  }
  const oc = overallConfig[overallStatus] || overallConfig.unavailable

  return (
    <AppLayout onRefresh={() => fetchDashboard(true)} refreshing={refreshing}>
      {/* ── Page header ───────────────────────────────────────── */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">
            Welcome back, <span className="gradient-text">{user?.username}</span>
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            {lastUpdated
              ? `Last updated at ${lastUpdated.toLocaleTimeString()}`
              : 'Loading platform status…'}
          </p>
        </div>

        {data && (
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm border ${oc.bg} ${oc.color}`}>
            <span className={`status-dot ${overallStatus}`} />
            {oc.label}
          </div>
        )}
      </div>

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error} — Check that the backend is running.
        </div>
      )}

      {loading ? (
        <DashboardSkeleton />
      ) : (
        <>
          {/* ── Metric cards ────────────────────────────────────── */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <MetricCard
              label="Active Investigations"
              value={metrics.investigations?.active ?? 0}
              sublabel="Phase 2 — Agents coming"
              icon={Search}
              gradient="bg-blue-500"
            />
            <MetricCard
              label="Threats Detected"
              value={metrics.threats?.detected ?? 0}
              sublabel="This week"
              icon={Shield}
              gradient="bg-red-500"
            />
            <MetricCard
              label="AI Agents Online"
              value={metrics.agents?.online ?? 0}
              sublabel="Phase 2 — Coming soon"
              icon={Cpu}
              gradient="bg-violet-500"
            />
            <MetricCard
              label="Reports Generated"
              value={metrics.investigations?.completed ?? 0}
              sublabel="Total completed"
              icon={FileText}
              gradient="bg-emerald-500"
            />
          </div>

          {/* ── Service health grid ─────────────────────────────── */}
          <section className="mb-8">
            <div className="flex items-center gap-2 mb-4">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                Infrastructure Health
              </h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {Object.entries(services).map(([name, svc]) => (
                <StatusCard
                  key={name}
                  name={name.charAt(0).toUpperCase() + name.slice(1)}
                  status={svc.status}
                  message={svc.message}
                  version={svc.version}
                  icon={SERVICE_ICONS[name]}
                />
              ))}
              {/* API Backend — always healthy if we got here */}
              <StatusCard
                name="Backend API"
                status="healthy"
                message="FastAPI running"
                version={data?.version}
                icon={Shield}
              />
              <StatusCard
                name="Authentication"
                status="healthy"
                message="JWT — Active session"
                icon={Users}
              />
            </div>
          </section>

          {/* ── System info ─────────────────────────────────────── */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                Platform Info
              </h2>
            </div>
            <div className="glass-card p-5 grid grid-cols-2 md:grid-cols-4 gap-6">
              {[
                { label: 'Version', value: data?.version ?? '—' },
                { label: 'Environment', value: data?.environment ?? '—' },
                { label: 'Uptime', value: `${metrics.system?.uptime_hours ?? 0}h` },
                { label: 'API Requests Today', value: metrics.system?.api_requests_today ?? 0 },
              ].map(({ label, value }) => (
                <div key={label}>
                  <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
                  <p className="text-base font-semibold text-slate-200 font-mono">{value}</p>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </AppLayout>
  )
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="glass-card h-28" />
        ))}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="glass-card h-20" />
        ))}
      </div>
    </div>
  )
}
