import { useState, useEffect, useCallback } from 'react'
import {
  ShieldAlert, RefreshCw, Filter, ChevronDown,
  AlertTriangle, CheckCircle, Clock, Search,
  ChevronLeft, ChevronRight, Shield, Zap, User, Globe
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { incidentsAPI, SEVERITY_CONFIG, formatDate } from '../api/logs'

// ── Status config ─────────────────────────────────────────────────────────────

const INCIDENT_STATUS = {
  open:           { label: 'Open',           color: 'text-red-400',     bg: 'bg-red-500/10',    border: 'border-red-500/20',    icon: AlertTriangle },
  investigating:  { label: 'Investigating',  color: 'text-amber-400',   bg: 'bg-amber-500/10',  border: 'border-amber-500/20',  icon: Search },
  resolved:       { label: 'Resolved',       color: 'text-emerald-400', bg: 'bg-emerald-500/10',border: 'border-emerald-500/20',icon: CheckCircle },
  false_positive: { label: 'False Positive', color: 'text-slate-400',   bg: 'bg-slate-500/10',  border: 'border-slate-500/20',  icon: Shield },
}

function StatusBadge({ status }) {
  const cfg = INCIDENT_STATUS[status] || INCIDENT_STATUS.open
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.bg} ${cfg.text || cfg.color} ${cfg.border}`}>
      <Icon className="w-3 h-3" />{cfg.label}
    </span>
  )
}

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {severity?.toUpperCase() || 'INFO'}
    </span>
  )
}

// ── Status update dropdown ────────────────────────────────────────────────────

function StatusDropdown({ incidentId, currentStatus, onUpdated }) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const statuses = Object.keys(INCIDENT_STATUS).filter(s => s !== currentStatus)

  async function update(status) {
    setLoading(true)
    setOpen(false)
    try {
      await incidentsAPI.updateStatus(incidentId, status)
      onUpdated(incidentId, status)
    } catch {
      // silent — UI will not update
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative">
      <button
        id={`incident-status-btn-${incidentId}`}
        onClick={() => setOpen(!open)}
        disabled={loading}
        className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200
                   transition-colors disabled:opacity-50"
      >
        {loading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <ChevronDown className="w-3 h-3" />}
        <span>Update</span>
      </button>
      {open && (
        <div className="absolute right-0 top-6 z-20 min-w-36 rounded-xl bg-slate-900 border border-white/10
                        shadow-xl shadow-black/40 overflow-hidden animate-fade-in">
          {statuses.map(s => {
            const cfg = INCIDENT_STATUS[s]
            return (
              <button
                key={s}
                id={`set-status-${s}`}
                onClick={() => update(s)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-xs text-left
                            hover:bg-white/5 transition-colors ${cfg.color}`}
              >
                <cfg.icon className="w-3 h-3" />
                {cfg.label}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Incident row ──────────────────────────────────────────────────────────────

function IncidentRow({ incident, onStatusUpdated }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-3 px-4 py-4
                    border-b border-white/5 last:border-0 hover:bg-white/2 transition-colors">
      {/* Left: severity + title */}
      <div className="flex items-start gap-3 flex-1 min-w-0">
        <div className="flex-shrink-0 mt-0.5">
          <SeverityBadge severity={incident.severity} />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-slate-200 truncate">
            {incident.event_type || 'Security Incident'}
          </p>
          <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1">
            {incident.source_ip && (
              <span className="text-xs text-slate-500 font-mono flex items-center gap-1">
                <Globe className="w-3 h-3" />{incident.source_ip}
              </span>
            )}
            {incident.username && (
              <span className="text-xs text-slate-500 flex items-center gap-1">
                <User className="w-3 h-3" />{incident.username}
              </span>
            )}
            {incident.mitre_technique_id && (
              <span className="text-xs font-mono px-1.5 py-0.5 rounded
                               bg-purple-500/10 border border-purple-500/20 text-purple-400">
                {incident.mitre_technique_id}
              </span>
            )}
          </div>
          {incident.tactic_name && (
            <p className="text-xs text-slate-600 mt-0.5">{incident.tactic_name}</p>
          )}
        </div>
      </div>

      {/* Right: status + time + actions */}
      <div className="flex items-center gap-3 flex-shrink-0 pl-0 sm:pl-4">
        <StatusBadge status={incident.status} />
        <span className="text-xs text-slate-600 flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {formatDate(incident.detected_at || incident.created_at)}
        </span>
        <StatusDropdown
          incidentId={incident.id}
          currentStatus={incident.status}
          onUpdated={onStatusUpdated}
        />
      </div>
    </div>
  )
}

// ── Filter bar ────────────────────────────────────────────────────────────────

const STATUS_OPTS = ['', ...Object.keys(INCIDENT_STATUS)]
const SEVERITY_OPTS = ['', 'critical', 'high', 'medium', 'low']

function FilterBar({ filters, onChange }) {
  return (
    <div className="flex flex-wrap gap-2 px-4 py-3 border-b border-white/5">
      <div className="relative">
        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" />
        <select id="status-filter"
          value={filters.status}
          onChange={(e) => onChange({ ...filters, status: e.target.value, page: 1 })}
          className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-white/5 border border-white/10
                     text-slate-300 focus:outline-none appearance-none">
          <option value="" className="bg-slate-900">All Statuses</option>
          {STATUS_OPTS.filter(Boolean).map(s => (
            <option key={s} value={s} className="bg-slate-900">{INCIDENT_STATUS[s].label}</option>
          ))}
        </select>
      </div>
      <div className="relative">
        <ShieldAlert className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" />
        <select id="severity-filter"
          value={filters.severity}
          onChange={(e) => onChange({ ...filters, severity: e.target.value, page: 1 })}
          className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-white/5 border border-white/10
                     text-slate-300 focus:outline-none appearance-none">
          <option value="" className="bg-slate-900">All Severities</option>
          {SEVERITY_OPTS.filter(Boolean).map(s => (
            <option key={s} value={s} className="bg-slate-900 capitalize">{s}</option>
          ))}
        </select>
      </div>
    </div>
  )
}

// ── Pagination ────────────────────────────────────────────────────────────────

function Pagination({ page, total, perPage, onChange }) {
  const pages = Math.ceil(total / perPage)
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-white/5">
      <p className="text-xs text-slate-500">{total} incident{total !== 1 ? 's' : ''}</p>
      <div className="flex gap-1 items-center">
        <button onClick={() => onChange(page - 1)} disabled={page <= 1}
          className="w-7 h-7 rounded-lg flex items-center justify-center text-slate-400
                     hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>
        <span className="text-xs text-slate-400 px-2">{page}/{pages}</span>
        <button onClick={() => onChange(page + 1)} disabled={page >= pages}
          className="w-7 h-7 rounded-lg flex items-center justify-center text-slate-400
                     hover:bg-white/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const PER_PAGE = 30

export default function IncidentPage() {
  const [incidents, setIncidents] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ status: '', severity: '', page: 1 })

  const fetchIncidents = useCallback(() => {
    setLoading(true)
    setError(null)
    const params = {
      page: filters.page,
      per_page: PER_PAGE,
      ...(filters.status && { status: filters.status }),
      ...(filters.severity && { severity: filters.severity }),
    }
    incidentsAPI.list(params)
      .then(({ data }) => {
        setIncidents(data.data?.items || data.data || [])
        setTotal(data.data?.total || 0)
      })
      .catch(err => setError(err.response?.data?.error?.message || 'Failed to load incidents.'))
      .finally(() => setLoading(false))
  }, [filters])

  useEffect(() => { fetchIncidents() }, [fetchIncidents])

  function handleStatusUpdated(id, status) {
    setIncidents(prev => prev.map(inc =>
      inc.id === id ? { ...inc, status } : inc
    ))
  }

  // Summary counts from current page
  const openCount = incidents.filter(i => i.status === 'open').length
  const criticalCount = incidents.filter(i => i.severity === 'critical').length

  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto space-y-6">

        {/* ── Header ──────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-orange-600
                            flex items-center justify-center shadow-lg shadow-red-500/25">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-100">Incidents</h1>
              <p className="text-xs text-slate-500">Security events requiring investigation</p>
            </div>
          </div>
          <button
            id="refresh-incidents-btn"
            onClick={fetchIncidents}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* ── Summary stats ──────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Total', value: total, color: 'text-slate-200', icon: Zap },
            { label: 'Open', value: openCount, color: 'text-red-400', icon: AlertTriangle },
            { label: 'Critical', value: criticalCount, color: 'text-rose-400', icon: ShieldAlert },
          ].map(({ label, value, color, icon: Icon }) => (
            <div key={label} className="glass-card p-4 flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center flex-shrink-0">
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <div>
                <p className={`text-xl font-bold ${color}`}>{value}</p>
                <p className="text-xs text-slate-500">{label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* ── Incidents list ─────────────────────────────────────── */}
        <div className="glass-card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/5 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold text-slate-200">Incident Queue</h2>
            {total > 0 && (
              <span className="text-xs px-1.5 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20">
                {total}
              </span>
            )}
          </div>

          <FilterBar filters={filters} onChange={setFilters} />

          {error ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertTriangle className="w-6 h-6 text-red-400" />
              <p className="text-sm text-slate-400">{error}</p>
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-5 h-5 border-2 border-red-500/30 border-t-red-500 rounded-full animate-spin" />
            </div>
          ) : incidents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <CheckCircle className="w-8 h-8 text-emerald-600" />
              <p className="text-sm text-slate-500">No incidents match your filters.</p>
            </div>
          ) : (
            <>
              {incidents.map((inc, i) => (
                <IncidentRow
                  key={inc.id || i}
                  incident={inc}
                  onStatusUpdated={handleStatusUpdated}
                />
              ))}
              <Pagination
                page={filters.page}
                total={total}
                perPage={PER_PAGE}
                onChange={(p) => setFilters(f => ({ ...f, page: p }))}
              />
            </>
          )}
        </div>
      </div>
    </AppLayout>
  )
}
