import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, FileText, Shield, Zap, AlertTriangle,
  ChevronDown, ChevronUp, Eye, Search, Filter,
  Clock, Globe, Hash, User, Monitor, Cpu, RefreshCw,
  ChevronLeft, ChevronRight
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { logsAPI, SEVERITY_CONFIG, STATUS_CONFIG, LOG_TYPE_LABELS, formatBytes, formatDate } from '../api/logs'

// ── Severity badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {severity?.toUpperCase() || 'INFO'}
    </span>
  )
}

// ── Event row (expandable) ───────────────────────────────────────────────────

function EventRow({ event }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="border-b border-white/5 last:border-0">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/3 transition-colors text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityBadge severity={event.severity} />
        <span className="flex-1 text-xs text-slate-300 font-medium truncate">
          {event.event_type || 'HTTP Request'}
        </span>
        {event.source_ip && (
          <span className="text-xs text-slate-500 font-mono flex items-center gap-1 flex-shrink-0">
            <Globe className="w-3 h-3" />{event.source_ip}
          </span>
        )}
        {event.mitre_technique_id && (
          <span className="hidden sm:block text-xs font-mono px-1.5 py-0.5 rounded
                           bg-purple-500/10 border border-purple-500/20 text-purple-400 flex-shrink-0">
            {event.mitre_technique_id}
          </span>
        )}
        <span className="text-xs text-slate-600 flex-shrink-0">#{event.line_number || '—'}</span>
        {expanded
          ? <ChevronUp className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
          : <ChevronDown className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />}
      </button>

      {expanded && (
        <div className="px-4 pb-3 space-y-2 animate-fade-in">
          {/* Raw line */}
          <div className="font-mono text-xs text-slate-400 bg-white/3 rounded-lg px-3 py-2 break-all">
            {event.raw_line || '—'}
          </div>

          {/* Metadata grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {[
              { icon: User, label: 'Username', value: event.username },
              { icon: Monitor, label: 'Hostname', value: event.hostname },
              { icon: Hash, label: 'Process', value: event.process_name },
              { icon: Globe, label: 'URL', value: event.url },
              { icon: Cpu, label: 'HTTP Method', value: event.http_method },
              { icon: Shield, label: 'MITRE Tactic', value: event.tactic_name },
            ].filter(({ value }) => value).map(({ icon: Icon, label, value }) => (
              <div key={label} className="text-xs bg-white/3 rounded-lg px-3 py-2">
                <p className="text-slate-600 flex items-center gap-1 mb-1">
                  <Icon className="w-3 h-3" />{label}
                </p>
                <p className="text-slate-300 truncate font-mono">{value}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Pagination ───────────────────────────────────────────────────────────────

function Pagination({ page, total, perPage, onChange }) {
  const totalPages = Math.ceil(total / perPage)
  if (totalPages <= 1) return null

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-white/5">
      <p className="text-xs text-slate-500">
        {((page - 1) * perPage) + 1}–{Math.min(page * perPage, total)} of {total} events
      </p>
      <div className="flex gap-1">
        <button
          onClick={() => onChange(page - 1)}
          disabled={page <= 1}
          className="w-7 h-7 rounded-lg flex items-center justify-center
                     text-slate-400 hover:text-slate-200 hover:bg-white/5
                     disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>
        <span className="flex items-center px-2 text-xs text-slate-400">{page}/{totalPages}</span>
        <button
          onClick={() => onChange(page + 1)}
          disabled={page >= totalPages}
          className="w-7 h-7 rounded-lg flex items-center justify-center
                     text-slate-400 hover:text-slate-200 hover:bg-white/5
                     disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

// ── Filter bar ───────────────────────────────────────────────────────────────

const SEVERITY_OPTS = ['', 'critical', 'high', 'medium', 'low', 'info']

function FilterBar({ filters, onChange }) {
  return (
    <div className="flex flex-wrap gap-2 px-4 py-3 border-b border-white/5">
      <div className="relative flex-1 min-w-48">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
        <input
          id="events-search"
          value={filters.q || ''}
          onChange={(e) => onChange({ ...filters, q: e.target.value, page: 1 })}
          placeholder="Search events…"
          className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg bg-white/5 border border-white/10
                     text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/40"
        />
      </div>
      <div className="relative">
        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" />
        <select
          id="severity-filter"
          value={filters.severity || ''}
          onChange={(e) => onChange({ ...filters, severity: e.target.value, page: 1 })}
          className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-white/5 border border-white/10
                     text-slate-300 focus:outline-none focus:border-cyan-500/40 appearance-none"
        >
          <option value="" className="bg-slate-900">All Severities</option>
          {SEVERITY_OPTS.filter(Boolean).map(s => (
            <option key={s} value={s} className="bg-slate-900 capitalize">{s}</option>
          ))}
        </select>
      </div>
      <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={filters.threats_only || false}
          onChange={(e) => onChange({ ...filters, threats_only: e.target.checked, page: 1 })}
          className="rounded accent-cyan-500"
          id="threats-only-toggle"
        />
        Threats only
      </label>
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

const PER_PAGE = 50

export default function LogViewerPage() {
  const { id } = useParams()
  const navigate = useNavigate()

  const [log, setLog] = useState(null)
  const [events, setEvents] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [eventsLoading, setEventsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ page: 1, severity: '', q: '', threats_only: false })

  // Load log metadata
  useEffect(() => {
    setLoading(true)
    logsAPI.get(id)
      .then(({ data }) => setLog(data.data))
      .catch(err => setError(err.response?.data?.error?.message || 'Log not found.'))
      .finally(() => setLoading(false))
  }, [id])

  // Load events when filters change
  const fetchEvents = useCallback(() => {
    setEventsLoading(true)
    const params = {
      page: filters.page,
      per_page: PER_PAGE,
      ...(filters.severity && { severity: filters.severity }),
      ...(filters.q && { q: filters.q }),
      ...(filters.threats_only && { threats_only: true }),
    }
    logsAPI.getEvents(id, params)
      .then(({ data }) => {
        setEvents(data.data?.items || data.data || [])
        setTotal(data.data?.total || 0)
      })
      .catch(() => {})
      .finally(() => setEventsLoading(false))
  }, [id, filters])

  useEffect(() => { if (!loading && !error) fetchEvents() }, [fetchEvents, loading, error])

  if (loading) {
    return (
      <AppLayout>
        <div className="flex items-center justify-center h-64">
          <div className="w-6 h-6 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
        </div>
      </AppLayout>
    )
  }

  if (error || !log) {
    return (
      <AppLayout>
        <div className="flex flex-col items-center justify-center h-64 gap-4">
          <AlertTriangle className="w-8 h-8 text-red-400" />
          <p className="text-sm text-slate-400">{error || 'Log not found.'}</p>
          <button onClick={() => navigate('/logs')} className="text-xs text-cyan-400 hover:underline">
            Back to Logs
          </button>
        </div>
      </AppLayout>
    )
  }

  const summary = log.pipeline_summary || {}
  const statusCfg = STATUS_CONFIG[log.status] || STATUS_CONFIG.pending

  return (
    <AppLayout>
      <div className="space-y-6 max-w-5xl mx-auto">

        {/* ── Breadcrumb + actions ─────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm">
            <button
              id="back-to-logs"
              onClick={() => navigate('/logs')}
              className="flex items-center gap-1.5 text-slate-500 hover:text-slate-300 transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Logs
            </button>
            <span className="text-slate-700">/</span>
            <span className="text-slate-300 font-medium truncate max-w-64">{log.filename}</span>
          </div>
          <button
            id="refresh-events-btn"
            onClick={fetchEvents}
            disabled={eventsLoading}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${eventsLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* ── Log header card ──────────────────────────────── */}
        <div className="glass-card p-5 space-y-4">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20
                            flex items-center justify-center flex-shrink-0">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-base font-bold text-slate-100 truncate">{log.filename}</h1>
                <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border
                                  ${statusCfg.bg} ${statusCfg.text} ${statusCfg.border}`}>
                  {log.status}
                </span>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1">
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  {LOG_TYPE_LABELS[log.log_type] || log.log_type}
                </span>
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <Eye className="w-3 h-3" />
                  {formatBytes(log.file_size)}
                </span>
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatDate(log.created_at)}
                </span>
              </div>
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Events', value: summary.parsed_events ?? log.total_events ?? '—', color: 'text-slate-200' },
              { label: 'Threats', value: summary.threats_detected ?? '—', color: 'text-amber-400' },
              { label: 'Critical', value: summary.critical_events ?? '—', color: 'text-red-400' },
              { label: 'IOCs', value: summary.unique_iocs ?? '—', color: 'text-cyan-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="text-center bg-white/3 rounded-xl py-3">
                <p className={`text-xl font-bold ${color}`}>{value}</p>
                <p className="text-xs text-slate-500 mt-0.5">{label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* ── Events table ─────────────────────────────────── */}
        <div className="glass-card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-200">Parsed Events</h2>
              {total > 0 && (
                <span className="text-xs px-1.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {total}
                </span>
              )}
            </div>
          </div>

          <FilterBar filters={filters} onChange={setFilters} />

          {eventsLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
            </div>
          ) : events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center gap-3">
              <Search className="w-6 h-6 text-slate-600" />
              <p className="text-sm text-slate-500">No events match your filters.</p>
            </div>
          ) : (
            <div>
              {events.map((ev, i) => <EventRow key={ev.id || i} event={ev} />)}
              <Pagination
                page={filters.page}
                total={total}
                perPage={PER_PAGE}
                onChange={(p) => setFilters(f => ({ ...f, page: p }))}
              />
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  )
}
