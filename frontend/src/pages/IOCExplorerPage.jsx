import { useState, useEffect, useCallback } from 'react'
import {
  Search, Globe, Hash, Mail, Link2, FileDigit, Key,
  Filter, ChevronDown, AlertTriangle, Copy, CheckCheck,
  RefreshCw, ChevronLeft, ChevronRight, Shield
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { iocsAPI } from '../api/logs'

// ── IOC type icon + colour map ────────────────────────────────────────────────

const IOC_CONFIG = {
  ipv4:     { icon: Globe,   color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20',   label: 'IPv4' },
  ipv6:     { icon: Globe,   color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/20', label: 'IPv6' },
  domain:   { icon: Link2,   color: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/20',   label: 'Domain' },
  url:      { icon: Link2,   color: 'text-teal-400',   bg: 'bg-teal-500/10',   border: 'border-teal-500/20',   label: 'URL' },
  email:    { icon: Mail,    color: 'text-purple-400',  bg: 'bg-purple-500/10', border: 'border-purple-500/20', label: 'Email' },
  md5:      { icon: Hash,    color: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/20',  label: 'MD5' },
  sha1:     { icon: Hash,    color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', label: 'SHA1' },
  sha256:   { icon: Hash,    color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/20',    label: 'SHA256' },
  cve:      { icon: Shield,  color: 'text-rose-400',   bg: 'bg-rose-500/10',   border: 'border-rose-500/20',   label: 'CVE' },
  port:     { icon: Key,     color: 'text-slate-400',  bg: 'bg-slate-500/10',  border: 'border-slate-500/20',  label: 'Port' },
  filename: { icon: FileDigit,color:'text-lime-400',   bg: 'bg-lime-500/10',   border: 'border-lime-500/20',   label: 'Filename' },
  registry: { icon: Key,     color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', label: 'Registry' },
}

function getIOCCfg(type) {
  return IOC_CONFIG[type?.toLowerCase()] || {
    icon: FileDigit, color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20', label: type,
  }
}

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyBtn({ value }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <button
      onClick={copy}
      className="flex-shrink-0 text-slate-600 hover:text-slate-300 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

// ── IOC card ──────────────────────────────────────────────────────────────────

function IOCCard({ ioc }) {
  const cfg = getIOCCfg(ioc.ioc_type)
  const Icon = cfg.icon

  return (
    <div className={`rounded-xl border p-4 flex items-start gap-3 hover:bg-white/3 transition-colors ${cfg.bg} ${cfg.border}`}>
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 bg-black/20`}>
        <Icon className={`w-4 h-4 ${cfg.color}`} />
      </div>

      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${cfg.bg} ${cfg.color}`}>
            {cfg.label}
          </span>
          {ioc.confidence !== undefined && (
            <span className="text-xs text-slate-600">
              {Math.round(ioc.confidence * 100)}% conf.
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <p className={`text-sm font-mono font-medium truncate ${cfg.color}`}>
            {ioc.value}
          </p>
          <CopyBtn value={ioc.value} />
        </div>
        {ioc.context && (
          <p className="text-xs text-slate-600 truncate font-mono">{ioc.context}</p>
        )}
        {ioc.seen_count > 1 && (
          <p className="text-xs text-slate-500">Seen <strong className="text-slate-300">{ioc.seen_count}×</strong> across logs</p>
        )}
      </div>
    </div>
  )
}

// ── Pagination ─────────────────────────────────────────────────────────────────

function Pagination({ page, total, perPage, onChange }) {
  const pages = Math.ceil(total / perPage)
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-between py-3">
      <p className="text-xs text-slate-500">{total} results</p>
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

// ── IOC type filter chips ──────────────────────────────────────────────────────

const IOC_TYPES = ['', ...Object.keys(IOC_CONFIG)]

function TypeChips({ selected, onChange }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {IOC_TYPES.map((t) => {
        const cfg = t ? getIOCCfg(t) : null
        const active = selected === t
        return (
          <button
            key={t || 'all'}
            id={`ioc-type-${t || 'all'}`}
            onClick={() => onChange(t)}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all
                        ${active
                          ? `${cfg?.bg || 'bg-white/10'} ${cfg?.color || 'text-slate-200'} ${cfg?.border || 'border-white/20'} border`
                          : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
          >
            {t ? (cfg?.label || t) : 'All Types'}
          </button>
        )
      })}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

const PER_PAGE = 40

export default function IOCExplorerPage() {
  const [iocs, setIOCs] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ q: '', ioc_type: '', page: 1 })

  const fetchIOCs = useCallback(() => {
    setLoading(true)
    setError(null)
    const params = {
      page: filters.page,
      per_page: PER_PAGE,
      ...(filters.q && { q: filters.q }),
      ...(filters.ioc_type && { ioc_type: filters.ioc_type }),
    }
    iocsAPI.search(params)
      .then(({ data }) => {
        setIOCs(data.data?.items || data.data || [])
        setTotal(data.data?.total || 0)
      })
      .catch(err => setError(err.response?.data?.error?.message || 'Failed to load IOCs.'))
      .finally(() => setLoading(false))
  }, [filters])

  useEffect(() => { fetchIOCs() }, [fetchIOCs])

  function setFilter(key, value) {
    setFilters(f => ({ ...f, [key]: value, page: 1 }))
  }

  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto space-y-6">

        {/* ── Header ──────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600
                            flex items-center justify-center shadow-lg shadow-purple-500/25">
              <Globe className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-100">IOC Explorer</h1>
              <p className="text-xs text-slate-500">Indicators of Compromise extracted by the NLP pipeline</p>
            </div>
          </div>
          <button
            id="refresh-iocs-btn"
            onClick={fetchIOCs}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* ── Search + type filter ─────────────────────── */}
        <div className="glass-card p-4 space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              id="ioc-search-input"
              value={filters.q}
              onChange={(e) => setFilter('q', e.target.value)}
              placeholder="Search IPs, domains, hashes, CVEs…"
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-white/5 border border-white/10
                         text-sm text-slate-200 placeholder-slate-600
                         focus:outline-none focus:border-cyan-500/50 transition-colors"
            />
          </div>
          <TypeChips
            selected={filters.ioc_type}
            onChange={(t) => setFilter('ioc_type', t)}
          />
        </div>

        {/* ── Results ─────────────────────────────────── */}
        {error ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <AlertTriangle className="w-6 h-6 text-red-400" />
            <p className="text-sm text-slate-400">{error}</p>
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-6 h-6 border-2 border-purple-500/30 border-t-purple-500 rounded-full animate-spin" />
          </div>
        ) : iocs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <Globe className="w-8 h-8 text-slate-700" />
            <p className="text-sm text-slate-500">No IOCs found matching your filters.</p>
          </div>
        ) : (
          <>
            <p className="text-xs text-slate-500">{total} indicator{total !== 1 ? 's' : ''} found</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {iocs.map((ioc, i) => <IOCCard key={ioc.id || i} ioc={ioc} />)}
            </div>
            <Pagination
              page={filters.page}
              total={total}
              perPage={PER_PAGE}
              onChange={(p) => setFilters(f => ({ ...f, page: p }))}
            />
          </>
        )}
      </div>
    </AppLayout>
  )
}
