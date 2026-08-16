import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Search, BookOpen, Database, Cpu, Zap,
  RefreshCw, AlertTriangle, ChevronDown, ChevronUp,
  Shield, Bug, FileText, Server, BookMarked, Layers,
  Clock, Copy, CheckCheck, BarChart2, Wifi, WifiOff,
  Info, X, Filter, UploadCloud
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { knowledgeAPI } from '../api/knowledge'
import { useAuth } from '../context/AuthContext'

// ─────────────────────────────────────────────────────────────────────────────
// Constants & Config
// ─────────────────────────────────────────────────────────────────────────────

const SOURCE_CONFIG = {
  mitre:    { icon: Shield,    color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/20',    label: 'MITRE ATT&CK' },
  nvd:      { icon: Bug,       color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', label: 'NVD / CVE' },
  sigma:    { icon: Layers,    color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', label: 'Sigma Rules' },
  owasp:    { icon: Server,    color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20',   label: 'OWASP' },
  cisa:     { icon: BookMarked,color: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/20',   label: 'CISA Advisory' },
  playbook: { icon: FileText,  color: 'text-emerald-400',bg: 'bg-emerald-500/10',border: 'border-emerald-500/20',label: 'Playbook' },
  custom:   { icon: BookOpen,  color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20', label: 'Custom' },
}

const SEVERITY_CONFIG = {
  critical: { text: 'text-red-400',    bg: 'bg-red-500/15',    label: 'CRITICAL' },
  high:     { text: 'text-orange-400', bg: 'bg-orange-500/15', label: 'HIGH' },
  medium:   { text: 'text-yellow-400', bg: 'bg-yellow-500/15', label: 'MEDIUM' },
  low:      { text: 'text-blue-400',   bg: 'bg-blue-500/15',   label: 'LOW' },
  info:     { text: 'text-slate-400',  bg: 'bg-slate-500/15',  label: 'INFO' },
}

const SOURCE_FILTERS = ['', ...Object.keys(SOURCE_CONFIG)]

const EXAMPLE_QUERIES = [
  'SQL injection attack techniques',
  'PowerShell execution evasion T1059',
  'CVE-2021-44228 Log4Shell exploitation',
  'Credential dumping LSASS memory',
  'Ransomware persistence mechanisms',
  'Lateral movement SMB network shares',
]

function getSourceCfg(type) {
  return SOURCE_CONFIG[type?.toLowerCase()] || {
    icon: BookOpen, color: 'text-slate-400', bg: 'bg-slate-500/10',
    border: 'border-slate-500/20', label: type || 'Unknown',
  }
}

function getSeverityCfg(sev) {
  return SEVERITY_CONFIG[sev?.toLowerCase()] || { text: 'text-slate-500', bg: 'bg-slate-500/10', label: sev || '—' }
}

// ─────────────────────────────────────────────────────────────────────────────
// Small reusable components
// ─────────────────────────────────────────────────────────────────────────────

function CopyBtn({ value, className = '' }) {
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
      className={`flex-shrink-0 text-slate-600 hover:text-slate-300 transition-colors ${className}`}
      title="Copy to clipboard"
    >
      {copied
        ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" />
        : <Copy className="w-3.5 h-3.5" />
      }
    </button>
  )
}

function Spinner({ size = 'w-5 h-5', color = 'border-cyan-500' }) {
  return (
    <div className={`${size} border-2 ${color}/30 border-t-${color.split('-')[1]}-500 rounded-full animate-spin`} />
  )
}

function StatBadge({ icon: Icon, label, value, color = 'text-slate-300' }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className={`w-3.5 h-3.5 ${color} flex-shrink-0`} />
      <span className="text-xs text-slate-500">{label}</span>
      <span className={`text-xs font-semibold ${color}`}>{value}</span>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Knowledge Stats Panel
// ─────────────────────────────────────────────────────────────────────────────

function StatsPanel({ stats, loading, error }) {
  if (loading) {
    return (
      <div className="glass-card p-4 flex items-center gap-3">
        <div className="w-4 h-4 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
        <span className="text-xs text-slate-500">Loading knowledge base stats…</span>
      </div>
    )
  }
  if (error || !stats) return null

  const bm25Status = stats.bm25_is_built
  const modelStatus = stats.embedding_model_loaded

  return (
    <div className="glass-card p-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <StatBadge
          icon={Database}
          label="Indexed chunks"
          value={stats.points_count?.toLocaleString() ?? '—'}
          color="text-cyan-400"
        />
        <StatBadge
          icon={Cpu}
          label="BM25 corpus"
          value={bm25Status ? `${stats.bm25_corpus_size?.toLocaleString()} chunks` : 'Not built'}
          color={bm25Status ? 'text-emerald-400' : 'text-amber-400'}
        />
        <StatBadge
          icon={Zap}
          label="BGE model"
          value={modelStatus ? 'Loaded' : 'Unloaded'}
          color={modelStatus ? 'text-emerald-400' : 'text-slate-500'}
        />
        <div className="flex items-center gap-1.5 ml-auto">
          {bm25Status
            ? <Wifi className="w-3.5 h-3.5 text-emerald-400" />
            : <WifiOff className="w-3.5 h-3.5 text-amber-400" />
          }
          <span className={`text-xs ${bm25Status ? 'text-emerald-400' : 'text-amber-400'}`}>
            {stats.collection_status === 'green' ? 'Collection healthy' : stats.collection_status}
          </span>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Result Card
// ─────────────────────────────────────────────────────────────────────────────

function ResultCard({ result, index }) {
  const [expanded, setExpanded] = useState(false)
  const src = getSourceCfg(result.source_type)
  const sev = getSeverityCfg(result.severity)
  const SrcIcon = src.icon
  const scorePercent = Math.round((result.rrf_score || 0) * 6000)

  return (
    <article
      className={`glass-card overflow-hidden transition-all duration-200
                  hover:border-white/15 border border-white/[0.06]
                  ${expanded ? 'ring-1 ring-cyan-500/20' : ''}`}
      aria-label={`Knowledge result ${index + 1}`}
    >
      {/* ── Card header ─────────────────────────────────────── */}
      <div
        className="p-4 cursor-pointer select-none"
        onClick={() => setExpanded(e => !e)}
        role="button"
        tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && setExpanded(v => !v)}
        aria-expanded={expanded}
      >
        <div className="flex items-start gap-3">
          {/* Rank badge */}
          <div className="flex-shrink-0 w-7 h-7 rounded-lg bg-white/5 border border-white/10
                          flex items-center justify-center text-xs font-bold text-slate-500">
            {index + 1}
          </div>

          {/* Source icon */}
          <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${src.bg}`}>
            <SrcIcon className={`w-4 h-4 ${src.color}`} />
          </div>

          {/* Content preview */}
          <div className="flex-1 min-w-0 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              {/* Source type */}
              <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${src.bg} ${src.color}`}>
                {src.label}
              </span>

              {/* Technique ID */}
              {result.technique_id && (
                <span className="text-xs font-mono px-1.5 py-0.5 rounded
                                 bg-red-500/10 text-red-400 border border-red-500/20">
                  {result.technique_id}
                </span>
              )}

              {/* CVE ID */}
              {result.cve_id && (
                <span className="text-xs font-mono px-1.5 py-0.5 rounded
                                 bg-orange-500/10 text-orange-400 border border-orange-500/20">
                  {result.cve_id}
                </span>
              )}

              {/* Severity */}
              {result.severity && (
                <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${sev.bg} ${sev.text}`}>
                  {sev.label}
                </span>
              )}

              {/* RRF score */}
              <span className="ml-auto text-xs text-slate-600 flex items-center gap-1">
                <BarChart2 className="w-3 h-3" />
                {scorePercent > 0 ? `score ${scorePercent}` : `rrf ${result.rrf_score?.toFixed(5)}`}
              </span>
            </div>

            {/* Text preview (truncated) */}
            <p className="text-sm text-slate-300 leading-relaxed line-clamp-2">
              {result.text}
            </p>

            {/* Chunk position */}
            <p className="text-xs text-slate-600">
              Chunk {result.chunk_index + 1}/{result.total_chunks} ·{' '}
              <span className="text-slate-700 font-mono text-[10px] truncate max-w-xs inline-block align-bottom">
                {result.source_path?.split('/').slice(-2).join('/')}
              </span>
            </p>
          </div>

          {/* Expand toggle */}
          <div className="flex-shrink-0 text-slate-600 mt-1">
            {expanded
              ? <ChevronUp className="w-4 h-4" />
              : <ChevronDown className="w-4 h-4" />
            }
          </div>
        </div>
      </div>

      {/* ── Expanded content ────────────────────────────────── */}
      {expanded && (
        <div className="px-4 pb-4 pt-0 border-t border-white/5 space-y-3 animate-fade-in">
          {/* Full text */}
          <div className="relative group">
            <pre className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed
                            bg-black/20 rounded-lg p-3 font-sans border border-white/5
                            max-h-64 overflow-y-auto scrollbar-thin">
              {result.text}
            </pre>
            <CopyBtn
              value={result.text}
              className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity"
            />
          </div>

          {/* Metadata grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
            {result.doc_hash && (
              <div className="flex items-center gap-1.5 bg-white/3 rounded-lg px-2.5 py-1.5">
                <span className="text-slate-600">hash</span>
                <span className="font-mono text-slate-500 truncate">{result.doc_hash.slice(0, 12)}…</span>
                <CopyBtn value={result.doc_hash} />
              </div>
            )}
            {result.source_url && (
              <a
                href={result.source_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 bg-white/3 rounded-lg px-2.5 py-1.5
                           text-cyan-400 hover:text-cyan-300 col-span-2 sm:col-span-3 truncate"
              >
                <Info className="w-3 h-3 flex-shrink-0" />
                {result.source_url}
              </a>
            )}
          </div>
        </div>
      )}
    </article>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Source filter chips
// ─────────────────────────────────────────────────────────────────────────────

function SourceChips({ selected, onChange }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {SOURCE_FILTERS.map(t => {
        const cfg = t ? getSourceCfg(t) : null
        const active = selected === t
        return (
          <button
            key={t || 'all'}
            id={`knowledge-source-${t || 'all'}`}
            onClick={() => onChange(t)}
            className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all
                        ${active
                          ? `${cfg?.bg || 'bg-white/10'} ${cfg?.color || 'text-slate-200'} border ${cfg?.border || 'border-white/20'}`
                          : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'}`}
          >
            {t ? (cfg?.label || t) : 'All Sources'}
          </button>
        )
      })}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Ingest Panel
// ─────────────────────────────────────────────────────────────────────────────

function AdminPanel({ onRebuild, rebuilding }) {
  return (
    <div className="glass-card p-4 border border-amber-500/20">
      <div className="flex items-center gap-2 mb-3">
        <Shield className="w-4 h-4 text-amber-400" />
        <span className="text-sm font-semibold text-amber-400">Admin Controls</span>
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          id="rebuild-bm25-btn"
          onClick={onRebuild}
          disabled={rebuilding}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                     bg-amber-500/10 text-amber-400 border border-amber-500/20
                     hover:bg-amber-500/20 disabled:opacity-50 disabled:cursor-not-allowed
                     transition-all"
        >
          {rebuilding
            ? <><div className="w-3 h-3 border border-amber-400/40 border-t-amber-400 rounded-full animate-spin" /> Rebuilding…</>
            : <><RefreshCw className="w-3 h-3" /> Rebuild BM25 Index</>
          }
        </button>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────

export default function KnowledgeSearchPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  // Search state
  const [query, setQuery] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [topK, setTopK] = useState(10)
  const [results, setResults] = useState([])
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState(null)
  const [searchMeta, setSearchMeta] = useState(null)   // { total, duration_ms, bm25_available }
  const [hasSearched, setHasSearched] = useState(false)

  // Stats state
  const [stats, setStats] = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [statsError, setStatsError] = useState(null)

  // Admin state
  const [rebuilding, setRebuilding] = useState(false)
  const [rebuildMsg, setRebuildMsg] = useState(null)

  const inputRef = useRef(null)

  // ── Load stats on mount ────────────────────────────────────────────────────
  useEffect(() => {
    setStatsLoading(true)
    knowledgeAPI.getStats()
      .then(({ data }) => setStats(data))
      .catch(err => setStatsError(err.response?.data?.detail || 'Could not load stats'))
      .finally(() => setStatsLoading(false))
  }, [])

  // ── Search ─────────────────────────────────────────────────────────────────
  const handleSearch = useCallback(async (overrideQuery) => {
    const q = (overrideQuery ?? query).trim()
    if (!q) return

    setSearching(true)
    setSearchError(null)
    setHasSearched(true)

    try {
      const payload = {
        query: q,
        top_k: topK,
        ...(sourceFilter && { source_type: sourceFilter }),
      }
      const { data } = await knowledgeAPI.search(payload)
      setResults(data.results || [])
      setSearchMeta({
        total: data.total_results,
        duration_ms: data.duration_ms,
        bm25_available: data.bm25_available,
      })
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Search failed'
      setSearchError(msg)
      setResults([])
      setSearchMeta(null)
    } finally {
      setSearching(false)
    }
  }, [query, topK, sourceFilter])

  function handleKeyDown(e) {
    if (e.key === 'Enter') handleSearch()
  }

  function handleExampleClick(q) {
    setQuery(q)
    handleSearch(q)
  }

  function clearSearch() {
    setQuery('')
    setResults([])
    setSearchMeta(null)
    setSearchError(null)
    setHasSearched(false)
    inputRef.current?.focus()
  }

  // ── BM25 Rebuild ───────────────────────────────────────────────────────────
  async function handleRebuild() {
    setRebuilding(true)
    setRebuildMsg(null)
    try {
      const { data } = await knowledgeAPI.rebuildIndex()
      setRebuildMsg({ ok: true, text: data.message })
      // Refresh stats
      knowledgeAPI.getStats().then(({ data }) => setStats(data)).catch(() => {})
    } catch (err) {
      setRebuildMsg({ ok: false, text: err.response?.data?.detail || 'Rebuild failed' })
    } finally {
      setRebuilding(false)
      setTimeout(() => setRebuildMsg(null), 5000)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto space-y-5">

        {/* ── Page header ───────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600
                            flex items-center justify-center shadow-lg shadow-cyan-500/25">
              <BookOpen className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-100">Knowledge Intelligence</h1>
              <p className="text-xs text-slate-500">
                Hybrid semantic + BM25 search over MITRE, NVD, OWASP, SIGMA &amp; CISA
              </p>
            </div>
          </div>
        </div>

        {/* ── Stats bar ──────────────────────────────────────────────────── */}
        <StatsPanel stats={stats} loading={statsLoading} error={statsError} />

        {/* ── Search box ─────────────────────────────────────────────────── */}
        <div className="glass-card p-4 space-y-3">
          {/* Input row */}
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                ref={inputRef}
                id="knowledge-search-input"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search for threats, techniques, CVEs, playbooks…"
                className="w-full pl-10 pr-10 py-3 rounded-xl bg-white/5 border border-white/10
                           text-sm text-slate-200 placeholder-slate-600
                           focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20
                           transition-all"
                autoComplete="off"
                spellCheck="false"
              />
              {query && (
                <button
                  onClick={clearSearch}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>

            {/* Top-K selector */}
            <select
              id="knowledge-top-k"
              value={topK}
              onChange={e => setTopK(Number(e.target.value))}
              className="px-3 py-3 rounded-xl bg-white/5 border border-white/10 text-sm text-slate-300
                         focus:outline-none focus:border-cyan-500/50 transition-colors cursor-pointer"
            >
              {[5, 10, 20, 50].map(k => (
                <option key={k} value={k} className="bg-slate-900">{k} results</option>
              ))}
            </select>

            {/* Search button */}
            <button
              id="knowledge-search-btn"
              onClick={() => handleSearch()}
              disabled={searching || !query.trim()}
              className="px-5 py-3 rounded-xl text-sm font-semibold
                         bg-gradient-to-r from-cyan-600 to-blue-600
                         hover:from-cyan-500 hover:to-blue-500
                         disabled:opacity-40 disabled:cursor-not-allowed
                         text-white shadow-lg shadow-cyan-500/20
                         transition-all flex items-center gap-2"
            >
              {searching
                ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Searching…</>
                : <><Search className="w-4 h-4" /> Search</>
              }
            </button>
          </div>

          {/* Source filter chips */}
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
            <SourceChips selected={sourceFilter} onChange={setSourceFilter} />
          </div>
        </div>

        {/* ── Example queries (shown before first search) ──────────────── */}
        {!hasSearched && (
          <div className="space-y-2">
            <p className="text-xs text-slate-600 px-1">Example queries</p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLE_QUERIES.map(q => (
                <button
                  key={q}
                  onClick={() => handleExampleClick(q)}
                  className="text-xs px-3 py-1.5 rounded-lg bg-white/4 border border-white/8
                             text-slate-400 hover:text-slate-200 hover:bg-white/8 hover:border-white/15
                             transition-all"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ── Search error ───────────────────────────────────────────────── */}
        {searchError && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-red-400">Search failed</p>
              <p className="text-xs text-red-400/70 mt-0.5">{searchError}</p>
            </div>
          </div>
        )}

        {/* ── Results ────────────────────────────────────────────────────── */}
        {hasSearched && !searching && !searchError && (
          <>
            {/* Results meta bar */}
            {searchMeta && (
              <div className="flex items-center justify-between text-xs text-slate-500 px-1">
                <span>
                  {searchMeta.total === 0
                    ? 'No results found'
                    : `${searchMeta.total} result${searchMeta.total !== 1 ? 's' : ''}`}
                </span>
                <div className="flex items-center gap-3">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {searchMeta.duration_ms?.toFixed(0)}ms
                  </span>
                  <span className={`flex items-center gap-1 ${searchMeta.bm25_available ? 'text-emerald-500' : 'text-amber-500'}`}>
                    {searchMeta.bm25_available
                      ? <><Zap className="w-3 h-3" /> Dense + BM25</>
                      : <><Cpu className="w-3 h-3" /> Dense only</>
                    }
                  </span>
                </div>
              </div>
            )}

            {/* No results state */}
            {results.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 gap-4">
                <div className="w-14 h-14 rounded-2xl bg-slate-800/60 flex items-center justify-center">
                  <BookOpen className="w-6 h-6 text-slate-600" />
                </div>
                <div className="text-center space-y-1">
                  <p className="text-sm font-medium text-slate-400">No knowledge chunks matched</p>
                  <p className="text-xs text-slate-600 max-w-xs">
                    Try broadening your query, removing the source filter, or ingest more documents first.
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                {results.map((result, i) => (
                  <ResultCard key={result.node_id || i} result={result} index={i} />
                ))}
              </div>
            )}
          </>
        )}

        {/* Loading skeleton */}
        {searching && (
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="glass-card p-4 animate-pulse">
                <div className="flex items-start gap-3">
                  <div className="w-7 h-7 rounded-lg bg-white/5" />
                  <div className="w-8 h-8 rounded-lg bg-white/5" />
                  <div className="flex-1 space-y-2">
                    <div className="flex gap-2">
                      <div className="h-5 w-20 rounded bg-white/5" />
                      <div className="h-5 w-16 rounded bg-white/5" />
                    </div>
                    <div className="h-4 w-full rounded bg-white/5" />
                    <div className="h-4 w-3/4 rounded bg-white/5" />
                    <div className="h-3 w-1/2 rounded bg-white/4" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Admin panel ──────────────────────────────────────────────── */}
        {isAdmin && (
          <div className="pt-2 space-y-2">
            <AdminPanel onRebuild={handleRebuild} rebuilding={rebuilding} />
            {rebuildMsg && (
              <div className={`text-xs px-3 py-2 rounded-lg border
                ${rebuildMsg.ok
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                {rebuildMsg.text}
              </div>
            )}
          </div>
        )}

      </div>
    </AppLayout>
  )
}
