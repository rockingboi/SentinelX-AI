/**
 * Log Analysis API — wraps all Phase 2 REST endpoints.
 * Matches the 10 routes registered in backend/routes/logs.py
 */
import api from './client'

// ── Log Upload & Management ─────────────────────────────────────────────────

export const logsAPI = {
  /**
   * Upload a raw log file for analysis.
   * POST /api/v1/logs/upload
   * @param {File} file  - The log file object
   * @param {string} [logType] - Optional forced log type (e.g. 'linux_syslog')
   * @param {string} [description] - Optional human description
   */
  upload: (file, logType = null, description = '') => {
    const form = new FormData()
    form.append('file', file)
    if (logType) form.append('force_log_type', logType)   // backend param name
    if (description) form.append('description', description)
    return api.post('/api/v1/logs/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120_000, // 2 min — large files
    })
  },

  /**
   * Trigger the NLP pipeline on an already-uploaded log.
   * POST /api/v1/logs/:id/parse
   */
  parse: (id, forceLogType = null) =>
    api.post(`/api/v1/logs/${id}/parse`, forceLogType ? { force_log_type: forceLogType } : {}),

  /**
   * List all logs with optional filters.
   * GET /api/v1/logs
   */
  list: (params = {}) => api.get('/api/v1/logs', { params }),

  /**
   * Get single log metadata + pipeline summary.
   * GET /api/v1/logs/:id
   */
  get: (id) => api.get(`/api/v1/logs/${id}`),

  /**
   * Delete a log and all its derived data.
   * DELETE /api/v1/logs/:id
   */
  delete: (id) => api.delete(`/api/v1/logs/${id}`),


  /**
   * Get all parsed events for a log.
   * GET /api/v1/logs/:id/events
   */
  getEvents: (id, params = {}) => api.get(`/api/v1/logs/${id}/events`, { params }),

  /**
   * Get all IOCs extracted from a log.
   * GET /api/v1/logs/:id/iocs
   */
  getIOCs: (id, params = {}) => api.get(`/api/v1/logs/${id}/iocs`, { params }),
}

// ── IOC Explorer ────────────────────────────────────────────────────────────

export const iocsAPI = {
  /**
   * Search IOCs across all logs.
   * GET /api/v1/iocs/search
   */
  search: (params = {}) => api.get('/api/v1/iocs/search', { params }),

  /**
   * Get a single IOC entity by ID.
   * GET /api/v1/iocs/:id
   */
  get: (id) => api.get(`/api/v1/iocs/${id}`),
}

// ── Incidents ───────────────────────────────────────────────────────────────

export const incidentsAPI = {
  /**
   * List all incident events with pagination + filters.
   * GET /api/v1/incidents
   */
  list: (params = {}) => api.get('/api/v1/incidents', { params }),

  /**
   * Update incident status (open → investigating → resolved → false_positive).
   * PATCH /api/v1/incidents/:id/status
   */
  updateStatus: (id, status) =>
    api.patch(`/api/v1/incidents/${id}/status`, { status }),
}

// ── Statistics ──────────────────────────────────────────────────────────────

export const statisticsAPI = {
  /**
   * Get aggregated platform-wide statistics.
   * GET /api/v1/statistics
   */
  get: (params = {}) => api.get('/api/v1/statistics', { params }),
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Severity badge colours — shared across all Phase 2 pages */
export const SEVERITY_CONFIG = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-500' },
  high:     { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', dot: 'bg-orange-500' },
  medium:   { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20', dot: 'bg-amber-500' },
  low:      { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', dot: 'bg-blue-500' },
  info:     { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20', dot: 'bg-slate-500' },
}

/** Status badge colours for log processing status */
export const STATUS_CONFIG = {
  pending:    { text: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20' },
  processing: { text: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/20' },
  completed:  { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
  failed:     { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
}

/** Human-readable log type labels */
export const LOG_TYPE_LABELS = {
  linux_syslog:   'Linux Syslog',
  windows_event:  'Windows Event',
  apache_access:  'Apache Access',
  nginx_access:   'Nginx Access',
  sysmon:         'Sysmon (XML)',
  unknown:        'Unknown',
}

/** Format bytes → human readable string */
export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

/** Format ISO date → short local string */
export function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}
