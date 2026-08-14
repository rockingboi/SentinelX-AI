import { useState, useCallback, useRef } from 'react'
import {
  Upload, FileText, CheckCircle, XCircle, AlertTriangle,
  Loader2, ChevronDown, Info, Shield, Zap
} from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { logsAPI, LOG_TYPE_LABELS } from '../api/logs'

// ── Drag-and-drop zone ───────────────────────────────────────────────────────

function DropZone({ onFile, isDragging, setIsDragging }) {
  const inputRef = useRef(null)

  function handleDrop(e) {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) onFile(file)
  }

  function handleChange(e) {
    const file = e.target.files[0]
    if (file) onFile(file)
  }

  return (
    <div
      id="log-dropzone"
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      className={`relative flex flex-col items-center justify-center gap-4
                  border-2 border-dashed rounded-2xl p-12 cursor-pointer
                  transition-all duration-300 select-none
                  ${isDragging
                    ? 'border-cyan-400 bg-cyan-500/10 scale-[1.01]'
                    : 'border-white/10 bg-white/2 hover:border-white/20 hover:bg-white/5'}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".log,.txt,.xml,.evtx"
        className="hidden"
        onChange={handleChange}
        id="log-file-input"
      />

      <div className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all
                        ${isDragging ? 'bg-cyan-500/20 border-cyan-500/40' : 'bg-white/5 border-white/10'} border`}>
        <Upload className={`w-7 h-7 ${isDragging ? 'text-cyan-400' : 'text-slate-500'}`} />
      </div>

      <div className="text-center">
        <p className="text-sm font-semibold text-slate-200">
          {isDragging ? 'Drop your log file here' : 'Drag & drop a log file'}
        </p>
        <p className="text-xs text-slate-500 mt-1">or click to browse</p>
        <p className="text-xs text-slate-600 mt-2">Supports: .log, .txt, .xml, .evtx — max 100 MB</p>
      </div>
    </div>
  )
}

// ── File preview chip ────────────────────────────────────────────────────────

function FileBadge({ file, onRemove }) {
  const kb = (file.size / 1024).toFixed(1)
  const mb = (file.size / 1024 / 1024).toFixed(2)
  const size = file.size > 1024 * 1024 ? `${mb} MB` : `${kb} KB`

  return (
    <div className="flex items-center gap-3 p-3 rounded-xl bg-white/5 border border-white/10">
      <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center flex-shrink-0">
        <FileText className="w-4 h-4 text-cyan-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-slate-200 truncate">{file.name}</p>
        <p className="text-xs text-slate-500">{size}</p>
      </div>
      <button onClick={onRemove} className="text-slate-500 hover:text-red-400 transition-colors flex-shrink-0">
        <XCircle className="w-4 h-4" />
      </button>
    </div>
  )
}

// ── Upload progress bar ──────────────────────────────────────────────────────

function ProgressBar({ value }) {
  return (
    <div className="w-full h-1.5 rounded-full bg-white/10 overflow-hidden">
      <div
        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
        style={{ width: `${value}%` }}
      />
    </div>
  )
}

// ── Result panel ─────────────────────────────────────────────────────────────

function ResultPanel({ result, onReset }) {
  const raw = result.data?.data ?? result.data ?? {}
  // Parse response uses parsed_event_count / ioc_count
  // Upload response nests under pipeline_summary
  const summ = raw.pipeline_summary || {}
  const evCount   = raw.parsed_event_count ?? summ.parsed_events
  const iocCount  = raw.ioc_count          ?? summ.unique_iocs
  const threats   = summ.threats_detected  ?? raw.threat_count
  const critical  = summ.critical_events   ?? raw.critical_count
  const logId     = raw.log_id
  const logType   = raw.log_type
  const isError   = !!result.error

  return (
    <div id="upload-result" className={`rounded-2xl border p-6 space-y-4 animate-fade-in
                            ${isError
                              ? 'bg-red-500/5 border-red-500/20'
                              : 'bg-emerald-500/5 border-emerald-500/20'}`}>
      <div className="flex items-start gap-4">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0
                          ${isError ? 'bg-red-500/10' : 'bg-emerald-500/10'}`}>
          {isError
            ? <XCircle className="w-5 h-5 text-red-400" />
            : <CheckCircle className="w-5 h-5 text-emerald-400" />}
        </div>
        <div>
          <p className={`text-sm font-semibold ${isError ? 'text-red-400' : 'text-emerald-400'}`}>
            {isError ? 'Upload Failed' : 'Log Processed Successfully'}
          </p>
          <p className="text-xs text-slate-400 mt-0.5">
            {isError
              ? result.error
              : `Log ID: ${logId ?? '—'} · Type: ${logType ?? '—'}`}
          </p>
        </div>
      </div>

      {!isError && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Events Parsed',   value: evCount  ?? '—' },
            { label: 'Threats Found',   value: threats  ?? '—' },
            { label: 'Critical Events', value: critical ?? '—' },
            { label: 'Unique IOCs',     value: iocCount ?? '—' },
          ].map(({ label, value }) => (
            <div key={label} className="bg-white/5 rounded-xl p-3 text-center">
              <p className="text-lg font-bold text-slate-100">{value}</p>
              <p className="text-xs text-slate-500 mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      <button
        id="upload-reset-btn"
        onClick={onReset}
        className="w-full py-2 rounded-xl text-xs font-medium text-slate-400
                   border border-white/10 hover:bg-white/5 transition-colors"
      >
        Upload Another File
      </button>
    </div>
  )
}


// ── Main page ────────────────────────────────────────────────────────────────

const LOG_TYPES = [
  { value: '', label: 'Auto-detect (recommended)' },
  ...Object.entries(LOG_TYPE_LABELS)
    .filter(([k]) => k !== 'unknown')
    .map(([value, label]) => ({ value, label })),
]

export default function LogUploadPage() {
  const [file, setFile] = useState(null)
  const [logType, setLogType] = useState('')
  const [description, setDescription] = useState('')
  const [isDragging, setIsDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState(null)

  const handleFile = useCallback((f) => {
    setFile(f)
    setResult(null)
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!file) return

    setUploading(true)
    setProgress(0)
    setResult(null)

    // Animate progress while upload + pipeline runs
    const tick = setInterval(() => {
      setProgress(p => p < 85 ? p + Math.random() * 8 : p)
    }, 400)

    try {
      // Step 1: upload the file
      const uploadRes = await logsAPI.upload(file, logType || null, description)
      const logId = uploadRes.data?.log_id || uploadRes.data?.id
      setProgress(50)

      // Step 2: trigger NLP pipeline
      if (logId) {
        const parseRes = await logsAPI.parse(logId)
        setProgress(100)
        setResult({ data: parseRes.data })
      } else {
        setProgress(100)
        setResult({ data: uploadRes.data })
      }
    } catch (err) {
      setResult({ error: err.response?.data?.error?.message || err.message || 'Upload failed.' })
    } finally {
      clearInterval(tick)
      setUploading(false)
    }
  }

  function reset() {
    setFile(null)
    setLogType('')
    setDescription('')
    setProgress(0)
    setResult(null)
  }

  return (
    <AppLayout>
      <div className="max-w-2xl mx-auto space-y-6">

        {/* ── Header ──────────────────────────────────────────── */}
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600
                          flex items-center justify-center shadow-lg shadow-cyan-500/25 flex-shrink-0">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100">Log Analysis</h1>
            <p className="text-xs text-slate-500">Upload a log file to run the NLP security pipeline</p>
          </div>
        </div>

        {/* ── Info banner ──────────────────────────────────────── */}
        <div className="flex items-start gap-3 p-4 rounded-xl bg-blue-500/5 border border-blue-500/15">
          <Info className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
          <p className="text-xs text-slate-400 leading-relaxed">
            The pipeline auto-detects log type, extracts IOCs, classifies events with MITRE ATT&amp;CK,
            and persists results for investigation. Supported formats:
            <span className="text-slate-300 font-medium"> Linux Syslog, Windows Event, Apache/Nginx Access, Sysmon XML</span>.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">

          {/* ── Drop zone / file badge ───────────────────────── */}
          {result ? (
            <ResultPanel result={result} onReset={reset} />
          ) : file ? (
            <FileBadge file={file} onRemove={() => setFile(null)} />
          ) : (
            <DropZone
              onFile={handleFile}
              isDragging={isDragging}
              setIsDragging={setIsDragging}
            />
          )}

          {!result && (
            <>
              {/* ── Log type selector ───────────────────────── */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Log Type
                </label>
                <div className="relative">
                  <select
                    id="log-type-select"
                    value={logType}
                    onChange={(e) => setLogType(e.target.value)}
                    className="w-full appearance-none px-4 py-2.5 rounded-xl
                               bg-white/5 border border-white/10 text-sm text-slate-200
                               focus:outline-none focus:border-cyan-500/50 focus:bg-white/8
                               transition-colors pr-10"
                  >
                    {LOG_TYPES.map(({ value, label }) => (
                      <option key={value} value={value} className="bg-slate-900">{label}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
                </div>
              </div>

              {/* ── Description ─────────────────────────────── */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                  Description <span className="text-slate-600 normal-case">(optional)</span>
                </label>
                <input
                  id="log-description-input"
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. Production web server logs — July 2025"
                  className="w-full px-4 py-2.5 rounded-xl bg-white/5 border border-white/10
                             text-sm text-slate-200 placeholder-slate-600
                             focus:outline-none focus:border-cyan-500/50 focus:bg-white/8 transition-colors"
                />
              </div>

              {/* ── Progress + submit ────────────────────────── */}
              {uploading && (
                <div className="space-y-2">
                  <div className="flex justify-between text-xs text-slate-500">
                    <span className="flex items-center gap-1.5">
                      <Zap className="w-3 h-3 text-cyan-400" /> Running NLP pipeline…
                    </span>
                    <span>{Math.round(progress)}%</span>
                  </div>
                  <ProgressBar value={progress} />
                </div>
              )}

              <button
                id="log-upload-btn"
                type="submit"
                disabled={!file || uploading}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl
                           font-semibold text-sm transition-all duration-200
                           bg-gradient-to-r from-cyan-500 to-blue-600
                           hover:from-cyan-400 hover:to-blue-500
                           shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40
                           disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
              >
                {uploading
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Processing…</>
                  : <><Upload className="w-4 h-4" /> Analyse Log File</>}
              </button>
            </>
          )}
        </form>
      </div>
    </AppLayout>
  )
}
