import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Eye, EyeOff, Zap, Mail, User, Lock, AlertCircle, CheckCircle } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function RegisterPage() {
  const navigate = useNavigate()
  const { register, loading } = useAuth()

  const [form, setForm] = useState({
    email: '', username: '', password: '', full_name: '',
  })
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const update = (field) => (e) => setForm({ ...form, [field]: e.target.value })

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    const result = await register(form)
    if (result.success) {
      setSuccess(true)
      setTimeout(() => navigate('/login'), 2000)
    } else {
      setError(result.message)
    }
  }

  return (
    <div className="min-h-screen bg-sentinel-950 bg-grid-pattern flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 right-1/3 w-80 h-80 rounded-full bg-violet-500/5 blur-3xl" />
        <div className="absolute bottom-1/3 left-1/3 w-64 h-64 rounded-full bg-cyan-500/5 blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600
                          flex items-center justify-center shadow-lg shadow-cyan-500/30">
            <Zap className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold gradient-text">SentinelX AI</h1>
            <p className="text-xs text-slate-500">Cyber Investigation Platform</p>
          </div>
        </div>

        <div className="glass-card p-8">
          <div className="mb-6">
            <h2 className="text-xl font-semibold text-slate-100">Create account</h2>
            <p className="text-sm text-slate-500 mt-1">Join the SentinelX AI platform</p>
          </div>

          {success && (
            <div className="flex items-center gap-2 p-3 mb-5 rounded-lg
                            bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm">
              <CheckCircle className="w-4 h-4" />
              Account created! Redirecting to login…
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 p-3 mb-5 rounded-lg
                            bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="full_name" className="input-label">Full name <span className="text-slate-600">(optional)</span></label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input id="full_name" type="text" value={form.full_name} onChange={update('full_name')}
                       className="input-field pl-10" placeholder="John Doe" />
              </div>
            </div>

            <div>
              <label htmlFor="reg-email" className="input-label">Email address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input id="reg-email" type="email" required value={form.email} onChange={update('email')}
                       className="input-field pl-10" placeholder="analyst@company.com" />
              </div>
            </div>

            <div>
              <label htmlFor="username" className="input-label">Username</label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-sm font-mono">@</span>
                <input id="username" type="text" required minLength={3} maxLength={50}
                       pattern="[a-zA-Z0-9_\-]+"
                       value={form.username} onChange={update('username')}
                       className="input-field pl-8" placeholder="jdoe_analyst" />
              </div>
            </div>

            <div>
              <label htmlFor="reg-password" className="input-label">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input id="reg-password" type={showPassword ? 'text' : 'password'} required
                       minLength={8} value={form.password} onChange={update('password')}
                       className="input-field pl-10 pr-10" placeholder="Min 8 chars, uppercase, number, special" />
                <button type="button" onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs text-slate-600 mt-1">
                Must include uppercase, lowercase, number and special character
              </p>
            </div>

            <button type="submit" disabled={loading || success} className="btn-primary w-full mt-2">
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </span>
              ) : 'Create account'}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-6">
            Already have an account?{' '}
            <Link to="/login" className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
