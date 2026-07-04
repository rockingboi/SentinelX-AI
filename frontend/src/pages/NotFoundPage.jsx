import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Zap, Home, ArrowLeft } from 'lucide-react'

export default function NotFoundPage() {
  const { isAuthenticated } = useAuth()

  return (
    <div className="min-h-screen bg-sentinel-950 bg-grid-pattern
                    flex flex-col items-center justify-center p-4 text-center">
      {/* Glowing orb */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2
                        w-96 h-96 rounded-full bg-cyan-500/5 blur-3xl" />
      </div>

      <div className="relative animate-slide-up">
        {/* Icon */}
        <div className="flex justify-center mb-6">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20
                          border border-cyan-500/30 flex items-center justify-center
                          shadow-2xl shadow-cyan-500/10">
            <Zap className="w-8 h-8 text-cyan-400" />
          </div>
        </div>

        <h1 className="text-8xl font-black gradient-text mb-4 leading-none">404</h1>
        <h2 className="text-xl font-semibold text-slate-200 mb-2">Page Not Found</h2>
        <p className="text-slate-500 text-sm max-w-sm mb-8">
          The page you&apos;re looking for doesn&apos;t exist or has been moved.
          The SentinelX AI platform couldn&apos;t locate this resource.
        </p>

        <div className="flex items-center justify-center gap-3">
          <Link
            to={isAuthenticated ? '/dashboard' : '/login'}
            className="btn-primary"
          >
            <Home className="w-4 h-4" />
            {isAuthenticated ? 'Go to Dashboard' : 'Go to Login'}
          </Link>
          <button
            onClick={() => window.history.back()}
            className="btn-secondary"
          >
            <ArrowLeft className="w-4 h-4" />
            Go back
          </button>
        </div>
      </div>
    </div>
  )
}
