import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import AppLayout from '../components/layout/AppLayout'
import { Activity, Database, Cpu, Network, Zap, Shield } from 'lucide-react'
import { StatusCard } from '../components/ui/Cards'
import { useState, useEffect, useCallback } from 'react'
import { healthAPI } from '../api/client'

export default function StatusPage() {
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetch = useCallback(async () => {
    try {
      const { data } = await healthAPI.check()
      setHealth(data)
    } catch {
      setHealth(null)
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { fetch() }, [fetch])

  const services = health?.services ?? {}

  return (
    <AppLayout onRefresh={fetch}>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
          <Activity className="w-6 h-6 text-cyan-400" />
          System Status
        </h1>
        <p className="text-sm text-slate-500 mt-1">Real-time infrastructure health monitoring</p>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 animate-pulse">
          {[...Array(6)].map((_, i) => <div key={i} className="glass-card h-24" />)}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {Object.entries(services).map(([name, svc]) => {
            const icons = { postgres: Database, redis: Zap, neo4j: Network, qdrant: Cpu }
            return (
              <StatusCard key={name} name={name.charAt(0).toUpperCase() + name.slice(1)}
                status={svc.status} message={svc.message} version={svc.version}
                icon={icons[name]} />
            )
          })}
          <StatusCard name="Backend API" status="healthy" message="FastAPI operational"
            version={health?.version} icon={Shield} />
        </div>
      )}
    </AppLayout>
  )
}
