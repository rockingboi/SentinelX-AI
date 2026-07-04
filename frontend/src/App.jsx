import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/ui/ProtectedRoute'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import SettingsPage from './pages/SettingsPage'
import StatusPage from './pages/StatusPage'
import NotFoundPage from './pages/NotFoundPage'
import AppLayout from './components/layout/AppLayout'
import { Shield } from 'lucide-react'

// Placeholder page for future phases
function ComingSoonPage({ title }) {
  return (
    <AppLayout>
      <div className="flex flex-col items-center justify-center h-96 text-center">
        <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20
                        flex items-center justify-center mb-6">
          <Shield className="w-8 h-8 text-cyan-400" />
        </div>
        <h1 className="text-xl font-bold text-slate-200 mb-2">{title}</h1>
        <p className="text-slate-500 text-sm max-w-sm">
          This module will be available in Phase 2 when AI agents are activated.
        </p>
        <div className="mt-4 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20
                        text-xs text-cyan-400">Phase 2 — Coming soon</div>
      </div>
    </AppLayout>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected routes */}
          <Route path="/dashboard" element={
            <ProtectedRoute><DashboardPage /></ProtectedRoute>
          } />
          <Route path="/status" element={
            <ProtectedRoute><StatusPage /></ProtectedRoute>
          } />
          <Route path="/settings" element={
            <ProtectedRoute><SettingsPage /></ProtectedRoute>
          } />

          {/* Placeholder routes for future phases */}
          <Route path="/investigations" element={
            <ProtectedRoute><ComingSoonPage title="Investigations" /></ProtectedRoute>
          } />
          <Route path="/threats" element={
            <ProtectedRoute><ComingSoonPage title="Threat Intelligence" /></ProtectedRoute>
          } />
          <Route path="/reports" element={
            <ProtectedRoute><ComingSoonPage title="Reports" /></ProtectedRoute>
          } />

          {/* Root redirect */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />

          {/* 404 */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
