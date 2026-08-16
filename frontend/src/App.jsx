import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import ProtectedRoute from './components/ui/ProtectedRoute'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import SettingsPage from './pages/SettingsPage'
import StatusPage from './pages/StatusPage'
import NotFoundPage from './pages/NotFoundPage'

// Phase 2 — Log Analysis pages
import LogUploadPage from './pages/LogUploadPage'
import LogViewerPage from './pages/LogViewerPage'
import IOCExplorerPage from './pages/IOCExplorerPage'
import IncidentPage from './pages/IncidentPage'
import StatisticsPage from './pages/StatisticsPage'

// Phase 3 — Knowledge Intelligence
import KnowledgeSearchPage from './pages/KnowledgeSearchPage'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/login"    element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Phase 1 — Core */}
          <Route path="/dashboard" element={
            <ProtectedRoute><DashboardPage /></ProtectedRoute>
          } />
          <Route path="/status" element={
            <ProtectedRoute><StatusPage /></ProtectedRoute>
          } />
          <Route path="/settings" element={
            <ProtectedRoute><SettingsPage /></ProtectedRoute>
          } />

          {/* Phase 2 — Log Analysis */}
          <Route path="/logs/upload" element={
            <ProtectedRoute><LogUploadPage /></ProtectedRoute>
          } />
          <Route path="/logs/:id" element={
            <ProtectedRoute><LogViewerPage /></ProtectedRoute>
          } />
          <Route path="/iocs" element={
            <ProtectedRoute><IOCExplorerPage /></ProtectedRoute>
          } />
          <Route path="/incidents" element={
            <ProtectedRoute><IncidentPage /></ProtectedRoute>
          } />
          <Route path="/statistics" element={
            <ProtectedRoute><StatisticsPage /></ProtectedRoute>
          } />

          {/* Phase 3 — Knowledge Intelligence */}
          <Route path="/knowledge" element={
            <ProtectedRoute><KnowledgeSearchPage /></ProtectedRoute>
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
