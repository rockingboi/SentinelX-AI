import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Request interceptor — inject Bearer token ────────────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error),
)

// ── Response interceptor — handle 401 globally ───────────────────────────────
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
      // Redirect to login without importing router (avoid circular deps)
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)

export default api

// ── Named API functions ──────────────────────────────────────────────────────

export const authAPI = {
  register: (data) => api.post('/api/v1/auth/register', data),
  login: (data) => api.post('/api/v1/auth/login', data),
  me: () => api.get('/api/v1/auth/me'),
}

export const dashboardAPI = {
  getStatus: () => api.get('/api/v1/dashboard'),
}

export const healthAPI = {
  check: () => api.get('/health'),
}
