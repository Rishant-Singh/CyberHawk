import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import useThreatStore from './store/threatStore'
import Login from './components/auth/Login.jsx'
import CommandCenter from './components/layout/CommandCenter.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Alerts from './pages/Alerts.jsx'

function RequireAuth({ children }) {
  const isAuthenticated = useThreatStore((s) => s.isAuthenticated)
  return isAuthenticated ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: 'rgba(13,20,36,0.98)',
            border: '1px solid rgba(0,255,157,0.2)',
            color: '#e0e8ff',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '12px',
          },
        }}
      />
      <Routes>
        {/* Public */}
        <Route path="/login" element={<LoginOrRedirect />} />

        {/* Protected — wrapped in CommandCenter layout */}
        <Route
          path="/"
          element={
            <RequireAuth>
              <CommandCenter />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="alerts" element={<Alerts />} />
        </Route>

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

function LoginOrRedirect() {
  const isAuthenticated = useThreatStore((s) => s.isAuthenticated)
  return isAuthenticated ? <Navigate to="/" replace /> : <Login />
}
