import { useState } from 'react'
import axios from 'axios'
import { toast } from 'react-hot-toast'
import useThreatStore from '../../store/threatStore'

const API_BASE = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:8000'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const setAuth = useThreatStore((s) => s.setAuth)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!username || !password) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('username', username)
      form.append('password', password)
      const res = await axios.post(`${API_BASE}/api/auth/login`, form, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      })
      const { access_token, user } = res.data
      setAuth(user || { username }, access_token)
      toast.success('ACCESS GRANTED', { style: toastStyle('#00ff9d') })
    } catch (err) {
      const msg = err?.response?.data?.detail || 'Authentication failed'
      toast.error(msg, { style: toastStyle('#ff2d55') })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-bg min-h-screen flex items-center justify-center relative overflow-hidden">
      {/* Scanline */}
      <div className="scanline" />

      {/* Animated grid background */}
      <div className="absolute inset-0 pointer-events-none">
        {[...Array(8)].map((_, i) => (
          <div
            key={i}
            className="absolute w-px bg-gradient-to-b from-transparent via-cyber-green/10 to-transparent"
            style={{
              left: `${(i + 1) * 12.5}%`,
              top: 0,
              bottom: 0,
              animationDelay: `${i * 0.3}s`,
            }}
          />
        ))}
      </div>

      {/* Glowing orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(0,255,157,0.04) 0%, transparent 70%)' }} />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(0,212,255,0.04) 0%, transparent 70%)' }} />

      {/* Login card */}
      <div className="cyber-panel cyber-corners w-full max-w-sm mx-4 p-8 z-10">

        {/* Logo / Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="relative">
              <svg width="56" height="56" viewBox="0 0 56 56" fill="none">
                <polygon points="28,4 52,18 52,38 28,52 4,38 4,18"
                  stroke="rgba(0,255,157,0.6)" strokeWidth="1.5" fill="rgba(0,255,157,0.06)" />
                <polygon points="28,14 44,23 44,33 28,42 12,33 12,23"
                  stroke="rgba(0,255,157,0.4)" strokeWidth="1" fill="none" />
                <circle cx="28" cy="28" r="5" fill="#00ff9d" opacity="0.9" />
                <circle cx="28" cy="28" r="9" stroke="#00ff9d" strokeWidth="0.8" fill="none" opacity="0.4" />
              </svg>
              <div className="absolute inset-0 rounded-full animate-ping"
                style={{ background: 'rgba(0,255,157,0.08)', animationDuration: '3s' }} />
            </div>
          </div>
          <h1 className="text-glow-green font-['Orbitron',sans-serif] font-bold text-xl tracking-widest uppercase">
            CTI Command
          </h1>
          <p className="text-gray-500 text-xs mt-1 tracking-widest uppercase font-mono">
            Cyber Threat Intelligence Platform
          </p>
        </div>

        {/* Divider */}
        <div className="border-t border-cyber-border mb-6 relative">
          <span className="absolute -top-2.5 left-1/2 -translate-x-1/2 bg-cyber-panel px-3 text-cyber-green/50 text-xs font-mono">
            AUTHENTICATE
          </span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-cyber-green/70 text-xs font-mono uppercase tracking-wider mb-1.5">
              Username
            </label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="operator_id"
              className="cyber-input"
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="block text-cyber-green/70 text-xs font-mono uppercase tracking-wider mb-1.5">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="cyber-input"
              autoComplete="current-password"
              required
            />
          </div>

          <button
            id="login-submit"
            type="submit"
            disabled={loading}
            className="cyber-btn-green w-full mt-2 flex items-center justify-center gap-2 h-10"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 border-2 border-cyber-black border-t-transparent rounded-full animate-spin" />
                AUTHENTICATING...
              </>
            ) : (
              '▶  INITIALIZE SESSION'
            )}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600 text-xs font-mono">
            Unauthorized access is monitored and prosecuted
          </p>
          <div className="flex items-center justify-center gap-2 mt-3">
            <span className="pulse-dot pulse-dot-green w-1.5 h-1.5" />
            <span className="text-cyber-green/50 text-xs font-mono">SYSTEM ONLINE</span>
          </div>
        </div>
      </div>
    </div>
  )
}

const toastStyle = (color) => ({
  background: 'rgba(13, 20, 36, 0.98)',
  border: `1px solid ${color}40`,
  color: color,
  fontFamily: 'JetBrains Mono, monospace',
  fontSize: '13px',
})
