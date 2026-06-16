import { Outlet } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import Sidebar from './Sidebar.jsx'
import { useWebSocket } from '../../hooks/useWebSocket.js'
import { useThreats } from '../../hooks/useThreats.js'

export default function CommandCenter() {
  // Initialize real-time connections
  useWebSocket()
  useThreats()

  return (
    <div className="flex h-screen overflow-hidden bg-cyber-black relative">
      {/* Scanline effect */}
      <div className="scanline" />

      {/* Sidebar */}
      <Sidebar />

      {/* Main content */}
      <main className="flex-1 overflow-hidden relative">
        {/* Top status bar */}
        <TopBar />

        {/* Page content */}
        <div className="h-[calc(100%-40px)] overflow-auto">
          <Outlet />
        </div>
      </main>

      <Toaster position="bottom-right" />
    </div>
  )
}

function TopBar() {
  const now = new Date()
  return (
    <div
      className="flex items-center justify-between px-4 h-10 border-b border-cyber-border/50 flex-shrink-0"
      style={{ background: 'rgba(5,8,18,0.9)', backdropFilter: 'blur(8px)' }}
    >
      {/* Left: breadcrumb */}
      <div className="flex items-center gap-1.5 text-[10px] font-mono text-gray-600">
        <span className="text-cyber-green/50">CTI</span>
        <span>›</span>
        <span className="text-gray-400">Command Center</span>
      </div>

      {/* Center: system label */}
      <div className="font-['Orbitron',sans-serif] text-[10px] text-cyber-green/30 tracking-widest uppercase hidden md:block">
        Cyber Threat Intelligence Platform v2.0
      </div>

      {/* Right: datetime */}
      <div className="text-[10px] font-mono text-gray-600 tabular-nums">
        {now.toISOString().replace('T', ' ').slice(0, 19)} UTC
      </div>
    </div>
  )
}
