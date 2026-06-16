import { NavLink } from 'react-router-dom'
import useThreatStore from '../../store/threatStore'

const navItems = [
  {
    to: '/',
    id: 'nav-dashboard',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
    label: 'Dashboard',
    exact: true,
  },
  {
    to: '/alerts',
    id: 'nav-alerts',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),
    label: 'Alerts',
  },
]

export default function Sidebar() {
  const { isAuthenticated, logout, wsConnected, criticalCount, highCount, user } = useThreatStore()

  return (
    <aside
      id="sidebar"
      className="flex flex-col h-full w-16 hover:w-56 group transition-all duration-300 ease-in-out overflow-hidden"
      style={{
        background: 'linear-gradient(180deg, rgba(8,12,24,0.98) 0%, rgba(5,8,18,0.98) 100%)',
        borderRight: '1px solid rgba(0,255,157,0.12)',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-3.5 py-5 border-b border-cyber-border/50">
        <div className="flex-shrink-0">
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
            <polygon
              points="16,2 30,10 30,22 16,30 2,22 2,10"
              stroke="rgba(0,255,157,0.8)" strokeWidth="1.5" fill="rgba(0,255,157,0.08)"
            />
            <circle cx="16" cy="16" r="3.5" fill="#00ff9d" />
            <circle cx="16" cy="16" r="6" stroke="#00ff9d" strokeWidth="0.7" fill="none" opacity="0.4" />
          </svg>
        </div>
        <div className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap overflow-hidden">
          <div className="text-cyber-green font-['Orbitron',sans-serif] font-bold text-xs tracking-widest uppercase">
            CTI Platform
          </div>
          <div className="text-gray-600 text-[10px] font-mono mt-0.5">Command Center</div>
        </div>
      </div>

      {/* Connection status */}
      <div className="px-3.5 py-3 border-b border-cyber-border/30">
        <div className="flex items-center gap-2.5">
          <span className={`pulse-dot w-2 h-2 ${wsConnected ? 'pulse-dot-green' : 'pulse-dot-red'}`} />
          <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 text-[10px] font-mono whitespace-nowrap">
            {wsConnected
              ? <span className="text-cyber-green">LIVE FEED ACTIVE</span>
              : <span className="text-cyber-red">STREAM OFFLINE</span>
            }
          </span>
        </div>
      </div>

      {/* Threat summary badges */}
      {(criticalCount > 0 || highCount > 0) && (
        <div className="px-3.5 py-3 border-b border-cyber-border/30 space-y-1.5">
          {criticalCount > 0 && (
            <div className="flex items-center gap-2.5">
              <span className="flex-shrink-0 w-5 h-5 rounded flex items-center justify-center text-[9px] font-bold"
                style={{ background: 'rgba(255,45,85,0.2)', color: '#ff2d55', border: '1px solid rgba(255,45,85,0.4)' }}>
                {criticalCount > 99 ? '99+' : criticalCount}
              </span>
              <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 text-[10px] font-mono text-cyber-red whitespace-nowrap">
                CRITICAL
              </span>
            </div>
          )}
          {highCount > 0 && (
            <div className="flex items-center gap-2.5">
              <span className="flex-shrink-0 w-5 h-5 rounded flex items-center justify-center text-[9px] font-bold"
                style={{ background: 'rgba(255,107,53,0.2)', color: '#ff6b35', border: '1px solid rgba(255,107,53,0.4)' }}>
                {highCount > 99 ? '99+' : highCount}
              </span>
              <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 text-[10px] font-mono text-orange-400 whitespace-nowrap">
                HIGH
              </span>
            </div>
          )}
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 py-3 space-y-1 px-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            id={item.id}
            end={item.exact}
            className={({ isActive }) =>
              `flex items-center gap-3 px-2.5 py-2.5 rounded transition-all duration-150 group/link ${
                isActive
                  ? 'text-cyber-green bg-cyber-green/10 border border-cyber-green/30'
                  : 'text-gray-500 hover:text-cyber-green hover:bg-cyber-green/5 border border-transparent'
              }`
            }
          >
            <span className="flex-shrink-0">{item.icon}</span>
            <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 text-xs font-mono uppercase tracking-wider whitespace-nowrap overflow-hidden">
              {item.label}
            </span>
          </NavLink>
        ))}
      </nav>

      {/* User / Logout */}
      <div className="border-t border-cyber-border/50 px-2 py-3">
        {user && (
          <div className="flex items-center gap-3 px-2.5 py-2 mb-1">
            <div className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold"
              style={{ background: 'rgba(0,255,157,0.15)', color: '#00ff9d', border: '1px solid rgba(0,255,157,0.3)' }}>
              {(user.username || 'U')[0].toUpperCase()}
            </div>
            <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 text-[10px] font-mono text-gray-400 whitespace-nowrap truncate">
              {user.username}
            </span>
          </div>
        )}

        <button
          id="sidebar-logout"
          onClick={logout}
          className="flex items-center gap-3 w-full px-2.5 py-2 rounded text-gray-600 hover:text-cyber-red hover:bg-cyber-red/5 transition-all duration-150"
          title="Logout"
        >
          <span className="flex-shrink-0">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
          </span>
          <span className="opacity-0 group-hover:opacity-100 transition-opacity duration-200 text-xs font-mono uppercase tracking-wider whitespace-nowrap">
            Terminate
          </span>
        </button>
      </div>
    </aside>
  )
}
