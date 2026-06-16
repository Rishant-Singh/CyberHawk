import { useEffect, useRef } from 'react'
import { formatDistanceToNow } from 'date-fns'
import useThreatStore from '../../store/threatStore'

const LEVEL_CONFIG = {
  CRITICAL: { color: '#ff2d55', bg: 'rgba(255,45,85,0.1)', border: 'rgba(255,45,85,0.4)', label: 'CRIT' },
  HIGH:     { color: '#ff6b35', bg: 'rgba(255,107,53,0.1)', border: 'rgba(255,107,53,0.4)', label: 'HIGH' },
  MEDIUM:   { color: '#ffaa00', bg: 'rgba(255,170,0,0.1)', border: 'rgba(255,170,0,0.4)', label: 'MED' },
  LOW:      { color: '#00d4ff', bg: 'rgba(0,212,255,0.08)', border: 'rgba(0,212,255,0.3)', label: 'LOW' },
  INFO:     { color: '#00ff9d', bg: 'rgba(0,255,157,0.05)', border: 'rgba(0,255,157,0.2)', label: 'INFO' },
}

const MAX_DISPLAY = 60

export default function AttackTimeline({ className = '' }) {
  const { liveThreats, setSelectedAlert } = useThreatStore()
  const listRef = useRef(null)
  const prevCountRef = useRef(0)

  // Auto-scroll on new threat
  useEffect(() => {
    if (liveThreats.length > prevCountRef.current && listRef.current) {
      listRef.current.scrollTop = 0
    }
    prevCountRef.current = liveThreats.length
  }, [liveThreats.length])

  const items = liveThreats.slice(0, MAX_DISPLAY)

  if (items.length === 0) {
    return (
      <div className={`flex flex-col items-center justify-center h-full gap-3 ${className}`}>
        <div className="relative">
          <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
            <circle cx="20" cy="20" r="18" stroke="rgba(0,255,157,0.2)" strokeWidth="1" strokeDasharray="4 3" />
            <circle cx="20" cy="20" r="3" fill="rgba(0,255,157,0.3)" />
          </svg>
          <div className="absolute inset-0 rounded-full animate-ping"
            style={{ border: '1px solid rgba(0,255,157,0.15)', animationDuration: '3s' }} />
        </div>
        <p className="text-gray-600 text-xs font-mono text-center">
          AWAITING THREAT EVENTS<br />
          <span className="text-cyber-green/30">WebSocket stream initializing...</span>
        </p>
      </div>
    )
  }

  return (
    <div ref={listRef} className={`overflow-y-auto space-y-1 pr-1 ${className}`}>
      {items.map((threat, i) => {
        const cfg = LEVEL_CONFIG[threat.threat_level] || LEVEL_CONFIG.INFO
        const isNew = i < 3 && liveThreats.length > prevCountRef.current - 3

        return (
          <button
            key={threat.id || `${threat.src_ip}-${threat.timestamp}-${i}`}
            onClick={() => setSelectedAlert(threat)}
            className={`w-full text-left flex items-start gap-2.5 p-2.5 rounded transition-all duration-150 hover:brightness-110 ${
              isNew ? 'alert-item-enter' : ''
            }`}
            style={{
              background: cfg.bg,
              border: `1px solid ${cfg.border}`,
            }}
          >
            {/* Level badge */}
            <span
              className="flex-shrink-0 text-[9px] font-bold font-['Orbitron',sans-serif] px-1.5 py-0.5 rounded mt-0.5"
              style={{ color: cfg.color, background: `${cfg.color}20`, border: `1px solid ${cfg.border}` }}
            >
              {cfg.label}
            </span>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2 mb-0.5">
                <span className="text-xs font-mono truncate" style={{ color: cfg.color }}>
                  {threat.attack_type || threat.alert_type || 'UNKNOWN_ATTACK'}
                </span>
                <span className="text-[9px] font-mono text-gray-600 flex-shrink-0">
                  {threat.timestamp
                    ? formatDistanceToNow(new Date(threat.timestamp), { addSuffix: true })
                    : 'just now'}
                </span>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-mono text-gray-500">
                <span className="truncate">
                  {threat.src_ip || '???'} → {threat.dst_ip || '???'}
                </span>
                {threat.threat_score != null && (
                  <span className="flex-shrink-0 font-bold" style={{ color: cfg.color }}>
                    {Math.round(threat.threat_score)}
                  </span>
                )}
              </div>
              {threat.mitre_technique && (
                <div className="text-[9px] font-mono text-gray-600 mt-0.5">
                  ⚑ {threat.mitre_technique}
                </div>
              )}
            </div>

            {/* Score bar */}
            <div className="flex-shrink-0 flex flex-col items-center justify-center">
              <div className="w-1 rounded-full overflow-hidden"
                style={{ height: '36px', background: 'rgba(255,255,255,0.06)' }}>
                <div
                  className="w-full rounded-full transition-all duration-500"
                  style={{
                    height: `${(threat.threat_score || 0)}%`,
                    background: cfg.color,
                    boxShadow: `0 0 4px ${cfg.color}80`,
                    marginTop: 'auto',
                  }}
                />
              </div>
            </div>
          </button>
        )
      })}
    </div>
  )
}
