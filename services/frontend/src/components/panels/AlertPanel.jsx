import { useEffect, useRef, useState } from 'react'
import useThreatStore from '../../store/threatStore'
import axios from 'axios'
import { format } from 'date-fns'

const API_BASE = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:8000'

const LEVEL_COLOR = {
  CRITICAL: '#ff2d55', HIGH: '#ff6b35', MEDIUM: '#ffaa00', LOW: '#00d4ff', INFO: '#00ff9d',
}

export default function AlertPanel({ className = '' }) {
  const { selectedAlert, setSelectedAlert, accessToken } = useThreatStore()
  const [mitreDetail, setMitreDetail] = useState(null)
  const panelRef = useRef(null)

  // Fetch MITRE detail when alert changes
  useEffect(() => {
    setMitreDetail(null)
    if (!selectedAlert?.mitre_technique_id || !accessToken) return
    axios.get(`${API_BASE}/api/mitre/${selectedAlert.mitre_technique_id}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    }).then(r => setMitreDetail(r.data)).catch(() => null)
  }, [selectedAlert, accessToken])

  if (!selectedAlert) {
    return (
      <div className={`flex flex-col items-center justify-center h-full gap-4 ${className}`}>
        <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
          <circle cx="24" cy="24" r="22" stroke="rgba(0,255,157,0.15)" strokeWidth="1" strokeDasharray="5 4" />
          <path d="M24 14v14M24 32v2" stroke="rgba(0,255,157,0.3)" strokeWidth="2" strokeLinecap="round" />
        </svg>
        <div className="text-center">
          <p className="text-gray-600 text-xs font-mono">NO ALERT SELECTED</p>
          <p className="text-gray-700 text-[10px] font-mono mt-1">Click a node or event to inspect</p>
        </div>
      </div>
    )
  }

  const color = LEVEL_COLOR[selectedAlert.threat_level] || '#00ff9d'
  const ts = selectedAlert.timestamp ? new Date(selectedAlert.timestamp) : null

  const fields = [
    ['Attack Type', selectedAlert.attack_type || selectedAlert.alert_type || '—'],
    ['Source IP', selectedAlert.src_ip || selectedAlert.source_ip || '—'],
    ['Destination IP', selectedAlert.dst_ip || selectedAlert.destination_ip || '—'],
    ['Protocol', selectedAlert.protocol || '—'],
    ['Port', selectedAlert.dst_port ?? selectedAlert.port ?? '—'],
    ['Country', selectedAlert.geo_country || '—'],
    ['Threat Score', selectedAlert.threat_score != null ? `${Math.round(selectedAlert.threat_score)} / 100` : '—'],
    ['Anomaly Score', selectedAlert.anomaly_score != null ? selectedAlert.anomaly_score.toFixed(4) : '—'],
    ['Classification', selectedAlert.classification || '—'],
    ['Timestamp', ts ? format(ts, 'yyyy-MM-dd HH:mm:ss') : '—'],
  ]

  return (
    <div ref={panelRef} className={`flex flex-col h-full overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-cyber-border flex-shrink-0"
        style={{ background: `linear-gradient(90deg, ${color}12 0%, transparent 100%)` }}>
        <div className="flex items-center gap-2.5">
          <span className="pulse-dot" style={{
            width: 8, height: 8, borderRadius: '50%', background: color,
            boxShadow: `0 0 6px ${color}`,
          }} />
          <span className="font-['Orbitron',sans-serif] text-xs font-bold tracking-widest uppercase"
            style={{ color }}>
            {selectedAlert.threat_level || 'ALERT'} — DRILL DOWN
          </span>
        </div>
        <button
          onClick={() => setSelectedAlert(null)}
          className="text-gray-600 hover:text-white transition-colors text-lg leading-none"
          aria-label="Close panel"
        >
          ✕
        </button>
      </div>

      {/* Score arc */}
      <div className="flex-shrink-0 flex items-center gap-4 px-4 py-3 border-b border-cyber-border/50">
        <ScoreArc score={selectedAlert.threat_score || 0} color={color} />
        <div>
          <div className="font-['Orbitron',sans-serif] text-2xl font-bold" style={{ color }}>
            {Math.round(selectedAlert.threat_score || 0)}
          </div>
          <div className="text-gray-500 text-[10px] font-mono uppercase tracking-wider">Threat Score</div>
          <div className="text-[10px] font-mono mt-0.5" style={{ color }}>
            {selectedAlert.threat_level}
          </div>
        </div>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">

        {/* Fields grid */}
        <div className="space-y-1.5">
          {fields.map(([label, value]) => (
            <div key={label} className="flex items-start gap-2 text-[11px]">
              <span className="text-gray-600 font-mono w-28 flex-shrink-0 uppercase tracking-wide">{label}</span>
              <span className="text-gray-200 font-mono break-all">{value}</span>
            </div>
          ))}
        </div>

        {/* Explanation */}
        {selectedAlert.explanation && (
          <div className="rounded p-3" style={{ background: 'rgba(0,255,157,0.04)', border: '1px solid rgba(0,255,157,0.15)' }}>
            <div className="text-cyber-green/70 text-[10px] font-mono uppercase tracking-wider mb-1.5">
              ⚙ ML Explanation
            </div>
            <p className="text-gray-300 text-[11px] font-mono leading-relaxed">
              {selectedAlert.explanation}
            </p>
          </div>
        )}

        {/* MITRE ATT&CK */}
        {(selectedAlert.mitre_technique || mitreDetail) && (
          <div className="rounded p-3" style={{ background: 'rgba(189,0,255,0.04)', border: '1px solid rgba(189,0,255,0.2)' }}>
            <div className="text-purple-400/70 text-[10px] font-mono uppercase tracking-wider mb-2">
              ⚑ MITRE ATT&CK
            </div>
            <div className="space-y-1.5 text-[11px] font-mono">
              <div className="flex gap-2">
                <span className="text-gray-600 w-20 flex-shrink-0">Technique</span>
                <span className="text-purple-300">
                  {mitreDetail?.technique_id || selectedAlert.mitre_technique_id || '—'}
                </span>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-600 w-20 flex-shrink-0">Name</span>
                <span className="text-gray-200">
                  {mitreDetail?.name || selectedAlert.mitre_technique || '—'}
                </span>
              </div>
              {mitreDetail?.tactic && (
                <div className="flex gap-2">
                  <span className="text-gray-600 w-20 flex-shrink-0">Tactic</span>
                  <span className="text-gray-300">{mitreDetail.tactic}</span>
                </div>
              )}
              {mitreDetail?.description && (
                <p className="text-gray-500 mt-2 leading-relaxed">{mitreDetail.description}</p>
              )}
            </div>
          </div>
        )}

        {/* Recommendation */}
        {selectedAlert.recommendation && (
          <div className="rounded p-3" style={{ background: 'rgba(255,170,0,0.04)', border: '1px solid rgba(255,170,0,0.2)' }}>
            <div className="text-cyber-amber/70 text-[10px] font-mono uppercase tracking-wider mb-1.5">
              ▶ Recommended Action
            </div>
            <p className="text-gray-300 text-[11px] font-mono leading-relaxed">
              {selectedAlert.recommendation}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// Mini SVG arc gauge
function ScoreArc({ score, color }) {
  const r = 22
  const circ = 2 * Math.PI * r
  const arc = (score / 100) * circ * 0.75
  const offset = circ * 0.125

  return (
    <svg width="56" height="56" viewBox="0 0 56 56">
      <circle cx="28" cy="28" r={r} fill="none" stroke="#1a2540" strokeWidth="4"
        strokeDasharray={`${circ * 0.75} ${circ}`}
        strokeDashoffset={`-${offset}`}
        strokeLinecap="round" transform="rotate(-90 28 28)" />
      <circle cx="28" cy="28" r={r} fill="none" stroke={color} strokeWidth="4"
        strokeDasharray={`${arc} ${circ}`}
        strokeDashoffset={`-${offset}`}
        strokeLinecap="round" transform="rotate(-90 28 28)"
        style={{ filter: `drop-shadow(0 0 4px ${color})`, transition: 'stroke-dasharray 0.5s ease' }} />
    </svg>
  )
}
