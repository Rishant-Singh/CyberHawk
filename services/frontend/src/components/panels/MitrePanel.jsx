import { useEffect, useState } from 'react'
import axios from 'axios'
import useThreatStore from '../../store/threatStore'

const API_BASE = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:8000'

const TACTIC_COLORS = {
  'initial-access':       '#ff6b35',
  'execution':            '#ffaa00',
  'persistence':          '#ff2d55',
  'privilege-escalation': '#bd00ff',
  'defense-evasion':      '#00d4ff',
  'credential-access':    '#ff6b35',
  'discovery':            '#00ff9d',
  'lateral-movement':     '#ffaa00',
  'collection':           '#00d4ff',
  'command-and-control':  '#ff2d55',
  'exfiltration':         '#bd00ff',
  'impact':               '#ff2d55',
}

export default function MitrePanel({ className = '' }) {
  const { accessToken, liveThreats } = useThreatStore()
  const [patterns, setPatterns] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [selectedTactic, setSelectedTactic] = useState('all')

  useEffect(() => {
    if (!accessToken) return
    axios.get(`${API_BASE}/api/mitre`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    }).then(r => {
      setPatterns(r.data?.patterns || r.data || [])
    }).catch(() => {
      setPatterns([])
    }).finally(() => setLoading(false))
  }, [accessToken])

  // Count how many live threats map to each technique
  const techniqueHitCounts = {}
  liveThreats.forEach((t) => {
    if (t.mitre_technique_id) {
      techniqueHitCounts[t.mitre_technique_id] = (techniqueHitCounts[t.mitre_technique_id] || 0) + 1
    }
  })

  const tactics = ['all', ...new Set(patterns.map((p) => p.tactic).filter(Boolean))]

  const filtered = patterns.filter((p) => {
    const matchSearch = !search || [p.name, p.technique_id, p.tactic, p.description]
      .join(' ').toLowerCase().includes(search.toLowerCase())
    const matchTactic = selectedTactic === 'all' || p.tactic === selectedTactic
    return matchSearch && matchTactic
  })

  return (
    <div className={`flex flex-col h-full ${className}`}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-cyber-border flex-shrink-0">
        <div className="flex items-center gap-2 mb-2">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#bd00ff" strokeWidth="2">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
          </svg>
          <span className="text-purple-400 text-xs font-['Orbitron',sans-serif] uppercase tracking-widest font-bold">
            MITRE ATT&CK Matrix
          </span>
        </div>
        <input
          type="text"
          placeholder="Search techniques..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="cyber-input text-xs h-7"
        />
        {tactics.length > 1 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {tactics.slice(0, 8).map((t) => (
              <button key={t}
                onClick={() => setSelectedTactic(t)}
                className="text-[9px] px-1.5 py-0.5 rounded font-mono uppercase transition-all"
                style={{
                  background: selectedTactic === t ? 'rgba(189,0,255,0.2)' : 'rgba(255,255,255,0.04)',
                  color: selectedTactic === t ? '#bd00ff' : 'rgba(160,176,192,0.5)',
                  border: `1px solid ${selectedTactic === t ? 'rgba(189,0,255,0.4)' : 'rgba(255,255,255,0.06)'}`,
                }}>
                {t === 'all' ? 'ALL' : t.replace(/-/g, ' ')}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
        {loading && (
          <div className="flex items-center justify-center h-24 gap-2 text-purple-400/50 text-xs font-mono">
            <span className="w-4 h-4 border border-purple-500 border-t-transparent rounded-full animate-spin" />
            Loading MITRE data...
          </div>
        )}

        {!loading && filtered.length === 0 && (
          <div className="flex items-center justify-center h-24 text-gray-600 text-xs font-mono">
            No techniques match your filter
          </div>
        )}

        {!loading && filtered.map((p) => {
          const hitCount = techniqueHitCounts[p.technique_id] || 0
          const tacticColor = TACTIC_COLORS[p.tactic] || '#00ff9d'
          return (
            <div key={p.technique_id || p.id}
              className="rounded p-2.5 transition-all duration-150 hover:brightness-110"
              style={{
                background: hitCount > 0 ? 'rgba(189,0,255,0.06)' : 'rgba(255,255,255,0.02)',
                border: hitCount > 0 ? '1px solid rgba(189,0,255,0.25)' : '1px solid rgba(255,255,255,0.05)',
              }}>
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-[9px] font-mono text-gray-600 flex-shrink-0">
                      {p.technique_id}
                    </span>
                    <span className="text-[9px] px-1 py-0.5 rounded font-mono uppercase"
                      style={{ color: tacticColor, background: `${tacticColor}18`, border: `1px solid ${tacticColor}30` }}>
                      {(p.tactic || '').replace(/-/g, ' ')}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-gray-200 truncate">{p.name}</div>
                  {p.description && (
                    <div className="text-[9px] font-mono text-gray-600 mt-0.5 line-clamp-2">
                      {p.description}
                    </div>
                  )}
                </div>
                {hitCount > 0 && (
                  <div className="flex-shrink-0 flex flex-col items-center gap-0.5">
                    <span className="text-[9px] font-bold font-['Orbitron',sans-serif] text-purple-300">
                      {hitCount}
                    </span>
                    <span className="text-[8px] font-mono text-purple-500/60">HITS</span>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-cyber-border/50 flex-shrink-0">
        <div className="flex items-center justify-between text-[9px] font-mono text-gray-600">
          <span>{filtered.length} / {patterns.length} techniques</span>
          <span className="text-purple-500/60">MITRE ATT&CK v14</span>
        </div>
      </div>
    </div>
  )
}
