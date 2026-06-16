import { useState, useMemo } from 'react'
import { format } from 'date-fns'
import useThreatStore from '../store/threatStore'
import AlertPanel from '../components/panels/AlertPanel.jsx'

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const LEVEL_CONFIG = {
  CRITICAL: { color: '#ff2d55', cls: 'badge-critical' },
  HIGH:     { color: '#ff6b35', cls: 'badge-high' },
  MEDIUM:   { color: '#ffaa00', cls: 'badge-medium' },
  LOW:      { color: '#00d4ff', cls: 'badge-low' },
  INFO:     { color: '#00ff9d', cls: 'badge-info' },
}

const PAGE_SIZE = 25

export default function Alerts() {
  const { alerts, alertsTotal, selectedAlert, setSelectedAlert, liveThreats } = useThreatStore()

  const [search, setSearch] = useState('')
  const [filterLevel, setFilterLevel] = useState('ALL')
  const [sortKey, setSortKey] = useState('timestamp')
  const [sortDir, setSortDir] = useState('desc')
  const [page, setPage] = useState(0)

  // Combine REST alerts + live threat events
  const combined = useMemo(() => {
    const seen = new Set()
    const all = []
    ;[...liveThreats, ...alerts].forEach((a) => {
      const key = a.id || `${a.src_ip}-${a.timestamp}`
      if (!seen.has(key)) { seen.add(key); all.push(a) }
    })
    return all
  }, [alerts, liveThreats])

  const filtered = useMemo(() => {
    return combined.filter((a) => {
      const level = a.threat_level || a.severity || 'INFO'
      if (filterLevel !== 'ALL' && level !== filterLevel) return false
      if (search) {
        const q = search.toLowerCase()
        return [a.src_ip, a.dst_ip, a.attack_type, a.alert_type, a.mitre_technique]
          .join(' ').toLowerCase().includes(q)
      }
      return true
    }).sort((a, b) => {
      let av, bv
      if (sortKey === 'timestamp') {
        av = new Date(a.timestamp || 0).getTime()
        bv = new Date(b.timestamp || 0).getTime()
      } else if (sortKey === 'threat_score') {
        av = a.threat_score || 0
        bv = b.threat_score || 0
      } else if (sortKey === 'severity') {
        av = SEVERITY_ORDER[a.threat_level] ?? 99
        bv = SEVERITY_ORDER[b.threat_level] ?? 99
      }
      return sortDir === 'asc' ? av - bv : bv - av
    })
  }, [combined, filterLevel, search, sortKey, sortDir])

  const pageSlice = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir((d) => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
    setPage(0)
  }

  return (
    <div className="h-full flex overflow-hidden">
      {/* Main table */}
      <div className="flex-1 flex flex-col overflow-hidden p-3 gap-3">

        {/* Toolbar */}
        <div className="flex items-center gap-3 flex-wrap">
          <input
            id="alerts-search"
            type="text"
            placeholder="Search IP, attack type..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0) }}
            className="cyber-input text-xs h-8 w-64"
          />

          {/* Level filter pills */}
          <div className="flex items-center gap-1.5">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((l) => {
              const cfg = LEVEL_CONFIG[l] || {}
              return (
                <button key={l}
                  onClick={() => { setFilterLevel(l); setPage(0) }}
                  className="text-[9px] px-2 py-1 rounded font-['Orbitron',sans-serif] uppercase tracking-wider transition-all"
                  style={{
                    background: filterLevel === l
                      ? (cfg.color ? `${cfg.color}25` : 'rgba(0,255,157,0.15)')
                      : 'rgba(255,255,255,0.04)',
                    color: filterLevel === l ? (cfg.color || '#00ff9d') : 'rgba(160,176,192,0.5)',
                    border: `1px solid ${filterLevel === l ? (cfg.color ? `${cfg.color}50` : 'rgba(0,255,157,0.4)') : 'rgba(255,255,255,0.06)'}`,
                  }}>
                  {l}
                </button>
              )
            })}
          </div>

          <div className="ml-auto text-[10px] font-mono text-gray-600">
            {filtered.length} alerts
            {alertsTotal > combined.length && ` (${alertsTotal} total)`}
          </div>
        </div>

        {/* Table */}
        <div className="cyber-panel flex-1 overflow-hidden flex flex-col">
          <div className="overflow-x-auto overflow-y-auto flex-1">
            <table className="w-full text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-cyber-border/50"
                  style={{ background: 'rgba(0,255,157,0.03)' }}>
                  {[
                    { key: 'severity', label: 'LEVEL' },
                    { key: 'timestamp', label: 'TIME' },
                    { label: 'ATTACK TYPE' },
                    { label: 'SRC IP' },
                    { label: 'DST IP' },
                    { label: 'PROTO' },
                    { key: 'threat_score', label: 'SCORE' },
                    { label: 'MITRE' },
                  ].map((col) => (
                    <th key={col.label}
                      onClick={() => col.key && toggleSort(col.key)}
                      className={`text-left px-3 py-2.5 text-[9px] text-gray-500 uppercase tracking-wider ${
                        col.key ? 'cursor-pointer hover:text-cyber-green' : ''
                      }`}>
                      {col.label}
                      {col.key && sortKey === col.key && (
                        <span className="ml-1 text-cyber-green">{sortDir === 'asc' ? '▲' : '▼'}</span>
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pageSlice.length === 0 && (
                  <tr>
                    <td colSpan={8} className="text-center py-12 text-gray-600 text-xs">
                      No alerts match current filters
                    </td>
                  </tr>
                )}
                {pageSlice.map((alert, i) => {
                  const level = alert.threat_level || alert.severity || 'INFO'
                  const cfg = LEVEL_CONFIG[level] || LEVEL_CONFIG.INFO
                  const isSelected = selectedAlert?.id === alert.id

                  return (
                    <tr key={alert.id || `${alert.src_ip}-${i}`}
                      onClick={() => setSelectedAlert(isSelected ? null : alert)}
                      className="border-b border-cyber-border/20 cursor-pointer transition-all duration-100 hover:brightness-125"
                      style={{
                        background: isSelected
                          ? `${cfg.color}12`
                          : i % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent',
                        borderLeft: isSelected ? `2px solid ${cfg.color}` : '2px solid transparent',
                      }}>
                      <td className="px-3 py-2">
                        <span className={cfg.cls}>{level}</span>
                      </td>
                      <td className="px-3 py-2 text-gray-500 whitespace-nowrap">
                        {alert.timestamp
                          ? format(new Date(alert.timestamp), 'MM-dd HH:mm:ss')
                          : '—'}
                      </td>
                      <td className="px-3 py-2" style={{ color: cfg.color }}>
                        {alert.attack_type || alert.alert_type || '—'}
                      </td>
                      <td className="px-3 py-2 text-gray-300">{alert.src_ip || '—'}</td>
                      <td className="px-3 py-2 text-gray-400">{alert.dst_ip || alert.destination_ip || '—'}</td>
                      <td className="px-3 py-2 text-gray-500">{alert.protocol || '—'}</td>
                      <td className="px-3 py-2 font-bold" style={{ color: cfg.color }}>
                        {alert.threat_score != null ? Math.round(alert.threat_score) : '—'}
                      </td>
                      <td className="px-3 py-2 text-purple-500 text-[9px]">
                        {alert.mitre_technique || '—'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-2 border-t border-cyber-border/50 flex-shrink-0">
              <button disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
                className="cyber-btn-outline text-xs px-3 py-1 disabled:opacity-30 disabled:cursor-not-allowed h-7">
                ◀ PREV
              </button>
              <span className="text-[10px] font-mono text-gray-600">
                Page {page + 1} of {totalPages}
              </span>
              <button disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => p + 1)}
                className="cyber-btn-outline text-xs px-3 py-1 disabled:opacity-30 disabled:cursor-not-allowed h-7">
                NEXT ▶
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Alert Drill-down sidebar */}
      {selectedAlert && (
        <div className="w-80 border-l border-cyber-border/50 flex-shrink-0 overflow-hidden">
          <div className="cyber-panel h-full">
            <AlertPanel className="h-full" />
          </div>
        </div>
      )}
    </div>
  )
}
