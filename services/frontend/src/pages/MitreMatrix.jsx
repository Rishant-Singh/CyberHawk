import { useEffect, useState } from 'react'
import axios from 'axios'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import Modal from '../components/common/Modal'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// MITRE ATT&CK tactics in order
const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', short: 'Recon' },
  { id: 'TA0042', name: 'Resource Development', short: 'Res. Dev.' },
  { id: 'TA0001', name: 'Initial Access', short: 'Init. Access' },
  { id: 'TA0002', name: 'Execution', short: 'Execution' },
  { id: 'TA0003', name: 'Persistence', short: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation', short: 'Priv. Esc.' },
  { id: 'TA0005', name: 'Defense Evasion', short: 'Def. Evasion' },
  { id: 'TA0006', name: 'Credential Access', short: 'Cred. Access' },
  { id: 'TA0007', name: 'Discovery', short: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement', short: 'Lateral Mov.' },
  { id: 'TA0009', name: 'Collection', short: 'Collection' },
  { id: 'TA0011', name: 'Command & Control', short: 'C2' },
  { id: 'TA0010', name: 'Exfiltration', short: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact', short: 'Impact' },
]

function heatColor(count, maxCount) {
  if (!count || count === 0) return 'rgba(0,255,157,0.04)'
  const intensity = Math.min(count / maxCount, 1)
  if (intensity > 0.7) return `rgba(255,45,85,${0.15 + intensity * 0.4})`
  if (intensity > 0.4) return `rgba(255,107,53,${0.15 + intensity * 0.35})`
  if (intensity > 0.1) return `rgba(255,196,0,${0.15 + intensity * 0.3})`
  return `rgba(0,255,157,${0.08 + intensity * 0.2})`
}

function heatBorder(count, maxCount) {
  if (!count) return 'rgba(0,255,157,0.12)'
  const intensity = Math.min(count / maxCount, 1)
  if (intensity > 0.7) return 'rgba(255,45,85,0.5)'
  if (intensity > 0.4) return 'rgba(255,107,53,0.5)'
  if (intensity > 0.1) return 'rgba(255,196,0,0.4)'
  return 'rgba(0,255,157,0.2)'
}

export default function MitreMatrix() {
  const token = useThreatStore((s) => s.accessToken)
  const authHeader = { headers: { Authorization: `Bearer ${token}` } }

  const [techniques, setTechniques] = useState([])
  const [heatmap, setHeatmap] = useState({})
  const [selected, setSelected] = useState(null)
  const [filterTactic, setFilterTactic] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      axios.get(`${API}/api/mitre/techniques`, authHeader),
      axios.get(`${API}/api/mitre/heatmap?hours=168`, authHeader),
    ]).then(([techRes, heatRes]) => {
      setTechniques(techRes.data.techniques || [])
      setHeatmap(heatRes.data.heatmap || {})
    }).catch(() => {
      // Use mock data if backend not available
      setTechniques(MOCK_TECHNIQUES)
      setHeatmap(MOCK_HEATMAP)
    }).finally(() => setLoading(false))
  }, [])

  const maxCount = Math.max(1, ...Object.values(heatmap))

  // Group techniques by tactic
  const byTactic = {}
  TACTICS.forEach((t) => { byTactic[t.name] = [] })
  techniques.forEach((tech) => {
    const tacticName = tech.tactic || ''
    if (byTactic[tacticName]) {
      byTactic[tacticName].push(tech)
    }
  })

  const totalDetected = Object.keys(heatmap).length
  const totalTechniques = techniques.length

  return (
    <div className="flex flex-col gap-5 h-full">
      <PageHeader
        title="MITRE ATT&CK Matrix"
        description="Interactive threat technique heatmap — color intensity reflects detection frequency"
        icon={
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M9 3v18M15 3v18M3 9h18M3 15h18" />
          </svg>
        }
      />

      {/* Legend + stats */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="text-[10px] font-mono text-gray-600 uppercase tracking-widest">Detection Intensity:</span>
          {[
            { label: 'None', color: 'rgba(0,255,157,0.08)' },
            { label: 'Low', color: 'rgba(0,255,157,0.3)' },
            { label: 'Medium', color: 'rgba(255,196,0,0.5)' },
            { label: 'High', color: 'rgba(255,107,53,0.6)' },
            { label: 'Critical', color: 'rgba(255,45,85,0.8)' },
          ].map((l) => (
            <div key={l.label} className="flex items-center gap-1.5">
              <div className="w-4 h-4 rounded" style={{ background: l.color }} />
              <span className="text-[10px] font-mono text-gray-500">{l.label}</span>
            </div>
          ))}
        </div>
        <div className="flex gap-4 text-[11px] font-mono">
          <span className="text-gray-500">{totalTechniques} techniques</span>
          <span className="text-cyber-green">{totalDetected} detected</span>
        </div>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          {/* Tactic headers */}
          <div className="grid gap-1 mb-1" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(90px, 1fr))` }}>
            {TACTICS.map((tactic) => (
              <button
                key={tactic.id}
                onClick={() => setFilterTactic(filterTactic === tactic.name ? null : tactic.name)}
                className="px-2 py-2 rounded-lg text-[9px] font-mono font-bold uppercase tracking-wider text-center transition-all"
                style={{
                  background: filterTactic === tactic.name ? 'rgba(0,255,157,0.2)' : 'rgba(0,255,157,0.07)',
                  color: filterTactic === tactic.name ? '#00ff9d' : '#5a7a6a',
                  border: filterTactic === tactic.name ? '1px solid rgba(0,255,157,0.4)' : '1px solid rgba(0,255,157,0.12)',
                }}
              >
                {tactic.short}
              </button>
            ))}
          </div>

          {/* Technique cells */}
          <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(90px, 1fr))` }}>
            {TACTICS.map((tactic) => {
              const techs = byTactic[tactic.name] || []
              const isFiltered = filterTactic && filterTactic !== tactic.name

              return (
                <div key={tactic.id} className={`flex flex-col gap-1 transition-opacity ${isFiltered ? 'opacity-20' : ''}`}>
                  {techs.length === 0 ? (
                    <div className="h-8 rounded" style={{ background: 'rgba(0,0,0,0.2)' }} />
                  ) : (
                    techs.map((tech) => {
                      const count = heatmap[tech.id] || 0
                      return (
                        <button
                          key={tech.id}
                          onClick={() => setSelected(tech)}
                          className="w-full rounded px-1.5 py-1.5 text-left transition-all hover:scale-105 hover:z-10 relative"
                          style={{
                            background: heatColor(count, maxCount),
                            border: `1px solid ${heatBorder(count, maxCount)}`,
                            minHeight: '36px',
                          }}
                          title={`${tech.id}: ${tech.name}\nDetections: ${count}`}
                        >
                          <div className="text-[9px] font-mono text-gray-500 leading-none">{tech.id}</div>
                          <div className="text-[10px] font-mono text-gray-300 leading-tight truncate mt-0.5">
                            {tech.name}
                          </div>
                          {count > 0 && (
                            <div className="absolute top-1 right-1 text-[8px] font-bold font-mono"
                              style={{ color: '#ff6b35' }}>
                              {count}
                            </div>
                          )}
                        </button>
                      )
                    })
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Technique detail modal */}
      <Modal open={!!selected} onClose={() => setSelected(null)} title={`${selected?.id} — ${selected?.name}`}>
        {selected && (
          <div className="space-y-4 text-sm font-mono">
            <div className="flex items-center gap-3">
              <StatusBadge value={selected.severity || 'HIGH'} />
              <span className="text-gray-500">{selected.tactic}</span>
              {heatmap[selected.id] && (
                <span className="text-orange-400">{heatmap[selected.id]} detections in last 7 days</span>
              )}
            </div>
            {selected.description && (
              <p className="text-gray-400 text-xs leading-relaxed">{selected.description}</p>
            )}
            {selected.platforms && (
              <div>
                <div className="text-[10px] text-gray-600 uppercase tracking-widest mb-1">Platforms</div>
                <div className="flex flex-wrap gap-1">
                  {(Array.isArray(selected.platforms) ? selected.platforms : [selected.platforms]).map((p) => (
                    <span key={p} className="px-2 py-0.5 rounded text-[10px]"
                      style={{ background: 'rgba(100,120,200,0.2)', color: '#8899ee' }}>{p}</span>
                  ))}
                </div>
              </div>
            )}
            {selected.detection && (
              <div>
                <div className="text-[10px] text-gray-600 uppercase tracking-widest mb-1">Detection Guidance</div>
                <p className="text-gray-400 text-xs leading-relaxed">{selected.detection}</p>
              </div>
            )}
            <a
              href={`https://attack.mitre.org/techniques/${selected.id}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-xs text-cyber-green hover:underline"
            >
              View on MITRE ATT&CK ↗
            </a>
          </div>
        )}
      </Modal>
    </div>
  )
}

// Mock data for offline development
const MOCK_TECHNIQUES = [
  { id: 'T1190', name: 'Exploit Public App', tactic: 'Initial Access', severity: 'CRITICAL' },
  { id: 'T1059', name: 'Command & Script', tactic: 'Execution', severity: 'HIGH' },
  { id: 'T1053', name: 'Scheduled Task', tactic: 'Persistence', severity: 'MEDIUM' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Privilege Escalation', severity: 'HIGH' },
  { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion', severity: 'HIGH' },
  { id: 'T1003', name: 'OS Credential Dump', tactic: 'Credential Access', severity: 'CRITICAL' },
  { id: 'T1083', name: 'File Discovery', tactic: 'Discovery', severity: 'LOW' },
  { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', severity: 'HIGH' },
  { id: 'T1005', name: 'Local Data', tactic: 'Collection', severity: 'MEDIUM' },
  { id: 'T1071', name: 'App Layer Protocol', tactic: 'Command & Control', severity: 'HIGH' },
  { id: 'T1041', name: 'C2 Channel Exfil', tactic: 'Exfiltration', severity: 'HIGH' },
  { id: 'T1486', name: 'Data Encrypted', tactic: 'Impact', severity: 'CRITICAL' },
]
const MOCK_HEATMAP = { T1190: 45, T1059: 32, T1078: 18, T1003: 12, T1486: 8, T1071: 6, T1021: 4 }
