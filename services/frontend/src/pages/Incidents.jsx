import { useEffect, useState, useCallback } from 'react'
import axios from 'axios'
import { toast } from 'react-hot-toast'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import Modal from '../components/common/Modal'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const STATUS_COLS = ['open', 'investigating', 'resolved', 'closed']
const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function IncidentCard({ incident, onClick }) {
  return (
    <button onClick={() => onClick(incident)}
      className="w-full text-left rounded-lg border p-3 hover:border-cyber-green/30 transition-all hover:bg-white/3 mb-2"
      style={{ background: 'rgba(6,10,24,0.8)', borderColor: 'rgba(255,255,255,0.08)' }}>
      <div className="flex items-center justify-between mb-2">
        <StatusBadge value={incident.severity} />
        <span className="text-[9px] font-mono text-gray-600">
          {new Date(incident.created_at).toLocaleDateString()}
        </span>
      </div>
      <div className="text-xs font-mono text-gray-200 font-semibold truncate">{incident.title}</div>
      {incident.assigned_to && (
        <div className="text-[10px] font-mono text-gray-600 mt-1">→ {incident.assigned_to}</div>
      )}
      <div className="flex items-center gap-2 mt-2">
        {incident.alert_count > 0 && (
          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded"
            style={{ background: 'rgba(0,255,157,0.1)', color: '#00ff9d' }}>
            {incident.alert_count} alerts
          </span>
        )}
        {incident.mitre_techniques?.slice(0, 2).map((t) => (
          <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded"
            style={{ background: 'rgba(100,120,200,0.15)', color: '#8899ee' }}>{t}</span>
        ))}
      </div>
    </button>
  )
}

export default function Incidents() {
  const token = useThreatStore((s) => s.accessToken)
  const authHeader = { headers: { Authorization: `Bearer ${token}` } }

  const [incidents, setIncidents] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [timeline, setTimeline] = useState(null)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ title: '', description: '', severity: 'MEDIUM', assigned_to: '' })
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [incRes, statsRes] = await Promise.all([
        axios.get(`${API}/api/incidents/?size=100`, authHeader),
        axios.get(`${API}/api/incidents/stats/summary`, authHeader),
      ])
      setIncidents(incRes.data.items || [])
      setStats(statsRes.data || {})
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [token])

  useEffect(() => { load() }, [load])

  const openIncident = async (incident) => {
    setSelected(incident)
    setTimeline(null)
    try {
      const { data } = await axios.get(`${API}/api/incidents/${incident.id}/timeline`, authHeader)
      setTimeline(data)
    } catch { /* silent */ }
  }

  const updateStatus = async (id, newStatus) => {
    try {
      await axios.put(`${API}/api/incidents/${id}`, { status: newStatus }, authHeader)
      toast.success(`Status → ${newStatus}`)
      await load()
      if (selected?.id === id) setSelected((s) => s ? { ...s, status: newStatus } : null)
    } catch { toast.error('Failed to update') }
  }

  const createIncident = async () => {
    if (!form.title.trim()) { toast.error('Title is required'); return }
    setCreating(true)
    try {
      await axios.post(`${API}/api/incidents/`, form, authHeader)
      toast.success('Incident created')
      setShowCreate(false)
      setForm({ title: '', description: '', severity: 'MEDIUM', assigned_to: '' })
      await load()
    } catch { toast.error('Failed to create incident') }
    finally { setCreating(false) }
  }

  // Group incidents by status
  const byStatus = {}
  STATUS_COLS.forEach((s) => { byStatus[s] = incidents.filter((i) => i.status === s) })

  const statusLabel = { open: 'Open', investigating: 'Investigating', resolved: 'Resolved', closed: 'Closed' }
  const statusColor = {
    open: '#ff2d55', investigating: '#ffc400', resolved: '#00ff9d', closed: '#6478c8'
  }

  return (
    <div className="flex flex-col gap-5 h-full">
      <PageHeader
        title="Incident Management"
        description="Track, investigate, and resolve security incidents"
        icon={
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
            <polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" />
          </svg>
        }
        action={
          <button onClick={() => setShowCreate(true)}
            className="px-4 py-2 rounded-lg text-xs font-mono font-bold uppercase tracking-widest transition-all"
            style={{ background: 'rgba(0,255,157,0.15)', color: '#00ff9d', border: '1px solid rgba(0,255,157,0.3)' }}>
            + New Incident
          </button>
        }
      />

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3">
        {STATUS_COLS.map((s) => (
          <div key={s} className="rounded-lg px-4 py-3 border"
            style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.1)' }}>
            <div className="text-xl font-['Orbitron'] font-bold" style={{ color: statusColor[s] }}>
              {stats.by_status?.[s] ?? byStatus[s].length}
            </div>
            <div className="text-[10px] font-mono text-gray-600 uppercase tracking-widest">{statusLabel[s]}</div>
          </div>
        ))}
      </div>

      {/* Kanban Board */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-8 h-8 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-4 gap-4 flex-1 min-h-0">
          {STATUS_COLS.map((status) => (
            <div key={status} className="flex flex-col rounded-xl border overflow-hidden"
              style={{ background: 'rgba(6,10,24,0.6)', borderColor: 'rgba(255,255,255,0.06)' }}>
              {/* Column header */}
              <div className="px-4 py-3 border-b flex items-center gap-2"
                style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                <div className="w-2 h-2 rounded-full" style={{ background: statusColor[status] }} />
                <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: statusColor[status] }}>
                  {statusLabel[status]}
                </span>
                <span className="ml-auto text-[10px] font-mono text-gray-600">{byStatus[status].length}</span>
              </div>
              {/* Cards */}
              <div className="flex-1 overflow-y-auto p-2">
                {byStatus[status].length === 0 ? (
                  <div className="text-center text-[10px] font-mono text-gray-700 py-8">No incidents</div>
                ) : (
                  byStatus[status].map((i) => (
                    <IncidentCard key={i.id} incident={i} onClick={openIncident} />
                  ))
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Incident Detail Modal */}
      <Modal open={!!selected} onClose={() => { setSelected(null); setTimeline(null) }}
        title={selected?.title || 'Incident'} maxWidth="max-w-3xl">
        {selected && (
          <div className="space-y-5">
            <div className="flex items-center gap-3 flex-wrap">
              <StatusBadge value={selected.severity} />
              <StatusBadge value={selected.status} />
              {selected.assigned_to && (
                <span className="text-xs font-mono text-gray-500">→ {selected.assigned_to}</span>
              )}
            </div>

            {selected.description && (
              <p className="text-sm font-mono text-gray-400 leading-relaxed">{selected.description}</p>
            )}

            {/* Status actions */}
            <div className="flex gap-2">
              <span className="text-[10px] font-mono text-gray-600 self-center">Move to:</span>
              {STATUS_COLS.filter((s) => s !== selected.status).map((s) => (
                <button key={s} onClick={() => updateStatus(selected.id, s)}
                  className="px-3 py-1 rounded text-[10px] font-mono uppercase tracking-wider border transition-all hover:bg-white/10"
                  style={{ borderColor: statusColor[s], color: statusColor[s] }}>
                  {s}
                </button>
              ))}
            </div>

            {/* MITRE techniques */}
            {selected.mitre_techniques?.length > 0 && (
              <div>
                <div className="text-[10px] font-mono text-gray-600 uppercase tracking-widest mb-2">MITRE Techniques</div>
                <div className="flex flex-wrap gap-1">
                  {selected.mitre_techniques.map((t) => (
                    <span key={t} className="px-2 py-0.5 rounded text-[10px] font-mono"
                      style={{ background: 'rgba(100,120,200,0.2)', color: '#8899ee' }}>{t}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Timeline */}
            {timeline && (
              <div>
                <div className="text-[10px] font-mono text-gray-600 uppercase tracking-widest mb-2">
                  Timeline ({timeline.timeline?.length} events)
                </div>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {timeline.timeline?.map((ev, i) => (
                    <div key={i} className="flex gap-3 p-2 rounded border"
                      style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' }}>
                      <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0"
                        style={{ background: ev.type === 'alert' ? '#ff6b35' : '#00ff9d' }} />
                      <div className="min-w-0">
                        <div className="text-xs font-mono text-gray-300">{ev.title}</div>
                        <div className="text-[10px] font-mono text-gray-600">
                          {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : ''}
                          {ev.src_ip && ` · src: ${ev.src_ip}`}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Create Incident Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create New Incident">
        <div className="space-y-4">
          {[
            { label: 'Title *', key: 'title', type: 'text', placeholder: 'Incident title...' },
            { label: 'Assigned To', key: 'assigned_to', type: 'text', placeholder: 'analyst@team.com' },
          ].map(({ label, key, type, placeholder }) => (
            <div key={key}>
              <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-1">{label}</label>
              <input type={type} value={form[key]} onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                placeholder={placeholder}
                className="w-full bg-transparent border rounded-lg px-3 py-2 text-sm font-mono text-gray-200 outline-none"
                style={{ borderColor: 'rgba(0,255,157,0.2)', background: 'rgba(0,0,0,0.3)' }} />
            </div>
          ))}

          <div>
            <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-1">Severity</label>
            <select value={form.severity} onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))}
              className="w-full bg-transparent border rounded-lg px-3 py-2 text-sm font-mono text-gray-200 outline-none"
              style={{ borderColor: 'rgba(0,255,157,0.2)', background: 'rgba(8,12,28,0.9)' }}>
              {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          <div>
            <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-1">Description</label>
            <textarea value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              rows={3} placeholder="Incident description..."
              className="w-full bg-transparent border rounded-lg px-3 py-2 text-sm font-mono text-gray-200 outline-none resize-none"
              style={{ borderColor: 'rgba(0,255,157,0.2)', background: 'rgba(0,0,0,0.3)' }} />
          </div>

          <div className="flex gap-3 pt-2">
            <button onClick={createIncident} disabled={creating}
              className="flex-1 py-2.5 rounded-lg text-sm font-mono font-bold uppercase tracking-widest transition-all"
              style={{ background: 'rgba(0,255,157,0.15)', color: '#00ff9d', border: '1px solid rgba(0,255,157,0.3)' }}>
              {creating ? 'Creating...' : 'Create Incident'}
            </button>
            <button onClick={() => setShowCreate(false)}
              className="px-6 py-2.5 rounded-lg text-sm font-mono text-gray-500 border border-gray-700 hover:text-white transition-all">
              Cancel
            </button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
