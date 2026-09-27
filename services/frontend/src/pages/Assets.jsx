import { useEffect, useState, useCallback } from 'react'
import axios from 'axios'
import { toast } from 'react-hot-toast'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import Modal from '../components/common/Modal'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const ASSET_TYPES = ['server', 'workstation', 'router', 'firewall', 'iot', 'cloud', 'unknown']
const CRITICALITIES = ['critical', 'high', 'medium', 'low']

const TYPE_ICONS = {
  server: '🖥️', workstation: '💻', router: '🔀', firewall: '🛡️',
  iot: '📡', cloud: '☁️', unknown: '❓',
}

function RiskBar({ score }) {
  const pct = Math.min(100, score)
  const color = pct >= 80 ? '#ff2d55' : pct >= 60 ? '#ff6b35' : pct >= 30 ? '#ffc400' : '#00ff9d'
  return (
    <div className="w-full bg-gray-800 rounded-full h-1.5 mt-1">
      <div className="h-1.5 rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
    </div>
  )
}

export default function Assets() {
  const token = useThreatStore((s) => s.accessToken)
  const authHeader = { headers: { Authorization: `Bearer ${token}` } }

  const [assets, setAssets] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [discovering, setDiscovering] = useState(false)
  const [selected, setSelected] = useState(null)
  const [assetThreats, setAssetThreats] = useState([])
  const [showCreate, setShowCreate] = useState(false)
  const [filters, setFilters] = useState({ search: '', criticality: '', asset_type: '', is_compromised: '' })
  const [form, setForm] = useState({
    ip_address: '', hostname: '', asset_type: 'unknown', criticality: 'medium',
    owner: '', department: '', os: '',
  })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = {}
      if (filters.search) params.search = filters.search
      if (filters.criticality) params.criticality = filters.criticality
      if (filters.asset_type) params.asset_type = filters.asset_type
      if (filters.is_compromised !== '') params.is_compromised = filters.is_compromised === 'true'

      const [assetsRes, statsRes] = await Promise.all([
        axios.get(`${API}/api/assets/`, { params: { ...params, size: 100 }, ...authHeader }),
        axios.get(`${API}/api/assets/stats/summary`, authHeader),
      ])
      setAssets(assetsRes.data.items || [])
      setStats(statsRes.data || {})
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [token, filters])

  useEffect(() => { load() }, [load])

  const discover = async () => {
    setDiscovering(true)
    try {
      const { data } = await axios.post(`${API}/api/assets/discover`, {}, authHeader)
      toast.success(`Discovered ${data.discovered} assets (${data.created} new, ${data.updated} updated)`)
      await load()
    } catch { toast.error('Discovery failed') }
    finally { setDiscovering(false) }
  }

  const openAsset = async (asset) => {
    setSelected(asset)
    setAssetThreats([])
    try {
      const { data } = await axios.get(`${API}/api/assets/${asset.id}/threats?limit=20`, authHeader)
      setAssetThreats(data)
    } catch { /* silent */ }
  }

  const createAsset = async () => {
    if (!form.ip_address.trim()) { toast.error('IP address is required'); return }
    try {
      await axios.post(`${API}/api/assets/`, form, authHeader)
      toast.success('Asset registered')
      setShowCreate(false)
      await load()
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Failed to create asset')
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Asset Inventory"
        description="Network asset tracking with risk scoring and threat attribution"
        icon={
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <rect x="2" y="3" width="20" height="14" rx="2" /><line x1="8" y1="21" x2="16" y2="21" />
            <line x1="12" y1="17" x2="12" y2="21" />
          </svg>
        }
        action={
          <div className="flex gap-2">
            <button onClick={discover} disabled={discovering}
              className="px-4 py-2 rounded-lg text-xs font-mono uppercase tracking-widest transition-all"
              style={{ background: 'rgba(0,255,157,0.08)', color: '#00ff9d', border: '1px solid rgba(0,255,157,0.2)' }}>
              {discovering ? 'Discovering...' : '⚡ Auto-Discover'}
            </button>
            <button onClick={() => setShowCreate(true)}
              className="px-4 py-2 rounded-lg text-xs font-mono font-bold uppercase tracking-widest transition-all"
              style={{ background: 'rgba(0,255,157,0.15)', color: '#00ff9d', border: '1px solid rgba(0,255,157,0.3)' }}>
              + Register Asset
            </button>
          </div>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Assets', value: stats.total ?? 0, color: '#00ff9d' },
          { label: 'Compromised', value: stats.compromised ?? 0, color: '#ff2d55' },
          { label: 'Critical Assets', value: stats.by_criticality?.critical ?? 0, color: '#ff6b35' },
          { label: 'Types', value: Object.keys(stats.by_type || {}).length, color: '#6478c8' },
        ].map((s) => (
          <div key={s.label} className="rounded-lg px-4 py-3 border"
            style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.1)' }}>
            <div className="text-xl font-['Orbitron'] font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="text-[10px] font-mono text-gray-600 uppercase tracking-widest">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3 items-center flex-wrap">
        <input value={filters.search} onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
          placeholder="Search IP / hostname / owner..."
          className="flex-1 min-w-48 bg-transparent border rounded-lg px-3 py-2 text-xs font-mono text-gray-200 outline-none"
          style={{ borderColor: 'rgba(0,255,157,0.15)', background: 'rgba(0,0,0,0.3)' }} />

        {[
          { key: 'criticality', options: ['', ...CRITICALITIES], label: 'Criticality' },
          { key: 'asset_type', options: ['', ...ASSET_TYPES], label: 'Type' },
          { key: 'is_compromised', options: ['', 'true', 'false'], label: 'Compromised' },
        ].map(({ key, options, label }) => (
          <select key={key} value={filters[key]} onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))}
            className="border rounded-lg px-3 py-2 text-xs font-mono text-gray-400 outline-none"
            style={{ borderColor: 'rgba(0,255,157,0.15)', background: 'rgba(8,12,28,0.9)' }}>
            {options.map((o) => <option key={o} value={o}>{o || label}</option>)}
          </select>
        ))}
      </div>

      {/* Asset Table */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="w-8 h-8 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="rounded-xl border overflow-hidden"
          style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.12)' }}>
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b" style={{ borderColor: 'rgba(0,255,157,0.12)' }}>
                {['', 'IP / Host', 'Type', 'Criticality', 'Risk Score', 'Alerts', 'Last Seen', 'Status'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-gray-600 font-normal uppercase text-[9px] tracking-widest">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {assets.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-gray-600">
                  No assets found. Click "Auto-Discover" to scan existing traffic.
                </td></tr>
              ) : (
                assets.map((a) => (
                  <tr key={a.id} onClick={() => openAsset(a)}
                    className="border-b hover:bg-white/4 cursor-pointer transition-colors"
                    style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                    <td className="px-4 py-3 text-lg">{TYPE_ICONS[a.asset_type] || '❓'}</td>
                    <td className="px-4 py-3">
                      <div className="text-gray-200">{a.ip_address}</div>
                      {a.hostname && <div className="text-gray-600 text-[10px]">{a.hostname}</div>}
                    </td>
                    <td className="px-4 py-3 text-gray-500 capitalize">{a.asset_type}</td>
                    <td className="px-4 py-3"><StatusBadge value={a.criticality} /></td>
                    <td className="px-4 py-3 w-28">
                      <div className="text-gray-300">{a.threat_score.toFixed(0)}</div>
                      <RiskBar score={a.threat_score} />
                    </td>
                    <td className="px-4 py-3 text-gray-400">{a.total_alerts}</td>
                    <td className="px-4 py-3 text-gray-600">
                      {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {a.is_compromised
                        ? <span className="text-[10px] font-bold text-red-400">⚠ COMPROMISED</span>
                        : <span className="text-[10px] text-green-600">✓ Clean</span>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Asset Detail Modal */}
      <Modal open={!!selected} onClose={() => setSelected(null)} title={selected?.ip_address || 'Asset'} maxWidth="max-w-2xl">
        {selected && (
          <div className="space-y-4 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3">
              {[
                ['Type', `${TYPE_ICONS[selected.asset_type]} ${selected.asset_type}`],
                ['Criticality', selected.criticality],
                ['Owner', selected.owner || '—'],
                ['Department', selected.department || '—'],
                ['OS', selected.os || '—'],
                ['Last Seen', selected.last_seen ? new Date(selected.last_seen).toLocaleString() : '—'],
                ['Risk Score', `${selected.threat_score.toFixed(1)} / 100`],
                ['Total Alerts', selected.total_alerts],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg p-3 border" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                  <div className="text-gray-600 uppercase tracking-widest text-[9px] mb-0.5">{label}</div>
                  <div className="text-gray-300">{value}</div>
                </div>
              ))}
            </div>

            {assetThreats.length > 0 && (
              <div>
                <div className="text-gray-600 uppercase tracking-widest text-[9px] mb-2">
                  Recent Threats ({assetThreats.length})
                </div>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {assetThreats.map((t) => (
                    <div key={t.id} className="flex items-center gap-3 p-2 rounded border"
                      style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                      <StatusBadge value={t.threat_level} />
                      <span className="text-gray-400 flex-1 truncate">{t.attack_type || t.classification}</span>
                      <span className="text-gray-600">{new Date(t.timestamp).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Register Asset Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Register Asset">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'IP Address *', key: 'ip_address', placeholder: '192.168.1.x' },
              { label: 'Hostname', key: 'hostname', placeholder: 'server-01.internal' },
              { label: 'Owner', key: 'owner', placeholder: 'John Doe' },
              { label: 'Department', key: 'department', placeholder: 'IT / Security' },
              { label: 'OS', key: 'os', placeholder: 'Windows Server 2019' },
            ].map(({ label, key, placeholder }) => (
              <div key={key}>
                <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-1">{label}</label>
                <input value={form[key]} onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                  placeholder={placeholder}
                  className="w-full bg-transparent border rounded-lg px-3 py-2 text-xs font-mono text-gray-200 outline-none"
                  style={{ borderColor: 'rgba(0,255,157,0.2)', background: 'rgba(0,0,0,0.3)' }} />
              </div>
            ))}

            {[
              { label: 'Asset Type', key: 'asset_type', options: ASSET_TYPES },
              { label: 'Criticality', key: 'criticality', options: CRITICALITIES },
            ].map(({ label, key, options }) => (
              <div key={key}>
                <label className="block text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-1">{label}</label>
                <select value={form[key]} onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                  className="w-full border rounded-lg px-3 py-2 text-xs font-mono text-gray-300 outline-none capitalize"
                  style={{ borderColor: 'rgba(0,255,157,0.2)', background: 'rgba(8,12,28,0.9)' }}>
                  {options.map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
            ))}
          </div>

          <div className="flex gap-3 pt-2">
            <button onClick={createAsset}
              className="flex-1 py-2.5 rounded-lg text-sm font-mono font-bold uppercase tracking-widest"
              style={{ background: 'rgba(0,255,157,0.15)', color: '#00ff9d', border: '1px solid rgba(0,255,157,0.3)' }}>
              Register Asset
            </button>
            <button onClick={() => setShowCreate(false)}
              className="px-6 py-2.5 rounded-lg text-sm font-mono text-gray-500 border border-gray-700">
              Cancel
            </button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
