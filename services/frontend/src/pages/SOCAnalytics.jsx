import { useEffect, useState } from 'react'
import axios from 'axios'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const COLORS = ['#ff2d55', '#ff6b35', '#ffc400', '#00ff9d', '#6478c8', '#a78bfa', '#34d399']

const DAYS_OF_WEEK = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

function KPICard({ label, value, sub, color = '#00ff9d', icon }) {
  return (
    <div className="rounded-xl border p-5 flex flex-col gap-2"
      style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.12)' }}>
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">{label}</span>
        {icon}
      </div>
      <div className="text-3xl font-['Orbitron'] font-bold" style={{ color }}>{value ?? '—'}</div>
      {sub && <div className="text-[10px] font-mono text-gray-600">{sub}</div>}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border px-3 py-2 text-xs font-mono"
      style={{ background: 'rgba(8,12,28,0.95)', borderColor: 'rgba(0,255,157,0.2)', color: '#e0e8ff' }}>
      <div className="text-gray-500 mb-1">{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</div>
      ))}
    </div>
  )
}

export default function SOCAnalytics() {
  const token = useThreatStore((s) => s.accessToken)
  const authHeader = { headers: { Authorization: `Bearer ${token}` } }

  const [overview, setOverview] = useState(null)
  const [trend, setTrend] = useState([])
  const [topAttackers, setTopAttackers] = useState([])
  const [attackTypes, setAttackTypes] = useState([])
  const [heatmap, setHeatmap] = useState([])
  const [window, setWindow] = useState(24)
  const [loading, setLoading] = useState(true)

  const loadData = async (hours = 24) => {
    setLoading(true)
    try {
      const [ov, tr, att, types, hm] = await Promise.all([
        axios.get(`${API}/api/analytics/overview?hours=${hours}`, authHeader),
        axios.get(`${API}/api/analytics/trend?days=14&metric=count`, authHeader),
        axios.get(`${API}/api/analytics/top-attackers?limit=10&hours=${hours}`, authHeader),
        axios.get(`${API}/api/analytics/attack-types?hours=${hours}`, authHeader),
        axios.get(`${API}/api/analytics/attack-heatmap?days=30`, authHeader),
      ])
      setOverview(ov.data)
      setTrend(tr.data.data || [])
      setTopAttackers(att.data || [])
      setAttackTypes(types.data || [])
      setHeatmap(hm.data.data || [])
    } catch { /* silent — backend might not be running */ }
    finally { setLoading(false) }
  }

  useEffect(() => { loadData(window) }, [window])

  // Build 7×24 heatmap grid
  const heatGrid = Array.from({ length: 7 }, (_, d) =>
    Array.from({ length: 24 }, (_, h) => {
      const cell = heatmap.find((r) => r.weekday === d && r.hour === h)
      return cell?.count || 0
    })
  )
  const maxHeat = Math.max(1, ...heatmap.map((r) => r.count))

  const fmt = { style: { fontSize: '10px', fontFamily: 'JetBrains Mono', fill: '#6b7280' } }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="SOC Analytics Dashboard"
        description="Security operations metrics, trends, and attack intelligence"
        icon={
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" />
            <line x1="6" y1="20" x2="6" y2="14" />
          </svg>
        }
        action={
          <div className="flex gap-2">
            {[24, 72, 168].map((h) => (
              <button key={h} onClick={() => setWindow(h)}
                className="px-3 py-1.5 rounded text-[10px] font-mono uppercase tracking-widest transition-all"
                style={{
                  background: window === h ? 'rgba(0,255,157,0.15)' : 'rgba(0,255,157,0.05)',
                  color: window === h ? '#00ff9d' : '#5a7a6a',
                  border: `1px solid ${window === h ? 'rgba(0,255,157,0.3)' : 'rgba(0,255,157,0.1)'}`,
                }}>
                {h === 24 ? '24h' : h === 72 ? '3d' : '7d'}
              </button>
            ))}
          </div>
        }
      />

      {loading && (
        <div className="flex items-center justify-center py-16">
          <div className="w-8 h-8 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {!loading && (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <KPICard label="Total Alerts" value={overview?.total_alerts ?? 0} color="#00ff9d"
              sub="In selected window" />
            <KPICard label="Critical" value={overview?.critical ?? 0} color="#ff2d55"
              sub={`${overview?.high ?? 0} high severity`} />
            <KPICard label="Detection Rate" value={`${overview?.detection_rate ?? 0}%`} color="#ffc400"
              sub="Malicious / Total" />
            <KPICard label="Open Incidents" value={overview?.open_incidents ?? 0} color="#ff6b35"
              sub={`${overview?.investigating_incidents ?? 0} investigating`} />
          </div>

          {/* Alert Trend + Top Attackers */}
          <div className="grid grid-cols-3 gap-4">
            {/* Trend chart */}
            <div className="col-span-2 rounded-xl border p-5"
              style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.12)' }}>
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-4">
                Alert Volume — Last 14 Days
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={trend}>
                  <defs>
                    <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00ff9d" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00ff9d" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="date" tickFormatter={(v) => v?.slice(5)} tick={fmt} />
                  <YAxis tick={fmt} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="value" name="Alerts" stroke="#00ff9d"
                    fill="url(#areaGrad)" strokeWidth={2} dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Attack type donut */}
            <div className="rounded-xl border p-5"
              style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.12)' }}>
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-4">Attack Types</div>
              {attackTypes.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={attackTypes} dataKey="count" nameKey="type" innerRadius={50} outerRadius={80}>
                      {attackTypes.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-48 flex items-center justify-center text-xs font-mono text-gray-600">
                  No data available
                </div>
              )}
              <div className="space-y-1 mt-2">
                {attackTypes.slice(0, 4).map((t, i) => (
                  <div key={t.type} className="flex items-center justify-between text-[10px] font-mono">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-sm" style={{ background: COLORS[i % COLORS.length] }} />
                      <span className="text-gray-400 truncate max-w-[120px]">{t.type}</span>
                    </div>
                    <span className="text-gray-600">{t.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Top Attackers + Hourly Heatmap */}
          <div className="grid grid-cols-2 gap-4">
            {/* Top attackers */}
            <div className="rounded-xl border overflow-hidden"
              style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.12)' }}>
              <div className="px-5 py-4 border-b" style={{ borderColor: 'rgba(0,255,157,0.12)' }}>
                <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">Top Attacking IPs</span>
              </div>
              <div className="overflow-y-auto max-h-64">
                {topAttackers.length === 0 ? (
                  <div className="p-6 text-center text-xs font-mono text-gray-600">No data yet</div>
                ) : (
                  topAttackers.map((a, i) => (
                    <div key={a.ip} className="flex items-center px-5 py-3 border-b hover:bg-white/3"
                      style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                      <span className="w-6 text-[10px] font-mono text-gray-700">#{i + 1}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-mono text-gray-300">{a.ip}</div>
                        <div className="text-[10px] font-mono text-gray-600">
                          {a.country} · {a.primary_attack}
                        </div>
                      </div>
                      <div className="text-right">
                        <StatusBadge value={a.max_level} />
                        <div className="text-[10px] font-mono text-gray-600 mt-0.5">{a.total_alerts} hits</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Activity heatmap */}
            <div className="rounded-xl border p-5"
              style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.12)' }}>
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-3">
                Attack Activity Heatmap (30 days)
              </div>
              <div className="overflow-x-auto">
                <div className="flex gap-0.5">
                  {/* Hour labels */}
                  <div className="flex flex-col gap-0.5 mr-1">
                    <div className="h-4" />
                    {DAYS_OF_WEEK.map((d) => (
                      <div key={d} className="h-4 flex items-center text-[8px] font-mono text-gray-700 w-6">{d}</div>
                    ))}
                  </div>
                  {Array.from({ length: 24 }, (_, h) => (
                    <div key={h} className="flex flex-col gap-0.5">
                      <div className="h-4 flex items-end justify-center text-[7px] font-mono text-gray-700">{h}</div>
                      {heatGrid.map((row, d) => {
                        const val = row[h]
                        const intensity = val / maxHeat
                        return (
                          <div key={d} className="w-4 h-4 rounded-sm"
                            title={`${DAYS_OF_WEEK[d]} ${h}:00 — ${val} attacks`}
                            style={{
                              background: val === 0
                                ? 'rgba(0,255,157,0.04)'
                                : `rgba(0,255,157,${0.1 + intensity * 0.7})`,
                            }}
                          />
                        )
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
