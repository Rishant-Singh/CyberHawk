import useThreatStore from '../../store/threatStore'

const METRIC_CONFIG = [
  {
    key: 'cpu_percent',
    label: 'CPU',
    unit: '%',
    warnAt: 70,
    criticalAt: 90,
    icon: '⬡',
  },
  {
    key: 'memory_percent',
    label: 'RAM',
    unit: '%',
    warnAt: 75,
    criticalAt: 90,
    icon: '▣',
  },
  {
    key: 'disk_percent',
    label: 'DISK',
    unit: '%',
    warnAt: 80,
    criticalAt: 95,
    icon: '◈',
  },
  {
    key: 'kafka_lag',
    label: 'KAFKA LAG',
    unit: ' msg',
    warnAt: 500,
    criticalAt: 2000,
    max: 5000,
    icon: '⇶',
  },
]

function getColor(value, cfg) {
  if (value == null) return '#4a5568'
  if (value >= cfg.criticalAt) return '#ff2d55'
  if (value >= cfg.warnAt) return '#ffaa00'
  return '#00ff9d'
}

function MiniGauge({ value, max = 100, color }) {
  const pct = Math.min(100, Math.max(0, ((value ?? 0) / max) * 100))
  return (
    <div className="relative h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
      <div
        className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
        style={{
          width: `${pct}%`,
          background: color,
          boxShadow: `0 0 6px ${color}80`,
        }}
      />
    </div>
  )
}

export default function SystemHealth({ className = '' }) {
  const { systemHealth, wsConnected } = useThreatStore()

  const services = systemHealth?.services || {}
  const serviceList = [
    { name: 'Elasticsearch', key: 'elasticsearch', status: services.elasticsearch },
    { name: 'PostgreSQL', key: 'postgres', status: services.postgres },
    { name: 'Kafka', key: 'kafka', status: services.kafka },
    { name: 'ML Engine', key: 'ml_engine', status: services.ml_engine },
    { name: 'WebSocket', key: 'ws', status: wsConnected ? 'ok' : 'error' },
  ]

  return (
    <div className={`space-y-3 ${className}`}>
      {/* Resource metrics */}
      <div className="grid grid-cols-2 gap-2">
        {METRIC_CONFIG.map((cfg) => {
          const raw = systemHealth?.[cfg.key]
          const value = raw != null ? Number(raw) : null
          const max = cfg.max || 100
          const color = getColor(value, cfg)

          return (
            <div key={cfg.key}
              className="rounded p-2.5"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px]" style={{ color }}>{cfg.icon}</span>
                  <span className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">{cfg.label}</span>
                </div>
                <span className="font-['Orbitron',sans-serif] text-xs font-bold" style={{ color }}>
                  {value != null ? `${value.toFixed(value < 10 ? 1 : 0)}${cfg.unit}` : '—'}
                </span>
              </div>
              <MiniGauge value={value} max={max} color={color} />
            </div>
          )
        })}
      </div>

      {/* Service status */}
      <div className="rounded p-2.5" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="text-[9px] font-mono text-gray-600 uppercase tracking-wider mb-2">Services</div>
        <div className="space-y-1.5">
          {serviceList.map(({ name, key, status }) => {
            const isOk = status === 'ok' || status === true || status === 'healthy'
            const isWarn = status === 'warn' || status === 'degraded'
            const color = isOk ? '#00ff9d' : isWarn ? '#ffaa00' : status == null ? '#4a5568' : '#ff2d55'
            const label = isOk ? 'ONLINE' : isWarn ? 'DEGRADED' : status == null ? 'UNKNOWN' : 'OFFLINE'

            return (
              <div key={key} className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-gray-400">{name}</span>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: color, boxShadow: isOk ? `0 0 4px ${color}` : 'none' }} />
                  <span className="text-[9px] font-mono font-bold" style={{ color }}>{label}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Network stats */}
      {systemHealth?.network_throughput != null && (
        <div className="flex items-center justify-between px-2.5 py-1.5 rounded"
          style={{ background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.15)' }}>
          <span className="text-[9px] font-mono text-gray-600 uppercase tracking-wider">Network I/O</span>
          <span className="text-[11px] font-mono font-bold text-cyan-400">
            {(systemHealth.network_throughput / 1024).toFixed(1)} KB/s
          </span>
        </div>
      )}

      {/* Last update */}
      <div className="text-center text-[9px] font-mono text-gray-700">
        {systemHealth
          ? `Updated ${new Date().toLocaleTimeString()}`
          : 'Awaiting health data...'}
      </div>
    </div>
  )
}
