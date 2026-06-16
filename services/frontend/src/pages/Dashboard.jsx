import useThreatStore from '../store/threatStore'
import ThreatMap from '../components/visualizations/ThreatMap.jsx'
import RadarPulse from '../components/visualizations/RadarPulse.jsx'
import ThreatGauge from '../components/visualizations/ThreatGauge.jsx'
import AnomalyHeatmap from '../components/visualizations/AnomalyHeatmap.jsx'
import AttackTimeline from '../components/visualizations/AttackTimeline.jsx'
import AlertPanel from '../components/panels/AlertPanel.jsx'
import MitrePanel from '../components/panels/MitrePanel.jsx'
import SystemHealth from '../components/panels/SystemHealth.jsx'

export default function Dashboard() {
  const {
    totalThreatsDetected,
    criticalCount,
    highCount,
    mediumCount,
    currentThreatScore,
    wsConnected,
    selectedAlert,
    liveThreats,
  } = useThreatStore()

  return (
    <div className="h-full overflow-auto p-3 grid gap-3"
      style={{
        gridTemplateColumns: '1fr 1fr 1fr 280px',
        gridTemplateRows: 'auto 1fr 1fr',
        minWidth: '900px',
      }}>

      {/* ── Row 1: KPI Stats ─────────────────────────────────────── */}
      <StatCard
        id="kpi-total"
        label="Total Threats"
        value={totalThreatsDetected}
        color="#00ff9d"
        icon="⬡"
        sub={wsConnected ? 'LIVE' : 'OFFLINE'}
        subColor={wsConnected ? '#00ff9d' : '#ff2d55'}
      />
      <StatCard
        id="kpi-critical"
        label="Critical"
        value={criticalCount}
        color="#ff2d55"
        icon="⚠"
        sub="SESSION"
        subColor="#ff2d55"
      />
      <StatCard
        id="kpi-high"
        label="High"
        value={highCount}
        color="#ff6b35"
        icon="▲"
        sub="SESSION"
        subColor="#ff6b35"
      />
      <StatCard
        id="kpi-medium"
        label="Medium"
        value={mediumCount}
        color="#ffaa00"
        icon="◆"
        sub="SESSION"
        subColor="#ffaa00"
      />

      {/* ── Row 2: Main panels ───────────────────────────────────── */}

      {/* Threat Map — 2 cols wide */}
      <div className="cyber-panel cyber-corners col-span-2" style={{ minHeight: '260px' }}>
        <div className="cyber-panel-header">
          <PanelTitle color="#00ff9d" icon="⊕">THREAT MAP — Active Connections</PanelTitle>
          <LiveDot />
        </div>
        <div className="relative" style={{ height: 'calc(100% - 44px)' }}>
          <ThreatMap className="absolute inset-0" />
          {liveThreats.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-gray-600 text-xs font-mono">Awaiting network data...</span>
            </div>
          )}
        </div>
      </div>

      {/* Radar + Gauge stacked */}
      <div className="flex flex-col gap-3">
        <div className="cyber-panel flex-1" style={{ minHeight: '130px' }}>
          <div className="cyber-panel-header">
            <PanelTitle color="#00d4ff" icon="◎">RADAR SWEEP</PanelTitle>
          </div>
          <div className="relative" style={{ height: 'calc(100% - 44px)' }}>
            <RadarPulse className="absolute inset-0" />
          </div>
        </div>
        <div className="cyber-panel flex-1" style={{ minHeight: '130px' }}>
          <div className="cyber-panel-header">
            <PanelTitle color="#ffaa00" icon="⊙">THREAT SCORE</PanelTitle>
          </div>
          <div className="relative" style={{ height: 'calc(100% - 44px)' }}>
            <ThreatGauge score={currentThreatScore} className="absolute inset-0" />
          </div>
        </div>
      </div>

      {/* Alert Drill-down or MITRE panel */}
      <div className="cyber-panel row-span-2 overflow-hidden" style={{ minHeight: '260px' }}>
        {selectedAlert
          ? <AlertPanel className="h-full" />
          : <MitrePanel className="h-full" />
        }
      </div>

      {/* ── Row 3: Bottom panels ─────────────────────────────────── */}

      {/* Attack Timeline */}
      <div className="cyber-panel col-span-2" style={{ minHeight: '200px' }}>
        <div className="cyber-panel-header">
          <PanelTitle color="#ff6b35" icon="⇶">ATTACK TIMELINE — Live Events</PanelTitle>
          <LiveDot />
        </div>
        <div style={{ height: 'calc(100% - 44px)', overflow: 'hidden', padding: '8px' }}>
          <AttackTimeline className="h-full" />
        </div>
      </div>

      {/* Anomaly Heatmap */}
      <div className="cyber-panel" style={{ minHeight: '200px' }}>
        <div className="cyber-panel-header">
          <PanelTitle color="#00ff9d" icon="▦">ANOMALY HEATMAP — 15W</PanelTitle>
        </div>
        <div className="p-3 h-[calc(100%-44px)] overflow-auto flex items-start">
          <AnomalyHeatmap />
        </div>
      </div>

      {/* System Health — already occupies the rightmost column via row-span-2 above.
           But we need it outside that span. Use a separate cell. */}
      <div className="cyber-panel" style={{ minHeight: '200px', gridColumn: 4, gridRow: 3 }}>
        <div className="cyber-panel-header">
          <PanelTitle color="#00d4ff" icon="◈">SYSTEM HEALTH</PanelTitle>
        </div>
        <div className="p-3 h-[calc(100%-44px)] overflow-y-auto">
          <SystemHealth />
        </div>
      </div>
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ id, label, value, color, icon, sub, subColor }) {
  return (
    <div id={id} className="cyber-panel cyber-corners p-4 flex items-center gap-4">
      <div className="text-2xl" style={{ color, textShadow: `0 0 12px ${color}80` }}>{icon}</div>
      <div className="flex-1">
        <div className="stat-number" style={{ color, textShadow: `0 0 8px ${color}60` }}>
          {value.toLocaleString()}
        </div>
        <div className="text-gray-500 text-[10px] font-mono uppercase tracking-wider">{label}</div>
      </div>
      <div className="text-right">
        <span className="text-[9px] font-['Orbitron',sans-serif] font-bold" style={{ color: subColor }}>
          {sub}
        </span>
      </div>
    </div>
  )
}

function PanelTitle({ children, color, icon }) {
  return (
    <div className="flex items-center gap-1.5 flex-1">
      <span className="text-xs" style={{ color }}>{icon}</span>
      <span className="text-[10px] font-['Orbitron',sans-serif] font-bold tracking-widest uppercase" style={{ color }}>
        {children}
      </span>
    </div>
  )
}

function LiveDot() {
  return (
    <div className="flex items-center gap-1.5">
      <span className="pulse-dot pulse-dot-green w-1.5 h-1.5" />
      <span className="text-[9px] font-mono text-cyber-green/50">LIVE</span>
    </div>
  )
}
