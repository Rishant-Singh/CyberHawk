import { create } from 'zustand'

const MAX_LIVE_THREATS = 200

const useThreatStore = create((set, get) => ({
  // Auth
  user: null,
  accessToken: localStorage.getItem('cti_token') || null,
  isAuthenticated: !!localStorage.getItem('cti_token'),

  setAuth: (user, token) => {
    localStorage.setItem('cti_token', token)
    set({ user, accessToken: token, isAuthenticated: true })
  },
  logout: () => {
    localStorage.removeItem('cti_token')
    set({ user: null, accessToken: null, isAuthenticated: false, liveThreats: [] })
  },

  // Live threats (from WebSocket)
  liveThreats: [],
  totalThreatsDetected: 0,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,

  addLiveThreat: (threat) => {
    set((state) => {
      const updated = [threat, ...state.liveThreats].slice(0, MAX_LIVE_THREATS)
      const level = threat.threat_level
      return {
        liveThreats: updated,
        totalThreatsDetected: state.totalThreatsDetected + 1,
        criticalCount: state.criticalCount + (level === 'CRITICAL' ? 1 : 0),
        highCount: state.highCount + (level === 'HIGH' ? 1 : 0),
        mediumCount: state.mediumCount + (level === 'MEDIUM' ? 1 : 0),
      }
    })
  },

  // Current threat score (rolling average of last 20)
  currentThreatScore: 0,
  updateThreatScore: () => {
    const { liveThreats } = get()
    if (liveThreats.length === 0) return
    const recent = liveThreats.slice(0, 20)
    const avg = recent.reduce((s, t) => s + (t.threat_score || 0), 0) / recent.length
    set({ currentThreatScore: Math.round(avg) })
  },

  // Selected alert for drill-down
  selectedAlert: null,
  setSelectedAlert: (alert) => set({ selectedAlert: alert }),

  // Network graph data
  networkNodes: [],
  networkEdges: [],
  setNetworkGraph: (nodes, edges) => set({ networkNodes: nodes, networkEdges: edges }),

  // System health
  systemHealth: null,
  setSystemHealth: (health) => set({ systemHealth: health }),

  // WebSocket status
  wsConnected: false,
  setWsConnected: (connected) => set({ wsConnected: connected }),

  // Heatmap data
  heatmapData: [],
  setHeatmapData: (data) => set({ heatmapData: data }),

  // Alerts list
  alerts: [],
  alertsTotal: 0,
  setAlerts: (alerts, total) => set({ alerts, alertsTotal: total }),
}))

export default useThreatStore
