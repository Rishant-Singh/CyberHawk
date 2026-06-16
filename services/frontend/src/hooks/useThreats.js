import { useEffect, useCallback, useRef } from 'react'
import axios from 'axios'
import useThreatStore from '../store/threatStore'

const API_BASE = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:8000'
const POLL_INTERVAL_MS = 15_000

/**
 * Polls the REST API for alerts and network graph data.
 * Also syncs heatmap data.
 */
export function useThreats() {
  const { accessToken, setAlerts, setNetworkGraph, setHeatmapData } = useThreatStore()
  const timerRef = useRef(null)

  const fetchAlerts = useCallback(async () => {
    if (!accessToken) return
    try {
      const res = await axios.get(`${API_BASE}/api/alerts`, {
        headers: { Authorization: `Bearer ${accessToken}` },
        params: { page: 1, size: 50 },
      })
      const { items, total } = res.data
      setAlerts(items || [], total || 0)

      // Build heatmap data from alerts (count per hour in last 7 days)
      const heatmap = buildHeatmap(items || [])
      setHeatmapData(heatmap)

      // Build network graph from recent alerts
      const { nodes, edges } = buildNetworkGraph(items || [])
      setNetworkGraph(nodes, edges)
    } catch (err) {
      console.warn('[useThreats] Failed to fetch alerts:', err?.message)
    }
  }, [accessToken, setAlerts, setNetworkGraph, setHeatmapData])

  useEffect(() => {
    fetchAlerts()
    timerRef.current = setInterval(fetchAlerts, POLL_INTERVAL_MS)
    return () => clearInterval(timerRef.current)
  }, [fetchAlerts])

  return { refetch: fetchAlerts }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function buildHeatmap(alerts) {
  const counts = {}
  alerts.forEach((a) => {
    if (!a.timestamp) return
    const d = new Date(a.timestamp)
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}`
    counts[key] = (counts[key] || 0) + 1
  })
  return Object.entries(counts).map(([key, count]) => {
    const [year, month, day, hour] = key.split('-').map(Number)
    return { date: new Date(year, month, day, hour), count }
  })
}

function buildNetworkGraph(alerts) {
  const nodeMap = new Map()
  const edges = []

  alerts.slice(0, 80).forEach((a) => {
    const src = a.src_ip
    const dst = a.dst_ip
    if (!src || !dst) return

    if (!nodeMap.has(src)) {
      nodeMap.set(src, {
        id: src,
        type: 'attacker',
        threat_level: a.threat_level || 'MEDIUM',
        threat_score: a.threat_score || 50,
        connections: 0,
      })
    }
    const srcNode = nodeMap.get(src)
    srcNode.connections++
    if ((a.threat_score || 0) > srcNode.threat_score) {
      srcNode.threat_score = a.threat_score
      srcNode.threat_level = a.threat_level
    }

    if (!nodeMap.has(dst)) {
      nodeMap.set(dst, { id: dst, type: 'target', threat_level: 'INFO', threat_score: 0, connections: 0 })
    }
    nodeMap.get(dst).connections++

    edges.push({ source: src, target: dst, threat_level: a.threat_level || 'MEDIUM' })
  })

  return { nodes: Array.from(nodeMap.values()), edges }
}
