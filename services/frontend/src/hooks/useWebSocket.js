import { useEffect, useRef, useCallback } from 'react'
import useThreatStore from '../store/threatStore'

const WS_URL = typeof __WS_URL__ !== 'undefined' ? __WS_URL__ : 'ws://localhost:8000'

export function useWebSocket() {
  const wsRef = useRef(null)
  const reconnectTimerRef = useRef(null)
  const reconnectAttemptsRef = useRef(0)

  const { accessToken, addLiveThreat, updateThreatScore, setWsConnected, setSystemHealth } =
    useThreatStore()

  const connect = useCallback(() => {
    if (!accessToken) return
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const url = `${WS_URL}/ws/live?token=${encodeURIComponent(accessToken)}`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      console.log('[WS] Connected to threat stream')
      setWsConnected(true)
      reconnectAttemptsRef.current = 0

      // Keepalive ping every 30s
      const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'PING' }))
        } else {
          clearInterval(pingInterval)
        }
      }, 30000)
      ws._pingInterval = pingInterval
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'THREAT_EVENT') {
          addLiveThreat(msg.data)
          updateThreatScore()
        } else if (msg.type === 'SYSTEM_HEALTH') {
          setSystemHealth(msg.data)
        }
      } catch (e) {
        console.warn('[WS] Failed to parse message:', e)
      }
    }

    ws.onerror = (err) => {
      console.warn('[WS] Error:', err)
    }

    ws.onclose = (event) => {
      setWsConnected(false)
      if (ws._pingInterval) clearInterval(ws._pingInterval)

      if (event.code !== 4001 && reconnectAttemptsRef.current < 10) {
        const delay = Math.min(1000 * 2 ** reconnectAttemptsRef.current, 30000)
        reconnectAttemptsRef.current++
        console.log(`[WS] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current})`)
        reconnectTimerRef.current = setTimeout(connect, delay)
      }
    }
  }, [accessToken, addLiveThreat, updateThreatScore, setWsConnected, setSystemHealth])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      if (wsRef.current) {
        wsRef.current.onclose = null // Prevent reconnect on unmount
        wsRef.current.close()
      }
    }
  }, [connect])
}
