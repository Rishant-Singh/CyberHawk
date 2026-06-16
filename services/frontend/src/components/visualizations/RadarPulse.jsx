import { useEffect, useRef, useMemo } from 'react'
import useThreatStore from '../../store/threatStore'

const LEVEL_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff6b35',
  MEDIUM: '#ffaa00',
  LOW: '#00d4ff',
  INFO: '#00ff9d',
}

const BLIP_LIFETIME_MS = 6000

export default function RadarPulse({ className = '' }) {
  const canvasRef = useRef(null)
  const blipsRef = useRef([])
  const rafRef = useRef(null)
  const sweepAngleRef = useRef(0)
  const { liveThreats } = useThreatStore()

  // Add new blips from threats
  useEffect(() => {
    if (liveThreats.length === 0) return
    const latest = liveThreats[0]
    if (!latest || latest.threat_level === 'INFO') return

    const canvas = canvasRef.current
    if (!canvas) return
    const cx = canvas.width / 2
    const cy = canvas.height / 2
    const r = Math.min(cx, cy) - 20

    // Place blip at random position within radar range
    const angle = Math.random() * Math.PI * 2
    const dist = Math.random() * r * 0.85
    blipsRef.current.push({
      x: cx + Math.cos(angle) * dist,
      y: cy + Math.sin(angle) * dist,
      level: latest.threat_level,
      score: latest.threat_score,
      born: Date.now(),
      alpha: 1,
    })

    // Keep max 30 blips
    if (blipsRef.current.length > 30) {
      blipsRef.current.shift()
    }
  }, [liveThreats])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    const resize = () => {
      const parent = canvas.parentElement
      canvas.width = parent.offsetWidth
      canvas.height = parent.offsetHeight
    }
    resize()
    const observer = new ResizeObserver(resize)
    observer.observe(canvas.parentElement)

    const SWEEP_SPEED = 0.02

    const draw = () => {
      const w = canvas.width
      const h = canvas.height
      const cx = w / 2
      const cy = h / 2
      const r = Math.min(cx, cy) - 16

      ctx.clearRect(0, 0, w, h)

      // Background
      const bgGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, r)
      bgGrad.addColorStop(0, 'rgba(0, 255, 157, 0.03)')
      bgGrad.addColorStop(1, 'rgba(0, 0, 0, 0)')
      ctx.fillStyle = bgGrad
      ctx.fillRect(0, 0, w, h)

      // Grid rings
      ctx.strokeStyle = 'rgba(0, 255, 157, 0.1)'
      ctx.lineWidth = 0.5
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath()
        ctx.arc(cx, cy, (r * i) / 4, 0, Math.PI * 2)
        ctx.stroke()
      }

      // Crosshairs
      ctx.beginPath()
      ctx.moveTo(cx - r, cy); ctx.lineTo(cx + r, cy)
      ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy + r)
      ctx.strokeStyle = 'rgba(0, 255, 157, 0.08)'
      ctx.stroke()

      // Outer ring
      ctx.beginPath()
      ctx.arc(cx, cy, r, 0, Math.PI * 2)
      ctx.strokeStyle = 'rgba(0, 255, 157, 0.3)'
      ctx.lineWidth = 1.5
      ctx.stroke()

      // Sweep gradient
      sweepAngleRef.current = (sweepAngleRef.current + SWEEP_SPEED) % (Math.PI * 2)
      const sweep = sweepAngleRef.current

      const sweepGrad = ctx.createConicalGradient
        ? null // Not available in all browsers
        : null

      // Manual sweep arc
      for (let i = 0; i < 60; i++) {
        const a = sweep - (i * Math.PI * 2) / 360
        const alpha = ((60 - i) / 60) * 0.3
        ctx.beginPath()
        ctx.moveTo(cx, cy)
        ctx.arc(cx, cy, r, a - 0.02, a)
        ctx.fillStyle = `rgba(0, 255, 157, ${alpha})`
        ctx.fill()
      }

      // Sweep line
      ctx.beginPath()
      ctx.moveTo(cx, cy)
      ctx.lineTo(cx + Math.cos(sweep) * r, cy + Math.sin(sweep) * r)
      ctx.strokeStyle = 'rgba(0, 255, 157, 0.9)'
      ctx.lineWidth = 1.5
      ctx.stroke()

      // Center dot
      ctx.beginPath()
      ctx.arc(cx, cy, 3, 0, Math.PI * 2)
      ctx.fillStyle = '#00ff9d'
      ctx.fill()

      // Blips
      const now = Date.now()
      blipsRef.current = blipsRef.current.filter((b) => now - b.born < BLIP_LIFETIME_MS)

      blipsRef.current.forEach((blip) => {
        const age = (now - blip.born) / BLIP_LIFETIME_MS
        const alpha = 1 - age
        const color = LEVEL_COLORS[blip.level] || '#00ff9d'
        const size = blip.level === 'CRITICAL' ? 6 : blip.level === 'HIGH' ? 5 : 4

        // Blip core
        ctx.beginPath()
        ctx.arc(blip.x, blip.y, size * (1 - age * 0.3), 0, Math.PI * 2)
        ctx.fillStyle = color
        ctx.globalAlpha = alpha * 0.9
        ctx.fill()
        ctx.globalAlpha = 1

        // Blip ring
        const ringR = size + age * 20
        ctx.beginPath()
        ctx.arc(blip.x, blip.y, ringR, 0, Math.PI * 2)
        ctx.strokeStyle = color
        ctx.lineWidth = 1
        ctx.globalAlpha = alpha * 0.5
        ctx.stroke()
        ctx.globalAlpha = 1
      })

      // Range labels
      ctx.fillStyle = 'rgba(0, 255, 157, 0.35)'
      ctx.font = '9px JetBrains Mono, monospace'
      ctx.textAlign = 'center'
      ;[25, 50, 75, 100].forEach((pct, i) => {
        ctx.fillText(`${pct}%`, cx + 6, cy - ((i + 1) * r) / 4 + 3)
      })

      rafRef.current = requestAnimationFrame(draw)
    }

    draw()

    return () => {
      cancelAnimationFrame(rafRef.current)
      observer.disconnect()
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className={`w-full h-full ${className}`}
      style={{ display: 'block' }}
    />
  )
}
