import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import useThreatStore from '../../store/threatStore'

export default function ThreatGauge({ className = '' }) {
  const svgRef = useRef(null)
  const { currentThreatScore } = useThreatStore()

  useEffect(() => {
    if (!svgRef.current) return

    const score = Math.max(0, Math.min(100, currentThreatScore))
    const W = 220, H = 160
    const cx = W / 2, cy = H - 20
    const outerR = 90, innerR = 62
    const startAngle = -Math.PI * 0.8
    const endAngle = Math.PI * 0.8
    const totalAngle = endAngle - startAngle

    const getColor = (s) => {
      if (s >= 90) return '#ff2d55'
      if (s >= 75) return '#ff6b35'
      if (s >= 50) return '#ffaa00'
      if (s >= 25) return '#00d4ff'
      return '#00ff9d'
    }

    const getLevelLabel = (s) => {
      if (s >= 90) return 'CRITICAL'
      if (s >= 75) return 'HIGH'
      if (s >= 50) return 'MEDIUM'
      if (s >= 25) return 'LOW'
      return 'INFO'
    }

    const color = getColor(score)
    const label = getLevelLabel(score)

    const svg = d3.select(svgRef.current)
      .attr('viewBox', `0 0 ${W} ${H}`)
      .attr('width', '100%')
      .attr('height', '100%')

    svg.selectAll('*').remove()

    const arcGen = d3.arc().innerRadius(innerR).outerRadius(outerR)

    // Track (background)
    const trackArc = arcGen({
      startAngle,
      endAngle,
    })

    // Filled arc (value)
    const fillEndAngle = startAngle + (score / 100) * totalAngle
    const fillArc = arcGen({
      startAngle,
      endAngle: fillEndAngle,
    })

    // Defs: gradient + glow
    const defs = svg.append('defs')
    const gradId = 'gauge-gradient'
    const grad = defs.append('linearGradient').attr('id', gradId).attr('gradientUnits', 'userSpaceOnUse')
      .attr('x1', -outerR).attr('y1', 0).attr('x2', outerR).attr('y2', 0)
    grad.append('stop').attr('offset', '0%').attr('stop-color', '#00ff9d')
    grad.append('stop').attr('offset', '40%').attr('stop-color', '#ffaa00')
    grad.append('stop').attr('offset', '75%').attr('stop-color', '#ff6b35')
    grad.append('stop').attr('offset', '100%').attr('stop-color', '#ff2d55')

    const filterId = 'gauge-glow'
    const filter = defs.append('filter').attr('id', filterId)
    filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur')
    const merge = filter.append('feMerge')
    merge.append('feMergeNode').attr('in', 'blur')
    merge.append('feMergeNode').attr('in', 'SourceGraphic')

    const g = svg.append('g').attr('transform', `translate(${cx}, ${cy})`)

    // Track
    g.append('path').attr('d', trackArc).attr('fill', '#1a2540').attr('opacity', 0.8)

    // Tick marks
    for (let i = 0; i <= 10; i++) {
      const tickAngle = startAngle + (i / 10) * totalAngle
      const isMain = i % 5 === 0
      const r1 = outerR + (isMain ? 6 : 3)
      const r2 = outerR + 1
      g.append('line')
        .attr('x1', Math.sin(tickAngle) * r2)
        .attr('y1', -Math.cos(tickAngle) * r2)
        .attr('x2', Math.sin(tickAngle) * r1)
        .attr('y2', -Math.cos(tickAngle) * r1)
        .attr('stroke', isMain ? 'rgba(0,255,157,0.5)' : 'rgba(0,255,157,0.2)')
        .attr('stroke-width', isMain ? 1.5 : 0.8)
    }

    // Fill arc
    const fillPath = g.append('path')
      .attr('d', arcGen({ startAngle, endAngle: startAngle }))
      .attr('fill', `url(#${gradId})`)
      .attr('filter', `url(#${filterId})`)

    fillPath.transition()
      .duration(800)
      .ease(d3.easeBackOut.overshoot(0.5))
      .attrTween('d', () => {
        const interp = d3.interpolate(startAngle, fillEndAngle)
        return (t) => arcGen({ startAngle, endAngle: interp(t) })
      })

    // Needle
    const needleAngle = startAngle + (score / 100) * totalAngle
    const needleLen = innerR - 8

    const needle = g.append('g').attr('class', 'needle')

    needle.append('line')
      .attr('x1', 0).attr('y1', 0)
      .attr('x2', 0).attr('y2', -needleLen)
      .attr('stroke', color)
      .attr('stroke-width', 2.5)
      .attr('stroke-linecap', 'round')
      .style('filter', `drop-shadow(0 0 4px ${color})`)
      .transition()
      .duration(800)
      .ease(d3.easeBackOut)
      .attrTween('transform', () => {
        const interp = d3.interpolate(startAngle * (180 / Math.PI), needleAngle * (180 / Math.PI))
        return (t) => `rotate(${interp(t)})`
      })

    // Center cap
    g.append('circle').attr('r', 6).attr('fill', color).attr('stroke', '#0a0e1a').attr('stroke-width', 2)
      .style('filter', `drop-shadow(0 0 6px ${color})`)

    // Score number
    const scoreText = g.append('text')
      .attr('y', -outerR * 0.2)
      .attr('text-anchor', 'middle')
      .attr('fill', color)
      .attr('font-family', 'Orbitron, sans-serif')
      .attr('font-weight', '700')
      .attr('font-size', '28px')
      .style('filter', `drop-shadow(0 0 8px ${color})`)
      .text('0')

    scoreText.transition()
      .duration(800)
      .tween('text', () => {
        const interp = d3.interpolateNumber(0, score)
        return (t) => { scoreText.text(Math.round(interp(t))) }
      })

    // Level label
    g.append('text')
      .attr('y', outerR * 0.15)
      .attr('text-anchor', 'middle')
      .attr('fill', color)
      .attr('font-family', 'Orbitron, sans-serif')
      .attr('font-weight', '600')
      .attr('font-size', '9px')
      .attr('letter-spacing', '0.15em')
      .style('filter', `drop-shadow(0 0 4px ${color})`)
      .text(label)

    // Scale labels
    ;[['0', -totalAngle / 2], ['50', 0], ['100', totalAngle / 2]].forEach(([text, offset]) => {
      const a = startAngle + totalAngle / 2 + offset
      const labelR = outerR + 18
      g.append('text')
        .attr('x', Math.sin(a) * labelR)
        .attr('y', -Math.cos(a) * labelR + 3)
        .attr('text-anchor', 'middle')
        .attr('fill', 'rgba(160, 176, 200, 0.6)')
        .attr('font-size', '8px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .text(text)
    })

  }, [currentThreatScore])

  return (
    <svg
      ref={svgRef}
      className={`w-full h-full ${className}`}
      style={{ display: 'block', overflow: 'visible' }}
    />
  )
}
