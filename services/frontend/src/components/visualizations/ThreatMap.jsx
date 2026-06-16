import { useEffect, useRef, useCallback } from 'react'
import * as d3 from 'd3'
import useThreatStore from '../../store/threatStore'

const LEVEL_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff6b35',
  MEDIUM: '#ffaa00',
  LOW: '#00d4ff',
  INFO: '#00ff9d',
}

const LEVEL_RADIUS = {
  CRITICAL: 14,
  HIGH: 11,
  MEDIUM: 9,
  LOW: 7,
  INFO: 5,
}

export default function ThreatMap({ className = '' }) {
  const svgRef = useRef(null)
  const simulationRef = useRef(null)
  const { networkNodes, networkEdges, setSelectedAlert, liveThreats } = useThreatStore()

  const buildGraph = useCallback(() => {
    if (!svgRef.current) return

    const container = svgRef.current.parentElement
    const width = container.offsetWidth
    const height = container.offsetHeight

    const svg = d3.select(svgRef.current)
    svg.attr('width', width).attr('height', height)

    // Use live threats to build dynamic graph
    const threatMap = new Map()
    const edgeSet = []

    liveThreats.slice(0, 60).forEach((t) => {
      if (!t.src_ip || !t.dst_ip) return
      if (!threatMap.has(t.src_ip)) {
        threatMap.set(t.src_ip, {
          id: t.src_ip,
          type: 'attacker',
          threat_level: t.threat_level,
          threat_score: t.threat_score,
          country: t.geo_country,
          connections: 0,
        })
      }
      const node = threatMap.get(t.src_ip)
      if (t.threat_score > node.threat_score) {
        node.threat_score = t.threat_score
        node.threat_level = t.threat_level
      }
      node.connections++

      if (!threatMap.has(t.dst_ip)) {
        threatMap.set(t.dst_ip, {
          id: t.dst_ip,
          type: 'target',
          threat_level: 'INFO',
          threat_score: 0,
          connections: 0,
        })
      }

      edgeSet.push({
        source: t.src_ip,
        target: t.dst_ip,
        threat_level: t.threat_level,
        threat_score: t.threat_score,
        id: `${t.src_ip}-${t.dst_ip}`,
      })
    })

    const nodes = Array.from(threatMap.values())
    const edges = edgeSet.slice(0, 100)

    if (nodes.length === 0) return

    svg.selectAll('*').remove()

    // Defs: glow filters + arrowhead
    const defs = svg.append('defs')
    
    Object.entries(LEVEL_COLORS).forEach(([level, color]) => {
      const filter = defs.append('filter').attr('id', `glow-${level}`).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%')
      filter.append('feGaussianBlur').attr('stdDeviation', level === 'CRITICAL' ? '4' : '2').attr('result', 'coloredBlur')
      const feMerge = filter.append('feMerge')
      feMerge.append('feMergeNode').attr('in', 'coloredBlur')
      feMerge.append('feMergeNode').attr('in', 'SourceGraphic')
    })

    defs.append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '-0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('orient', 'auto')
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .append('path')
      .attr('d', 'M 0,-5 L 10 ,0 L 0,5')
      .attr('fill', 'rgba(0, 255, 157, 0.4)')

    // Background
    svg.append('rect').attr('width', width).attr('height', height).attr('fill', 'transparent')

    const g = svg.append('g')

    // Zoom
    svg.call(d3.zoom()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => g.attr('transform', event.transform))
    )

    // Force simulation
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id((d) => d.id).distance(80).strength(0.3))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius((d) => LEVEL_RADIUS[d.threat_level] + 8))
    simulationRef.current = sim

    // Edges
    const link = g.append('g').selectAll('line').data(edges).join('line')
      .attr('stroke-width', (d) => Math.max(1, d.threat_score / 40))
      .attr('stroke-opacity', 0.5)
      .attr('class', (d) => `link-${d.threat_level.toLowerCase()}`)
      .attr('marker-end', 'url(#arrowhead)')

    // Nodes group
    const node = g.append('g').selectAll('g').data(nodes).join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) sim.alphaTarget(0.3).restart()
          d.fx = d.x; d.fy = d.y
        })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y })
        .on('end', (event, d) => {
          if (!event.active) sim.alphaTarget(0)
          d.fx = null; d.fy = null
        })
      )

    // Pulse ring for critical/high nodes
    node.filter((d) => ['CRITICAL', 'HIGH'].includes(d.threat_level))
      .append('circle')
      .attr('r', (d) => LEVEL_RADIUS[d.threat_level] + 8)
      .attr('fill', 'none')
      .attr('stroke', (d) => LEVEL_COLORS[d.threat_level])
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0)
      .each(function(d) {
        d3.select(this)
          .transition()
          .duration(1500)
          .ease(d3.easeLinear)
          .attr('r', LEVEL_RADIUS[d.threat_level] + 20)
          .attr('stroke-opacity', 0.6)
          .transition()
          .duration(1000)
          .attr('stroke-opacity', 0)
          .on('end', function repeat() {
            d3.select(this)
              .attr('r', LEVEL_RADIUS[d.threat_level] + 8)
              .attr('stroke-opacity', 0)
              .transition().duration(1500)
              .attr('r', LEVEL_RADIUS[d.threat_level] + 20)
              .attr('stroke-opacity', 0.6)
              .transition().duration(1000)
              .attr('stroke-opacity', 0)
              .on('end', repeat)
          })
      })

    // Node circles
    node.append('circle')
      .attr('r', (d) => LEVEL_RADIUS[d.threat_level] || 5)
      .attr('fill', (d) => LEVEL_COLORS[d.threat_level] || '#00ff9d')
      .attr('fill-opacity', 0.85)
      .attr('filter', (d) => `url(#glow-${d.threat_level})`)
      .attr('stroke', (d) => LEVEL_COLORS[d.threat_level])
      .attr('stroke-width', 1.5)

    // Node labels
    node.append('text')
      .text((d) => d.id.length > 15 ? d.id.slice(0, 13) + '…' : d.id)
      .attr('x', 0)
      .attr('y', (d) => LEVEL_RADIUS[d.threat_level] + 12)
      .attr('text-anchor', 'middle')
      .attr('fill', (d) => LEVEL_COLORS[d.threat_level])
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('opacity', 0.7)

    // Tooltip
    const tooltip = d3.select('body').selectAll('.d3-tooltip-map')
      .data([null])
      .join('div')
      .attr('class', 'd3-tooltip d3-tooltip-map')
      .style('display', 'none')

    node
      .on('mouseenter', (event, d) => {
        tooltip
          .style('display', 'block')
          .style('left', (event.clientX + 12) + 'px')
          .style('top', (event.clientY - 10) + 'px')
          .html(`
            <div style="color:${LEVEL_COLORS[d.threat_level]};font-family:Orbitron,sans-serif;font-size:11px;margin-bottom:4px">${d.threat_level}</div>
            <div style="color:#a0b0c0;font-size:11px">IP: <span style="color:#e0e8ff">${d.id}</span></div>
            <div style="color:#a0b0c0;font-size:11px">Score: <span style="color:#e0e8ff">${d.threat_score}</span></div>
            <div style="color:#a0b0c0;font-size:11px">Connections: <span style="color:#e0e8ff">${d.connections}</span></div>
            ${d.country ? `<div style="color:#a0b0c0;font-size:11px">Country: <span style="color:#e0e8ff">${d.country}</span></div>` : ''}
          `)
      })
      .on('mousemove', (event) => {
        tooltip
          .style('left', (event.clientX + 12) + 'px')
          .style('top', (event.clientY - 10) + 'px')
      })
      .on('mouseleave', () => tooltip.style('display', 'none'))
      .on('click', (event, d) => {
        const threat = liveThreats.find((t) => t.src_ip === d.id)
        if (threat) setSelectedAlert(threat)
      })

    sim.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y)
      node.attr('transform', (d) => `translate(${d.x},${d.y})`)
    })

    return () => {
      sim.stop()
      tooltip.remove()
    }
  }, [liveThreats, setSelectedAlert])

  useEffect(() => {
    const cleanup = buildGraph()
    return cleanup
  }, [buildGraph])

  // Rebuild on resize
  useEffect(() => {
    const observer = new ResizeObserver(() => buildGraph())
    if (svgRef.current?.parentElement) observer.observe(svgRef.current.parentElement)
    return () => observer.disconnect()
  }, [buildGraph])

  return (
    <svg
      ref={svgRef}
      className={`w-full h-full ${className}`}
      style={{ display: 'block' }}
    />
  )
}
