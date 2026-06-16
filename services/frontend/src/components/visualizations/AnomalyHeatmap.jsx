import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import useThreatStore from '../../store/threatStore'

const CELL_SIZE = 14
const WEEKS = 15
const DAYS = 7
const DAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const COLOR_SCALE = ['#0d1424', '#0d2a1c', '#0a4d2e', '#00a85e', '#00ff9d']

export default function AnomalyHeatmap({ className = '' }) {
  const svgRef = useRef(null)
  const { heatmapData, liveThreats } = useThreatStore()

  useEffect(() => {
    if (!svgRef.current) return

    // Build cell data from heatmap store data + live threats
    const counts = new Map()

    // From store
    heatmapData.forEach(({ date, count }) => {
      const key = dateKey(new Date(date))
      counts.set(key, (counts.get(key) || 0) + count)
    })

    // Also count live threats by day
    liveThreats.forEach((t) => {
      if (!t.timestamp) return
      const key = dateKey(new Date(t.timestamp))
      counts.set(key, (counts.get(key) || 0) + 1)
    })

    // Generate date range: last WEEKS weeks
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const startDate = new Date(today)
    startDate.setDate(today.getDate() - WEEKS * 7 + 1)

    const cells = []
    for (let i = 0; i < WEEKS * DAYS; i++) {
      const d = new Date(startDate)
      d.setDate(startDate.getDate() + i)
      const key = dateKey(d)
      cells.push({ date: d, count: counts.get(key) || 0, key })
    }

    const maxCount = Math.max(1, d3.max(cells, (c) => c.count))
    const colorFn = d3.scaleQuantize().domain([0, maxCount]).range(COLOR_SCALE)

    const margin = { top: 20, left: 30, right: 8, bottom: 8 }
    const width = WEEKS * (CELL_SIZE + 2) + margin.left + margin.right
    const height = DAYS * (CELL_SIZE + 2) + margin.top + margin.bottom

    const svg = d3.select(svgRef.current)
    svg.attr('width', width).attr('height', height)
    svg.selectAll('*').remove()

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`)

    // Day labels
    DAY_LABELS.forEach((label, i) => {
      if (i % 2 === 0) {
        g.append('text')
          .attr('x', -4)
          .attr('y', i * (CELL_SIZE + 2) + CELL_SIZE / 2 + 4)
          .attr('text-anchor', 'end')
          .attr('font-size', '8px')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('fill', 'rgba(160,176,192,0.5)')
          .text(label)
      }
    })

    // Month labels
    const monthsSeen = new Set()
    cells.forEach((c, i) => {
      const month = c.date.toLocaleString('default', { month: 'short' })
      const week = Math.floor(i / DAYS)
      if (!monthsSeen.has(month)) {
        monthsSeen.add(month)
        g.append('text')
          .attr('x', week * (CELL_SIZE + 2))
          .attr('y', -6)
          .attr('font-size', '8px')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('fill', 'rgba(160,176,192,0.5)')
          .text(month)
      }
    })

    // Tooltip
    const tooltip = d3.select('body').selectAll('.d3-tooltip-heatmap')
      .data([null]).join('div')
      .attr('class', 'd3-tooltip d3-tooltip-heatmap')
      .style('display', 'none')

    // Cells
    g.selectAll('rect')
      .data(cells)
      .join('rect')
      .attr('width', CELL_SIZE)
      .attr('height', CELL_SIZE)
      .attr('x', (c) => Math.floor(cells.indexOf(c) / DAYS) * (CELL_SIZE + 2))
      .attr('y', (c) => c.date.getDay() * (CELL_SIZE + 2))
      .attr('rx', 2)
      .attr('fill', (c) => c.count === 0 ? '#0d1424' : colorFn(c.count))
      .attr('stroke', (c) => c.count > 0 ? 'rgba(0,255,157,0.15)' : 'rgba(0,255,157,0.04)')
      .attr('stroke-width', 0.5)
      .style('cursor', 'default')
      .on('mouseenter', function (event, c) {
        d3.select(this).attr('stroke', 'rgba(0,255,157,0.7)').attr('stroke-width', 1)
        tooltip.style('display', 'block')
          .style('left', (event.clientX + 12) + 'px')
          .style('top', (event.clientY - 10) + 'px')
          .html(`
            <div style="color:#a0b0c0;font-size:11px">${c.date.toLocaleDateString()}</div>
            <div style="color:#00ff9d;font-size:12px;margin-top:2px">${c.count} anomalies</div>
          `)
      })
      .on('mousemove', (event) => {
        tooltip.style('left', (event.clientX + 12) + 'px').style('top', (event.clientY - 10) + 'px')
      })
      .on('mouseleave', function () {
        d3.select(this).attr('stroke', (c) => c.count > 0 ? 'rgba(0,255,157,0.15)' : 'rgba(0,255,157,0.04)')
          .attr('stroke-width', 0.5)
        tooltip.style('display', 'none')
      })

    // Legend
    const legendG = svg.append('g').attr('transform', `translate(${margin.left},${height - 10})`)
    legendG.append('text').text('Less').attr('x', 0).attr('y', 8)
      .attr('font-size', '8px').attr('fill', 'rgba(160,176,192,0.4)').attr('font-family', 'JetBrains Mono, monospace')
    COLOR_SCALE.forEach((c, i) => {
      legendG.append('rect').attr('x', 28 + i * (CELL_SIZE + 2)).attr('y', 0)
        .attr('width', CELL_SIZE).attr('height', CELL_SIZE).attr('rx', 2).attr('fill', c)
    })
    legendG.append('text').text('More').attr('x', 28 + COLOR_SCALE.length * (CELL_SIZE + 2) + 4).attr('y', 8)
      .attr('font-size', '8px').attr('fill', 'rgba(160,176,192,0.4)').attr('font-family', 'JetBrains Mono, monospace')

    return () => tooltip.remove()
  }, [heatmapData, liveThreats])

  return (
    <div className={`overflow-x-auto ${className}`}>
      <svg ref={svgRef} />
    </div>
  )
}

function dateKey(d) {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}
