import { useState, useCallback, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import { MapContainer, TileLayer, CircleMarker, Tooltip, useMap } from 'react-leaflet'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'
import { toast } from 'react-hot-toast'

// Fly-to controller for the inline modal map
function ModalMapController({ center, zoom }) {
  const map = useMap()
  useEffect(() => {
    if (center && center[0] != null && center[1] != null) {
      map.flyTo(center, zoom || 10, { duration: 1.2 })
    }
  }, [center, zoom, map])
  return null
}

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const EXAMPLE_IOCS = [
  { label: 'Public Threat IP (DE)', val: '185.220.101.1' },
  { label: 'Lab Asset (Linux)', val: '10.0.0.25' },
  { label: 'Lab Asset (DC)', val: '10.0.0.10' },
  { label: 'Netherlands Exit (NL)', val: '192.42.116.14' },
  { label: 'Log4j RCE (CVE)', val: 'CVE-2021-44228' },
  { label: 'Russian Host (RU)', val: '45.142.212.100' },
]

export default function IOCSearch() {
  const navigate = useNavigate()
  const token = useThreatStore((s) => s.accessToken)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [recentIOCs, setRecentIOCs] = useState([])
  const [recentLoading, setRecentLoading] = useState(false)
  const timelineRef = useRef(null)
  const [showMapModal, setShowMapModal] = useState(false)

  const authHeader = { headers: { Authorization: `Bearer ${token}` } }

  const search = useCallback(async (q) => {
    const searchQuery = q || query
    if (!searchQuery.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await axios.get(`${API}/api/ioc/search`, {
        params: { query: searchQuery.trim(), days: 30 },
        ...authHeader,
      })
      setResult(data)
    } catch (e) {
      toast.error('IOC search failed')
    } finally {
      setLoading(false)
    }
  }, [query, token])

  const loadRecent = useCallback(async () => {
    setRecentLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/ioc/recent`, authHeader)
      setRecentIOCs(data)
    } catch { /* silent */ }
    finally { setRecentLoading(false) }
  }, [token])

  useEffect(() => {
    loadRecent()
  }, [loadRecent])

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const handleViewOnMap = () => {
    if (result && result.geo && result.geo.lat != null && result.geo.lon != null) {
      setShowMapModal(true)
    } else {
      toast.error('Geographic coordinates not available for this IOC (Private or shielded IP)')
    }
  }

  const handleOpenFullMap = () => {
    if (result && result.geo && result.geo.lat != null && result.geo.lon != null) {
      const q = new URLSearchParams({
        focus: result.ioc,
        lat: result.geo.lat,
        lon: result.geo.lon,
        country: result.geo.country_name || result.geo.country || '',
        city: result.geo.city || '',
        region: result.geo.region || '',
        zip: result.geo.zip || '',
        isp: result.geo.isp || '',
        asn: result.geo.asn || '',
        hits: result.total_hits || 0,
        reputation: result.reputation || 'clean',
        threat_level: result.threat_level || 'LOW',
      })
      navigate(`/map?${q.toString()}`)
    }
  }

  const handleViewIncidents = () => {
    navigate(`/incidents?search=${encodeURIComponent(result.ioc)}`)
  }

  const handleScrollToTimeline = () => {
    timelineRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  // Determine marker color based on reputation
  const markerColor = result?.reputation === 'malicious' ? '#ff2d55'
    : result?.reputation === 'suspicious' ? '#ff6b35'
    : result?.reputation === 'potentially_unwanted' ? '#ffc400'
    : '#00ff9d'

  return (
    <div className="flex flex-col gap-6 p-1">

      {/* ── Inline Map Modal ─────────────────────────────────────────── */}
      {showMapModal && result?.geo?.lat != null && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(6px)' }}
          onClick={(e) => { if (e.target === e.currentTarget) setShowMapModal(false) }}
        >
          <div
            className="relative rounded-2xl overflow-hidden shadow-2xl border flex flex-col"
            style={{
              width: '92vw',
              maxWidth: '1200px',
              height: '82vh',
              background: 'rgba(6,10,24,0.97)',
              borderColor: 'rgba(0,255,157,0.25)',
              boxShadow: '0 0 60px rgba(0,255,157,0.1), 0 0 120px rgba(0,0,0,0.8)',
            }}
          >
            {/* Modal Header */}
            <div
              className="flex items-center justify-between px-5 py-3.5 border-b flex-shrink-0"
              style={{ borderColor: 'rgba(0,255,157,0.15)', background: 'rgba(5,8,18,0.8)' }}
            >
              <div className="flex items-center gap-3">
                <span className="text-lg">🗺️</span>
                <div>
                  <div className="text-sm font-mono font-bold text-white">
                    IP Geolocation — <span style={{ color: markerColor }}>{result.ioc}</span>
                  </div>
                  <div className="text-[10px] font-mono text-gray-500">
                    {result.geo.city ? `${result.geo.city}, ` : ''}
                    {result.geo.region ? `${result.geo.region}, ` : ''}
                    {result.geo.country_name || result.geo.country || 'Unknown Country'}
                    {result.geo.lat != null ? ` · ${result.geo.lat.toFixed(4)}°N, ${result.geo.lon.toFixed(4)}°E` : ''}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  id="map-modal-open-full"
                  onClick={handleOpenFullMap}
                  className="text-xs font-mono px-3 py-1.5 rounded border font-bold transition-all hover:brightness-125 flex items-center gap-1.5"
                  style={{
                    color: '#00d4ff',
                    borderColor: 'rgba(0,212,255,0.35)',
                    background: 'rgba(0,212,255,0.08)',
                  }}
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" />
                    <polyline points="15 3 21 3 21 9" />
                    <line x1="10" y1="14" x2="21" y2="3" />
                  </svg>
                  Open in Full Map
                </button>
                <button
                  id="map-modal-close"
                  onClick={() => setShowMapModal(false)}
                  className="w-8 h-8 rounded-full border flex items-center justify-center text-gray-400 hover:text-white hover:bg-white/10 transition-all font-mono text-sm font-bold"
                  style={{ borderColor: 'rgba(255,255,255,0.1)' }}
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Map + Info Panel */}
            <div className="flex flex-1 min-h-0">
              {/* Leaflet Map */}
              <div className="flex-1 relative" style={{ filter: 'invert(1) hue-rotate(180deg)' }}>
                <MapContainer
                  center={[result.geo.lat, result.geo.lon]}
                  zoom={10}
                  style={{ width: '100%', height: '100%' }}
                  zoomControl={true}
                  attributionControl={false}
                >
                  <TileLayer
                    url="https://tile.openstreetmap.org/{z}/{x}/{y}.png"
                    attribution="&copy; <a href='https://www.openstreetmap.org/copyright'>OpenStreetMap</a> contributors"
                  />
                  <ModalMapController center={[result.geo.lat, result.geo.lon]} zoom={10} />

                  {/* Outer glow ring */}
                  <CircleMarker
                    center={[result.geo.lat, result.geo.lon]}
                    radius={28}
                    pathOptions={{
                      color: markerColor,
                      fillColor: markerColor,
                      fillOpacity: 0.06,
                      weight: 1,
                      dashArray: '4 4',
                    }}
                  />
                  {/* Middle pulse ring */}
                  <CircleMarker
                    center={[result.geo.lat, result.geo.lon]}
                    radius={16}
                    pathOptions={{
                      color: markerColor,
                      fillColor: markerColor,
                      fillOpacity: 0.12,
                      weight: 1.5,
                    }}
                  />
                  {/* Core marker */}
                  <CircleMarker
                    center={[result.geo.lat, result.geo.lon]}
                    radius={8}
                    pathOptions={{
                      color: markerColor,
                      fillColor: markerColor,
                      fillOpacity: 0.9,
                      weight: 2,
                    }}
                  >
                    <Tooltip permanent direction="top" offset={[0, -12]}
                      className="leaflet-tooltip-cyber"
                    >
                      <span style={{ fontFamily: 'monospace', fontSize: '11px', color: markerColor, fontWeight: 'bold' }}>
                        📍 {result.ioc}
                      </span>
                    </Tooltip>
                  </CircleMarker>
                </MapContainer>

                {/* Map coordinate overlay — sits outside the filter div so colours aren't inverted */}
                <div
                  className="absolute bottom-3 left-3 z-[1000] px-3 py-1.5 rounded-lg font-mono text-[10px] border pointer-events-none"
                  style={{
                    background: 'rgba(6,10,24,0.88)',
                    borderColor: 'rgba(0,255,157,0.2)',
                    color: '#00ff9d',
                    filter: 'none',
                  }}
                >
                  📍 {result.geo.lat.toFixed(6)}°, {result.geo.lon.toFixed(6)}°
                </div>
              </div>

              {/* Right Info Panel */}
              <div
                className="w-72 flex-shrink-0 border-l overflow-y-auto"
                style={{ borderColor: 'rgba(0,255,157,0.12)', background: 'rgba(4,7,18,0.95)' }}
              >
                {/* Reputation banner */}
                <div
                  className="px-4 py-3 border-b"
                  style={{
                    borderColor: 'rgba(0,255,157,0.1)',
                    background: `rgba(${result.reputation === 'malicious' ? '255,45,85' : result.reputation === 'suspicious' ? '255,107,53' : '0,255,157'},0.07)`,
                  }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Reputation</span>
                    <StatusBadge value={result.reputation} />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Threat Level</span>
                    <StatusBadge value={result.threat_level} />
                  </div>
                </div>

                {/* Location details */}
                <div className="p-4 space-y-4">
                  <div>
                    <div className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Location Details</div>
                    <div className="space-y-2">
                      {[
                        { label: 'Country', value: result.geo.country_name || result.geo.country || '—' },
                        { label: 'City', value: result.geo.city || '—' },
                        { label: 'Region', value: result.geo.region || '—' },
                        { label: 'Postal Code', value: result.geo.zip || '—' },
                        { label: 'Coordinates', value: result.geo.lat != null ? `${result.geo.lat.toFixed(4)}°, ${result.geo.lon.toFixed(4)}°` : '—' },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex justify-between items-start gap-2">
                          <span className="text-[10px] font-mono text-gray-500 flex-shrink-0">{label}:</span>
                          <span className="text-[10px] font-mono text-gray-200 text-right">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="border-t pt-4" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                    <div className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Network Info</div>
                    <div className="space-y-2">
                      {[
                        { label: 'ISP', value: result.geo.isp || '—' },
                        { label: 'ASN', value: result.geo.asn || '—' },
                        { label: 'Org', value: result.geo.org || result.geo.isp || '—' },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex justify-between items-start gap-2">
                          <span className="text-[10px] font-mono text-gray-500 flex-shrink-0">{label}:</span>
                          <span className="text-[10px] font-mono text-gray-200 text-right truncate max-w-[160px]" title={value}>{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="border-t pt-4" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                    <div className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-2">Threat Activity</div>
                    <div className="space-y-2">
                      {[
                        { label: 'Total Hits', value: result.total_hits || 0 },
                        { label: 'Risk Score', value: `${result.risk_score}/100` },
                        { label: 'Max Score', value: `${result.max_score}/100` },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex justify-between items-start gap-2">
                          <span className="text-[10px] font-mono text-gray-500">{label}:</span>
                          <span className="text-[10px] font-mono font-bold" style={{ color: markerColor }}>{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Action buttons */}
                  <div className="border-t pt-4 space-y-2" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                    <button
                      onClick={handleOpenFullMap}
                      className="w-full text-xs font-mono py-2 rounded border font-bold transition-all hover:brightness-125 flex items-center justify-center gap-2"
                      style={{
                        color: '#00d4ff',
                        borderColor: 'rgba(0,212,255,0.3)',
                        background: 'rgba(0,212,255,0.07)',
                      }}
                    >
                      🗺️ Open in Full Map
                    </button>
                    <button
                      onClick={() => { setShowMapModal(false); handleViewIncidents() }}
                      className="w-full text-xs font-mono py-2 rounded border font-bold transition-all hover:brightness-125 flex items-center justify-center gap-2"
                      style={{
                        color: '#a855f7',
                        borderColor: 'rgba(168,85,247,0.3)',
                        background: 'rgba(168,85,247,0.07)',
                      }}
                    >
                      📁 View Incidents
                    </button>
                    <button
                      onClick={() => setShowMapModal(false)}
                      className="w-full text-xs font-mono py-2 rounded border font-bold transition-all hover:bg-white/5 text-gray-500 border-white/10"
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <PageHeader
        title="IOC Search & Investigation"
        description="Lookup IPs, Domains, Hashes, URLs, and CVEs across CyberHawk observations and threat intelligence"
        icon={
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
        }
      />

      {/* Search Input Box */}
      <div className="rounded-xl border p-4 shadow-lg"
        style={{ background: 'rgba(8,12,28,0.85)', borderColor: 'rgba(0,255,157,0.18)' }}>
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <svg className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" width="16" height="16"
              viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <input
              id="ioc-search-input"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && search()}
              placeholder="Search IP (e.g. 185.220.101.1), internal asset (10.0.0.25), hash, or CVE..."
              className="w-full bg-transparent border rounded-lg pl-10 pr-4 py-3 text-sm font-mono text-gray-100 outline-none transition-all"
              style={{
                borderColor: 'rgba(0,255,157,0.25)',
                background: 'rgba(0,0,0,0.4)',
              }}
              onFocus={(e) => (e.target.style.borderColor = 'rgba(0,255,157,0.6)')}
              onBlur={(e) => (e.target.style.borderColor = 'rgba(0,255,157,0.25)')}
            />
          </div>
          <button
            id="ioc-search-btn"
            onClick={() => search()}
            disabled={loading}
            className="px-6 py-3 rounded-lg text-sm font-mono font-bold uppercase tracking-wider transition-all flex items-center gap-2 hover:brightness-110 active:scale-95"
            style={{
              background: loading ? 'rgba(0,255,157,0.1)' : 'linear-gradient(135deg, rgba(0,255,157,0.25), rgba(0,212,255,0.2))',
              color: '#00ff9d',
              border: '1px solid rgba(0,255,157,0.4)',
              boxShadow: '0 0 15px rgba(0,255,157,0.15)',
            }}
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-cyber-green border-t-transparent rounded-full animate-spin" />
                Searching...
              </>
            ) : (
              'Search IOC'
            )}
          </button>
        </div>

        {/* Quick Example Chips */}
        <div className="flex flex-wrap items-center gap-2 mt-3 pt-2 border-t border-white/5">
          <span className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Quick Query:</span>
          {EXAMPLE_IOCS.map((ex) => (
            <button
              key={ex.val}
              onClick={() => { setQuery(ex.val); search(ex.val) }}
              className="text-[11px] font-mono px-2.5 py-1 rounded border text-gray-400 hover:text-cyber-green hover:border-cyber-green/40 hover:bg-cyber-green/5 transition-all"
              style={{ borderColor: 'rgba(255,255,255,0.08)' }}
            >
              <span className="text-gray-600 mr-1">{ex.label}:</span>
              <span className="text-gray-300 font-semibold">{ex.val}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Results Grid */}
      <div className="grid grid-cols-3 gap-5">
        {/* Left Column (2 Cols): Investigation Details */}
        <div className="col-span-2 space-y-4">
          {loading && (
            <div className="rounded-xl border p-12 text-center"
              style={{ background: 'rgba(8,12,28,0.8)', borderColor: 'rgba(0,255,157,0.15)' }}>
              <div className="w-10 h-10 border-2 border-cyber-green border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-sm font-mono text-gray-400">Querying CyberHawk local database & threat intel feeds...</p>
            </div>
          )}

          {result && !loading && (
            <div className="rounded-xl border overflow-hidden shadow-2xl space-y-4"
              style={{ background: 'rgba(8,12,28,0.85)', borderColor: 'rgba(0,255,157,0.18)' }}>
              
              {/* IOC Card Header */}
              <div className="px-6 py-4 border-b flex flex-wrap items-center justify-between gap-3"
                style={{ borderColor: 'rgba(0,255,157,0.15)', background: 'rgba(5,8,18,0.7)' }}>
                <div className="flex items-center gap-3">
                  <span className="text-lg font-mono text-white font-bold tracking-tight">{result.ioc}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold"
                    style={{ borderColor: 'rgba(0,255,157,0.3)', color: '#00ff9d', background: 'rgba(0,255,157,0.08)' }}>
                    {result.ioc_type}
                  </span>
                  <StatusBadge value={result.reputation} />
                  {result.is_private_ip && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400">
                      RFC1918 PRIVATE
                    </span>
                  )}
                </div>

                {/* Primary Investigation Actions */}
                <div className="flex items-center gap-2">
                  <button
                    id="ioc-action-map"
                    onClick={handleViewOnMap}
                    disabled={!result.can_view_map}
                    title={result.can_view_map ? "Center on World Map" : "Coordinates unavailable for private/shielded IP"}
                    className={`text-xs font-mono px-3 py-1.5 rounded border transition-all flex items-center gap-1.5 font-bold ${
                      result.can_view_map
                        ? 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 shadow-cyan-500/20'
                        : 'text-gray-600 border-gray-800 bg-gray-900/40 cursor-not-allowed opacity-50'
                    }`}
                  >
                    <span>🗺️</span> [VIEW ON MAP]
                  </button>

                  <button
                    id="ioc-action-incidents"
                    onClick={handleViewIncidents}
                    className="text-xs font-mono px-3 py-1.5 rounded border text-purple-400 border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 font-bold transition-all"
                  >
                    <span>📁</span> [VIEW INCIDENTS]
                  </button>

                  <button
                    id="ioc-action-timeline"
                    onClick={handleScrollToTimeline}
                    className="text-xs font-mono px-3 py-1.5 rounded border text-amber-400 border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 font-bold transition-all"
                  >
                    <span>⏱️</span> [VIEW TIMELINE]
                  </button>

                  <button
                    onClick={() => copyToClipboard(result.ioc)}
                    className="text-xs font-mono px-2.5 py-1.5 rounded border border-white/10 text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div className="p-6 space-y-6">
                {/* Metrics Bar */}
                <div className="grid grid-cols-4 gap-3">
                  {[
                    { label: 'Total Hits', value: result.total_hits, color: '#00ff9d' },
                    { label: 'Risk Score', value: `${result.risk_score}/100`, color: result.risk_score > 70 ? '#ff2d55' : '#ffaa00' },
                    { label: 'Max Threat Score', value: `${result.max_score}/100`, color: '#ff2d55' },
                    { label: 'Related Incidents', value: result.related_incidents?.length || 0, color: '#a855f7' },
                  ].map((s) => (
                    <div key={s.label} className="rounded-lg p-3 border text-center"
                      style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                      <div className="text-xl font-['Orbitron'] font-bold" style={{ color: s.color }}>{s.value}</div>
                      <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider mt-0.5">{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* Section 1: Threat Intelligence & Exact Geolocation */}
                <div className="rounded-lg border p-4"
                  style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                  <div className="flex items-center justify-between mb-3 border-b border-white/5 pb-2">
                    <span className="text-xs font-mono text-cyber-green uppercase tracking-wider font-bold flex items-center gap-1.5">
                      <span>🌐</span> Threat Intelligence & Exact Geolocation
                    </span>
                    {result.geo?.lat != null && result.geo?.lon != null && (
                      <span className="text-[11px] font-mono text-cyan-400 font-semibold flex items-center gap-1">
                        <span>📍</span> Exact Coordinates: {result.geo.lat.toFixed(4)}°, {result.geo.lon.toFixed(4)}°
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-4 gap-4 text-xs font-mono">
                    <div>
                      <div className="text-gray-500 text-[10px] uppercase">Country</div>
                      <div className="text-gray-200 font-semibold mt-0.5">
                        {result.geo?.country_name || result.geo?.country || (result.is_private_ip ? 'Lab Network' : 'Unknown')}
                      </div>
                    </div>
                    <div>
                      <div className="text-gray-500 text-[10px] uppercase">City / Region</div>
                      <div className="text-gray-200 font-semibold mt-0.5">
                        {result.geo?.city ? `${result.geo.city}${result.geo.region ? `, ${result.geo.region}` : ''}` : (result.is_private_ip ? 'Internal Segment' : 'Unavailable')}
                      </div>
                    </div>
                    <div>
                      <div className="text-gray-500 text-[10px] uppercase">Postal / ZIP</div>
                      <div className="text-gray-200 font-semibold mt-0.5">
                        {result.geo?.zip || '—'}
                      </div>
                    </div>
                    <div>
                      <div className="text-gray-500 text-[10px] uppercase">ASN & Network Provider</div>
                      <div className="text-gray-200 font-semibold mt-0.5 truncate">
                        {result.geo?.asn ? `${result.geo.asn} (${result.geo.isp || 'ISP'})` : (result.is_private_ip ? 'RFC1918 Private Subnet' : '—')}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 text-[10px] font-mono text-emerald-400/80 flex items-center gap-1">
                    <span>📍</span> {result.is_private_ip ? 'Private RFC1918 IP address (Internal Subnet Shielded)' : 'Exact physical geolocation resolved. Click [VIEW ON MAP] to pinpoint on interactive world map.'}
                  </div>

                  {/* External Threat Intel info if available */}
                  {result.threat_intelligence?.abuseipdb && (
                    <div className="mt-3 pt-3 border-t border-white/5 flex items-center gap-4 text-xs font-mono">
                      <span className="text-gray-400">AbuseIPDB Confidence:</span>
                      <span className="text-red-400 font-bold">{result.threat_intelligence.abuseipdb.abuse_confidence_score}%</span>
                      <span className="text-gray-500">({result.threat_intelligence.abuseipdb.total_reports} reports)</span>
                    </div>
                  )}
                </div>

                {/* Section 2: Observations & Connected SOC Assets */}
                <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                  {/* Observation Timing */}
                  <div className="rounded-lg border p-4"
                    style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                    <div className="text-xs text-cyber-green font-bold uppercase tracking-wider mb-3">
                      Observation Window
                    </div>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-500">First Seen:</span>
                        <span className="text-gray-300">{result.first_seen ? new Date(result.first_seen).toLocaleString() : '—'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Last Seen:</span>
                        <span className="text-gray-300">{result.last_seen ? new Date(result.last_seen).toLocaleString() : '—'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Occurrences:</span>
                        <span className="text-cyber-green font-bold">{result.occurrences} events</span>
                      </div>
                    </div>
                  </div>

                  {/* Connected Assets */}
                  <div className="rounded-lg border p-4"
                    style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                    <div className="text-xs text-cyber-green font-bold uppercase tracking-wider mb-3">
                      Connected Assets ({result.related_assets?.length || 0})
                    </div>
                    {result.related_assets?.length === 0 ? (
                      <div className="text-gray-600 italic">No specific internal assets linked</div>
                    ) : (
                      <div className="space-y-2">
                        {result.related_assets.map((asset) => (
                          <div key={asset.id} className="flex items-center justify-between p-2 rounded bg-white/5 border border-white/5">
                            <div>
                              <div className="font-bold text-gray-200">{asset.hostname}</div>
                              <div className="text-[10px] text-gray-500">{asset.ip_address} · {asset.location || 'Lab'}</div>
                            </div>
                            <span className="text-[9px] px-2 py-0.5 rounded font-bold uppercase"
                              style={{
                                background: asset.criticality === 'critical' ? 'rgba(255,45,85,0.2)' : 'rgba(255,170,0,0.2)',
                                color: asset.criticality === 'critical' ? '#ff2d55' : '#ffaa00',
                              }}>
                              {asset.criticality}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Section 3: Related Incidents & MITRE Techniques */}
                <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                  {/* Related Incidents */}
                  <div className="rounded-lg border p-4"
                    style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                    <div className="text-xs text-cyber-green font-bold uppercase tracking-wider mb-3">
                      Related Incidents ({result.related_incidents?.length || 0})
                    </div>
                    {result.related_incidents?.length === 0 ? (
                      <div className="text-gray-600 italic">No open incidents currently associated</div>
                    ) : (
                      <div className="space-y-2">
                        {result.related_incidents.map((inc) => (
                          <div key={inc.id}
                            onClick={() => navigate(`/incidents`)}
                            className="flex items-center justify-between p-2 rounded bg-purple-500/5 border border-purple-500/20 hover:bg-purple-500/10 cursor-pointer transition-colors">
                            <div>
                              <div className="font-bold text-purple-300 truncate max-w-[200px]">{inc.title}</div>
                              <div className="text-[9px] text-gray-500">Status: {inc.status}</div>
                            </div>
                            <StatusBadge value={inc.severity} />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* MITRE ATT&CK Techniques */}
                  <div className="rounded-lg border p-4"
                    style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                    <div className="text-xs text-cyber-green font-bold uppercase tracking-wider mb-3">
                      Observed MITRE ATT&CK
                    </div>
                    {result.mitre_techniques?.length === 0 ? (
                      <div className="text-gray-600 italic">No techniques tagged</div>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {result.mitre_techniques.map((t) => (
                          <span key={t} className="px-2.5 py-1 rounded text-xs font-bold flex items-center gap-1.5"
                            style={{ background: 'rgba(100,120,250,0.15)', color: '#a5b4fc', border: '1px solid rgba(100,120,250,0.3)' }}>
                            <span>🎯</span> {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Section 4: Alert History & Chronological Timeline */}
                <div ref={timelineRef} id="ioc-timeline" className="pt-2">
                  <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-3 flex items-center justify-between">
                    <span>Recent Observations & Event Log ({result.alerts?.length || 0})</span>
                    <span className="text-[10px] text-gray-600">Showing up to 50 recent events</span>
                  </div>

                  <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                    <table className="w-full text-xs font-mono">
                      <thead>
                        <tr className="border-b bg-white/2" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                          {['Timestamp', 'Env', 'Source', 'Level', 'Score', 'Attack Pattern', 'Target'].map((h) => (
                            <th key={h} className="px-3.5 py-2.5 text-left text-gray-500 font-normal uppercase text-[9px] tracking-wider">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {result.alerts?.map((a) => (
                          <tr key={a.id} className="border-b hover:bg-white/5 transition-colors"
                            style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                            <td className="px-3.5 py-2 text-gray-400">{new Date(a.timestamp).toLocaleTimeString()}</td>
                            <td className="px-3.5 py-2">
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                                a.environment === 'OBSERVED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                                a.environment === 'LAB' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                                'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                              }`}>
                                {a.environment || 'SIMULATED'}
                              </span>
                            </td>
                            <td className="px-3.5 py-2 text-gray-500 text-[10px]">{a.detection_source || 'simulator'}</td>
                            <td className="px-3.5 py-2"><StatusBadge value={a.threat_level} /></td>
                            <td className="px-3.5 py-2 text-gray-200 font-semibold">{a.threat_score}</td>
                            <td className="px-3.5 py-2 text-gray-300 truncate max-w-[150px]">{a.attack_type || a.classification}</td>
                            <td className="px-3.5 py-2 text-cyan-400 font-mono">{a.dst_ip || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>
            </div>
          )}

          {!result && !loading && (
            <div className="rounded-xl border p-12 text-center"
              style={{ background: 'rgba(8,12,28,0.5)', borderColor: 'rgba(0,255,157,0.08)' }}>
              <div className="text-5xl mb-3 opacity-30">🛡️</div>
              <p className="text-sm font-mono text-gray-400 font-semibold">Enter an IOC above to begin investigation</p>
              <p className="text-xs font-mono text-gray-600 mt-1">
                Supports public threat IPs, internal monitored assets, domains, URLs, file hashes, and CVE identifiers.
              </p>
            </div>
          )}
        </div>

        {/* Right Column (1 Col): Recently Seen Suspicious IOCs */}
        <div className="rounded-xl border overflow-hidden shadow-xl"
          style={{ background: 'rgba(8,12,28,0.85)', borderColor: 'rgba(0,255,157,0.15)' }}>
          <div className="px-4 py-3.5 border-b flex items-center justify-between"
            style={{ borderColor: 'rgba(0,255,157,0.15)', background: 'rgba(5,8,18,0.7)' }}>
            <span className="text-xs font-mono text-cyber-green uppercase tracking-wider font-bold">
              Active Threat Registry
            </span>
            <button onClick={loadRecent} className="text-[10px] font-mono text-gray-500 hover:text-white">
              ↻ Refresh
            </button>
          </div>

          <div className="overflow-y-auto max-h-[650px] divide-y divide-white/5">
            {recentIOCs.map((ioc) => (
              <button
                key={ioc.ioc_value || ioc.ip}
                onClick={() => {
                  const target = ioc.ioc_value || ioc.ip
                  setQuery(target)
                  search(target)
                }}
                className="w-full text-left px-4 py-3 hover:bg-white/5 transition-all group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-gray-300 group-hover:text-cyber-green transition-colors">
                    {ioc.ioc_value || ioc.ip}
                  </span>
                  <StatusBadge value={ioc.threat_level} />
                </div>
                <div className="flex items-center justify-between mt-1 text-[10px] font-mono text-gray-500">
                  <span>Hits: <strong className="text-gray-300">{ioc.hit_count}</strong></span>
                  <span>{ioc.country ? `Approx: ${ioc.country}` : 'Internal'}</span>
                </div>
              </button>
            ))}

            {recentIOCs.length === 0 && (
              <div className="p-8 text-center text-xs font-mono text-gray-600">
                Awaiting IOC observations...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
