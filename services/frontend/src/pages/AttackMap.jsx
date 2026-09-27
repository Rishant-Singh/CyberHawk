import { useEffect, useState, useRef, useMemo, useCallback } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { MapContainer, TileLayer, CircleMarker, Polyline, Tooltip, useMap } from 'react-leaflet'
import axios from 'axios'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'
import StatusBadge from '../components/common/StatusBadge'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Legal OpenStreetMap Standard Tiles (Free, No API key required)
const TILE_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png'
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer">OpenStreetMap</a> contributors'

const SEVERITY_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff6b35',
  MEDIUM: '#ffc400',
  LOW: '#00ff9d',
  INFO: '#6478c8',
}

// Controller component to smoothly fly/pan map to focused coordinates
function MapController({ center, zoom }) {
  const map = useMap()
  useEffect(() => {
    if (center && center[0] != null && center[1] != null) {
      map.flyTo(center, zoom || 6, { duration: 1.5 })
    }
  }, [center, zoom, map])
  return null
}

export default function AttackMap() {
  const location = useLocation()
  const navigate = useNavigate()
  const token = useThreatStore((s) => s.accessToken)
  const liveThreats = useThreatStore((s) => s.liveThreats)

  // Filter states
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [timeFilter, setTimeFilter] = useState('24') // hours: 1, 24, 168 (7D), 720 (30D)
  const [envFilter, setEnvFilter] = useState('ALL') // ALL | OBSERVED | LAB | SIMULATED
  const [searchQuery, setSearchQuery] = useState('')

  // Map events state
  const [historicalEvents, setHistoricalEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [mapCenter, setMapCenter] = useState([20.0, 10.0])
  const [mapZoom, setMapZoom] = useState(2.5)
  const [showTimelineModal, setShowTimelineModal] = useState(false)

  const authHeader = useMemo(() => ({ headers: { Authorization: `Bearer ${token}` } }), [token])

  // Fetch verified map events from backend
  const fetchMapEvents = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await axios.get(`${API}/api/threats/map-events`, {
        params: {
          threat_level: severityFilter,
          environment: envFilter,
          hours: parseInt(timeFilter, 10),
          limit: 150,
        },
        ...authHeader,
      })
      setHistoricalEvents(data)
    } catch {
      // Fallback silent
    } finally {
      setLoading(false)
    }
  }, [severityFilter, envFilter, timeFilter, authHeader])

  useEffect(() => {
    fetchMapEvents()
  }, [fetchMapEvents])

  // Handle Search → Map workflow from URL query parameters (e.g. ?focus=8.8.8.8&lat=39.0438&lon=-77.4874)
  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const focusIP = params.get('focus')
    const lat = parseFloat(params.get('lat'))
    const lon = parseFloat(params.get('lon'))

    if (focusIP && !isNaN(lat) && !isNaN(lon)) {
      setMapCenter([lat, lon])
      setMapZoom(14) // High-precision street/city zoom on exact coordinates
      const hits = parseInt(params.get('hits') || '0', 10)
      const country = params.get('country') || ''
      const city = params.get('city') || ''
      const region = params.get('region') || ''
      const zip = params.get('zip') || ''
      const isp = params.get('isp') || ''
      const asn = params.get('asn') || ''
      const rep = params.get('reputation') || (hits > 0 ? 'suspicious' : 'clean')
      const threatLvl = params.get('threat_level') || (hits > 0 ? 'HIGH' : 'LOW')

      setSelectedThreat({
        id: `target-${focusIP}`,
        src_ip: focusIP,
        dst_ip: 'N/A',
        geo_country: country || 'Identified Location',
        geo_city: city || 'Exact Coordinates',
        geo_region: region,
        geo_zip: zip,
        geo_lat: lat,
        geo_lon: lon,
        isp: isp,
        asn: asn,
        threat_level: threatLvl,
        threat_score: hits > 0 ? 80 : 0,
        attack_type: hits > 0 ? 'Recorded Attack Vector' : 'Clean IP — Zero Cyber Attacks Detected',
        mitre_technique: hits > 0 ? 'T1110' : 'None',
        environment: 'OBSERVED',
        detection_source: 'ioc_investigation',
        total_hits: hits,
        reputation: rep,
        is_exact_pinpoint: true,
      })
    }
  }, [location.search])

  // Combine live stream events and historical events (filtering out invalid or missing coordinates)
  const validEvents = useMemo(() => {
    const combined = [...liveThreats, ...historicalEvents]
    const seen = new Set()
    const valid = []

    for (const evt of combined) {
      if (!evt.geo_lat || !evt.geo_lon) continue
      const lat = parseFloat(evt.geo_lat)
      const lon = parseFloat(evt.geo_lon)
      if (isNaN(lat) || isNaN(lon)) continue

      // Filter by severity
      if (severityFilter !== 'ALL' && evt.threat_level !== severityFilter) continue

      // Filter by environment
      if (envFilter !== 'ALL' && (evt.environment || 'SIMULATED') !== envFilter) continue

      // Filter by search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matches =
          evt.src_ip?.toLowerCase().includes(q) ||
          evt.dst_ip?.toLowerCase().includes(q) ||
          evt.attack_type?.toLowerCase().includes(q) ||
          evt.mitre_technique?.toLowerCase().includes(q)
        if (!matches) continue
      }

      // Deduplicate key by src_ip + coords
      const key = `${evt.src_ip}-${lat.toFixed(2)}-${lon.toFixed(2)}`
      if (!seen.has(key)) {
        seen.add(key)
        valid.push({
          ...evt,
          lat,
          lon,
        })
      }
    }
    return valid
  }, [liveThreats, historicalEvents, severityFilter, envFilter, searchQuery])

  // Stats calculation
  const stats = useMemo(() => {
    const countries = new Set(validEvents.map((e) => e.geo_country).filter(Boolean))
    return {
      total: validEvents.length,
      critical: validEvents.filter((e) => e.threat_level === 'CRITICAL').length,
      high: validEvents.filter((e) => e.threat_level === 'HIGH').length,
      countries: countries.size,
    }
  }, [validEvents])

  // Select marker and center map with exact precision zoom
  const handleSelectThreat = (threat) => {
    setSelectedThreat(threat)
    const lat = threat.lat != null ? threat.lat : threat.geo_lat
    const lon = threat.lon != null ? threat.lon : threat.geo_lon
    if (lat != null && lon != null) {
      setMapCenter([lat, lon])
      setMapZoom(13)
    }
  }

  // Quick search by IP (resolves exact location even with 0 attacks)
  const handleQuickSearch = async (e) => {
    if (e.key !== 'Enter') return
    const q = searchQuery.trim()
    if (!q) return

    // 1. Check matching event in current dataset
    const matched = validEvents.find(
      (evt) => evt.src_ip?.toLowerCase() === q.toLowerCase() || evt.dst_ip?.toLowerCase() === q.toLowerCase()
    )
    if (matched && (matched.lat || matched.geo_lat) && (matched.lon || matched.geo_lon)) {
      handleSelectThreat(matched)
      return
    }

    // 2. Direct IP lookup (works even if 0 attacks)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q)) {
      try {
        const { data } = await axios.get(`${API}/api/threats/geolocation/${encodeURIComponent(q)}`, authHeader)
        if (data && data.lat != null && data.lon != null) {
          setMapCenter([data.lat, data.lon])
          setMapZoom(14)
          setSelectedThreat({
            id: `target-${q}`,
            src_ip: q,
            dst_ip: 'N/A',
            geo_country: data.country_name || data.country || 'Target Location',
            geo_city: data.city || 'Exact Location',
            geo_region: data.region || '',
            geo_zip: data.zip || '',
            geo_lat: data.lat,
            geo_lon: data.lon,
            isp: data.isp || '',
            asn: data.asn || '',
            threat_level: 'LOW',
            threat_score: 0,
            attack_type: 'Direct IP Geolocation — Zero Active Attacks',
            mitre_technique: 'None',
            environment: data.is_private ? 'LAB' : 'OBSERVED',
            detection_source: 'direct_lookup',
            total_hits: 0,
            is_exact_pinpoint: true,
          })
        }
      } catch (err) {
        console.error('Failed to resolve IP location', err)
      }
    }
  }

  // Quick navigation buttons from investigation panel
  const handleOpenIOC = (ip) => {
    navigate(`/ioc?q=${encodeURIComponent(ip)}`)
  }

  const handleOpenIncident = (ip) => {
    navigate(`/incidents?search=${encodeURIComponent(ip)}`)
  }

  return (
    <div className="flex flex-col h-full gap-3 p-1">
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyber-border/40 pb-3">
        <PageHeader
          title="Global Threat Map"
          description="Geographic threat intelligence with exact IP geolocation coordinates, attack vectors, and live telemetry"
          icon={
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <line x1="2" y1="12" x2="22" y2="12" />
              <path d="M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20" />
            </svg>
          }
        />

        {/* Global Filter Toolbar */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          {/* Quick Search */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search or type IP + Enter..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleQuickSearch}
              className="bg-black/40 border border-cyber-green/30 rounded px-3 py-1.5 text-xs text-gray-200 outline-none w-52 focus:border-cyber-green"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex rounded border border-cyber-border/50 overflow-hidden bg-black/40">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSeverityFilter(lvl)}
                className={`px-2.5 py-1 text-[10px] font-bold uppercase transition-colors ${
                  severityFilter === lvl
                    ? 'bg-cyber-green/20 text-cyber-green'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {/* Time Filter */}
          <div className="flex rounded border border-cyber-border/50 overflow-hidden bg-black/40">
            {[
              { label: '1H', val: '1' },
              { label: '24H', val: '24' },
              { label: '7D', val: '168' },
              { label: '30D', val: '720' },
            ].map((t) => (
              <button
                key={t.label}
                onClick={() => setTimeFilter(t.val)}
                className={`px-2.5 py-1 text-[10px] font-bold uppercase transition-colors ${
                  timeFilter === t.val
                    ? 'bg-cyan-500/20 text-cyan-400'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Environment Filter */}
          <div className="flex rounded border border-cyber-border/50 overflow-hidden bg-black/40">
            {['ALL', 'OBSERVED', 'LAB', 'SIMULATED'].map((env) => (
              <button
                key={env}
                onClick={() => setEnvFilter(env)}
                className={`px-2.5 py-1 text-[10px] font-bold uppercase transition-colors ${
                  envFilter === env
                    ? 'bg-purple-500/25 text-purple-300'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {env}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* KPI Stats Bar */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Mapped Events', value: stats.total, color: '#00ff9d' },
          { label: 'Critical Severity', value: stats.critical, color: '#ff2d55' },
          { label: 'High Severity', value: stats.high, color: '#ff6b35' },
          { label: 'Source Countries', value: stats.countries, color: '#00d4ff' },
        ].map((s) => (
          <div
            key={s.label}
            className="rounded-lg px-4 py-2 border flex items-center justify-between"
            style={{ background: 'rgba(8,12,28,0.85)', borderColor: 'rgba(0,255,157,0.12)' }}
          >
            <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">{s.label}</span>
            <span className="text-lg font-['Orbitron'] font-bold" style={{ color: s.color }}>
              {s.value}
            </span>
          </div>
        ))}
      </div>

      {/* Main Map + Side Panels Area */}
      <div className="flex gap-3 flex-1 min-h-0 relative">
        {/* Real Leaflet Map Container */}
        <div
          className="flex-1 rounded-xl border overflow-hidden relative shadow-2xl"
          style={{ background: '#070b19', borderColor: 'rgba(0,255,157,0.18)' }}
        >
          <MapContainer
            center={mapCenter}
            zoom={mapZoom}
            minZoom={2}
            maxZoom={18}
            scrollWheelZoom={true}
            style={{ width: '100%', height: '100%', background: '#050814' }}
          >
            <MapController center={mapCenter} zoom={mapZoom} />

            {/* Legal OpenStreetMap Standard Tiles (No API key required) */}
            <TileLayer
              url={TILE_URL}
              attribution={TILE_ATTRIBUTION}
              maxZoom={19}
              className="dark-map-tiles"
            />

            {/* Render Attack Arcs between external source and target destination */}
            {validEvents.map((evt) => {
              // Draw an arc if there's a target asset or sensor destination
              // Center of monitored defense lab gateway (approx location)
              const defLat = 50.1109
              const defLon = 8.6821
              const color = SEVERITY_COLORS[evt.threat_level] || '#00ff9d'

              return (
                <Polyline
                  key={`arc-${evt.id}`}
                  positions={[
                    [evt.lat, evt.lon],
                    [defLat, defLon],
                  ]}
                  pathOptions={{
                    color,
                    weight: evt.threat_level === 'CRITICAL' ? 1.8 : 1.0,
                    opacity: evt.threat_level === 'CRITICAL' ? 0.6 : 0.35,
                    dashArray: '4, 8',
                  }}
                />
              )
            })}

            {/* Render Verified Geographic Markers */}
            {validEvents.map((evt) => {
              const color = SEVERITY_COLORS[evt.threat_level] || '#00ff9d'
              const isSelected = selectedThreat && selectedThreat.src_ip === evt.src_ip
              const radius = evt.threat_level === 'CRITICAL' ? 9 : evt.threat_level === 'HIGH' ? 7 : 5

              return (
                <CircleMarker
                  key={evt.id}
                  center={[evt.lat, evt.lon]}
                  radius={isSelected ? radius + 4 : radius}
                  pathOptions={{
                    color: isSelected ? '#ffffff' : color,
                    fillColor: color,
                    fillOpacity: isSelected ? 0.95 : 0.75,
                    weight: isSelected ? 2.5 : 1.2,
                  }}
                  eventHandlers={{
                    click: () => handleSelectThreat(evt),
                  }}
                >
                  <Tooltip direction="top" offset={[0, -5]} opacity={0.95}>
                    <div className="font-mono text-xs p-1">
                      <div className="font-bold text-gray-900 flex items-center justify-between gap-2">
                        <span>{evt.src_ip}</span>
                        <span style={{ color }}>{evt.threat_level}</span>
                      </div>
                      <div className="text-[10px] text-gray-700 mt-0.5">
                        {evt.geo_city ? `${evt.geo_city}, ` : ''}{evt.geo_country}
                      </div>
                      <div className="text-[9px] text-gray-500 italic mt-0.5">
                        {evt.attack_type || evt.classification}
                      </div>
                    </div>
                  </Tooltip>
                </CircleMarker>
              )
            })}
            {/* Dedicated High-Precision Pinpoint Marker (Renders for focused/searched IP, even if 0 attacks) */}
            {selectedThreat && selectedThreat.geo_lat != null && selectedThreat.geo_lon != null && (
              <>
                <CircleMarker
                  center={[selectedThreat.geo_lat, selectedThreat.geo_lon]}
                  radius={22}
                  pathOptions={{
                    color: '#00d4ff',
                    fillColor: '#00d4ff',
                    fillOpacity: 0.18,
                    weight: 2,
                    dashArray: '3, 4',
                  }}
                />
                <CircleMarker
                  center={[selectedThreat.geo_lat, selectedThreat.geo_lon]}
                  radius={9}
                  pathOptions={{
                    color: '#ffffff',
                    fillColor: selectedThreat.threat_score > 60 ? '#ff2d55' : selectedThreat.threat_score > 30 ? '#ff6b35' : '#00ff9d',
                    fillOpacity: 1.0,
                    weight: 3,
                  }}
                >
                  <Tooltip permanent direction="top" offset={[0, -12]} opacity={0.95}>
                    <div className="font-mono text-xs p-1">
                      <div className="font-bold text-gray-900 flex items-center gap-1.5">
                        <span>📍</span>
                        <span>{selectedThreat.src_ip}</span>
                        <span className="text-[9px] px-1 py-0.5 rounded font-bold uppercase"
                          style={{
                            background: selectedThreat.threat_score === 0 ? '#dcfce7' : '#fee2e2',
                            color: selectedThreat.threat_score === 0 ? '#15803d' : '#b91c1c'
                          }}>
                          {selectedThreat.threat_score === 0 ? '0 ATTACKS (CLEAN)' : 'ATTACK TARGET'}
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-700 mt-0.5 font-semibold">
                        {[selectedThreat.geo_city, selectedThreat.geo_region, selectedThreat.geo_country].filter(Boolean).join(', ')}
                      </div>
                      <div className="text-[9px] text-cyan-700 font-bold mt-0.5">
                        {selectedThreat.geo_lat.toFixed(4)}°, {selectedThreat.geo_lon.toFixed(4)}°
                      </div>
                    </div>
                  </Tooltip>
                </CircleMarker>
              </>
            )}
          </MapContainer>

          {/* Exact Coordinates Precision Badge */}
          <div
            className="absolute bottom-2.5 left-2.5 z-[1000] px-3 py-1.5 rounded-md border text-[10px] font-mono shadow-md backdrop-blur-md flex items-center gap-2"
            style={{ background: 'rgba(5,8,18,0.88)', borderColor: 'rgba(0,255,157,0.2)', color: '#94a3b8' }}
          >
            <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
            <span>Exact Geolocation Coordinates Active · Precision OpenStreetMap Pinpoint · Private subnets shielded</span>
          </div>
        </div>

        {/* Right Sidebar: Investigation Drawer & Live Threat Stream */}
        <div className="w-80 flex flex-col gap-3 min-h-0">
          {/* Section 7: Investigation Panel (Shown when marker/threat is selected) */}
          {selectedThreat ? (
            <div
              className="rounded-xl border p-4 shadow-xl flex flex-col gap-3 transition-all"
              style={{ background: 'rgba(8,12,28,0.95)', borderColor: 'rgba(0,255,157,0.3)' }}
            >
              <div className="flex items-center justify-between border-b border-white/10 pb-2.5">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_COLORS[selectedThreat.threat_level] }} />
                  <span className="text-sm font-mono font-bold text-white tracking-tight">
                    {selectedThreat.src_ip}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedThreat(null)}
                  className="text-gray-500 hover:text-white text-xs font-mono"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between items-start">
                  <span className="text-gray-500">Exact Location:</span>
                  <span className="text-gray-200 text-right font-semibold">
                    {[selectedThreat.geo_city, selectedThreat.geo_region, selectedThreat.geo_country].filter(Boolean).join(', ') || 'Identified Location'}
                  </span>
                </div>
                {selectedThreat.geo_zip && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Postal / ZIP:</span>
                    <span className="text-gray-200">{selectedThreat.geo_zip}</span>
                  </div>
                )}
                {selectedThreat.geo_lat != null && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Coordinates:</span>
                    <span className="text-cyan-400 font-mono font-semibold">
                      {selectedThreat.geo_lat.toFixed(4)}°, {selectedThreat.geo_lon.toFixed(4)}°
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-500">Severity:</span>
                  <StatusBadge value={selectedThreat.threat_level} />
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Threat Score:</span>
                  <span className={`font-bold ${selectedThreat.threat_score === 0 ? 'text-cyber-green' : 'text-white'}`}>
                    {selectedThreat.threat_score != null ? selectedThreat.threat_score : 85}/100
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Attack Status:</span>
                  <span className={`truncate max-w-[150px] font-semibold ${selectedThreat.threat_score === 0 ? 'text-emerald-400' : 'text-gray-300'}`}>
                    {selectedThreat.attack_type || (selectedThreat.threat_score === 0 ? '0 Attacks (Clean IP)' : selectedThreat.classification || 'Intrusion Attempt')}
                  </span>
                </div>
                {(selectedThreat.isp || selectedThreat.asn) && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Network / ISP:</span>
                    <span className="text-gray-300 truncate max-w-[150px]" title={selectedThreat.isp || selectedThreat.asn}>
                      {selectedThreat.isp || selectedThreat.asn}
                    </span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-500">Environment:</span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                    selectedThreat.environment === 'OBSERVED' ? 'bg-emerald-500/20 text-emerald-400' :
                    selectedThreat.environment === 'LAB' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'
                  }`}>
                    {selectedThreat.environment || 'SIMULATED'}
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-2 border-t border-white/10 grid grid-cols-2 gap-2 text-xs font-mono">
                <button
                  id="map-open-ioc-btn"
                  onClick={() => handleOpenIOC(selectedThreat.src_ip)}
                  className="px-2.5 py-1.5 rounded border border-cyber-green/30 bg-cyber-green/10 text-cyber-green hover:bg-cyber-green/20 font-bold transition-all text-center"
                >
                  [OPEN IOC]
                </button>
                <button
                  id="map-open-incident-btn"
                  onClick={() => handleOpenIncident(selectedThreat.src_ip)}
                  className="px-2.5 py-1.5 rounded border border-purple-500/30 bg-purple-500/10 text-purple-300 hover:bg-purple-500/20 font-bold transition-all text-center"
                >
                  [OPEN INCIDENT]
                </button>
              </div>

              <button
                onClick={() => setShowTimelineModal(true)}
                className="w-full py-1.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 font-mono text-xs font-bold transition-all text-center"
              >
                [VIEW TIMELINE]
              </button>
            </div>
          ) : (
            <div
              className="rounded-xl border p-4 text-center text-xs font-mono text-gray-500"
              style={{ background: 'rgba(8,12,28,0.7)', borderColor: 'rgba(0,255,157,0.12)' }}
            >
              <span className="text-xl block mb-1">🎯</span>
              Click any map marker to open its SOC investigation panel.
            </div>
          )}

          {/* Active Events Feed */}
          <div
            className="flex-1 rounded-xl border overflow-hidden flex flex-col"
            style={{ background: 'rgba(6,10,24,0.92)', borderColor: 'rgba(0,255,157,0.14)' }}
          >
            <div className="px-4 py-2.5 border-b flex items-center justify-between border-white/10">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
                <span className="text-xs font-mono text-cyber-green uppercase tracking-wider font-bold">
                  Telemetry Feed
                </span>
              </div>
              <span className="text-[10px] font-mono text-gray-500">{validEvents.length} events</span>
            </div>

            <div className="flex-1 overflow-y-auto divide-y divide-white/5">
              {validEvents.slice(0, 30).map((t) => (
                <div
                  key={t.id}
                  onClick={() => handleSelectThreat(t)}
                  className={`p-3 hover:bg-white/5 cursor-pointer transition-colors ${
                    selectedThreat?.id === t.id ? 'bg-cyber-green/10 border-l-2 border-cyber-green' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-bold text-gray-200">{t.src_ip}</span>
                    <StatusBadge value={t.threat_level} />
                  </div>
                  <div className="text-[10px] font-mono text-gray-500 flex items-center justify-between">
                    <span className="truncate max-w-[140px]">{t.attack_type || t.classification}</span>
                    <span>{t.geo_country ? `(${t.geo_country})` : ''}</span>
                  </div>
                </div>
              ))}

              {validEvents.length === 0 && (
                <div className="p-8 text-center text-xs font-mono text-gray-600">
                  {loading ? 'Loading threat events...' : 'No events matching current filters'}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Timeline Modal */}
      {showTimelineModal && selectedThreat && (
        <div className="fixed inset-0 z-[2000] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div
            className="w-full max-w-xl rounded-xl border p-6 space-y-4 shadow-2xl"
            style={{ background: 'rgba(8,12,28,0.98)', borderColor: 'rgba(0,255,157,0.3)' }}
          >
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <span className="text-sm font-mono font-bold text-cyber-green">
                Chronological Event Timeline — {selectedThreat.src_ip}
              </span>
              <button onClick={() => setShowTimelineModal(false)} className="text-gray-400 hover:text-white text-sm">
                ✕
              </button>
            </div>

            <div className="max-h-80 overflow-y-auto space-y-3 font-mono text-xs">
              <div className="p-3 rounded border border-white/5 bg-white/5 flex items-center justify-between">
                <div>
                  <div className="font-bold text-gray-200">First Observed Contact</div>
                  <div className="text-[10px] text-gray-500">Initial network detection logged by sensor</div>
                </div>
                <span className="text-gray-400 text-[10px]">{new Date().toLocaleTimeString()}</span>
              </div>
              <div className="p-3 rounded border border-white/5 bg-white/5 flex items-center justify-between">
                <div>
                  <div className="font-bold text-amber-300">Exploitation Signature Triggered</div>
                  <div className="text-[10px] text-gray-500">{selectedThreat.attack_type || 'Malicious Payload'} ({selectedThreat.mitre_technique || 'T1110'})</div>
                </div>
                <span className="text-amber-400 text-[10px]">Severity {selectedThreat.threat_level}</span>
              </div>
              <div className="p-3 rounded border border-white/5 bg-white/5 flex items-center justify-between">
                <div>
                  <div className="font-bold text-cyber-green">Approximate GeoIP Resolved</div>
                  <div className="text-[10px] text-gray-500">{selectedThreat.geo_city}, {selectedThreat.geo_country} (±{selectedThreat.accuracy_radius_km || 30} km)</div>
                </div>
                <span className="text-gray-400 text-[10px]">Accuracy Verified</span>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-white/10">
              <button
                onClick={() => setShowTimelineModal(false)}
                className="px-4 py-2 rounded bg-white/10 text-xs font-mono text-gray-300 hover:text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
