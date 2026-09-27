// Severity / threat level badge component
const LEVEL_STYLES = {
  CRITICAL: { bg: 'rgba(255,45,85,0.15)', color: '#ff2d55', border: 'rgba(255,45,85,0.4)' },
  HIGH:     { bg: 'rgba(255,107,53,0.15)', color: '#ff6b35', border: 'rgba(255,107,53,0.4)' },
  MEDIUM:   { bg: 'rgba(255,196,0,0.15)',  color: '#ffc400', border: 'rgba(255,196,0,0.4)' },
  LOW:      { bg: 'rgba(0,255,157,0.12)',  color: '#00ff9d', border: 'rgba(0,255,157,0.3)' },
  INFO:     { bg: 'rgba(100,120,200,0.15)',color: '#6478c8', border: 'rgba(100,120,200,0.4)' },
  // Status badges
  open:          { bg: 'rgba(255,45,85,0.15)',   color: '#ff2d55', border: 'rgba(255,45,85,0.4)' },
  investigating: { bg: 'rgba(255,196,0,0.15)',   color: '#ffc400', border: 'rgba(255,196,0,0.4)' },
  resolved:      { bg: 'rgba(0,255,157,0.12)',   color: '#00ff9d', border: 'rgba(0,255,157,0.3)' },
  closed:        { bg: 'rgba(80,80,100,0.2)',    color: '#777',    border: 'rgba(80,80,100,0.4)' },
  // Reputation
  malicious:          { bg: 'rgba(255,45,85,0.15)',   color: '#ff2d55', border: 'rgba(255,45,85,0.4)' },
  suspicious:         { bg: 'rgba(255,107,53,0.15)',  color: '#ff6b35', border: 'rgba(255,107,53,0.4)' },
  potentially_unwanted: { bg: 'rgba(255,196,0,0.15)', color: '#ffc400', border: 'rgba(255,196,0,0.4)' },
  clean:              { bg: 'rgba(0,255,157,0.12)',   color: '#00ff9d', border: 'rgba(0,255,157,0.3)' },
  unknown:            { bg: 'rgba(80,80,100,0.2)',    color: '#777',    border: 'rgba(80,80,100,0.4)' },
  // Criticality
  critical: { bg: 'rgba(255,45,85,0.15)',   color: '#ff2d55', border: 'rgba(255,45,85,0.4)' },
  high:     { bg: 'rgba(255,107,53,0.15)',  color: '#ff6b35', border: 'rgba(255,107,53,0.4)' },
  medium:   { bg: 'rgba(255,196,0,0.15)',   color: '#ffc400', border: 'rgba(255,196,0,0.4)' },
  low:      { bg: 'rgba(0,255,157,0.12)',   color: '#00ff9d', border: 'rgba(0,255,157,0.3)' },
}

export default function StatusBadge({ value, className = '' }) {
  const key = (value || 'unknown').toString()
  const style = LEVEL_STYLES[key] || LEVEL_STYLES.unknown

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-widest ${className}`}
      style={{
        background: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
      }}
    >
      {key.replace(/_/g, ' ')}
    </span>
  )
}
