// Page header with icon, title, description, and optional action button
export default function PageHeader({ icon, title, description, action }) {
  return (
    <div className="flex items-center justify-between mb-6">
      <div className="flex items-center gap-4">
        {icon && (
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{
              background: 'rgba(0,255,157,0.08)',
              border: '1px solid rgba(0,255,157,0.2)',
            }}
          >
            {icon}
          </div>
        )}
        <div>
          <h1 className="text-lg font-['Orbitron',sans-serif] font-bold text-white tracking-wide">
            {title}
          </h1>
          {description && (
            <p className="text-xs font-mono text-gray-500 mt-0.5">{description}</p>
          )}
        </div>
      </div>
      {action && <div>{action}</div>}
    </div>
  )
}
