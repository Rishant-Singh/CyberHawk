// Reusable Modal overlay component
export default function Modal({ open, onClose, title, children, maxWidth = 'max-w-2xl' }) {
  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className={`relative w-full ${maxWidth} rounded-xl border overflow-hidden`}
        style={{
          background: 'linear-gradient(135deg, rgba(8,12,28,0.99) 0%, rgba(5,8,20,0.99) 100%)',
          borderColor: 'rgba(0,255,157,0.2)',
          boxShadow: '0 0 60px rgba(0,255,157,0.08), 0 25px 50px rgba(0,0,0,0.6)',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-4 border-b"
          style={{ borderColor: 'rgba(0,255,157,0.15)' }}
        >
          <h2 className="text-sm font-mono font-bold text-cyber-green tracking-widest uppercase">
            {title}
          </h2>
          <button
            onClick={onClose}
            className="w-7 h-7 rounded flex items-center justify-center text-gray-500 hover:text-white hover:bg-white/10 transition-all"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 max-h-[80vh] overflow-y-auto">
          {children}
        </div>
      </div>
    </div>
  )
}
