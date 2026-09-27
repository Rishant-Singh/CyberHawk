import { useState, useEffect, useRef, useCallback } from 'react'
import axios from 'axios'
import { toast } from 'react-hot-toast'
import useThreatStore from '../store/threatStore'
import PageHeader from '../components/common/PageHeader'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Simple markdown renderer (bold, code, bullet lists, numbered lists)
function SimpleMarkdown({ text }) {
  if (!text) return null
  const lines = text.split('\n')
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        // Heading
        if (line.startsWith('## ')) return <div key={i} className="text-cyber-green font-bold text-sm mt-3">{line.slice(3)}</div>
        if (line.startsWith('# ')) return <div key={i} className="text-cyber-green font-bold text-base mt-3">{line.slice(2)}</div>
        if (line.startsWith('**') && line.endsWith('**')) return <div key={i} className="text-gray-200 font-semibold">{line.slice(2, -2)}</div>
        // Bullet list
        if (line.startsWith('- ') || line.startsWith('• ')) {
          return (
            <div key={i} className="flex gap-2 pl-2">
              <span className="text-cyber-green flex-shrink-0 mt-0.5">›</span>
              <span className="text-gray-300">{renderInline(line.slice(2))}</span>
            </div>
          )
        }
        // Numbered list
        const numMatch = line.match(/^(\d+)\.\s(.+)/)
        if (numMatch) {
          return (
            <div key={i} className="flex gap-2 pl-2">
              <span className="text-gray-600 flex-shrink-0 w-4">{numMatch[1]}.</span>
              <span className="text-gray-300">{renderInline(numMatch[2])}</span>
            </div>
          )
        }
        if (!line.trim()) return <div key={i} className="h-1" />
        return <div key={i} className="text-gray-300 leading-relaxed">{renderInline(line)}</div>
      })}
    </div>
  )
}

function renderInline(text) {
  // Bold: **text**
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} className="text-gray-100">{part.slice(2, -2)}</strong>
    if (part.startsWith('`') && part.endsWith('`'))
      return <code key={i} className="px-1 py-0.5 rounded text-[11px]"
        style={{ background: 'rgba(0,255,157,0.1)', color: '#00ff9d' }}>{part.slice(1, -1)}</code>
    return part
  })
}

function TypingDots() {
  return (
    <div className="flex gap-1 items-center py-1">
      {[0, 1, 2].map((i) => (
        <div key={i} className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-bounce"
          style={{ animationDelay: `${i * 0.15}s` }} />
      ))}
    </div>
  )
}

function ChatBubble({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} gap-3`}>
      {!isUser && (
        <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 mt-1"
          style={{ background: 'rgba(0,255,157,0.15)', border: '1px solid rgba(0,255,157,0.3)' }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <path d="M12 2C6.477 2 2 6.477 2 12c0 1.82.487 3.53 1.338 5L2 22l5.5-1.5A9.96 9.96 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2z" />
          </svg>
        </div>
      )}
      <div className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm font-mono leading-relaxed ${isUser ? 'rounded-tr-sm' : 'rounded-tl-sm'}`}
        style={{
          background: isUser ? 'rgba(0,255,157,0.12)' : 'rgba(15,20,40,0.9)',
          border: isUser ? '1px solid rgba(0,255,157,0.25)' : '1px solid rgba(255,255,255,0.07)',
          color: isUser ? '#d0ffe8' : '#c8d4f0',
        }}>
        {isUser ? (
          <span>{msg.content}</span>
        ) : (
          <SimpleMarkdown text={msg.content} />
        )}
        {msg.model && (
          <div className="text-[9px] text-gray-700 mt-2 text-right">
            via {msg.model}
          </div>
        )}
      </div>
      {isUser && (
        <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 mt-1 text-[10px] font-bold"
          style={{ background: 'rgba(100,120,200,0.2)', border: '1px solid rgba(100,120,200,0.3)', color: '#8899ee' }}>
          A
        </div>
      )}
    </div>
  )
}

const SUGGESTED = [
  'What are the top threats right now?',
  'How do I respond to a ransomware attack?',
  'Explain MITRE T1190 in simple terms',
  'What are signs of lateral movement?',
  'How do I hunt for C2 beaconing?',
  'Walk me through IR steps for a data breach',
]

export default function AIAssistant() {
  const token = useThreatStore((s) => s.accessToken)
  const authHeader = { headers: { Authorization: `Bearer ${token}` } }

  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "Hello! I'm **CyberHawk AI**, your SOC assistant. I can help you investigate threats, explain alerts, and guide incident response.\n\nWhat would you like to explore today?",
    },
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [suggestions, setSuggestions] = useState(SUGGESTED)
  const endRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const send = useCallback(async (text) => {
    const message = (text || input).trim()
    if (!message || loading) return

    const userMsg = { role: 'user', content: message }
    setMessages((m) => [...m, userMsg])
    setInput('')
    setLoading(true)

    try {
      const { data } = await axios.post(`${API}/api/ai/chat`, {
        message,
        history: messages.slice(-6),
      }, authHeader)

      setMessages((m) => [...m, { role: 'assistant', content: data.content, model: data.model }])
    } catch {
      setMessages((m) => [...m, {
        role: 'assistant',
        content: "I'm having trouble connecting to the AI service. Please check your GEMINI_API_KEY configuration.",
      }])
    } finally {
      setLoading(false)
      setTimeout(() => inputRef.current?.focus(), 100)
    }
  }, [input, messages, loading, token])

  const clearChat = () => {
    setMessages([{
      role: 'assistant',
      content: "Chat cleared. How can I help you with your security investigations?",
    }])
  }

  return (
    <div className="flex flex-col h-full gap-4">
      <PageHeader
        title="AI Threat Assistant"
        description="Powered by Google Gemini — ask anything about threats, alerts, and incident response"
        icon={
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
            <path d="M12 2a10 10 0 100 20 10 10 0 000-20z" />
            <path d="M12 8v4l3 3" />
          </svg>
        }
        action={
          <button onClick={clearChat}
            className="px-3 py-1.5 rounded text-[10px] font-mono text-gray-500 border border-gray-700 hover:text-white transition-all">
            Clear Chat
          </button>
        }
      />

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Chat panel */}
        <div className="flex-1 flex flex-col rounded-xl border overflow-hidden"
          style={{ background: 'rgba(6,10,24,0.95)', borderColor: 'rgba(0,255,157,0.12)' }}>
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {messages.map((msg, i) => (
              <ChatBubble key={i} msg={msg} />
            ))}
            {loading && (
              <div className="flex gap-3">
                <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{ background: 'rgba(0,255,157,0.15)', border: '1px solid rgba(0,255,157,0.3)' }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" strokeWidth="1.5">
                    <path d="M12 2C6.477 2 2 6.477 2 12c0 1.82.487 3.53 1.338 5L2 22l5.5-1.5A9.96 9.96 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2z" />
                  </svg>
                </div>
                <div className="px-4 py-3 rounded-2xl rounded-tl-sm"
                  style={{ background: 'rgba(15,20,40,0.9)', border: '1px solid rgba(255,255,255,0.07)' }}>
                  <TypingDots />
                </div>
              </div>
            )}
            <div ref={endRef} />
          </div>

          {/* Input */}
          <div className="border-t p-4" style={{ borderColor: 'rgba(0,255,157,0.1)' }}>
            <div className="flex gap-3">
              <input
                ref={inputRef}
                id="ai-chat-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && send()}
                placeholder="Ask about threats, alerts, MITRE techniques, incident response..."
                disabled={loading}
                className="flex-1 bg-transparent border rounded-xl px-4 py-3 text-sm font-mono text-gray-200 outline-none transition-all"
                style={{
                  borderColor: 'rgba(0,255,157,0.2)',
                  background: 'rgba(0,0,0,0.3)',
                }}
                onFocus={(e) => (e.target.style.borderColor = 'rgba(0,255,157,0.5)')}
                onBlur={(e) => (e.target.style.borderColor = 'rgba(0,255,157,0.2)')}
              />
              <button
                id="ai-send-btn"
                onClick={() => send()}
                disabled={loading || !input.trim()}
                className="w-12 h-12 rounded-xl flex items-center justify-center transition-all"
                style={{
                  background: input.trim() && !loading ? 'rgba(0,255,157,0.2)' : 'rgba(0,255,157,0.06)',
                  border: '1px solid rgba(0,255,157,0.3)',
                  color: '#00ff9d',
                }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Suggested prompts sidebar */}
        <div className="w-60 flex flex-col rounded-xl border overflow-hidden"
          style={{ background: 'rgba(6,10,24,0.8)', borderColor: 'rgba(0,255,157,0.1)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'rgba(0,255,157,0.1)' }}>
            <span className="text-[10px] font-mono text-gray-600 uppercase tracking-widest">Suggested Prompts</span>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {suggestions.map((prompt, i) => (
              <button key={i} onClick={() => send(prompt)}
                className="w-full text-left px-3 py-2.5 rounded-lg border text-[11px] font-mono text-gray-400 hover:text-cyber-green hover:border-cyber-green/30 hover:bg-white/4 transition-all leading-relaxed"
                style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                {prompt}
              </button>
            ))}
          </div>

          {/* Model badge */}
          <div className="px-4 py-3 border-t" style={{ borderColor: 'rgba(0,255,157,0.08)' }}>
            <div className="text-[9px] font-mono text-gray-700 uppercase tracking-widest">Powered by</div>
            <div className="text-[11px] font-mono text-gray-500 mt-0.5">Google Gemini 1.5 Flash</div>
          </div>
        </div>
      </div>
    </div>
  )
}
