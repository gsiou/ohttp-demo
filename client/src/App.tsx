import React, { useState } from 'react'

const relayUrl = import.meta.env.VITE_RELAY_URL || 'http://localhost:4001'

export default function App() {
  const [data, setData] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const callChain = async () => {
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const res = await fetch(`${relayUrl}/api/relay`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json = await res.json()
      setData(json)
    } catch (e: any) {
      setError(e.message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ fontFamily: 'system-ui, Arial, sans-serif', padding: 24 }}>
      <h1>Client → Relay → Gateway → Target</h1>
      <p>Relay URL: <code>{relayUrl}</code></p>
      <button onClick={callChain} disabled={loading} style={{ padding: '8px 12px' }}>
        {loading ? 'Calling…' : 'Call the chain'}
      </button>
      {error && <pre style={{ color: 'crimson', marginTop: 16 }}>{error}</pre>}
      {data && <pre style={{ background: '#f7f7f7', padding: 12, marginTop: 16, borderRadius: 8 }}>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  )
}
