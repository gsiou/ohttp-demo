import express from 'express'
import cors from 'cors'
import axios from 'axios'

const app = express()
const PORT = Number(process.env.PORT) || 3001
const DOWNSTREAM_URL = process.env.DOWNSTREAM_URL || 'http://localhost:3002'
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'

app.use(cors({ origin: ALLOWED_ORIGIN }))
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'relay', port: PORT })
})

app.get('/api/relay', async (_req, res) => {
  const started = Date.now()
  try {
    const r = await axios.get(`${DOWNSTREAM_URL}/api/gateway`, { timeout: 5000 })
    const elapsed = Date.now() - started
    res.json({
      service: 'relay',
      port: PORT,
      downstream: r.data,
      elapsed_ms: elapsed
    })
  } catch (err: any) {
    const elapsed = Date.now() - started
    res.status(502).json({
      service: 'relay',
      port: PORT,
      error: err?.message || 'Downstream error',
      elapsed_ms: elapsed
    })
  }
})

app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] relay (dev) listening on :${PORT} → downstream ${DOWNSTREAM_URL}`)
})
