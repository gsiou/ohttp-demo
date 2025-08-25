import express from 'express'
import cors from 'cors'

const app = express()
const PORT = Number(process.env.PORT) || 3003
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'

app.use(cors({ origin: ALLOWED_ORIGIN }))
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'target', port: PORT })
})

app.get('/api/target', (_req, res) => {
  res.json({
    service: 'target',
    port: PORT,
    message: 'Hello from target!',
    time: new Date().toISOString()
  })
})

app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] target (dev) listening on :${PORT}`)
})
