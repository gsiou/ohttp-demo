import express from 'express'
import cors from 'cors'
import axios from 'axios'
import { generateX25519KeyPair } from './keys';

const app = express()
const PORT = Number(process.env.PORT) || 3002
const DOWNSTREAM_URL = process.env.DOWNSTREAM_URL || 'http://localhost:3003'
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'

app.use(cors({ origin: ALLOWED_ORIGIN }))
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'gateway', port: PORT })
})

app.get('/api/gateway', async (_req, res) => {
  const started = Date.now()
  try {
    const r = await axios.get(`${DOWNSTREAM_URL}/api/target`, { timeout: 5000 })
    const elapsed = Date.now() - started
    res.json({
      service: 'gateway',
      port: PORT,
      downstream: r.data,
      elapsed_ms: elapsed
    })
  } catch (err: any) {
    const elapsed = Date.now() - started
    res.status(502).json({
      service: 'gateway',
      port: PORT,
      error: err?.message || 'Downstream error',
      elapsed_ms: elapsed
    })
  }
})

app.get('/api/testkeys', async(_req, _res) => {
  const {publicKey, privateKey} = await generateX25519KeyPair();
  console.log(publicKey);
  return _res.status(200).send();
});

app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] gateway (dev) listening on :${PORT} → downstream ${DOWNSTREAM_URL}`)
})
