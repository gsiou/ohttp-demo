import express from 'express'
import cors from 'cors'
import axios from 'axios'
import { encodeKeyConfig, encodeOhttpKeys, generateX25519KeyPair } from './keys';

const app = express()
const PORT = Number(process.env.PORT) || 3002
const DOWNSTREAM_URL = process.env.DOWNSTREAM_URL || 'http://localhost:3003'
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'

app.use(cors({ origin: ALLOWED_ORIGIN }))
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'gateway', port: PORT })
})

app.all('/api/gateway', async (_req, res) => {
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

app.get('/.well-known/ohttp-gateway', async (_req, res) => {
  const { publicKeyRaw } = await generateX25519KeyPair();

  const keyConfig = encodeKeyConfig({
    keyId: 0x01,
    kemId: 0x0020,                 // X25519
    publicKey: publicKeyRaw,
    kdfAeadPairs: [
      // { kdfId: 0x0001, aeadId: 0x0003 }, // HKDF-SHA256 + ChaCha20-Poly1305
      { kdfId: 0x0001, aeadId: 0x0001 }, // AES-128-GCM
    ],
  });

  const body = encodeOhttpKeys([keyConfig]);

  res
    .status(200)
    .type('application/ohttp-keys')
    .send(Buffer.from(body));
});

app.get('/api/testkeys', async (_req, res) => {
  const { publicKeyRaw } = await generateX25519KeyPair();
  res.json({ publicKeyHex: Buffer.from(publicKeyRaw).toString('hex') });
});

app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] gateway (dev) listening on :${PORT} → downstream ${DOWNSTREAM_URL}`)
})
