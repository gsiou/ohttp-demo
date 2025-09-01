import express from 'express'
import cors from 'cors'
import axios from 'axios'
import { createProxyMiddleware } from "http-proxy-middleware";

const app = express()
const PORT = Number(process.env.PORT) || 3001
const DOWNSTREAM_URL = process.env.DOWNSTREAM_URL || 'http://localhost:3002'
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'

app.use(cors({ origin: ALLOWED_ORIGIN }))
app.use(express.json())

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'relay', port: PORT })
})

app.use('/api/relay', createProxyMiddleware({
    // target: `${DOWNSTREAM_URL}/api/gateway`,
    target: 'https://host.docker.internal:4567/gateway-echo',
    changeOrigin: true,          // sets Host to target host
    secure: false,
    xfwd: true,                  // adds X-Forwarded-* headers
    ws: true,                    // proxy websockets if needed
    pathRewrite: { "/api/relay/": "" }, // /proxy/foo -> /foo
    onProxyReq(proxyReq, req, res) {
      // e.g., add custom headers
      proxyReq.setHeader("X-From-Proxy", "Express");
    },
    onError(err, req, res) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Bad gateway", details: err.message }));
    },
  }));

app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] relay (dev) listening on :${PORT} → downstream ${DOWNSTREAM_URL}`)
})
