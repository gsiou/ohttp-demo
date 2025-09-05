import React, { useState } from 'react'
import { CipherSuite, HkdfSha256, Aes128Gcm } from '@hpke/core'
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519'
import { decodeKnownLengthRequest, encodeKnownLengthRequest, headersFromObject } from './lib/bhttp'
import { concat, encode1, encode2, toArrayBuffer, toHex } from './lib/util'

const relayUrl = import.meta.env.VITE_RELAY_URL || 'http://localhost:4001'
const gatewayUrl = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:4002'

type KdfAead = { kdfId: number; aeadId: number }
type KeyConfig = { keyId: number; kemId: number; publicKey: Uint8Array; pairs: KdfAead[] }

const parseOhttpKeys = (buf: ArrayBuffer): KeyConfig[] => {
  const dv = new DataView(buf)
  const out: KeyConfig[] = []
  let off = 0
  console.log(dv);
  while (off + 2 <= dv.byteLength) {
    console.log("off=", off);
    const cfgLen = dv.getUint16(off, false); off += 2
    if (off + cfgLen > dv.byteLength) break
    const base = off
    let p = 0

    const keyId = dv.getUint8(base + p); p += 1
    const kemId = dv.getUint16(base + p, false); p += 2

    console.log("keyId=", keyId)
    console.log("kemId=", kemId)

    // demo: support X25519 (0x0020) only
    const pubLen = kemId === 0x0020 ? 32 : (() => { throw new Error(`Unsupported KEM 0x${kemId.toString(16)}`) })()
    // const pubLen = 32;
    const publicKey = new Uint8Array(buf, base + p, pubLen); p += pubLen

    const algsLen = dv.getUint16(base + p, false); p += 2
    if (algsLen % 4 !== 0) throw new Error('Bad algs length')
    const pairs: KdfAead[] = []
    for (let i = 0; i < algsLen; i += 4) {
      const kdfId  = dv.getUint16(base + p + i + 0, false)
      const aeadId = dv.getUint16(base + p + i + 2, false)
      pairs.push({ kdfId, aeadId })
    }

    out.push({ keyId, kemId, publicKey: new Uint8Array(publicKey), pairs })
    off += cfgLen
  }
  return out
}

const buildSuite = (kdfId: number, aeadId: number) => {
  // demo: KDF must be HKDF-SHA256 (0x0001) for our helper
  if (kdfId !== 0x0001) throw new Error(`Unsupported KDF 0x${kdfId.toString(16)} in demo`)
  const kem  = new DhkemX25519HkdfSha256()
  const kdf  = new HkdfSha256()
  if (aeadId !== 0x0001) throw new Error(`Unsupported AEAD 0x${aeadId.toString(16)} in demo`)
  const aead = new Aes128Gcm()
  return new CipherSuite({ kem, kdf, aead })
}

const importGatewayPublicKey = async (suite: CipherSuite, raw: Uint8Array) => {
  const kem: any = (suite as any).kem

  if (typeof kem.deserializePublicKey === 'function') {
    console.log("Using decerializePublicKey");
    return await kem.deserializePublicKey(raw)
  }
}

export default function App() {
  const [data, setData] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const [keysInfo, setKeysInfo] = useState<{
    keyId?: number
    kemId?: number
    kdfId?: number
    aeadId?: number
    pubHex?: string
  } | null>(null)

  const [hpkeOut, setHpkeOut] = useState<{
    enc?: ArrayBuffer
    ciphertext?: ArrayBuffer
  } | null>(null)

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

  // Derive `len` bytes using HKDF-SHA256 with arbitrary salt
  // Avoid hpke lib because of weird salt size limitation
  async function hkdfExpandWebCrypto(
    ikm: ArrayBuffer,            // HPKE-exported `secret`
    salt: Uint8Array,            // enc || response_nonce
    infoLabel: string,           // "key" or "nonce"
    len: number                  // bytes to derive
  ): Promise<Uint8Array> {
    const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const info = new TextEncoder().encode(infoLabel);
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(salt), info },
      baseKey,
      len * 8
    );
    return new Uint8Array(bits);
  }


  async function decryptEncapsulatedResponse(
    suite: CipherSuite,
    sender: any,                     // HPKE sender context
    encFromRequest: ArrayBuffer,     // enc
    encResponseBuf: ArrayBuffer      // bytes from relay's HTTP body
  ): Promise<Uint8Array> {
    // TODO: unhardcode these
    const Nk = 16; // key bytes
    const Nn = 12; // nonce bytes
    const L  = Math.max(Nk, Nn);

    const encU8   = new Uint8Array(encFromRequest);
    const respU8  = new Uint8Array(encResponseBuf);
    if (respU8.length < L) throw new Error("ohttp-res too short");

    const responseNonce = respU8.slice(0, L);
    const ct            = respU8.slice(L);

    // RFC 9458 §4.4 step 1: exporter secret
    const exporterCtx = new TextEncoder().encode("message/bhttp response");
    const secret = await sender.export(exporterCtx, L); // length = max(Nn, Nk)

    // RFC 9458 §4.4 steps 3–5: HKDF( salt=enc||responseNonce )
    const kdf : any = (suite as any).kdf;
    const salt = concat(encU8, responseNonce);
    // const prk  = await kdf.extract(toArrayBuffer(salt), secret);
    // const aeadKey   = await kdf.expand(prk, new TextEncoder().encode("key"),   Nk);
    // const aeadNonce = await kdf.expand(prk, new TextEncoder().encode("nonce"), Nn);
    const aeadKey   = await hkdfExpandWebCrypto(secret, salt, "key",   Nk);
    const aeadNonce = await hkdfExpandWebCrypto(secret, salt, "nonce", Nn);


    const aeadCtx = (suite as any).aead.createEncryptionContext(toArrayBuffer(aeadKey));
    const pt = await aeadCtx.open(
      toArrayBuffer(aeadNonce),        // nonce
      toArrayBuffer(ct),               // ciphertext+tag
      new ArrayBuffer(0)      // AAD
    );

    return new Uint8Array(pt);
  }

  const fetchKeyConfig = async () => {
    setError(null)
    setKeysInfo(null)
    setHpkeOut(null)
    try {
      // const res = await fetch(`${gatewayUrl}/.well-known/ohttp-gateway`, {
      const res = await fetch('https://localhost:4567/ohttp-keys', {
        headers: { Accept: 'application/ohttp-keys' },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const buf = await res.arrayBuffer()

      const cfgs = parseOhttpKeys(buf)
      if (!cfgs.length) throw new Error('No key configs found')
      const cfg = cfgs[0]
      if (!cfg.pairs.length) throw new Error('No symmetric alg pairs in config')
      const { kdfId, aeadId } = cfg.pairs[0] // demo: first pair

      setKeysInfo({
        keyId: cfg.keyId,
        kemId: cfg.kemId,
        kdfId,
        aeadId,
        pubHex: toHex(cfg.publicKey),
      })

      const suite = buildSuite(kdfId, aeadId)
      const recip = await importGatewayPublicKey(suite, cfg.publicKey)

      const hdr = concat(
        encode1(cfg.keyId),
        encode2(cfg.kemId),
        encode2(kdfId),
        encode2(aeadId)
      );

      console.log("hdr length =", hdr.length); // 7 bytes
      console.log("hdr hex =", [...hdr].map(b => b.toString(16).padStart(2,'0')).join(''));

      const info = concat(
        new TextEncoder().encode("message/bhttp request"),
        encode1(0), // single zero byte
        hdr
      );

      console.log("info length =", info.length);
      console.log("info hex =", [...info].map(b => b.toString(16).padStart(2,'0')).join(''));

      const sender = await suite.createSenderContext({
        recipientPublicKey: recip,
        info: toArrayBuffer(info) as ArrayBuffer
      })

      // const ct = await sender.seal(new TextEncoder().encode("Hello world!").buffer);
      const ephemeralPublic = sender.enc;

      const body = new TextEncoder().encode('{"x":1}');

      const req = encodeKnownLengthRequest({
        method: "POST",
        scheme: "https",
        authority: "example.com",
        path: "/echo",
        headers: headersFromObject({
          "content-type": "application/json",
        }),
        body,                 // <— known-length body
        // trailers: []       // trailers are known-length too; zero-length is encoded as 0
      });
      console.log(toHex(req));
      const ct2 = await sender.seal(toArrayBuffer(req) as ArrayBuffer);

      const encapsulatedRequest = concat(
        encode1(cfg.keyId),
        encode2(cfg.kemId),
        encode2(kdfId),
        encode2(aeadId),
        new Uint8Array(ephemeralPublic),
        new Uint8Array(ct2)
      )

      const res2 = await fetch(`${relayUrl}/api/relay`, {
        method: 'POST',
        headers: { 'Content-Type': 'message/ohttp-req' },
        body: toArrayBuffer(encapsulatedRequest) as ArrayBuffer,
      });

      console.log("Info");
      console.log(toHex(info));

      console.log("Encapsulated request");
      console.log(toHex(encapsulatedRequest));

      // Handle response (ciphertext of the Encapsulated Response)
      if (!res2.ok) throw new Error(`Relay HTTP ${res2.status}`);

      const responseBuffer = await res2.arrayBuffer()
      console.log("Response");
      console.log(toHex(new Uint8Array(responseBuffer)));
  
      const plaintextBhttp = await decryptEncapsulatedResponse(
        suite,
        sender,
        ephemeralPublic,
        responseBuffer
      );

      console.log("BHTTP:")
      console.log(toHex(plaintextBhttp));

      const decodedRequest = decodeKnownLengthRequest(plaintextBhttp);
      console.log(decodedRequest);
      setHpkeOut({ ciphertext: ct2 });

    } catch (e: any) {
      setError(e.message || 'Unknown error while fetching/parsing keys')
      console.log(e);
    }
  }

  return (
    <div style={{ fontFamily: 'system-ui, Arial, sans-serif', padding: 24 }}>
      <h1>Client → Relay → Gateway → Target</h1>
      <p>Relay URL: <code>{relayUrl}</code></p>
      <button onClick={callChain} disabled={loading} style={{ padding: '8px 12px' }}>
        {loading ? 'Calling…' : 'Call the chain'}
      </button>

      <div style={{ height: 16 }} />

      <p>Gateway URL: <code>{gatewayUrl}</code></p>
      <button onClick={fetchKeyConfig} style={{ padding: '8px 12px' }}>
        Fetch Keys &amp; HPKE (demo)
      </button>

      {error && <pre style={{ color: 'crimson', marginTop: 16 }}>{error}</pre>}
      {data && <pre style={{ background: '#f7f7f7', padding: 12, marginTop: 16, borderRadius: 8 }}>{JSON.stringify(data, null, 2)}</pre>}

      {keysInfo && (
        <div style={{ marginTop: 24 }}>
          <h3>Parsed Key Config (demo picks first)</h3>
          <ul>
            <li>Key ID: <code>{keysInfo.keyId}</code></li>
            <li>KEM ID: <code>0x{(keysInfo.kemId ?? 0).toString(16).padStart(4,'0')}</code> (expect 0x0020 for X25519)</li>
            <li>KDF ID: <code>0x{(keysInfo.kdfId ?? 0).toString(16).padStart(4,'0')}</code></li>
            <li>AEAD ID: <code>0x{(keysInfo.aeadId ?? 0).toString(16).padStart(4,'0')}</code></li>
            <li>Public Key (hex, first 16 bytes): <code>{keysInfo.pubHex?.slice(0, 32)}…</code></li>
          </ul>
        </div>
      )}

      {hpkeOut && (
        <div style={{ marginTop: 24 }}>
          <h3>HPKE Sender Output</h3>
          <div>enc (ephemeral key to send):</div>
          <pre style={{ background: '#f7f7f7', padding: 12, borderRadius: 8, wordBreak: 'break-all' }}>
            {hpkeOut.enc && toHex(new Uint8Array(hpkeOut.enc))}
          </pre>
          <div>ciphertext:</div>
          <pre style={{ background: '#f7f7f7', padding: 12, borderRadius: 8, wordBreak: 'break-all' }}>
            {hpkeOut.ciphertext && toHex(new Uint8Array(hpkeOut.ciphertext))}
          </pre>
        </div>
      )}
    </div>
  )
}
