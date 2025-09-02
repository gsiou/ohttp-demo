import React, { useState } from 'react'
import { CipherSuite, HkdfSha256, Aes128Gcm } from '@hpke/core'
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519'

const relayUrl = import.meta.env.VITE_RELAY_URL || 'http://localhost:4001'
const gatewayUrl = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:4002'

type KdfAead = { kdfId: number; aeadId: number }
type KeyConfig = { keyId: number; kemId: number; publicKey: Uint8Array; pairs: KdfAead[] }

const toHex = (u8?: Uint8Array | null) => u8 ? [...u8].map(b => b.toString(16).padStart(2, '0')).join('') : ''

const toArrayBuffer = (u8: Uint8Array) =>
  u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

function encode1(val: number): Uint8Array {
  if (val < 0 || val > 0xff) throw new Error("encode1: out of range");
  return Uint8Array.of(val & 0xff);
}

function encode2(val: number): Uint8Array {
  if (val < 0 || val > 0xffff) throw new Error("encode2: out of range");
  return Uint8Array.of((val >>> 8) & 0xff, val & 0xff);
}

// concat multiple Uint8Arrays
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// --- RFC 9292 / QUIC-style varint encoder (1/2/4/8 bytes) ---
function encVarint(v: number | bigint): Uint8Array {
  const n = typeof v === 'bigint' ? v : BigInt(v);
  if (n < 0n) throw new Error("varint must be non-negative");
  if (n <= 63n) {
    // 00xxxxxx
    return Uint8Array.of(Number(n & 0x3fn));
  } else if (n <= 16383n) {
    // 01xxxxxx (2 bytes)
    const val = Number(n);
    const b0 = 0x40 | ((val >>> 8) & 0x3f);
    const b1 = val & 0xff;
    return Uint8Array.of(b0, b1);
  } else if (n <= 1073741823n) {
    // 10xxxxxx (4 bytes)
    const val = Number(n);
    const b0 = 0x80 | ((val >>> 24) & 0x3f);
    const b1 = (val >>> 16) & 0xff;
    const b2 = (val >>> 8) & 0xff;
    const b3 = val & 0xff;
    return Uint8Array.of(b0, b1, b2, b3);
  } else if (n <= 4611686018427387903n) {
    // 11xxxxxx (8 bytes)
    let x = n;
    const out = new Uint8Array(8);
    out[0] = 0xC0 | Number((x >> 56n) & 0x3fn);
    out[1] = Number((x >> 48n) & 0xffn);
    out[2] = Number((x >> 40n) & 0xffn);
    out[3] = Number((x >> 32n) & 0xffn);
    out[4] = Number((x >> 24n) & 0xffn);
    out[5] = Number((x >> 16n) & 0xffn);
    out[6] = Number((x >> 8n) & 0xffn);
    out[7] = Number(x & 0xffn);
    return out;
  } else {
    throw new Error("varint too large (max 2^62-1)");
  }
}

function u8(s: string | Uint8Array): Uint8Array {
  return typeof s === 'string' ? new TextEncoder().encode(s) : s;
}

// A single Field Line: NameLen(i), Name, ValueLen(i), Value
function encFieldLine(name: string, value: string | Uint8Array): Uint8Array {
  if (!name || /[A-Z]/.test(name))
    throw new Error("field name must be lowercase and non-empty");
  const n = u8(name);
  const v = u8(value);
  if (n.length < 1) throw new Error("field name must be at least 1 byte");
  return concat(encVarint(n.length), n, encVarint(v.length), v);
}

// Known-Length Field Section:
//   Length(i) = total bytes of concatenated Field Lines (no terminator)
//   FieldLine...
function encKnownFieldSection(headers: Array<[string, string | Uint8Array]>): Uint8Array {
  const lines = headers.map(([k, v]) => encFieldLine(k, v));
  const body = concat(...lines);
  return concat(encVarint(body.length), body);
}

// Indeterminate-Length Field Section:
//   FieldLine... ; then Content Terminator(i)=0
function encIndetFieldSection(headers: Array<[string, string | Uint8Array]>): Uint8Array {
  const lines = headers.map(([k, v]) => encFieldLine(k, v));
  return concat(...lines, encVarint(0));
}

// Request Control Data:
//   MethodLen(i), Method, SchemeLen(i), Scheme,
//   AuthorityLen(i), Authority, PathLen(i), Path
function encRequestControlData(
  method: string,
  scheme: string,
  authority: string,   // can be ""
  path: string         // e.g. "/foo?bar=baz"
): Uint8Array {
  const m = u8(method);
  const s = u8(scheme);
  const a = u8(authority); // may be length 0
  const p = u8(path);
  return concat(
    encVarint(m.length), m,
    encVarint(s.length), s,
    encVarint(a.length), a,
    encVarint(p.length), p
  );
}

// --- Content encoders ---
function encKnownContent(body?: Uint8Array): Uint8Array {
  const b = body ?? new Uint8Array(0);
  return concat(encVarint(b.length), b);
}

// Indeterminate content: ChunkLen(i)>0, Chunk..., ... , 0
function encIndetContent(chunks: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const c of chunks) {
    if (!c || c.length === 0) continue;  // skip empty
    parts.push(encVarint(c.length), c);
  }
  parts.push(encVarint(0)); // terminator
  return concat(...parts);
}

// --- Known-Length Request ---
// FramingIndicator(i)=0, RequestControlData, Known-Length Header Section,
// Known-Length Content, Known-Length Trailer Section, (optional) Padding(zeros)
function encodeKnownLengthRequest(opts: {
  method: string;
  scheme: string;            // e.g. "https"
  authority: string;         // host[:port], "" allowed
  path: string;              // absolute-path + query, e.g. "/v1/check?x=1"
  headers?: Array<[string, string | Uint8Array]>;
  body?: Uint8Array;         // if undefined, length 0 (and trailers can be omitted per truncation rules)
  trailers?: Array<[string, string | Uint8Array]>;
  padBytes?: number;         // number of trailing zero bytes to add
}): Uint8Array {
  const framing = encVarint(0); // known-length request
  const rcd = encRequestControlData(opts.method, opts.scheme, opts.authority, opts.path);

  const hdrs = encKnownFieldSection(opts.headers ?? []);
  const content = encKnownContent(opts.body);
  const trls = encKnownFieldSection(opts.trailers ?? []);

  // RFC 9292 allows truncating empty content+trailers instead of emitting explicit 0 lengths.
  // if body and trailers are both empty, we can omit both sections entirely.
  const emptyBody = !opts.body || opts.body.length === 0;
  const emptyTrailers = !opts.trailers || opts.trailers.length === 0;

  const parts: Uint8Array[] = [framing, rcd, hdrs];
  if (!(emptyBody && emptyTrailers)) {
    parts.push(content);
    if (!emptyTrailers) parts.push(trls);
    else {
      // If trailers are empty but body present (possibly empty), still include zero-length trailers.
      parts.push(encVarint(0)); // Known-Length Field Section with Length=0
    }
  }
  if (opts.padBytes && opts.padBytes > 0) {
    parts.push(new Uint8Array(opts.padBytes)); // zero padding
  }
  return concat(...parts);
}

// --- Indeterminate-Length Request ---
// FramingIndicator(i)=2, RequestControlData, Indet Header Section,
// Indet Content, Indet Trailer Section, (optional) Padding
function encodeIndeterminateLengthRequest(opts: {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  headers?: Array<[string, string | Uint8Array]>;
  bodyChunks?: Uint8Array[];   // zero or more chunks
  trailers?: Array<[string, string | Uint8Array]>;
  padBytes?: number;
}): Uint8Array {
  const framing = encVarint(2); // indeterminate-length request
  const rcd = encRequestControlData(opts.method, opts.scheme, opts.authority, opts.path);

  const hdrs = encIndetFieldSection(opts.headers ?? []);
  const content = encIndetContent(opts.bodyChunks ?? []);
  const trls = encIndetFieldSection(opts.trailers ?? []);

  const parts: Uint8Array[] = [framing, rcd, hdrs, content, trls];
  if (opts.padBytes && opts.padBytes > 0) parts.push(new Uint8Array(opts.padBytes));
  return concat(...parts);
}

// --- Convenience: build headers from a JS object (lowercases keys) ---
function headersFromObject(obj: Record<string, string | Uint8Array>): Array<[string, string | Uint8Array]> {
  return Object.entries(obj).map(([k, v]) => [k.toLowerCase(), v]);
}


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
