// keys.ts
import { CipherSuite, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { DhkemX25519HkdfSha256, X25519 } from "@hpke/dhkem-x25519";

// Single u16be helper
function u16be(n: number) {
  const b = new Uint8Array(2);
  b[0] = (n >>> 8) & 0xff;
  b[1] = n & 0xff;
  return b;
}

export async function generateX25519KeyPair() {
  const suite = new CipherSuite({
    kem:  new DhkemX25519HkdfSha256(),
    kdf:  new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  const { publicKey, privateKey } = await suite.kem.generateKeyPair();
  console.log(publicKey.constructor?.name);
  const x = new X25519(new HkdfSha256());
  // Export raw 32-byte X25519 public key for RFC 9458
  const rawPub = new Uint8Array(await x.serializePublicKey(publicKey)); // 32 bytes

  // const rawPriv = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));

  return {
    publicKey: publicKey,
    publicKeyRaw: rawPub,            // Uint8Array (32 bytes)
    privateKey,
    // privateKeyRaw: rawPriv,
  };
}

export type KdfAead = { kdfId: number; aeadId: number };

export function encodeKeyConfig(params: {
  keyId: number;                 // 0..255
  kemId: number;
  publicKey: Uint8Array;         // RAW bytes from the KEM (32B for X25519)
  kdfAeadPairs: KdfAead[];       // one or more (KDF, AEAD) pairs
}): Uint8Array {
  const { keyId, kemId, publicKey, kdfAeadPairs } = params;

  if (keyId < 0 || keyId > 255) throw new Error("keyId must be 0..255");
  if (!publicKey?.length)        throw new Error("publicKey is required");
  if (!kdfAeadPairs.length)      throw new Error("at least one KDF/AEAD pair required");

  const algs = new Uint8Array(kdfAeadPairs.length * 4);
  kdfAeadPairs.forEach((p, i) => {
    algs.set(u16be(p.kdfId),  i * 4 + 0);
    algs.set(u16be(p.aeadId), i * 4 + 2);
  });

  const parts = [
    Uint8Array.of(keyId & 0xff),
    u16be(kemId),
    publicKey,
    u16be(algs.length),
    algs,
  ];

  const totalLen = parts.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(totalLen);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export function encodeOhttpKeys(configs: Uint8Array[]): Uint8Array {
  const chunks = configs.map(cfg => {
    const len = u16be(cfg.length);
    const out = new Uint8Array(2 + cfg.length);
    out.set(len, 0);
    out.set(cfg, 2);
    return out;
  });

  const total = chunks.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}
