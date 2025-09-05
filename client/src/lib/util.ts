export const toHex = (u8?: Uint8Array | null) => u8 ? [...u8].map(b => b.toString(16).padStart(2, '0')).join('') : ''

export const toArrayBuffer = (u8: Uint8Array) => {
  if (
    u8.byteOffset === 0 &&
    u8.buffer instanceof ArrayBuffer &&
    u8.buffer.byteLength === u8.byteLength
  ) {
    return u8.buffer; // exact ArrayBuffer
  }
  // otherwise, copy into a fresh ArrayBuffer (so that it always returns ArrayBuffer)
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
}
  // u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

export function encode1(val: number): Uint8Array {
  if (val < 0 || val > 0xff) throw new Error("encode1: out of range");
  return Uint8Array.of(val & 0xff);
}

export function encode2(val: number): Uint8Array {
  if (val < 0 || val > 0xffff) throw new Error("encode2: out of range");
  return Uint8Array.of((val >>> 8) & 0xff, val & 0xff);
}

// concat multiple Uint8Arrays
export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}