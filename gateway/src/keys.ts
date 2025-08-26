// gen-key.ts
import { CipherSuite, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

export async function generateX25519KeyPair() {
  const suite = new CipherSuite({
    kem:  new DhkemX25519HkdfSha256(),
    kdf:  new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  // Raw key bytes suitable for RFC 9458 (publicKey is 32 bytes)
  const { publicKey, privateKey } = await suite.kem.generateKeyPair();
  return { publicKey, privateKey };
}
