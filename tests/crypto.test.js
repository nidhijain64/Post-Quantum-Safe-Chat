import { describe, it, expect } from 'vitest';
import { encryptMessage, decryptMessage } from '../lib/crypto';
import { fromBase64, base64ByteLength } from '../lib/encoding';

// The ML-KEM half of lib/crypto.js needs the browser WASM module, so these
// cover the AES-256-GCM layer that wraps whatever shared secret the KEM
// produced. A 32-byte secret stands in for the real encapsulation output.
const secret = () => globalThis.crypto.getRandomValues(new Uint8Array(32));

describe('AES-256-GCM message layer', () => {
  it('round-trips a message', async () => {
    const key = secret();
    const { cipherText, nonce } = await encryptMessage('attack at dawn', key);
    expect(await decryptMessage(cipherText, nonce, key)).toBe('attack at dawn');
  });

  it('round-trips unicode and emoji', async () => {
    const key = secret();
    const text = 'नमस्ते 🔐 çéü — post-quantum';
    const { cipherText, nonce } = await encryptMessage(text, key);
    expect(await decryptMessage(cipherText, nonce, key)).toBe(text);
  });

  it('never emits the plaintext in the ciphertext', async () => {
    const { cipherText, nonce } = await encryptMessage('hello bob', secret());
    expect(cipherText).not.toContain('hello');
    expect(nonce).not.toContain('hello');
  });

  it('uses a fresh 12-byte nonce every time', async () => {
    const key = secret();
    const a = await encryptMessage('same text', key);
    const b = await encryptMessage('same text', key);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.cipherText).not.toBe(b.cipherText); // identical plaintext, different output
    expect(base64ByteLength(a.nonce)).toBe(12);
  });

  it('fails to decrypt under the wrong key', async () => {
    const { cipherText, nonce } = await encryptMessage('secret', secret());
    await expect(decryptMessage(cipherText, nonce, secret())).rejects.toThrow();
  });

  it('rejects a tampered ciphertext — GCM integrity holds', async () => {
    const key = secret();
    const { cipherText, nonce } = await encryptMessage('transfer 100', key);

    const bytes = fromBase64(cipherText);
    bytes[0] ^= 0xff; // flip one byte
    const tampered = Buffer.from(bytes).toString('base64');

    await expect(decryptMessage(tampered, nonce, key)).rejects.toThrow();
  });

  it('rejects a swapped nonce', async () => {
    const key = secret();
    const a = await encryptMessage('message one', key);
    const b = await encryptMessage('message two', key);
    await expect(decryptMessage(a.cipherText, b.nonce, key)).rejects.toThrow();
  });

  it('only uses the first 32 bytes of the shared secret', async () => {
    const base = secret();
    const padded = new Uint8Array(64);
    padded.set(base, 0); // same first 32 bytes, extra trailing data
    const { cipherText, nonce } = await encryptMessage('hi', base);
    expect(await decryptMessage(cipherText, nonce, padded)).toBe('hi');
  });
});
