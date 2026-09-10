import { describe, it, expect } from 'vitest';
import { toBase64, fromBase64, base64ByteLength } from '../lib/encoding';
import { ML_KEM_768 } from '../lib/validate';

describe('base64 encoding', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    expect(Array.from(fromBase64(toBase64(bytes)))).toEqual(Array.from(bytes));
  });

  it('round-trips every byte value including 0x00 and 0xFF', () => {
    const edges = new Uint8Array([0, 1, 127, 128, 254, 255]);
    expect(Array.from(fromBase64(toBase64(edges)))).toEqual([0, 1, 127, 128, 254, 255]);
  });

  it('handles an empty array', () => {
    expect(toBase64(new Uint8Array([]))).toBe('');
  });

  it('accepts an ArrayBuffer as well as a Uint8Array', () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    expect(toBase64(bytes.buffer)).toBe(toBase64(bytes));
  });

  describe('base64ByteLength', () => {
    it('matches the real decoded length across every padding case', () => {
      for (let n = 0; n < 40; n++) {
        const encoded = toBase64(new Uint8Array(n));
        expect(base64ByteLength(encoded)).toBe(n);
      }
    });

    it('reports the documented ML-KEM-768 sizes', () => {
      const pk = toBase64(new Uint8Array(ML_KEM_768.publicKey));
      const ct = toBase64(new Uint8Array(ML_KEM_768.cipherText));
      expect(pk.length).toBe(1580);
      expect(ct.length).toBe(1452);
      expect(base64ByteLength(pk)).toBe(1184);
      expect(base64ByteLength(ct)).toBe(1088);
    });
  });
});
