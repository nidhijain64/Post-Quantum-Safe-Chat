import { describe, it, expect } from 'vitest';
import {
  validateUsername, validatePassword, validatePublicKey, validateEncryptedBlob, ML_KEM_768
} from '../lib/validate';
import { toBase64 } from '../lib/encoding';

const b64OfSize = (n) => toBase64(new Uint8Array(n));

describe('validateUsername', () => {
  it('accepts ordinary names', () => {
    for (const ok of ['alice', 'bob_99', 'Nidhi_Jain', 'abc']) {
      expect(validateUsername(ok)).toBeNull();
    }
  });

  it('rejects names that are too short or too long', () => {
    expect(validateUsername('ab')).toBeTruthy();
    expect(validateUsername('a'.repeat(21))).toBeTruthy();
  });

  it('rejects characters that could confuse a query or a path', () => {
    for (const bad of ['alice bob', 'al/ice', '../etc', 'a$b', '<script>', 'née']) {
      expect(validateUsername(bad)).toBeTruthy();
    }
  });

  it('rejects non-strings and blanks', () => {
    for (const bad of [null, undefined, 42, {}, '', '   ']) {
      expect(validateUsername(bad)).toBeTruthy();
    }
  });
});

describe('validatePassword', () => {
  it('requires at least 8 characters', () => {
    expect(validatePassword('short7!')).toBeTruthy();
    expect(validatePassword('longenough')).toBeNull();
  });

  it('rejects absurdly long input', () => {
    expect(validatePassword('a'.repeat(201))).toBeTruthy();
  });

  it('rejects non-strings', () => {
    expect(validatePassword(undefined)).toBeTruthy();
  });
});

describe('validatePublicKey', () => {
  it('accepts a correctly sized ML-KEM-768 key', () => {
    expect(validatePublicKey(b64OfSize(ML_KEM_768.publicKey))).toBeNull();
  });

  it('rejects a key of the wrong size', () => {
    expect(validatePublicKey(b64OfSize(800))).toBeTruthy();          // Kyber-512-ish
    expect(validatePublicKey(b64OfSize(1568))).toBeTruthy();         // ML-KEM-1024
  });

  it('rejects non-base64 input', () => {
    expect(validatePublicKey('not base64!!')).toBeTruthy();
    expect(validatePublicKey('')).toBeTruthy();
    expect(validatePublicKey(null)).toBeTruthy();
  });
});

describe('validateEncryptedBlob', () => {
  const good = () => ({
    kemCipherText: b64OfSize(ML_KEM_768.cipherText),
    nonce: b64OfSize(12),
    cipherText: b64OfSize(64)
  });

  it('accepts a well-formed blob', () => {
    expect(validateEncryptedBlob(good())).toBeNull();
  });

  it('rejects a KEM ciphertext of the wrong length', () => {
    expect(validateEncryptedBlob({ ...good(), kemCipherText: b64OfSize(768) })).toBeTruthy();
  });

  it('rejects a nonce that is not 12 bytes', () => {
    expect(validateEncryptedBlob({ ...good(), nonce: b64OfSize(16) })).toBeTruthy();
  });

  it('rejects an oversized payload', () => {
    expect(validateEncryptedBlob({ ...good(), cipherText: b64OfSize(9 * 1024) })).toBeTruthy();
  });

  it('rejects missing fields and non-objects', () => {
    expect(validateEncryptedBlob(null)).toBeTruthy();
    expect(validateEncryptedBlob({})).toBeTruthy();
    expect(validateEncryptedBlob('string')).toBeTruthy();
    const { nonce, ...noNonce } = good();
    expect(validateEncryptedBlob(noNonce)).toBeTruthy();
  });

  it('names the field that failed', () => {
    expect(validateEncryptedBlob(null, 'senderCopy')).toContain('senderCopy');
  });
});
