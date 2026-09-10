// Input validation applied before any database write or cryptographic operation.
// Every function returns an error string, or null when the value is acceptable.

import { base64ByteLength } from './encoding';

// ML-KEM-768 sizes, in bytes (FIPS 203).
export const ML_KEM_768 = {
  publicKey: 1184,
  secretKey: 2400,
  cipherText: 1088,
  sharedSecret: 32
};

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;

const MAX_MESSAGE_BYTES = 8 * 1024; // generous ceiling for one chat message

export const isBase64 = (v) => typeof v === 'string' && v.length > 0 && BASE64_RE.test(v);

export const validateUsername = (value) => {
  if (typeof value !== 'string') return 'Username must be text';
  const name = value.trim();
  if (!name) return 'Username is required';
  if (!USERNAME_RE.test(name)) {
    return 'Username must be 3-20 characters: letters, digits or underscore';
  }
  return null;
};

export const validatePassword = (value) => {
  if (typeof value !== 'string') return 'Password must be text';
  if (value.length < 8) return 'Password must be at least 8 characters';
  if (value.length > 200) return 'Password is too long';
  return null;
};

export const validatePublicKey = (value) => {
  if (!isBase64(value)) return 'Public key must be base64';
  if (base64ByteLength(value) !== ML_KEM_768.publicKey) {
    return `Public key must be a ${ML_KEM_768.publicKey}-byte ML-KEM-768 key`;
  }
  return null;
};

// Shape of one sealed message: the KEM encapsulation plus the AES-GCM payload.
export const validateEncryptedBlob = (blob, label = 'encryptedData') => {
  if (!blob || typeof blob !== 'object') return `${label} is required`;

  const { kemCipherText, nonce, cipherText } = blob;

  if (!isBase64(kemCipherText)) return `${label}.kemCipherText must be base64`;
  if (base64ByteLength(kemCipherText) !== ML_KEM_768.cipherText) {
    return `${label}.kemCipherText must be ${ML_KEM_768.cipherText} bytes`;
  }

  if (!isBase64(nonce)) return `${label}.nonce must be base64`;
  if (base64ByteLength(nonce) !== 12) return `${label}.nonce must be 12 bytes`;

  if (!isBase64(cipherText)) return `${label}.cipherText must be base64`;
  if (base64ByteLength(cipherText) > MAX_MESSAGE_BYTES) return `${label}.cipherText is too large`;

  return null;
};
