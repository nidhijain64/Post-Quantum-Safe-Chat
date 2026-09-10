// Base64 helpers shared by the browser crypto bridge and the server.
// Kept free of `window` so they can run — and be tested — under Node too.

export const toBase64 = (input) => {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (typeof btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  return Buffer.from(bytes).toString('base64');
};

export const fromBase64 = (str) => {
  if (typeof atob === 'function') {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(str, 'base64'));
};

// Byte length of the data a base64 string encodes, without decoding it.
export const base64ByteLength = (str) => {
  if (typeof str !== 'string' || str.length === 0) return 0;
  const padding = str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0;
  return (str.length / 4) * 3 - padding;
};
