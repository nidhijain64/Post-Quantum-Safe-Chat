import { toBase64, fromBase64 } from './encoding';

let libPromise = null;

// The folloiwng function dynamically loads liboqs.js (from /public) into the browser only when needed (if not already loaded).
export const loadOQS = () => {
    if (libPromise) return libPromise;

    // Standard loader with script injection
    if (typeof window.liboqs !== 'function') {
        libPromise = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = '/liboqs.js';
            script.onload = () => {
                window.liboqs({
                    locateFile: (path) => path.endsWith('.wasm') ? '/' + path : path
                }).then(resolve).catch(reject);
            };
            script.onerror = () => reject(new Error("Failed to load /liboqs.js"));
            document.body.appendChild(script);
        });
    } else {
        libPromise = window.liboqs({
            locateFile: (path) => path.endsWith('.wasm') ? '/' + path : path
        });
    }
    
    return libPromise;
};

// --- HELPER: Safe Memory Read ---
// Tries to use HEAPU8 (fast), falls back to getValue (slow but guaranteed)
const readBytes = (mod, ptr, len) => {
    // 1. Try Fast Path (Direct Memory Access)
    let heap = mod.HEAPU8;
    if (!heap && mod.wasmMemory) heap = new Uint8Array(mod.wasmMemory.buffer);
    if (!heap && mod.buffer) heap = new Uint8Array(mod.buffer);

    if (heap && heap.buffer.byteLength > 0) {
        return new Uint8Array(heap.subarray(ptr, ptr + len));
    }

    // 2. Slow Path (Backdoor via getValue)
    // This works even if HEAPU8 is hidden, as long as 'getValue' is exported.
    if (mod.getValue) {
        const bytes = new Uint8Array(len);
        for(let i = 0; i < len; i++) {
            bytes[i] = mod.getValue(ptr + i, 'i8');
        }
        return bytes;
    }

    throw new Error("Cannot read WASM memory. HEAPU8 missing and getValue not exported.");
};

// --- HELPER: Safe Memory Write ---
const writeBytes = (mod, ptr, bytes) => {
    // 1. Try Fast Path
    let heap = mod.HEAPU8;
    if (!heap && mod.wasmMemory) heap = new Uint8Array(mod.wasmMemory.buffer);
    if (!heap && mod.buffer) heap = new Uint8Array(mod.buffer);

    if (heap && heap.buffer.byteLength > 0) {
        heap.set(bytes, ptr);
        return;
    }

    // 2. Slow Path (Backdoor via setValue)
    if (mod.setValue) {
        for(let i = 0; i < bytes.length; i++) {
            mod.setValue(ptr + i, bytes[i], 'i8');
        }
        return;
    }

    throw new Error("Cannot write to WASM memory. HEAPU8 missing and setValue not exported.");
};

// --- DATA CONVERSION ---
// toBase64 / fromBase64 now live in ./encoding so the server and the test suite
// can share them.

// --- KYBER FUNCTIONS ---

export const generateKEMKeyPair = async () => {
    const mod = await loadOQS();
    const alg = "ML-KEM-768";
    
    if (!mod._malloc) throw new Error("WASM corrupt: _malloc missing.");

    const kemPtr = mod.ccall('init_kem', 'number', ['string'], [alg]);
    if (kemPtr === 0) throw new Error("Algorithm init failed");

    const pkLen = mod.ccall('get_len_pk', 'number', ['number'], [kemPtr]);
    const skLen = mod.ccall('get_len_sk', 'number', ['number'], [kemPtr]);

    const pkPtr = mod._malloc(pkLen);
    const skPtr = mod._malloc(skLen);

    const res = mod.ccall('generate_keypair', 'number', ['number', 'number', 'number'], [kemPtr, pkPtr, skPtr]);
    if (res !== 0) throw new Error("Key generation failed");

    // READ USING SAFE HELPER
    const pkBytes = readBytes(mod, pkPtr, pkLen);
    const skBytes = readBytes(mod, skPtr, skLen);
    
    const keys = { pk: toBase64(pkBytes), sk: toBase64(skBytes) };

    mod._free(pkPtr); 
    mod._free(skPtr);
    mod.ccall('free_kem', 'void', ['number'], [kemPtr]);
    
    return keys;
};

export const encapsulateSecret = async (pkBase64) => {
    const mod = await loadOQS();
    const alg = "ML-KEM-768";
    const kemPtr = mod.ccall('init_kem', 'number', ['string'], [alg]);

    const pkBytes = fromBase64(pkBase64);
    const ctLen = mod.ccall('get_len_ct', 'number', ['number'], [kemPtr]);
    const ssLen = mod.ccall('get_len_ss', 'number', ['number'], [kemPtr]);

    const ctPtr = mod._malloc(ctLen);
    const ssPtr = mod._malloc(ssLen);
    const pkPtr = mod._malloc(pkBytes.length);

    // WRITE USING SAFE HELPER
    writeBytes(mod, pkPtr, pkBytes);

    const res = mod.ccall('encap_secret', 'number', ['number', 'number', 'number', 'number'], [kemPtr, ctPtr, ssPtr, pkPtr]);
    if (res !== 0) throw new Error("Encapsulation failed");

    // READ USING SAFE HELPER
    const ctBytes = readBytes(mod, ctPtr, ctLen);
    const ssBytes = readBytes(mod, ssPtr, ssLen);

    const result = { 
        kemCipherText: toBase64(ctBytes), 
        sharedSecret: ssBytes 
    };

    mod._free(ctPtr); mod._free(ssPtr); mod._free(pkPtr);
    mod.ccall('free_kem', 'void', ['number'], [kemPtr]);
    return result;
};

export const decapsulateSecret = async (ctBase64, skBase64) => {
    const mod = await loadOQS();
    const alg = "ML-KEM-768";
    const kemPtr = mod.ccall('init_kem', 'number', ['string'], [alg]);

    const ctBytes = fromBase64(ctBase64);
    const skBytes = fromBase64(skBase64);
    const ssLen = mod.ccall('get_len_ss', 'number', ['number'], [kemPtr]);

    const ssPtr = mod._malloc(ssLen);
    const ctPtr = mod._malloc(ctBytes.length);
    const skPtr = mod._malloc(skBytes.length);

    // WRITE USING SAFE HELPER
    writeBytes(mod, ctPtr, ctBytes);
    writeBytes(mod, skPtr, skBytes);

    const res = mod.ccall('decap_secret', 'number', ['number', 'number', 'number', 'number'], [kemPtr, ssPtr, ctPtr, skPtr]);
    if (res !== 0) throw new Error("Decapsulation failed");

    // READ USING SAFE HELPER
    const ssBytes = readBytes(mod, ssPtr, ssLen);

    mod._free(ssPtr); mod._free(ctPtr); mod._free(skPtr);
    mod.ccall('free_kem', 'void', ['number'], [kemPtr]);
    return ssBytes;
};

// --- AES FUNCTIONS ---
// globalThis.crypto rather than window.crypto: identical in the browser, but it
// also resolves to Node's Web Crypto so these are unit-testable.
const subtle = () => globalThis.crypto.subtle;

const importKey = (bytes) => subtle().importKey("raw", bytes.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);

export const encryptMessage = async (txt, secretBytes) => {
    const key = await importKey(secretBytes);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const enc = await subtle().encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(txt));
    return { cipherText: toBase64(enc), nonce: toBase64(iv) };
};

export const decryptMessage = async (ctBase64, ivBase64, secretBytes) => {
    const key = await importKey(secretBytes);
    const dec = await subtle().decrypt({ name: "AES-GCM", iv: fromBase64(ivBase64) }, key, fromBase64(ctBase64));
    return new TextDecoder().decode(dec);
};
