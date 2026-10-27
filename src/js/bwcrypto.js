// Bitwarden "password protected" encrypted JSON exports, implemented from the documented format:
//
//   master  = KDF(password, salt)            PBKDF2-HMAC-SHA256, or Argon2id with salt = SHA-256(salt)
//   encKey  = HKDF-Expand(master, "enc", 32) macKey = HKDF-Expand(master, "mac", 32)
//   string  = "2." + b64(iv) + "|" + b64(ciphertext) + "|" + b64(HMAC-SHA256(macKey, iv + ciphertext))
//   cipher  = AES-256-CBC with PKCS#7 padding
//
// "Account restricted" exports are encrypted with a key that never leaves the user's Bitwarden
// account, so they can't be opened here. Everything uses the browser's Web Crypto API.

import { argon2Raw } from './argon2.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;

export const BW_KDF = { PBKDF2: 0, ARGON2ID: 1 };
export const BW_DEFAULTS = {
  pbkdf2: { kdfType: 0, kdfIterations: 600000 },
  argon2id: { kdfType: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 },
};

export class BitwardenCryptoError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'BitwardenCryptoError';
    this.code = code;
  }
}

function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const concat = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

async function sha256(bytes) {
  return new Uint8Array(await subtle().digest('SHA-256', bytes));
}

async function hmac(keyBytes, data) {
  const key = await subtle().importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle().sign('HMAC', key, data));
}

/** HKDF-Expand (RFC 5869) for a single 32-byte block: T(1) = HMAC(PRK, info || 0x01). */
const hkdfExpand32 = (prk, info) => hmac(prk, concat(enc.encode(info), Uint8Array.of(1)));

// Limits that stop a hostile file from freezing the page with an absurd work factor.
const LIMITS = { pbkdf2: 5_000_000, argonMemoryMiB: 1024, argonIterations: 64, argonParallelism: 16 };

export async function deriveKeys(password, params) {
  const { kdfType, kdfIterations: iterations, kdfMemory, kdfParallelism, salt } = params;
  if (typeof salt !== 'string' || !salt) throw new BitwardenCryptoError('The file has no salt.', 'format');
  let master;
  if (kdfType === BW_KDF.PBKDF2) {
    if (!(iterations >= 1 && iterations <= LIMITS.pbkdf2)) throw new BitwardenCryptoError('Unreasonable PBKDF2 iteration count.', 'format');
    const base = await subtle().importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    master = new Uint8Array(await subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations }, base, 256));
  } else if (kdfType === BW_KDF.ARGON2ID) {
    if (!(kdfMemory >= 1 && kdfMemory <= LIMITS.argonMemoryMiB && iterations >= 1 && iterations <= LIMITS.argonIterations && kdfParallelism >= 1 && kdfParallelism <= LIMITS.argonParallelism)) {
      throw new BitwardenCryptoError('Unreasonable Argon2 settings in this file.', 'format');
    }
    master = await argon2Raw({
      password: enc.encode(password),
      salt: await sha256(enc.encode(salt)), // Bitwarden hashes the salt before Argon2
      memoryKiB: kdfMemory * 1024,
      iterations,
      parallelism: kdfParallelism,
      length: 32,
      type: 'id',
    });
  } else {
    throw new BitwardenCryptoError(`Unsupported KDF type ${kdfType}.`, 'format');
  }
  return { encKey: await hkdfExpand32(master, 'enc'), macKey: await hkdfExpand32(master, 'mac') };
}

async function decryptString(encString, keys) {
  const m = /^(\d+)\.(.+)$/.exec(String(encString || ''));
  if (!m || m[1] !== '2') throw new BitwardenCryptoError('Unsupported encrypted string format.', 'format');
  const parts = m[2].split('|');
  if (parts.length !== 3) throw new BitwardenCryptoError('Damaged encrypted string.', 'format');
  const [iv, ct, mac] = parts.map(fromB64);
  const expected = await hmac(keys.macKey, concat(iv, ct));
  // Constant-time comparison of the two MACs.
  let diff = expected.length ^ mac.length;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ (mac[i] ?? 0);
  if (diff !== 0) throw new BitwardenCryptoError('Wrong password, or the file has been altered.', 'wrong-key');
  const key = await subtle().importKey('raw', keys.encKey, 'AES-CBC', false, ['decrypt']);
  try {
    return dec.decode(await subtle().decrypt({ name: 'AES-CBC', iv }, key, ct));
  } catch {
    throw new BitwardenCryptoError('Could not decrypt the data.', 'format');
  }
}

async function encryptString(plain, keys) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const key = await subtle().importKey('raw', keys.encKey, 'AES-CBC', false, ['encrypt']);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-CBC', iv }, key, enc.encode(plain)));
  const mac = await hmac(keys.macKey, concat(iv, ct));
  return `2.${toB64(iv)}|${toB64(ct)}|${toB64(mac)}`;
}

export const isBitwardenEncrypted = (obj) => !!obj && typeof obj === 'object' && obj.encrypted === true;

/** Returns the decrypted inner JSON text. Throws BitwardenCryptoError with code 'wrong-key', 'account' or 'format'. */
export async function decryptBitwardenExport(json, password) {
  if (!json.passwordProtected && !json.salt) {
    throw new BitwardenCryptoError(
      'This export is encrypted to your Bitwarden account, so it can only be opened by that account. In Bitwarden, export again and choose "File format: .json (Encrypted)" with "Password protected".',
      'account',
    );
  }
  if (!password) throw new BitwardenCryptoError('A password is required.', 'wrong-key');
  const keys = await deriveKeys(password, json);
  if (json.encKeyValidation_DO_NOT_EDIT) await decryptString(json.encKeyValidation_DO_NOT_EDIT, keys);
  return decryptString(json.data, keys);
}

/**
 * Wraps an unencrypted export (JSON text) in Bitwarden's password-protected envelope.
 * @param {string} innerJson
 * @param {string} password
 * @param {{kdf?: 'pbkdf2'|'argon2id', iterations?: number, memoryMiB?: number, parallelism?: number}} opts
 */
export async function encryptBitwardenExport(innerJson, password, opts = {}) {
  if (!password) throw new BitwardenCryptoError('A password is required.', 'wrong-key');
  const kdf = opts.kdf === 'argon2id' ? 'argon2id' : 'pbkdf2';
  const d = BW_DEFAULTS[kdf];
  const params = {
    salt: toB64(globalThis.crypto.getRandomValues(new Uint8Array(16))),
    kdfType: d.kdfType,
    kdfIterations: opts.iterations ?? d.kdfIterations,
    kdfMemory: kdf === 'argon2id' ? opts.memoryMiB ?? d.kdfMemory : null,
    kdfParallelism: kdf === 'argon2id' ? opts.parallelism ?? d.kdfParallelism : null,
  };
  const keys = await deriveKeys(password, params);
  return {
    encrypted: true,
    passwordProtected: true,
    salt: params.salt,
    kdfType: params.kdfType,
    kdfIterations: params.kdfIterations,
    kdfMemory: params.kdfMemory,
    kdfParallelism: params.kdfParallelism,
    encKeyValidation_DO_NOT_EDIT: await encryptString(globalThis.crypto.randomUUID(), keys),
    data: await encryptString(innerJson, keys),
  };
}
