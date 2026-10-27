// Argon2 in WebAssembly (hash-wasm, bundled into the page, so no network access is needed).
// Shared by the KeePass KDBX 4 engine and Bitwarden's Argon2id-protected exports.

import { argon2d, argon2id } from 'hash-wasm';

/**
 * @param {{password: Uint8Array, salt: Uint8Array, memoryKiB: number, iterations: number,
 *          parallelism: number, length?: number, type?: 'd'|'id'}} p
 * @returns {Promise<Uint8Array>}
 */
export async function argon2Raw({ password, salt, memoryKiB, iterations, parallelism, length = 32, type = 'id' }) {
  const fn = type === 'd' ? argon2d : argon2id;
  return fn({
    password,
    salt,
    parallelism,
    iterations,
    memorySize: memoryKiB,
    hashLength: length,
    outputType: 'binary',
  });
}

/** Adapter with the signature kdbxweb expects for CryptoEngine.setArgon2Impl. */
export async function kdbxwebArgon2(password, salt, memory, iterations, length, parallelism, type, version) {
  if (version !== 0x13) throw new Error('Argon2 version 1.0 databases are not supported. Re-save the file in KeePass first.');
  // kdbxweb: type 0 = Argon2d, 2 = Argon2id. `memory` is in KiB.
  const out = await argon2Raw({
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    memoryKiB: memory,
    iterations,
    parallelism,
    length,
    type: type === 2 ? 'id' : 'd',
  });
  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
}
