// Cross-checks our Bitwarden encrypted-export code against an independent Python implementation.
// Needs: pip install cryptography argon2-cffi        Run: node tests/crosscheck/bw.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encryptBitwardenExport, decryptBitwardenExport } from '../../src/js/bwcrypto.js';

const py = join(dirname(fileURLToPath(import.meta.url)), 'bw_check.py');
const dir = mkdtempSync(join(tmpdir(), 'bw-cross-'));
const inner = JSON.stringify({ encrypted: false, folders: [{ id: 'f', name: 'Ünïcode ✓' }], items: [{ type: 1, name: 'x', login: { username: 'u', password: 'p' } }] });
const innerFile = join(dir, 'inner.json');
writeFileSync(innerFile, inner);

for (const [label, kdf, opts] of [
  ['PBKDF2', 'pbkdf2', { kdf: 'pbkdf2', iterations: 100000 }],
  ['Argon2id', 'argon2id', { kdf: 'argon2id', iterations: 2, memoryMiB: 16, parallelism: 2 }],
]) {
  // JS encrypts -> Python decrypts
  const file = join(dir, `js-${kdf}.json`);
  writeFileSync(file, JSON.stringify(await encryptBitwardenExport(inner, 'pässwörd ✓', opts)));
  const plain = execFileSync('python3', ['-I', py, 'decrypt', file, 'pässwörd ✓'], { encoding: 'utf8' }).trim();
  assert.equal(plain, inner);

  // Python encrypts -> JS decrypts
  const pyFile = join(dir, `py-${kdf}.json`);
  execFileSync('python3', ['-I', py, 'encrypt', pyFile, 'pässwörd ✓', kdf, innerFile]);
  assert.equal(await decryptBitwardenExport(JSON.parse(readFileSync(pyFile, 'utf8')), 'pässwörd ✓'), inner);
  console.log(`${label}: JS -> Python and Python -> JS both decrypt correctly`);
}
console.log('Bitwarden cross-check passed.');
