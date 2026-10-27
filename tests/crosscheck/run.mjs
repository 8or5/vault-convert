// Cross-checks our KDBX engine against pykeepass, an independent implementation.
// Needs Python with: pip install pykeepass
// Run: node tests/crosscheck/run.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDb, openKdbx, syncToDb, saveDb, loadModel, setKdfParams } from '../../src/js/kdbx.js';
import { addAttachmentBytes, getAttachmentBytes } from '../../src/js/attachments.js';
import { newItem } from '../../src/js/model.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'kdbx-cross-'));

const results = [];
for (const [kdf, label] of [['argon2d', 'Argon2d'], ['argon2id', 'Argon2id'], ['aes', 'AES-KDF']]) {
  const db = createDb({ name: 'Cross', password: 'correct horse', kdf, preset: 'fast' });
  const m = loadModel(db);
  const att = new TextEncoder().encode('attached bytes');
  const item = newItem({
    name: 'GitHub', username: 'ada', password: 'Sup3r-secret!', urls: ['https://github.com'], notes: 'line1\nline2 ü ✓',
    totp: 'JBSWY3DPEHPK3PXP', vault: 'Work', folder: 'Code / Hosting', favorite: true, tags: ['dev'],
    customFields: [{ name: 'Recovery', value: 'abcd', hidden: true }, { name: 'Plan', value: 'Pro', hidden: false }],
  });
  item.attachments = [{ id: addAttachmentBytes(att), name: 'a.txt', size: att.length }];
  await syncToDb(db, m, [item], { vaults: [], folders: {} });
  writeFileSync(join(dir, 'js-made.kdbx'), await saveDb(db));

  const out = execFileSync('python3', ['-I', join(here, 'kdbx_check.py'), dir], { encoding: 'utf8' }).trim().split('\n').pop();
  const s = JSON.parse(out);
  const e = s.entries[0];
  assert.equal(e.title, 'GitHub');
  assert.equal(e.username, 'ada');
  assert.equal(e.password, 'Sup3r-secret!');
  assert.equal(e.url, 'https://github.com');
  assert.equal(e.notes, 'line1\nline2 ü ✓');
  assert.deepEqual(e.group.slice(-3), ['Work', 'Code', 'Hosting']);
  assert.ok(e.tags.includes('Favorite') && e.tags.includes('dev'));
  assert.equal(e.custom.Recovery, 'abcd');
  assert.equal(e.custom.Plan, 'Pro');
  assert.match(e.otp, /JBSWY3DPEHPK3PXP/);
  assert.equal(e.attachments['a.txt'], 'attached bytes');
  results.push(`${label}: pykeepass read our file (KDBX ${s.version.join('.')}, kdf=${s.kdf}, cipher=${s.cipher})`);
}

// The last python run also wrote py-made.kdbx. Open it with our engine.
const o = await openKdbx(new Uint8Array(readFileSync(join(dir, 'py-made.kdbx'))), { password: 'py pass' });
const runner = o.items.find((i) => i.name === 'Runner');
assert.ok(runner, 'entry written by pykeepass is present');
assert.equal(runner.username, 'robot');
assert.equal(runner.password, 'r0b0t-pass');
assert.equal(runner.vault, 'Work');
assert.equal(runner.folder, 'CI');
assert.equal(runner.favorite, true);
assert.match(runner.totp, /secret=JBSWY3DPEHPK3PXP/);
assert.equal(runner.customFields.find((c) => c.name === 'API token').hidden, true);
assert.equal(runner.customFields.find((c) => c.name === 'Region').value, 'eu');
assert.equal(new TextDecoder().decode(getAttachmentBytes(runner.attachments[0].id)), 'hello from python');
assert.ok(o.items.find((i) => i.name === 'Top-level'));
results.push('our engine read a file written by pykeepass (groups, custom fields, TOTP, attachment, favorite tag)');

console.log(results.join('\n'));
console.log('KDBX cross-check passed.');
