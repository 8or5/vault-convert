import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFile, NeedsPassword } from '../src/js/importers.js';
import { exportItems, exportPlan, FORMATS } from '../src/js/exporters.js';
import { encryptBitwardenExport, decryptBitwardenExport, BitwardenCryptoError } from '../src/js/bwcrypto.js';
import { newItem } from '../src/js/model.js';
import { addAttachmentBytes, getAttachmentBytes } from '../src/js/attachments.js';

const bytesOf = (s) => new TextEncoder().encode(s);
const toBytes = (c) => (typeof c === 'string' ? bytesOf(c) : c);

const sample = () => [
  newItem({ name: 'Mail', username: 'ada@example.com', password: 'Tr1cky-Passw0rd!', urls: ['https://mail.example.com'], totp: 'JBSWY3DPEHPK3PXP', vault: 'Work', folder: 'Email', favorite: true, customFields: [{ name: 'PIN', value: '4242', hidden: true }] }),
  newItem({ type: 'note', name: 'Safe', notes: 'combination 1-2-3', vault: 'Home' }),
  newItem({ type: 'card', name: 'Visa', vault: 'Home', customFields: [{ name: 'Number', value: '4111111111111111', hidden: true }] }),
];

test('Bitwarden encrypted export: PBKDF2 round trip through exportItems and parseFile', async () => {
  const out = await exportItems('bitwarden-encrypted', sample(), { password: 'a strong password' });
  const file = JSON.parse(out.content);
  assert.equal(file.encrypted, true);
  assert.equal(file.passwordProtected, true);
  assert.equal(file.kdfType, 0);
  assert.ok(!out.content.includes('Tr1cky-Passw0rd'), 'no plaintext in the encrypted file');

  await assert.rejects(parseFile('x.json', toBytes(out.content)), NeedsPassword);
  const r = await parseFile('x.json', toBytes(out.content), { password: 'a strong password' });
  assert.equal(r.format, 'Bitwarden JSON (encrypted)');
  assert.equal(r.items.length, 3);
  const mail = r.items.find((i) => i.name === 'Mail');
  assert.equal(mail.password, 'Tr1cky-Passw0rd!');
  assert.equal(mail.totp, 'JBSWY3DPEHPK3PXP');
  assert.equal(mail.favorite, true);
  assert.equal(r.items.find((i) => i.name === 'Visa').type, 'card');
});

test('Bitwarden encrypted export: Argon2id round trip', async () => {
  const out = await exportItems('bitwarden-encrypted', sample(), { password: 'pw', kdf: 'argon2id' });
  const file = JSON.parse(out.content);
  assert.equal(file.kdfType, 1);
  assert.equal(file.kdfMemory, 64);
  const r = await parseFile('x.json', toBytes(out.content), { password: 'pw' });
  assert.equal(r.items.length, 3);
});

test('Bitwarden encrypted export: wrong password, tampering and account-only files', async () => {
  const wrapped = await encryptBitwardenExport('{"encrypted":false,"items":[]}', 'right', { kdf: 'pbkdf2', iterations: 1000 });
  await assert.rejects(decryptBitwardenExport(wrapped, 'wrong'), (e) => e instanceof BitwardenCryptoError && e.code === 'wrong-key');

  const tampered = { ...wrapped, data: wrapped.data.replace(/\|[^|]+$/, '|' + Buffer.alloc(32).toString('base64')) };
  await assert.rejects(decryptBitwardenExport(tampered, 'right'), (e) => e.code === 'wrong-key');

  await assert.rejects(parseFile('a.json', bytesOf('{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}')), /Bitwarden account/);
});

test('Bitwarden encrypted export: hostile work factors are refused', async () => {
  const base = { salt: 'c2FsdA==', encKeyValidation_DO_NOT_EDIT: '2.AA==|AA==|AA==', data: '2.AA==|AA==|AA==', passwordProtected: true };
  await assert.rejects(decryptBitwardenExport({ ...base, kdfType: 0, kdfIterations: 4_000_000_000 }, 'x'), (e) => e.code === 'format');
  await assert.rejects(decryptBitwardenExport({ ...base, kdfType: 1, kdfIterations: 3, kdfMemory: 999999, kdfParallelism: 4 }, 'x'), (e) => e.code === 'format');
  await assert.rejects(decryptBitwardenExport({ ...base, kdfType: 7, kdfIterations: 3 }, 'x'), (e) => e.code === 'format');
});

test('KDBX export is readable by parseFile, keeps vaults, folders, types and attachments', async () => {
  const items = sample();
  const bytes = bytesOf('attached!');
  items[0].attachments = [{ id: addAttachmentBytes(bytes), name: 'proof.txt', size: bytes.length }];
  const out = await exportItems('kdbx', items, { password: 'db pass', preset: 'fast', name: 'My export' });
  assert.ok(out.content instanceof Uint8Array);

  await assert.rejects(parseFile('x.kdbx', out.content), NeedsPassword);
  const r = await parseFile('x.kdbx', out.content, { password: 'db pass' });
  assert.equal(r.format, 'KeePass KDBX');
  const mail = r.items.find((i) => i.name === 'Mail');
  assert.equal(mail.vault, 'Work');
  assert.equal(mail.folder, 'Email');
  assert.equal(mail.favorite, true);
  assert.equal(r.items.find((i) => i.name === 'Safe').type, 'note');
  assert.equal(r.items.find((i) => i.name === 'Visa').type, 'card');
  assert.equal(new TextDecoder().decode(getAttachmentBytes(mail.attachments[0].id)), 'attached!');
});

test('Vault Convert JSON re-imports with nothing lost, attachments included', async () => {
  const items = sample();
  const bytes = bytesOf('keep me');
  items[1].attachments = [{ id: addAttachmentBytes(bytes), name: 'k.bin', size: bytes.length }];
  const out = await exportItems('vault-json', items);
  const r = await parseFile('backup.json', bytesOf(out.content));
  assert.equal(r.format, 'Vault Convert JSON');
  assert.equal(r.items.length, 3);
  const mail = r.items.find((i) => i.name === 'Mail');
  assert.deepEqual([mail.vault, mail.folder, mail.totp, mail.favorite], ['Work', 'Email', 'JBSWY3DPEHPK3PXP', true]);
  assert.equal(mail.customFields[0].hidden, true);
  assert.notEqual(mail.id, items[0].id, 'imported items get fresh ids');
  assert.equal(new TextDecoder().decode(getAttachmentBytes(r.items.find((i) => i.name === 'Safe').attachments[0].id)), 'keep me');
});

test('recycle-bin items are never exported, and the preview matches the real export', async () => {
  const items = sample();
  items[1].trashed = true;
  for (const f of FORMATS) {
    const plan = exportPlan(f.id, items);
    const out = await exportItems(f.id, items, { password: 'x', preset: 'fast' });
    assert.equal(plan.exported, out.exported, f.id);
    assert.ok(plan.exported <= 2, f.id);
  }
});
