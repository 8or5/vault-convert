import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDb, openKdbx, syncToDb, saveDb, loadModel, describeDb, isKdbx, mergeRemote, generateKeyFile, setKdfParams, KdbxUnlockError } from '../src/js/kdbx.js';
import { newItem } from '../src/js/model.js';
import { addAttachmentBytes, getAttachmentBytes } from '../src/js/attachments.js';

const enc = new TextEncoder();

/** A fresh, empty app-side session for a newly created database. */
function session(db) {
  const m = loadModel(db);
  return { kd: { ...m }, items: m.items, meta: m.meta };
}

async function build(items, meta = { vaults: [], folders: {} }) {
  const db = createDb({ name: 'Test DB', password: 'correct horse', preset: 'fast' });
  const s = session(db);
  await syncToDb(db, s.kd, items, meta);
  return { db, bytes: await saveDb(db) };
}

const sample = () => [
  newItem({
    name: 'GitHub', username: 'ada', password: 'Sup3r-secret!', urls: ['https://github.com', 'https://gist.github.com'],
    totp: 'JBSWY3DPEHPK3PXP', notes: 'dev account', vault: 'Work', folder: 'Code / Hosting', favorite: true, tags: ['dev', 'git'],
    customFields: [{ name: 'Recovery code', value: 'abcd-1234', hidden: true }, { name: 'Plan', value: 'Pro', hidden: false }],
  }),
  newItem({ type: 'note', name: 'Wifi', notes: 'router pin 1234', vault: 'Home' }),
  newItem({ type: 'card', name: 'Visa', vault: 'Home', customFields: [{ name: 'Number', value: '4111111111111111', hidden: true }] }),
];

test('round trip: every field, group path, tag, type and TOTP survives save and reopen', async () => {
  const { bytes } = await build(sample());
  assert.ok(isKdbx(bytes));
  const opened = await openKdbx(bytes, { password: 'correct horse' });
  const by = Object.fromEntries(opened.items.map((i) => [i.name, i]));

  const g = by.GitHub;
  assert.equal(g.username, 'ada');
  assert.equal(g.password, 'Sup3r-secret!');
  assert.deepEqual(g.urls, ['https://github.com', 'https://gist.github.com']);
  assert.equal(g.totp.startsWith('otpauth://totp/'), true);
  assert.match(g.totp, /secret=JBSWY3DPEHPK3PXP/);
  assert.equal(g.notes, 'dev account');
  assert.equal(g.vault, 'Work');
  assert.equal(g.folder, 'Code / Hosting');
  assert.equal(g.favorite, true);
  assert.deepEqual(g.tags.sort(), ['dev', 'git']);
  const rc = g.customFields.find((c) => c.name === 'Recovery code');
  assert.equal(rc.value, 'abcd-1234');
  assert.equal(rc.hidden, true);
  assert.equal(g.customFields.find((c) => c.name === 'Plan').hidden, false);

  assert.equal(by.Wifi.type, 'note');
  assert.equal(by.Visa.type, 'card');
  assert.equal(by.Wifi.vault, 'Home');
  assert.deepEqual(opened.meta.vaults.sort(), ['Home', 'Work']);
  assert.deepEqual(opened.meta.folders.Work.sort(), ['Code', 'Code / Hosting']);
});

test('wrong password and empty credentials give clear errors', async () => {
  const { bytes } = await build(sample());
  await assert.rejects(openKdbx(bytes, { password: 'nope' }), (e) => e instanceof KdbxUnlockError && e.code === 'wrong-key');
  await assert.rejects(openKdbx(bytes, {}), (e) => e instanceof KdbxUnlockError && e.code === 'empty');
});

test('editing in place keeps history, only touches changed entries, and keeps attachments', async () => {
  const items = sample();
  const att = new TextEncoder().encode('secret file contents');
  items[0].attachments = [{ id: addAttachmentBytes(att), name: 'recovery.txt', size: att.length }];
  const first = await build(items);

  const open1 = await openKdbx(first.bytes, { password: 'correct horse' });
  const kd = { ...open1 };
  const gh = open1.items.find((i) => i.name === 'GitHub');
  assert.equal(gh.attachments.length, 1);
  assert.equal(new TextDecoder().decode(getAttachmentBytes(gh.attachments[0].id)), 'secret file contents');

  gh.password = 'Rotated-pass-2';
  gh.updatedAt = new Date().toISOString();
  await syncToDb(open1.db, kd, open1.items, open1.meta);
  const bytes2 = await saveDb(open1.db);

  const open2 = await openKdbx(bytes2, { password: 'correct horse' });
  const gh2 = open2.items.find((i) => i.name === 'GitHub');
  assert.equal(gh2.password, 'Rotated-pass-2');
  assert.equal(gh2.historyCount, 1);
  assert.equal(gh2.pwHistory[0].password, 'Sup3r-secret!');
  assert.equal(gh2.attachments.length, 1);
  assert.equal(new TextDecoder().decode(getAttachmentBytes(gh2.attachments[0].id)), 'secret file contents');
  assert.equal(open2.items.find((i) => i.name === 'Wifi').historyCount, 0, 'untouched entries get no history');
});

test('recycle bin: trash, restore and permanent delete', async () => {
  const first = await build(sample());
  const o = await openKdbx(first.bytes, { password: 'correct horse' });
  const wifi = o.items.find((i) => i.name === 'Wifi');
  wifi.trashed = true;
  await syncToDb(o.db, o, o.items, o.meta);
  const o2 = await openKdbx(await saveDb(o.db), { password: 'correct horse' });
  const w2 = o2.items.find((i) => i.name === 'Wifi');
  assert.equal(w2.trashed, true);
  assert.equal(w2.vault, 'Home', 'original location is remembered');

  w2.trashed = false;
  await syncToDb(o2.db, o2, o2.items, o2.meta);
  const o3 = await openKdbx(await saveDb(o2.db), { password: 'correct horse' });
  const w3 = o3.items.find((i) => i.name === 'Wifi');
  assert.equal(w3.trashed, false);
  assert.equal(w3.vault, 'Home');

  o3.permanent.add(w3.id);
  const kept = o3.items.filter((i) => i.id !== w3.id);
  await syncToDb(o3.db, o3, kept, o3.meta);
  const o4 = await openKdbx(await saveDb(o3.db), { password: 'correct horse' });
  assert.equal(o4.items.some((i) => i.name === 'Wifi'), false);
});

test('moving an item between vaults and renaming away from an empty vault', async () => {
  const first = await build(sample());
  const o = await openKdbx(first.bytes, { password: 'correct horse' });
  for (const i of o.items) if (i.vault === 'Home') i.vault = 'Family';
  o.meta.vaults = o.meta.vaults.map((v) => (v === 'Home' ? 'Family' : v));
  await syncToDb(o.db, o, o.items, o.meta);
  const o2 = await openKdbx(await saveDb(o.db), { password: 'correct horse' });
  assert.deepEqual(o2.meta.vaults.sort(), ['Family', 'Work']);
  assert.equal(o2.items.find((i) => i.name === 'Visa').vault, 'Family');
});

test('KDBX 3 files are written and read', async () => {
  const db = createDb({ name: 'Old', password: 'pw', kdf: 'aes' });
  db.setVersion(3);
  const s = session(db);
  await syncToDb(db, s.kd, [newItem({ name: 'X', username: 'u', password: 'p', vault: 'V' })], { vaults: [], folders: {} });
  const bytes = await saveDb(db);
  const o = await openKdbx(bytes, { password: 'pw' });
  assert.equal(describeDb(o.db).version.startsWith('3.'), true);
  assert.equal(o.items[0].password, 'p');
});

test('key file only, and password plus key file', async () => {
  const keyFile = await generateKeyFile();
  const db = createDb({ name: 'K', password: 'pw', keyFile, preset: 'fast' });
  const s = session(db);
  await syncToDb(db, s.kd, [newItem({ name: 'X', password: 'p' })], { vaults: [], folders: {} });
  const bytes = await saveDb(db);
  assert.equal((await openKdbx(bytes, { password: 'pw', keyFile })).items.length, 1);
  await assert.rejects(openKdbx(bytes, { password: 'pw' }), KdbxUnlockError);
  await assert.rejects(openKdbx(bytes, { keyFile }), KdbxUnlockError);

  const onlyKey = createDb({ name: 'K2', keyFile, preset: 'fast' });
  const bytes2 = await saveDb(onlyKey);
  assert.equal((await openKdbx(bytes2, { keyFile })).db.meta.name, 'K2');
});

test('new databases get a real KDF, not the library default', async () => {
  const db = createDb({ name: 'D', password: 'pw', preset: 'standard' });
  const info = describeDb(db);
  assert.equal(info.kdf, 'Argon2d');
  assert.match(info.kdfDetail, /^64 MiB, 3 passes/);
  setKdfParams(db, { kdf: 'argon2id', preset: 'fast' });
  assert.equal(describeDb(db).kdf, 'Argon2id');
});

test('merging an independently edited copy brings in remote changes', async () => {
  const first = await build(sample());
  const a = await openKdbx(first.bytes, { password: 'correct horse' });
  const b = await openKdbx(first.bytes, { password: 'correct horse' });

  const remoteItem = b.items.find((i) => i.name === 'Wifi');
  remoteItem.notes = 'changed elsewhere';
  remoteItem.updatedAt = new Date(Date.now() + 5000).toISOString();
  await syncToDb(b.db, b, b.items, b.meta);
  const remoteBytes = await saveDb(b.db);

  const localItem = a.items.find((i) => i.name === 'GitHub');
  localItem.notes = 'changed here';
  localItem.updatedAt = new Date(Date.now() + 5000).toISOString();
  await syncToDb(a.db, a, a.items, a.meta);
  await mergeRemote(a.db, remoteBytes);

  const merged = loadModel(a.db).items;
  assert.equal(merged.find((i) => i.name === 'Wifi').notes, 'changed elsewhere');
  assert.equal(merged.find((i) => i.name === 'GitHub').notes, 'changed here');
});

test('TOTP stored by KeePassXC (key=...) and KeePass plugin fields is read', async () => {
  const db = createDb({ name: 'T', password: 'pw', preset: 'fast' });
  const root = db.getDefaultGroup();
  const e1 = db.createEntry(root);
  e1.fields.set('Title', 'legacy');
  e1.fields.set('otp', 'key=JBSWY3DPEHPK3PXP&step=30&size=6');
  const e2 = db.createEntry(root);
  e2.fields.set('Title', 'plugin');
  e2.fields.set('TimeOtp-Secret-Base32', 'JBSWY3DPEHPK3PXP');
  e2.fields.set('TimeOtp-Period', '60');
  const items = loadModel(db).items;
  assert.equal(items.find((i) => i.name === 'legacy').totp, 'JBSWY3DPEHPK3PXP');
  assert.match(items.find((i) => i.name === 'plugin').totp, /period=60/);

  // Untouched TOTP fields are left exactly as the other program wrote them.
  const s = session(db);
  s.items.find((i) => i.name === 'plugin').notes = 'x';
  await syncToDb(db, s.kd, s.items, s.meta);
  const plugin = [...root.allEntries()].find((e) => e.fields.get('Title') === 'plugin');
  assert.equal(plugin.fields.get('TimeOtp-Secret-Base32'), 'JBSWY3DPEHPK3PXP');
});
