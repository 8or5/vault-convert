import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFile } from '../src/js/importers.js';
import { exportItems, FORMATS } from '../src/js/exporters.js';
import { totpCode, toOtpauthUri } from '../src/js/totp.js';
import { readZip, writeZip } from '../src/js/zip.js';
import { analyse, mergeGroup, linkTotp, generatePassword, suggestTotpTargets } from '../src/js/analysis.js';
import { newItem } from '../src/js/model.js';
import { parseCsv, toCsv } from '../src/js/csv.js';

const enc = new TextEncoder();
const bytesOf = (s) => enc.encode(s);

test('TOTP matches the RFC 6238 SHA-1 test vector (8 digits at t=59)', async () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
  assert.equal(await totpCode(secret, 59000), '287082');
  assert.equal(await totpCode(toOtpauthUri(secret, 'x').replace('digits=6', 'digits=8'), 59000), '94287082');
});

test('otpauth URIs round-trip through toOtpauthUri', () => {
  const uri = toOtpauthUri('gezdgnbv gy3tqojq', 'alice@example.com', 'Example');
  assert.match(uri, /^otpauth:\/\/totp\/alice%40example\.com\?secret=GEZDGNBVGY3TQOJQ/);
});

test('CSV handles quoted commas, quotes and newlines', () => {
  const rows = parseCsv('a,b\n"x, y","say ""hi""\nthere"\n');
  assert.deepEqual(rows, [['a', 'b'], ['x, y', 'say "hi"\nthere']]);
  assert.equal(parseCsv(toCsv([['h'], ['has,comma']]))[1][0], 'has,comma');
});

test('Bitwarden JSON import keeps folders, TOTP, URIs and custom fields', async () => {
  const data = {
    encrypted: false,
    folders: [{ id: 'f1', name: 'Work' }],
    items: [{
      type: 1, name: 'GitHub', notes: 'n', folderId: 'f1', favorite: true,
      fields: [{ name: 'Recovery', value: 'abc', type: 1 }],
      login: { username: 'me', password: 'Pa55w0rd!long', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://github.com' }] },
      revisionDate: '2026-01-02T03:04:05.000Z',
    }],
  };
  const r = await parseFile('bw.json', bytesOf(JSON.stringify(data)));
  assert.equal(r.format, 'Bitwarden JSON');
  const [it] = r.items;
  assert.equal(it.name, 'GitHub');
  assert.equal(it.folder, 'Work');
  assert.equal(it.favorite, true);
  assert.deepEqual(it.urls, ['https://github.com']);
  assert.equal(it.totp, 'JBSWY3DPEHPK3PXP');
  assert.equal(it.customFields[0].hidden, true);
});

test('encrypted Bitwarden export is refused with a clear message', async () => {
  await assert.rejects(parseFile('x.json', bytesOf('{"encrypted":true,"data":"..."}')), /encrypted/);
});

test('Proton Pass CSV is detected and mapped (vault, email as username)', async () => {
  const csv = 'type,name,url,email,username,password,note,totp,vault\n'
    + 'login,Netflix,https://netflix.com,me@x.com,,hunter22hunter22,,,Family\n'
    + 'note,Passport,,,,,my number is 123,,Personal\n';
  const r = await parseFile('proton.csv', bytesOf(csv));
  assert.equal(r.format, 'Proton Pass CSV');
  assert.equal(r.items[0].username, 'me@x.com');
  assert.equal(r.items[0].vault, 'Family');
  assert.equal(r.items[1].type, 'note');
});

test('Chrome CSV import and unknown columns become custom fields', async () => {
  const csv = 'name,url,username,password,note,PIN\nExample,https://example.com,bob,pw123456789,hi,4242\n';
  const r = await parseFile('chrome.csv', bytesOf(csv));
  assert.equal(r.format, 'Chrome / Google / Edge CSV');
  assert.equal(r.items[0].customFields[0].name, 'PIN');
  assert.equal(r.items[0].customFields[0].hidden, true);
});

test('Enpass-style JSON maps typed fields', async () => {
  const data = { items: [{ title: 'Bank', category: 'login', fields: [
    { type: 'username', label: 'Username', value: 'jane' },
    { type: 'password', label: 'Password', value: 'bankpass123456' },
    { type: 'website', label: 'Website', value: 'bank.example' },
    { type: 'totp', label: 'OTP', value: 'JBSWY3DPEHPK3PXP' },
  ] }] };
  const r = await parseFile('enpass.json', bytesOf(JSON.stringify(data)));
  const [it] = r.items;
  assert.equal(it.username, 'jane');
  assert.equal(it.password, 'bankpass123456');
  assert.deepEqual(it.urls, ['bank.example']);
  assert.equal(it.totp, 'JBSWY3DPEHPK3PXP');
});

test('a CSV row with only a one-time code is imported as a login (authenticator-only)', async () => {
  const r = await parseFile('totp.csv', bytesOf('name,url,username,password,totp\nAuth GitLab,,,,JBSWY3DPEHPK3PXP\n'));
  assert.equal(r.items[0].type, 'login');
  assert.equal(r.items[0].totp, 'JBSWY3DPEHPK3PXP');
});

// KeePass XML needs DOMParser, which only exists in a browser. It is covered by the browser smoke test.
test('KeePass XML import (browser only: needs DOMParser)', { skip: typeof DOMParser === 'undefined' }, async () => {
  const xml = '<KeePassFile><Root><Group><Name>DB</Name>'
    + '<Group><Name>Work</Name><Group><Name>Clients</Name>'
    + '<Entry><String><Key>Title</Key><Value>Acme</Value></String><String><Key>UserName</Key><Value>ada</Value></String><String><Key>Password</Key><Value>pw-long-enough-1</Value></String><String><Key>URL</Key><Value>https://acme.example</Value></String></Entry>'
    + '</Group></Group></Group></Root></KeePassFile>';
  const r = await parseFile('kp.xml', bytesOf(xml));
  assert.equal(r.items[0].vault, 'Work');
  assert.equal(r.items[0].folder, 'Clients');
});

test('1PUX export round-trips through the ZIP writer and the importer', async () => {
  const items = [
    newItem({ name: 'Site', urls: ['https://site.example'], username: 'u', password: 'p123456789ab', totp: 'JBSWY3DPEHPK3PXP', vault: 'Work', customFields: [{ name: 'Note', value: 'x', hidden: false }] }),
    newItem({ type: 'note', name: 'Secret note', notes: 'line 1\nline 2' }),
  ];
  const out = exportItems('1password-1pux', items);
  const files = await readZip(out.content);
  assert.ok(files.has('export.data'));
  const r = await parseFile('x.1pux', out.content);
  assert.equal(r.format, '1Password (1PUX)');
  const site = r.items.find((i) => i.name === 'Site');
  assert.equal(site.username, 'u');
  assert.equal(site.password, 'p123456789ab');
  assert.equal(site.totp, 'JBSWY3DPEHPK3PXP');
  assert.equal(site.vault, 'Work');
  assert.equal(r.items.find((i) => i.name === 'Secret note').notes, 'line 1\nline 2');
});

test('ZIP writer output is readable by the reader (stored entries)', async () => {
  const zip = writeZip([{ name: 'a.txt', data: bytesOf('hello') }, { name: 'dir/b.txt', data: bytesOf('world') }]);
  const files = await readZip(zip);
  assert.equal(new TextDecoder().decode(files.get('dir/b.txt')), 'world');
});

test('every export format produces output and reports skipped types', () => {
  const items = [
    newItem({ name: 'L', urls: ['https://l.example'], username: 'u', password: 'pw-long-enough-1', totp: 'JBSWY3DPEHPK3PXP', folder: 'F' }),
    newItem({ type: 'note', name: 'N', notes: 'x' }),
    newItem({ type: 'card', name: 'C', customFields: [{ name: 'Number', value: '4111', hidden: true }] }),
  ];
  for (const f of FORMATS) {
    const out = exportItems(f.id, items);
    assert.ok(out.content && out.content.length > 0, f.id);
    assert.equal(out.exported + Object.values(out.excluded).reduce((a, b) => a + b, 0), items.length, f.id);
  }
  assert.equal(exportItems('chrome-csv', items).exported, 1);
});

test('Bitwarden JSON export re-imports with folder and card data intact', async () => {
  const items = [newItem({ name: 'Card', type: 'card', vault: 'Money', customFields: [{ name: 'Number', value: '4111111111111111', hidden: true }, { name: 'Cardholder name', value: 'Ada', hidden: false }] })];
  const out = exportItems('bitwarden-json', items);
  const json = JSON.parse(out.content);
  assert.equal(json.items[0].card.number, '4111111111111111');
  assert.equal(json.folders[0].name, 'Money');
  const r = await parseFile('bw.json', bytesOf(out.content));
  assert.equal(r.items[0].type, 'card');
});

test('duplicate detection finds exact duplicates and conflicting logins', () => {
  const a = newItem({ name: 'Mail', urls: ['https://mail.example.com'], username: 'me', password: 'aaaaaaaaaaaa' });
  const b = newItem({ name: 'Mail copy', urls: ['https://www.mail.example.com/login'], username: 'ME', password: 'aaaaaaaaaaaa' });
  const c = newItem({ name: 'Mail other', urls: ['mail.example.com'], username: 'me', password: 'bbbbbbbbbbbb' });
  const a2 = analyse([a, b, c]);
  assert.equal(a2.dupes.exact.length, 1);
  assert.equal(a2.dupes.conflicts.length, 1);
  assert.ok(a2.flags.get(a.id).some((f) => f.code === 'duplicate'));
  assert.ok(a2.flags.get(c.id).some((f) => f.code === 'conflict'));
});

test('merge keeps conflicting passwords as alternates instead of dropping them', () => {
  const a = newItem({ name: 'X', urls: ['https://x.example'], username: 'me', password: 'first-password-1', source: 'A' });
  const b = newItem({ name: 'X', urls: ['https://y.example'], username: 'me', password: 'second-password-2', source: 'B', totp: 'JBSWY3DPEHPK3PXP' });
  const m = mergeGroup([a, b]);
  assert.equal(m.password, 'first-password-1');
  assert.equal(m.totp, 'JBSWY3DPEHPK3PXP');
  assert.equal(m.urls.length, 2);
  assert.ok(m.customFields.some((f) => f.value === 'second-password-2' && f.hidden));
});

test('TOTP-only items can be linked to a login and suggestions prefer matching sites', () => {
  const login = newItem({ name: 'GitHub', urls: ['https://github.com'], username: 'me', password: 'pw-long-enough-1' });
  const other = newItem({ name: 'Bank', urls: ['https://bank.example'], username: 'me', password: 'pw-long-enough-2' });
  const code = newItem({ name: 'GitHub', totp: 'JBSWY3DPEHPK3PXP' });
  const sug = suggestTotpTargets(code, [other, login]);
  assert.equal(sug[0].item.id, login.id);
  const linked = linkTotp(login, code);
  assert.equal(linked.totp, 'JBSWY3DPEHPK3PXP');
});

test('flags catch missing passwords, weak passwords and invalid TOTP secrets', () => {
  const items = [
    newItem({ name: 'A', urls: ['https://a.example'], username: 'u' }),
    newItem({ name: 'B', urls: ['https://b.example'], username: 'u', password: 'short' }),
    newItem({ name: 'C', totp: 'not base32!!' }),
  ];
  const a = analyse(items);
  const codes = (id) => a.flags.get(id).map((f) => f.code);
  assert.ok(codes(items[0].id).includes('no-password'));
  assert.ok(codes(items[1].id).includes('weak'));
  assert.ok(codes(items[2].id).includes('bad-totp'));
});

test('generated passwords have the requested length and character sets', () => {
  const pw = generatePassword({ length: 32, symbols: false });
  assert.equal(pw.length, 32);
  assert.match(pw, /^[A-Za-z0-9]+$/);
});
