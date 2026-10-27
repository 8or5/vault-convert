// Export: turns items into the file formats the app supports. Each exporter reports
// which items it had to skip and which data it could not represent (lossy notes).

import { toCsv } from './csv.js';
import { writeZip } from './zip.js';
import { TYPES, vaultOf, folderPath, displayName, DEFAULT_VAULT, uid } from './model.js';
import { toOtpauthUri } from './totp.js';
import { createDb, syncToDb, saveDb, loadModel } from './kdbx.js';
import { encryptBitwardenExport } from './bwcrypto.js';
import { getAttachmentBytes } from './attachments.js';

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

export const FORMATS = [
  { id: 'kdbx', label: 'KeePass database (KDBX 4, encrypted)', ext: 'kdbx', types: TYPES, encrypted: true, desc: 'Opens in KeePass, KeePassXC, KeePassDX and more. Keeps attachments and every item type.' },
  { id: 'bitwarden-encrypted', label: 'Bitwarden JSON (password protected)', ext: 'json', types: TYPES, encrypted: true, desc: 'Encrypted file Bitwarden can import into any account.' },
  { id: 'vault-json', label: 'Vault Convert JSON', ext: 'json', types: TYPES, desc: 'Full-fidelity backup, attachments included. Re-import it here to keep editing.' },
  { id: 'generic-csv', label: 'Generic CSV', ext: 'csv', types: TYPES, desc: 'Every item type. Custom fields go into a Fields column.' },
  { id: 'bitwarden-json', label: 'Bitwarden JSON (unencrypted)', ext: 'json', types: TYPES, desc: 'Bitwarden items with folders. Keep the file private.' },
  { id: 'bitwarden-csv', label: 'Bitwarden CSV', ext: 'csv', types: TYPES, desc: 'Cards and identities become secure notes.' },
  { id: '1password-1pux', label: '1Password (1PUX)', ext: '1pux', types: TYPES, desc: 'Zip container with JSON, vaults kept as separate vaults.' },
  { id: 'keepass-xml', label: 'KeePass 2 XML', ext: 'xml', types: TYPES, desc: 'Plain XML. Groups map to vaults and folders.' },
  { id: 'keepassxc-csv', label: 'KeePassXC CSV', ext: 'csv', types: TYPES, desc: 'Group column holds vault / folder.' },
  { id: 'proton-csv', label: 'Proton Pass CSV', ext: 'csv', types: ['login', 'note'], desc: 'Logins and notes only.' },
  { id: 'lastpass-csv', label: 'LastPass CSV', ext: 'csv', types: ['login', 'note'], desc: 'Logins and notes only.' },
  { id: 'dashlane-csv', label: 'Dashlane CSV', ext: 'csv', types: ['login', 'note'], desc: 'Logins and notes only.' },
  { id: 'apple-csv', label: 'Apple Passwords CSV', ext: 'csv', types: ['login'], desc: 'Logins only, with one-time codes.' },
  { id: 'chrome-csv', label: 'Chrome / Google / Edge CSV', ext: 'csv', types: ['login'], desc: 'Logins only. No one-time codes.' },
];

const BW_NUM = { login: 1, note: 2, card: 3, identity: 4 };
const CAT_1PUX = { login: '001', card: '002', note: '003', identity: '004' };
const CARD_KEYS = { cardholdername: 'cardholderName', number: 'number', brand: 'brand', expmonth: 'expMonth', expyear: 'expYear', code: 'code' };

const epochSeconds = (iso) => (iso ? Math.floor(Date.parse(iso) / 1000) || 0 : 0);
const fieldsText = (it) => it.customFields.map((f) => `${f.name}: ${f.value}`).join('\n');
const notesWithFields = (it) => [it.notes, fieldsText(it)].filter(Boolean).join('\n\n');
const firstUrl = (it) => it.urls[0] || '';
const bwFolder = (it) => (it.folder ? folderPath(it) : vaultOf(it) === DEFAULT_VAULT ? '' : vaultOf(it));
const randomId = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
};

const withoutTrash = (items) => items.filter((i) => !i.trashed);
const attachmentCount = (items) => items.reduce((n, i) => n + (i.attachments || []).length, 0);

/** What an export would contain, without doing any work or encryption. Used for the preview. */
export function exportPlan(formatId, items) {
  const fmt = FORMATS.find((f) => f.id === formatId);
  if (!fmt) throw new Error(`Unknown format ${formatId}`);
  const live = withoutTrash(items);
  if (!fmt.encrypted) {
    const { content, ...rest } = exportSync(formatId, live);
    return rest;
  }
  const supported = live.filter((it) => fmt.types.includes(it.type));
  const notes = [];
  const files = attachmentCount(supported);
  if (formatId === 'bitwarden-encrypted' && files) notes.push(`${files} attachment(s) can't be stored in Bitwarden exports and will be left out.`);
  if (formatId === 'bitwarden-encrypted' && supported.some((i) => i.customFields.length)) notes.push('Custom fields are kept as Bitwarden fields.');
  return { exported: supported.length, excluded: {}, notes, filename: `vault-export-${formatId}-${new Date().toISOString().slice(0, 10)}.${fmt.ext}` };
}

/**
 * Builds the export. Plain formats return a string or bytes; encrypted formats need
 * `options`: { password, keyFile?, kdf?, preset? } for kdbx, { password, kdf? } for Bitwarden.
 * Returns { filename, mime, content, exported, excluded, notes }.
 */
export async function exportItems(formatId, items, options = {}) {
  const fmt = FORMATS.find((f) => f.id === formatId);
  if (!fmt) throw new Error(`Unknown format ${formatId}`);
  const live = withoutTrash(items);
  if (!fmt.encrypted) return exportSync(formatId, live);

  const plan = exportPlan(formatId, items);
  if (formatId === 'kdbx') {
    const supported = live.filter((it) => fmt.types.includes(it.type));
    const db = createDb({ name: options.name || 'Vault Convert export', password: options.password, keyFile: options.keyFile, kdf: options.kdf, preset: options.preset });
    const model = loadModel(db);
    const copies = supported.map((it) => ({ ...structuredClone(it), source: 'KeePass KDBX', attachments: (it.attachments || []).map((a) => ({ ...a, existing: false })) }));
    const meta = { vaults: [], folders: {} };
    for (const it of copies) {
      const v = vaultOf(it);
      if (!meta.vaults.includes(v)) meta.vaults.push(v);
    }
    await syncToDb(db, { ...model, rootName: db.getDefaultGroup().name }, copies, meta);
    return { ...plan, content: await saveDb(db), mime: 'application/octet-stream' };
  }
  // Bitwarden password-protected JSON
  const inner = JSON.stringify(bitwardenJson(live.filter((it) => fmt.types.includes(it.type))));
  const wrapped = await encryptBitwardenExport(inner, options.password, { kdf: options.kdf });
  return { ...plan, content: JSON.stringify(wrapped, null, 2), mime: 'application/json' };
}

const toBase64 = (bytes) => {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};

function exportSync(formatId, items) {
  const fmt = FORMATS.find((f) => f.id === formatId);
  if (!fmt || fmt.encrypted) throw new Error(`No plain exporter for ${formatId}`);
  const supported = items.filter((it) => fmt.types.includes(it.type));
  const excluded = {};
  for (const it of items) if (!fmt.types.includes(it.type)) excluded[it.type] = (excluded[it.type] || 0) + 1;
  const notes = [];
  const withCustom = supported.filter((it) => it.customFields.length).length;
  const withTotp = supported.filter((it) => it.totp).length;
  const stamp = new Date().toISOString().slice(0, 10);
  const base = `vault-export-${formatId}-${stamp}`;
  const out = { filename: `${base}.${fmt.ext}`, exported: supported.length, excluded, notes };
  const files = attachmentCount(supported);
  if (files && formatId !== 'vault-json') notes.push(`${files} attachment(s) can't be stored in this format and will be left out.`);

  switch (formatId) {
    case 'vault-json':
      out.content = JSON.stringify({
        format: 'vault-convert',
        version: 2,
        exportedAt: new Date().toISOString(),
        items: supported.map((it) => ({
          ...it,
          attachments: (it.attachments || []).map((a) => ({ name: a.name, size: a.size, data: toBase64(getAttachmentBytes(a.id) || new Uint8Array()) })),
        })),
      }, null, 2);
      out.mime = 'application/json';
      break;
    case 'generic-csv':
      out.content = toCsv([
        ['Type', 'Name', 'URL', 'Username', 'Password', 'TOTP', 'Notes', 'Vault', 'Folder', 'Favorite', 'Tags', 'Fields'],
        ...supported.map((it) => [it.type, displayName(it), it.urls.join('\n'), it.username, it.password, it.totp, it.notes, vaultOf(it), it.folder, it.favorite ? 'yes' : '', it.tags.join(', '), fieldsText(it)]),
      ]);
      out.mime = 'text/csv';
      break;
    case 'bitwarden-json':
      out.content = JSON.stringify(bitwardenJson(supported), null, 2);
      out.mime = 'application/json';
      if (withCustom) notes.push('Custom fields are kept as Bitwarden fields.');
      break;
    case 'bitwarden-csv':
      out.content = toCsv([
        ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'],
        ...supported.map((it) => {
          const asNote = it.type === 'card' || it.type === 'identity';
          const isLogin = it.type === 'login';
          return [
            bwFolder(it), it.favorite ? 1 : 0, isLogin ? 'login' : 'note', displayName(it),
            asNote ? notesWithFields(it) : it.notes, '', 0,
            isLogin ? it.urls.join(',') : '', isLogin ? it.username : '', isLogin ? it.password : '', isLogin ? it.totp : '',
          ];
        }),
      ]);
      out.mime = 'text/csv';
      if (supported.some((it) => it.type === 'card' || it.type === 'identity')) notes.push('Cards and identities were written as secure notes.');
      break;
    case '1password-1pux':
      out.content = writeZip([
        { name: 'export.data', data: new TextEncoder().encode(JSON.stringify(onePuxData(supported))) },
        { name: 'manifest.json', data: new TextEncoder().encode(JSON.stringify({ version: 3, description: 'Exported by Vault Convert' })) },
      ]);
      out.mime = 'application/zip';
      notes.push('Test the import in 1Password with a few items first. This writer follows the 1PUX layout.');
      break;
    case 'keepass-xml':
      out.content = keepassXml(supported);
      out.mime = 'application/xml';
      break;
    case 'keepassxc-csv':
      out.content = toCsv([
        ['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP', 'Icon', 'Last Modified', 'Created'],
        ...supported.map((it) => [folderPath(it), displayName(it), it.username, it.password, firstUrl(it), notesWithFields(it), it.totp ? toOtpauthUri(it.totp, displayName(it)) : '', '0', it.updatedAt || '', it.createdAt || '']),
      ]);
      out.mime = 'text/csv';
      break;
    case 'proton-csv':
      out.content = toCsv([
        ['type', 'name', 'url', 'email', 'username', 'password', 'note', 'totp', 'vault'],
        ...supported.map((it) => [
          it.type === 'note' ? 'note' : 'login', displayName(it), firstUrl(it),
          it.username.includes('@') ? it.username : '', it.username, it.password, notesWithFields(it), it.totp, vaultOf(it),
        ]),
      ]);
      out.mime = 'text/csv';
      break;
    case 'lastpass-csv':
      out.content = toCsv([
        ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav'],
        ...supported.map((it) => [
          it.type === 'note' ? 'http://sn' : firstUrl(it), it.username, it.password, it.totp, notesWithFields(it),
          displayName(it), folderPath(it), it.favorite ? 1 : 0,
        ]),
      ]);
      out.mime = 'text/csv';
      break;
    case 'dashlane-csv':
      out.content = toCsv([
        ['title', 'url', 'username', 'password', 'note', 'totp', 'category'],
        ...supported.map((it) => [displayName(it), firstUrl(it), it.username, it.password, notesWithFields(it), it.totp, it.folder]),
      ]);
      out.mime = 'text/csv';
      break;
    case 'apple-csv':
      out.content = toCsv([
        ['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'],
        ...supported.map((it) => [displayName(it), firstUrl(it), it.username, it.password, notesWithFields(it), it.totp ? toOtpauthUri(it.totp, displayName(it)) : '']),
      ]);
      out.mime = 'text/csv';
      break;
    case 'chrome-csv':
      out.content = toCsv([
        ['name', 'url', 'username', 'password', 'note'],
        ...supported.map((it) => [displayName(it), firstUrl(it), it.username, it.password, notesWithFields(it)]),
      ]);
      out.mime = 'text/csv';
      if (withTotp) notes.push(`${withTotp} one-time code(s) were dropped because this format has no field for them.`);
      break;
    default:
      throw new Error(`No exporter for ${formatId}`);
  }

  if (withCustom && ['proton-csv', 'lastpass-csv', 'dashlane-csv', 'apple-csv', 'chrome-csv'].includes(formatId)) {
    notes.push('Custom fields were merged into the notes column.');
  }
  if (Object.keys(excluded).length) notes.push('Some item types are not supported by this format and were left out.');
  return out;
}

function bitwardenJson(items) {
  const folderIds = new Map();
  const folders = [];
  const folderIdFor = (name) => {
    if (!name) return null;
    if (!folderIds.has(name)) {
      const id = uid();
      folderIds.set(name, id);
      folders.push({ id, name });
    }
    return folderIds.get(name);
  };
  const out = items.map((it) => {
    const bw = {
      id: uid(),
      organizationId: null,
      folderId: folderIdFor(bwFolder(it)),
      type: BW_NUM[it.type],
      reprompt: 0,
      name: displayName(it),
      notes: it.notes,
      favorite: !!it.favorite,
      fields: it.customFields.map((f) => ({ name: f.name, value: f.value, type: f.hidden ? 1 : 0 })),
      collectionIds: null,
    };
    if (it.type === 'login') {
      bw.login = {
        uris: it.urls.map((uri) => ({ match: null, uri })),
        username: it.username,
        password: it.password,
        totp: it.totp,
      };
    } else if (it.type === 'card') {
      const card = {};
      for (const f of it.customFields) {
        const key = CARD_KEYS[norm(f.name)];
        if (key) card[key] = f.value;
      }
      bw.card = { cardholderName: '', number: '', brand: '', expMonth: '', expYear: '', code: '', ...card };
      bw.fields = it.customFields.filter((f) => !CARD_KEYS[norm(f.name)]).map((f) => ({ name: f.name, value: f.value, type: f.hidden ? 1 : 0 }));
    } else if (it.type === 'identity') {
      bw.identity = {};
    } else {
      bw.secureNote = { type: 0 };
    }
    return bw;
  });
  return { encrypted: false, folders, items: out };
}

function onePuxData(items) {
  const vaults = new Map();
  for (const it of items) {
    const name = vaultOf(it);
    if (!vaults.has(name)) vaults.set(name, []);
    const fields = [];
    const sections = [];
    if (it.totp) sections.push({ name: 'totp', title: 'One-time password', fields: [{ title: 'one-time password', id: 'totp', value: { totp: it.totp } }] });
    if (it.customFields.length) {
      sections.push({
        name: 'custom',
        title: 'Custom fields',
        fields: it.customFields.map((f, i) => ({ title: f.name, id: `cf${i}`, value: f.hidden ? { concealed: f.value } : { string: f.value } })),
      });
    }
    const login = it.type === 'login';
    if (login) {
      fields.push({ value: it.username, id: 'username', name: 'username', designation: 'username', fieldType: 'T' });
      fields.push({ value: it.password, id: 'password', name: 'password', designation: 'password', fieldType: 'P' });
    }
    vaults.get(name).push({
      uuid: uid(),
      favIndex: it.favorite ? 1 : 0,
      categoryUuid: CAT_1PUX[it.type],
      details: {
        loginFields: fields,
        notesPlain: it.notes,
        sections,
      },
      overview: {
        title: displayName(it),
        url: firstUrl(it),
        urls: it.urls.map((url, i) => ({ label: i === 0 ? 'website' : `website ${i + 1}`, url })),
        tags: it.tags,
        ps: 0,
      },
      createdAt: epochSeconds(it.createdAt),
      updatedAt: epochSeconds(it.updatedAt),
      state: 'active',
    });
  }
  return {
    accounts: [
      {
        attrs: { accountName: 'Vault Convert', name: 'Vault Convert', email: '', uuid: uid(), domain: '', avatar: '', userUUID: uid() },
        vaults: [...vaults.entries()].map(([name, list]) => ({ attrs: { name, uuid: uid(), desc: '', avatar: '', type: 'U' }, items: list })),
      },
    ],
  };
}

const xmlEscape = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);

function keepassXml(items) {
  const now = new Date().toISOString();
  const groupTree = new Map();
  for (const it of items) {
    const vault = vaultOf(it);
    if (!groupTree.has(vault)) groupTree.set(vault, new Map());
    const folders = groupTree.get(vault);
    const folder = it.folder || '';
    if (!folders.has(folder)) folders.set(folder, []);
    folders.get(folder).push(it);
  }
  const entryXml = (it) => {
    const str = (key, value, protectedValue = false) => `<String><Key>${xmlEscape(key)}</Key><Value${protectedValue ? ' Protected="True"' : ''}>${xmlEscape(value)}</Value></String>`;
    const parts = [
      str('Title', displayName(it)),
      str('UserName', it.username),
      str('Password', it.password, true),
      str('URL', firstUrl(it)),
      str('Notes', it.notes),
    ];
    if (it.totp) parts.push(str('otp', toOtpauthUri(it.totp, displayName(it)), true));
    for (const f of it.customFields) parts.push(str(f.name, f.value, f.hidden));
    return `    <Entry>
      <UUID>${randomId()}</UUID>
      <IconID>0</IconID>
      <Tags>${xmlEscape(it.tags.join(';'))}</Tags>
      <Times>
        <CreationTime>${xmlEscape(it.createdAt || now)}</CreationTime>
        <LastModificationTime>${xmlEscape(it.updatedAt || now)}</LastModificationTime>
      </Times>
      ${parts.join('\n      ')}
    </Entry>`;
  };
  const groupXml = (name, entries, children = '') => `  <Group>
    <UUID>${randomId()}</UUID>
    <Name>${xmlEscape(name)}</Name>
    <IconID>48</IconID>
${children}${entries.map(entryXml).join('\n')}
  </Group>`;
  const vaultXml = [...groupTree.entries()].map(([vault, folders]) => {
    const sub = [...folders.entries()]
      .filter(([folder]) => folder)
      .map(([folder, list]) => groupXml(folder, list))
      .join('\n');
    const direct = folders.get('') || [];
    return groupXml(vault, direct, sub ? `${sub}\n` : '');
  });
  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <Generator>Vault Convert</Generator>
  </Meta>
  <Root>
    <Group>
      <UUID>${randomId()}</UUID>
      <Name>Vault Convert export</Name>
      <IconID>48</IconID>
${vaultXml.join('\n')}
    </Group>
  </Root>
</KeePassFile>
`;
}

