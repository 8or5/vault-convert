// Import: detects a file's format from its bytes and turns its records into items.
// Unknown layouts fall back to header-name matching, and unmatched columns are kept as
// custom fields so nothing is silently dropped.

import { parseCsv, detectDelimiter } from './csv.js';
import { readZip } from './zip.js';
import { newItem, toIso, hostOf, splitUrls, DEFAULT_VAULT } from './model.js';

const BW_TYPE = { 1: 'login', 2: 'note', 3: 'card', 4: 'identity' };
const CAT_1PUX = { '001': 'login', '005': 'login', '002': 'card', '003': 'note', '004': 'identity' };

// Normalised header names (lower case, letters and digits only) for each logical field.
const FIELD_ALIASES = {
  name: ['name', 'title', 'itemname', 'entryname', 'itemtitle', 'label', 'entry', 'accountname', 'displayname'],
  url: ['url', 'uri', 'uris', 'urls', 'website', 'webaddress', 'web', 'link', 'loginuri', 'loginuris', 'origin', 'formactionorigin', 'location'],
  username: ['username', 'loginusername', 'user', 'loginname', 'email', 'userid', 'useremail', 'usernameemail', 'accountusername'],
  password: ['password', 'loginpassword', 'pass', 'pwd', 'passwordvalue', 'secret'],
  totp: ['totp', 'otp', 'otpauth', 'loginotp', 'logintotp', 'onetimepassword', 'totpsecret', 'totpuri', 'twofactor', 'authenticator'],
  notes: ['notes', 'note', 'notesplain', 'extra', 'comments', 'comment', 'memo', 'description', 'loginnotes', 'secretnotes'],
  folder: ['folder', 'foldername', 'folders', 'folderpath', 'grouping', 'group', 'groupname', 'groups'],
  vault: ['vault', 'vaultname', 'collection', 'collections', 'space', 'library'],
  favorite: ['favorite', 'favourite', 'favorites', 'favourites', 'fav', 'starred', 'isfavorite'],
  type: ['type', 'itemtype', 'kind', 'category', 'templatetype', 'typename'],
  created: ['created', 'createdat', 'createtime', 'timecreated', 'dateadded', 'datecreated', 'creationtime', 'creationdate'],
  updated: ['updated', 'updatedat', 'lastmodified', 'modifiedat', 'timemodified', 'timelastmodified', 'revisiondate', 'lastmodifieddate', 'updatetime', 'lastmodificationtime'],
  tags: ['tags', 'tag', 'labels'],
};

const SENSITIVE = /pin|secret|cvv|cvc|code|number|passport|security|password/i;
const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const humanize = (k) => k.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_.]+/g, ' ').replace(/^./, (c) => c.toUpperCase());

/** Entry point. `bytes` is a Uint8Array of the file contents. */
export async function parseFile(fileName, bytes) {
  let result;
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    const entries = await readZip(bytes);
    if (!entries.has('export.data')) throw new Error('ZIP archive without a recognised export inside.');
    result = parse1pux(JSON.parse(decodeText(entries.get('export.data'))), []);
  } else {
    const text = decodeText(bytes).replace(/^﻿/, '');
    const head = text.trimStart();
    if (head.startsWith('<')) result = parseKeePassXml(text, []);
    else if (head.startsWith('{') || head.startsWith('[')) result = parseJson(text, []);
    else if (head.startsWith('***')) result = parse1pif(text, []);
    else result = parseCsvText(text, []);
  }
  const items = result.items.map((it) => ({ ...it, source: result.format }));
  return { ...result, items, fileName, count: items.length };
}

function decodeText(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes.subarray(2));
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder('utf-16be').decode(bytes.subarray(2));
  return new TextDecoder('utf-8').decode(bytes);
}

// ---------- JSON ----------

function parseJson(text, warnings) {
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON: ${e.message}`);
  }
  if (Array.isArray(data)) {
    if (data.some((i) => i && Array.isArray(i.fields))) return parseEnpassJson({ items: data }, warnings);
    return parseRecords(data.filter((o) => o && typeof o === 'object').map((o) => flattenRecord(o)), 'Generic JSON', warnings);
  }
  if (!data || typeof data !== 'object') throw new Error('Unrecognised JSON structure.');
  if (data.encrypted === true) throw new Error('This Bitwarden export is encrypted. Export it again as unencrypted JSON.');
  if (data.accounts) return parse1pux(data, warnings);
  if (Array.isArray(data.items)) {
    if ('encrypted' in data || data.items.some((i) => typeof i.type === 'number')) return parseBitwardenJson(data, warnings);
    if (data.items.some((i) => Array.isArray(i.fields))) return parseEnpassJson(data, warnings);
    return parseRecords(data.items.map((o) => flattenRecord(o)), 'JSON export', warnings);
  }
  // Shapes such as { "AUTHENTIFIANT": [ {...} ], "PERSONAL_INFO": [ ... ] }: one list per category.
  const records = [];
  for (const [section, value] of Object.entries(data)) {
    if (Array.isArray(value)) {
      for (const o of value) if (o && typeof o === 'object') records.push(flattenRecord({ section, ...o }));
    }
  }
  if (records.length) return parseRecords(records, 'JSON export (sectioned)', warnings);
  throw new Error('Unrecognised JSON structure.');
}

function parseBitwardenJson(data, warnings) {
  const folders = new Map((data.folders || []).map((f) => [f.id, f.name || '']));
  const items = (data.items || []).map((b) => {
    const login = b.login || {};
    const item = newItem({
      type: BW_TYPE[b.type] || 'login',
      name: b.name || '',
      notes: b.notes || '',
      folder: folders.get(b.folderId) || '',
      favorite: !!b.favorite,
      urls: (login.uris || []).map((u) => u.uri).filter(Boolean),
      username: login.username || '',
      password: login.password || '',
      totp: login.totp || '',
      customFields: (b.fields || []).map((f) => ({ name: f.name || '', value: f.value || '', hidden: f.type === 1 })),
      createdAt: toIso(b.creationDate),
      updatedAt: toIso(b.revisionDate),
    });
    if (b.card) item.customFields.push(...objectToFields(b.card));
    if (b.identity) item.customFields.push(...objectToFields(b.identity));
    if (!item.name) item.name = hostOf(item.urls[0]) || item.username || 'Untitled';
    return item;
  });
  return { format: 'Bitwarden JSON', items, warnings };
}

function objectToFields(obj) {
  return Object.entries(obj || {})
    .filter(([, v]) => v !== null && v !== undefined && String(v) !== '')
    .map(([k, v]) => ({ name: humanize(k), value: String(v), hidden: SENSITIVE.test(k) }));
}

function parseEnpassJson(data, warnings) {
  const records = data.items.map((it) => {
    const rec = {
      title: it.title || it.subtitle || '',
      category: it.category || '',
      note: it.note || it.notes || '',
      folder: Array.isArray(it.folders) ? it.folders.join(' / ') : it.folder || '',
    };
    for (const f of it.fields || []) {
      if (f.value === undefined || f.value === null || f.value === '') continue;
      const t = String(f.type || '').toLowerCase();
      const key = { username: 'username', email: 'username', password: 'password', website: 'url', url: 'url', totp: 'totp', otp: 'totp' }[t] || f.label || t || 'field';
      if (key === 'url') rec.url = rec.url ? `${rec.url}\n${f.value}` : String(f.value);
      else if (rec[key] === undefined) rec[key] = String(f.value);
      else rec[`${key} ${Object.keys(rec).length}`] = String(f.value);
    }
    return rec;
  });
  return parseRecords(records, 'Enpass JSON', warnings);
}

function parse1pux(data, warnings) {
  const items = [];
  for (const account of data.accounts || []) {
    for (const vault of account.vaults || []) {
      const vaultName = vault.attrs?.name || DEFAULT_VAULT;
      for (const it of vault.items || []) {
        const o = it.overview || {};
        const d = it.details || {};
        const item = newItem({
          type: CAT_1PUX[it.categoryUuid] || 'login',
          name: o.title || '',
          vault: vaultName,
          favorite: Number(it.favIndex) > 0,
          urls: uniqueList([o.url, ...(o.urls || []).map((u) => u.url)]),
          notes: d.notesPlain || '',
          tags: o.tags || [],
          createdAt: toIso(it.createdAt),
          updatedAt: toIso(it.updatedAt),
          password: d.password || '',
        });
        for (const f of d.loginFields || []) {
          if (f.designation === 'username') item.username = f.value || '';
          else if (f.designation === 'password') item.password = f.value || '';
        }
        for (const s of d.sections || []) {
          for (const f of s.fields || []) {
            const [kind, value] = Object.entries(f.value || {})[0] || [];
            if (value === undefined || value === null || value === '') continue;
            if (kind === 'totp') item.totp = String(value);
            else {
              const label = [s.title, f.title].filter(Boolean).join(' · ') || 'Field';
              item.customFields.push({ name: label, value: typeof value === 'object' ? JSON.stringify(value) : String(value), hidden: kind === 'concealed' });
            }
          }
        }
        if (!item.name) item.name = hostOf(item.urls[0]) || item.username || 'Untitled';
        items.push(item);
      }
    }
  }
  return { format: '1Password (1PUX)', items, warnings };
}

function uniqueList(list) {
  return [...new Set(list.filter(Boolean))];
}

function flattenRecord(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v === null || v === undefined) continue;
    if (Array.isArray(v)) {
      if (v.every((x) => x === null || typeof x !== 'object')) out[key] = v.filter((x) => x !== null && x !== '').join('\n');
      else v.forEach((x, i) => { if (x && typeof x === 'object') flattenRecord(x, `${key}${i}`, out); });
    } else if (typeof v === 'object') {
      flattenRecord(v, key, out);
    } else {
      out[key] = String(v);
    }
  }
  return out;
}

// ---------- 1PIF (older 1Password format: JSON records separated by ***uuid*** lines) ----------

function parse1pif(text, warnings) {
  const chunks = text.split(/^\*\*\*[0-9a-f-]+\*\*\*\s*$/im).map((s) => s.trim()).filter(Boolean);
  const records = [];
  let bad = 0;
  for (const chunk of chunks) {
    let r;
    try {
      r = JSON.parse(chunk);
    } catch {
      bad++;
      continue;
    }
    const sc = r.secureContents || {};
    const rec = {
      title: r.title || '',
      type: r.typeName || '',
      url: [r.location, ...(sc.URLs || []).map((u) => u.url)].filter(Boolean).join('\n'),
      notes: sc.notesPlain || '',
      favorite: r.faveIndex ? '1' : '',
    };
    for (const f of sc.fields || []) {
      if (f.value === undefined || f.value === '') continue;
      if (f.designation === 'username') rec.username = String(f.value);
      else if (f.designation === 'password') rec.password = String(f.value);
      else rec[f.title || f.name || 'field'] = String(f.value);
    }
    records.push(rec);
  }
  if (bad) warnings.push(`${bad} record(s) could not be read.`);
  return parseRecords(records, '1Password (1PIF)', warnings);
}

// ---------- KeePass 2 XML ----------

function parseKeePassXml(text, warnings) {
  if (typeof DOMParser === 'undefined') throw new Error('XML import needs a browser.');
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror')) throw new Error('Invalid KeePass XML.');
  const rootGroup = doc.querySelector('KeePassFile > Root > Group');
  if (!rootGroup) throw new Error('KeePass XML without a Root group.');
  const records = [];
  const childOf = (el, tag) => [...el.children].find((c) => c.tagName === tag) || { children: [] };
  const childText = (el, tag) => [...el.children].find((c) => c.tagName === tag)?.textContent ?? '';
  const walk = (group, path) => {
    for (const child of [...group.children]) {
      if (child.tagName === 'Group') {
        walk(child, [...path, childText(child, 'Name')]);
      } else if (child.tagName === 'Entry') {
        const rec = {
          vault: path[0] || '',
          folder: path.slice(1).join(' / '),
          created: childText(childOf(child, 'Times'), 'CreationTime'),
          lastmodificationtime: childText(childOf(child, 'Times'), 'LastModificationTime'),
        };
        for (const s of child.children) {
          if (s.tagName !== 'String') continue;
          const key = childText(s, 'Key');
          const value = childText(s, 'Value');
          if (key) rec[key] = value;
        }
        records.push(rec);
      }
    }
  };
  walk(rootGroup, []);
  return parseRecords(records, 'KeePass XML', warnings);
}

// ---------- CSV ----------

const CSV_SIGNATURES = [
  ['Bitwarden CSV', (h) => h.includes('loginuri') || h.includes('loginpassword')],
  ['LastPass CSV', (h) => h.includes('grouping') && h.includes('extra')],
  ['KeePassXC CSV', (h) => h[0] === 'group' && h.includes('totp')],
  ['Proton Pass CSV', (h) => h.includes('email') && h.includes('vault') && h.includes('type')],
  ['Apple Passwords CSV', (h) => h.includes('otpauth') && h.includes('title')],
  ['Firefox CSV', (h) => h.includes('httprealm') || h.includes('formactionorigin')],
  ['Dashlane CSV', (h) => h.includes('username2') || h.includes('username3')],
  ['1Password CSV', (h) => h.includes('title') && h.includes('website') && h.includes('vault')],
  ['Chrome / Google / Edge CSV', (h) => h.length <= 6 && h.includes('name') && h.includes('url') && h.includes('password')],
];

function parseCsvText(text, warnings) {
  const rows = parseCsv(text, detectDelimiter(text));
  if (rows.length < 2) throw new Error('No data rows found. Is this a CSV export?');
  const seen = new Map();
  const headers = rows[0].map((h) => {
    const base = h.trim() || 'column';
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    return n > 1 ? `${base} ${n}` : base;
  });
  const normHeaders = headers.map(norm);
  const format = (CSV_SIGNATURES.find(([, test]) => test(normHeaders)) || [null])[0] || 'Generic CSV';
  const records = rows.slice(1).map((r) => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ''])));
  return parseRecords(records, format, warnings);
}

// ---------- Shared record mapping ----------

function parseRecords(records, format, warnings) {
  const items = [];
  let skipped = 0;
  for (const rec of records) {
    if (!Object.values(rec).some((v) => String(v).trim())) {
      skipped++;
      continue;
    }
    items.push(recordToItem(rec));
  }
  if (skipped) warnings.push(`${skipped} empty row(s) skipped.`);
  return { format, items, warnings };
}

function recordToItem(rec) {
  const keys = Object.keys(rec);
  const used = new Set();
  const take = (aliases) => {
    let found = '';
    for (const alias of aliases) {
      for (const k of keys) {
        if (norm(k) !== alias) continue;
        used.add(k);
        if (!found && String(rec[k]).trim() !== '') found = String(rec[k]);
      }
    }
    return found;
  };

  const name = take(FIELD_ALIASES.name);
  const urls = splitUrls(take(FIELD_ALIASES.url));
  const username = take(FIELD_ALIASES.username).trim();
  const password = take(FIELD_ALIASES.password);
  const totp = take(FIELD_ALIASES.totp).trim();
  const notes = take(FIELD_ALIASES.notes);
  const folder = take(FIELD_ALIASES.folder).trim();
  const vault = take(FIELD_ALIASES.vault).trim();
  const fav = take(FIELD_ALIASES.favorite);
  const typeRaw = take(FIELD_ALIASES.type);
  const created = take(FIELD_ALIASES.created);
  const updated = take(FIELD_ALIASES.updated);
  const tags = take(FIELD_ALIASES.tags);

  let type = typeFrom(typeRaw);
  // Rows with nothing login-like (no user, password, site or one-time code) are treated as notes.
  if (!typeRaw && !username && !password && !urls.length && !totp) type = 'note';

  const customFields = keys
    .filter((k) => !used.has(k) && String(rec[k]).trim() !== '')
    .map((k) => ({ name: k, value: String(rec[k]), hidden: SENSITIVE.test(k) }));

  const item = newItem({
    type,
    urls,
    username,
    password,
    totp,
    notes,
    folder,
    vault: vault || DEFAULT_VAULT,
    favorite: /^(1|true|yes|y|x|on)$/i.test(fav.trim()),
    tags: tags.split(/[,;]/).map((t) => t.trim()).filter(Boolean),
    customFields,
    createdAt: toIso(created),
    updatedAt: toIso(updated),
  });
  item.name = name.trim() || hostOf(urls[0]) || username || 'Untitled';
  return item;
}

function typeFrom(raw) {
  const v = String(raw || '').toLowerCase();
  if (/card|credit|debit|payment/.test(v)) return 'card';
  if (/identity|passport|driver|licen[cs]e/.test(v)) return 'identity';
  if (/note|memo/.test(v)) return 'note';
  return 'login';
}
