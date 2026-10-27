// KeePass KDBX engine (versions 3 and 4) on top of kdbxweb, with Argon2 in WebAssembly.
//
// The app edits a flat list of items. This module converts between that list and the
// KDBX tree, and it edits the original KDBX objects in place when saving, so data the app
// doesn't model (entry history, custom icons, group settings, unknown fields) survives.

import kdbxweb from 'kdbxweb';
import { kdbxwebArgon2 } from './argon2.js';
import { newItem, toIso, uniq, vaultOf, DEFAULT_VAULT } from './model.js';
import { toOtpauthUri, cleanSecret } from './totp.js';
import { addAttachmentBytes, getAttachmentBytes, clearAttachments } from './attachments.js';

kdbxweb.CryptoEngine.setArgon2Impl(kdbxwebArgon2);

const { ProtectedValue, Credentials, Kdbx, Consts } = kdbxweb;
const { KdfId, CipherId } = Consts;

export const FOLDER_SEP = ' / ';
export const TYPE_KEY = 'VaultConvert.Type';
const PREV_KEY = 'VaultConvert.PreviousLocation';
const KDBX_SIGNATURE = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];

export const isKdbx = (bytes) => bytes.length > 8 && KDBX_SIGNATURE.every((b, i) => bytes[i] === b);

export const KDF_PRESETS = {
  fast: { label: 'Fast (16 MiB, 2 passes)', memoryMiB: 16, iterations: 2, parallelism: 2 },
  standard: { label: 'Standard (64 MiB, 3 passes)', memoryMiB: 64, iterations: 3, parallelism: 2 },
  strong: { label: 'Strong (256 MiB, 4 passes)', memoryMiB: 256, iterations: 4, parallelism: 2 },
};
export const KDF_TYPES = { argon2d: 'Argon2d (KeePass default)', argon2id: 'Argon2id', aes: 'AES-KDF (oldest, widest support)' };

const STANDARD = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes']);
const OTP_KEYS = new Set([
  'otp', 'TimeOtp-Secret-Base32', 'TimeOtp-Secret', 'TimeOtp-Secret-Hex', 'TimeOtp-Secret-Base64',
  'TimeOtp-Length', 'TimeOtp-Period', 'TimeOtp-Algorithm', 'TOTP Seed', 'TOTP Settings',
]);
const isUrlExtra = (k) => /^KP2A_URL(_\d+)?$/.test(k);
const reserved = (k) => STANDARD.has(k) || OTP_KEYS.has(k) || isUrlExtra(k);

const text = (v) => (v instanceof ProtectedValue ? v.getText() : v === undefined || v === null ? '' : String(v));
const toBuffer = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

export class KdbxUnlockError extends Error {
  constructor(message, code = 'unlock') {
    super(message);
    this.name = 'KdbxUnlockError';
    this.code = code;
  }
}

function credentialsFrom({ password, keyFile }) {
  const pv = password ? ProtectedValue.fromString(password) : null;
  const key = keyFile ? (keyFile instanceof Uint8Array ? toBuffer(keyFile) : keyFile) : null;
  if (!pv && !key) throw new KdbxUnlockError('Enter a password or choose a key file.', 'empty');
  return new Credentials(pv, key);
}

export const makeCredentials = credentialsFrom;

// ---------- reading ----------

function readTotp(fields) {
  const otp = text(fields.get('otp')).trim();
  if (otp) {
    if (/^otpauth:\/\//i.test(otp)) return otp;
    if (/(^|&|;)key=/i.test(otp)) {
      // KeePassXC legacy "key=BASE32&step=30&size=6" format.
      const q = new URLSearchParams(otp.replace(/;/g, '&'));
      const secret = cleanSecret(q.get('key'));
      const step = Number(q.get('step')) || 30;
      const size = Number(q.get('size')) || 6;
      return step === 30 && size === 6 ? secret : `otpauth://totp/account?secret=${secret}&period=${step}&digits=${size}`;
    }
    return cleanSecret(otp);
  }
  const b32 = text(fields.get('TimeOtp-Secret-Base32')).trim();
  if (b32) {
    const len = Number(text(fields.get('TimeOtp-Length'))) || 6;
    const period = Number(text(fields.get('TimeOtp-Period'))) || 30;
    const algo = { 'HMAC-SHA-1': 'SHA1', 'HMAC-SHA-256': 'SHA256', 'HMAC-SHA-512': 'SHA512' }[text(fields.get('TimeOtp-Algorithm'))] || 'SHA1';
    if (len === 6 && period === 30 && algo === 'SHA1') return cleanSecret(b32);
    return `otpauth://totp/account?secret=${cleanSecret(b32)}&period=${period}&digits=${len}&algorithm=${algo}`;
  }
  const seed = text(fields.get('TOTP Seed')).trim();
  if (seed) {
    const [period, digits] = text(fields.get('TOTP Settings')).split(';').map(Number);
    const secret = cleanSecret(seed);
    return !period || (period === 30 && (digits || 6) === 6) ? secret : `otpauth://totp/account?secret=${secret}&period=${period}&digits=${digits || 6}`;
  }
  return '';
}

function binaryBytes(bin) {
  const v = bin && bin.value !== undefined ? bin.value : bin;
  if (v instanceof ProtectedValue) return v.getBinary();
  return new Uint8Array(v);
}

function pathFromGroup(group, root) {
  const names = [];
  for (let g = group; g && g !== root; g = g.parentGroup) names.unshift(g.name || '');
  return names;
}

function recycleBin(db) {
  const id = db.meta.recycleBinUuid;
  if (!id || !db.meta.recycleBinEnabled) return undefined;
  return db.getGroup(id) || undefined;
}

const insideGroup = (entry, group) => {
  for (let g = entry.parentGroup; g; g = g.parentGroup) if (g === group) return true;
  return false;
};

function entryToItem(db, entry, rootName, bin) {
  const f = entry.fields;
  const root = db.getDefaultGroup();
  const trashed = !!bin && insideGroup(entry, bin);
  let names;
  let known = true;
  if (trashed) {
    // Remember where a trashed entry came from. KDBX 4.1 records this natively, but we keep
    // files at 4.0 for compatibility with older KeePass, so we store it ourselves.
    const saved = entry.customData?.get?.(PREV_KEY)?.value;
    try { names = saved ? JSON.parse(saved) : null; } catch { names = null; }
    if (!Array.isArray(names)) {
      const prev = entry.previousParentGroup ? db.getGroup(entry.previousParentGroup) : undefined;
      names = prev && !insideGroup({ parentGroup: prev }, bin) ? pathFromGroup(prev, root) : [];
      known = !!prev;
    }
  } else {
    names = pathFromGroup(entry.parentGroup, root);
  }
  const vault = names.length ? names[0] : trashed && !known ? 'Recovered' : rootName;
  const folder = names.slice(1).join(FOLDER_SEP);

  const urls = [text(f.get('URL'))];
  const extras = [...f.keys()].filter(isUrlExtra).sort();
  for (const k of extras) urls.push(text(f.get(k)));

  const customFields = [];
  for (const [k, v] of f) {
    if (reserved(k)) continue;
    customFields.push({ name: k, value: text(v), hidden: v instanceof ProtectedValue });
  }

  const tags = [...(entry.tags || [])];
  const favorite = tags.some((t) => t.toLowerCase() === 'favorite');
  const attachments = [...entry.binaries].map(([name, bin]) => {
    const bytes = binaryBytes(bin);
    return { id: addAttachmentBytes(bytes), name, size: bytes.byteLength, existing: true };
  });

  const savedType = entry.customData?.get?.(TYPE_KEY)?.value;
  const username = text(f.get('UserName'));
  const password = text(f.get('Password'));
  const totp = readTotp(f);
  const clean = urls.filter(Boolean);
  const looksLikeNote = !username && !password && !totp && !clean.length;
  const type = ['login', 'note', 'card', 'identity'].includes(savedType) ? savedType : looksLikeNote && text(f.get('Notes')) ? 'note' : 'login';

  const seen = new Set();
  const pwHistory = [];
  for (const h of [...(entry.history || [])].reverse()) {
    const p = text(h.fields.get('Password'));
    if (p && p !== password && !seen.has(p)) {
      seen.add(p);
      pwHistory.push({ password: p, time: h.times?.lastModTime ? h.times.lastModTime.toISOString() : null });
    }
  }

  const item = newItem({
    id: entry.uuid.id,
    type,
    name: text(f.get('Title')),
    username,
    password,
    urls: clean,
    totp,
    notes: text(f.get('Notes')),
    vault,
    folder,
    favorite,
    tags: tags.filter((t) => t.toLowerCase() !== 'favorite'),
    customFields,
    attachments,
    createdAt: toIso(entry.times?.creationTime),
    updatedAt: toIso(entry.times?.lastModTime),
    trashed,
    source: 'KeePass KDBX',
  });
  item.pwHistory = pwHistory;
  item.historyCount = (entry.history || []).length;
  return item;
}

/** Stable signature of everything the app persists, used to skip untouched entries on save. */
export function persistSig(item) {
  return JSON.stringify([
    item.type, item.name, item.username, item.password, item.urls, item.totp, item.notes,
    vaultOf(item), item.folder, !!item.favorite, item.tags,
    (item.customFields || []).map((c) => [c.name, c.value, !!c.hidden]),
    (item.attachments || []).map((a) => [a.id, a.name]),
    !!item.trashed,
  ]);
}

/** Builds the app-side model. Callers clear the attachment store themselves when starting a fresh session. */
export function loadModel(db) {
  const root = db.getDefaultGroup();
  const bin = recycleBin(db);
  const rootName = root.name || 'Database';
  const items = [];
  for (const e of root.allEntries()) items.push(entryToItem(db, e, rootName, bin));

  const vaults = [];
  const folders = {};
  const walk = (group, vault, path) => {
    for (const g of group.groups) {
      if (g === bin) continue;
      const p = [...path, g.name || ''];
      if (!vault) {
        vaults.push(g.name || '');
        folders[g.name || ''] = [];
        walk(g, g.name || '', []);
      } else {
        folders[vault].push(p.join(FOLDER_SEP));
        walk(g, vault, p);
      }
    }
  };
  walk(root, '', []);
  if (items.some((i) => i.vault === rootName && !i.trashed) && !vaults.includes(rootName)) vaults.unshift(rootName);

  const baseline = new Map(items.map((i) => [i.id, persistSig(i)]));
  const idMap = new Map(items.map((i) => [i.id, i.id]));
  const baselineItems = items.map((i) => [i.id, { totp: i.totp }]);
  return { items, meta: { vaults, folders }, rootName, baseline, baselineItems, idMap, permanent: new Set() };
}

export async function openKdbx(bytes, { password, keyFile } = {}) {
  const creds = credentialsFrom({ password, keyFile });
  let db;
  try {
    db = await Kdbx.load(toBuffer(bytes), creds);
  } catch (e) {
    if (e && (e.code === 'InvalidKey' || /invalid key|hmac|credentials/i.test(String(e.message)))) {
      throw new KdbxUnlockError('Wrong password or key file.', 'wrong-key');
    }
    if (e && e.code === 'FileCorrupt') throw new KdbxUnlockError('This file looks damaged or is not a KeePass database.', 'corrupt');
    throw e;
  }
  return { db, ...loadModel(db) };
}

// ---------- writing ----------

function ensureGroup(db, names, bin) {
  let g = db.getDefaultGroup();
  for (const n of names) {
    let child = g.groups.find((x) => x.name === n && x !== bin);
    if (!child) child = db.createGroup(g, n);
    g = child;
  }
  return g;
}

function groupNames(item, rootName) {
  const f = item.folder ? item.folder.split(FOLDER_SEP).filter(Boolean) : [];
  return vaultOf(item) === rootName ? f : [vaultOf(item), ...f];
}

function setField(entry, key, value, protect) {
  const existing = entry.fields.get(key);
  const mustProtect = protect || existing instanceof ProtectedValue;
  entry.fields.set(key, mustProtect ? ProtectedValue.fromString(value) : value);
}

async function applyItem(db, entry, item, base) {
  setField(entry, 'Title', item.name || '', false);
  setField(entry, 'UserName', item.username || '', false);
  setField(entry, 'Password', item.password || '', true);
  setField(entry, 'URL', item.urls[0] || '', false);
  setField(entry, 'Notes', item.notes || '', false);

  for (const k of [...entry.fields.keys()]) if (isUrlExtra(k)) entry.fields.delete(k);
  item.urls.slice(1).forEach((u, i) => entry.fields.set(i === 0 ? 'KP2A_URL' : `KP2A_URL_${i}`, u));

  const wanted = new Map();
  for (const c of item.customFields || []) {
    if (!c.name && !c.value) continue;
    let name = c.name || 'Field';
    if (reserved(name)) name = `Field: ${name}`;
    for (let n = 2; wanted.has(name); n++) name = `${c.name || 'Field'} (${n})`;
    wanted.set(name, c);
  }
  for (const k of [...entry.fields.keys()]) if (!reserved(k) && !wanted.has(k)) entry.fields.delete(k);
  for (const [name, c] of wanted) setField(entry, name, c.value, !!c.hidden);

  if (base === undefined || item.totp !== base.totp) {
    for (const k of OTP_KEYS) entry.fields.delete(k);
    if (item.totp) entry.fields.set('otp', ProtectedValue.fromString(toOtpauthUri(item.totp, item.name || 'account')));
  }

  entry.tags = uniq([...(item.tags || []), ...(item.favorite ? ['Favorite'] : [])]);

  if (!entry.customData) entry.customData = new Map();
  if (item.type && item.type !== 'login') entry.customData.set(TYPE_KEY, { value: item.type, lastModified: new Date() });
  else entry.customData.delete(TYPE_KEY);

  const desired = new Map((item.attachments || []).map((a) => [a.name, a]));
  for (const name of [...entry.binaries.keys()]) {
    const a = desired.get(name);
    if (!a || !a.existing) entry.binaries.delete(name);
  }
  for (const [name, a] of desired) {
    if (a.existing && entry.binaries.has(name)) continue;
    const bytes = getAttachmentBytes(a.id);
    if (bytes) entry.binaries.set(name, await db.createBinary(bytes.slice()));
  }
}

/**
 * Writes the app's items into the open database. `kd` carries { baseline, idMap, rootName, permanent }.
 * Only entries whose persisted content changed are touched, so history stays meaningful.
 */
export async function syncToDb(db, kd, items, meta) {
  const root = db.getDefaultGroup();
  let bin = recycleBin(db);
  const byUuid = new Map();
  for (const e of root.allEntries()) byUuid.set(e.uuid.id, e);
  const baseItems = new Map(kd.baselineItems || []);

  // Keep empty vaults and folders that the user created.
  for (const v of meta.vaults || []) {
    if (v !== kd.rootName) ensureGroup(db, [v], bin);
    for (const f of meta.folders?.[v] || []) ensureGroup(db, v === kd.rootName ? f.split(FOLDER_SEP) : [v, ...f.split(FOLDER_SEP)], bin);
  }

  const present = new Set();
  for (const item of items) {
    present.add(item.id);
    const sig = persistSig(item);
    let entry = byUuid.get(kd.idMap.get(item.id));
    const isNew = !entry;
    if (!isNew && kd.baseline.get(item.id) === sig) continue;

    if (isNew) {
      entry = db.createEntry(ensureGroup(db, groupNames(item, kd.rootName), bin));
      kd.idMap.set(item.id, entry.uuid.id);
      if (item.createdAt) entry.times.creationTime = new Date(item.createdAt);
    } else {
      entry.pushHistory();
    }
    await applyItem(db, entry, item, baseItems.get(item.id));

    if (!entry.customData) entry.customData = new Map();
    if (item.trashed) {
      if (!bin) {
        db.createRecycleBin();
        bin = recycleBin(db);
      }
      entry.customData.set(PREV_KEY, { value: JSON.stringify(groupNames(item, kd.rootName)), lastModified: new Date() });
      if (!insideGroup(entry, bin)) db.move(entry, bin);
    } else {
      entry.customData.delete(PREV_KEY);
      const target = ensureGroup(db, groupNames(item, kd.rootName), bin);
      if (entry.parentGroup !== target) db.move(entry, target);
    }
    entry.times.lastModTime = item.updatedAt ? new Date(item.updatedAt) : new Date();
  }

  for (const [itemId, uuid] of [...kd.idMap]) {
    if (present.has(itemId)) continue;
    const entry = byUuid.get(uuid);
    if (entry) {
      // remove() sends things to the recycle bin; move(x, null) deletes for good and records a
      // tombstone so that merges with other copies of the file also delete it.
      if (kd.permanent?.has(itemId)) db.move(entry, null);
      else db.remove(entry);
    }
    kd.idMap.delete(itemId);
    kd.baseline.delete(itemId);
  }

  // Remove groups the user deleted or renamed away from, but only if they are empty.
  const desired = new Set();
  for (const v of meta.vaults || []) {
    desired.add(v);
    for (const f of meta.folders?.[v] || []) desired.add(`${v}${FOLDER_SEP}${f}`);
  }
  for (const item of items) {
    const n = groupNames(item, kd.rootName);
    for (let i = 1; i <= n.length; i++) desired.add(n.slice(0, i).join(FOLDER_SEP));
  }
  const prune = (group, prefix) => {
    for (const g of [...group.groups]) {
      if (g === bin) continue;
      const p = [...prefix, g.name || ''];
      prune(g, p);
      const key = p.join(FOLDER_SEP);
      if (!desired.has(key) && !g.entries.length && !g.groups.length) db.move(g, null);
    }
  };
  prune(root, []);

  kd.baseline = new Map(items.map((i) => [i.id, persistSig(i)]));
  kd.baselineItems = items.map((i) => [i.id, { totp: i.totp }]);
  kd.permanent?.clear();
  for (const item of items) for (const a of item.attachments || []) a.existing = true;
}

export async function saveDb(db) {
  const buf = await db.save();
  return new Uint8Array(buf);
}

/** Merges another copy of the same database (for example edited elsewhere) into this one. */
export async function mergeRemote(db, bytes, creds) {
  const remote = await Kdbx.load(toBuffer(bytes), creds || db.credentials);
  db.merge(remote);
}

// ---------- creating and configuring databases ----------

export function setKdfParams(db, { kdf = 'argon2d', preset = 'standard' } = {}) {
  const p = KDF_PRESETS[preset] || KDF_PRESETS.standard;
  if (kdf === 'aes') {
    db.setKdf(KdfId.Aes);
    return;
  }
  db.setKdf(kdf === 'argon2id' ? KdfId.Argon2id : KdfId.Argon2d);
  const kp = db.header.kdfParameters;
  const T = kdbxweb.VarDictionary.ValueType;
  kp.set('M', T.UInt64, new kdbxweb.Int64(p.memoryMiB * 1024 * 1024));
  kp.set('I', T.UInt64, new kdbxweb.Int64(p.iterations));
  kp.set('P', T.UInt32, p.parallelism);
}

export function createDb({ name, password, keyFile, kdf, preset }) {
  const db = Kdbx.create(credentialsFrom({ password, keyFile }), name || 'Passwords');
  setKdfParams(db, { kdf, preset });
  return db;
}

export const generateKeyFile = () => Credentials.createRandomKeyFile(2);

export function describeDb(db) {
  const h = db.header;
  let kdf = 'Unknown';
  let detail = '';
  if (h.kdfParameters) {
    const id = kdbxweb.ByteUtils.bytesToBase64(h.kdfParameters.get('$UUID'));
    const mem = h.kdfParameters.get('M');
    const it = h.kdfParameters.get('I');
    if (id === KdfId.Argon2d || id === KdfId.Argon2id) {
      kdf = id === KdfId.Argon2id ? 'Argon2id' : 'Argon2d';
      detail = `${Math.round(Number(mem.valueOf()) / 1048576)} MiB, ${it.valueOf()} passes, ${h.kdfParameters.get('P')} lanes`;
    } else if (id === KdfId.Aes) {
      kdf = 'AES-KDF';
      detail = `${h.kdfParameters.get('R')?.valueOf?.() ?? ''} rounds`;
    }
  } else if (h.keyEncryptionRounds) {
    kdf = 'AES-KDF';
    detail = `${h.keyEncryptionRounds} rounds`;
  }
  const cipherId = h.dataCipherUuid?.id ?? '';
  const cipher = cipherId === CipherId.ChaCha20 ? 'ChaCha20' : 'AES-256';
  return { version: `${db.versionMajor}.${db.versionMinor}`, kdf, kdfDetail: detail, cipher, name: db.meta.name || '' };
}

export async function changeCredentials(db, { password, keyFile }) {
  const creds = credentialsFrom({ password, keyFile });
  await creds.ready;
  db.credentials = creds;
}

export { DEFAULT_VAULT };
