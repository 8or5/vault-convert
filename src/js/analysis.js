// Analysis: duplicate detection, quality flags, merging, TOTP linking, password helpers.
// Pure functions over the item list. The UI decides when to apply any change.

import { hostOf, uniq, vaultOf, displayName } from './model.js';
import { isValidTotp, issuerOf } from './totp.js';

export const FLAG_LABEL = {
  'no-password': 'No password',
  'no-username': 'No username',
  'no-url': 'No website',
  weak: 'Weak password',
  reused: 'Reused password',
  'bad-totp': 'Invalid authenticator secret',
  'totp-only': 'Authenticator only',
  duplicate: 'Duplicate',
  conflict: 'Conflicting logins',
  empty: 'Empty item',
};

export const FLAG_HINT = {
  'no-password': 'Add a password, or generate one.',
  'no-username': 'Add the username or email used to sign in.',
  'no-url': 'Add the website so the login can be matched.',
  weak: 'Under 10 characters or only one kind of character.',
  reused: 'The same password is used by other items.',
  'bad-totp': 'The one-time code secret is not valid base32. Re-copy it from the site.',
  'totp-only': 'This is an authenticator with no login. Link it to a login.',
  duplicate: 'Same site, username and password as another item.',
  conflict: 'Same site and username but a different password.',
  empty: 'Nothing is filled in.',
};

/** Identity used to find exact duplicates. */
export function exactKey(it) {
  const host = hostOf(it.urls[0]);
  if (it.type === 'login') {
    const ident = host || it.name.toLowerCase();
    return ['login', ident, it.username.trim().toLowerCase(), it.password].join('\u0001');
  }
  return [it.type, it.name.trim().toLowerCase(), it.notes.trim()].join('\u0001');
}

export function findDuplicateGroups(items) {
  const exact = new Map();
  const sites = new Map();
  for (const it of items) {
    if (it.type === 'login') {
      const host = hostOf(it.urls[0]);
      if (!host && !it.username && !it.password) continue;
      const siteKey = [host || it.name.toLowerCase(), it.username.trim().toLowerCase()].join('\u0001');
      if (!sites.has(siteKey)) sites.set(siteKey, []);
      sites.get(siteKey).push(it);
    }
    const key = exactKey(it);
    if (!exact.has(key)) exact.set(key, []);
    exact.get(key).push(it);
  }
  const exactGroups = [...exact.values()].filter(
    (g) => g.length > 1 && (g[0].type !== 'login' || g[0].password || g[0].username),
  );
  const conflictGroups = [...sites.values()].filter((g) => g.length > 1 && new Set(g.map((i) => i.password)).size > 1);
  return {
    exact: exactGroups.map((g) => g.map((i) => i.id)),
    conflicts: conflictGroups.map((g) => g.map((i) => i.id)),
  };
}

export function passwordStrength(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 10) score++;
  if (pw.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (classes >= 3) score++;
  if (classes === 4 && pw.length >= 14) score++;
  return Math.min(score, 4);
}

/** Returns the quality flags for one item. `ctx` carries cross-item information. */
export function flagItem(it, ctx) {
  const out = [];
  const add = (code, level) => out.push({ code, level, label: FLAG_LABEL[code], hint: FLAG_HINT[code] });
  const hasUrl = it.urls.length > 0;

  if (it.type === 'login') {
    if (it.totp && !it.password && !it.username && !hasUrl) add('totp-only', 'info');
    else if (!it.password && !it.totp) add('no-password', 'warn');
    if (it.password && !it.username) add('no-username', 'info');
    if (!hasUrl && (it.password || it.username)) add('no-url', 'info');
    if (it.password && passwordStrength(it.password) < 2) add('weak', 'warn');
    if (it.password && (ctx.pwCount.get(it.password) || 0) > 1) add('reused', 'warn');
  }
  if (it.totp && !isValidTotp(it.totp)) add('bad-totp', 'error');
  if (ctx.dupeIds.has(it.id)) add('duplicate', 'warn');
  if (ctx.conflictIds.has(it.id)) add('conflict', 'warn');
  const hasData = it.username || it.password || it.totp || it.notes || hasUrl || it.customFields.length;
  if (!hasData) add('empty', 'info');
  return out;
}

export function analyse(items) {
  const pwCount = new Map();
  for (const it of items) if (it.password) pwCount.set(it.password, (pwCount.get(it.password) || 0) + 1);
  const dupes = findDuplicateGroups(items);
  const dupeIds = new Set(dupes.exact.flat());
  const conflictIds = new Set(dupes.conflicts.flat());
  const ctx = { pwCount, dupeIds, conflictIds };
  const flags = new Map();
  const totpOnly = new Set();
  for (const it of items) {
    const f = flagItem(it, ctx);
    flags.set(it.id, f);
    if (f.some((x) => x.code === 'totp-only')) totpOnly.add(it.id);
  }
  return { flags, dupes, dupeIds, conflictIds, totpOnly, pwCount };
}

/** Merges items into the first one. Blank fields are filled from the others, and
 *  conflicting values are kept as alternate custom fields instead of being lost. */
export function mergeGroup(group) {
  const base = structuredClone(group[0]);
  const altLabel = (o) => o.source && o.source !== 'manual' ? o.source : vaultOf(o);
  for (const o of group.slice(1)) {
    base.urls = uniq([...base.urls, ...o.urls]);
    if (!base.username && o.username) base.username = o.username;
    else if (o.username && o.username !== base.username) base.customFields.push({ name: `Alternate username (${altLabel(o)})`, value: o.username, hidden: false });
    if (!base.password && o.password) base.password = o.password;
    else if (o.password && o.password !== base.password) base.customFields.push({ name: `Alternate password (${altLabel(o)})`, value: o.password, hidden: true });
    if (!base.totp && o.totp) base.totp = o.totp;
    else if (o.totp && o.totp !== base.totp) base.customFields.push({ name: `Alternate one-time code (${altLabel(o)})`, value: o.totp, hidden: true });
    if (o.notes && !base.notes.includes(o.notes)) base.notes = [base.notes, o.notes].filter(Boolean).join('\n\n');
    for (const f of o.customFields) {
      if (!base.customFields.some((b) => b.name === f.name && b.value === f.value)) base.customFields.push({ ...f });
    }
    base.tags = uniq([...base.tags, ...o.tags]);
    base.favorite = base.favorite || o.favorite;
    if (!base.createdAt || (o.createdAt && o.createdAt < base.createdAt)) base.createdAt = o.createdAt || base.createdAt;
    if (!base.updatedAt || (o.updatedAt && o.updatedAt > base.updatedAt)) base.updatedAt = o.updatedAt || base.updatedAt;
  }
  return base;
}

/** The item to keep when removing duplicates: the most recently updated one. */
export function newestId(group) {
  return group.reduce((best, it) => ((it.updatedAt || it.createdAt || '') > (best.updatedAt || best.createdAt || '') ? it : best), group[0]).id;
}

/** Moves a one-time code from an authenticator-only item onto a login. Returns the login. */
export function linkTotp(login, source) {
  const next = structuredClone(login);
  if (!next.totp) next.totp = source.totp;
  else if (next.totp !== source.totp) next.customFields.push({ name: 'Alternate one-time code', value: source.totp, hidden: true });
  if (!next.urls.length && source.urls.length) next.urls = [...source.urls];
  next.updatedAt = new Date().toISOString();
  return next;
}

/** Login items that could take this authenticator, best match first. */
export function suggestTotpTargets(totpItem, items) {
  const issuer = issuerOf(totpItem.totp).toLowerCase();
  const host = hostOf(totpItem.urls[0]);
  const name = (totpItem.name || '').toLowerCase();
  return items
    .filter((it) => it.type === 'login' && it.id !== totpItem.id && !it.totp)
    .map((it) => {
      let score = 0;
      const h = hostOf(it.urls[0]);
      const n = displayName(it).toLowerCase();
      if (host && h && host === h) score += 5;
      if (issuer && (n.includes(issuer) || (h && h.includes(issuer)))) score += 3;
      if (name && (n === name || n.includes(name) || name.includes(n))) score += 2;
      return { item: it, score };
    })
    .sort((a, b) => b.score - a.score || displayName(a.item).localeCompare(displayName(b.item)));
}

/** Cryptographically random password using rejection sampling (no modulo bias). */
export function generatePassword({ length = 20, lower = true, upper = true, digits = true, symbols = true } = {}) {
  let pool = '';
  if (lower) pool += 'abcdefghijkmnopqrstuvwxyz';
  if (upper) pool += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  if (digits) pool += '23456789';
  if (symbols) pool += '!@#$%^&*()-_=+[]{};:,.?';
  if (!pool) return '';
  const max = 256 - (256 % pool.length);
  const out = [];
  while (out.length < length) {
    const byte = crypto.getRandomValues(new Uint8Array(1))[0];
    if (byte < max) out.push(pool[byte % pool.length]);
  }
  return out.join('');
}
