// Shared item model and small helpers. Pure functions: no DOM, no network.

export const TYPES = ['login', 'note', 'card', 'identity'];
export const TYPE_LABEL = { login: 'Login', note: 'Secure note', card: 'Card', identity: 'Identity' };
export const TYPE_GLYPH = { login: '◍', note: '✎', card: '▭', identity: '◉' };
export const DEFAULT_VAULT = 'Personal';

export function uid() {
  if (globalThis.crypto?.randomUUID) return crypto.randomUUID();
  return 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

/** Creates a fresh item. Every field exists so the rest of the app can rely on its shape. */
export function newItem(partial = {}) {
  return {
    id: uid(),
    type: 'login',
    name: '',
    username: '',
    password: '',
    urls: [],
    totp: '',
    notes: '',
    vault: DEFAULT_VAULT,
    folder: '',
    favorite: false,
    tags: [],
    customFields: [], // { name, value, hidden }
    createdAt: null,
    updatedAt: null,
    source: 'manual',
    ...partial,
  };
}

export const clone = (value) => structuredClone(value);

/** Accepts ISO strings, Date-parsable strings, or unix seconds/milliseconds. Returns ISO or null. */
export function toIso(value) {
  if (value === undefined || value === null || value === '') return null;
  let d;
  const text = String(value).trim();
  if (/^\d{9,13}$/.test(text)) {
    const n = Number(text);
    d = new Date(n < 1e11 ? n * 1000 : n);
  } else {
    d = new Date(text);
  }
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Host name without "www.", lower-cased. Returns '' when the value is not URL-like. */
export function hostOf(url) {
  let s = String(url || '').trim();
  if (!s) return '';
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  try {
    return new URL(s).hostname.replace(/^(www|m)\./i, '').toLowerCase();
  } catch {
    return '';
  }
}

export function splitUrls(value) {
  const text = Array.isArray(value) ? value.join('\n') : String(value || '');
  return text.split(/[\n\r;]+/).map((s) => s.trim()).filter(Boolean);
}

export const uniq = (list) => [...new Set(list.filter((v) => v !== undefined && v !== null && v !== ''))];

export const vaultOf = (item) => item.vault || DEFAULT_VAULT;

export function folderPath(item) {
  return [vaultOf(item), item.folder].filter(Boolean).join(' / ');
}

export function displayName(item) {
  return item.name || hostOf(item.urls[0]) || item.username || 'Untitled';
}
