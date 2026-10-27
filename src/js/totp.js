// TOTP (RFC 6238) helpers using the browser's Web Crypto API. Works fully offline.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGO = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export const cleanSecret = (s) => String(s || '').toUpperCase().replace(/[\s\-=]/g, '');

/** Accepts a bare base32 secret or an otpauth:// URI. Returns null when empty. */
export function parseTotpInput(input) {
  const raw = String(input || '').trim();
  if (!raw) return null;
  if (/^otpauth:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const params = u.searchParams;
      return {
        secret: cleanSecret(params.get('secret')),
        digits: Number(params.get('digits')) || 6,
        period: Number(params.get('period')) || 30,
        algorithm: (params.get('algorithm') || 'SHA1').toUpperCase(),
        issuer: params.get('issuer') || '',
        label: decodeURIComponent(u.pathname.replace(/^\/+/, '')),
        uri: raw,
      };
    } catch {
      return { secret: '', digits: 6, period: 30, algorithm: 'SHA1', issuer: '', label: '', uri: raw };
    }
  }
  return { secret: cleanSecret(raw), digits: 6, period: 30, algorithm: 'SHA1', issuer: '', label: '', uri: '' };
}

export function isValidTotp(input) {
  const p = parseTotpInput(input);
  return !!p && p.secret.length >= 8 && /^[A-Z2-7]+$/.test(p.secret);
}

export function base32ToBytes(secret) {
  const s = cleanSecret(secret);
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32 character');
    value = ((value << 5) | idx) & 0xffffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Returns the current code, or null if the input is not a usable secret. */
export async function totpCode(input, now = Date.now()) {
  const p = parseTotpInput(input);
  if (!p || !isValidTotp(input)) return null;
  const counter = Math.floor(now / 1000 / p.period);
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey(
    'raw',
    base32ToBytes(p.secret),
    { name: 'HMAC', hash: ALGO[p.algorithm] || 'SHA-1' },
    false,
    ['sign'],
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[off] & 0x7f) << 24 | sig[off + 1] << 16 | sig[off + 2] << 8 | sig[off + 3]) >>> 0;
  return String(bin % 10 ** p.digits).padStart(p.digits, '0');
}

export function secondsLeft(period = 30, now = Date.now()) {
  return period - (Math.floor(now / 1000) % period);
}

/** Builds a standard otpauth URI so that exports keep the issuer and label. */
export function toOtpauthUri(input, label = '', issuer = '') {
  const p = parseTotpInput(input);
  if (!p || !isValidTotp(input)) return String(input || '');
  if (p.uri) return p.uri;
  const q = new URLSearchParams({
    secret: p.secret,
    algorithm: p.algorithm,
    digits: String(p.digits),
    period: String(p.period),
  });
  if (issuer) q.set('issuer', issuer);
  return `otpauth://totp/${encodeURIComponent(label || issuer || 'account')}?${q.toString()}`;
}

export function issuerOf(input) {
  const p = parseTotpInput(input);
  return p ? p.issuer || p.label : '';
}
