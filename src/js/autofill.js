// Extensionless autofill.
//
// A web page can't type into other apps or other tabs (that needs an extension or OS-level
// permissions), so this works in two complementary ways:
//
//  1. Fill bookmarklet. The app copies a short-lived "fill packet" to the clipboard. The user
//     clicks a bookmark on the login page, which reads the packet, checks that the page's domain
//     matches the login, fills the form, and clears the clipboard. The bookmark itself holds no secrets.
//  2. Fill assistant. A small always-on-top window (Document Picture-in-Picture where the browser
//     has it, otherwise a popup) with one-click copy buttons that stays above the login page.

import { hostOf, uniq } from './model.js';

export const PACKET_PREFIX = 'VCFILL1.';
export const PACKET_TTL_MS = 90_000;

export const hostsOfItem = (item) => uniq((item.urls || []).map(hostOf).filter(Boolean));

function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Builds the clipboard text the bookmarklet understands. */
export function makePacket(item, totpCode = '', now = Date.now()) {
  const payload = { h: hostsOfItem(item), u: item.username || '', p: item.password || '', t: totpCode || '', ts: now };
  return PACKET_PREFIX + b64url(new TextEncoder().encode(JSON.stringify(payload)));
}

/** Same decoding the bookmarklet does. Returns null for anything that isn't a valid packet. */
export function parsePacket(text) {
  if (!text || !text.startsWith(PACKET_PREFIX)) return null;
  try {
    const b = text.slice(PACKET_PREFIX.length).replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b), (c) => c.charCodeAt(0))));
  } catch {
    return null;
  }
}

/**
 * The bookmarklet. It runs inside the login page, so it must be completely self-contained:
 * no imports and no references to anything outside this function. Its source text is what
 * gets placed in the bookmark, which is why it is written as one plain function.
 */
export function vaultFill() {
  const PREFIX = 'VCFILL1.';
  const TTL = 90000;
  const say = (msg, bad) => {
    const d = document.createElement('div');
    d.textContent = msg;
    d.setAttribute('role', 'status');
    d.style.cssText = 'position:fixed;z-index:2147483647;top:16px;right:16px;max-width:340px;padding:12px 14px;border-radius:10px;font:14px/1.4 system-ui,sans-serif;color:#fff;box-shadow:0 8px 24px rgba(0,0,0,.3);background:' + (bad ? '#b91c1c' : '#0f766e');
    document.documentElement.appendChild(d);
    setTimeout(() => d.remove(), bad ? 7000 : 3500);
  };
  (async () => {
    let raw;
    try {
      raw = await navigator.clipboard.readText();
    } catch (e) {
      say('Vault Fill: the browser did not allow reading the clipboard. Allow it, then click the bookmark again.', true);
      return;
    }
    if (!raw || raw.indexOf(PREFIX) !== 0) {
      say('Vault Fill: nothing to fill. In Vault Convert, click Fill on a login, then click this bookmark.', true);
      return;
    }
    let p;
    try {
      const b = raw.slice(PREFIX.length).replace(/-/g, '+').replace(/_/g, '/');
      p = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b), (c) => c.charCodeAt(0))));
    } catch (e) {
      say('Vault Fill: the copied data is damaged. Click Fill in Vault Convert again.', true);
      return;
    }
    if (!p || Date.now() - p.ts > TTL) {
      say('Vault Fill: that fill data has expired. Click Fill in Vault Convert again.', true);
      return;
    }
    const host = location.hostname.replace(/^www\./, '').toLowerCase();
    const hosts = p.h || [];
    const match = hosts.some((h) => host === h || host.endsWith('.' + h));
    if (!match && !confirm('This page (' + host + ') does not match this login (' + (hosts.join(', ') || 'no website saved') + ').\n\nFill it anyway? Only continue if you are sure this is the right site.')) return;
    if (location.protocol !== 'https:' && host !== 'localhost' && !confirm('This page is not using HTTPS, so what you fill in can be read on the network. Fill anyway?')) return;

    const visible = (el) => {
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
    };
    const inputs = [].slice.call(document.querySelectorAll('input')).filter(visible);
    const typeOf = (i) => (i.getAttribute('type') || 'text').toLowerCase();
    const pwField = inputs.find((i) => typeOf(i) === 'password');
    const textish = inputs.filter((i) => ['text', 'email', 'tel'].indexOf(typeOf(i)) >= 0);
    const hint = (i) => (i.name + ' ' + i.id + ' ' + (i.autocomplete || '') + ' ' + (i.placeholder || '') + ' ' + (i.getAttribute('aria-label') || '')).toLowerCase();
    const isCode = (i) => /one-time-code/.test(i.autocomplete || '') || /otp|totp|2fa|mfa|verif|authenticator|passcode/.test(hint(i));
    const userScore = (i) => {
      const h = hint(i);
      let n = 0;
      if (/username|email/.test(i.autocomplete || '')) n += 5;
      if (/user|login|email|mail|account|identifier/.test(h)) n += 3;
      if (/search|query|zip|postal|phone|captcha|coupon/.test(h)) n -= 4;
      if (isCode(i)) n -= 6;
      return n;
    };
    const before = pwField ? textish.filter((i) => i.compareDocumentPosition(pwField) & Node.DOCUMENT_POSITION_FOLLOWING) : textish;
    let user = null;
    let best = -Infinity;
    before.forEach((i) => {
      const s = userScore(i);
      if (s >= best && s > -4) {
        best = s;
        user = i; // on ties, the field closest to the password wins
      }
    });
    const codeField = p.t ? inputs.find((i) => i !== pwField && i !== user && isCode(i)) : null;

    const set = (el, v) => {
      el.focus();
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };
    let did = '';
    if (user && p.u) {
      set(user, p.u);
      did += 'username ';
    }
    if (pwField && p.p) {
      set(pwField, p.p);
      did += 'password ';
    }
    if (codeField) {
      set(codeField, p.t);
      did += 'code ';
    }
    if (!did) {
      say('Vault Fill: could not find a sign-in form here. If the site asks for something first, continue, then click the bookmark again.', true);
      return;
    }
    if (pwField || codeField) {
      try { await navigator.clipboard.writeText(''); } catch (e) { /* clipboard cleared by the app later */ }
      say('Vault Fill: filled ' + did.trim().replace(/ /g, ', ') + '. Clipboard cleared.');
    } else {
      say('Vault Fill: filled the username. Continue to the next step, then click the bookmark again for the password.');
    }
  })();
}

/** The javascript: URL to put in a bookmark. */
export const bookmarkletHref = () => 'javascript:' + encodeURIComponent('(' + vaultFill.toString() + ')()');

// ---------- Fill assistant window ----------

let assistWin = null;

export const assistSupport = () => ({
  pip: typeof window !== 'undefined' && 'documentPictureInPicture' in window,
});

/**
 * Opens (or focuses) the floating assistant and returns its window, or null if the browser blocked it.
 * Must be called from a click handler (browsers require a user gesture for both kinds of window).
 */
export async function openAssistWindow() {
  if (assistWin && !assistWin.closed) {
    assistWin.focus?.();
    return assistWin;
  }
  let win = null;
  if ('documentPictureInPicture' in window) {
    try {
      win = await window.documentPictureInPicture.requestWindow({ width: 380, height: 560 });
    } catch { win = null; }
  }
  if (!win) win = window.open('', 'vault-fill-assistant', 'popup=yes,width=400,height=620');
  if (!win) return null;

  win.document.title = 'Vault Fill assistant';
  win.document.documentElement.setAttribute('data-theme', document.documentElement.getAttribute('data-theme') || 'system');
  for (const sheet of document.querySelectorAll('style')) {
    const copy = win.document.createElement('style');
    copy.textContent = sheet.textContent;
    win.document.head.appendChild(copy);
  }
  win.document.body.innerHTML = '<div id="assist" class="assist"></div>';
  assistWin = win;
  win.addEventListener('pagehide', () => { if (assistWin === win) assistWin = null; });
  return win;
}

export function closeAssistWindow() {
  try { assistWin?.close(); } catch { /* already closed */ }
  assistWin = null;
}

export const currentAssistWindow = () => (assistWin && !assistWin.closed ? assistWin : null);
