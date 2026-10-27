# Vault Convert

An offline, browser-only password manager for **KeePass `.kdbx` databases**, and a converter for everything else.
Open a KeePass file and use it directly (view, edit, copy, save back, lock). Or load an export from any other manager,
tidy it, and download it in the format another manager expects, including encrypted KDBX and encrypted Bitwarden JSON.

**Your data never leaves the page.** The built app is one HTML file. It has no server, no analytics, and no network
requests. Its Content-Security-Policy sets `connect-src 'none'`, so the browser blocks any outgoing request. You can verify this in DevTools → Network.

## Use it

1. Run `npm install && npm run build`.
2. Open `dist/vault-convert.html` in any modern browser. Double-clicking the file is enough.

## As a KeePass client

- **Open** a `.kdbx` (KDBX 3 or 4, password and/or key file) or **create** a new KDBX 4 database. Argon2d, Argon2id and AES-KDF are supported, and Argon2 runs in WebAssembly.
- **Save back to the same file** in Chromium browsers (File System Access API). Other browsers download the file instead. If the file changed on disk since you opened it, Save offers to **merge** rather than overwrite.
- **Lock** (button, Ctrl+L, or after inactivity). Locking removes the items from the page. Unsaved changes are kept, encrypted, and return after you unlock.
- **Recycle bin**, **entry history** (old passwords are kept and shown), **attachments**, custom fields, tags, favourites, and moving between groups.
- **Change the master password**, **encryption strength**, rename, download an encrypted backup, or **merge** another `.kdbx` into the open one.
- Optional **auto-save** (needs a database opened with Save in place).

### Click to copy everything

In the item panel, every row is a button: click a username, password, one-time code, website, note, custom field, tag, or an old password to copy it. **Copy all** copies the whole item as text. In the table, hover a row for quick buttons (username, password, code, fill). Press `U`, `P` or `T` with an item open. The clipboard clears itself (30 s by default; configurable).

### Fill logins without an extension

Click **Autofill** for setup. Two parts, neither installs anything:

1. **Vault Fill bookmark.** Drag it to your bookmarks bar once. Click **Fill** on a login here, open the site's login page, click the bookmark. It fills username, password and code, and handles two-step logins (click it again on the second page). It checks that the page's site matches the login's website and asks first if not, or if the page isn't HTTPS.
2. **Floating assistant window.** A small always-on-top window (Picture-in-Picture where the browser supports it, otherwise a pop-up) with a search box and one-click copy buttons, for sites that block bookmarks.

Limits, stated plainly:

- The fill data is one encoded line on your clipboard for up to 90 seconds, and is cleared once used. Other programs that read the clipboard could see it in that window.
- Your browser may ask to allow clipboard reading for the page you click the bookmark on.
- Sites with a strict Content Security Policy can block bookmarks. Use the assistant there.
- A web page cannot type into other applications, so there is no desktop "auto-type".

See [docs/RESEARCH.md](docs/RESEARCH.md) for how this compares with Proton Pass and KeeWeb, including what it cannot do.

## As a converter

## What it does

- **Import** several files at once. The format is detected from the file contents, and unknown layouts are read by
  matching column or field names. Columns that aren't recognised are kept as custom fields, so nothing is silently dropped.
- **Edit** items in a table with a detail panel: name, type, vault, folder, username, password, website(s), one-time code,
  notes, tags, favourite, and custom fields. Hidden values can be shown or hidden.
- **Organise**: separate vaults, folders inside vaults, favourites, search, sorting, item-type filters, and bulk move,
  favourite, merge, delete, and export.
- **Check**: each item is flagged for missing passwords or usernames, missing websites, weak or reused passwords,
  invalid one-time-code secrets, empty items, duplicates, and conflicting logins.
- **Duplicates**: find exact duplicates and conflicting logins (same site and username, different password). Merge them,
  or keep only the newest. Merging never discards data. When two values disagree, the second one is saved as an
  "Alternate … (source)" custom field.
- **Authenticators**: attach a one-time code to a login. Standalone codes get ranked suggestions for the login they belong to.
  Codes are generated live in the browser with Web Crypto (RFC 6238).
- **Export** to any supported format from a popup. It shows how many items are included, which types a format can't
  hold, and what data it can't represent.
- **Undo** every change (Ctrl/Cmd+Z), up to the last 60 changes.
- **Preferences**: theme (system, light, dark), density, which table columns show, and whether passwords start hidden.
  Only these display settings are saved in the browser. Items are never stored.

### Keyboard

| Key | Action |
|---|---|
| `/` | Search |
| `N` | New item |
| `Ctrl/Cmd+Z` | Undo |
| `Ctrl/Cmd+E` | Export |
| `Ctrl/Cmd+S` | Save the KeePass database |
| `Ctrl/Cmd+L` | Lock |
| `U` `P` `T` | Copy username, password, one-time code of the open item |
| `Esc` | Close the detail panel |

## Formats

**Import:** KeePass `.kdbx`, Bitwarden (JSON, CSV, password-protected JSON), 1Password (1PUX, 1PIF, CSV), Proton Pass (CSV), Dashlane (CSV, JSON), LastPass (CSV),
KeePass 2 (XML, CSV), KeePassXC (CSV), Enpass (JSON, CSV), Monica (generic JSON or CSV), Apple Passwords (CSV),
Chrome / Edge / Google (CSV), Firefox (CSV), and any CSV with a header row.

**Export:** KeePass `.kdbx` (encrypted), Bitwarden password-protected JSON (encrypted), Vault Convert JSON (full fidelity), Generic CSV, Bitwarden JSON (unencrypted), Bitwarden CSV,
1Password 1PUX, KeePass 2 XML, KeePassXC CSV, Proton Pass CSV, LastPass CSV, Dashlane CSV, Apple Passwords CSV,
Chrome / Google / Edge CSV.

### KeePass mapping notes

- Top-level groups become **vaults**; nested groups become **folders** joined with ` / `. Entries in the root group go to a vault named after the root.
- Favourite is stored as the tag `Favorite`. Non-login types (note, card, identity) are stored in a custom-data entry, so other KeePass apps show them as ordinary entries.
- One-time codes are stored in the `otp` field as an `otpauth://` URI (KeePassXC style). The older KeePassXC `key=` and `TimeOtp-*` fields are read.
- Extra websites go in `KP2A_URL`, `KP2A_URL_1`, … Attachments are kept only in KDBX and Vault Convert JSON.
- Tags are written separated by `, `. KeePass and KeePassXC trim them; some libraries (pykeepass) don't.

### What is verified

- **Unit tests** (`npm test`): TOTP vector, CSV, Bitwarden JSON, Proton Pass and Chrome CSV, Enpass JSON, 1PUX round trip, duplicate / merge / flag / linking logic, KDBX round trips (v3 and v4, Argon2, key files, attachments, history, recycle bin, merge), and Bitwarden encrypted export round trips.
- **Cross-checked against independent implementations** (`npm run crosscheck`; needs `pip install pykeepass cryptography argon2-cffi`): databases written here open in pykeepass with the right contents, and Bitwarden encrypted files written here decrypt in a separate Python implementation, and vice versa.
- **Headless Chromium** (`bash tests/browser/run.sh`, not part of `npm test`; needs python playwright and pykeepass): open a `.kdbx` with a wrong then right password; click-to-copy of password, username and live one-time code; edit and save (download path), re-checked with pykeepass; lock leaves no items in the page; unlock restores unsaved changes; recycle bin; encrypted KDBX and Bitwarden export from the popup; encrypted Bitwarden import prompt; the bookmark on mock login pages (matching site, two-step, host mismatch, expired, empty clipboard, one-time code); the assistant pop-up window; no network requests and no console errors.
- **Not verified:**
  - Save in place (File System Access) can't be driven by headless automation. It is implemented with a download fallback, but I haven't watched it write to a real file.
  - The Picture-in-Picture assistant (only the pop-up fallback was exercised).
  - Bitwarden encrypted files were checked against a separate implementation of the documented format, **not against a file produced by Bitwarden itself**. Test with a small real export first.
  - The field layouts for other managers were written from documentation, not real vendor exports. The **1Password 1PUX writer** is the least certain part.
  - Large databases (thousands of entries) and slow devices with the "Strong" encryption setting.

### Not supported (and why)

- **Bitwarden account-restricted exports** are encrypted to your account key and can't be opened outside Bitwarden. Use the password-protected option there.
- **Passkeys** can't be exported as files by most managers, so they can't be converted here either.
- **Password-protected ZIP** files (Proton's encrypted export) can't be opened.
- Sync, sharing, mobile apps, breach lookups, and true desktop auto-type, which need a server or native apps.

## Security notes

- Everything is held in memory on the page. Closing the tab discards it, and a warning appears if you try to close with unsaved items.
- Exported files contain passwords in **plain text**. Import them, then delete them.
- Copied values are cleared from the clipboard after a delay (30 s by default). A newer copy cancels the older timer.
- The page enforces a strict Content-Security-Policy with `connect-src 'none'`. The only relaxation is `'wasm-unsafe-eval'`, needed to run Argon2 in WebAssembly.
- A web page can't wipe memory. **Lock** drops every reference to your data and keeps only the encrypted file bytes, but it can't promise the browser has overwritten the old memory. Close the tab on a shared machine.
- The master password and decrypted entries exist in page memory while a database is unlocked.

## Development

```
npm install
npm test          # unit tests (Node 22+)
npm run crosscheck  # compare with pykeepass / Python crypto (see above)
npm run build     # writes dist/vault-convert.html
```

Layout:

```
src/js/model.js       item model and helpers
src/js/totp.js        RFC 6238 one-time codes, otpauth URIs
src/js/csv.js         CSV reader and writer
src/js/zip.js         ZIP reader (deflate via DecompressionStream) and writer (stored)
src/js/importers.js   format detection and mapping to the item model
src/js/exporters.js   export formats, with per-format notes on what they can't hold
src/js/analysis.js    flags, duplicates, merging, authenticator linking, password generator
src/js/kdbx.js        KeePass database engine (kdbxweb) and mapping to items
src/js/bwcrypto.js    Bitwarden password-protected export crypto
src/js/argon2.js      Argon2 in WebAssembly (hash-wasm)
src/js/session.js     open, save, lock, merge, settings for the open database
src/js/autofill.js    fill bookmark and assistant window
src/js/copyfields.js  what each clickable field copies
src/js/state.js       shared state, undo, selectors
src/js/views.js       rendering
src/js/ui/            dom, clipboard, file access, dialogs, icons
src/js/app.js         controller (events and actions)
src/template.html     page shell
src/styles.css        design system (light and dark, compact and comfortable)
build.mjs             bundles everything into one HTML file with esbuild
tests/                Node test suite
```
