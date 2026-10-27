# Vault Convert

An offline, browser-only converter and editor for password manager exports.
Load an export from one manager, check and tidy it, then download it in the format another manager expects.

**Your data never leaves the page.** The built app is one HTML file. It has no server, no analytics, and no network
requests. Its Content-Security-Policy sets `connect-src 'none'`, so the browser blocks any outgoing request. You can verify this in DevTools → Network.

## Use it

1. Run `npm install && npm run build`.
2. Open `dist/vault-convert.html` in any modern browser. Double-clicking the file is enough.

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
| `Esc` | Close the detail panel |

## Formats

**Import:** Bitwarden (JSON, CSV), 1Password (1PUX, 1PIF, CSV), Proton Pass (CSV), Dashlane (CSV, JSON), LastPass (CSV),
KeePass 2 (XML, CSV), KeePassXC (CSV), Enpass (JSON, CSV), Monica (generic JSON or CSV), Apple Passwords (CSV),
Chrome / Edge / Google (CSV), Firefox (CSV), and any CSV with a header row.

**Export:** Vault Convert JSON (full fidelity), Generic CSV, Bitwarden JSON (unencrypted), Bitwarden CSV,
1Password 1PUX, KeePass 2 XML, KeePassXC CSV, Proton Pass CSV, LastPass CSV, Dashlane CSV, Apple Passwords CSV,
Chrome / Google / Edge CSV.

### What is verified

- **Verified by tests in this repo** (`npm test`): the TOTP RFC 6238 test vector, CSV quoting, the Bitwarden JSON
  import and export, the Proton Pass and Chrome CSV layouts, Enpass-style JSON, the 1PUX round trip through the built-in
  ZIP reader and writer, and the duplicate, merge, flag, and linking logic.
- **Verified in headless Chromium**: the full import → duplicate merge → edit → export flow, KeePass XML import,
  authenticator linking, undo, search, and the no-network check.
- **Not verified against real vendor exports.** The field layouts for each manager were written from documentation I
  know, not tested against files from each product. Real exports may differ in small ways, and the generic header matching
  should still catch most of that. Before relying on an export, import it into the target manager and check a few items.
  The **1Password 1PUX writer** is the least certain part, so test it first.

### Not supported (and why)

- **KeePass `.kdbx` databases** and **encrypted Bitwarden JSON** need the password and a key-derivation step. Export
  those unencrypted from the source manager first.
- **Passkeys** can't be exported as files by most managers, so they can't be converted here either.
- **Password-protected ZIP** files (Proton's encrypted export) can't be opened.

## Security notes

- Everything is held in memory on the page. Closing the tab discards it, and a warning appears if you try to close with unsaved items.
- Exported files contain passwords in **plain text**. Import them, then delete them.
- Copied passwords and one-time codes are removed from the clipboard after 30 seconds. If you copy something else in
  that window, that copy is cleared too.
- The page enforces a strict Content-Security-Policy with `connect-src 'none'`.

## Development

```
npm install
npm test          # unit tests (Node 22+)
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
src/js/app.js         UI controller
src/template.html     page shell
src/styles.css        design system (light and dark, compact and comfortable)
build.mjs             bundles everything into one HTML file with esbuild
tests/                Node test suite
```
