# Research: Proton Pass and KeeWeb, and where Vault Convert fits

Gathered 27 Oct 2026 from the vendors' own pages (linked below). Anything I could not confirm from those pages is marked as such. This is a feature comparison, not a security audit of any product.

## What Proton Pass is

A cloud-synced password manager with an account, browser extensions, mobile and desktop apps, built around end-to-end encrypted vaults.

From Proton's [roadmap post](https://proton.me/blog/proton-pass-roadmap-winter-spring) (the post is from 2024, so treat its "planned" list as dated):

- Shipped then: passkeys, Pass Monitor (dark-web monitoring, password health, inactive-2FA reminders), secure links and vault sharing, Mac and Linux apps, Safari extension, identities, biometric login on desktop apps, clipboard auto-clear, drag-and-drop between vaults, business admin features.
- Planned then: file attachments, emergency access, custom item types, auto-type for desktop apps, SSO.

From Proton's [autotype support page](https://proton.me/support/pass-autotype):

- Autotype fills username and password fields in **desktop apps**. It needs a paid plan, and on macOS and Linux a one-time permission (accessibility access on macOS, a remote-interaction toggle on Linux). The page does not mention Windows.

The "extension-less autofill" Proton offers is therefore a **desktop-app feature that types keystrokes into other applications**. A web page cannot do that, whatever it does.

## What KeeWeb is

A KeePass client that runs as a single HTML file or a desktop app ([repository](https://github.com/keeweb/keeweb)).

- Opens and creates `.kdbx` databases.
- Storage: local file, Dropbox, Google Drive, OneDrive.
- Can be self-hosted.
- The repository page I could read shows no last-commit or release date, and 433 open issues. I could not confirm its current maintenance status from that page, so check the repository yourself before relying on it.
- The page I read does not describe autotype, and says nothing about converting other managers' exports.

## Where Vault Convert is deliberately different

| Area | Proton Pass | KeeWeb | Vault Convert |
| --- | --- | --- | --- |
| Account needed | Yes | No | No |
| Network | Cloud sync | Optional cloud storage | None. A CSP blocks every request, so the page *cannot* call out |
| Opens KeePass `.kdbx` | No (imports only) | Yes | Yes, KDBX 3 and 4, password and/or key file |
| Saves back to the same file | n/a | Yes | Yes where the browser allows (Chromium); otherwise a download |
| Conflict handling | Sync | Sync via storage | Detects that the file changed on disk, then merges instead of overwriting |
| Convert between managers | Import only | Not in what I read | Imports 14+ formats, exports 14, including encrypted KDBX and encrypted Bitwarden |
| Duplicate / merge / link TOTP to login / flag weak or old | Health monitoring | Not confirmed | Built in, offline |
| Click to copy every field | Per field | Per field | Every row, plus Copy all, plus `u` `p` `t` shortcuts |
| Auto-clearing clipboard | Yes | Not confirmed | Yes, configurable |
| Fill without an extension | Desktop autotype (paid, OS permission) | Not confirmed | Bookmark plus floating assistant, see limits below |
| Password history, recycle bin | Not confirmed | Yes (KeePass features) | Yes |
| Passkeys, breach monitoring, sharing, mobile apps | Yes | No | **No.** These need a server or native apps |

## Honest position

"Much better" depends on what you need.

**Where this is stronger:**

- No account and no network. The guarantee is enforced by the page's security policy, not by a promise.
- One tool both manages a `.kdbx` and moves data between managers.
- Safe handling of file-based vaults: unsaved changes survive a lock, and an externally changed file is merged rather than overwritten.

**Where it is weaker, and always will be as a single offline page:**

- No sync, no mobile app, no sharing, no breach database lookups, no passkey provider.
- No true auto-type into other applications, and no real in-page autofill without an extension.
- JavaScript cannot wipe memory, so "Lock" removes references rather than guaranteeing the secrets are erased.

## The autofill trade-off, plainly

Without an extension or a native helper, a web page can't reach into another site. The workable design is:

1. A **bookmark** you add once. When clicked on a login page, it reads a short-lived fill packet from the clipboard and fills the form on that page.
2. A **floating assistant window** for one-click copy of user, password or code when a site blocks bookmarks.

Costs: the packet is on the clipboard for up to 90 seconds (it is cleared once used), the browser may ask to allow clipboard reading, and sites with a strict Content Security Policy can block bookmarks. The bookmark checks that the page's site matches the login's website and asks first when it doesn't.

## Sources

- Proton Pass roadmap: https://proton.me/blog/proton-pass-roadmap-winter-spring
- Proton Pass autotype: https://proton.me/support/pass-autotype
- KeeWeb: https://github.com/keeweb/keeweb
