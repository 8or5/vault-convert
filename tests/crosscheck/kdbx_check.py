"""Independent KDBX check using pykeepass (separate implementation from kdbxweb).

usage: kdbx_check.py <dir>
  reads  <dir>/js-made.kdbx  (password "correct horse"), prints a JSON summary
  writes <dir>/py-made.kdbx  (password "py pass") for the JS side to open
"""
import json
import sys
from pykeepass import PyKeePass, create_database

d = sys.argv[1]

kp = PyKeePass(f"{d}/js-made.kdbx", password="correct horse")
summary = {
    "version": list(kp.version),
    "kdf": kp.kdf_algorithm,
    "cipher": kp.encryption_algorithm,
    "entries": [],
}
for e in kp.entries:
    summary["entries"].append({
        "title": e.title,
        "username": e.username,
        "password": e.password,
        "url": e.url,
        "notes": e.notes,
        # kdbxweb separates tags with ", ". KeePass and KeePassXC trim that; pykeepass keeps the space.
        "tags": sorted(t.strip() for t in (e.tags or [])),
        "group": [g for g in e.group.path if g] if isinstance(e.group.path, list) else [p for p in str(e.group.path).split("/") if p],
        "custom": dict(e.custom_properties),
        "otp": e.otp,
        "attachments": {a.filename: a.data.decode("utf8", "replace") for a in e.attachments},
    })
print(json.dumps(summary))

# Now write a database with another implementation for the JS side to read.
out = create_database(f"{d}/py-made.kdbx", password="py pass")
root = out.root_group
work = out.add_group(root, "Work")
ci = out.add_group(work, "CI")
e = out.add_entry(ci, "Runner", "robot", "r0b0t-pass", url="https://ci.example.com", notes="made by pykeepass", tags=["ci", "Favorite"])
e.set_custom_property("API token", "tok_123", protect=True)
e.set_custom_property("Region", "eu", protect=False)
e.otp = "otpauth://totp/Runner?secret=JBSWY3DPEHPK3PXP&issuer=CI"
att = out.add_binary(b"hello from python")
e.add_attachment(att, "note.txt")
out.add_entry(root, "Top-level", "u", "p")
out.save()
