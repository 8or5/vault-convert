#!/usr/bin/env bash
# Browser checks in headless Chromium. Needs: npm run build, python3 playwright, pip install pykeepass.
set -euo pipefail
cd "$(dirname "$0")"
export VC_TMP="${VC_TMP:-/tmp/vc-browser}"
mkdir -p "$VC_TMP"
node mk.mjs "$VC_TMP/test.kdbx"
node mkbw.mjs "$VC_TMP/bw-enc.json"
for t in ui1 ui2 ui3 ui4; do echo "== $t"; python3 $t.py; done
python3 - <<PY
from pykeepass import PyKeePass
import os
S=os.environ["VC_TMP"]
for f,pw in [("saved.kdbx","hunter2 pw"),("exported.kdbx","exp pass")]:
    print(f,[(e.title,e.username) for e in PyKeePass(S+"/"+f,password=pw).entries])
PY
