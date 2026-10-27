"""Independent implementation of Bitwarden's password-protected JSON export (cryptography + argon2-cffi).

usage:
  bw_check.py decrypt <file> <password>   -> prints the decrypted inner JSON
  bw_check.py encrypt <out> <password> <pbkdf2|argon2id> <inner-json-file>
"""
import base64
import hashlib
import hmac
import json
import os
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derive(password, j):
    salt = j["salt"]
    if j["kdfType"] == 0:
        master = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), j["kdfIterations"], 32)
    else:
        master = hash_secret_raw(
            password.encode(), hashlib.sha256(salt.encode()).digest(),
            time_cost=j["kdfIterations"], memory_cost=j["kdfMemory"] * 1024,
            parallelism=j["kdfParallelism"], hash_len=32, type=Type.ID,
        )
    expand = lambda info: hmac.new(master, info + b"\x01", hashlib.sha256).digest()
    return expand(b"enc"), expand(b"mac")


def decrypt(s, keys):
    kind, rest = s.split(".", 1)
    assert kind == "2", f"unexpected type {kind}"
    iv, ct, mac = (base64.b64decode(p) for p in rest.split("|"))
    good = hmac.new(keys[1], iv + ct, hashlib.sha256).digest()
    assert hmac.compare_digest(good, mac), "MAC mismatch"
    dec = Cipher(algorithms.AES(keys[0]), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unp = padding.PKCS7(128).unpadder()
    return (unp.update(padded) + unp.finalize()).decode()


def encrypt(plain, keys):
    iv = os.urandom(16)
    pad = padding.PKCS7(128).padder()
    data = pad.update(plain.encode()) + pad.finalize()
    enc = Cipher(algorithms.AES(keys[0]), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = hmac.new(keys[1], iv + ct, hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return f"2.{b(iv)}|{b(ct)}|{b(mac)}"


if sys.argv[1] == "decrypt":
    j = json.load(open(sys.argv[2]))
    keys = derive(sys.argv[3], j)
    decrypt(j["encKeyValidation_DO_NOT_EDIT"], keys)
    print(decrypt(j["data"], keys))
else:
    _, _, out, password, kdf, inner = sys.argv
    j = {"encrypted": True, "passwordProtected": True,
         "salt": base64.b64encode(os.urandom(16)).decode()}
    if kdf == "pbkdf2":
        j.update(kdfType=0, kdfIterations=100000, kdfMemory=None, kdfParallelism=None)
    else:
        j.update(kdfType=1, kdfIterations=2, kdfMemory=16, kdfParallelism=2)
    keys = derive(password, j)
    j["encKeyValidation_DO_NOT_EDIT"] = encrypt("validation-string", keys)
    j["data"] = encrypt(open(inner).read(), keys)
    json.dump(j, open(out, "w"))
