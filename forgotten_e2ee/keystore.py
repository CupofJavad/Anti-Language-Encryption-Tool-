import json, os
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from .crypto_core import (
    ed25519_keypair, x25519_keypair, scrypt_key, aead_encrypt, aead_decrypt,
    raw_pub_bytes_ed, raw_pub_bytes_x, raw_priv_bytes_ed, raw_priv_bytes_x, sha256_hex
)
from .util import b64u_enc, b64u_dec, hex24
from .transparency import publish_identity

KEYFILE_VERSION = 1

@dataclass
class Identity:
    ed_priv: ed25519.Ed25519PrivateKey
    x_priv: x25519.X25519PrivateKey

    def ed_pub(self): return self.ed_priv.public_key()
    def x_pub(self):  return self.x_priv.public_key()

    def fingerprint(self) -> str:
        blob = raw_pub_bytes_ed(self.ed_pub()) + raw_pub_bytes_x(self.x_pub())
        return hex24(bytes.fromhex(sha256_hex(blob)))

def save_public(path_pub: str, ed_pub, x_pub, name: str):
    pub = raw_pub_bytes_ed(ed_pub)
    dhp = raw_pub_bytes_x(x_pub)
    bundle = {
        "version": KEYFILE_VERSION,
        "type": "fg-public",
        "name": name,
        "ed25519_pub": b64u_enc(pub),
        "x25519_pub": b64u_enc(dhp),
        "fingerprint": hex24(bytes.fromhex(sha256_hex(pub + dhp))),
    }
    with open(path_pub, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    publish_identity(bundle["fingerprint"], bundle["ed25519_pub"], bundle["x25519_pub"], None)

def save_secret(path_sec: str, ident: Identity, passphrase: str | None):
    ed_raw = raw_priv_bytes_ed(ident.ed_priv)
    x_raw = raw_priv_bytes_x(ident.x_priv)
    if passphrase:
        salt = os.urandom(16)
        key = scrypt_key(passphrase, salt, 32)
        nonce = os.urandom(12)
        ct = aead_encrypt(key, nonce, b"fg-sec", b"ED"+ed_raw+b"XK"+x_raw)
        payload = {"enc":"scrypt+chacha20", "salt":b64u_enc(salt), "nonce":b64u_enc(nonce), "ct":b64u_enc(ct)}
    else:
        payload = {"enc":"raw","ed":b64u_enc(ed_raw),"xk":b64u_enc(x_raw)}
    bundle = {"version": KEYFILE_VERSION, "type":"fg-secret", "payload":payload}
    with open(path_sec, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

def load_public(path_pub: str):
    with open(path_pub, "r", encoding="utf-8") as f:
        b = json.load(f)
    ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(b["ed25519_pub"]))
    x_pub = x25519.X25519PublicKey.from_public_bytes(b64u_dec(b["x25519_pub"]))
    return ed_pub, x_pub, b.get("fingerprint",""), b

def load_secret(path_sec: str, passphrase: str | None) -> Identity:
    with open(path_sec, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    p = bundle["payload"]
    if p["enc"] == "raw":
        ed_raw = b64u_dec(p["ed"])
        x_raw  = b64u_dec(p["xk"])
    else:
        salt = b64u_dec(p["salt"]); nonce = b64u_dec(p["nonce"]); ct = b64u_dec(p["ct"])
        if not passphrase:
            raise ValueError("Passphrase required")
        key = scrypt_key(passphrase, salt, 32)
        pt = aead_decrypt(key, nonce, b"fg-sec", ct)
        if not (pt.startswith(b"ED") and b"XK" in pt):
            raise ValueError("Corrupt keyfile")
        ed_raw = pt[2:34]
        x_raw  = pt[36:68]
    return Identity(
        ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed_raw),
        x_priv  = x25519.X25519PrivateKey.from_private_bytes(x_raw)
    )
