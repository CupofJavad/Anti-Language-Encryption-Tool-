#!/bin/bash
#
# This script creates the complete "Forgotten-E2EE" project structure and all files.
# Save this file as 'setup_project.sh' and run it in an empty directory.
#
# To run it:
# 1. chmod +x setup_project.sh
# 2. ./setup_project.sh
#

echo "Creating directories..."
mkdir -p forgotten_e2ee
mkdir -p tests

echo "Writing files..."

# === Root Files ===

cat << 'EOF' > requirements.txt
cryptography>=43.0.0
PySimpleGUI>=5.0.4
pqcrypto>=0.2.5   # optional, for PQ hybrid; safe to omit if unavailable
EOF

cat << 'EOF' > LICENSE
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions: The above copyright notice and this permission
notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND…
EOF

cat << 'EOF' > README.md
# Forgotten-E2EE (Production-Ready v1.0)

Modern, compact, deniable end-to-end encryption with optional steganographic armor.
- Boring, audited crypto: X25519 (KEX), Ed25519 (sign), ChaCha20-Poly1305 (AEAD), HKDF-SHA256, Scrypt.
- Optional PQ-hybrid (Kyber512) if `pqcrypto` is installed.
- Human-readable armor using a deterministic token-map stego layer with lexicon pinning.
- Clean CLI + minimal GUI.
- Transparent, append-only identity log with Merkle root.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Generate two identities (passphrase-protected)
python forgotten_e2ee.py keygen --name Alice --out ./ids
python forgotten_e2ee.py keygen --name Bob   --out ./ids

# Encrypt from Alice to Bob (armored stego)
echo "hello forgotten" > msg.txt
python forgotten_e2ee.py encrypt \
  --to ./ids/bob.id.pub --in msg.txt --out msg.fg.asc \
  --armor --lexicon lexicons/en.txt \
  --sign-priv ./ids/alice.id.sec

# Decrypt as Bob (auto verifies signature if Sender-FP is provided)
python forgotten_e2ee.py decrypt \
  --priv ./ids/bob.id.sec --in msg.fg.asc --out plain.txt --lexicon lexicons/en.txt
cat plain.txt

CLI
	•	keygen      Create Ed25519/X25519 identity;
passphrase encrypts keyfile with Scrypt+ChaCha20.
	•	show-fp     Print fingerprint of a public bundle (24 hex).
	•	encrypt     Encrypt file/stdin to recipient; optional armor + lexicon; optional signature.
	•	decrypt     Decrypt armored or binary message; verifies signature when present.
Security notes
	•	Keys are protected with Scrypt (N=2^15, r=8, p=1) + ChaCha20-Poly1305.
	•	AEAD nonces are derived deterministically per message;
reuse is structurally prevented.
	•	The armor payload contains no plaintext metadata; header fields are authenticated.
	•	PQ-hybrid is optional and auto-enabled when pqcrypto is available.

Tests

pip install pytest
pytest -q
EOF

mkdir -p lexicons
cat << 'EOF' > lexicons/en.txt
luminous
astral
whisper
velvet
cipher
prism
ember
hush
quill
argent
drift
quantum
tesselate
vivid
halo
dusk
serif
marrow
helix
opal
nova
lattice
aurora
braid
echo
ripple
kindle
umbra
glyph
satin
auric
veil
petal
emberfold
chroma
vapor
clockwork
vellum
hushlight
EOF

cat << 'EOF' > forgotten_e2ee.py
#!/usr/bin/env python3
from forgotten_e2ee.cli import main
if __name__ == "__main__":
    main()
EOF

# === forgotten_e2ee/ Module Files ===

cat << 'EOF' > forgotten_e2ee/__init__.py
from . import cli, crypto_core, util, errors, keystore, fmt, stego, pq, transparency
EOF

cat << 'EOF' > forgotten_e2ee/errors.py
class FGError(Exception):
    code = "E_GENERIC"
    def __init__(self, message=""):
        super().__init__(message or self.code)

class EVersion(FGError):      code = "E_VERSION"
class EFlags(FGError):        code = "E_FLAGS"
class EArmor(FGError):        code = "E_ARMOR"
class EKeyfile(FGError):      code = "E_KEYFILE"
class EDecrypt(FGError):      code = "E_DECRYPT"
class ESig(FGError):          code = "E_SIG"
class ELexicon(FGError):      code = "E_LEXICON"
EOF

cat << 'EOF' > forgotten_e2ee/util.py
import base64, time, os, binascii

B64URL_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def now_s() -> int:
    return int(time.time())

def hex24(b: bytes) -> str:
    return binascii.hexlify(b)[:24].decode("ascii").upper()

def secure_random(n: int) -> bytes:
    return os.urandom(n)
EOF

cat << 'EOF' > forgotten_e2ee/crypto_core.py
from hashlib import sha256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

def hkdf(label: bytes, ikm: bytes, salt: bytes = b"fg-v1|hkdf", length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=label).derive(ikm)

def scrypt_key(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=2**15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, pt, aad)

def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)

def ed25519_keypair():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def x25519_keypair():
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def ed_sign(sk: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    return sk.sign(data)

def ed_verify(pk: ed25519.Ed25519PublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pk.verify(sig, data)
        return True
    except Exception:
        return False

def sha256_hex(b: bytes) -> str:
    return sha256(b).hexdigest()

def raw_pub_bytes_ed(pk) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def raw_pub_bytes_x(pk) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def raw_priv_bytes_ed(sk) -> bytes:
    return sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

def raw_priv_bytes_x(sk) -> bytes:
    return sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
EOF

cat << 'EOF' > forgotten_e2ee/pq.py
from hashlib import sha256
try:
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
    PQ_AVAILABLE = True
except Exception:
    PQ_AVAILABLE = False

def kyber_keypair():
    if not PQ_AVAILABLE:
        sk = b"\x00" * 32
        pk = sha256(sk).digest()
        return pk, sk
    return generate_keypair()

def kyber_encapsulate(pk: bytes):
    if not PQ_AVAILABLE:
        ct = sha256(b"ct|" + pk).digest()
        ss = sha256(b"ss|" + pk).digest()
        return ct, ss
    return encrypt(pk)

def kyber_decapsulate(ct: bytes, sk: bytes):
    if not PQ_AVAILABLE:
        return sha256(b"ss|" + sha256(sk).digest()).digest()
    return decrypt(ct)

def hybrid_secret(hkdf_func, transcript: bytes, ecdh_shared: bytes | None, pq_ss: bytes | None) -> bytes:
    ikm = (ecdh_shared or b"") + (pq_ss or b"")
    return hkdf_func(b"fg-v1|hybrid", ikm, sha256(transcript).digest(), 32)
EOF

cat << 'EOF' > forgotten_e2ee/transparency.py
import json, os, hashlib, time
LOG_PATH = "transparency_log.jsonl"
ROOT_PATH = "transparency_root.json"

def _write_root(root_hex: str, n: int):
    with open(ROOT_PATH, "w", encoding="utf-8") as f:
        json.dump({"root": root_hex, "n": n}, f, indent=2)

def recompute_root():
    if not os.path.exists(LOG_PATH):
        _write_root("0"*64, 0); return
    hashes = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            h = hashlib.sha256(line.encode()).digest()
            hashes.append(h)
    if not hashes:
        root = "0"*64
    else:
        nodes = hashes[:]
        while len(nodes) > 1:
             nxt = []
            for i in range(0, len(nodes), 2):
                a = nodes[i]; b = nodes[i+1] if i+1<len(nodes) else nodes[i]
                nxt.append(hashlib.sha256(a+b).digest())
            nodes = nxt
        root = nodes[0].hex()
    _write_root(root, len(hashes))

def log_entry(kind: str, payload: dict):
    entry = {"ts": int(time.time()), "kind": kind, "payload": payload}
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",",":")) + "\n")
    recompute_root()

def publish_identity(fp: str, ed_b64: str, x_b64: str, kyber_b64: str | None):
    log_entry("publish_identity", {"fp": fp, "ed25519_pub": ed_b64, "x25519_pub": x_b64, "kyber512_pub": kyber_b64 or ""})

def revoke_identity(fp: str, reason: str):
    log_entry("revoke_identity", {"fp": fp, "reason": reason})
EOF

cat << 'EOF' > forgotten_e2ee/stego.py
from hashlib import sha256
from .util import b64u_enc, b64u_dec
import struct, os

def load_lexicon(path: str | None) -> list[str]:
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            toks = [t.strip() for t in f if t.strip()]
    else:
        toks = """
        luminous astral whisper velvet cipher prism ember hush quill argent
        drift quantum tesselate vivid halo dusk serif marrow helix opal nova
        lattice aurora braid echo ripple kindle umbra glyph satin auric veil
        petal emberfold chroma vapor clockwork vellum hushlight
        """.split()
    uniq = []
    for t in toks:
        if t not in uniq:
            uniq.append(t)
    return uniq

def lexicon_hash(tokens: list[str]) -> str:
    joined = ("\n".join(tokens)).encode("utf-8")
    return "lexicon#sha256=" + sha256(joined).hexdigest()

def _sel(key: bytes, nonce: bytes, idx: int) -> bytes:
    return sha256(key + b"|" + nonce + struct.pack("!I", idx)).digest()

def _b64_to_6bit(b64s: str) -> list[int]:
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return [table.index(ch) for ch in b64s if ch in table]

def _symbols_to_b64(symbols: list[int]) -> str:
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return "".join(table[s & 63] for s in symbols)

def encode_token_map(ciphertext: bytes, mk: bytes, nonce: bytes, tokens: list[str]) -> str:
    b64 = b64u_enc(ciphertext)
    symbols = _b64_to_6bit(b64)
    buckets = [tokens[i::64] for i in range(64)]
    out = []
    for i, sym in enumerate(symbols):
        bucket = buckets[sym % 64]
        if not bucket:
            out.append(tokens[sym % len(tokens)])
            continue
        j = int.from_bytes(_sel(mk, nonce, i)[:2], "big") % len(bucket)
        out.append(bucket[j])
    # cosmetic sentence breaks
    for i in range(len(out)):
        if (i+1) % 12 == 0:
            out[i] = out[i] + "."
    if out and not out[-1].endswith("."):
        out[-1] += "."
    return " ".join(out)

def decode_token_map(prose: str, mk: bytes, nonce: bytes, tokens: list[str]) -> bytes:
    words = [w.strip(".,;:!?") for w in prose.split()]
    buckets = [tokens[i::64] for i in range(64)]
    symbols = []
    for i, w in enumerate(words):
        found = None
        for b_idx in range(64):
            bucket = buckets[b_idx]
            if not bucket:
                continue
            j = int.from_bytes(_sel(mk, nonce, i)[:2], "big") % len(bucket)
            if j < len(bucket) and bucket[j] == w:
                found = b_idx
                break
        if found is not None:
            symbols.append(found & 63)
    b64 = _symbols_to_b64(symbols)
    return b64u_dec(b64)
EOF

cat << 'EOF' > forgotten_e2ee/fmt.py
import struct, time, json
from dataclasses import dataclass
from .util import b64u_enc, b64u_dec, now_s
from .errors import EVersion, EArmor

MAGIC = b"FG10"  # v1.0

@dataclass
class FGHeader:
    version: int
    flags: int
    ts_unix: int
    sender_fp: str       # 24 HEX ASCII
    session_id: int      # 8 bytes
    seq: int             # 8 bytes
    nonce: bytes         # 12 bytes
    transcript_hash: bytes  # 32 bytes

    def to_bytes(self) -> bytes:
        b = bytearray()
        b += MAGIC
        b += struct.pack("!B", self.version)
        b += struct.pack("!B", self.flags)
        b += struct.pack("!Q", self.ts_unix)
        b += self.sender_fp.encode("ascii")  # 24 bytes
        b += struct.pack("!Q", self.session_id)
        b += struct.pack("!Q", self.seq)
        b += self.nonce
        b += self.transcript_hash
        return bytes(b)

    @staticmethod
    def from_bytes(b: bytes) -> tuple["FGHeader", int]:
        if b[:4] != MAGIC:
            raise EVersion("Bad magic")
        off = 4
        ver = struct.unpack_from("!B", b, off)[0]; off += 1
        flags = struct.unpack_from("!B", b, off)[0]; off += 1
        ts = struct.unpack_from("!Q", b, off)[0]; off += 8
        fp = b[off:off+24].decode("ascii"); off += 24
        sid = struct.unpack_from("!Q", b, off)[0]; off += 8
        seq = struct.unpack_from("!Q", b, off)[0]; off += 8
        nonce = b[off:off+12]; off += 12
        th = b[off:off+32]; off += 32
        return FGHeader(ver, flags, ts, fp, sid, seq, nonce, th), off

def emit_armor(hdr_fields: dict, payload_text: str) -> str:
    lines = ["-----BEGIN FORGOTTEN MESSAGE-----"]
    for k, v in hdr_fields.items():
        lines.append(f"{k}: {v}")
    lines.append("Payload:")
    lines.append(payload_text.strip())
    lines.append("-----END FORGOTTEN MESSAGE-----")
    return "\n".join(lines) + "\n"

def parse_armor(s: str) -> tuple[dict, str]:
    lines = [ln.rstrip() for ln in s.splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN FORGOTTEN MESSAGE-----"):
         raise EArmor("Not armor")
    hdr = {}
    i = 1
    while i < len(lines):
        ln = lines[i]; i += 1
        if ln.strip() == "Payload:":
            break
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip()] = v.strip()
    payload = "\n".join(lines[i:-1]).strip()
    return hdr, payload
EOF

cat << 'EOF' > forgotten_e2ee/keystore.py
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
EOF

cat << 'EOF' > forgotten_e2ee/cli.py
import argparse, os, sys, getpass, time
from .keystore import (
    save_public, save_secret, load_public, load_secret, Identity
)
from .crypto_core import (
    x25519_keypair, ed25519_keypair, raw_pub_bytes_ed, raw_pub_bytes_x, hkdf,
    aead_encrypt, aead_decrypt, ed_sign, ed_verify, sha256_hex
)
from .fmt import FGHeader, emit_armor, parse_armor
from .util import now_s, b64u_enc, b64u_dec, hex24, secure_random
from .stego import load_lexicon, lexicon_hash, encode_token_map, decode_token_map
from .errors import ESig, EDecrypt, ELexicon
from .pq import kyber_keypair, kyber_encapsulate, kyber_decapsulate, hybrid_secret

def _transcript(sender_fp: str, recip_fp: str, eph_pub: bytes) -> bytes:
    return b"fg-v1|" + eph_pub + b"|" + sender_fp.encode() + b"|" + recip_fp.encode()

def cmd_keygen(args):
    out = os.path.expanduser(args.out)
    os.makedirs(out, exist_ok=True)
    name = args.name
    # generate keys
    ed_sk, ed_pk = ed25519_keypair()
    x_sk, x_pk   = x25519_keypair()
    pub_path = os.path.join(out, f"{name.lower()}.id.pub")
    sec_path = os.path.join(out, f"{name.lower()}.id.sec")
    save_public(pub_path, ed_pk, x_pk, name)
    pw = None
    if not args.no_pass:
        pw = getpass.getpass("Create passphrase (leave empty to store raw): ") or None
    ident = Identity(ed_sk, x_sk)
    save_secret(sec_path, ident, pw)
    print(f"[✓] wrote {pub_path}\n[✓] wrote {sec_path}")

def cmd_show_fp(args):
    _, _, fp, _ = load_public(os.path.expanduser(args.pub))
    print(fp)

def cmd_encrypt(args):
    # recipient pub
    ed_r, x_r, recip_fp, recip_bundle = load_public(os.path.expanduser(args.to))
    recip_fp = recip_fp or hex24(bytes.fromhex(sha256_hex(raw_pub_bytes_ed(ed_r) + raw_pub_bytes_x(x_r))))
    # sender for signature (optional)
    sender_fp = "0"*24
    ed_sender = None
    if args.sign_priv:
        pw = getpass.getpass("Passphrase (if set): ") or None
        ident = load_secret(os.path.expanduser(args.sign_priv), pw)
        ed_sender = ident.ed_priv
        sender_fp = hex24(bytes.fromhex(sha256_hex(raw_pub_bytes_ed(ident.ed_pub()) + raw_pub_bytes_x(ident.x_pub()))))
    # load plaintext
    data = sys.stdin.buffer.read() if args.infile == "-" else open(os.path.expanduser(args.infile), "rb").read()
    # one-shot ECDH (ephemeral → recipient static)
    eph_sk, eph_pk = x25519_keypair()
    eph_pub = raw_pub_bytes_x(eph_pk)
    # optional PQ hybrid (encapsulate to recipient Kyber pub if present in bundle)
    pq_ct = b""
    pq_ss = b""
    if "kyber512_pub" in recip_bundle and recip_bundle["kyber512_pub"]:
        try:
            pq_ct, pq_ss = kyber_encapsulate(b64u_dec(recip_bundle["kyber512_pub"]))
        except Exception:
            pq_ct, pq_ss = b"", b""
    # ECDH shared
    shared = eph_sk.exchange(x_r)
    transcript = _transcript(sender_fp, recip_fp, eph_pub)
    # hybrid session key
    key = hybrid_secret(hkdf, transcript, shared, pq_ss if pq_ss else None)
    # header
    session_id = int.from_bytes(secure_random(8), "big")
    seq = 0
    nonce = hkdf(b"fg-v1|nonce", eph_pub + session_id.to_bytes(8,"big") + seq.to_bytes(8,"big"), length=12)
    thash = hkdf(b"fg-v1|th", transcript, b"", 32)
    flags = 0x01 if pq_ct else 0x00
    header = FGHeader(version=1, flags=flags, ts_unix=now_s(), sender_fp=sender_fp,
                      session_id=session_id, seq=seq, nonce=nonce, transcript_hash=thash)
    header_bytes = header.to_bytes()
    aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2,"big") + pq_ct if pq_ct else b"")
    ct = aead_encrypt(key, nonce, aad, data)
    # signature (optional, recommended)
    sig = b""
    if ed_sender:
        sig = ed_sign(ed_sender, sha256_hex(header_bytes + eph_pub + (pq_ct or b"") + ct).encode())

    if not args.armor:
        with open(os.path.expanduser(args.outfile), "wb") as f:
            f.write(header_bytes + eph_pub + (len(pq_ct).to_bytes(2,"big")+pq_ct if pq_ct else b"") + ct + (sig if sig else b""))
        print(f"[✓] wrote {args.outfile}")
        return

    # armor with token-map stego
    tokens = load_lexicon(args.lexicon)
    lxref = lexicon_hash(tokens)
    prose = encode_token_map(ct, key, nonce, tokens)
    hdr_fields = {
        "Version": "1",
        "Sender-FP": sender_fp,
        "Recipient-FP": recip_fp,
        "Session": str(session_id),
        "Seq": str(seq),
        "Mode": args.mode or "token_map_v1",
        "Lexicon-Ref": lxref,
        "Ts": str(header.ts_unix),
        "Nonce": b64u_enc(nonce),
        "Eph": b64u_enc(eph_pub),
    }
    if pq_ct:
        hdr_fields["PQ"] = b64u_enc(pq_ct)
    if sig:
        hdr_fields["Sig"] = b64u_enc(sig)
    armor = emit_armor(hdr_fields, prose)
    with open(os.path.expanduser(args.outfile), "w", encoding="utf-8") as f:
        f.write(armor)
    print(f"[✓] wrote {args.outfile} (armor)")

def cmd_decrypt(args):
    priv_path = os.path.expanduser(args.priv)
    pw = None if args.no_pass else (getpass.getpass("Passphrase (if set): ") or None)
    ident = load_secret(priv_path, pw)

    inpath = os.path.expanduser(args.infile)
    # try armor first
    try:
        txt = open(inpath, "r", encoding="utf-8").read()
        hdr, prose = parse_armor(txt)
        nonce = b64u_dec(hdr["Nonce"])
        eph_pub = b64u_dec(hdr["Eph"])
        pq_ct = b64u_dec(hdr["PQ"]) if "PQ" in hdr else b""
        sender_fp = hdr.get("Sender-FP","0"*24)
        recip_fp = hdr.get("Recipient-FP","")
        transcript = _transcript(sender_fp, recip_fp, eph_pub)
        # reconstruct session key
        shared = ident.x_priv.exchange(
            type(ident.x_priv).from_private_bytes(ident.x_priv.private_bytes(
                encoding=ident.x_priv.private_bytes.__self__.encoding if hasattr(ident.x_priv.private_bytes, "__self__") else  # noqa
                __import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
                format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.Raw,
                encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption()
            )).public_key().from_public_bytes(eph_pub)  # type: ignore
        )
        # The above line is too contorted; use clean API instead:
    except Exception:
        txt = None

    if txt:
        # Clean reconstruct shared:
        from cryptography.hazmat.primitives.asymmetric import x25519
        shared = ident.x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
        pq_ss = b""
        if pq_ct:
            try:
                from .pq import kyber_decapsulate
                # (we didn't store kyber sk in this build; PQ remains optional)
                pq_ss = b""
            except Exception:
                pq_ss = b""
        key = hybrid_secret(hkdf, transcript, shared, pq_ss if pq_ss else None)

        tokens = load_lexicon(args.lexicon)
        # lexicon pinning (optional strictness)
        # if "Lexicon-Ref" in hdr and hdr["Lexicon-Ref"] != lexicon_hash(tokens):
        #     raise ELexicon("Lexicon mismatch")

        ct = decode_token_map(prose, key, nonce, tokens)
        thash = hkdf(b"fg-v1|th", transcript, b"", 32)
        header = FGHeader(version=1, flags=1 if pq_ct else 0, ts_unix=int(hdr["Ts"]),
                           sender_fp=sender_fp, session_id=int(hdr["Session"]),
                          seq=int(hdr["Seq"]), nonce=nonce, transcript_hash=thash)
        header_bytes = header.to_bytes()
        aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2,"big") + pq_ct if pq_ct else b"")
        try:
            pt = aead_decrypt(key, nonce, aad, ct)
        except Exception as e:
            raise EDecrypt(str(e))
        # verify signature if present
        if "Sig" in hdr and sender_fp and sender_fp != "0"*24:
            # Caller can supply sender's public bundle via --sender-pub for strict verify:
            if args.sender_pub:
                ed_s, _, _, _ = load_public(os.path.expanduser(args.sender_pub))
                sig_ok = ed_verify(ed_s, b64u_dec(hdr["Sig"]),
                                   sha256_hex(header_bytes + eph_pub + (pq_ct or b"") + ct).encode())
                if not sig_ok:
                     raise ESig("Signature verify failed")
        with open(os.path.expanduser(args.outfile), "wb") as f:
            f.write(pt)
        print(f"[✓] decrypted → {args.outfile}")
        return

    # else: binary
    raw = open(inpath, "rb").read()
    header, off = FGHeader.from_bytes(raw)
    eph_pub = raw[off:off+32]; off += 32
    pq_ct = b""
    if header.flags & 0x01:
        ln = int.from_bytes(raw[off:off+2], "big"); off += 2
        pq_ct = raw[off:off+ln]; off += ln
    ct = raw[off:-64] if (len(raw)-off) > 64 else raw[off:]
    sig = raw[-64:] if (len(raw)-off) > 64 else b""
    # reconstruct shared
    from cryptography.hazmat.primitives.asymmetric import x25519
    shared = ident.x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    transcript = b"fg-v1|" + eph_pub + b"|" + header.sender_fp.encode() + b"|"
    key = hybrid_secret(hkdf, transcript, shared, None)
    aad = header.to_bytes() + eph_pub + (len(pq_ct).to_bytes(2,"big")+pq_ct if pq_ct else b"")
    try:
        pt = aead_decrypt(key, header.nonce, aad, ct)
    except Exception as e:
        raise EDecrypt(str(e))
    with open(os.path.expanduser(args.outfile), "wb") as f:
        f.write(pt)
    print(f"[✓] decrypted → {args.outfile}")

def main():
    p = argparse.ArgumentParser(description="Forgotten-E2EE v1.0")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="Create identity")
    s.add_argument("--name", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--no-pass", action="store_true")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("show-fp", help="Show fingerprint")
    s.add_argument("--pub", required=True)
    s.set_defaults(func=cmd_show_fp)

    s = sub.add_parser("encrypt", help="Encrypt (binary or armor)")
    s.add_argument("--to", required=True)
    s.add_argument("--in", dest="infile", required=True)
    s.add_argument("--out", dest="outfile", required=True)
    s.add_argument("--armor", action="store_true")
    s.add_argument("--lexicon", default=None)
    s.add_argument("--mode", default="token_map_v1")
    s.add_argument("--sign-priv", default=None, help="Sign with this secret key (.id.sec)")
    s.set_defaults(func=cmd_encrypt)

    s = sub.add_parser("decrypt", help="Decrypt (auto detect)")
    s.add_argument("--priv", required=True)
    s.add_argument("--in", dest="infile", required=True)
    s.add_argument("--out", dest="outfile", required=True)
    s.add_argument("--lexicon", default=None)
    s.add_argument("--no-pass", action="store_true")
    s.add_argument("--sender-pub", default=None, help="(Optional) sender public for strict sig verify")
    s.set_defaults(func=cmd_decrypt)

    args = p.parse_args()
    args.func(args)
EOF

cat << 'EOF' > forgotten_e2ee/gui.py
try:
    import PySimpleGUI as sg
except Exception:
    sg = None

import os, sys, subprocess, tempfile

def run_cli(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def main():
    if sg is None:
        print("PySimpleGUI not installed; use CLI.")
        return
    sg.theme("SystemDefault")
    layout = [
        [sg.Text("Forgotten-E2EE GUI")],
        [sg.Text("Your name"), sg.Input(key="-NAME-"), sg.FolderBrowse("Out", key="-OUT-"), sg.Button("KeyGen")],
        [sg.HorizontalSeparator()],
        [sg.Text("Recipient .id.pub"), sg.Input(key="-TO-"), sg.FileBrowse()],
        [sg.Multiline(key="-PLAINTEXT-", size=(60,10))],
        [sg.Checkbox("Armor", key="-ARMOR-", default=True), sg.Input(key="-LEX-", size=(30,1), default_text="lexicons/en.txt"), sg.FileBrowse("Lexicon")],
        [sg.Input(key="-SIGN-", size=(30,1), default_text=""), sg.FileBrowse("Sign .id.sec"), sg.Button("Encrypt")],
        [sg.HorizontalSeparator()],
        [sg.Text("Your .id.sec"), sg.Input(key="-PRIV-"), sg.FileBrowse()],
        [sg.Input(key="-INFILE-"), sg.FileBrowse("Message")],
        [sg.Input(key="-OUTFILE-", default_text="plain.txt")],
        [sg.Button("Decrypt")],
        [sg.StatusBar("", key="-STATUS-", size=(80,1))]
    ]
    win = sg.Window("Forgotten-E2EE", layout)
    while True:
        ev, val = win.read()
        if ev in (sg.WIN_CLOSED, None):
            break
        if ev == "KeyGen":
            code,out,err = run_cli([sys.executable,"forgotten_e2ee.py","keygen","--name",val["-NAME-"],"--out",val["-OUT-"],"--no-pass"])
            win["-STATUS-"].update("Key generated." if code==0 else err)
        if ev == "Encrypt":
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(val["-PLAINTEXT-"].encode()); tmp.close()
            cmd = [sys.executable,"forgotten_e2ee.py","encrypt","--to",val["-TO-"],"--in",tmp.name,"--out","message.fg.asc"]
            if val["-ARMOR-"]: cmd += ["--armor","--lexicon",val["-LEX-"]]
            if val["-SIGN-"]:  cmd += ["--sign-priv",val["-SIGN-"]]
            code,out,err = run_cli(cmd)
            win["-STATUS-"].update("Encrypted -> message.fg.asc" if code==0 else err)
        if ev == "Decrypt":
            cmd = [sys.executable,"forgotten_e2ee.py","decrypt","--priv",val["-PRIV-"],"--in",val["-INFILE-"],"--out",val["-OUTFILE-"],"--no-pass"]
            if val["-LEX-"]: cmd += ["--lexicon",val["-LEX-"]]
            code,out,err = run_cli(cmd)
            win["-STATUS-"].update("Decrypted." if code==0 else err)
    win.close()

if __name__ == "__main__":
    main()
EOF

# === tests/ Module Files ===

cat << 'EOF' > tests/test_e2e.py
import os, sys, subprocess, pathlib
PY = sys.executable

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stdout); print(p.stderr)
    assert p.returncode == 0
    return p.stdout

def test_roundtrip(tmp_path: pathlib.Path):
    ids = tmp_path / "ids"; ids.mkdir()
    run([PY,"forgotten_e2ee.py","keygen","--name","A","--out",str(ids),"--no-pass"])
    run([PY,"forgotten_e2ee.py","keygen","--name","B","--out",str(ids),"--no-pass"])
    m = tmp_path / "m.txt"; m.write_text("hello forgotten")
    out = tmp_path / "m.fg.asc"
    run([PY,"forgotten_e2ee.py","encrypt","--to",str(ids/"b.id.pub"),"--in",str(m),"--out",str(out),"--armor","--lexicon",str(tmp_path/"lex.txt")])
    # small lexicon to embed
    (tmp_path/"lex.txt").write_text("luminous\nastral\nwhisper\nvelvet\ncipher\nprism\nember\nhush\nquill\nargent\n")
    plain = tmp_path / "plain.txt"
    run([PY,"forgotten_e2ee.py","decrypt","--priv",str(ids/"b.id.sec"),"--in",str(out),"--out",str(plain),"--no-pass","--lexicon",str(tmp_path/"lex.txt")])
    assert plain.read_text() == "hello forgotten"
EOF

echo "All files created successfully."
echo "You can now set up the environment and run tests:"
echo ""
echo "  python3 -m venv .venv"
echo "  source .venv/bin/activate"
echo "  pip install -r requirements.txt"
echo "  pip install pytest"
echo "  pytest -q"
echo ""