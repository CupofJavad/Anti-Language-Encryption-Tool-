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
    x_sk, x_pk = x25519_keypair()
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
    sender_fp = "0" * 24
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
    nonce = hkdf(b"fg-v1|nonce", eph_pub + session_id.to_bytes(8, "big") + seq.to_bytes(8, "big"), length=12)
    thash = hkdf(b"fg-v1|th", transcript, b"", 32)
    flags = 0x01 if pq_ct else 0x00
    if ed_sender:
        flags |= 0x02
    header = FGHeader(version=1, flags=flags, ts_unix=now_s(), sender_fp=sender_fp,
                      session_id=session_id, seq=seq, nonce=nonce, transcript_hash=thash)
    header_bytes = header.to_bytes()
    aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
    ct = aead_encrypt(key, nonce, aad, data)
    # signature (optional, recommended)
    sig = b""
    if ed_sender:
        sig = ed_sign(ed_sender, sha256_hex(header_bytes + eph_pub + (pq_ct or b"") + ct).encode())

    if not args.armor:
        with open(os.path.expanduser(args.outfile), "wb") as f:
            f.write(header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"") + ct + (
                sig if sig else b""))
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
    hdr_fields["Ciphertext-B64"] = b64u_enc(ct)
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
        sender_fp = hdr.get("Sender-FP", "0" * 24)
        recip_fp_hdr = hdr.get("Recipient-FP", "")
        recip_fp_actual = ident.fingerprint()
        if recip_fp_hdr and recip_fp_hdr != recip_fp_actual:
            raise EDecrypt("Recipient fingerprint mismatch")
        transcript = _transcript(sender_fp, recip_fp_actual, eph_pub)
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
        expected_lxref = hdr.get("Lexicon-Ref")
        if expected_lxref:
            # ensure we decrypt with the same lexicon that was used to encrypt
            actual_lxref = lexicon_hash(tokens)
            if actual_lxref != expected_lxref:
                fallback_tokens = load_lexicon(None)
                if lexicon_hash(fallback_tokens) == expected_lxref:
                    tokens = fallback_tokens
                else:
                    raise ELexicon("Lexicon mismatch")

        if "Ciphertext-B64" in hdr:
            ct = b64u_dec(hdr["Ciphertext-B64"])
        else:
            ct = decode_token_map(prose, key, nonce, tokens)
        thash = hkdf(b"fg-v1|th", transcript, b"", 32)
        flags = 0x01 if pq_ct else 0x00
        if "Sig" in hdr:
            flags |= 0x02
        header = FGHeader(version=1, flags=flags, ts_unix=int(hdr["Ts"]),
                          sender_fp=sender_fp, session_id=int(hdr["Session"]),
                          seq=int(hdr["Seq"]), nonce=nonce, transcript_hash=thash)
        header_bytes = header.to_bytes()
        aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
        try:
            pt = aead_decrypt(key, nonce, aad, ct)
        except Exception as e:
            raise EDecrypt(str(e))
        # verify signature if present
        if "Sig" in hdr and sender_fp and sender_fp != "0" * 24:
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
    eph_pub = raw[off:off + 32];
    off += 32
    pq_ct = b""
    if header.flags & 0x01:
        ln = int.from_bytes(raw[off:off + 2], "big");
        off += 2
        pq_ct = raw[off:off + ln];
        off += ln
    ct = raw[off:]
    sig = b""
    if header.flags & 0x02:
        if len(ct) < 64:
            raise EDecrypt("Truncated signature block")
        sig = ct[-64:]
        ct = ct[:-64]

    # reconstruct shared
    from cryptography.hazmat.primitives.asymmetric import x25519
    shared = ident.x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))

    # *** THIS IS THE FIX for BUG 2 ***
    # The transcript must include the recipient's fingerprint, which we get from our loaded identity
    recip_fp = ident.fingerprint()
    transcript = _transcript(header.sender_fp, recip_fp, eph_pub)

    key = hybrid_secret(hkdf, transcript, shared, None)  # No PQ in binary path
    aad = header.to_bytes() + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
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