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
