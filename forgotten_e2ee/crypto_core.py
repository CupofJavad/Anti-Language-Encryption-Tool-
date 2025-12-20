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
