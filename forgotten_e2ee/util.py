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
