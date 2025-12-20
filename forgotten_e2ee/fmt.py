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
