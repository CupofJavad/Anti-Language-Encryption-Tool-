from hashlib import sha256
from pathlib import Path
from .util import b64u_enc, b64u_dec
import struct, os


_FALLBACK_LEXICON = """
        luminous astral whisper velvet cipher prism ember hush quill argent
        drift quantum tesselate vivid halo dusk serif marrow helix opal nova
        lattice aurora braid echo ripple kindle umbra glyph satin auric veil
        petal emberfold chroma vapor clockwork vellum hushlight
        """.split()


def _default_lexicon_path() -> Path:
    return Path(__file__).resolve().parent.parent / "lexicons" / "en.txt"


def load_lexicon(path: str | None) -> list[str]:
    tokens: list[str]
    lex_path: Path | None = None
    if path and os.path.exists(path):
        lex_path = Path(path).expanduser()
    else:
        candidate = _default_lexicon_path()
        if candidate.exists():
            lex_path = candidate
    if lex_path and lex_path.exists():
        with open(lex_path, "r", encoding="utf-8") as f:
            toks = [t.strip() for t in f if t.strip()]
    else:
        toks = list(_FALLBACK_LEXICON)
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


def _build_buckets(tokens: list[str]) -> list[list[str]]:
    n = len(tokens)
    if n == 0:
        raise ValueError("Lexicon must contain at least one token")
    buckets = []
    for i in range(64):
        bucket = []
        idx = i
        while idx < n:
            bucket.append(tokens[idx])
            idx += 64
        if not bucket:
            bucket.append(tokens[i % n])
        buckets.append(bucket)
    return buckets


def encode_token_map(ciphertext: bytes, mk: bytes, nonce: bytes, tokens: list[str]) -> str:
    b64 = b64u_enc(ciphertext)
    symbols = _b64_to_6bit(b64)
    buckets = _build_buckets(tokens)
    out = []
    for i, sym in enumerate(symbols):
        bucket = buckets[sym % 64]
        j = int.from_bytes(_sel(mk, nonce, i)[:2], "big") % len(bucket)
        out.append(bucket[j])
    # cosmetic sentence breaks
    for i in range(len(out)):
        if (i + 1) % 12 == 0:
            out[i] = out[i] + "."
    if out and not out[-1].endswith("."):
        out[-1] += "."
    return " ".join(out)


def decode_token_map(prose: str, mk: bytes, nonce: bytes, tokens: list[str]) -> bytes:
    words = [w.strip(".,;:!?") for w in prose.split()]
    buckets = _build_buckets(tokens)
    symbols = []

    for i, w in enumerate(words):
        found = None

        # 1. Check deterministic buckets (the intended path)
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