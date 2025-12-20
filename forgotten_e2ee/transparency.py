import json, os, hashlib, time

LOG_PATH = "transparency_log.jsonl"
ROOT_PATH = "transparency_root.json"


def _write_root(root_hex: str, n: int):
    with open(ROOT_PATH, "w", encoding="utf-8") as f:
        json.dump({"root": root_hex, "n": n}, f, indent=2)


def recompute_root():
    if not os.path.exists(LOG_PATH):
        _write_root("0" * 64, 0);
        return
    hashes = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            h = hashlib.sha256(line.encode()).digest()
            hashes.append(h)

    if not hashes:
        root = "0" * 64
    else:
        nodes = hashes[:]
        while len(nodes) > 1:
            nxt = []
            for i in range(0, len(nodes), 2):
                a = nodes[i]
                b = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
                nxt.append(hashlib.sha256(a + b).digest())
            nodes = nxt
        root = nodes[0].hex()
    _write_root(root, len(hashes))


def log_entry(kind: str, payload: dict):
    entry = {"ts": int(time.time()), "kind": kind, "payload": payload}
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    recompute_root()


def publish_identity(fp: str, ed_b64: str, x_b64: str, kyber_b64: str | None):
    log_entry("publish_identity",
              {"fp": fp, "ed25519_pub": ed_b64, "x25519_pub": x_b64, "kyber512_pub": kyber_b64 or ""})


def revoke_identity(fp: str, reason: str):
    log_entry("revoke_identity", {"fp": fp, "reason": reason})