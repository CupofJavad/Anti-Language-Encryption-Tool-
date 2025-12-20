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

## Detailed Walkthrough

Follow these steps to reproduce two complete encryption/decryption cycles using the sample dream log texts.

### 1. Set up a clean workspace (optional but recommended)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdir -p demo/ids demo/texts demo/out
```

### 2. Generate two identities (no passphrases for the demo)
```bash
python forgotten_e2ee.py keygen --name Alice --out demo/ids --no-pass
python forgotten_e2ee.py keygen --name Bob   --out demo/ids --no-pass
```

### 3. Prepare a lexicon
Use the bundled `lexicons/en.txt`, or copy it beside the outputs for clarity:
```bash
cp lexicons/en.txt demo/lexicon.txt
```

### 4. Create the sample texts
```bash
cat <<'EOF' > demo/texts/dream1.txt
Private Dreamlog Entry 6.16.22

Huge massive tree among this coast where I recognize coming here for the maybe they second time but only after mentioning it. The tree has these massive swinging branches with petals/flowers attached to bottom that cup or fold out. There are different statues of animals and extremely oversized animals running around. You see a dark beautiful woman swinging on a swing, then approach a white woman who comes off as initially very attractive…somehow she knows your name upfront and you soon realize the meetup was a setup. The question “You don’t think your worth all this?” Possibly about your drug use? Possibly this is a real life projection of donkey Kong map ? Tree of life visit?
EOF

cat <<'EOF' > demo/texts/dream2.txt
Private Dreamlog Entry 9.19.22

3-25

We are driving in the Audi and some guy breaks in front of me because these drones were distracting our view. I been drinking, get out to see what it was and apologize or whatever. Drones are no where. We see another one go by and do some weird shit with another one. They later we find out their these hovering magnets pieces of glass projecting a holographic image of drone directly up. I stop one as it goes by. They’re transparent and next level tech. Wake up
EOF
```

### 5. Encrypt Example Text 1 (Alice ➜ Bob, armored stego)
```bash
python forgotten_e2ee.py encrypt \
  --to demo/ids/bob.id.pub \
  --in demo/texts/dream1.txt \
  --out demo/out/dream1.fg.asc \
  --armor \
  --lexicon demo/lexicon.txt \
  --sign-priv demo/ids/alice.id.sec
```
The armored result is in `demo/out/dream1.fg.asc` and includes `Ciphertext-B64`, letting Bob recover the authenticated ciphertext exactly.

### 6. Decrypt Example Text 1 (Bob)
```bash
python forgotten_e2ee.py decrypt \
  --priv demo/ids/bob.id.sec \
  --in demo/out/dream1.fg.asc \
  --out demo/out/dream1.plain.txt \
  --lexicon demo/lexicon.txt \
  --no-pass
cat demo/out/dream1.plain.txt
```
Bob now reads the original dream entry.

### 7. Encrypt Example Text 2 (reuse the same keys/lexicon)
```bash
python forgotten_e2ee.py encrypt \
  --to demo/ids/bob.id.pub \
  --in demo/texts/dream2.txt \
  --out demo/out/dream2.fg.asc \
  --armor \
  --lexicon demo/lexicon.txt \
  --sign-priv demo/ids/alice.id.sec
```

### 8. Decrypt Example Text 2
```bash
python forgotten_e2ee.py decrypt \
  --priv demo/ids/bob.id.sec \
  --in demo/out/dream2.fg.asc \
  --out demo/out/dream2.plain.txt \
  --lexicon demo/lexicon.txt \
  --no-pass
cat demo/out/dream2.plain.txt
```

### 9. Optional verifications
- `forgotten_e2ee.py show-fp --pub demo/ids/bob.id.pub` to confirm Bob’s fingerprint matches the armor header.
- Inspect `demo/out/dream*.fg.asc` to see the token-map prose and authenticated metadata such as `Lexicon-Ref` and `Ciphertext-B64`.

The same pattern works for any plaintext files—you can swap in different lexicons or identities as needed. Tests remain available with:
```bash
pytest -q
```
