<div align="center">

# 🔐 Forgotten-E2EE

**Modern, deniable end-to-end encryption with steganographic armor**

*Encryption that looks like poetry, not ciphertext*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-53%2F53%20Passed-brightgreen.svg)](web_app/FINAL_TEST_RESULTS.md)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success.svg)]()

> *"If privacy is outlawed, only outlaws will have privacy."*  
> — **Phil Zimmermann**, creator of PGP

</div>

---

## 📑 Table of Contents

- [The Story That Started It All](#the-story-that-started-it-all-phil-zimmermann--pgp)
- [What is Forgotten-E2EE?](#-what-is-forgotten-e2ee)
- [Quick Start](#-quick-start)
- [Ways to Use It](#-ways-to-use-it)
- [Features Deep Dive](#-features-deep-dive)
- [Documentation](#-documentation)
- [Security Notes](#-security-notes)
- [Testing](#-testing)
- [Web Deployment](#-web-deployment)
- [Contributing](#-contributing)
- [License](#-license)

---

## The Story That Started It All: Phil Zimmermann & PGP

In 1991, a software engineer named **Phil Zimmermann** did something that would change the world of cryptography forever—and nearly land him in federal prison.

### The Man Who Dared to Encrypt

Phil created **Pretty Good Privacy (PGP)**, the first widely available encryption software that gave ordinary people the power to communicate privately. But here's where it gets interesting: **the U.S. government wasn't exactly thrilled.**

### The Crypto Wars Begin 🛡️

You see, in the early 1990s, encryption software was classified as a **"munition"** under U.S. export laws. The government argued that strong encryption in the hands of civilians was a national security threat. So when Phil released PGP to the world—making it freely available on the internet—he found himself in the crosshairs of a **three-year federal criminal investigation**.

**The charges?** Violating the Arms Export Control Act by "exporting" encryption software (even though he just uploaded it to the internet).

### The Battle for Privacy

For three years, Phil faced the possibility of **federal prison time**. But he never backed down. He argued that privacy is a fundamental human right, and that strong encryption protects journalists, activists, dissidents, and ordinary citizens from surveillance and oppression.

The case became a symbol of the **"Crypto Wars"**—the battle between privacy advocates and government surveillance. Phil's defense was simple yet powerful: *"If privacy is outlawed, only outlaws will have privacy."*

### Victory & Legacy 🏆

In 1996, after years of legal battles and mounting public pressure, **the charges were dropped**. The government realized they couldn't stop the spread of encryption technology—it was already out there, and it was here to stay.

Phil's fight paved the way for:
- ✅ End-to-end encryption becoming standard
- ✅ Privacy tools for everyone (not just governments)
- ✅ The modern encryption ecosystem we rely on today
- ✅ Projects like this one

### Why This Matters to Me (And This Project)

Phil Zimmermann's story is more than history—it's a **reminder of why privacy matters**. He risked everything to give people the tools to protect their communications, and he won. That's the spirit behind **Forgotten-E2EE**.

This project is my small contribution to that legacy: **encryption that's powerful, deniable, and accessible to everyone**—no government approval required, no backdoors, no compromises.

---

## 🌟 What is Forgotten-E2EE?

**Forgotten-E2EE** is a modern, compact end-to-end encryption toolkit with a twist: **steganographic armor** that makes encrypted messages look like innocent prose. Think of it as PGP's rebellious younger sibling who learned to hide in plain sight.

### The Cool Parts ✨

- 🔒 **Boring, Audited Crypto** - X25519, Ed25519, ChaCha20-Poly1305 (the good stuff)
- 🎭 **Steganographic Armor** - Encrypted messages disguised as beautiful prose
- 🚫 **Deniable** - Messages look like poetry, not ciphertext
- 🌐 **Web-Ready** - Deploy it, embed it, share it
- 🎨 **Multiple Interfaces** - CLI, GUI (Tkinter), and Web app
- 🔐 **Post-Quantum Ready** - Optional Kyber512 hybrid encryption

### The Steganography Magic 🎪

Here's where it gets fun: instead of outputting ugly base64 gibberish, Forgotten-E2EE can transform your encrypted messages into **beautiful, readable prose** using a deterministic token-map. Your secret message becomes something like:

> *"luminous whisper drifts through velvet shadows, where ember thoughts kindle in the hush of midnight's embrace..."*

Looks like poetry, right? **It's actually your encrypted message.** Only someone with the right key and lexicon can decode it. Even if intercepted, it just looks like... well, poetry.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repo
git clone https://github.com/CupofJavad/Anti-Language-Encryption-Tool-.git
cd Anti-Language-Encryption-Tool-

# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Your First Encrypted Message (30 seconds)

```bash
# 1. Generate your identity
python forgotten_e2ee.py keygen --name Alice --out ./ids --no-pass

# 2. Generate a friend's identity
python forgotten_e2ee.py keygen --name Bob --out ./ids --no-pass

# 3. Encrypt a message (with steganographic armor!)
echo "Hello from the future!" > secret.txt
python forgotten_e2ee.py encrypt \
  --to ./ids/bob.id.pub \
  --in secret.txt \
  --out message.fg.asc \
  --armor \
  --lexicon lexicons/en.txt

# 4. Decrypt it (as Bob)
python forgotten_e2ee.py decrypt \
  --priv ./ids/bob.id.sec \
  --in message.fg.asc \
  --out decrypted.txt \
  --lexicon lexicons/en.txt \
  --no-pass

cat decrypted.txt  # "Hello from the future!"
```

**Boom!** You just sent an encrypted message that looks like poetry. 🎉

---

## 🎮 Ways to Use It

### Option 1: Command Line (For the Terminal Warriors)

```bash
# Generate keys
python forgotten_e2ee.py keygen --name YourName --out ./keys

# Encrypt
python forgotten_e2ee.py encrypt \
  --to recipient.id.pub \
  --in message.txt \
  --out encrypted.fg.asc \
  --armor \
  --lexicon lexicons/en.txt

# Decrypt
python forgotten_e2ee.py decrypt \
  --priv your.id.sec \
  --in encrypted.fg.asc \
  --out decrypted.txt \
  --lexicon lexicons/en.txt
```

### Option 2: GUI (For the Click-Happy Folks)

```bash
# Launch the GUI (uses Tkinter - free, no dependencies!)
python launch_gui.py
# OR
python forgotten_e2ee/gui.py
```

Beautiful, intuitive interface with tabs for:
- 🔑 Key generation
- ✉️ Encryption
- 📬 Decryption

### Option 3: Web App (For the Modern Web) 🌐

**Full-featured web interface with ALL capabilities!**

```bash
cd web_app
python app.py
```

Then visit `http://localhost:8080` (or whatever port it shows).

**Or deploy it to DigitalOcean** and embed it on your website! (See [Deployment Guide](web_app/DEPLOYMENT_GUIDE.md))

#### Web App Features (Complete Feature Parity!)

The web app includes **EVERYTHING** from the CLI and GUI:

✅ **Key Generation**
- Generate identity keypairs with custom names
- Optional passphrase encryption (Scrypt + ChaCha20)
- Download keys as `.id.pub` and `.id.sec` files (ZIP download)
- Upload existing key files
- Show fingerprint utility

✅ **Encryption**
- Encrypt messages for recipients
- Steganographic armor (prose output) - **default enabled**
- 9+ lexicon options (English, German, Spanish, French, Italian, Biotech, Cyberpunk, etc.)
- Mapping mode selection (token_map_v1/v2)
- **Message signing** (add authenticity with your secret key)
- File upload for recipient public keys
- File download for encrypted messages

✅ **Decryption**
- Decrypt with secret key (supports passphrase-protected keys)
- Automatic format detection (armor/binary)
- Lexicon selection (must match encryption)
- **Signature verification** (verify sender authenticity)
- File upload for secret keys and encrypted messages
- File download for decrypted plaintext

✅ **LipsumLab Integration** 🎨
- **Language → Themed Ipsum**: Transform any text into themed prose
- **Themed Ipsum → Language**: Reversibly decode back to original
- Multiple theme options (Latin, Cyberpunk, Biotech, etc.)
- Automatic mapping generation and storage
- Perfect for creating deniable encrypted messages

✅ **Advanced Features**
- Fingerprint display utility
- File upload/download support
- Message signing and verification
- Admin dashboard (usage stats, mapping management, theme customization)
- Usage tracking and analytics

✅ **Admin System** 🔐
- Secure admin authentication
- Access to all mapping files (encryption roadmaps)
- Usage statistics and analytics
- UI theme customization
- Site usage tracking

**The web app is NOT a simplified version—it's a complete, feature-rich interface!**

---

## 🔧 Features Deep Dive

### The Crypto Stack

We use **boring, well-audited cryptography** (because exciting crypto usually means broken crypto):

- **X25519** - Elliptic curve key exchange (fast, secure, modern)
- **Ed25519** - Digital signatures (compact, fast, secure)
- **ChaCha20-Poly1305** - Authenticated encryption (what Signal uses)
- **HKDF-SHA256** - Key derivation (the safe way to stretch keys)
- **Scrypt** - Password-based key derivation (protects your keys)

### Complete Feature List 🎯

#### Key Management
- ✅ Generate identity keypairs (Ed25519 + X25519)
- ✅ Passphrase-protected secret keys (optional)
- ✅ Key fingerprint display
- ✅ File upload/download for keys
- ✅ Key encryption with Scrypt + ChaCha20

#### Encryption Features
- ✅ End-to-end encryption (E2EE)
- ✅ Steganographic armor (prose output)
- ✅ 9+ lexicon options (themes and languages)
- ✅ Mapping mode selection (token_map_v1/v2)
- ✅ **Message signing** (Ed25519 signatures for authenticity)
- ✅ Post-quantum hybrid (optional Kyber512)
- ✅ Binary and armor output formats
- ✅ File upload/download support

#### Decryption Features
- ✅ Automatic format detection (armor/binary)
- ✅ Lexicon verification (ensures correct decryption)
- ✅ **Signature verification** (verify sender authenticity)
- ✅ Passphrase support for encrypted keys
- ✅ File upload/download support

#### LipsumLab Integration 🎨
- ✅ **Language → Themed Ipsum**: Transform text into themed prose
- ✅ **Themed Ipsum → Language**: Reversibly decode back
- ✅ Multiple themes (Latin, Cyberpunk, Biotech, etc.)
- ✅ Automatic mapping generation
- ✅ Mapping storage and retrieval
- ✅ Language code support (40+ languages)

#### Web App Features
- ✅ Full-featured web interface
- ✅ File upload/download
- ✅ Real-time encryption/decryption
- ✅ Lexicon selection dropdowns
- ✅ Configuration management
- ✅ Admin dashboard
- ✅ Usage tracking
- ✅ Theme customization

#### Admin System 🔐
- ✅ Secure authentication
- ✅ Mapping file access (encryption roadmaps)
- ✅ Usage statistics
- ✅ Analytics dashboard
- ✅ UI theme management
- ✅ Site monitoring

### Steganographic Armor 🎭

The **really cool part**: your encrypted messages can be disguised as prose using a deterministic token-map. You provide a lexicon (word list), and the system maps ciphertext bits to words, creating beautiful text that looks completely innocent.

**Example output:**
```
-----BEGIN FORGOTTEN MESSAGE-----
Version: 1
Sender-FP: ABC123...
Recipient-FP: XYZ789...
Mode: token_map_v1
Lexicon-Ref: sha256:abc123...
Payload:
luminous whispers drift through velvet shadows where ember thoughts 
kindle in the hush of midnight's embrace. quantum echoes ripple across 
astral planes, each glyph a silent guardian of secrets untold...
-----END FORGOTTEN MESSAGE-----
```

Looks like poetry. **Is actually encrypted data.** Only you and your recipient know the difference.

### Message Signing & Verification ✍️

**Add authenticity to your messages!** Just like PGP, you can sign your encrypted messages to prove they came from you.

**How it works:**
1. **Signing**: When encrypting, provide your secret key (`--sign-priv` in CLI, or signer secret key in web app)
2. **Verification**: When decrypting, provide the sender's public key to verify the signature
3. **Result**: You get a ✅ or ❌ indicating whether the signature is valid

**Why it matters:**
- Proves the message came from the claimed sender
- Prevents tampering (signature won't verify if message was modified)
- Adds an extra layer of trust to your communications

**Example (CLI):**
```bash
# Encrypt with signature
python forgotten_e2ee.py encrypt \
  --to bob.id.pub \
  --in message.txt \
  --out signed.fg.asc \
  --armor \
  --sign-priv alice.id.sec \
  --lexicon lexicons/en.txt

# Decrypt and verify signature
python forgotten_e2ee.py decrypt \
  --priv bob.id.sec \
  --in signed.fg.asc \
  --out verified.txt \
  --sender-pub alice.id.pub \
  --lexicon lexicons/en.txt
```

**In the web app:** Just paste your signer secret key when encrypting, and the sender's public key when decrypting. The interface will show you the verification status!

### LipsumLab: Reversible Themed Ipsum 🎨

**Transform any text into themed prose, then decode it back perfectly!**

LipsumLab is a powerful feature that lets you:
- Convert regular text into themed "Lorem Ipsum" style prose
- Use different themes (Latin, Cyberpunk, Biotech, etc.)
- **Reversibly decode** back to the original text (lossless!)

**Perfect for:**
- Creating deniable encrypted messages
- Hiding plaintext in plain sight
- Artistic text transformation
- Testing steganographic techniques

**Example:**
```bash
# Encode English → Cyberpunk theme
python -m LipsumLab.li_manager
# Choose option 1 (Language → Ipsum)
# Enter your text
# Select theme: cyberpunk
# Get themed output with mapping ID

# Decode back
python -m LipsumLab.li_manager
# Choose option 2 (Ipsum → Language)
# Paste themed text (mapping ID auto-extracted)
# Get original text back!
```

**In the web app:** Use the "LipsumLab" tab to encode/decode text with a beautiful interface!

### File Upload/Download 📁

**No more copy-pasting!** The web app supports full file operations:

- **Upload key files**: Drag and drop `.id.pub` or `.id.sec` files
- **Upload messages**: Upload encrypted messages or plaintext files
- **Download keys**: Get your generated keys as a ZIP file
- **Download encrypted**: Save encrypted messages as `.fg.asc` files
- **Download decrypted**: Save decrypted plaintext as `.txt` files

**How to use:**
1. Click the "Upload" button next to any key/message field
2. Select your file
3. The content is automatically parsed and filled in
4. After encryption/decryption, click "Download" to save results

### Fingerprint Utility 🔍

**Show the fingerprint of any public key!**

Fingerprints are short identifiers (24 hex characters) that uniquely identify a keypair. Use them to:
- Verify you have the correct recipient's key
- Share your identity without revealing the full key
- Check key integrity

**CLI:**
```bash
python forgotten_e2ee.py show-fp --pub alice.id.pub
# Output: abc123def456...
```

**Web App:** Use the "Show Fingerprint" button in the key generation tab, or the dedicated fingerprint utility.

### Post-Quantum Hybrid (Optional)

If you install `pqcrypto`, you get **Kyber512** post-quantum encryption mixed with classical crypto. Future-proof your messages against quantum computers (you know, just in case Skynet happens).

### Admin Dashboard 🔐

**For site administrators:** The web app includes a powerful admin system.

**Features:**
- **Secure Login**: Admin-only access with credentials
- **Usage Statistics**: Track all API calls, user counts, uptime
- **Mapping Management**: Access all LipsumLab mapping files (encryption roadmaps)
- **Theme Customization**: Modify UI colors and styling
- **Analytics**: View recent API calls, success rates, user IPs

**Access:** Navigate to `/admin/login` on your deployed instance.

**Default Credentials** (change in production!):
- Username: `admin`
- Password: Set via `ADMIN_PASSWORD` environment variable

**Security Note:** Mapping files contain the "roadmap" for decryption and are **admin-only** for security. Regular users cannot access them.

---

## 📚 Documentation

- **[Web App Guide](web_app/README.md)** - Deploy and embed the web version
- **[Deployment Guide](web_app/DEPLOYMENT_GUIDE.md)** - Deploy to DigitalOcean
- **[Embedding Guide](web_app/EMBEDDING_GUIDE.md)** - Add to your website
- **[Test Results](web_app/FINAL_TEST_RESULTS.md)** - Comprehensive test suite (53/53 passed! ✅)

---

## 🛡️ Security Notes

**Important things to know:**

- 🔐 Keys are protected with **Scrypt + ChaCha20-Poly1305**
- 🎲 Nonces are derived deterministically (no reuse possible)
- ✅ Armor headers are authenticated (can't be tampered with)
- 🔒 No plaintext metadata leaks in armor mode
- 🚫 **No backdoors. No compromises. No exceptions.**

This is real encryption. Use it responsibly.

---

## 🧪 Testing

We take testing seriously. **53 comprehensive tests** covering:
- Core functionality
- API endpoints
- Deployment scenarios
- Edge cases
- Security checks

Run the test suite:
```bash
cd web_app
python comprehensive_test_suite.py
python deployment_tests.py
python final_validation.py
```

**Result:** ✅ All 53 tests passed!

---

## 🌐 Web Deployment

Want to embed this on your website? We've got you covered:

1. **Deploy to DigitalOcean** (see [Deployment Guide](web_app/DEPLOYMENT_GUIDE.md))
2. **Get your URL**: `https://your-app.ondigitalocean.app`
3. **Embed it:**
   ```html
   <iframe 
       src="https://your-app.ondigitalocean.app/embed" 
       width="100%" 
       height="800" 
       frameborder="0">
   </iframe>
   ```

Done! Your visitors can now encrypt messages directly on your site. 🎉

---

## 🤝 Contributing

Found a bug? Have an idea? Want to add a feature?

1. Fork the repo
2. Create a branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**We welcome contributions!** Especially:
- New lexicon files (different languages, themes)
- UI/UX improvements
- Documentation improvements
- Security audits (please!)

---

## 📜 License

MIT License - Do whatever you want with it. Just don't blame us if you encrypt something you shouldn't have. 😉

See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- **Phil Zimmermann** - For fighting the good fight and inspiring this project
- **The cryptography community** - For the amazing tools and libraries
- **Everyone who values privacy** - You're the reason this exists

---

## ⚠️ Disclaimer

This is encryption software. Use it responsibly. We're not responsible for:
- What you encrypt
- What you decrypt
- Any legal consequences
- Your cat learning to use it (though that would be impressive)

**Remember:** With great encryption comes great responsibility. Use it for good. 🦸

---

## 📞 Support & Questions

- **Issues:** [GitHub Issues](https://github.com/CupofJavad/Anti-Language-Encryption-Tool-/issues)
- **Documentation:** Check the `web_app/` directory for detailed guides
- **Security Issues:** Please report responsibly

---

## 📖 Complete Usage Guide

### Web App: Step-by-Step Tutorial

#### 1. Generate Your Identity

1. Open the web app (local or deployed)
2. Go to "🔑 Generate Keys" tab
3. Enter your name (e.g., "Alice")
4. (Optional) Enter a passphrase to encrypt your secret key
5. Click "Generate Keys"
6. **Download your keys** using the download button (saves as ZIP)
7. **Save your secret key securely** - you'll need it to decrypt messages!

#### 2. Encrypt a Message

1. Go to "✉️ Encrypt" tab
2. **Upload or paste** recipient's public key (`.id.pub` file or JSON)
3. Type or paste your message
4. **Select a lexicon** (e.g., "English" for normal prose, "Cyberpunk" for sci-fi theme)
5. (Optional) **Sign the message**: Upload your secret key to add authenticity
6. Click "Encrypt"
7. **Download the encrypted message** (saves as `.fg.asc` file)
8. Share it with your recipient!

#### 3. Decrypt a Message

1. Go to "📬 Decrypt" tab
2. **Upload or paste** your secret key (`.id.sec` file or JSON)
3. Enter passphrase if your key is encrypted
4. **Upload or paste** the encrypted message (`.fg.asc` file or armor text)
5. **Select the lexicon** used during encryption (must match!)
6. (Optional) **Verify signature**: Upload sender's public key to verify authenticity
7. Click "Decrypt"
8. View your decrypted message!
9. **Download the plaintext** if needed

#### 4. Use LipsumLab (Themed Ipsum)

1. Go to "🎨 LipsumLab" tab (if available)
2. **Encode (Language → Ipsum)**:
   - Enter your text
   - Select source language
   - Choose a theme (Latin, Cyberpunk, Biotech, etc.)
   - Click "Encode"
   - Copy the themed output (includes mapping ID in header)
3. **Decode (Ipsum → Language)**:
   - Paste the themed text
   - Mapping ID is auto-extracted from header
   - Click "Decode"
   - Get your original text back!

#### 5. Show Fingerprint

1. Go to "🔑 Generate Keys" tab
2. Click "Show Fingerprint" button
3. Paste a public key (`.id.pub` file or JSON)
4. View the 24-character fingerprint
5. Use it to verify key identity!

### Advanced Features Explained

#### Message Signing

**What it does:** Adds a cryptographic signature proving the message came from you.

**When to use:**
- Important communications where authenticity matters
- Business transactions
- Legal documents
- Any situation where you need to prove you sent the message

**How it works:**
1. You encrypt with your secret key (signer key)
2. System creates Ed25519 signature
3. Recipient verifies with your public key
4. ✅ = Valid signature, message is authentic
5. ❌ = Invalid signature, message may be tampered with

#### Signature Verification

**What it does:** Verifies that a signed message actually came from the claimed sender.

**When to use:**
- When receiving signed messages
- To detect tampering
- To verify sender identity

**How it works:**
1. Message includes signature in armor header
2. You provide sender's public key
3. System verifies signature cryptographically
4. Result shows verification status

#### Lexicon Selection

**What it does:** Chooses the vocabulary theme for steganographic armor output.

**Available lexicons:**
- `en.txt` - English (default)
- `de.txt` - German
- `es.txt` - Spanish
- `fr.txt` - French
- `it.txt` - Italian
- `biotech.txt` - Biotech/scientific terms
- `cyberpunk.txt` - Cyberpunk/sci-fi theme
- `english.txt` - Alternative English
- `fl_custom_full_lexicon.txt` - Custom full lexicon

**Important:** The lexicon used for encryption **MUST** match the lexicon used for decryption, or decryption will fail!

#### Mapping Modes

- **token_map_v1** (default): Original mapping algorithm
- **token_map_v2** (experimental): Alternative mapping algorithm

Both modes are compatible, but v2 may produce different prose output for the same input.

## 🎯 Roadmap

- [x] Complete feature parity (CLI → Web App) ✅
- [x] File upload/download ✅
- [x] Message signing and verification ✅
- [x] LipsumLab web interface ✅
- [x] Admin dashboard ✅
- [ ] More lexicon options (themes, languages)
- [ ] Mobile app (maybe?)
- [ ] Browser extension
- [ ] Group messaging support
- [ ] Your idea here! (seriously, suggest it)

---

<div align="center">

**Made with 🔐 and ❤️ for privacy advocates everywhere**

*"If privacy is outlawed, only outlaws will have privacy."*  
— Phil Zimmermann

[⭐ Star this repo](https://github.com/CupofJavad/Anti-Language-Encryption-Tool-) | [🐛 Report Bug](https://github.com/CupofJavad/Anti-Language-Encryption-Tool-/issues) | [💡 Request Feature](https://github.com/CupofJavad/Anti-Language-Encryption-Tool-/issues)

</div>
