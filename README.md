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

### Option 3: Web App (For the Modern Web)

```bash
cd web_app
python app.py
```

Then visit `http://localhost:8080` (or whatever port it shows).

**Or deploy it to DigitalOcean** and embed it on your website! (See [Deployment Guide](web_app/DEPLOYMENT_GUIDE.md))

---

## 🔧 Features Deep Dive

### The Crypto Stack

We use **boring, well-audited cryptography** (because exciting crypto usually means broken crypto):

- **X25519** - Elliptic curve key exchange (fast, secure, modern)
- **Ed25519** - Digital signatures (compact, fast, secure)
- **ChaCha20-Poly1305** - Authenticated encryption (what Signal uses)
- **HKDF-SHA256** - Key derivation (the safe way to stretch keys)
- **Scrypt** - Password-based key derivation (protects your keys)

### Steganographic Armor 🎭

The **really cool part**: your encrypted messages can be disguised as prose using a deterministic token-map. You provide a lexicon (word list), and the system maps ciphertext bits to words, creating beautiful text that looks completely innocent.

**Example output:**
```
-----BEGIN FORGOTTEN MESSAGE-----
Version: 1
Sender-FP: ABC123...
Recipient-FP: XYZ789...
Payload:
luminous whispers drift through velvet shadows where ember thoughts 
kindle in the hush of midnight's embrace. quantum echoes ripple across 
astral planes, each glyph a silent guardian of secrets untold...
-----END FORGOTTEN MESSAGE-----
```

Looks like poetry. **Is actually encrypted data.** Only you and your recipient know the difference.

### Post-Quantum Hybrid (Optional)

If you install `pqcrypto`, you get **Kyber512** post-quantum encryption mixed with classical crypto. Future-proof your messages against quantum computers (you know, just in case Skynet happens).

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

## 🎯 Roadmap

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
