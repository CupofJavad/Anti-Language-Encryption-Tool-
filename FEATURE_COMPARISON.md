# 🔍 COMPREHENSIVE FEATURE COMPARISON
## Original CLI/GUI vs Web App (MVP Failure Analysis)

**Date**: 2025-12-25  
**Purpose**: Document ALL features from original implementations and compare to web app

---

## 📋 CLI FEATURES (forgotten_e2ee/cli.py)

### Command: `keygen`
- ✅ `--name` (required): Identity name
- ✅ `--out` (required): Output directory for keys
- ✅ `--no-pass`: Skip passphrase (store raw keys)
- ✅ **Passphrase prompt**: Interactive `getpass.getpass()` if not `--no-pass`
- ✅ **File output**: Creates `<name>.id.pub` and `<name>.id.sec`
- ✅ **Key encryption**: Uses Scrypt + ChaCha20 if passphrase provided

### Command: `show-fp`
- ✅ `--pub` (required): Show fingerprint from public key file
- ❌ **MISSING IN WEB**: No fingerprint display utility

### Command: `encrypt`
- ✅ `--to` (required): Recipient public key file path
- ✅ `--in` (required): Input file (or `-` for stdin)
- ✅ `--out` (required): Output file path
- ✅ `--armor`: Enable steganographic armor (prose output)
- ✅ `--lexicon`: Lexicon file path (required for armor)
- ✅ `--mode`: Mapping mode (default: `token_map_v1`)
- ✅ `--sign-priv`: Optional signer secret key file (adds authenticity)
- ✅ **Post-quantum support**: Auto-detects Kyber512 in recipient bundle
- ✅ **Signature support**: Ed25519 signing if `--sign-priv` provided
- ✅ **Binary output**: If no `--armor`, outputs raw binary
- ✅ **Armor output**: If `--armor`, outputs prose with headers
- ✅ **File I/O**: Reads from file/stdin, writes to file

### Command: `decrypt`
- ✅ `--priv` (required): Your secret key file path
- ✅ `--in` (required): Encrypted input file
- ✅ `--out` (required): Decrypted output file path
- ✅ `--lexicon`: Lexicon file path (required for armor decryption)
- ✅ `--no-pass`: Skip passphrase prompt
- ✅ `--sender-pub`: Optional sender public key for signature verification
- ✅ **Passphrase prompt**: Interactive if key is encrypted and not `--no-pass`
- ✅ **Auto-detect format**: Tries armor first, falls back to binary
- ✅ **Lexicon verification**: Checks lexicon hash matches
- ✅ **Signature verification**: Verifies Ed25519 signature if present
- ✅ **File I/O**: Reads from file, writes to file

---

## 📋 GUI FEATURES (forgotten_e2ee/gui.py)

### Key Generation Frame
- ✅ **Name input**: Text field with tooltip
- ✅ **Output directory**: Folder browser (`FolderBrowse`)
- ✅ **Create Identity button**: Triggers CLI `keygen --no-pass`
- ✅ **Status bar**: Shows success/error messages
- ✅ **File output**: Creates `.id.pub` and `.id.sec` files

### Encryption Frame
- ✅ **Recipient public key**: File browser (`FileBrowse`) for `.id.pub`
- ✅ **Message input**: Multiline text area (72x8 chars)
- ✅ **Armor checkbox**: Default checked
- ✅ **Lexicon selection**: File browser (`FileBrowse`) with default `lexicons/en.txt`
- ✅ **Signer secret key**: Optional file browser for `.id.sec` (adds authenticity)
- ✅ **Output filename**: Text input with default `message.fg.asc`
- ✅ **Encrypt button**: Triggers CLI `encrypt` with all options
- ✅ **Status bar**: Shows success/error messages
- ✅ **File output**: Saves encrypted message to file

### Decryption Frame
- ✅ **Secret key**: File browser (`FileBrowse`) for `.id.sec`
- ✅ **Encrypted message file**: File browser for `.fg.asc` or `.fg.bin`
- ✅ **Output filename**: Text input with default `plain.txt`
- ✅ **Lexicon selection**: File browser with default `lexicons/en.txt`
- ✅ **Decrypt button**: Triggers CLI `decrypt --no-pass` with lexicon
- ✅ **Status bar**: Shows success/error messages
- ✅ **File output**: Saves decrypted plaintext to file

### GUI General Features
- ✅ **Theme**: DarkBlue14 (PySimpleGUI theme)
- ✅ **Welcome frame**: Instructions and guidance
- ✅ **Resizable window**: `resizable=True`
- ✅ **Tooltips**: Every field has helpful tooltips
- ✅ **Status bar**: Real-time feedback at bottom

---

## 📋 LIPSUMLAB FEATURES (LipsumLab/li_manager.py)

### Language → Ipsum Encoding
- ✅ **Language code picker**: Shows all ISO language codes with lexicon availability
- ✅ **Theme selection**: Choose from available lexicons in `./lexicons/`
- ✅ **Language-matched theme**: Option to use theme matching language code
- ✅ **Lexicon builder**: Can build missing lexicons from corpus files
- ✅ **Input methods**: Paste interactively OR read from file
- ✅ **Mapping generation**: Creates UUID-based reversible mapping
- ✅ **Mapping storage**: Saves to `./mappings/<UUID>.json`
- ✅ **Output storage**: Saves to `./LanguageToIpsum/<Lang>To<Theme>_<timestamp>.txt`
- ✅ **Header embedding**: Embeds `[LI-MAP-ID: <UUID>]` in output

### Ipsum → Language Decoding
- ✅ **Input methods**: Paste interactively OR read from file
- ✅ **Mapping ID extraction**: Auto-extracts from header OR prompts for UUID
- ✅ **Mapping lookup**: Loads mapping from `./mappings/<UUID>.json`
- ✅ **Output storage**: Saves to `./IpsumToLanguage/<Theme>To<Lang>_<timestamp>.txt`
- ✅ **Metadata display**: Shows theme, language, creation date

### Lexicon Management
- ✅ **Auto-discovery**: Scans `./lexicons/*.txt` and `*.lex`
- ✅ **Lexicon display**: Shows word count and sample words
- ✅ **Language code matching**: Marks which language codes have lexicons
- ✅ **Lexicon building**: Can build from corpus files
- ✅ **Multiple lexicons**: Supports 9+ lexicons (en, de, es, fr, it, biotech, cyberpunk, etc.)

---

## 📋 WEB APP FEATURES (Current State)

### Key Generation
- ✅ Name input
- ✅ Passphrase input (optional)
- ✅ Key generation
- ✅ JSON output (not file output)
- ❌ **MISSING**: File download option
- ❌ **MISSING**: Output directory selection
- ❌ **MISSING**: `show-fp` utility

### Encryption
- ✅ Recipient public key input (JSON paste)
- ✅ Message input (textarea)
- ✅ Armor checkbox (default checked)
- ✅ Lexicon dropdown (9 lexicons)
- ✅ Mode selection (token_map_v1/v2)
- ✅ JSON output (not file output)
- ❌ **MISSING**: File upload for recipient key
- ❌ **MISSING**: Signer secret key (signing support)
- ❌ **MISSING**: File download option
- ❌ **MISSING**: Output filename selection

### Decryption
- ✅ Secret key input (JSON paste)
- ✅ Encrypted message input (textarea)
- ✅ Passphrase input (for encrypted keys)
- ✅ Lexicon dropdown
- ✅ Plaintext output
- ❌ **MISSING**: File upload for secret key
- ❌ **MISSING**: File upload for encrypted message
- ❌ **MISSING**: Sender public key (signature verification)
- ❌ **MISSING**: File download option
- ❌ **MISSING**: Output filename selection

### Configuration Tab
- ✅ Mapping mode selection
- ✅ Lexicon directory info
- ✅ Lexicon count display
- ✅ Mappings list (LipsumLab mappings)
- ✅ Advanced options checkboxes
- ❌ **MISSING**: Actual functionality for advanced options
- ❌ **MISSING**: Theme customization
- ❌ **MISSING**: Admin access

### Missing Features Summary
1. ❌ **File I/O**: No file upload/download
2. ❌ **Signing**: No signer secret key support
3. ❌ **Signature verification**: No sender public key option
4. ❌ **Fingerprint utility**: No `show-fp` equivalent
5. ❌ **LipsumLab integration**: No Language→Ipsum/Ipsum→Language UI
6. ❌ **Mapping management**: Can view but not create/use mappings
7. ❌ **Admin system**: No admin authentication
8. ❌ **Usage tracking**: No analytics
9. ❌ **Theme management**: No UI customization
10. ❌ **Mapping file security**: Mappings visible to all users (should be admin-only)

---

## 🔐 LEXICON COMPARISON

### Available Lexicons
**Root lexicons/**: 9 lexicons
- biotech.txt
- cyberpunk.txt
- de.txt
- en.txt
- english.txt
- es.txt
- fl_custom_full_lexicon.txt
- fr.txt
- it.txt

**LipsumLab/lexicons/**: 9 lexicons (same as root)

**Web App Access**: ✅ All 9 lexicons accessible via dropdown

---

## 🗺️ MAPPING SYSTEM COMPARISON

### LipsumLab Mappings
**Location**: `LipsumLab/mappings/`
**Format**: JSON files with UUID names
**Contents**:
- `id`: Mapping UUID
- `created`: Unix timestamp
- `source_lang`: Source language code
- `theme_key`: Lexicon key used
- `theme_name`: Display name
- `forward_map`: Dictionary of source→theme word mappings

**Current Mappings Found**: 3
- 30f3bf00-58b9-45bc-ac3e-91faff8ccb69.json
- 555eedb4-fc69-46dc-ae9c-4dc2b7190fbb.json
- ae4d2d88-a755-4a40-8aeb-a2e5efc21a8e.json

### Security Issue
❌ **CRITICAL**: Mapping files are currently accessible to ALL users via `/api/mappings`
❌ **CRITICAL**: Mapping files contain the "roadmap" for decryption - should be ADMIN-ONLY
✅ **REQUIRED**: Admin authentication to access mapping files
✅ **REQUIRED**: Regular users should NOT see mapping UUIDs or contents

---

## 📊 FEATURE PARITY SCORE

| Category | CLI | GUI | Web App | Status |
|----------|-----|-----|---------|--------|
| Key Generation | 5/5 | 4/5 | 3/5 | ⚠️ Partial |
| Encryption | 8/8 | 7/8 | 5/8 | ⚠️ Partial |
| Decryption | 7/7 | 6/7 | 4/7 | ⚠️ Partial |
| File I/O | ✅ | ✅ | ❌ | ❌ Missing |
| Signing | ✅ | ✅ | ❌ | ❌ Missing |
| Lexicon Management | ✅ | ✅ | ⚠️ | ⚠️ Partial |
| Mapping System | ✅ | N/A | ⚠️ | ⚠️ Partial |
| Admin System | N/A | N/A | ❌ | ❌ Missing |

**Overall Score**: CLI: 100% | GUI: 85% | Web App: 45%

---

## 🚨 CRITICAL MISSING FEATURES

1. **File Upload/Download**: Users can't upload key files or download results
2. **Signing Support**: No way to sign messages (adds authenticity)
3. **Signature Verification**: No way to verify sender signatures
4. **Fingerprint Utility**: No way to display/show fingerprints
5. **LipsumLab UI**: No web interface for Language→Ipsum encoding
6. **Admin Authentication**: No admin login system
7. **Mapping Security**: Mappings exposed to all users (should be admin-only)
8. **Usage Tracking**: No analytics or usage monitoring
9. **Theme Management**: No UI customization for admins
10. **Advanced Options**: Checkboxes exist but don't do anything

---

## ✅ NEXT STEPS REQUIRED

1. **Implement Admin System**
   - Admin login with credentials
   - Session management
   - Admin dashboard

2. **Secure Mapping Files**
   - Remove public access to `/api/mappings`
   - Admin-only endpoint for mapping files
   - Hide mapping UUIDs from regular users

3. **Add Missing Features**
   - File upload/download
   - Signing support
   - Signature verification
   - Fingerprint utility
   - LipsumLab web UI

4. **Usage Tracking**
   - Log all API calls
   - Track user actions
   - Admin dashboard with analytics

5. **Theme Management**
   - Admin UI for theme customization
   - CSS variable system
   - Theme preview/apply

---

**Document Status**: Complete  
**Last Updated**: 2025-12-25

