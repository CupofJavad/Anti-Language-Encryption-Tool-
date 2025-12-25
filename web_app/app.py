#!/usr/bin/env python3
"""
Forgotten-E2EE Web Application
Flask-based web interface for encryption/decryption
"""
import os
import sys
from pathlib import Path

# Add project root to Python path
# Handle both running from root and from web_app directory
if Path(__file__).parent.name == 'web_app':
    project_root = Path(__file__).parent.parent
else:
    project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for, send_file
from flask_cors import CORS
from functools import wraps
import json
import hashlib
from datetime import datetime
import tempfile
import os
from werkzeug.utils import secure_filename
from forgotten_e2ee.keystore import Identity, save_public, save_secret, load_secret, load_public
from forgotten_e2ee.crypto_core import (
    ed25519_keypair, x25519_keypair, raw_pub_bytes_ed, raw_pub_bytes_x,
    raw_priv_bytes_ed, raw_priv_bytes_x, hkdf, aead_encrypt, aead_decrypt,
    ed_sign, ed_verify, sha256_hex
)
from forgotten_e2ee.fmt import FGHeader, emit_armor, parse_armor
from forgotten_e2ee.util import b64u_enc, b64u_dec, hex24, now_s, secure_random
from forgotten_e2ee.stego import load_lexicon, lexicon_hash, encode_token_map, decode_token_map
from forgotten_e2ee.errors import ESig, EDecrypt, ELexicon
from forgotten_e2ee.pq import hybrid_secret

app = Flask(__name__, template_folder='templates')
CORS(app)

# Production configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
app.config['TESTING'] = False

# Admin credentials (basic - should be changed in production)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'ForgottenE2EE2025!')  # Change this!

# Usage tracking storage (in-memory for now, should use DB in production)
usage_stats = {
    'total_requests': 0,
    'keygen_count': 0,
    'encrypt_count': 0,
    'decrypt_count': 0,
    'api_calls': [],
    'user_ips': set(),
    'start_time': datetime.now().isoformat()
}

def track_usage(endpoint, ip_address, success=True):
    """Track API usage"""
    usage_stats['total_requests'] += 1
    usage_stats['user_ips'].add(ip_address)
    if endpoint == 'keygen':
        usage_stats['keygen_count'] += 1
    elif endpoint == 'encrypt':
        usage_stats['encrypt_count'] += 1
    elif endpoint == 'decrypt':
        usage_stats['decrypt_count'] += 1
    
    usage_stats['api_calls'].append({
        'timestamp': datetime.now().isoformat(),
        'endpoint': endpoint,
        'ip': ip_address,
        'success': success
    })
    # Keep only last 1000 calls
    if len(usage_stats['api_calls']) > 1000:
        usage_stats['api_calls'] = usage_stats['api_calls'][-1000:]

def admin_required(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({'success': False, 'error': 'Admin authentication required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Find lexicon directory
LEXICON_DIR = project_root / 'lexicons'
DEFAULT_LEXICON = LEXICON_DIR / 'en.txt' if (LEXICON_DIR / 'en.txt').exists() else None

@app.route('/')
def index():
    """Main interface"""
    response = make_response(render_template('index.html'))
    # Add cache-busting headers
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/embed')
def embed():
    """Embeddable version"""
    response = make_response(render_template('embed.html'))
    # Add cache-busting headers
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/api/lexicons', methods=['GET'])
def api_list_lexicons():
    """List available lexicons"""
    try:
        lexicons = []
        if LEXICON_DIR.exists():
            for lex_file in sorted(LEXICON_DIR.glob('*.txt')):
                lexicons.append({
                    'name': lex_file.name,
                    'path': str(lex_file.relative_to(project_root)),
                    'display_name': lex_file.stem.replace('_', ' ').title()
                })
        return jsonify({
            'success': True,
            'lexicons': lexicons,
            'default': 'en.txt' if (LEXICON_DIR / 'en.txt').exists() else (lexicons[0]['name'] if lexicons else None)
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

# Mapping endpoints REMOVED from public access - now admin-only
# Mappings contain encryption roadmaps and should not be accessible to regular users

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page and authentication"""
    if request.method == 'GET':
        return render_template('admin_login.html')
    
    data = request.get_json() or request.form
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session['admin_login_time'] = datetime.now().isoformat()
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard (requires authentication)"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/api/admin/mappings', methods=['GET'])
@admin_required
def api_admin_list_mappings():
    """List available mappings (ADMIN ONLY - includes full mapping data)"""
    try:
        mappings = []
        mappings_dir = project_root / 'LipsumLab' / 'mappings'
        if mappings_dir.exists():
            for map_file in sorted(mappings_dir.glob('*.json')):
                try:
                    import json
                    with open(map_file, 'r', encoding='utf-8') as f:
                        map_data = json.load(f)
                    mappings.append({
                        'id': map_data.get('id', map_file.stem),
                        'created': map_data.get('created'),
                        'source_lang': map_data.get('source_lang', 'unknown'),
                        'theme_key': map_data.get('theme_key', ''),
                        'theme_name': map_data.get('theme_name', ''),
                        'map_size': len(map_data.get('forward_map', {})),
                        'forward_map': map_data.get('forward_map', {}),  # Full mapping (admin only)
                        'file_path': str(map_file.relative_to(project_root))
                    })
                except Exception:
                    continue
        return jsonify({
            'success': True,
            'mappings': mappings
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/admin/mapping/<map_id>', methods=['GET'])
@admin_required
def api_admin_get_mapping(map_id):
    """Get full mapping details (ADMIN ONLY)"""
    try:
        mappings_dir = project_root / 'LipsumLab' / 'mappings'
        map_file = mappings_dir / f'{map_id}.json'
        if not map_file.exists():
            return jsonify({'success': False, 'error': 'Mapping not found'}), 404
        
        import json
        with open(map_file, 'r', encoding='utf-8') as f:
            map_data = json.load(f)
        
        return jsonify({
            'success': True,
            'mapping': map_data  # Full mapping data (admin only)
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_admin_stats():
    """Get usage statistics (ADMIN ONLY)"""
    try:
        stats = {
            'total_requests': usage_stats['total_requests'],
            'keygen_count': usage_stats['keygen_count'],
            'encrypt_count': usage_stats['encrypt_count'],
            'decrypt_count': usage_stats['decrypt_count'],
            'unique_users': len(usage_stats['user_ips']),
            'start_time': usage_stats['start_time'],
            'recent_calls': usage_stats['api_calls'][-100:],  # Last 100 calls
            'uptime_seconds': (datetime.now() - datetime.fromisoformat(usage_stats['start_time'])).total_seconds()
        }
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/admin/theme', methods=['GET', 'POST'])
@admin_required
def api_admin_theme():
    """Get or update UI theme (ADMIN ONLY)"""
    theme_file = project_root / 'web_app' / 'theme_config.json'
    
    if request.method == 'GET':
        try:
            if theme_file.exists():
                with open(theme_file, 'r') as f:
                    theme = json.load(f)
            else:
                # Default theme
                theme = {
                    'primary_color': '#667eea',
                    'secondary_color': '#764ba2',
                    'background_gradient': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    'text_color': '#333333',
                    'border_radius': '12px'
                }
            return jsonify({'success': True, 'theme': theme})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # POST - Update theme
    try:
        data = request.get_json()
        theme = data.get('theme', {})
        with open(theme_file, 'w') as f:
            json.dump(theme, f, indent=2)
        return jsonify({'success': True, 'message': 'Theme updated'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/config', methods=['GET'])
def api_get_config():
    """Get configuration options"""
    try:
        return jsonify({
            'success': True,
            'config': {
                'modes': [
                    {'value': 'token_map_v1', 'label': 'Token Map v1 (Default)'},
                    {'value': 'token_map_v2', 'label': 'Token Map v2 (Experimental)'},
                ],
                'default_mode': 'token_map_v1',
                'lexicon_dir': str(LEXICON_DIR.relative_to(project_root)),
                'mappings_dir': 'LipsumLab/mappings (admin-only)'
            }
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/keygen', methods=['POST'])
def api_keygen():
    """Generate a new identity keypair"""
    try:
        # Track usage
        track_usage('keygen', request.remote_addr)
        data = request.get_json() or {}
        name = data.get('name', 'Anonymous')
        passphrase = data.get('passphrase', '')  # Optional passphrase
        
        # Generate keys
        ed_priv, ed_pub = ed25519_keypair()
        x_priv, x_pub = x25519_keypair()
        
        # Create identity (only takes ed_priv and x_priv)
        identity = Identity(ed_priv, x_priv)
        
        # Serialize public key bundle (like save_public does)
        pub = raw_pub_bytes_ed(ed_pub)
        dhp = raw_pub_bytes_x(x_pub)
        public_bundle = {
            "version": 1,
            "type": "fg-public",
            "name": name,
            "ed25519_pub": b64u_enc(pub),
            "x25519_pub": b64u_enc(dhp),
            "fingerprint": hex24(bytes.fromhex(sha256_hex(pub + dhp))),
        }
        
        # Serialize secret key bundle (like save_secret does, but in memory)
        from forgotten_e2ee.crypto_core import raw_priv_bytes_ed, raw_priv_bytes_x, scrypt_key, aead_encrypt
        ed_raw = raw_priv_bytes_ed(ed_priv)
        x_raw = raw_priv_bytes_x(x_priv)
        
        # Support passphrase encryption (like CLI does)
        if passphrase:
            import os
            salt = os.urandom(16)
            key = scrypt_key(passphrase, salt, 32)
            nonce = os.urandom(12)
            ct = aead_encrypt(key, nonce, b"fg-sec", b"ED"+ed_raw+b"XK"+x_raw)
            secret_bundle = {
                "version": 1,
                "type": "fg-secret",
                "payload": {
                    "enc": "scrypt+chacha20",
                    "salt": b64u_enc(salt),
                    "nonce": b64u_enc(nonce),
                    "ct": b64u_enc(ct)
                }
            }
        else:
            # Store as raw (no passphrase)
            secret_bundle = {
                "version": 1,
                "type": "fg-secret",
                "payload": {
                    "enc": "raw",
                    "ed": b64u_enc(ed_raw),
                    "xk": b64u_enc(x_raw)
                }
            }
        
        return jsonify({
            'success': True,
            'public_key': json.dumps(public_bundle),
            'secret_key': json.dumps(secret_bundle),
            'name': name,
            'fingerprint': public_bundle['fingerprint'],
            'encrypted': bool(passphrase)
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

def _transcript(sender_fp: str, recip_fp: str, eph_pub: bytes) -> bytes:
    """Create transcript for key derivation"""
    return b"fg-v1|" + eph_pub + b"|" + sender_fp.encode() + b"|" + recip_fp.encode()

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """Encrypt a message"""
    try:
        # Track usage
        track_usage('encrypt', request.remote_addr)
        data = request.get_json() or {}
        recipient_pub_json = data.get('recipient_pub')
        plaintext = data.get('plaintext', '')
        # Default to armor=True (steganographic prose output is the main feature)
        armor = data.get('armor', True)
        mode = data.get('mode', 'token_map_v1')  # Mapping mode (like CLI --mode)
        lexicon_name = data.get('lexicon')  # Can be filename like "en.txt" or "cyberpunk.txt"
        lexicon_path = None
        
        # Resolve lexicon path (like CLI/GUI do)
        if lexicon_name:
            # If it's a filename, look in lexicons directory
            if not os.path.isabs(lexicon_name) and not os.path.exists(lexicon_name):
                lexicon_path = LEXICON_DIR / lexicon_name
            else:
                lexicon_path = Path(lexicon_name)
        elif DEFAULT_LEXICON and DEFAULT_LEXICON.exists():
            lexicon_path = DEFAULT_LEXICON
        
        if not recipient_pub_json:
            return jsonify({'success': False, 'error': 'recipient_pub required'}), 400
        
        # Parse recipient public key bundle
        if isinstance(recipient_pub_json, str):
            recip_bundle = json.loads(recipient_pub_json)
        else:
            recip_bundle = recipient_pub_json
        
        # Load recipient public keys
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        ed_r = ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(recip_bundle["ed25519_pub"]))
        x_r = x25519.X25519PublicKey.from_public_bytes(b64u_dec(recip_bundle["x25519_pub"]))
        recip_fp = recip_bundle.get("fingerprint") or hex24(bytes.fromhex(sha256_hex(raw_pub_bytes_ed(ed_r) + raw_pub_bytes_x(x_r))))
        
        # Convert plaintext to bytes
        data_bytes = plaintext.encode('utf-8')
        
        # Generate ephemeral keypair
        eph_sk, eph_pk = x25519_keypair()
        eph_pub = raw_pub_bytes_x(eph_pk)
        
        # Optional PQ hybrid (if available)
        pq_ct = b""
        pq_ss = b""
        if "kyber512_pub" in recip_bundle and recip_bundle["kyber512_pub"]:
            try:
                from forgotten_e2ee.pq import kyber_encapsulate
                pq_ct, pq_ss = kyber_encapsulate(b64u_dec(recip_bundle["kyber512_pub"]))
            except Exception:
                pq_ct, pq_ss = b"", b""
        
        # Optional sender signature (like CLI --sign-priv)
        sender_fp = "0" * 24
        ed_sender = None
        signer_secret_json = data.get('signer_secret')  # Optional signer secret key
        signer_passphrase = data.get('signer_passphrase', '')
        
        if signer_secret_json:
            # Load signer identity
            if isinstance(signer_secret_json, str):
                signer_bundle = json.loads(signer_secret_json)
            else:
                signer_bundle = signer_secret_json
            
            from forgotten_e2ee.crypto_core import scrypt_key, aead_decrypt
            payload = signer_bundle["payload"]
            if payload["enc"] == "raw":
                ed_raw = b64u_dec(payload["ed"])
                x_raw = b64u_dec(payload["xk"])
            elif payload["enc"] == "scrypt+chacha20":
                if not signer_passphrase:
                    return jsonify({'success': False, 'error': 'Signer passphrase required for encrypted signer key'}), 400
                salt = b64u_dec(payload["salt"])
                nonce = b64u_dec(payload["nonce"])
                ct = b64u_dec(payload["ct"])
                key = scrypt_key(signer_passphrase, salt, 32)
                decrypted = aead_decrypt(key, nonce, b"fg-sec", ct)
                ed_raw = decrypted[2:34]  # Skip "ED" prefix
                x_raw = decrypted[36:]   # Skip "XK" prefix
            else:
                return jsonify({'success': False, 'error': 'Invalid signer key format'}), 400
            
            # Create signer identity
            from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
            from cryptography.hazmat.primitives import serialization
            ed_sender_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed_raw)
            x_sender_priv = x25519.X25519PrivateKey.from_private_bytes(x_raw)
            ed_sender = ed_sender_priv
            
            # Calculate sender fingerprint
            ed_sender_pub = ed_sender_priv.public_key()
            x_sender_pub = x_sender_priv.public_key()
            sender_fp = hex24(bytes.fromhex(sha256_hex(raw_pub_bytes_ed(ed_sender_pub) + raw_pub_bytes_x(x_sender_pub))))
        
        # ECDH shared secret
        shared = eph_sk.exchange(x_r)
        transcript = _transcript(sender_fp, recip_fp, eph_pub)
        
        # Hybrid session key
        key = hybrid_secret(hkdf, transcript, shared, pq_ss if pq_ss else None)
        
        # Create header
        session_id = int.from_bytes(secure_random(8), "big")
        seq = 0
        nonce = hkdf(b"fg-v1|nonce", eph_pub + session_id.to_bytes(8, "big") + seq.to_bytes(8, "big"), length=12)
        thash = hkdf(b"fg-v1|th", transcript, b"", 32)
        flags = 0x01 if pq_ct else 0x00
        if ed_sender:
            flags |= 0x02  # Set signature flag
        header = FGHeader(version=1, flags=flags, ts_unix=now_s(), sender_fp=sender_fp,
                         session_id=session_id, seq=seq, nonce=nonce, transcript_hash=thash)
        header_bytes = header.to_bytes()
        aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
        
        # Encrypt
        ct = aead_encrypt(key, nonce, aad, data_bytes)
        
        # Sign if sender key provided
        sig = b""
        if ed_sender:
            sig = ed_sign(ed_sender, sha256_hex(header_bytes + eph_pub + (pq_ct or b"") + ct).encode())
        
        if not armor:
            # Binary output (include signature if present)
            output = b64u_enc(header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"") + ct + (sig if sig else b""))
            return jsonify({
                'success': True,
                'output': output,
                'format': 'binary',
                'signed': bool(sig)
            })
        
        # Armor with steganography
        if lexicon_path and os.path.exists(lexicon_path):
            tokens = load_lexicon(lexicon_path)
        elif DEFAULT_LEXICON and DEFAULT_LEXICON.exists():
            tokens = load_lexicon(str(DEFAULT_LEXICON))
        else:
            # Fallback to default lexicon loading (uses fallback if needed)
            tokens = load_lexicon(None)
            if not tokens or len(tokens) < 64:
                return jsonify({'success': False, 'error': 'Lexicon required for armor mode. Please ensure lexicons/en.txt exists.'}), 400
        
        lxref = lexicon_hash(tokens)
        prose = encode_token_map(ct, key, nonce, tokens)
        hdr_fields = {
            "Version": "1",
            "Sender-FP": sender_fp,
            "Recipient-FP": recip_fp,
            "Session": str(session_id),
            "Seq": str(seq),
            "Mode": mode,  # Use configurable mode
            "Lexicon-Ref": lxref,
            "Ts": str(header.ts_unix),
            "Nonce": b64u_enc(nonce),
            "Eph": b64u_enc(eph_pub),
        }
        if pq_ct:
            hdr_fields["PQ"] = b64u_enc(pq_ct)
        if sig:
            hdr_fields["Sig"] = b64u_enc(sig)
        # Include Ciphertext-B64 for decryption compatibility
        hdr_fields["Ciphertext-B64"] = b64u_enc(ct)
        armor_output = emit_armor(hdr_fields, prose)
        
        result = jsonify({
            'success': True,
            'output': armor_output,
            'format': 'armor',
            'signed': bool(sig)  # Include signing status in armor response too
        })
        track_usage('encrypt', request.remote_addr, True)
        return result
    except Exception as e:
        import traceback
        track_usage('encrypt', request.remote_addr, False)
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """Decrypt a message"""
    try:
        # Track usage
        track_usage('decrypt', request.remote_addr)
        data = request.get_json() or {}
        secret_key_json = data.get('secret_key')
        encrypted_data = data.get('encrypted_data')
        passphrase = data.get('passphrase', '')  # Optional passphrase for encrypted secret keys
        lexicon_name = data.get('lexicon')  # Can be filename like "en.txt"
        lexicon_path = None
        
        # Resolve lexicon path (like CLI/GUI do)
        if lexicon_name:
            if not os.path.isabs(lexicon_name) and not os.path.exists(lexicon_name):
                lexicon_path = LEXICON_DIR / lexicon_name
            else:
                lexicon_path = Path(lexicon_name)
        
        if not secret_key_json or not encrypted_data:
            return jsonify({'success': False, 'error': 'secret_key and encrypted_data required'}), 400
        
        # Parse secret key bundle
        if isinstance(secret_key_json, str):
            secret_bundle = json.loads(secret_key_json)
        else:
            secret_bundle = secret_key_json
        
        # Load identity from secret bundle (support both raw and encrypted)
        payload = secret_bundle["payload"]
        from forgotten_e2ee.crypto_core import scrypt_key, aead_decrypt
        
        if payload["enc"] == "raw":
            ed_raw = b64u_dec(payload["ed"])
            x_raw = b64u_dec(payload["xk"])
        elif payload["enc"] == "scrypt+chacha20":
            # Decrypt with passphrase (like CLI does)
            passphrase = data.get('passphrase', '')
            if not passphrase:
                return jsonify({'success': False, 'error': 'Passphrase required for encrypted secret key'}), 400
            salt = b64u_dec(payload["salt"])
            nonce = b64u_dec(payload["nonce"])
            ct = b64u_dec(payload["ct"])
            key = scrypt_key(passphrase, salt, 32)
            pt = aead_decrypt(key, nonce, b"fg-sec", ct)
            if not (pt.startswith(b"ED") and b"XK" in pt):
                return jsonify({'success': False, 'error': 'Invalid passphrase or corrupted keyfile'}), 400
            ed_raw = pt[2:34]
            x_raw = pt[36:68]
        else:
            return jsonify({'success': False, 'error': f'Unsupported encryption format: {payload["enc"]}'}), 400
        
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        ident = Identity(
            ed25519.Ed25519PrivateKey.from_private_bytes(ed_raw),
            x25519.X25519PrivateKey.from_private_bytes(x_raw)
        )
        
        # Try to parse as armor first
        try:
            hdr, prose = parse_armor(encrypted_data)
            nonce = b64u_dec(hdr["Nonce"])
            eph_pub = b64u_dec(hdr["Eph"])
            pq_ct = b64u_dec(hdr["PQ"]) if "PQ" in hdr else b""
            sender_fp = hdr.get("Sender-FP", "0" * 24)
            recip_fp_hdr = hdr.get("Recipient-FP", "")
            ct = b64u_dec(hdr["Ciphertext-B64"])
            
            # Reconstruct shared secret
            from cryptography.hazmat.primitives.asymmetric import x25519
            eph_pk = x25519.X25519PublicKey.from_public_bytes(eph_pub)
            shared = ident.x_priv.exchange(eph_pk)
            
            # Get recipient fingerprint
            recip_fp = recip_fp_hdr or ident.fingerprint()
            transcript = _transcript(sender_fp, recip_fp, eph_pub)
            
            # Decapsulate PQ if present
            pq_ss = b""
            if pq_ct:
                try:
                    from forgotten_e2ee.pq import kyber_decapsulate
                    # kyber_decapsulate takes (ct, sk) where sk is bytes
                    from forgotten_e2ee.crypto_core import raw_priv_bytes_x
                    x_priv_bytes = raw_priv_bytes_x(ident.x_priv)
                    pq_ss = kyber_decapsulate(pq_ct, x_priv_bytes)
                except Exception:
                    pq_ss = b""
            
            # Derive key
            key = hybrid_secret(hkdf, transcript, shared, pq_ss if pq_ss else None)
            
            # Decode token map to get ciphertext (if using armor)
            # Resolve lexicon path (like CLI/GUI do)
            if lexicon_name:
                if not os.path.isabs(lexicon_name) and not os.path.exists(lexicon_name):
                    lexicon_path = LEXICON_DIR / lexicon_name
                else:
                    lexicon_path = Path(lexicon_name)
            
            if lexicon_path and lexicon_path.exists():
                tokens = load_lexicon(str(lexicon_path))
            elif DEFAULT_LEXICON and DEFAULT_LEXICON.exists():
                tokens = load_lexicon(str(DEFAULT_LEXICON))
            else:
                # Fallback to default lexicon loading
                tokens = load_lexicon(None)
                if not tokens or len(tokens) < 64:
                    return jsonify({'success': False, 'error': 'Lexicon required for armor decryption. Please ensure lexicons/en.txt exists or specify a lexicon.'}), 400
            
            # Verify lexicon matches if specified in header
            expected_lxref = hdr.get("Lexicon-Ref")
            if expected_lxref:
                actual_lxref = lexicon_hash(tokens)
                if actual_lxref != expected_lxref:
                    # Try fallback lexicon
                    fallback_tokens = load_lexicon(None)
                    if lexicon_hash(fallback_tokens) == expected_lxref:
                        tokens = fallback_tokens
                    else:
                        return jsonify({'success': False, 'error': f'Lexicon mismatch. Expected: {expected_lxref[:20]}..., Got: {actual_lxref[:20]}...'}), 400
            
            # Decode token map (verify it matches Ciphertext-B64)
            decoded_ct = decode_token_map(prose, key, nonce, tokens)
            if decoded_ct != ct:
                return jsonify({'success': False, 'error': 'Token map decode mismatch'}), 400
            
            # Decrypt
            # Reconstruct AAD to match encryption
            # Encryption uses: header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
            # We need to reconstruct the exact header_bytes that were used during encryption
            from forgotten_e2ee.fmt import FGHeader
            from forgotten_e2ee.util import now_s
            # Reconstruct transcript hash for header (must match encryption)
            transcript_for_header = _transcript(sender_fp, recip_fp, eph_pub)
            thash = hkdf(b"fg-v1|th", transcript_for_header, b"", 32)
            # Reconstruct header exactly as it was during encryption
            # Include signature flag if signature is present
            flags = 0x01 if pq_ct else 0x00
            if "Sig" in hdr:
                flags |= 0x02  # Signature flag
            header = FGHeader(
                version=1,
                flags=flags,
                ts_unix=int(hdr.get("Ts", str(now_s()))),
                sender_fp=sender_fp,
                session_id=int(hdr.get("Session", "0")),
                seq=int(hdr.get("Seq", "0")),
                nonce=nonce,
                transcript_hash=thash
            )
            header_bytes = header.to_bytes()
            aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
            pt = aead_decrypt(key, nonce, aad, ct)
            
            plaintext = pt.decode('utf-8')
            
            # Optional signature verification (like CLI --sender-pub)
            sender_pub_json = data.get('sender_pub')  # Optional sender public key for verification
            sig_verified = False
            sig_error = None
            
            if "Sig" in hdr and sender_fp and sender_fp != "0" * 24:
                if sender_pub_json:
                    # Verify signature with provided sender public key
                    if isinstance(sender_pub_json, str):
                        sender_bundle = json.loads(sender_pub_json)
                    else:
                        sender_bundle = sender_pub_json
                    
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    ed_s = ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(sender_bundle["ed25519_pub"]))
                    sig_bytes = b64u_dec(hdr["Sig"])
                    
                    try:
                        sig_verified = ed_verify(ed_s, sig_bytes, sha256_hex(header_bytes + eph_pub + (pq_ct or b"") + ct).encode())
                        if not sig_verified:
                            sig_error = "Signature verification failed"
                    except Exception as sig_ex:
                        sig_error = f"Signature verification error: {str(sig_ex)}"
                else:
                    sig_error = "Signature present but no sender public key provided for verification"
            
            # Return result with signature verification status
            result_data = {
                'success': True,
                'plaintext': plaintext
            }
            if "Sig" in hdr:
                result_data['signed'] = True
                result_data['signature_verified'] = sig_verified
                if sig_error:
                    result_data['signature_error'] = sig_error
            else:
                result_data['signed'] = False
            
            return jsonify(result_data)
        except Exception as armor_error:
            import traceback
            armor_error_msg = str(armor_error) or repr(armor_error)
            armor_traceback = traceback.format_exc()
            # Try binary format
            try:
                from forgotten_e2ee.fmt import FGHeader
                raw = b64u_dec(encrypted_data)
                header, off = FGHeader.from_bytes(raw)
                eph_pub = raw[off:off + 32]
                off += 32
                pq_ct = b""
                if header.flags & 0x01:
                    ln = int.from_bytes(raw[off:off + 2], "big")
                    off += 2
                    pq_ct = raw[off:off + ln]
                    off += ln
                ct = raw[off:]
                sig = b""
                if header.flags & 0x02:
                    if len(ct) < 64:
                        raise EDecrypt("Truncated signature block")
                    sig = ct[-64:]
                    ct = ct[:-64]
                
                # Reconstruct shared secret
                from cryptography.hazmat.primitives.asymmetric import x25519
                eph_pk = x25519.X25519PublicKey.from_public_bytes(eph_pub)
                shared = ident.x_priv.exchange(eph_pk)
                
                recip_fp = ident.fingerprint()
                transcript = _transcript(header.sender_fp, recip_fp, eph_pub)
                key = hybrid_secret(hkdf, transcript, shared, None)
                aad = header.to_bytes() + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
                pt = aead_decrypt(key, header.nonce, aad, ct)
                
                plaintext = pt.decode('utf-8')
                
                return jsonify({
                    'success': True,
                    'plaintext': plaintext
                })
            except Exception as binary_error:
                return jsonify({
                    'success': False,
                    'error': f'Armor error: {armor_error_msg}; Binary error: {str(binary_error)}',
                    'armor_traceback': armor_traceback[:1000] if 'armor_traceback' in locals() else ''
                }), 500
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/show-fp', methods=['POST'])
def api_show_fp():
    """Show fingerprint from public key (equivalent to CLI show-fp)"""
    try:
        data = request.get_json() or {}
        public_key_json = data.get('public_key')
        
        if not public_key_json:
            return jsonify({'success': False, 'error': 'public_key required'}), 400
        
        # Parse public key bundle
        if isinstance(public_key_json, str):
            pub_bundle = json.loads(public_key_json)
        else:
            pub_bundle = public_key_json
        
        fingerprint = pub_bundle.get('fingerprint')
        if not fingerprint:
            # Calculate fingerprint if not present
            ed_pub_bytes = b64u_dec(pub_bundle["ed25519_pub"])
            x_pub_bytes = b64u_dec(pub_bundle["x25519_pub"])
            fingerprint = hex24(bytes.fromhex(sha256_hex(ed_pub_bytes + x_pub_bytes)))
        
        return jsonify({
            'success': True,
            'fingerprint': fingerprint,
            'name': pub_bundle.get('name', 'Unknown')
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/lipsumlab/encode', methods=['POST'])
def api_lipsumlab_encode():
    """Encode text to themed Ipsum (Language → Ipsum)"""
    try:
        data = request.get_json() or {}
        text = data.get('text', '')
        source_lang = data.get('source_lang', 'unknown')
        theme_key = data.get('theme_key', 'en')  # Default to English lexicon
        use_lang_theme = data.get('use_lang_theme', False)
        
        if not text:
            return jsonify({'success': False, 'error': 'text required'}), 400
        
        # Import LipsumLab functions
        import sys
        lipsumlab_path = project_root / 'LipsumLab'
        if str(lipsumlab_path) not in sys.path:
            sys.path.insert(0, str(lipsumlab_path))
        
        from li_reversible_themed import encode_to_theme, discover_lexicons, LANG_NAMES
        
        # Get lexicon words
        lexicons = discover_lexicons(lipsumlab_path / 'lexicons')
        
        if use_lang_theme and source_lang in lexicons:
            theme_key = source_lang
            theme_words = lexicons[source_lang]
            theme_name = "Lipsum" if theme_key == "latin" else LANG_NAMES.get(source_lang, source_lang).split(" ")[0]
        elif theme_key in lexicons:
            theme_words = lexicons[theme_key]
            theme_name = "Lipsum" if theme_key == "latin" else theme_key.title()
        else:
            return jsonify({'success': False, 'error': f'Theme "{theme_key}" not found. Available: {list(lexicons.keys())}'}), 400
        
        # Encode
        output, map_id = encode_to_theme(text, source_lang, theme_key, theme_name, theme_words)
        
        return jsonify({
            'success': True,
            'output': output,
            'map_id': map_id,
            'theme_key': theme_key,
            'theme_name': theme_name,
            'source_lang': source_lang
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/lipsumlab/decode', methods=['POST'])
def api_lipsumlab_decode():
    """Decode themed Ipsum back to original (Ipsum → Language)"""
    try:
        data = request.get_json() or {}
        themed_text = data.get('themed_text', '')
        map_id = data.get('map_id', '')  # Optional, will try to extract from header
        
        if not themed_text:
            return jsonify({'success': False, 'error': 'themed_text required'}), 400
        
        # Import LipsumLab functions
        import sys
        lipsumlab_path = project_root / 'LipsumLab'
        if str(lipsumlab_path) not in sys.path:
            sys.path.insert(0, str(lipsumlab_path))
        
        from li_reversible_themed import decode_to_original, extract_map_id
        
        # Extract map_id from header if not provided
        if not map_id:
            themed_wo, embedded_id = extract_map_id(themed_text)
            map_id = embedded_id or map_id
            if not map_id:
                return jsonify({'success': False, 'error': 'map_id required (not found in header)'}), 400
        else:
            themed_wo = themed_text  # Use as-is if map_id provided
        
        # Decode
        restored = decode_to_original(themed_wo, map_id)
        
        return jsonify({
            'success': True,
            'output': restored,
            'map_id': map_id
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/upload', methods=['POST'])
def api_upload():
    """Upload and parse key files (.id.pub or .id.sec)"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Read file content
        content = file.read().decode('utf-8')
        
        # Try to parse as JSON (key bundle)
        try:
            key_data = json.loads(content)
            key_type = key_data.get('type', 'unknown')
            
            if key_type == 'fg-public':
                return jsonify({
                    'success': True,
                    'type': 'public',
                    'public_key': content,
                    'name': key_data.get('name', 'Unknown'),
                    'fingerprint': key_data.get('fingerprint', '')
                })
            elif key_type == 'fg-secret':
                return jsonify({
                    'success': True,
                    'type': 'secret',
                    'secret_key': content,
                    'encrypted': key_data.get('payload', {}).get('enc') != 'raw'
                })
            else:
                return jsonify({'success': False, 'error': 'Unknown key type'}), 400
        except json.JSONDecodeError:
            return jsonify({'success': False, 'error': 'Invalid key file format (must be JSON)'}), 400
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/download/<file_type>', methods=['POST'])
def api_download(file_type):
    """Download generated keys or encrypted/decrypted messages as files"""
    try:
        data = request.get_json() or {}
        
        if file_type == 'keys':
            name = data.get('name', 'identity')
            public_key = data.get('public_key', '')
            secret_key = data.get('secret_key', '')
            
            if not public_key or not secret_key:
                return jsonify({'success': False, 'error': 'public_key and secret_key required'}), 400
            
            # Create temporary directory for files
            import tempfile
            import shutil
            temp_dir = tempfile.mkdtemp()
            pub_path = os.path.join(temp_dir, f"{name.lower()}.id.pub")
            sec_path = os.path.join(temp_dir, f"{name.lower()}.id.sec")
            
            with open(pub_path, 'w') as f:
                f.write(public_key)
            with open(sec_path, 'w') as f:
                f.write(secret_key)
            
            # Create zip file
            import zipfile
            zip_path = os.path.join(temp_dir, f"{name.lower()}_keys.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.write(pub_path, f"{name.lower()}.id.pub")
                zf.write(sec_path, f"{name.lower()}.id.sec")
            
            return send_file(zip_path, as_attachment=True, download_name=f"{name.lower()}_keys.zip", mimetype='application/zip')
        
        elif file_type == 'encrypted':
            output = data.get('output', '')
            filename = data.get('filename', 'message.fg.asc')
            
            if not output:
                return jsonify({'success': False, 'error': 'output required'}), 400
            
            # Create temporary file
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.fg.asc')
            temp_file.write(output)
            temp_file.close()
            
            return send_file(temp_file.name, as_attachment=True, download_name=filename, mimetype='text/plain')
        
        elif file_type == 'decrypted':
            plaintext = data.get('plaintext', '')
            filename = data.get('filename', 'decrypted.txt')
            
            if not plaintext:
                return jsonify({'success': False, 'error': 'plaintext required'}), 400
            
            # Create temporary file
            import tempfile
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            temp_file.write(plaintext)
            temp_file.close()
            
            return send_file(temp_file.name, as_attachment=True, download_name=filename, mimetype='text/plain')
        
        else:
            return jsonify({'success': False, 'error': f'Unknown file type: {file_type}'}), 400
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    import socket
    
    # Find an available port, or use PORT env variable
    def find_free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    # Use PORT from environment (required by DigitalOcean) or default to 8080
    port = int(os.environ.get('PORT', 8080))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"Starting Forgotten-E2EE Web App on http://{host}:{port}")
    print(f"Main interface: http://{host}:{port}/")
    print(f"Embeddable version: http://{host}:{port}/embed")
    
    app.run(debug=False, host=host, port=port, use_reloader=False)

