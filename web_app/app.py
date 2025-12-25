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

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
from forgotten_e2ee.keystore import Identity, save_public, save_secret, load_secret, load_public
from forgotten_e2ee.crypto_core import (
    ed25519_keypair, x25519_keypair, raw_pub_bytes_ed, raw_pub_bytes_x,
    raw_priv_bytes_ed, raw_priv_bytes_x, hkdf, aead_encrypt, aead_decrypt,
    ed_sign, ed_verify, sha256_hex, secure_random
)
from forgotten_e2ee.fmt import FGHeader, emit_armor, parse_armor
from forgotten_e2ee.util import b64u_enc, b64u_dec, hex24, sha256_hex, now_s
from forgotten_e2ee.stego import load_lexicon, lexicon_hash, encode_token_map, decode_token_map
from forgotten_e2ee.errors import ESig, EDecrypt, ELexicon
from forgotten_e2ee.pq import hybrid_secret

app = Flask(__name__, template_folder='templates')
CORS(app)

# Production configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
app.config['TESTING'] = False

# Find lexicon directory
LEXICON_DIR = project_root / 'lexicons'
DEFAULT_LEXICON = LEXICON_DIR / 'en.txt' if (LEXICON_DIR / 'en.txt').exists() else None

@app.route('/')
def index():
    """Main interface"""
    return render_template('index.html')

@app.route('/embed')
def embed():
    """Embeddable version"""
    return render_template('embed.html')

@app.route('/api/keygen', methods=['POST'])
def api_keygen():
    """Generate a new identity keypair"""
    try:
        data = request.get_json() or {}
        name = data.get('name', 'Anonymous')
        
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
        from forgotten_e2ee.crypto_core import raw_priv_bytes_ed, raw_priv_bytes_x
        ed_raw = raw_priv_bytes_ed(ed_priv)
        x_raw = raw_priv_bytes_x(x_priv)
        # Store as raw (no passphrase for web API)
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
            'fingerprint': public_bundle['fingerprint']
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
        data = request.get_json() or {}
        recipient_pub_json = data.get('recipient_pub')
        plaintext = data.get('plaintext', '')
        armor = data.get('armor', False)
        lexicon_path = data.get('lexicon')
        
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
        
        # ECDH shared secret
        shared = eph_sk.exchange(x_r)
        sender_fp = "0" * 24  # No sender signature for now
        transcript = _transcript(sender_fp, recip_fp, eph_pub)
        
        # Hybrid session key
        key = hybrid_secret(hkdf, transcript, shared, pq_ss if pq_ss else None)
        
        # Create header
        session_id = int.from_bytes(secure_random(8), "big")
        seq = 0
        nonce = hkdf(b"fg-v1|nonce", eph_pub + session_id.to_bytes(8, "big") + seq.to_bytes(8, "big"), length=12)
        thash = hkdf(b"fg-v1|th", transcript, b"", 32)
        flags = 0x01 if pq_ct else 0x00
        header = FGHeader(version=1, flags=flags, ts_unix=now_s(), sender_fp=sender_fp,
                         session_id=session_id, seq=seq, nonce=nonce, transcript_hash=thash)
        header_bytes = header.to_bytes()
        aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
        
        # Encrypt
        ct = aead_encrypt(key, nonce, aad, data_bytes)
        
        if not armor:
            # Binary output
            output = b64u_enc(header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"") + ct)
            return jsonify({
                'success': True,
                'output': output,
                'format': 'binary'
            })
        
        # Armor with steganography
        if lexicon_path and os.path.exists(lexicon_path):
            tokens = load_lexicon(lexicon_path)
        elif DEFAULT_LEXICON:
            tokens = load_lexicon(str(DEFAULT_LEXICON))
        else:
            return jsonify({'success': False, 'error': 'Lexicon required for armor mode'}), 400
        
        lxref = lexicon_hash(tokens)
        prose = encode_token_map(ct, key, nonce, tokens)
        hdr_fields = {
            "Version": "1",
            "Sender-FP": sender_fp,
            "Recipient-FP": recip_fp,
            "Session": str(session_id),
            "Seq": str(seq),
            "Mode": "token_map_v1",
            "Lexicon-Ref": lxref,
            "Ts": str(header.ts_unix),
            "Nonce": b64u_enc(nonce),
            "Eph": b64u_enc(eph_pub),
        }
        if pq_ct:
            hdr_fields["PQ"] = b64u_enc(pq_ct)
        hdr_fields["Ciphertext-B64"] = b64u_enc(ct)
        armor_output = emit_armor(hdr_fields, prose)
        
        return jsonify({
            'success': True,
            'output': armor_output,
            'format': 'armor'
        })
    except Exception as e:
        import traceback
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """Decrypt a message"""
    try:
        data = request.get_json() or {}
        secret_key_json = data.get('secret_key')
        encrypted_data = data.get('encrypted_data')
        lexicon_path = data.get('lexicon')
        
        if not secret_key_json or not encrypted_data:
            return jsonify({'success': False, 'error': 'secret_key and encrypted_data required'}), 400
        
        # Parse secret key bundle
        if isinstance(secret_key_json, str):
            secret_bundle = json.loads(secret_key_json)
        else:
            secret_bundle = secret_key_json
        
        # Load identity from secret bundle
        payload = secret_bundle["payload"]
        if payload["enc"] == "raw":
            ed_raw = b64u_dec(payload["ed"])
            x_raw = b64u_dec(payload["xk"])
        else:
            return jsonify({'success': False, 'error': 'Only raw (unencrypted) secret keys supported in web API'}), 400
        
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
                    pq_ss = kyber_decapsulate(ident.x_priv, pq_ct)  # Note: This might need adjustment
                except Exception:
                    pq_ss = b""
            
            # Derive key
            key = hybrid_secret(hkdf, transcript, shared, pq_ss if pq_ss else None)
            
            # Decode token map to get ciphertext (if using armor)
            if lexicon_path and os.path.exists(lexicon_path):
                tokens = load_lexicon(lexicon_path)
            elif DEFAULT_LEXICON:
                tokens = load_lexicon(str(DEFAULT_LEXICON))
            else:
                return jsonify({'success': False, 'error': 'Lexicon required for armor decryption'}), 400
            
            # Decode token map
            decoded_ct = decode_token_map(prose, tokens)
            if decoded_ct != ct:
                return jsonify({'success': False, 'error': 'Token map decode mismatch'}), 400
            
            # Decrypt
            header_bytes = b""  # Simplified for armor mode
            aad = header_bytes + eph_pub + (len(pq_ct).to_bytes(2, "big") + pq_ct if pq_ct else b"")
            pt = aead_decrypt(key, nonce, aad, ct)
            
            plaintext = pt.decode('utf-8')
            
            return jsonify({
                'success': True,
                'plaintext': plaintext
            })
        except Exception as armor_error:
            # Try binary format
            try:
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
                    'error': f'Armor error: {str(armor_error)}; Binary error: {str(binary_error)}'
                }), 500
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

