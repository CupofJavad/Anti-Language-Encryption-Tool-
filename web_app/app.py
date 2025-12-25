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
from forgotten_e2ee.keystore import Identity, save_public, save_secret
from forgotten_e2ee.crypto_core import ed25519_keypair, x25519_keypair
from forgotten_e2ee.fmt import FGHeader, emit_armor, parse_armor
from forgotten_e2ee.util import b64u_enc, b64u_dec
from forgotten_e2ee.stego import load_lexicon
from forgotten_e2ee.errors import ESig, EDecrypt

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
        
        # Create identity
        identity = Identity(
            name=name,
            ed25519_priv=ed_priv,
            ed25519_pub=ed_pub,
            x25519_priv=x_priv,
            x25519_pub=x_pub
        )
        
        # Serialize keys
        public_bundle = identity.public_bundle()
        secret_bundle = identity.secret_bundle()
        
        return jsonify({
            'success': True,
            'public_key': public_bundle,
            'secret_key': secret_bundle,
            'name': name
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """Encrypt a message"""
    try:
        data = request.get_json() or {}
        recipient_pub = data.get('recipient_pub')
        plaintext = data.get('plaintext', '')
        armor = data.get('armor', False)
        lexicon_path = data.get('lexicon')
        
        if not recipient_pub:
            return jsonify({'success': False, 'error': 'recipient_pub required'}), 400
        
        # Load lexicon if provided
        lexicon = None
        if armor:
            if lexicon_path and os.path.exists(lexicon_path):
                lexicon = load_lexicon(lexicon_path)
            elif DEFAULT_LEXICON:
                lexicon = load_lexicon(str(DEFAULT_LEXICON))
        
        # Encrypt (simplified - you may need to adjust based on your actual encryption flow)
        # This is a placeholder - you'll need to implement the full encryption logic
        from forgotten_e2ee.cli import cmd_encrypt
        
        # For now, return a basic response
        return jsonify({
            'success': True,
            'output': f'[Encrypted: {plaintext[:20]}...]',  # Placeholder
            'armor': armor
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """Decrypt a message"""
    try:
        data = request.get_json() or {}
        secret_key = data.get('secret_key')
        encrypted_data = data.get('encrypted_data')
        lexicon_path = data.get('lexicon')
        
        if not secret_key or not encrypted_data:
            return jsonify({'success': False, 'error': 'secret_key and encrypted_data required'}), 400
        
        # Load lexicon if needed
        lexicon = None
        if lexicon_path and os.path.exists(lexicon_path):
            lexicon = load_lexicon(lexicon_path)
        elif DEFAULT_LEXICON:
            lexicon = load_lexicon(str(DEFAULT_LEXICON))
        
        # Decrypt (simplified - implement full logic)
        return jsonify({
            'success': True,
            'plaintext': '[Decrypted message]'  # Placeholder
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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

