"""
Pytest configuration and shared fixtures
"""
import pytest
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def app():
    """Create Flask app instance for testing"""
    from web_app.app import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    return flask_app

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def sample_public_key():
    """Generate sample public key bundle for testing"""
    from forgotten_e2ee.crypto_core import ed25519_keypair, x25519_keypair, raw_pub_bytes_ed, raw_pub_bytes_x
    from forgotten_e2ee.util import b64u_enc, hex24, sha256_hex
    
    ed_priv, ed_pub = ed25519_keypair()
    x_priv, x_pub = x25519_keypair()
    
    pub = raw_pub_bytes_ed(ed_pub)
    dhp = raw_pub_bytes_x(x_pub)
    
    return {
        "version": 1,
        "type": "fg-public",
        "name": "TestUser",
        "ed25519_pub": b64u_enc(pub),
        "x25519_pub": b64u_enc(dhp),
        "fingerprint": hex24(bytes.fromhex(sha256_hex(pub + dhp))),
    }

@pytest.fixture
def sample_secret_key():
    """Generate sample secret key bundle for testing"""
    from forgotten_e2ee.crypto_core import ed25519_keypair, x25519_keypair, raw_priv_bytes_ed, raw_priv_bytes_x
    from forgotten_e2ee.util import b64u_enc
    
    ed_priv, ed_pub = ed25519_keypair()
    x_priv, x_pub = x25519_keypair()
    
    ed_raw = raw_priv_bytes_ed(ed_priv)
    x_raw = raw_priv_bytes_x(x_priv)
    
    return {
        "version": 1,
        "type": "fg-secret",
        "payload": {
            "enc": "raw",
            "ed": b64u_enc(ed_raw),
            "xk": b64u_enc(x_raw)
        }
    }

@pytest.fixture
def test_lexicon_path():
    """Path to test lexicon"""
    lexicon_path = project_root / 'lexicons' / 'en.txt'
    if lexicon_path.exists():
        return str(lexicon_path)
    return None

