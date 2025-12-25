"""
Unit Tests - Test individual functions and methods
"""
import pytest
import json
from forgotten_e2ee.keystore import Identity
from forgotten_e2ee.crypto_core import ed25519_keypair, x25519_keypair
from forgotten_e2ee.util import b64u_enc, b64u_dec, hex24
from forgotten_e2ee.crypto_core import raw_pub_bytes_ed, raw_pub_bytes_x, raw_priv_bytes_ed, raw_priv_bytes_x, sha256_hex

class TestIdentity:
    """Test Identity class"""
    
    def test_identity_creation(self):
        """Test creating an Identity with correct parameters"""
        ed_priv, ed_pub = ed25519_keypair()
        x_priv, x_pub = x25519_keypair()
        
        identity = Identity(ed_priv, x_priv)
        
        assert identity is not None
        assert identity.ed_priv == ed_priv
        assert identity.x_priv == x_priv
    
    def test_identity_fingerprint(self):
        """Test identity fingerprint generation"""
        ed_priv, ed_pub = ed25519_keypair()
        x_priv, x_pub = x25519_keypair()
        
        identity = Identity(ed_priv, x_priv)
        fingerprint = identity.fingerprint()
        
        assert fingerprint is not None
        assert len(fingerprint) == 24
        assert isinstance(fingerprint, str)
    
    def test_identity_public_keys(self):
        """Test getting public keys from identity"""
        ed_priv, ed_pub = ed25519_keypair()
        x_priv, x_pub = x25519_keypair()
        
        identity = Identity(ed_priv, x_priv)
        
        assert identity.ed_pub() is not None
        assert identity.x_pub() is not None

class TestKeyGeneration:
    """Test key generation functions"""
    
    def test_ed25519_keypair(self):
        """Test Ed25519 keypair generation"""
        priv, pub = ed25519_keypair()
        
        assert priv is not None
        assert pub is not None
        assert priv != pub
    
    def test_x25519_keypair(self):
        """Test X25519 keypair generation"""
        priv, pub = x25519_keypair()
        
        assert priv is not None
        assert pub is not None
        assert priv != pub
    
    def test_keypair_uniqueness(self):
        """Test that each keypair is unique"""
        priv1, pub1 = ed25519_keypair()
        priv2, pub2 = ed25519_keypair()
        
        assert priv1 != priv2
        assert pub1 != pub2

class TestSerialization:
    """Test key serialization/deserialization"""
    
    def test_raw_pub_bytes_ed(self):
        """Test Ed25519 public key serialization"""
        _, pub = ed25519_keypair()
        raw = raw_pub_bytes_ed(pub)
        
        assert raw is not None
        assert isinstance(raw, bytes)
        assert len(raw) == 32
    
    def test_raw_pub_bytes_x(self):
        """Test X25519 public key serialization"""
        _, pub = x25519_keypair()
        raw = raw_pub_bytes_x(pub)
        
        assert raw is not None
        assert isinstance(raw, bytes)
        assert len(raw) == 32
    
    def test_b64u_encoding(self):
        """Test base64url encoding"""
        test_bytes = b"test data"
        encoded = b64u_enc(test_bytes)
        decoded = b64u_dec(encoded)
        
        assert encoded is not None
        assert isinstance(encoded, str)
        assert decoded == test_bytes
    
    def test_hex24(self):
        """Test hex24 fingerprint generation"""
        test_hash = "a" * 64  # 32 bytes in hex
        fingerprint = hex24(bytes.fromhex(test_hash))
        
        assert fingerprint is not None
        assert len(fingerprint) == 24
        assert isinstance(fingerprint, str)

class TestKeyBundle:
    """Test key bundle creation"""
    
    def test_public_bundle_creation(self):
        """Test creating a public key bundle"""
        ed_priv, ed_pub = ed25519_keypair()
        x_priv, x_pub = x25519_keypair()
        
        pub = raw_pub_bytes_ed(ed_pub)
        dhp = raw_pub_bytes_x(x_pub)
        
        bundle = {
            "version": 1,
            "type": "fg-public",
            "name": "Test",
            "ed25519_pub": b64u_enc(pub),
            "x25519_pub": b64u_enc(dhp),
            "fingerprint": hex24(bytes.fromhex(sha256_hex(pub + dhp))),
        }
        
        assert bundle["version"] == 1
        assert bundle["type"] == "fg-public"
        assert "ed25519_pub" in bundle
        assert "x25519_pub" in bundle
        assert "fingerprint" in bundle
    
    def test_secret_bundle_creation(self):
        """Test creating a secret key bundle"""
        ed_priv, ed_pub = ed25519_keypair()
        x_priv, x_pub = x25519_keypair()
        
        ed_raw = raw_priv_bytes_ed(ed_priv)
        x_raw = raw_priv_bytes_x(x_priv)
        
        bundle = {
            "version": 1,
            "type": "fg-secret",
            "payload": {
                "enc": "raw",
                "ed": b64u_enc(ed_raw),
                "xk": b64u_enc(x_raw)
            }
        }
        
        assert bundle["version"] == 1
        assert bundle["type"] == "fg-secret"
        assert bundle["payload"]["enc"] == "raw"
        assert "ed" in bundle["payload"]
        assert "xk" in bundle["payload"]

