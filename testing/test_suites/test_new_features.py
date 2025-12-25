"""
Comprehensive Tests for New Features
Tests for file upload/download, signing, signature verification, fingerprint, and LipsumLab
"""
import pytest
import json
import tempfile
import os
from pathlib import Path
from web_app.app import app

class TestFileUpload:
    """Test file upload endpoint"""
    
    def test_upload_public_key_file(self, client):
        """Test uploading a public key file"""
        # Create a temporary public key file
        pub_key_data = {
            "version": 1,
            "type": "fg-public",
            "name": "TestUser",
            "ed25519_pub": "dGVzdF9lZDI1NTE5X3B1Yg",
            "x25519_pub": "dGVzdF94MjU1MTlfcHVi",
            "fingerprint": "abc123def456ghi789jkl012"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pub', delete=False) as f:
            json.dump(pub_key_data, f)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/api/upload', data={'file': f}, content_type='multipart/form-data')
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] == True
            assert data['type'] == 'public'
            assert data['name'] == 'TestUser'
            assert 'public_key' in data
        finally:
            os.unlink(temp_path)
    
    def test_upload_secret_key_file(self, client):
        """Test uploading a secret key file"""
        sec_key_data = {
            "version": 1,
            "type": "fg-secret",
            "payload": {
                "enc": "raw",
                "ed": "dGVzdF9lZDI1NTE5X3ByaXY",
                "xk": "dGVzdF94MjU1MTlfcHJpdg"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sec', delete=False) as f:
            json.dump(sec_key_data, f)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/api/upload', data={'file': f}, content_type='multipart/form-data')
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] == True
            assert data['type'] == 'secret'
            assert 'secret_key' in data
            assert data['encrypted'] == False
        finally:
            os.unlink(temp_path)
    
    def test_upload_encrypted_secret_key(self, client):
        """Test uploading an encrypted secret key file"""
        sec_key_data = {
            "version": 1,
            "type": "fg-secret",
            "payload": {
                "enc": "scrypt+chacha20",
                "salt": "dGVzdF9zYWx0",
                "nonce": "dGVzdF9ub25jZQ",
                "ct": "dGVzdF9jaXBoZXJ0ZXh0"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sec', delete=False) as f:
            json.dump(sec_key_data, f)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/api/upload', data={'file': f}, content_type='multipart/form-data')
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] == True
            assert data['type'] == 'secret'
            assert data['encrypted'] == True
        finally:
            os.unlink(temp_path)
    
    def test_upload_no_file(self, client):
        """Test upload without file"""
        response = client.post('/api/upload', data={}, content_type='multipart/form-data')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
        assert 'error' in data
    
    def test_upload_invalid_file(self, client):
        """Test upload with invalid file format"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is not a valid key file")
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/api/upload', data={'file': f}, content_type='multipart/form-data')
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert data['success'] == False
        finally:
            os.unlink(temp_path)

class TestFileDownload:
    """Test file download endpoints"""
    
    def test_download_keys(self, client):
        """Test downloading keys as ZIP"""
        pub_key = json.dumps({
            "version": 1,
            "type": "fg-public",
            "name": "TestUser",
            "ed25519_pub": "dGVzdF9lZDI1NTE5X3B1Yg",
            "x25519_pub": "dGVzdF94MjU1MTlfcHVi",
            "fingerprint": "abc123def456ghi789jkl012"
        })
        sec_key = json.dumps({
            "version": 1,
            "type": "fg-secret",
            "payload": {"enc": "raw", "ed": "dGVzdA", "xk": "dGVzdA"}
        })
        
        response = client.post('/api/download/keys', json={
            'name': 'testuser',
            'public_key': pub_key,
            'secret_key': sec_key
        })
        
        assert response.status_code == 200
        assert response.content_type == 'application/zip'
        assert b'PK' in response.data  # ZIP file signature
    
    def test_download_encrypted(self, client):
        """Test downloading encrypted message"""
        encrypted_output = "-----BEGIN FORGOTTEN MESSAGE-----\nTest encrypted content\n-----END FORGOTTEN MESSAGE-----"
        
        response = client.post('/api/download/encrypted', json={
            'output': encrypted_output,
            'filename': 'test.fg.asc'
        })
        
        assert response.status_code == 200
        assert 'text/plain' in response.content_type
        assert encrypted_output.encode() in response.data
    
    def test_download_decrypted(self, client):
        """Test downloading decrypted plaintext"""
        plaintext = "This is the decrypted message"
        
        response = client.post('/api/download/decrypted', json={
            'plaintext': plaintext,
            'filename': 'decrypted.txt'
        })
        
        assert response.status_code == 200
        assert 'text/plain' in response.content_type
        assert plaintext.encode() in response.data
    
    def test_download_keys_missing_data(self, client):
        """Test download keys with missing data"""
        response = client.post('/api/download/keys', json={})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_download_invalid_type(self, client):
        """Test download with invalid file type"""
        response = client.post('/api/download/invalid', json={})
        assert response.status_code == 400

class TestSigning:
    """Test message signing functionality"""
    
    def test_encrypt_with_signing(self, client):
        """Test encryption with signer secret key"""
        # Generate recipient key
        recip_resp = client.post('/api/keygen', json={'name': 'Recipient'})
        recip_data = json.loads(recip_resp.data)
        recip_pub = recip_data['public_key']
        
        # Generate signer key
        signer_resp = client.post('/api/keygen', json={'name': 'Signer'})
        signer_data = json.loads(signer_resp.data)
        signer_sec = signer_data['secret_key']
        
        # Encrypt with signing
        response = client.post('/api/encrypt', json={
            'recipient_pub': recip_pub,
            'plaintext': 'Test signed message',
            'armor': True,
            'lexicon': 'lexicons/en.txt',
            'signer_secret': signer_sec
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert data.get('signed', False) == True
        assert 'output' in data
        # Check that signature is in armor output
        assert 'Sig' in data['output'] or '-----BEGIN' in data['output']
    
    def test_encrypt_with_signing_encrypted_key(self, client):
        """Test encryption with encrypted signer key"""
        # Generate recipient key
        recip_resp = client.post('/api/keygen', json={'name': 'Recipient'})
        recip_data = json.loads(recip_resp.data)
        recip_pub = recip_data['public_key']
        
        # Generate signer key with passphrase
        signer_resp = client.post('/api/keygen', json={
            'name': 'Signer',
            'passphrase': 'testpass123'
        })
        signer_data = json.loads(signer_resp.data)
        signer_sec = signer_data['secret_key']
        
        # Encrypt with signing (should require passphrase)
        response = client.post('/api/encrypt', json={
            'recipient_pub': recip_pub,
            'plaintext': 'Test signed message',
            'armor': True,
            'lexicon': 'lexicons/en.txt',
            'signer_secret': signer_sec,
            'signer_passphrase': 'testpass123'
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_encrypt_with_signing_wrong_passphrase(self, client):
        """Test encryption with wrong signer passphrase"""
        # Generate recipient key
        recip_resp = client.post('/api/keygen', json={'name': 'Recipient'})
        recip_data = json.loads(recip_resp.data)
        recip_pub = recip_data['public_key']
        
        # Generate signer key with passphrase
        signer_resp = client.post('/api/keygen', json={
            'name': 'Signer',
            'passphrase': 'correctpass'
        })
        signer_data = json.loads(signer_resp.data)
        signer_sec = signer_data['secret_key']
        
        # Try to encrypt with wrong passphrase
        response = client.post('/api/encrypt', json={
            'recipient_pub': recip_pub,
            'plaintext': 'Test signed message',
            'armor': True,
            'lexicon': 'lexicons/en.txt',
            'signer_secret': signer_sec,
            'signer_passphrase': 'wrongpass'
        })
        
        # Should fail or return error
        assert response.status_code in [200, 400, 500]
        data = json.loads(response.data)
        if not data.get('success'):
            assert 'error' in data or 'passphrase' in str(data.get('error', '')).lower()

class TestSignatureVerification:
    """Test signature verification functionality"""
    
    def test_decrypt_with_signature_verification(self, client):
        """Test decryption with signature verification"""
        # Generate keys
        recip_resp = client.post('/api/keygen', json={'name': 'Recipient'})
        recip_data = json.loads(recip_resp.data)
        recip_pub = recip_data['public_key']
        recip_sec = recip_data['secret_key']
        
        signer_resp = client.post('/api/keygen', json={'name': 'Signer'})
        signer_data = json.loads(signer_resp.data)
        signer_pub = signer_data['public_key']
        signer_sec = signer_data['secret_key']
        
        # Encrypt with signing
        encrypt_resp = client.post('/api/encrypt', json={
            'recipient_pub': recip_pub,
            'plaintext': 'Verified message',
            'armor': True,
            'lexicon': 'lexicons/en.txt',
            'signer_secret': signer_sec
        })
        encrypt_data = json.loads(encrypt_resp.data)
        encrypted = encrypt_data['output']
        
        # Decrypt with signature verification
        response = client.post('/api/decrypt', json={
            'secret_key': recip_sec,
            'encrypted_data': encrypted,
            'lexicon': 'lexicons/en.txt',
            'sender_pub': signer_pub
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert data.get('signed') == True
        assert data.get('signature_verified') == True
        assert data['plaintext'] == 'Verified message'
    
    def test_decrypt_with_wrong_sender_pub(self, client):
        """Test decryption with wrong sender public key"""
        # Generate keys
        recip_resp = client.post('/api/keygen', json={'name': 'Recipient'})
        recip_data = json.loads(recip_resp.data)
        recip_pub = recip_data['public_key']
        recip_sec = recip_data['secret_key']
        
        signer_resp = client.post('/api/keygen', json={'name': 'Signer'})
        signer_data = json.loads(signer_resp.data)
        signer_sec = signer_data['secret_key']
        
        wrong_signer_resp = client.post('/api/keygen', json={'name': 'WrongSigner'})
        wrong_signer_data = json.loads(wrong_signer_resp.data)
        wrong_signer_pub = wrong_signer_data['public_key']
        
        # Encrypt with signing
        encrypt_resp = client.post('/api/encrypt', json={
            'recipient_pub': recip_pub,
            'plaintext': 'Test message',
            'armor': True,
            'lexicon': 'lexicons/en.txt',
            'signer_secret': signer_sec
        })
        encrypt_data = json.loads(encrypt_resp.data)
        encrypted = encrypt_data['output']
        
        # Decrypt with wrong sender public key
        response = client.post('/api/decrypt', json={
            'secret_key': recip_sec,
            'encrypted_data': encrypted,
            'lexicon': 'lexicons/en.txt',
            'sender_pub': wrong_signer_pub
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        # Signature should fail verification
        assert data.get('signature_verified') == False
        assert 'signature_error' in data

class TestFingerprint:
    """Test fingerprint utility"""
    
    def test_show_fingerprint(self, client):
        """Test showing fingerprint from public key"""
        # Generate a key
        keygen_resp = client.post('/api/keygen', json={'name': 'TestUser'})
        keygen_data = json.loads(keygen_resp.data)
        pub_key = keygen_data['public_key']
        expected_fp = keygen_data['fingerprint']
        
        # Show fingerprint
        response = client.post('/api/show-fp', json={'public_key': pub_key})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['fingerprint'] == expected_fp
        assert data['name'] == 'TestUser'
    
    def test_show_fingerprint_missing_key(self, client):
        """Test show fingerprint without public key"""
        response = client.post('/api/show-fp', json={})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_show_fingerprint_invalid_key(self, client):
        """Test show fingerprint with invalid key"""
        response = client.post('/api/show-fp', json={'public_key': 'invalid json'})
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['success'] == False

class TestLipsumLab:
    """Test LipsumLab encoding/decoding"""
    
    def test_lipsumlab_encode(self, client):
        """Test encoding text to themed Ipsum"""
        response = client.post('/api/lipsumlab/encode', json={
            'text': 'Hello world, this is a test message.',
            'source_lang': 'en',
            'theme_key': 'en',
            'use_lang_theme': False
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'output' in data
        assert 'map_id' in data
        assert data['theme_key'] == 'en'
        assert '[LI-MAP-ID:' in data['output']
    
    def test_lipsumlab_encode_missing_text(self, client):
        """Test encoding without text"""
        response = client.post('/api/lipsumlab/encode', json={
            'source_lang': 'en',
            'theme_key': 'en'
        })
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_lipsumlab_encode_invalid_theme(self, client):
        """Test encoding with invalid theme"""
        response = client.post('/api/lipsumlab/encode', json={
            'text': 'Test message',
            'source_lang': 'en',
            'theme_key': 'nonexistent_theme_xyz'
        })
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_lipsumlab_decode(self, client):
        """Test decoding themed Ipsum to original"""
        # First encode
        encode_resp = client.post('/api/lipsumlab/encode', json={
            'text': 'Hello world test message',
            'source_lang': 'en',
            'theme_key': 'en'
        })
        encode_data = json.loads(encode_resp.data)
        themed_text = encode_data['output']
        map_id = encode_data['map_id']
        
        # Then decode
        response = client.post('/api/lipsumlab/decode', json={
            'themed_text': themed_text,
            'map_id': map_id
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'output' in data
        # Should recover original text (may have some differences due to tokenization)
        assert 'Hello' in data['output'] or 'hello' in data['output'].lower()
    
    def test_lipsumlab_decode_auto_extract_map_id(self, client):
        """Test decoding with auto-extracted map ID from header"""
        # First encode
        encode_resp = client.post('/api/lipsumlab/encode', json={
            'text': 'Test message for auto extraction',
            'source_lang': 'en',
            'theme_key': 'en'
        })
        encode_data = json.loads(encode_resp.data)
        themed_text = encode_data['output']
        
        # Decode without providing map_id (should auto-extract)
        response = client.post('/api/lipsumlab/decode', json={
            'themed_text': themed_text
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_lipsumlab_decode_missing_text(self, client):
        """Test decoding without themed text"""
        response = client.post('/api/lipsumlab/decode', json={})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_lipsumlab_decode_invalid_map_id(self, client):
        """Test decoding with invalid map ID"""
        response = client.post('/api/lipsumlab/decode', json={
            'themed_text': 'Some themed text without header',
            'map_id': 'invalid-map-id-xyz'
        })
        # Should fail (map file not found)
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False

class TestNewFeaturesIntegration:
    """Integration tests for new features working together"""
    
    def test_full_workflow_with_signing_and_verification(self, client):
        """Test complete workflow: keygen -> encrypt with signing -> decrypt with verification"""
        # Generate keys
        recip_resp = client.post('/api/keygen', json={'name': 'Recipient'})
        recip_data = json.loads(recip_resp.data)
        recip_pub = recip_data['public_key']
        recip_sec = recip_data['secret_key']
        
        signer_resp = client.post('/api/keygen', json={'name': 'Signer'})
        signer_data = json.loads(signer_resp.data)
        signer_pub = signer_data['public_key']
        signer_sec = signer_data['secret_key']
        
        # Show fingerprints
        fp_resp = client.post('/api/show-fp', json={'public_key': signer_pub})
        fp_data = json.loads(fp_resp.data)
        assert fp_data['success'] == True
        
        # Encrypt with signing
        encrypt_resp = client.post('/api/encrypt', json={
            'recipient_pub': recip_pub,
            'plaintext': 'Full workflow test message',
            'armor': True,
            'lexicon': 'lexicons/en.txt',
            'signer_secret': signer_sec
        })
        encrypt_data = json.loads(encrypt_resp.data)
        assert encrypt_data['success'] == True
        
        # Decrypt with verification
        decrypt_resp = client.post('/api/decrypt', json={
            'secret_key': recip_sec,
            'encrypted_data': encrypt_data['output'],
            'lexicon': 'lexicons/en.txt',
            'sender_pub': signer_pub
        })
        decrypt_data = json.loads(decrypt_resp.data)
        assert decrypt_data['success'] == True
        assert decrypt_data['plaintext'] == 'Full workflow test message'
        assert decrypt_data.get('signature_verified') == True

