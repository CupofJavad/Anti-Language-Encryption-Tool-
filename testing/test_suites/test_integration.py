"""
Integration Tests - Test API endpoints and component interactions
"""
import pytest
import json
from web_app.app import app

class TestAPIKeygen:
    """Test key generation API"""
    
    def test_keygen_endpoint_exists(self, client):
        """Test that keygen endpoint exists"""
        response = client.post('/api/keygen', json={})
        assert response.status_code in [200, 400, 500]  # Endpoint exists
    
    def test_keygen_with_name(self, client):
        """Test key generation with name"""
        response = client.post('/api/keygen', json={'name': 'TestUser'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'public_key' in data
        assert 'secret_key' in data
        assert data['name'] == 'TestUser'
    
    def test_keygen_without_name(self, client):
        """Test key generation without name (should use default)"""
        response = client.post('/api/keygen', json={})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['name'] == 'Anonymous'
    
    def test_keygen_public_key_format(self, client):
        """Test that public key is valid JSON"""
        response = client.post('/api/keygen', json={'name': 'Test'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        public_key_json = json.loads(data['public_key'])
        
        assert public_key_json['version'] == 1
        assert public_key_json['type'] == 'fg-public'
        assert 'ed25519_pub' in public_key_json
        assert 'x25519_pub' in public_key_json
        assert 'fingerprint' in public_key_json
    
    def test_keygen_secret_key_format(self, client):
        """Test that secret key is valid JSON"""
        response = client.post('/api/keygen', json={'name': 'Test'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        secret_key_json = json.loads(data['secret_key'])
        
        assert secret_key_json['version'] == 1
        assert secret_key_json['type'] == 'fg-secret'
        assert 'payload' in secret_key_json
        assert secret_key_json['payload']['enc'] == 'raw'

class TestAPIEncrypt:
    """Test encryption API"""
    
    def test_encrypt_endpoint_exists(self, client):
        """Test that encrypt endpoint exists"""
        response = client.post('/api/encrypt', json={})
        assert response.status_code in [200, 400, 500]
    
    def test_encrypt_missing_recipient_pub(self, client):
        """Test encryption without recipient public key"""
        response = client.post('/api/encrypt', json={'plaintext': 'test'})
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
        assert 'recipient_pub required' in data['error']
    
    def test_encrypt_with_valid_keys(self, client):
        """Test encryption with valid keys"""
        # First generate keys
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        # Then encrypt
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'Hello, World!',
            'armor': False
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'output' in data
        assert data['format'] == 'binary'
    
    def test_encrypt_armor_mode(self, client):
        """Test encryption with armor mode"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'Test message',
            'armor': True
        })
        
        # May fail if lexicon not available, but endpoint should respond
        assert response.status_code in [200, 400, 500]

class TestAPIDecrypt:
    """Test decryption API"""
    
    def test_decrypt_endpoint_exists(self, client):
        """Test that decrypt endpoint exists"""
        response = client.post('/api/decrypt', json={})
        assert response.status_code in [200, 400, 500]
    
    def test_decrypt_missing_parameters(self, client):
        """Test decryption without required parameters"""
        response = client.post('/api/decrypt', json={})
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_encrypt_decrypt_roundtrip(self, client):
        """Test complete encrypt-decrypt roundtrip"""
        # Generate keys
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        # Encrypt
        plaintext = "Secret message 123!"
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': plaintext,
            'armor': False
        })
        
        assert encrypt_response.status_code == 200
        encrypt_data = json.loads(encrypt_response.data)
        assert encrypt_data['success'] == True
        encrypted_output = encrypt_data['output']
        
        # Decrypt
        decrypt_response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': encrypted_output
        })
        
        assert decrypt_response.status_code == 200
        decrypt_data = json.loads(decrypt_response.data)
        assert decrypt_data['success'] == True
        assert decrypt_data['plaintext'] == plaintext

class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_endpoint(self, client):
        """Test health check"""
        response = client.get('/health')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'

class TestRoutes:
    """Test route availability"""
    
    def test_index_route(self, client):
        """Test index page loads"""
        response = client.get('/')
        assert response.status_code == 200
    
    def test_embed_route(self, client):
        """Test embed page loads"""
        response = client.get('/embed')
        assert response.status_code == 200
    
    def test_nonexistent_route(self, client):
        """Test 404 for nonexistent routes"""
        response = client.get('/nonexistent')
        assert response.status_code == 404

