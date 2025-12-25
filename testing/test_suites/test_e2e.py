"""
End-to-End Tests - Test complete workflows
"""
import pytest
import json
import time
import requests
from web_app.app import app
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Production URL for E2E testing
PRODUCTION_URL = "https://antilanguageencryptiontool-y9rjc.ondigitalocean.app"

class TestE2EKeyGeneration:
    """E2E tests for key generation"""
    
    @pytest.mark.e2e
    def test_keygen_production(self):
        """Test key generation on production"""
        response = requests.post(
            f"{PRODUCTION_URL}/api/keygen",
            json={'name': 'E2ETest'},
            timeout=10,
            verify=False  # Disable SSL verification for testing
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert 'public_key' in data
        assert 'secret_key' in data
    
    @pytest.mark.e2e
    def test_keygen_multiple_times(self):
        """Test generating multiple keypairs"""
        keys = []
        for i in range(3):
            response = requests.post(
                f"{PRODUCTION_URL}/api/keygen",
                json={'name': f'User{i}'},
                timeout=10
            )
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True
            keys.append(data)
        
        # Verify all keys are different
        fingerprints = [json.loads(k['public_key'])['fingerprint'] for k in keys]
        assert len(set(fingerprints)) == 3

class TestE2EEncryption:
    """E2E tests for encryption"""
    
    @pytest.mark.e2e
    def test_encrypt_decrypt_roundtrip_production(self):
        """Test complete encrypt-decrypt on production"""
        # Generate keys
        keygen_response = requests.post(
            f"{PRODUCTION_URL}/api/keygen",
            json={'name': 'E2EUser'},
            timeout=10
        )
        assert keygen_response.status_code == 200
        keygen_data = keygen_response.json()
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        # Encrypt
        plaintext = "E2E Test Message " + str(int(time.time()))
        encrypt_response = requests.post(
            f"{PRODUCTION_URL}/api/encrypt",
            json={
                'recipient_pub': public_key,
                'plaintext': plaintext,
                'armor': False
            },
            timeout=10
        )
        
        assert encrypt_response.status_code == 200
        encrypt_data = encrypt_response.json()
        assert encrypt_data['success'] == True
        encrypted_output = encrypt_data['output']
        
        # Decrypt
        decrypt_response = requests.post(
            f"{PRODUCTION_URL}/api/decrypt",
            json={
                'secret_key': secret_key,
                'encrypted_data': encrypted_output
            },
            timeout=10
        )
        
        assert decrypt_response.status_code == 200
        decrypt_data = decrypt_response.json()
        assert decrypt_data['success'] == True
        assert decrypt_data['plaintext'] == plaintext
    
    @pytest.mark.e2e
    def test_encrypt_different_messages(self):
        """Test encrypting different message types"""
        # Generate keys
        keygen_response = requests.post(
            f"{PRODUCTION_URL}/api/keygen",
            json={'name': 'TestUser'},
            timeout=10
        )
        keygen_data = keygen_response.json()
        public_key = keygen_data['public_key']
        
        test_messages = [
            "Short",
            "A" * 100,  # Long message
            "Special chars: !@#$%^&*()",
            "Unicode: 你好世界 🌍",
            "Newlines:\nLine1\nLine2",
        ]
        
        for msg in test_messages:
            response = requests.post(
                f"{PRODUCTION_URL}/api/encrypt",
                json={
                    'recipient_pub': public_key,
                    'plaintext': msg,
                    'armor': False
                },
                timeout=10
            )
            assert response.status_code == 200
            data = response.json()
            assert data['success'] == True

class TestE2EHealth:
    """E2E tests for health endpoint"""
    
    @pytest.mark.e2e
    def test_health_endpoint_production(self):
        """Test health endpoint on production"""
        response = requests.get(f"{PRODUCTION_URL}/health", timeout=10, verify=False)
        
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
    
    @pytest.mark.e2e
    def test_production_availability(self):
        """Test that production site is accessible"""
        response = requests.get(PRODUCTION_URL, timeout=10)
        assert response.status_code == 200

class TestE2EPages:
    """E2E tests for web pages"""
    
    @pytest.mark.e2e
    def test_index_page_loads(self):
        """Test index page loads on production"""
        response = requests.get(PRODUCTION_URL, timeout=10)
        assert response.status_code == 200
        assert 'Forgotten-E2EE' in response.text
    
    @pytest.mark.e2e
    def test_embed_page_loads(self):
        """Test embed page loads on production"""
        response = requests.get(f"{PRODUCTION_URL}/embed", timeout=10)
        assert response.status_code == 200
        assert 'Forgotten-E2EE' in response.text or 'Encrypt' in response.text

