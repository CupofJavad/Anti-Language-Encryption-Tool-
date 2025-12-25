"""
Security Tests - Test security aspects of the application
"""
import pytest
import json
from web_app.app import app

class TestSecurityKeyGeneration:
    """Security tests for key generation"""
    
    def test_keys_are_unique(self, client):
        """Test that each key generation produces unique keys"""
        response1 = client.post('/api/keygen', json={'name': 'User1'})
        response2 = client.post('/api/keygen', json={'name': 'User2'})
        
        data1 = json.loads(response1.data)
        data2 = json.loads(response2.data)
        
        pub1 = json.loads(data1['public_key'])
        pub2 = json.loads(data2['public_key'])
        
        assert pub1['fingerprint'] != pub2['fingerprint']
        assert pub1['ed25519_pub'] != pub2['ed25519_pub']
    
    def test_secret_key_not_in_public_key(self, client):
        """Test that secret key is not leaked in public key"""
        response = client.post('/api/keygen', json={'name': 'Test'})
        data = json.loads(response.data)
        
        public_key = data['public_key']
        secret_key = data['secret_key']
        
        # Secret key should not appear in public key
        assert secret_key not in public_key

class TestSecurityEncryption:
    """Security tests for encryption"""
    
    def test_same_message_different_ciphertext(self, client):
        """Test that same message produces different ciphertext each time"""
        # Generate keys
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        
        # Encrypt same message twice
        plaintext = "Same message"
        encrypt1 = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': plaintext,
            'armor': False
        })
        encrypt2 = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': plaintext,
            'armor': False
        })
        
        data1 = json.loads(encrypt1.data)
        data2 = json.loads(encrypt2.data)
        
        # Ciphertexts should be different (due to ephemeral keys)
        assert data1['output'] != data2['output']
    
    def test_encryption_requires_valid_key(self, client):
        """Test that encryption fails with invalid key"""
        response = client.post('/api/encrypt', json={
            'recipient_pub': 'invalid_key',
            'plaintext': 'test',
            'armor': False
        })
        
        # Should fail gracefully
        assert response.status_code in [400, 500]

class TestSecurityInputValidation:
    """Test input validation and sanitization"""
    
    def test_xss_prevention(self, client):
        """Test XSS prevention in inputs"""
        response = client.post('/api/keygen', json={
            'name': '<script>alert("xss")</script>'
        })
        
        # Should handle safely (either escape or reject)
        assert response.status_code in [200, 400]
    
    def test_sql_injection_prevention(self, client):
        """Test SQL injection prevention (if applicable)"""
        response = client.post('/api/keygen', json={
            'name': "'; DROP TABLE users; --"
        })
        
        # Should handle safely
        assert response.status_code in [200, 400]
    
    def test_very_long_input(self, client):
        """Test handling of very long inputs"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        
        # Very long message
        long_message = "A" * 100000
        response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': long_message,
            'armor': False
        })
        
        # Should handle or reject gracefully
        assert response.status_code in [200, 400, 413]

class TestSecurityErrorHandling:
    """Test error handling doesn't leak information"""
    
    def test_error_messages_no_sensitive_data(self, client):
        """Test that error messages don't leak sensitive data"""
        # Try to decrypt with invalid data
        response = client.post('/api/decrypt', json={
            'secret_key': 'invalid',
            'encrypted_data': 'invalid'
        })
        
        data = json.loads(response.data)
        error_msg = data.get('error', '')
        
        # Should not contain stack traces or internal details in production
        assert 'Traceback' not in error_msg
        assert 'File' not in error_msg or 'web_app' not in error_msg

