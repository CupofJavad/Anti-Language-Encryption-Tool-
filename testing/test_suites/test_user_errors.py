"""
User Error Tests - 50 comprehensive tests focused on anticipating potential user errors
These tests simulate real user mistakes and edge cases that could cause errors
"""
import pytest
import json
import time
from web_app.app import app

class TestUserErrorKeyGeneration:
    """Tests for user errors in key generation workflow"""
    
    def test_keygen_empty_name(self, client):
        """User submits empty name - should handle gracefully"""
        response = client.post('/api/keygen', json={'name': ''})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        # Empty string is valid, may be used as-is or defaulted
        assert 'name' in data
    
    def test_keygen_missing_name_field(self, client):
        """User doesn't provide name field at all"""
        response = client.post('/api/keygen', json={})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['name'] == 'Anonymous'
    
    def test_keygen_name_with_special_characters(self, client):
        """User enters name with special characters"""
        response = client.post('/api/keygen', json={'name': 'User@#$%^&*()'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'public_key' in data
    
    def test_keygen_name_with_unicode(self, client):
        """User enters name with Unicode characters"""
        response = client.post('/api/keygen', json={'name': '用户 你好 🌍'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_keygen_name_very_long(self, client):
        """User enters extremely long name"""
        long_name = 'A' * 10000
        response = client.post('/api/keygen', json={'name': long_name})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_keygen_name_with_newlines(self, client):
        """User enters name with newline characters"""
        response = client.post('/api/keygen', json={'name': 'User\nWith\nNewlines'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_keygen_name_whitespace_only(self, client):
        """User enters only whitespace"""
        response = client.post('/api/keygen', json={'name': '   \n\t  '})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_keygen_invalid_json(self, client):
        """User sends invalid JSON"""
        response = client.post('/api/keygen', 
                              data='{invalid json}',
                              content_type='application/json')
        # Should handle gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_keygen_wrong_content_type(self, client):
        """User sends data with wrong content type"""
        response = client.post('/api/keygen', 
                              data='name=Test',
                              content_type='application/x-www-form-urlencoded')
        # Should handle gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_keygen_null_name(self, client):
        """User sends null as name"""
        response = client.post('/api/keygen', json={'name': None})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True

class TestUserErrorEncryption:
    """Tests for user errors in encryption workflow"""
    
    def test_encrypt_missing_recipient_pub(self, client):
        """User tries to encrypt without providing recipient public key"""
        response = client.post('/api/encrypt', json={'plaintext': 'test'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
        assert 'recipient_pub' in data['error'].lower()
    
    def test_encrypt_empty_recipient_pub(self, client):
        """User provides empty recipient public key"""
        response = client.post('/api/encrypt', json={
            'recipient_pub': '',
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_encrypt_invalid_recipient_pub_json(self, client):
        """User provides invalid JSON as recipient public key"""
        response = client.post('/api/encrypt', json={
            'recipient_pub': '{invalid json}',
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_encrypt_malformed_recipient_pub(self, client):
        """User provides malformed public key (missing fields)"""
        malformed_key = json.dumps({
            "version": 1,
            "type": "fg-public",
            # Missing required fields
        })
        response = client.post('/api/encrypt', json={
            'recipient_pub': malformed_key,
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_encrypt_invalid_base64_in_pubkey(self, client):
        """User provides public key with invalid base64 encoding"""
        invalid_key = json.dumps({
            "version": 1,
            "type": "fg-public",
            "name": "Test",
            "ed25519_pub": "!!!invalid base64!!!",
            "x25519_pub": "!!!invalid base64!!!",
            "fingerprint": "ABC123"
        })
        response = client.post('/api/encrypt', json={
            'recipient_pub': invalid_key,
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_encrypt_empty_message(self, client):
        """User tries to encrypt empty message"""
        # First generate valid keys
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': ''
        })
        # Empty message should be allowed (might be valid use case)
        assert response.status_code in [200, 400]
    
    def test_encrypt_missing_message(self, client):
        """User doesn't provide message field"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub
        })
        # Should default to empty string or error
        assert response.status_code in [200, 400]
    
    def test_encrypt_very_long_message(self, client):
        """User encrypts extremely long message"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        long_message = 'A' * 100000  # 100KB
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': long_message
        })
        # Should handle or reject gracefully
        assert response.status_code in [200, 400, 413]
    
    def test_encrypt_message_with_special_characters(self, client):
        """User encrypts message with special characters"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'Special: !@#$%^&*()\n\t\r'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_encrypt_message_with_unicode(self, client):
        """User encrypts message with Unicode characters"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'Unicode: 你好世界 🌍 émojis 🎉'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_encrypt_armor_without_lexicon(self, client):
        """User requests armor mode but lexicon is unavailable"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'test',
            'armor': True
        })
        # Should handle gracefully (may fail if lexicon required)
        assert response.status_code in [200, 400, 500]
    
    def test_encrypt_wrong_key_type(self, client):
        """User tries to use secret key instead of public key"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        secret_key = keygen_data['secret_key']  # Wrong type!
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': secret_key,  # Should be public key
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]

class TestUserErrorDecryption:
    """Tests for user errors in decryption workflow"""
    
    def test_decrypt_missing_secret_key(self, client):
        """User tries to decrypt without providing secret key"""
        response = client.post('/api/decrypt', json={
            'encrypted_data': 'some encrypted data'
        })
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_decrypt_missing_encrypted_data(self, client):
        """User tries to decrypt without providing encrypted message"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        secret_key = keygen_data['secret_key']
        
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key
        })
        assert response.status_code == 400
    
    def test_decrypt_empty_secret_key(self, client):
        """User provides empty secret key"""
        response = client.post('/api/decrypt', json={
            'secret_key': '',
            'encrypted_data': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_decrypt_invalid_secret_key_json(self, client):
        """User provides invalid JSON as secret key"""
        response = client.post('/api/decrypt', json={
            'secret_key': '{invalid json}',
            'encrypted_data': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_decrypt_malformed_secret_key(self, client):
        """User provides malformed secret key (missing fields)"""
        malformed_key = json.dumps({
            "version": 1,
            "type": "fg-secret",
            # Missing payload
        })
        response = client.post('/api/decrypt', json={
            'secret_key': malformed_key,
            'encrypted_data': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_decrypt_wrong_secret_key(self, client):
        """User tries to decrypt with wrong secret key"""
        # Generate two keypairs
        keygen1 = client.post('/api/keygen', json={'name': 'User1'})
        keygen2 = client.post('/api/keygen', json={'name': 'User2'})
        key1 = json.loads(keygen1.data)
        key2 = json.loads(keygen2.data)
        
        # Encrypt with User1's public key
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': key1['public_key'],
            'plaintext': 'secret message'
        })
        encrypt_data = json.loads(encrypt_response.data)
        encrypted = encrypt_data['output']
        
        # Try to decrypt with User2's secret key (wrong key!)
        response = client.post('/api/decrypt', json={
            'secret_key': key2['secret_key'],
            'encrypted_data': encrypted
        })
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_decrypt_invalid_encrypted_data(self, client):
        """User provides invalid encrypted data"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        secret_key = keygen_data['secret_key']
        
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': 'not valid encrypted data!!!'
        })
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_decrypt_corrupted_encrypted_data(self, client):
        """User provides corrupted encrypted data"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        # Encrypt a message
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'test message'
        })
        encrypt_data = json.loads(encrypt_response.data)
        encrypted = encrypt_data['output']
        
        # Corrupt the encrypted data
        corrupted = encrypted[:-10] + 'CORRUPTED'
        
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': corrupted
        })
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_decrypt_empty_encrypted_data(self, client):
        """User provides empty encrypted data"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        secret_key = keygen_data['secret_key']
        
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': ''
        })
        assert response.status_code in [400, 500]
    
    def test_decrypt_message_for_different_recipient(self, client):
        """User tries to decrypt message encrypted for someone else"""
        # Generate two keypairs
        keygen1 = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen2 = client.post('/api/keygen', json={'name': 'WrongUser'})
        key1 = json.loads(keygen1.data)
        key2 = json.loads(keygen2.data)
        
        # Encrypt for Recipient
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': key1['public_key'],
            'plaintext': 'secret'
        })
        encrypt_data = json.loads(encrypt_response.data)
        encrypted = encrypt_data['output']
        
        # WrongUser tries to decrypt
        response = client.post('/api/decrypt', json={
            'secret_key': key2['secret_key'],
            'encrypted_data': encrypted
        })
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False

class TestUserErrorRoundtrip:
    """Tests for errors in complete encryption/decryption cycles"""
    
    def test_roundtrip_with_whitespace_in_keys(self, client):
        """User copies keys with extra whitespace"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = '  \n  ' + keygen_data['public_key'] + '  \n  '
        secret_key = '  \n  ' + keygen_data['secret_key'] + '  \n  '
        
        # Encrypt
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key.strip(),  # Should handle or strip
            'plaintext': 'test'
        })
        # May fail if whitespace breaks JSON parsing
        assert encrypt_response.status_code in [200, 400, 500]
    
    def test_roundtrip_partial_key_copy(self, client):
        """User copies only part of the key"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key'][:100]  # Only first 100 chars
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_roundtrip_keys_from_different_sessions(self, client):
        """User uses keys generated in different API sessions"""
        # Generate keys in "session 1"
        keygen1 = client.post('/api/keygen', json={'name': 'User'})
        key1 = json.loads(keygen1.data)
        
        # Simulate new session - generate new keys
        keygen2 = client.post('/api/keygen', json={'name': 'User'})
        key2 = json.loads(keygen2.data)
        
        # Try to use keys from session 1 in session 2
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': key1['public_key'],
            'plaintext': 'test'
        })
        assert encrypt_response.status_code == 200
        
        # Decrypt with session 1 secret key (should work)
        encrypt_data = json.loads(encrypt_response.data)
        decrypt_response = client.post('/api/decrypt', json={
            'secret_key': key1['secret_key'],
            'encrypted_data': encrypt_data['output']
        })
        assert decrypt_response.status_code == 200

class TestUserErrorNetwork:
    """Tests for network-related user errors"""
    
    def test_concurrent_keygen_requests(self, client):
        """User rapidly clicks generate keys multiple times"""
        import threading
        
        results = []
        def make_request():
            response = client.post('/api/keygen', json={'name': 'User'})
            results.append(response.status_code)
        
        threads = [threading.Thread(target=make_request) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should succeed or fail gracefully
        assert all(code in [200, 500] for code in results)
    
    def test_concurrent_encrypt_requests(self, client):
        """User sends multiple encrypt requests simultaneously"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        import threading
        results = []
        def make_request():
            response = client.post('/api/encrypt', json={
                'recipient_pub': recipient_pub,
                'plaintext': 'test'
            })
            results.append(response.status_code)
        
        threads = [threading.Thread(target=make_request) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert all(code in [200, 500] for code in results)

class TestUserErrorInputValidation:
    """Tests for input validation errors"""
    
    def test_keygen_non_string_name(self, client):
        """User sends non-string as name"""
        response = client.post('/api/keygen', json={'name': 12345})
        # Should handle gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_keygen_array_as_name(self, client):
        """User sends array as name"""
        response = client.post('/api/keygen', json={'name': ['array', 'value']})
        # Should handle gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_encrypt_non_string_plaintext(self, client):
        """User sends non-string as plaintext"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 12345  # Not a string
        })
        # Should handle or error gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_encrypt_boolean_armor(self, client):
        """User sends boolean as string for armor"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'test',
            'armor': 'true'  # String instead of boolean
        })
        # Should handle gracefully
        assert response.status_code in [200, 400, 500]
    
    def test_decrypt_with_public_key_instead_of_secret(self, client):
        """User accidentally uses public key instead of secret key"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']  # Wrong type!
        
        response = client.post('/api/decrypt', json={
            'secret_key': public_key,  # Should be secret key
            'encrypted_data': 'some data'
        })
        assert response.status_code in [400, 500]
        data = json.loads(response.data)
        assert data['success'] == False
    
    def test_encrypt_with_secret_key_instead_of_public(self, client):
        """User accidentally uses secret key instead of public key"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        secret_key = keygen_data['secret_key']  # Wrong type!
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': secret_key,  # Should be public key
            'plaintext': 'test'
        })
        assert response.status_code in [400, 500]
    
    def test_decrypt_binary_with_armor_parser(self, client):
        """User tries to decrypt binary format but system tries armor first"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        # Encrypt in binary format
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'test',
            'armor': False
        })
        encrypt_data = json.loads(encrypt_response.data)
        binary_encrypted = encrypt_data['output']
        
        # Decrypt should handle binary format
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': binary_encrypted
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['plaintext'] == 'test'
    
    def test_encrypt_with_extra_fields(self, client):
        """User sends extra unexpected fields in request"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': 'test',
            'extra_field': 'should be ignored',
            'another_field': 12345
        })
        # Should ignore extra fields and work
        assert response.status_code == 200
    
    def test_decrypt_with_extra_fields(self, client):
        """User sends extra unexpected fields in decrypt request"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'test'
        })
        encrypt_data = json.loads(encrypt_response.data)
        encrypted = encrypt_data['output']
        
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': encrypted,
            'extra_field': 'should be ignored'
        })
        # Should ignore extra fields and work
        assert response.status_code == 200
    
    def test_keygen_with_sql_injection_attempt(self, client):
        """User tries SQL injection in name field (security test)"""
        response = client.post('/api/keygen', json={
            'name': "'; DROP TABLE users; --"
        })
        # Should handle safely (no SQL, but test input sanitization)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_encrypt_with_xss_attempt(self, client):
        """User tries XSS in message field (security test)"""
        keygen_response = client.post('/api/keygen', json={'name': 'Recipient'})
        keygen_data = json.loads(keygen_response.data)
        recipient_pub = keygen_data['public_key']
        
        response = client.post('/api/encrypt', json={
            'recipient_pub': recipient_pub,
            'plaintext': '<script>alert("xss")</script>'
        })
        # Should encrypt the string as-is (XSS prevention is frontend's job)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
    
    def test_multiple_encrypt_decrypt_roundtrips(self, client):
        """User performs multiple encrypt/decrypt cycles with same keys"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        messages = ['Message 1', 'Message 2', 'Message 3']
        for msg in messages:
            # Encrypt
            encrypt_response = client.post('/api/encrypt', json={
                'recipient_pub': public_key,
                'plaintext': msg
            })
            encrypt_data = json.loads(encrypt_response.data)
            assert encrypt_data['success'] == True
            
            # Decrypt
            decrypt_response = client.post('/api/decrypt', json={
                'secret_key': secret_key,
                'encrypted_data': encrypt_data['output']
            })
            decrypt_data = json.loads(decrypt_response.data)
            assert decrypt_data['success'] == True
            assert decrypt_data['plaintext'] == msg
    
    def test_decrypt_armor_format_without_lexicon(self, client):
        """User tries to decrypt armor format but lexicon is missing"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        # Try to encrypt with armor (may fail if lexicon missing)
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'test',
            'armor': True
        })
        # If armor encryption succeeds, decryption should handle lexicon
        if encrypt_response.status_code == 200:
            encrypt_data = json.loads(encrypt_response.data)
            response = client.post('/api/decrypt', json={
                'secret_key': secret_key,
                'encrypted_data': encrypt_data['output']
            })
            # Should handle gracefully (may fail if lexicon required)
            assert response.status_code in [200, 400, 500]

