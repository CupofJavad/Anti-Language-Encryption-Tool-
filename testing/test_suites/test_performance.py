"""
Performance Tests - Test application performance
"""
import pytest
import json
import time
from web_app.app import app

class TestPerformanceKeyGeneration:
    """Performance tests for key generation"""
    
    def test_keygen_response_time(self, client):
        """Test key generation response time"""
        start = time.time()
        response = client.post('/api/keygen', json={'name': 'PerfTest'})
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 1.0  # Should complete in under 1 second
    
    def test_keygen_concurrent_requests(self, client):
        """Test handling multiple concurrent keygen requests"""
        import threading
        
        results = []
        errors = []
        
        def make_request():
            try:
                response = client.post('/api/keygen', json={'name': 'Concurrent'})
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=make_request) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert all(code == 200 for code in results)

class TestPerformanceEncryption:
    """Performance tests for encryption"""
    
    def test_encrypt_response_time(self, client):
        """Test encryption response time"""
        # Generate keys first
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        
        start = time.time()
        response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'Performance test message',
            'armor': False
        })
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 2.0  # Should complete in under 2 seconds
    
    def test_encrypt_different_sizes(self, client):
        """Test encryption performance with different message sizes"""
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        
        sizes = [10, 100, 1000, 10000]
        for size in sizes:
            message = "A" * size
            start = time.time()
            response = client.post('/api/encrypt', json={
                'recipient_pub': public_key,
                'plaintext': message,
                'armor': False
            })
            elapsed = time.time() - start
            
            assert response.status_code == 200
            assert elapsed < 5.0  # Even large messages should complete

class TestPerformanceDecryption:
    """Performance tests for decryption"""
    
    def test_decrypt_response_time(self, client):
        """Test decryption response time"""
        # Generate keys and encrypt
        keygen_response = client.post('/api/keygen', json={'name': 'User'})
        keygen_data = json.loads(keygen_response.data)
        public_key = keygen_data['public_key']
        secret_key = keygen_data['secret_key']
        
        encrypt_response = client.post('/api/encrypt', json={
            'recipient_pub': public_key,
            'plaintext': 'Test message',
            'armor': False
        })
        encrypt_data = json.loads(encrypt_response.data)
        encrypted_output = encrypt_data['output']
        
        start = time.time()
        response = client.post('/api/decrypt', json={
            'secret_key': secret_key,
            'encrypted_data': encrypted_output
        })
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 2.0  # Should complete in under 2 seconds

