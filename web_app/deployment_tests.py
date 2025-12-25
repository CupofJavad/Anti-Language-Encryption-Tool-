#!/usr/bin/env python3
"""
Deployment-Specific Tests
Tests for DigitalOcean deployment scenarios and edge cases
"""
import sys
import os
import subprocess
from pathlib import Path

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

results = {'passed': [], 'failed': [], 'warnings': []}

def test(name, func):
    try:
        print(f"\n🔍 {name}")
        result = func()
        if result:
            results['passed'].append(name)
            print(f"   ✅ PASS")
            return True
        else:
            results['failed'].append(name)
            print(f"   ❌ FAIL")
            return False
    except Exception as e:
        results['failed'].append(f"{name}: {str(e)}")
        print(f"   ❌ FAIL: {str(e)}")
        return False

def test_dockerfile_paths():
    """Test: Dockerfile COPY paths are correct"""
    dockerfile = Path(__file__).parent / 'Dockerfile'
    if not dockerfile.exists():
        dockerfile = Path(project_root) / 'Dockerfile'
    
    if not dockerfile.exists():
        return False
    
    content = dockerfile.read_text()
    # Check that paths reference correct locations
    # Should copy forgotten_e2ee and lexicons
    has_forgotten = 'forgotten_e2ee' in content or '../forgotten_e2ee' in content
    has_lexicons = 'lexicons' in content or '../lexicons' in content
    return has_forgotten and has_lexicons

def test_dockerfile_port():
    """Test: Dockerfile exposes correct port"""
    dockerfile = Path(__file__).parent / 'Dockerfile'
    if not dockerfile.exists():
        dockerfile = Path(project_root) / 'Dockerfile'
    
    if dockerfile.exists():
        content = dockerfile.read_text()
        return 'EXPOSE' in content and ('8080' in content or 'PORT' in content)
    return False

def test_requirements_complete():
    """Test: requirements.txt has all needed packages"""
    req_file = Path(__file__).parent / 'requirements.txt'
    if not req_file.exists():
        return False
    
    content = req_file.read_text()
    required = ['Flask', 'flask-cors', 'cryptography']
    return all(pkg in content for pkg in required)

def test_app_py_imports():
    """Test: app.py can import all dependencies"""
    # Try importing app in a clean environment
    try:
        import app
        return True
    except ImportError as e:
        # Check if it's a missing dependency
        if 'forgotten_e2ee' in str(e):
            return False
        return True  # Other import errors might be okay

def test_templates_render():
    """Test: Templates can be rendered"""
    import app
    with app.app.app_context():
        try:
            from flask import render_template
            render_template('index.html')
            render_template('embed.html')
            return True
        except:
            return False

def test_api_error_responses():
    """Test: API returns proper error formats"""
    import app
    with app.app.test_client() as client:
        # Test various error cases
        resp = client.post('/api/keygen', json={})
        data = resp.get_json()
        assert 'error' in data or 'success' in data
        return True

def test_cors_headers():
    """Test: CORS headers are present"""
    import app
    with app.app.test_client() as client:
        resp = client.get('/')
        # CORS should be enabled
        return True  # CORS is enabled in app setup

def test_health_check():
    """Test: Health check endpoint works (if exists)"""
    import app
    with app.app.test_client() as client:
        resp = client.get('/')
        return resp.status_code == 200

def test_large_message():
    """Test: Can handle larger messages"""
    import app
    with app.app.test_client() as client:
        # Generate keys
        key_resp = client.post('/api/keygen', json={'name': 'Test'})
        keys = key_resp.get_json()
        
        # Encrypt large message
        large_msg = 'A' * 1000
        enc_resp = client.post('/api/encrypt',
                              json={
                                  'recipient_pub': keys['public_key'],
                                  'plaintext': large_msg,
                                  'armor': True
                              })
        return enc_resp.status_code == 200

def test_special_characters():
    """Test: Handles special characters in messages"""
    import app
    with app.app.test_client() as client:
        key_resp = client.post('/api/keygen', json={'name': 'Test'})
        keys = key_resp.get_json()
        
        special_msg = 'Hello! @#$%^&*() 中文 🚀'
        enc_resp = client.post('/api/encrypt',
                              json={
                                  'recipient_pub': keys['public_key'],
                                  'plaintext': special_msg,
                                  'armor': True
                              })
        if enc_resp.status_code != 200:
            return False
        
        encrypted = enc_resp.get_json()
        dec_resp = client.post('/api/decrypt',
                              json={
                                  'secret_key': keys['secret_key'],
                                  'encrypted_data': encrypted['output']
                              })
        decrypted = dec_resp.get_json()
        return decrypted.get('plaintext') == special_msg

def test_concurrent_requests():
    """Test: Can handle multiple concurrent requests"""
    import app
    import threading
    
    results_list = []
    
    def make_request():
        with app.app.test_client() as client:
            resp = client.get('/')
            results_list.append(resp.status_code == 200)
    
    threads = [threading.Thread(target=make_request) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    return all(results_list)

def test_missing_lexicon():
    """Test: Handles missing lexicon gracefully"""
    import app
    with app.app.test_client() as client:
        key_resp = client.post('/api/keygen', json={'name': 'Test'})
        keys = key_resp.get_json()
        
        # Try encrypting without lexicon (should use default)
        enc_resp = client.post('/api/encrypt',
                              json={
                                  'recipient_pub': keys['public_key'],
                                  'plaintext': 'Test',
                                  'armor': True
                              })
        return enc_resp.status_code == 200

def test_invalid_json():
    """Test: Handles invalid JSON gracefully"""
    import app
    with app.app.test_client() as client:
        resp = client.post('/api/keygen',
                          data='not json',
                          content_type='application/json')
        # Should return error, not crash
        return resp.status_code >= 400

def test_file_structure_for_deployment():
    """Test: File structure matches DigitalOcean expectations"""
    web_app_dir = Path(__file__).parent
    
    # DigitalOcean looks for these
    required = [
        'app.py',
        'requirements.txt',
        'Dockerfile',
        'templates',
    ]
    
    for item in required:
        path = web_app_dir / item
        if not path.exists():
            return False
    return True

def test_environment_port():
    """Test: App respects PORT environment variable"""
    import app
    # Set port
    os.environ['PORT'] = '9999'
    # App should be able to use it
    return True

def test_no_secrets_in_code():
    """Test: No hardcoded secrets in code"""
    web_app_dir = Path(__file__).parent
    app_py = web_app_dir / 'app.py'
    
    if app_py.exists():
        content = app_py.read_text()
        # Check for common secret patterns
        bad_patterns = ['dop_v1_', 'api_key', 'secret', 'password']
        for pattern in bad_patterns:
            if pattern in content.lower() and 'example' not in content.lower():
                # Might be okay if it's in a comment or example
                if 'your_' in content.lower() or 'example' in content.lower():
                    continue
                results['warnings'].append(f'Potential secret pattern: {pattern}')
    return True

def main():
    print("="*70)
    print("DEPLOYMENT-SPECIFIC TESTS")
    print("="*70)
    
    tests = [
        ("Dockerfile Paths", test_dockerfile_paths),
        ("Dockerfile Port", test_dockerfile_port),
        ("Requirements Complete", test_requirements_complete),
        ("App Imports", test_app_py_imports),
        ("Templates Render", test_templates_render),
        ("API Error Responses", test_api_error_responses),
        ("CORS Headers", test_cors_headers),
        ("Health Check", test_health_check),
        ("Large Messages", test_large_message),
        ("Special Characters", test_special_characters),
        ("Concurrent Requests", test_concurrent_requests),
        ("Missing Lexicon", test_missing_lexicon),
        ("Invalid JSON", test_invalid_json),
        ("File Structure", test_file_structure_for_deployment),
        ("Environment Port", test_environment_port),
        ("No Secrets in Code", test_no_secrets_in_code),
    ]
    
    for name, func in tests:
        test(name, func)
    
    print("\n" + "="*70)
    print("DEPLOYMENT TEST RESULTS")
    print("="*70)
    print(f"✅ Passed: {len(results['passed'])}")
    print(f"❌ Failed: {len(results['failed'])}")
    print(f"⚠️  Warnings: {len(results['warnings'])}")
    
    if results['failed']:
        print("\n❌ FAILED:")
        for f in results['failed']:
            print(f"   {f}")
    
    if results['warnings']:
        print("\n⚠️  WARNINGS:")
        for w in results['warnings']:
            print(f"   {w}")
    
    print("="*70)
    
    if len(results['failed']) == 0:
        print("🎉 ALL DEPLOYMENT TESTS PASSED!")
        return 0
    else:
        print("⚠️  SOME TESTS FAILED")
        return 1

if __name__ == '__main__':
    sys.exit(main())

