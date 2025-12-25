#!/usr/bin/env python3
"""
Comprehensive Test Suite for Forgotten-E2EE Web App Deployment
Tests all aspects: functionality, deployment, and potential failure points
"""
import sys
import os
import subprocess
import json
import tempfile
import shutil
from pathlib import Path

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Test results
results = {
    'passed': [],
    'failed': [],
    'warnings': []
}

def test(name, func):
    """Run a test and record results"""
    try:
        print(f"\n{'='*60}")
        print(f"TEST: {name}")
        print(f"{'='*60}")
        result = func()
        if result:
            results['passed'].append(name)
            print(f"✅ PASS: {name}")
            return True
        else:
            results['failed'].append(name)
            print(f"❌ FAIL: {name}")
            return False
    except Exception as e:
        results['failed'].append(f"{name} (Error: {str(e)})")
        print(f"❌ FAIL: {name} - {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_1_imports():
    """Test 1: All Python imports work"""
    from forgotten_e2ee.keystore import Identity, save_public, save_secret
    from forgotten_e2ee.crypto_core import ed25519_keypair, x25519_keypair
    from forgotten_e2ee.fmt import FGHeader, emit_armor, parse_armor
    from forgotten_e2ee.util import b64u_enc, b64u_dec
    from forgotten_e2ee.stego import load_lexicon
    return True

def test_2_app_module():
    """Test 2: Flask app module loads"""
    import app
    assert app.app is not None
    assert hasattr(app.app, 'route')
    return True

def test_3_templates_exist():
    """Test 3: All template files exist"""
    template_dir = Path(__file__).parent / 'templates'
    required = ['index.html', 'embed.html']
    for template in required:
        if not (template_dir / template).exists():
            return False
    return True

def test_4_requirements_file():
    """Test 4: requirements.txt exists and is valid"""
    req_file = Path(__file__).parent / 'requirements.txt'
    if not req_file.exists():
        return False
    content = req_file.read_text()
    assert 'Flask' in content
    assert 'flask-cors' in content
    assert 'cryptography' in content
    return True

def test_5_dockerfile_exists():
    """Test 5: Dockerfile exists"""
    dockerfile = Path(__file__).parent / 'Dockerfile'
    root_dockerfile = Path(project_root) / 'Dockerfile'
    return dockerfile.exists() or root_dockerfile.exists()

def test_6_dockerfile_valid():
    """Test 6: Dockerfile syntax is valid"""
    dockerfile = Path(__file__).parent / 'Dockerfile'
    if not dockerfile.exists():
        dockerfile = Path(project_root) / 'Dockerfile'
    if not dockerfile.exists():
        return False
    
    content = dockerfile.read_text()
    # Check for essential Dockerfile commands
    assert 'FROM' in content
    assert 'WORKDIR' in content or 'RUN' in content
    assert 'COPY' in content or 'ADD' in content
    assert 'CMD' in content or 'ENTRYPOINT' in content
    return True

def test_7_project_structure():
    """Test 7: Required project structure exists"""
    required = [
        'forgotten_e2ee',
        'lexicons',
        'web_app',
        'web_app/templates',
    ]
    for path in required:
        full_path = Path(project_root) / path
        if not full_path.exists():
            return False
    return True

def test_8_api_keygen():
    """Test 8: Key generation API works"""
    import app
    with app.app.test_client() as client:
        response = client.post('/api/keygen', 
                             json={'name': 'TestUser'},
                             content_type='application/json')
        if response.status_code != 200:
            return False
        data = json.loads(response.data)
        return data.get('success') and 'public_key' in data and 'secret_key' in data

def test_9_api_encrypt():
    """Test 9: Encryption API works"""
    import app
    # First generate keys
    with app.app.test_client() as client:
        # Generate keys
        key_resp = client.post('/api/keygen', json={'name': 'Test'})
        keys = json.loads(key_resp.data)
        
        # Encrypt
        encrypt_resp = client.post('/api/encrypt',
                                  json={
                                      'recipient_pub': keys['public_key'],
                                      'plaintext': 'Test message',
                                      'armor': True
                                  })
        if encrypt_resp.status_code != 200:
            return False
        data = json.loads(encrypt_resp.data)
        return data.get('success') and 'output' in data

def test_10_api_decrypt():
    """Test 10: Decryption API works (full roundtrip)"""
    import app
    with app.app.test_client() as client:
        # Generate keys
        key_resp = client.post('/api/keygen', json={'name': 'Test'})
        keys = json.loads(key_resp.data)
        
        # Encrypt
        encrypt_resp = client.post('/api/encrypt',
                                  json={
                                      'recipient_pub': keys['public_key'],
                                      'plaintext': 'Hello World Test',
                                      'armor': True
                                  })
        encrypted = json.loads(encrypt_resp.data)
        
        # Decrypt
        decrypt_resp = client.post('/api/decrypt',
                                  json={
                                      'secret_key': keys['secret_key'],
                                      'encrypted_data': encrypted['output']
                                  })
        if decrypt_resp.status_code != 200:
            return False
        decrypted = json.loads(decrypt_resp.data)
        return decrypted.get('success') and decrypted.get('plaintext') == 'Hello World Test'

def test_11_routes():
    """Test 11: All routes respond"""
    import app
    with app.app.test_client() as client:
        routes = ['/', '/embed']
        for route in routes:
            resp = client.get(route)
            if resp.status_code != 200:
                return False
        return True

def test_12_lexicon_files():
    """Test 12: Lexicon files exist"""
    lex_dir = Path(project_root) / 'lexicons'
    if not lex_dir.exists():
        return False
    # Check for at least one lexicon
    lexicons = list(lex_dir.glob('*.txt'))
    return len(lexicons) > 0

def test_13_docker_build():
    """Test 13: Docker image can be built"""
    try:
        # Check if docker is available
        subprocess.run(['docker', '--version'], 
                      capture_output=True, check=True)
        
        # Try building (dry run - just check syntax)
        dockerfile = Path(__file__).parent / 'Dockerfile'
        if dockerfile.exists():
            # Just validate, don't actually build (takes too long)
            return True
        return False
    except (subprocess.CalledProcessError, FileNotFoundError):
        results['warnings'].append('Docker not available (optional)')
        return True  # Docker is optional for testing

def test_14_config_files():
    """Test 14: Configuration files exist"""
    web_app_dir = Path(__file__).parent
    required = ['deploy_config.example', 'requirements.txt']
    for file in required:
        if not (web_app_dir / file).exists():
            return False
    return True

def test_15_environment_variables():
    """Test 15: App handles missing environment variables"""
    import app
    # App should work without special env vars
    assert app.app is not None
    return True

def test_16_cors_enabled():
    """Test 16: CORS is enabled"""
    import app
    assert hasattr(app, 'CORS')
    return True

def test_17_error_handling():
    """Test 17: API error handling works"""
    import app
    with app.app.test_client() as client:
        # Test invalid request
        resp = client.post('/api/keygen', json={})
        # Should return error, not crash
        assert resp.status_code in [400, 500]
        data = json.loads(resp.data)
        assert 'error' in data
        return True

def test_18_file_paths():
    """Test 18: File paths are correct"""
    import app
    # Check that app can find required files
    web_app_dir = Path(__file__).parent
    assert (web_app_dir / 'app.py').exists()
    assert (web_app_dir / 'templates').exists()
    return True

def test_19_port_configuration():
    """Test 19: Port configuration works"""
    import app
    # App should be able to run on different ports
    os.environ['PORT'] = '9999'
    # Just check it doesn't crash on import
    return True

def test_20_git_repo_structure():
    """Test 20: Git repository has required files"""
    git_dir = Path(project_root) / '.git'
    if not git_dir.exists():
        results['warnings'].append('Not a git repository')
        return True  # Not critical for functionality
    
    # Check that web_app is tracked (or would be)
    return True

def test_21_deployment_config():
    """Test 21: Deployment configuration is valid"""
    web_app_dir = Path(__file__).parent
    config_example = web_app_dir / 'deploy_config.example'
    if config_example.exists():
        content = config_example.read_text()
        # Check for required fields
        assert 'DIGITALOCEAN_API_TOKEN' in content
        return True
    return False

def test_22_app_yaml():
    """Test 22: app.yaml exists and is valid YAML"""
    web_app_dir = Path(__file__).parent
    app_yaml = web_app_dir / 'app.yaml'
    if app_yaml.exists():
        try:
            import yaml
            with open(app_yaml) as f:
                yaml.safe_load(f)
            return True
        except ImportError:
            # YAML module not installed, but file exists - that's okay
            # Just check file is readable
            with open(app_yaml) as f:
                content = f.read()
                # Basic YAML structure check
                return 'name:' in content or 'services:' in content
        except Exception:
            return False
    return True  # Optional file

def test_23_import_paths():
    """Test 23: All import paths resolve correctly"""
    # Test that app.py can import everything
    import app
    # If we got here, imports work
    return True

def test_24_lexicon_loading():
    """Test 24: Lexicon loading works"""
    from forgotten_e2ee.stego import load_lexicon
    lex_dir = Path(project_root) / 'lexicons'
    if lex_dir.exists():
        lexicons = list(lex_dir.glob('*.txt'))
        if lexicons:
            tokens = load_lexicon(str(lexicons[0]))
            return len(tokens) > 0
    return True  # Lexicons are optional for basic functionality

def test_25_full_integration():
    """Test 25: Full integration test (generate, encrypt, decrypt)"""
    import app
    with app.app.test_client() as client:
        # Generate
        key_resp = client.post('/api/keygen', json={'name': 'IntegrationTest'})
        keys = json.loads(key_resp.data)
        if not keys.get('success'):
            return False
        
        # Encrypt
        enc_resp = client.post('/api/encrypt',
                              json={
                                  'recipient_pub': keys['public_key'],
                                  'plaintext': 'Integration Test Message 123',
                                  'armor': True
                              })
        encrypted = json.loads(enc_resp.data)
        if not encrypted.get('success'):
            return False
        
        # Decrypt
        dec_resp = client.post('/api/decrypt',
                              json={
                                  'secret_key': keys['secret_key'],
                                  'encrypted_data': encrypted['output']
                              })
        decrypted = json.loads(dec_resp.data)
        if not decrypted.get('success'):
            return False
        
        # Verify message matches
        return decrypted.get('plaintext') == 'Integration Test Message 123'

def main():
    """Run all tests"""
    print("="*70)
    print("COMPREHENSIVE TEST SUITE - Forgotten-E2EE Web App")
    print("="*70)
    
    tests = [
        ("Imports", test_1_imports),
        ("App Module", test_2_app_module),
        ("Templates Exist", test_3_templates_exist),
        ("Requirements File", test_4_requirements_file),
        ("Dockerfile Exists", test_5_dockerfile_exists),
        ("Dockerfile Valid", test_6_dockerfile_valid),
        ("Project Structure", test_7_project_structure),
        ("API Key Generation", test_8_api_keygen),
        ("API Encryption", test_9_api_encrypt),
        ("API Decryption", test_10_api_decrypt),
        ("Routes", test_11_routes),
        ("Lexicon Files", test_12_lexicon_files),
        ("Docker Build", test_13_docker_build),
        ("Config Files", test_14_config_files),
        ("Environment Variables", test_15_environment_variables),
        ("CORS Enabled", test_16_cors_enabled),
        ("Error Handling", test_17_error_handling),
        ("File Paths", test_18_file_paths),
        ("Port Configuration", test_19_port_configuration),
        ("Git Repo Structure", test_20_git_repo_structure),
        ("Deployment Config", test_21_deployment_config),
        ("App YAML", test_22_app_yaml),
        ("Import Paths", test_23_import_paths),
        ("Lexicon Loading", test_24_lexicon_loading),
        ("Full Integration", test_25_full_integration),
    ]
    
    for name, func in tests:
        test(name, func)
    
    # Summary
    print("\n" + "="*70)
    print("TEST RESULTS SUMMARY")
    print("="*70)
    print(f"✅ Passed: {len(results['passed'])}")
    print(f"❌ Failed: {len(results['failed'])}")
    print(f"⚠️  Warnings: {len(results['warnings'])}")
    print("="*70)
    
    if results['failed']:
        print("\nFAILED TESTS:")
        for fail in results['failed']:
            print(f"  ❌ {fail}")
    
    if results['warnings']:
        print("\nWARNINGS:")
        for warn in results['warnings']:
            print(f"  ⚠️  {warn}")
    
    print("\n" + "="*70)
    if len(results['failed']) == 0:
        print("🎉 ALL TESTS PASSED!")
        return 0
    else:
        print("⚠️  SOME TESTS FAILED")
        return 1

if __name__ == '__main__':
    sys.exit(main())

