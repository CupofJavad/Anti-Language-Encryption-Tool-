#!/usr/bin/env python3
"""
Final Validation - Simulates Real Deployment Scenario
"""
import sys
import os
import json
from pathlib import Path

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def validate_deployment_readiness():
    """Final validation before deployment"""
    print("="*70)
    print("FINAL DEPLOYMENT VALIDATION")
    print("="*70)
    
    all_checks = []
    
    # Check 1: All required files exist
    print("\n1. Checking required files...")
    web_app = Path(__file__).parent
    required_files = {
        'app.py': web_app / 'app.py',
        'requirements.txt': web_app / 'requirements.txt',
        'Dockerfile': web_app / 'Dockerfile',
        'templates/index.html': web_app / 'templates' / 'index.html',
        'templates/embed.html': web_app / 'templates' / 'embed.html',
    }
    
    for name, path in required_files.items():
        exists = path.exists()
        all_checks.append(('File', name, exists))
        print(f"   {'✅' if exists else '❌'} {name}")
    
    # Check 2: App functionality
    print("\n2. Testing app functionality...")
    try:
        import app
        with app.app.test_client() as client:
            # Test keygen
            resp = client.post('/api/keygen', json={'name': 'FinalTest'})
            keys = resp.get_json()
            keygen_works = keys.get('success', False)
            all_checks.append(('Functionality', 'Key Generation', keygen_works))
            print(f"   {'✅' if keygen_works else '❌'} Key Generation")
            
            if keygen_works:
                # Test encrypt
                enc_resp = client.post('/api/encrypt', json={
                    'recipient_pub': keys['public_key'],
                    'plaintext': 'Final validation test',
                    'armor': True
                })
                encrypt_works = enc_resp.get_json().get('success', False)
                all_checks.append(('Functionality', 'Encryption', encrypt_works))
                print(f"   {'✅' if encrypt_works else '❌'} Encryption")
                
                # Test decrypt
                if encrypt_works:
                    encrypted = enc_resp.get_json()
                    dec_resp = client.post('/api/decrypt', json={
                        'secret_key': keys['secret_key'],
                        'encrypted_data': encrypted['output']
                    })
                    decrypt_works = dec_resp.get_json().get('success', False)
                    all_checks.append(('Functionality', 'Decryption', decrypt_works))
                    print(f"   {'✅' if decrypt_works else '❌'} Decryption")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        all_checks.append(('Functionality', 'App Test', False))
    
    # Check 3: Routes
    print("\n3. Testing routes...")
    try:
        import app
        with app.app.test_client() as client:
            routes = {
                '/': client.get('/'),
                '/embed': client.get('/embed'),
            }
            for route, resp in routes.items():
                works = resp.status_code == 200
                all_checks.append(('Route', route, works))
                print(f"   {'✅' if works else '❌'} {route}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Check 4: Deployment config
    print("\n4. Checking deployment configuration...")
    config_file = web_app / 'deploy_config.example'
    if config_file.exists():
        content = config_file.read_text()
        has_token_placeholder = 'DIGITALOCEAN_API_TOKEN' in content
        all_checks.append(('Config', 'deploy_config.example', has_token_placeholder))
        print(f"   {'✅' if has_token_placeholder else '❌'} deploy_config.example")
    
    # Check 5: Dockerfile validity
    print("\n5. Validating Dockerfile...")
    dockerfile = web_app / 'Dockerfile'
    if dockerfile.exists():
        content = dockerfile.read_text()
        has_from = 'FROM' in content
        has_copy = 'COPY' in content
        has_cmd = 'CMD' in content or 'ENTRYPOINT' in content
        dockerfile_valid = has_from and has_copy and has_cmd
        all_checks.append(('Dockerfile', 'Structure', dockerfile_valid))
        print(f"   {'✅' if dockerfile_valid else '❌'} Dockerfile structure")
    
    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, _, result in all_checks if result)
    total = len(all_checks)
    
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 ALL VALIDATION CHECKS PASSED!")
        print("✅ Ready for deployment to DigitalOcean!")
        return True
    else:
        print("\n⚠️  Some checks failed - review above")
        return False

if __name__ == '__main__':
    success = validate_deployment_readiness()
    sys.exit(0 if success else 1)

