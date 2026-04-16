#!/usr/bin/env python3
"""
Jour 3 - Asymmetric Key Exchange Test Suite
Tests RSA-2048 key exchange, key encapsulation, and message encryption
"""

import socket
import json
import base64
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from client import encrypt_text, decrypt_text

def json_line(p):
    return (json.dumps(p, separators=(",", ":")) + "\n").encode()

def auth_jour3(username, password, port=5050):
    """
    Authenticate user via Jour 3 asymmetric key exchange.
    Returns: (socket, message_key)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    s.settimeout(5)
    
    # Step 1: Hello
    s.sendall(json_line({"type": "hello", "username": username}))
    resp = json.loads(s.recv(4096).decode())
    assert resp['type'] == 'auth_required'
    
    # Step 2: Auth
    s.sendall(json_line({"type": "auth", "password": password, "confirm": password}))
    resp = json.loads(s.recv(4096).decode())
    assert resp['type'] == 'key_required'
    
    # Extract key exchange parameters
    salt = base64.b64decode(resp['salt'])
    server_pub_pem = resp['server_public_key']
    iterations = resp['iterations']
    
    # Step 3: Generate client RSA keypair
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    # Step 4: Send client public key
    s.sendall(json_line({"type": "client_public_key", "public_key": pub_pem}))
    resp = json.loads(s.recv(4096).decode())
    assert resp['type'] == 'encapsulate_key'
    
    # Step 5: Derive message key and encapsulate
    msg_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, 16)
    server_pub = serialization.load_pem_public_key(server_pub_pem.encode(), default_backend())
    encrypted = server_pub.encrypt(msg_key, padding.OAEP(
        padding.MGF1(hashes.SHA256()),
        hashes.SHA256(),
        None
    ))
    
    # Step 6: Send encapsulated key
    s.sendall(json_line({"type": "key_encapsulation", "encapsulated_key": base64.b64encode(encrypted).decode()}))
    resp = json.loads(s.recv(4096).decode())
    assert resp['type'] == 'welcome'
    
    return s, msg_key

def test_jour3():
    """Run all Jour 3 tests"""
    print("\n" + "="*70)
    print(" JOUR 3 - ASYMMETRIC KEY EXCHANGE TEST SUITE")
    print("="*70 + "\n")
    
    pwd = "SecurePass123!@"
    
    # Test 1: Client keypair generation and exchange
    print("[TEST 1] RSA Keypair generation and key exchange...")
    try:
        alice_sock, alice_key = auth_jour3("alice_j3", pwd)
        print(f"  ✓ Alice authenticated via Jour 3")
        print(f"    Message key: {alice_key.hex()[:16]}...")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False
    
    # Test 2: Multiple users can connect
    print("\n[TEST 2] Multiple concurrent users...")
    try:
        bob_sock, bob_key = auth_jour3("bob_j3", pwd)
        print(f"  ✓ Bob authenticated via Jour 3")
        print(f"    Message key: {bob_key.hex()[:16]}...")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        alice_sock.close()
        return False
    
    # Test 3: Message encryption and decryption
    print("\n[TEST 3] Message encryption through session key...")
    try:
        plaintext = "Test message from Jour 3"
        ciphertext = encrypt_text(plaintext, alice_key)
        print(f"  ✓ Encrypted: {ciphertext[:40]}...")
        
        alice_sock.sendall(json_line({"type": "message", "ciphertext": ciphertext}))
        time.sleep(0.5)
        
        # Skip notification
        bob_sock.settimeout(10)
        notif = json.loads(bob_sock.recv(4096).decode())
        msg = json.loads(bob_sock.recv(4096).decode())
        
        decrypted = decrypt_text(msg['ciphertext'], bob_key)
        if decrypted == plaintext:
            print(f"  ✓ Decrypted correctly: '{decrypted}'")
        else:
            print(f"  ✗ Plaintext mismatch")
            return False
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False
    finally:
        alice_sock.close()
        bob_sock.close()
    
    print("\n" + "="*70)
    print(" ✓✓✓ ALL JOUR 3 TESTS PASSED ✓✓✓")
    print("="*70 + "\n")
    return True

if __name__ == "__main__":
    import sys
    success = test_jour3()
    sys.exit(0 if success else 1)
