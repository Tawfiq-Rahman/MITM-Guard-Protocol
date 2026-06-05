from crypto_core import RSAEngine

def run_all_tests():
    print("=========================================")
    print("  RUNNING CRYPTO_CORE.PY UNIT TESTS  ")
    print("=========================================\n")

    # --- Test 1: Basic Encryption & Decryption ---
    print(">>> TEST 1: Encryption & Decryption (512-bit keys)")
    pub_key, priv_key = RSAEngine.generate_keypair(512)
    
    original_message = "Hello, Object-Oriented World!"
    print(f"Original : {original_message}")
    
    ciphertext = RSAEngine.encrypt_string(original_message, pub_key)
    print(f"Encrypted: {ciphertext[:30]}...")
    
    decrypted_message = RSAEngine.decrypt_string(ciphertext, priv_key)
    print(f"Decrypted: {decrypted_message}")
    
    assert original_message == decrypted_message, "Encryption Test Failed!"
    print("[SUCCESS] Encryption/Decryption works perfectly.\n")


    # --- Test 2: Digital Signatures ---
    print(">>> TEST 2: Digital Signatures")
    payload = "Bob:65537:1234567890"
    print(f"Payload to sign: '{payload}'")
    
    signature = RSAEngine.sign_data(payload, priv_key)
    print(f"Signature generated: {signature}")
    
    is_valid = RSAEngine.verify_signature(payload, signature, pub_key)
    assert is_valid is True, "Signature Verification Failed!"
    print("[SUCCESS] Signature verified successfully.\n")


    # --- Test 3: Tiny Keys (Edge Case) ---
    print(">>> TEST 3: Tiny Key Math Stability (32-bit keys)")
    tiny_pub, tiny_priv = RSAEngine.generate_keypair(32)
    
    tiny_payload = "Alice"
    tiny_sig = RSAEngine.sign_data(tiny_payload, tiny_priv)
    tiny_valid = RSAEngine.verify_signature(tiny_payload, tiny_sig, tiny_pub)
    
    assert tiny_valid is True, "Tiny Key Verification Failed!"
    print("[SUCCESS] Math holds up even with tiny 32-bit constraints.\n")

    print("=========================================")
    print("       ALL UNIT TESTS PASSED!            ")
    print("=========================================")

if __name__ == "__main__":
    run_all_tests()