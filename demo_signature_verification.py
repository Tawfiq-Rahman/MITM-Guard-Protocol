from crypto_core import RSAEngine

print("====================================================")
print("  OFFLINE SIMULATION: CA SIGNATURES VS MITM ATTACK  ")
print("====================================================\n")

# 1. Setup the Entities
print("1. Generating Keys for all entities...")
ca_pub, ca_priv = RSAEngine.generate_keypair(32)
bob_pub, bob_priv = RSAEngine.generate_keypair(32)
eve_pub, eve_priv = RSAEngine.generate_keypair(32)
print("   [Done]\n")

# 2. The CA signs Bob's public key
print("2. The CA Server acts as the Trust Anchor.")
payload_bob = f"Bob:{bob_pub.e}:{bob_pub.n}"
print(f"   CA is signing payload: '{payload_bob}'")
valid_signature = RSAEngine.sign_data(payload_bob, ca_priv)
print(f"   Signature generated: {valid_signature}\n")

# 3. Alice verifies Bob (The Happy Path)
print("3. Alice requests Bob's key and verifies the signature.")
is_verified = RSAEngine.verify_signature(payload_bob, valid_signature, ca_pub)
if is_verified:
    print("   [SUCCESS] Alice verified Bob's key successfully.\n")

# 4. Eve attacks! (The MITM Scenario)
print("4. EVE ATTACKS: Eve intercepts the network.")
print("   Eve drops Bob's key and inserts her own fake key.")
payload_eve_fake = f"Bob:{eve_pub.e}:{eve_pub.n}"
print(f"   Alice receives fake payload: '{payload_eve_fake}'")
print("   Alice receives the original signature (Eve cannot forge a new one).")

# 5. Alice blocks the attack
print("\n5. Alice attempts to verify the tampered data against the CA Public Key...")
is_verified_fake = RSAEngine.verify_signature(payload_eve_fake, valid_signature, ca_pub)

if not is_verified_fake:
    print("   [FATAL SECURITY ALERT] Signature mismatch!")
    print("   [SUCCESS] ALICE BLOCKED THE MITM ATTACK!")
else:
    print("   [ERROR] The attack succeeded (This should not happen).")