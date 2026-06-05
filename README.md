# MITM-Guard-Protocol
# Secure Messaging with RSA and Certificate Authority (CA)

## Overview
This project demonstrates secure end-to-end encrypted messaging using RSA cryptography and a Certificate Authority (CA) to prevent Man-in-the-Middle (MITM) attacks. It includes a server (acting as CA), clients (Alice, Bob), and an optional MITM attacker (Eve). The system supports three scenarios:

1. **Unprotected Communication** (no CA, vulnerable to MITM)
2. **MITM Attack** (Eve intercepts and reads messages)
3. **Secure Mode** (CA signatures, MITM is detected and blocked)

---

## File Structure
- `secure_client.py` — Client application (Alice/Bob). Handles key generation, messaging, and signature verification.
- `secure_server.py` — Relay server and Certificate Authority. Registers clients, signs keys, and relays messages.
- `attacker_eve.py` — MITM proxy (Eve). Intercepts and manipulates traffic between clients and server.
- `crypto_core.py` — All RSA math, key generation, encryption/decryption, signing, and verification logic.
- `automated_demo.py` — Automated script to simulate all three scenarios and print results.
- `demo_signature_verification.py` — Standalone demo of signature verification and MITM detection.
- `test_crypto_core.py` — Unit tests for RSA encryption, decryption, signing, and verification.
- `README.md` — Project documentation (this file).

---

## How It Works

### 1. Key Generation & Registration
- Each client generates its own RSA keypair on startup.
- The server (CA) generates its own keypair if running in secure mode.
- Clients connect to the server and register their public key.
- The server replies with its CA public key (if secure mode).

### 2. Key Discovery & Verification
- To send a message, a client requests the recipient's public key from the server.
- In secure mode, the server signs the recipient's key with its CA private key.
- The client verifies the signature using the CA public key. If verification fails, a MITM attack is detected.

### 3. Messaging
- Messages are encrypted with the recipient's public key and sent to the server.
- The server relays the message to the recipient.
- The recipient decrypts the message with their private key.

### 4. MITM Attack Simulation
- The MITM proxy (`attacker_eve.py`) sits between a client and the server, intercepting and modifying traffic.
- In unprotected mode, Eve can read and re-encrypt messages.
- In secure mode, signature verification fails, and the attack is detected.

---

## How to Run

### Prerequisites
- Python 3.7+
- No external dependencies required

### 1. Unprotected Communication (Vulnerable)
1. **Start the server:**
```sh
   python secure_server.py --port 8000
```
2. **Start Bob (client):**
```sh
   python secure_client.py Bob --port 8000
```
3. **Start Alice (client):**
```sh
   python secure_client.py Alice --port 8000
```
4. **Send a message:**
   In Alice's prompt:

Bob will receive the message. No signature verification is performed.

### 2. MITM Attack (Eve Intercepts)
1. **Start the server:**
```sh
   python secure_server.py --port 8000
```
2. **Start the MITM proxy:**
```sh
   python attacker_eve.py --keysize 32
```
3. **Start Bob (client):**
```sh
   python secure_client.py Bob --port 8000
```
4. **Start Alice (client, connect via MITM):**
```sh
   python secure_client.py Alice --port 9000
```
5. **Send a message:**
   In Alice's prompt:

Eve (MITM) will print the intercepted message. Bob still receives it.

### 3. Secure Mode (CA, MITM Detected)
1. **Start the server in secure mode:**
```sh
   python secure_server.py --port 8000 --secure --keysize 32
```
2. **Start the MITM proxy:**
```sh
   python attacker_eve.py --keysize 32
```
3. **Start Bob (client, connect via MITM, secure mode):**
```sh
   python secure_client.py Bob --port 9000 --secure
```
4. **Start Alice (client, connect via MITM, secure mode):**
```sh
   python secure_client.py Alice --port 9000 --secure
```
5. **Send a message:**
   In Alice's prompt:

Alice will see a signature verification failure and detect the MITM attack. Bob will also detect MITM if he tries to message Alice.

---

## Automated Testing
To run all three scenarios automatically and see results:
```sh
python automated_demo.py
```

---

## Educational Demos
- `demo_signature_verification.py`: Shows how digital signatures work and how MITM is detected.
- `test_crypto_core.py`: Unit tests for RSA math and cryptographic functions.

---

## Further Reading
See [RSA_AND_CA_EXPLAINED.md](https://github.com/Tawfiq-Rahman/MITM-Guard-Protocol/blob/main/RSA_AND_CA_EXPLAINED.md) for a deep dive into the math, protocol, and security analysis.

---
