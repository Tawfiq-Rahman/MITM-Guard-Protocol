import random
import hashlib
from dataclasses import dataclass

# --- Data Structures for Clean Code ---
@dataclass
class PublicKey:
    """Represents an RSA Public Key (e, n)"""
    e: int
    n: int

@dataclass
class PrivateKey:
    """Represents an RSA Private Key (d, n)"""
    d: int
    n: int

# --- Core Cryptography Engine ---
class RSAEngine:
    """Handles all RSA Math, Key Generation, Encryption, and Signatures."""
    
    @staticmethod
    def _is_prime(n: int, k: int = 40) -> bool:
        """Miller-Rabin primality test."""
        if n == 2 or n == 3: return True
        if n % 2 == 0 or n < 2: return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @classmethod
    def _generate_prime(cls, bits: int) -> int:
        """Generates a random prime number of the specified bit length."""
        while True:
            candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if cls._is_prime(candidate):
                return candidate

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """Finds the modular inverse using the Extended Euclidean Algorithm."""
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    @classmethod
    def generate_keypair(cls, bits: int = 32) -> tuple[PublicKey, PrivateKey]:
        """Generates a matching Public and Private keypair."""
        p = cls._generate_prime(bits // 2)
        q = cls._generate_prime(bits // 2)
        while p == q:
            q = cls._generate_prime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        # e is typically 65537, but for tiny keys we must ensure it's valid
        e = 65537
        if e >= phi or phi % e == 0:
            e = 3
            while phi % e == 0:
                e += 2

        d = cls._mod_inverse(e, phi)
        
        return PublicKey(e, n), PrivateKey(d, n)

    # --- Communication Methods ---
    
    @staticmethod
    def encrypt_string(message: str, pub_key: PublicKey) -> str:
        """Encrypts a string into a comma-separated hex ciphertext."""
        cipher_blocks = []
        for char in message:
            m = ord(char)
            if m >= pub_key.n:
                raise ValueError("Key size too small for this character.")
            c = pow(m, pub_key.e, pub_key.n) # c = m^e mod n
            cipher_blocks.append(hex(c)[2:])
        return ",".join(cipher_blocks)

    @staticmethod
    def decrypt_string(ciphertext: str, priv_key: PrivateKey) -> str:
        """Decrypts a comma-separated hex ciphertext back to a string."""
        message = ""
        blocks = ciphertext.split(',')
        for block in blocks:
            if not block: continue
            c = int(block, 16)
            m = pow(c, priv_key.d, priv_key.n) # m = c^d mod n
            message += chr(m)
        return message

    # --- Authentication Methods ---

    @staticmethod
    def _hash_payload(payload: str) -> int:
        """Creates a SHA-256 integer hash of a string."""
        return int(hashlib.sha256(payload.encode('utf-8')).hexdigest(), 16)

    @classmethod
    def sign_data(cls, payload: str, priv_key: PrivateKey) -> int:
        """Creates a digital signature: s = hash(m)^d mod n"""
        h = cls._hash_payload(payload)
        # Ensure hash fits inside modulus for tiny keys
        h = h % priv_key.n 
        signature = pow(h, priv_key.d, priv_key.n)
        return signature

    @classmethod
    def verify_signature(cls, payload: str, signature: int, pub_key: PublicKey) -> bool:
        """Verifies a digital signature: s^e mod n == hash(m)"""
        expected_hash = cls._hash_payload(payload) % pub_key.n
        decrypted_hash = pow(signature, pub_key.e, pub_key.n)
        return expected_hash == decrypted_hash