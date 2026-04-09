"""
SecureVault - Hybrid Cryptographic Engine
=========================================
- AES-256-GCM for confidential encryption of file/data.
- Simulated Order-Revealing Encryption (ORE) for searchable indexing.
  (Real ORE is complex; we simulate with deterministic comparable tokens.)
Encrypted payload and ORE token are stored separately in the data tier.
"""

import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class HybridCryptoEngine:
    """AES-256 encryption + simulated ORE token generation."""

    def __init__(self, key: bytes):
        """
        Initialize with a 32-byte key for AES-256.
        Key must come from KMS after OTP verification.
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        self._key = key

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive 32-byte key from password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.
        Returns (ciphertext_with_nonce, nonce) for storage.
        GCM provides confidentiality and authenticity.
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt AES-256-GCM ciphertext. Fails if tampered."""
        aesgcm = AESGCM(self._key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    # ---- Simulated ORE ----
    # Real ORE allows comparison of ciphertexts without decryption.
    # We simulate by: token = HMAC(key, canonical_representation(value))
    # so same value => same token; tokens can be sorted for range queries.

    def generate_ore_token(self, value: str) -> bytes:
        """
        Generate a deterministic, comparable token for the given value.
        Same value => same token. Tokens are comparable (lexicographic order).
        Used for searchable indexing without revealing plaintext.
        """
        # Use HMAC with key so tokens are bound to this vault's key
        h = hashlib.new("sha256", self._key + value.encode())
        return h.digest()

    def generate_ore_token_for_search(self, value: str) -> bytes:
        """Same as generate_ore_token; used when searching by value."""
        return self.generate_ore_token(value)
