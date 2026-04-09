"""
SecureVault - Key Management Service (KMS)
=========================================
Stores encryption keys separately from data.
Releases key only after OTP verification (zero-trust).
"""

import os
from typing import Optional, Dict


class KMS:
    """
    In-memory KMS: stores per-user keys, releases only after OTP verified.
    In production, keys would be in HSM or secure enclave.
    """

    def __init__(self):
        # user -> 32-byte AES key (held until release)
        self._keys: Dict[str, bytes] = {}
        # user -> key released for this session after OTP (single use)
        self._released: Dict[str, bool] = {}

    def store_key(self, username: str, key: bytes) -> None:
        """Store 32-byte AES key for user. Overwrites existing."""
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self._keys[username] = key
        self._released[username] = False

    def release_key_after_otp(self, username: str) -> Optional[bytes]:
        """
        Release key for user (call only after OTP verified).
        Returns the key; subsequent calls return None until key is re-stored.
        """
        if username not in self._keys:
            return None
        self._released[username] = True
        return self._keys[username]

    def get_key_if_released(self, username: str) -> Optional[bytes]:
        """Get key only if it was already released this session (e.g. for decryption)."""
        if username not in self._keys or not self._released.get(username):
            return None
        return self._keys[username]

    def revoke_release(self, username: str) -> None:
        """Revoke release (e.g. after logout). Next decryption requires OTP again."""
        self._released[username] = False

    def delete_key(self, username: str) -> None:
        """Remove user key (e.g. account deletion)."""
        self._keys.pop(username, None)
        self._released.pop(username, None)

    def get_key_for_encrypt(self, username: str) -> Optional[bytes]:
        """Return key for encryption (upload). Key is stored but not 'released' for decrypt until OTP."""
        return self._keys.get(username)

    def has_key(self, username: str) -> bool:
        return username in self._keys

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new 32-byte AES-256 key."""
        return os.urandom(32)
