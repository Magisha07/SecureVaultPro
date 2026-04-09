"""
SecureVault - SEAL (Searchable Encrypted Audit Logs)
====================================================
- Log entries are encrypted (AES) so content is confidential.
- HMAC-SHA256 tag is computed for event_type so admin can search logs
  by event type without decrypting every entry.
- Search: hash(event_type) and return entries whose event_type tag matches.
"""

import json
import hmac
import hashlib
import base64
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Event types for audit
EVENT_LOGIN = "LOGIN"
EVENT_LOGOUT = "LOGOUT"
EVENT_UPLOAD = "UPLOAD"
EVENT_SEARCH = "SEARCH"
EVENT_DOWNLOAD = "DOWNLOAD"
EVENT_VIEW_LOGS = "VIEW_LOGS"
EVENT_REGISTER = "REGISTER"
EVENT_IDS_BLOCK = "IDS_BLOCK"
EVENT_OTP_SENT = "OTP_SENT"
EVENT_OTP_VERIFIED = "OTP_VERIFIED"


class SEAL:
    """Searchable Encrypted Audit Logs with HMAC-SHA256 tags per event type."""

    def __init__(self, seal_key: bytes):
        """
        seal_key: 32-byte key for AES log encryption and HMAC.
        Should be separate from data encryption key (key separation).
        """
        if len(seal_key) != 32:
            raise ValueError("SEAL key must be 32 bytes")
        self._key = seal_key
        self._entries: List[Tuple[bytes, bytes, str]] = []  # (encrypted_payload, hmac_tag_b64, event_type_for_tag)

    def _hmac_tag(self, event_type: str) -> bytes:
        """HMAC-SHA256( key, event_type ) -> tag for searchable index."""
        return hmac.new(self._key, event_type.encode(), hashlib.sha256).digest()

    def _encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt log entry (nonce + ciphertext)."""
        nonce = hashlib.sha256(plaintext + self._key).digest()[:12]
        aes = AESGCM(self._key)
        ct = aes.encrypt(nonce, plaintext, None)
        return nonce + ct

    def _decrypt(self, blob: bytes) -> bytes:
        """Decrypt log entry."""
        nonce, ct = blob[:12], blob[12:]
        aes = AESGCM(self._key)
        return aes.decrypt(nonce, ct, None)

    def append(self, event_type: str, message: str, user: str = "", extra: Optional[dict] = None) -> None:
        """
        Append an encrypted log entry. Event type is used for HMAC tag (searchable).
        """
        payload = {
            "event": event_type,
            "message": message,
            "user": user,
            "extra": extra or {},
        }
        plaintext = json.dumps(payload).encode()
        encrypted = self._encrypt(plaintext)
        tag = self._hmac_tag(event_type)
        tag_b64 = base64.b64encode(tag).decode()
        self._entries.append((encrypted, tag_b64, event_type))

    def search_by_event_type(self, event_type: str) -> List[dict]:
        """
        Search logs by event type without decrypting non-matching entries.
        Compute HMAC tag for requested event_type; return only entries with matching tag.
        """
        target_tag = base64.b64encode(self._hmac_tag(event_type)).decode()
        results = []
        for encrypted, tag_b64, _ in self._entries:
            if tag_b64 != target_tag:
                continue
            try:
                plain = self._decrypt(encrypted)
                results.append(json.loads(plain.decode()))
            except Exception:
                pass
        return results

    def get_all_decrypted(self, decrypt_key: Optional[bytes] = None) -> List[dict]:
        """
        Decrypt and return all log entries (admin). Uses same key as append.
        """
        out = []
        for encrypted, _, _ in self._entries:
            try:
                plain = self._decrypt(encrypted)
                out.append(json.loads(plain.decode()))
            except Exception:
                out.append({"error": "decrypt_failed"})
        return out

    def count(self) -> int:
        return len(self._entries)
