"""
SecureVault - Zero-Trust Retrieval (Out-of-Band OTP)
====================================================
Before decryption, an OTP is generated and "sent" (simulated to console).
Decryption is allowed only after OTP verification.
Simulates out-of-band delivery (e.g. SMS/email) by printing to console.
"""

import secrets
import time
from typing import Optional


class OTPService:
    """Generate and verify one-time passwords for zero-trust decryption."""

    def __init__(self, digits: int = 6, validity_seconds: int = 300):
        self.digits = digits
        self.validity_seconds = validity_seconds
        # pending_otp: (otp_value, expiry_time)
        self._pending: Optional[tuple] = None

    def generate(self, recipient_hint: str = "user") -> str:
        """
        Generate OTP and simulate sending out-of-band.
        Returns the OTP (in demo we also print it to console).
        """
        # Numeric OTP
        otp = "".join(secrets.choice("0123456789") for _ in range(self.digits))
        expiry = time.monotonic() + self.validity_seconds
        self._pending = (otp, expiry)
        return otp

    def simulate_send_to_console(self, otp: str, action: str = "Decrypt data") -> None:
        """Simulate OOB delivery by printing to console (educational)."""
        print(f"\n  [OTP] Zero-Trust: {action}")
        print(f"  [OTP] Your one-time password: {otp}")
        print(f"  [OTP] Valid for {self.validity_seconds} seconds. Enter it when prompted.\n")

    def verify(self, user_input: str) -> bool:
        """
        Verify user-provided OTP. Returns True if correct and not expired.
        Clears pending OTP after use (one-time).
        """
        if self._pending is None:
            return False
        otp, expiry = self._pending
        if time.monotonic() > expiry:
            self._pending = None
            return False
        if user_input.strip() != otp:
            return False
        self._pending = None
        return True

    def has_pending(self) -> bool:
        return self._pending is not None and time.monotonic() <= self._pending[1]
