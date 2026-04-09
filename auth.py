"""
SecureVault - User Authentication Module
========================================
Handles username/password login and in-memory session management.
Passwords are hashed with bcrypt before storage - plaintext never stored.
"""

from typing import Optional, Dict, Tuple
import hashlib
import bcrypt


class UserAuth:
    """In-memory user authentication with bcrypt-hashed password storage."""

    def __init__(self):
        # user -> (password_hash, is_admin); password_hash is bcrypt hash (utf-8 string)
        self._users: Dict[str, Tuple[str, bool]] = {}
        # session_id -> username (simple in-memory session)
        self._sessions: Dict[str, str] = {}
        # current session id for active user
        self._current_session_id: Optional[str] = None

    @staticmethod
    def _hash_password(password: str) -> str:
        """
        Hash password with bcrypt.
        In production, tune rounds (cost factor) based on deployment constraints.
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def _check_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored bcrypt hash."""
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode("utf-8"))
        except Exception:
            return False

    def register(self, username: str, password: str, is_admin: bool = False) -> bool:
        """
        Register a new user. Password is bcrypt-hashed before storage.
        Returns False if username already exists.
        """
        if username in self._users:
            return False
        self._users[username] = (self._hash_password(password), is_admin)
        return True

    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate user. On success, create session and return session_id.
        Returns None if credentials invalid.
        """
        if username not in self._users:
            return None
        stored_hash, _ = self._users[username]
        if not self._check_password(password, stored_hash):
            return None
        # Simple session id derived from username + stored hash (not from raw password)
        session_id_src = f"{username}:{stored_hash}".encode()
        session_id = hashlib.sha256(session_id_src).hexdigest()[:16]
        self._sessions[session_id] = username
        self._current_session_id = session_id
        return session_id

    def create_session_for_user(self, username: str) -> Optional[str]:
        """
        Create a session for a user that has already passed external checks.
        """
        if username not in self._users:
            return None
        stored_hash, _ = self._users[username]
        session_id_src = f"{username}:{stored_hash}".encode()
        session_id = hashlib.sha256(session_id_src).hexdigest()[:16]
        self._sessions[session_id] = username
        self._current_session_id = session_id
        return session_id

    def sync_user(self, username: str, password: str, is_admin: bool = False) -> None:
        """
        Ensure in-memory auth store has a user with the provided credentials.
        Used by web app after validating persistent credentials from DB.
        """
        self._users[username] = (self._hash_password(password), is_admin)

    def logout(self) -> None:
        """Clear current session."""
        if self._current_session_id and self._current_session_id in self._sessions:
            del self._sessions[self._current_session_id]
        self._current_session_id = None

    def get_current_user(self) -> Optional[str]:
        """Return username for current session, or None."""
        if not self._current_session_id:
            return None
        return self._sessions.get(self._current_session_id)

    def is_admin(self, username: Optional[str] = None) -> bool:
        """Check if user has admin role. Uses current user if username not given."""
        u = username or self.get_current_user()
        if not u or u not in self._users:
            return False
        _, admin = self._users[u]
        return admin

    def set_session(self, session_id: str) -> bool:
        """Set active session by id (e.g. after restart)."""
        if session_id in self._sessions:
            self._current_session_id = session_id
            return True
        return False

    def session_id(self) -> Optional[str]:
        """Return current session id."""
        return self._current_session_id
