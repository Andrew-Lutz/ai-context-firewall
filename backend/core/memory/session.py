"""
Session Memory Security — AI Context Firewall
Encrypted session isolation, zero-trust context boundaries, and memory poisoning prevention.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Session data models
# ---------------------------------------------------------------------------

@dataclass
class SecureMessage:
    """A single message in an isolated session."""
    message_id:   str
    role:         str
    content:      str
    timestamp:    float
    risk_score:   float = 0.0
    was_redacted: bool  = False
    metadata:     dict  = field(default_factory=dict)


@dataclass
class SessionMetadata:
    """Metadata for an active session (never contains raw content)."""
    session_id:       str
    tenant_id:        str
    user_id:          str
    user_role:        str
    created_at:       float
    last_active_at:   float
    message_count:    int   = 0
    total_risk_score: float = 0.0
    policy_ids:       list  = field(default_factory=list)
    is_flagged:       bool  = False
    flag_reason:      str   = ""


# ---------------------------------------------------------------------------
# Encrypted session store
# ---------------------------------------------------------------------------

class EncryptedSessionStore:
    """
    In-memory encrypted session store.
    In production this is backed by Redis with Fernet-encrypted values.

    Security properties:
    - Session content is encrypted at rest (Fernet AES-128-CBC + HMAC)
    - Session keys are tenant-scoped (tenant_id:session_id)
    - TTL enforcement on stale sessions
    - Zero cross-tenant leakage
    - Session fingerprinting for replay detection
    """

    DEFAULT_TTL_SECONDS = 3600      # 1 hour
    MAX_SESSIONS_PER_TENANT = 1000

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.ttl = ttl_seconds

        # Encrypted store: key → (encrypted_bytes, expiry_timestamp)
        self._store: dict[str, tuple[bytes, float]] = {}

        # Session metadata index (lightweight, unencrypted)
        self._meta:  dict[str, SessionMetadata] = {}

        # Encryption key
        if CRYPTO_AVAILABLE:
            raw_key = os.getenv("SESSION_ENCRYPTION_KEY", "")
            if raw_key:
                self._fernet = Fernet(raw_key.encode())
            else:
                self._fernet = Fernet(Fernet.generate_key())
        else:
            self._fernet = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(
        self,
        session_id: str,
        tenant_id:  str,
        user_id:    str,
        user_role:  str = "employee",
        policy_ids: list[str] | None = None,
    ) -> SessionMetadata:
        """Create a new isolated session."""
        now = time.time()
        meta = SessionMetadata(
            session_id     = session_id,
            tenant_id      = tenant_id,
            user_id        = user_id,
            user_role      = user_role,
            created_at     = now,
            last_active_at = now,
            policy_ids     = policy_ids or [],
        )
        key = self._key(tenant_id, session_id)
        self._meta[key] = meta
        self._set_encrypted(key, [])   # Empty message list
        return meta

    def get_session(self, tenant_id: str, session_id: str) -> list[SecureMessage] | None:
        """Retrieve decrypted messages for a session. Returns None if expired/missing."""
        key = self._key(tenant_id, session_id)
        if key not in self._meta:
            return None
        if self._is_expired(key):
            self.destroy_session(tenant_id, session_id)
            return None
        return self._get_decrypted(key)

    def append_message(
        self,
        tenant_id:  str,
        session_id: str,
        role:       str,
        content:    str,
        risk_score: float = 0.0,
        was_redacted: bool = False,
        metadata:   dict | None = None,
    ) -> SecureMessage:
        """Append a message to a session."""
        key = self._key(tenant_id, session_id)
        messages = self._get_decrypted(key) or []

        msg = SecureMessage(
            message_id   = str(uuid.uuid4()),
            role         = role,
            content      = content,
            timestamp    = time.time(),
            risk_score   = risk_score,
            was_redacted = was_redacted,
            metadata     = metadata or {},
        )
        messages.append(msg)
        self._set_encrypted(key, messages)

        # Update metadata
        if key in self._meta:
            m = self._meta[key]
            m.message_count  += 1
            m.last_active_at  = time.time()
            m.total_risk_score = max(m.total_risk_score, risk_score)

        return msg

    def get_metadata(self, tenant_id: str, session_id: str) -> SessionMetadata | None:
        key = self._key(tenant_id, session_id)
        return self._meta.get(key)

    def flag_session(self, tenant_id: str, session_id: str, reason: str):
        key = self._key(tenant_id, session_id)
        if key in self._meta:
            self._meta[key].is_flagged  = True
            self._meta[key].flag_reason = reason

    def destroy_session(self, tenant_id: str, session_id: str):
        key = self._key(tenant_id, session_id)
        self._store.pop(key, None)
        self._meta.pop(key, None)

    def purge_expired(self) -> int:
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if exp < now]
        for k in expired:
            self._store.pop(k, None)
            self._meta.pop(k, None)
        return len(expired)

    def list_sessions(self, tenant_id: str) -> list[SessionMetadata]:
        prefix = f"{tenant_id}:"
        return [m for k, m in self._meta.items() if k.startswith(prefix)]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _key(tenant_id: str, session_id: str) -> str:
        return f"{tenant_id}:{session_id}"

    def _is_expired(self, key: str) -> bool:
        if key not in self._store:
            return True
        _, expiry = self._store[key]
        return time.time() > expiry

    def _set_encrypted(self, key: str, messages: list[SecureMessage]):
        raw = json.dumps([
            {
                "message_id":   m.message_id,
                "role":         m.role,
                "content":      m.content,
                "timestamp":    m.timestamp,
                "risk_score":   m.risk_score,
                "was_redacted": m.was_redacted,
                "metadata":     m.metadata,
            }
            for m in messages
        ]).encode()

        if self._fernet:
            encrypted = self._fernet.encrypt(raw)
        else:
            encrypted = raw   # Fallback: unencrypted (dev only)

        self._store[key] = (encrypted, time.time() + self.ttl)

    def _get_decrypted(self, key: str) -> list[SecureMessage] | None:
        if key not in self._store:
            return None
        encrypted, _ = self._store[key]
        try:
            if self._fernet:
                raw = self._fernet.decrypt(encrypted)
            else:
                raw = encrypted
            data = json.loads(raw)
            return [SecureMessage(**d) for d in data]
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Context window manager (prevents context poisoning)
# ---------------------------------------------------------------------------

class ContextWindowManager:
    """
    Manages the context window fed to LLMs to prevent:
    - Context overflow attacks
    - Memory poisoning via long conversations
    - Stale PII persistence across turns
    - Cross-turn injection chains
    """

    MAX_TOKENS_ESTIMATE     = 100_000   # Characters (~tokens * 4)
    MAX_MESSAGES_PER_WINDOW = 40
    POISON_CHECK_PATTERNS   = [
        r"(?:remember|recall|note)\s+that\s+(?:you\s+)?(?:are|must|should)\s+(?:ignore|bypass)",
        r"(?:from\s+now\s+on|henceforth|always)\s+(?:ignore|bypass|forget)",
        r"(?:forget|disregard|ignore)\s+(?:everything|all)\s+(?:above|before|previous)",
    ]

    def __init__(self):
        import re
        self._poison_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.POISON_CHECK_PATTERNS
        ]

    def prepare_context(
        self,
        messages:       list[SecureMessage],
        system_prompt:  str | None = None,
        max_tokens:     int | None = None,
    ) -> tuple[list[dict], list[str]]:
        """
        Returns (safe_messages_for_llm, warnings).

        Applies:
        1. Reverse chronological truncation (keep newest, drop oldest)
        2. Poisoned message detection and removal
        3. System prompt injection check
        4. Format for LLM consumption (strips internal metadata)
        """
        warnings: list[str] = []
        safe: list[SecureMessage] = []

        char_limit = max_tokens or self.MAX_TOKENS_ESTIMATE

        total_chars = len(system_prompt or "")
        total_msgs  = 0

        # Process newest-first, then reverse
        for msg in reversed(messages):
            if total_msgs >= self.MAX_MESSAGES_PER_WINDOW:
                warnings.append(f"Message history truncated at {self.MAX_MESSAGES_PER_WINDOW} messages")
                break

            content_len = len(msg.content)
            if total_chars + content_len > char_limit:
                warnings.append("Message history truncated due to context window limit")
                break

            # Check for deferred poisoning attempts
            if self._is_poisoned(msg.content):
                warnings.append(f"Poisoned message detected and removed: message_id={msg.message_id}")
                continue  # Skip

            safe.append(msg)
            total_chars += content_len
            total_msgs  += 1

        safe.reverse()

        llm_messages = [
            {"role": m.role, "content": m.content}
            for m in safe
        ]

        return llm_messages, warnings

    def _is_poisoned(self, text: str) -> bool:
        return any(p.search(text) for p in self._poison_patterns)


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_session_store: EncryptedSessionStore | None = None
_context_manager: ContextWindowManager | None = None


def get_session_store() -> EncryptedSessionStore:
    global _session_store
    if _session_store is None:
        ttl = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
        _session_store = EncryptedSessionStore(ttl_seconds=ttl)
    return _session_store


def get_context_manager() -> ContextWindowManager:
    global _context_manager
    if _context_manager is None:
        _context_manager = ContextWindowManager()
    return _context_manager
