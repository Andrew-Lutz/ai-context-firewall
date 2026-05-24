"""
Redaction + Tokenization Engine.

Transforms sensitive data in text using:
- Masking: replaces with placeholder labels (e.g., [NAME_001])
- Hashing: one-way hash (for deduplication without storage)
- Tokenization: reversible token vault with encrypted storage

Example transformation:
  "John Smith, SSN 123-45-6789, card 4111-1111-1111-1111"
  →
  "[NAME_001], SSN [REDACTED_SSN_001], card [REDACTED_CC_001]"

Tokens are stored in encrypted Redis vault with configurable TTL.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import structlog
from cryptography.fernet import Fernet

from core.inspection.engine import (
    DetectedEntity,
    EntityType,
    InspectionResult,
    ThreatCategory,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Redaction Templates
# ---------------------------------------------------------------------------

REDACTION_LABELS: Dict[EntityType, str] = {
    EntityType.PERSON_NAME: "NAME",
    EntityType.EMAIL: "EMAIL",
    EntityType.PHONE: "PHONE",
    EntityType.ADDRESS: "ADDRESS",
    EntityType.DATE_OF_BIRTH: "DOB",
    EntityType.NATIONAL_ID: "NATIONAL_ID",
    EntityType.PASSPORT: "PASSPORT",
    EntityType.DRIVERS_LICENSE: "DL_NUM",
    EntityType.IP_ADDRESS: "IP_ADDR",
    EntityType.SSN: "SSN",
    EntityType.MEDICAL_RECORD_NUMBER: "MRN",
    EntityType.HEALTH_PLAN_BENEFICIARY: "HPN",
    EntityType.DIAGNOSIS_CODE: "DX_CODE",
    EntityType.PRESCRIPTION: "RX",
    EntityType.CREDIT_CARD: "CC_NUM",
    EntityType.BANK_ACCOUNT: "ACCT_NUM",
    EntityType.ROUTING_NUMBER: "ROUTING",
    EntityType.CVV: "CVV",
    EntityType.API_KEY: "API_KEY",
    EntityType.AWS_KEY: "AWS_KEY",
    EntityType.JWT_TOKEN: "JWT",
    EntityType.PRIVATE_KEY: "PRIV_KEY",
    EntityType.PASSWORD: "PASSWORD",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RedactionRecord:
    """Record of a single redaction applied to text."""
    token: str                   # e.g., "[SSN_001]"
    entity_type: str
    original_start: int
    original_end: int
    original_hash: str           # SHA-256 of original (never stored in plaintext)
    reversible: bool
    vault_key: Optional[str] = None  # Redis key for reversible tokens


@dataclass
class RedactionResult:
    """
    Result of the redaction pass over a piece of text.
    Contains redacted text and full mapping of what was changed.
    """
    original_hash: str           # SHA-256 of full original text
    redacted_text: str
    records: List[RedactionRecord] = field(default_factory=list)
    redaction_count: int = 0
    categories_redacted: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    reversible: bool = True


# ---------------------------------------------------------------------------
# Token Vault (Redis-backed, encrypted)
# ---------------------------------------------------------------------------

class TokenVault:
    """
    Encrypted reversible token vault.

    Stores {token → encrypted_original_value} in Redis with TTL.
    Values are encrypted with Fernet symmetric encryption before storage.
    Only authorized systems with the encryption key can reverse tokens.
    """

    def __init__(self, redis_client, encryption_key: str, ttl_hours: int = 24):
        self._redis = redis_client
        self._fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        self._ttl_hours = ttl_hours

    def store(self, token: str, original_value: str, tenant_id: str, session_id: str) -> str:
        """
        Encrypt and store original value under the given token.
        Returns the vault key used.
        """
        vault_key = f"vault:{tenant_id}:{session_id}:{token}"
        encrypted = self._fernet.encrypt(original_value.encode("utf-8"))
        ttl_seconds = self._ttl_hours * 3600

        if self._redis:
            self._redis.setex(vault_key, ttl_seconds, encrypted)

        return vault_key

    def retrieve(self, token: str, tenant_id: str, session_id: str) -> Optional[str]:
        """
        Retrieve and decrypt the original value for a token.
        Returns None if not found or expired.
        """
        vault_key = f"vault:{tenant_id}:{session_id}:{token}"

        if not self._redis:
            return None

        encrypted = self._redis.get(vault_key)
        if not encrypted:
            return None

        try:
            return self._fernet.decrypt(encrypted).decode("utf-8")
        except Exception:
            logger.warning("vault_decryption_failed", token=token[:12])
            return None

    def invalidate_session(self, tenant_id: str, session_id: str) -> int:
        """Delete all vault entries for a session. Returns count deleted."""
        if not self._redis:
            return 0
        pattern = f"vault:{tenant_id}:{session_id}:*"
        keys = self._redis.keys(pattern)
        if keys:
            return self._redis.delete(*keys)
        return 0


# ---------------------------------------------------------------------------
# Redaction Engine
# ---------------------------------------------------------------------------

class RedactionEngine:
    """
    Applies redaction, hashing, or tokenization to text based on inspection results.

    Modes:
    - mask: Replace with labeled placeholder [ENTITY_TYPE_NNN]
    - hash: Replace with deterministic hash [HASH:abc123...]
    - tokenize: Replace with reversible token, store original in encrypted vault

    All modes are non-destructive — original content is never logged in plaintext.
    """

    def __init__(
        self,
        mode: str = "mask",
        vault: Optional[TokenVault] = None,
        reversible: bool = True,
    ):
        if mode not in ("mask", "hash", "tokenize"):
            raise ValueError(f"Invalid redaction mode: {mode}")
        self.mode = mode
        self.vault = vault
        self.reversible = reversible and (vault is not None) and (mode == "tokenize")
        logger.info("RedactionEngine initialized", mode=mode, reversible=self.reversible)

    def _make_token(self, entity_type: EntityType, counter: int) -> str:
        """Generate a labeled placeholder token."""
        label = REDACTION_LABELS.get(entity_type, entity_type.value.upper())
        return f"[{label}_{counter:03d}]"

    def _make_hash_token(self, value: str, entity_type: EntityType) -> str:
        """Generate a deterministic hash-based token."""
        label = REDACTION_LABELS.get(entity_type, entity_type.value.upper())
        h = hashlib.sha256(value.encode()).hexdigest()[:12]
        return f"[{label}:HASH:{h}]"

    def _value_hash(self, value: str) -> str:
        """One-way hash of a sensitive value for audit logging."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def redact(
        self,
        text: str,
        inspection_result: InspectionResult,
        tenant_id: str = "default",
        session_id: str = "default",
    ) -> RedactionResult:
        """
        Apply redaction to text based on detected entities in InspectionResult.

        Process:
        1. Sort entities by position (end → start) to preserve offsets
        2. For each entity, generate token and replace in text
        3. If reversible tokenization, store encrypted original in vault
        4. Build and return RedactionResult

        Args:
            text: Original text to redact
            inspection_result: Output from InputInspectionEngine.inspect()
            tenant_id: Tenant identifier for vault scoping
            session_id: Session identifier for vault scoping

        Returns:
            RedactionResult with redacted text and full mapping
        """
        start_time = time.monotonic()

        if not inspection_result.entities:
            return RedactionResult(
                original_hash=inspection_result.content_hash,
                redacted_text=text,
                redaction_count=0,
                processing_time_ms=0.0,
            )

        redacted_text = text
        records: List[RedactionRecord] = []
        entity_counters: Dict[str, int] = {}
        categories_redacted: set = set()

        # Process entities sorted by position (reverse order to preserve offsets)
        sorted_entities = sorted(
            inspection_result.entities,
            key=lambda e: e.start,
            reverse=True,
        )

        for entity in sorted_entities:
            # Extract original value from text using original offsets
            original_value = text[entity.start:entity.end]
            if not original_value:
                continue

            # Get counter for this entity type
            label = REDACTION_LABELS.get(entity.entity_type, entity.entity_type.value.upper())
            entity_counters[label] = entity_counters.get(label, 0) + 1
            counter = entity_counters[label]

            # Generate token based on mode
            if self.mode == "hash":
                token = self._make_hash_token(original_value, entity.entity_type)
                vault_key = None
                is_reversible = False
            elif self.mode == "tokenize" and self.vault:
                token = self._make_token(entity.entity_type, counter)
                vault_key = self.vault.store(token, original_value, tenant_id, session_id)
                is_reversible = True
            else:
                # Default: mask
                token = self._make_token(entity.entity_type, counter)
                vault_key = None
                is_reversible = False

            # Apply replacement in text (working reverse order preserves offsets)
            redacted_text = redacted_text[:entity.start] + token + redacted_text[entity.end:]

            records.append(RedactionRecord(
                token=token,
                entity_type=entity.entity_type.value,
                original_start=entity.start,
                original_end=entity.end,
                original_hash=self._value_hash(original_value),
                reversible=is_reversible,
                vault_key=vault_key,
            ))

            categories_redacted.add(entity.category.value)

        processing_time_ms = (time.monotonic() - start_time) * 1000

        result = RedactionResult(
            original_hash=inspection_result.content_hash,
            redacted_text=redacted_text,
            records=records,
            redaction_count=len(records),
            categories_redacted=list(categories_redacted),
            processing_time_ms=round(processing_time_ms, 2),
            reversible=any(r.reversible for r in records),
        )

        logger.info(
            "redaction_complete",
            count=len(records),
            categories=list(categories_redacted),
            mode=self.mode,
            duration_ms=processing_time_ms,
        )

        return result

    def restore(
        self,
        redacted_text: str,
        records: List[RedactionRecord],
        tenant_id: str,
        session_id: str,
    ) -> str:
        """
        Restore original values from redacted text using vault lookup.
        Only works with tokenize mode and non-expired vault entries.
        Requires appropriate authorization (checked upstream via RBAC).

        Args:
            redacted_text: Text with [TOKEN] placeholders
            records: List of RedactionRecord from original redaction
            tenant_id: Tenant for vault scoping
            session_id: Session for vault scoping

        Returns:
            Text with tokens replaced by original values where possible
        """
        if not self.vault:
            raise RuntimeError("Vault not configured — cannot restore tokenized values")

        restored = redacted_text
        for record in reversed(records):
            if not record.reversible:
                continue
            original = self.vault.retrieve(record.token, tenant_id, session_id)
            if original:
                restored = restored.replace(record.token, original)

        return restored

    def redact_for_industry(
        self,
        text: str,
        industry: str,
        tenant_id: str = "default",
        session_id: str = "default",
    ) -> Tuple[str, List[str]]:
        """
        Apply industry-specific redaction using pre-configured regex rules.
        Used when full inspection engine result is not available.

        Returns: (redacted_text, list_of_applied_rule_names)
        """
        from core.inspection.engine import InputInspectionEngine
        engine = InputInspectionEngine()
        result = engine.inspect(text, content_type="prompt")
        redaction = self.redact(text, result, tenant_id, session_id)
        return redaction.redacted_text, [r.entity_type for r in redaction.records]
