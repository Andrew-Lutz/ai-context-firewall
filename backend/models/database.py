"""
SQLAlchemy ORM models for the AI Context Firewall platform.
Covers audit events, users, tenants, policies, sessions, and tokens.
"""
import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import (
    Column, String, Text, Boolean, Integer, Float,
    DateTime, ForeignKey, JSON, Enum as SAEnum,
    Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncAttrs, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy.sql import func

import enum


class Base(AsyncAttrs, DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThreatSeverity(str, enum.Enum):
    """Severity levels for detected threats."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, enum.Enum):
    """Status of an inspection/scan operation."""
    CLEAN = "clean"
    FLAGGED = "flagged"
    BLOCKED = "blocked"
    REDACTED = "redacted"
    ERROR = "error"


class UserRole(str, enum.Enum):
    """RBAC user roles."""
    SUPER_ADMIN = "super_admin"
    TENANT_ADMIN = "tenant_admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


class PolicyFramework(str, enum.Enum):
    """Supported compliance frameworks."""
    HIPAA = "hipaa"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    FINRA = "finra"
    SEC = "sec"
    NIST = "nist"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------

class Tenant(Base):
    """Multi-tenant organization model."""
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    industry: Mapped[Optional[str]] = mapped_column(String(100))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[Optional[Dict]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    users = relationship("User", back_populates="tenant")
    policies = relationship("Policy", back_populates="tenant")
    audit_events = relationship("AuditEvent", back_populates="tenant")


class User(Base):
    """User account with RBAC role."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole), default=UserRole.DEVELOPER
    )
    department: Mapped[Optional[str]] = mapped_column(String(100))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    tenant = relationship("Tenant", back_populates="users")

    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        Index("ix_users_email", "email"),
        Index("ix_users_tenant_id", "tenant_id"),
    )


class Policy(Base):
    """Governance policy definition."""
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    framework: Mapped[PolicyFramework] = mapped_column(
        SAEnum(PolicyFramework), nullable=False
    )
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    description: Mapped[Optional[str]] = mapped_column(Text)
    rules: Mapped[Dict] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    enforce_mode: Mapped[bool] = mapped_column(Boolean, default=True, comment="False = audit-only")
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    tenant = relationship("Tenant", back_populates="policies")

    __table_args__ = (
        Index("ix_policies_tenant_id", "tenant_id"),
        Index("ix_policies_framework", "framework"),
    )


class AuditEvent(Base):
    """Immutable audit log entry for every firewall action."""
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    session_id: Mapped[Optional[str]] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # e.g.: input_scan, output_scan, redaction, policy_violation, auth, agent_action

    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), nullable=False)
    severity: Mapped[Optional[ThreatSeverity]] = mapped_column(SAEnum(ThreatSeverity))

    # What was detected
    detections: Mapped[Optional[Dict]] = mapped_column(JSON)
    # Which policies triggered
    policies_triggered: Mapped[Optional[list]] = mapped_column(JSON)
    # Explainability output
    explanation: Mapped[Optional[str]] = mapped_column(Text)
    # Confidence scores
    confidence_scores: Mapped[Optional[Dict]] = mapped_column(JSON)
    # Remediation recommendation
    remediation: Mapped[Optional[str]] = mapped_column(Text)

    # Request metadata (no raw content stored)
    request_hash: Mapped[Optional[str]] = mapped_column(String(64), comment="SHA256 of original content")
    content_type: Mapped[Optional[str]] = mapped_column(String(100))
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(512))
    model_used: Mapped[Optional[str]] = mapped_column(String(100))
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    tenant = relationship("Tenant", back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_events_tenant_id", "tenant_id"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_status", "status"),
        Index("ix_audit_events_created_at", "created_at"),
        Index("ix_audit_events_user_id", "user_id"),
    )


class TokenVaultEntry(Base):
    """
    Reversible token vault for redacted sensitive values.
    Entries expire after TTL and are encrypted at rest.
    """
    __tablename__ = "token_vault"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    token: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # Encrypted original value
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_token_vault_token", "token"),
        Index("ix_token_vault_session_id", "session_id"),
        Index("ix_token_vault_expires_at", "expires_at"),
    )


class ScanResult(Base):
    """Detailed scan result for input/output inspection."""
    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    audit_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("audit_events.id"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # input_prompt | output_response | file | rag_document

    pii_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    phi_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    pci_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    secrets_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    injection_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    toxicity_detected: Mapped[bool] = mapped_column(Boolean, default=False)

    entities_found: Mapped[Optional[list]] = mapped_column(JSON)
    injection_patterns: Mapped[Optional[list]] = mapped_column(JSON)
    redactions_applied: Mapped[Optional[list]] = mapped_column(JSON)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    processing_time_ms: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_scan_results_audit_event_id", "audit_event_id"),
        Index("ix_scan_results_tenant_id", "tenant_id"),
    )


class AgentAction(Base):
    """Log of AI agent actions requiring approval or audit."""
    __tablename__ = "agent_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # api_call | email | code_execution | db_query | file_write

    action_params: Mapped[Optional[Dict]] = mapped_column(JSON)
    permission_level: Mapped[str] = mapped_column(String(50), nullable=False)
    approved: Mapped[Optional[bool]] = mapped_column(Boolean)
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    execution_result: Mapped[Optional[Dict]] = mapped_column(JSON)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    blocked_reason: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_agent_actions_tenant_id", "tenant_id"),
        Index("ix_agent_actions_agent_id", "agent_id"),
        Index("ix_agent_actions_session_id", "session_id"),
    )
