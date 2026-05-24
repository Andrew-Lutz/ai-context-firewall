"""
Application configuration using Pydantic Settings.
All values are loaded from environment variables or .env file.
"""
from functools import lru_cache
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration for the AI Context Firewall platform.
    All secrets must be provided via environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_env: str = Field(default="production", description="Environment: development|staging|production")
    app_secret_key: str = Field(default="dev-secret-key-change-in-production", description="Application secret key for signing")
    app_debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    api_version: str = Field(default="v1")
    allowed_origins: List[str] = Field(default=["http://localhost:8501"])

    # --- Database ---
    database_url: str = Field(default="sqlite+aiosqlite:///./acf_dev.db", description="PostgreSQL async URL")
    db_pool_size: int = Field(default=20)
    db_max_overflow: int = Field(default=10)
    db_pool_timeout: int = Field(default=30)

    # --- Redis ---
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis connection URL with password")
    redis_session_ttl: int = Field(default=3600, description="Session TTL in seconds")

    # --- JWT ---
    jwt_secret_key: str = Field(default="dev-jwt-secret-key-32chars-minimum!!", description="JWT signing secret")
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=60)
    jwt_refresh_token_expire_days: int = Field(default=7)

    # --- LLM Providers ---
    openai_api_key: Optional[str] = Field(default=None)
    anthropic_api_key: Optional[str] = Field(default=None)
    default_llm_provider: str = Field(default="openai")
    default_model: str = Field(default="gpt-4o")
    llm_timeout_seconds: int = Field(default=60)
    llm_max_retries: int = Field(default=3)

    # --- Encryption ---
    encryption_key: str = Field(default="", description="Fernet encryption key for vault")
    token_vault_salt: str = Field(default="dev-salt", description="Salt for token generation")

    # --- Redaction ---
    redaction_mode: str = Field(default="mask", description="mask|hash|tokenize")
    enable_reversible_tokens: bool = Field(default=True)
    token_vault_ttl_hours: int = Field(default=24)

    # --- Rate Limiting ---
    rate_limit_requests_per_minute: int = Field(default=100)
    rate_limit_burst: int = Field(default=20)

    # --- File Upload ---
    file_upload_max_mb: int = Field(default=50)
    allowed_file_types: List[str] = Field(
        default=["pdf", "csv", "json", "txt", "docx", "eml"]
    )

    # --- Observability ---
    prometheus_enabled: bool = Field(default=True)
    prometheus_port: int = Field(default=9090)

    # --- Multi-tenancy ---
    default_tenant_id: str = Field(default="default")
    max_tenants: int = Field(default=100)

    # --- Vector DB ---
    pinecone_api_key: Optional[str] = Field(default=None)
    pinecone_environment: Optional[str] = Field(default=None)
    weaviate_url: Optional[str] = Field(default=None)

    # --- Kafka ---
    kafka_bootstrap_servers: Optional[str] = Field(default=None)
    kafka_topic_audit: str = Field(default="firewall.audit")
    kafka_topic_alerts: str = Field(default="firewall.alerts")

    # --- Email ---
    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    alert_email_from: Optional[str] = Field(default=None)
    alert_email_to: Optional[str] = Field(default=None)

    # --- Scanning Thresholds ---
    pii_confidence_threshold: float = Field(default=0.75)
    injection_severity_threshold: float = Field(default=0.60)
    toxicity_threshold: float = Field(default=0.70)

    @field_validator("redaction_mode")
    @classmethod
    def validate_redaction_mode(cls, v: str) -> str:
        """Ensure redaction mode is one of the allowed values."""
        allowed = {"mask", "hash", "tokenize"}
        if v not in allowed:
            raise ValueError(f"redaction_mode must be one of {allowed}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log level is valid."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.app_env == "development"

    @property
    def file_upload_max_bytes(self) -> int:
        """Maximum file upload size in bytes."""
        return self.file_upload_max_mb * 1024 * 1024


@lru_cache()
def get_settings() -> Settings:
    """
    Return cached application settings.
    Uses lru_cache to ensure settings are loaded once.
    """
    return Settings()
