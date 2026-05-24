"""
Content Scanning API Routes.

Provides endpoints for:
- POST /scan/prompt       — scan a text prompt
- POST /scan/file         — scan an uploaded file
- POST /scan/output       — scan an LLM output response
- POST /scan/batch        — batch scan multiple items
- GET  /scan/{scan_id}    — retrieve scan result by ID
"""
from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field

from config import get_settings
from core.inspection.engine import InputInspectionEngine, InspectionResult
from core.redaction.engine import RedactionEngine
from core.governance.engine import PolicyEngine

logger = structlog.get_logger(__name__)
settings = get_settings()
router = APIRouter()

# Shared engine instances (initialized once, thread-safe for read)
_inspection_engine = InputInspectionEngine(
    pii_threshold=settings.pii_confidence_threshold,
    injection_threshold=settings.injection_severity_threshold,
    toxicity_threshold=settings.toxicity_threshold,
)
_redaction_engine = RedactionEngine(mode=settings.redaction_mode)
_policy_engine = PolicyEngine(policies_dir="policies")


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class ScanPromptRequest(BaseModel):
    """Request body for prompt scanning."""
    text: str = Field(..., min_length=1, max_length=100_000, description="Text to scan")
    content_type: str = Field(default="prompt", description="prompt | output | rag_doc")
    apply_redaction: bool = Field(default=True, description="Apply redaction to detected entities")
    tenant_id: Optional[str] = Field(default=None, description="Tenant identifier")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    user_role: Optional[str] = Field(default=None, description="User role for policy evaluation")
    department: Optional[str] = Field(default=None, description="User department")
    model_name: Optional[str] = Field(default=None, description="Target LLM model name")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class DetectedEntityResponse(BaseModel):
    entity_type: str
    category: str
    value_masked: str
    confidence: float
    detection_method: str
    explanation: Optional[str] = None


class InjectionAttemptResponse(BaseModel):
    attack_type: str
    severity: str
    confidence: float
    explanation: str
    remediation: str


class PolicyRuleResponse(BaseModel):
    rule_id: str
    rule_name: str
    framework: str
    action: str
    severity: str
    explanation: str
    remediation: str


class ScanResponse(BaseModel):
    """Comprehensive scan response with full explainability."""
    scan_id: str
    content_hash: str
    content_type: str
    scan_duration_ms: float

    # Detection results
    entities_detected: List[DetectedEntityResponse]
    injection_attempts: List[InjectionAttemptResponse]

    # Flags
    pii_detected: bool
    phi_detected: bool
    pci_detected: bool
    secrets_detected: bool
    injection_detected: bool
    toxicity_detected: bool

    # Risk scoring
    overall_risk_score: float
    confidence_scores: Dict[str, float]

    # Policy evaluation
    policy_action: str
    triggered_policy_rules: List[PolicyRuleResponse]
    compliance_frameworks: List[str]

    # Redaction
    redacted_text: Optional[str] = None
    redaction_count: int = 0

    # Explainability
    explanation_summary: str
    remediation_recommendations: List[str]
    triggered_rules: List[str]

    # Final decision
    action: str                  # allow | redact | block
    block_reason: Optional[str] = None
    safe_to_forward: bool


class FileScanResponse(BaseModel):
    """Response for file upload scanning."""
    scan_id: str
    filename: str
    file_size_bytes: int
    content_type: str
    pages_scanned: Optional[int] = None
    overall_risk_score: float
    action: str
    summary: str
    entities_detected: List[DetectedEntityResponse]
    injection_attempts: List[InjectionAttemptResponse]
    redacted_preview: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_policy_context(
    inspection: InspectionResult,
    request: ScanPromptRequest,
) -> Dict[str, Any]:
    """Build context dict for policy engine evaluation."""
    return {
        "entities": [e.entity_type.value for e in inspection.entities],
        "data_categories": [e.category.value for e in inspection.entities],
        "risk_score": inspection.overall_risk_score,
        "injection_detected": inspection.injection_detected,
        "injection_confidence": max(
            (inj.confidence for inj in inspection.injections), default=0.0
        ),
        "content_type": request.content_type,
        "user_role": request.user_role or "developer",
        "department": request.department or "",
        "model_name": request.model_name or settings.default_model,
        "text_lower": "",  # Not exposing raw text to policy engine
        "region": request.metadata.get("region", ""),
    }


def _make_scan_id() -> str:
    """Generate a unique scan identifier."""
    return f"scan_{uuid.uuid4().hex[:16]}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/prompt",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a text prompt for sensitive data and threats",
)
async def scan_prompt(
    request: ScanPromptRequest,
    http_request: Request,
) -> ScanResponse:
    """
    Scan a text prompt through the full inspection pipeline:
    1. Entity detection (PII/PHI/PCI/secrets)
    2. Injection/jailbreak detection
    3. Toxicity detection
    4. Policy evaluation
    5. Redaction (if required)

    Returns full explainability output including:
    - All detected entities (masked values only)
    - Injection attempts
    - Risk score and confidence
    - Policy rules triggered
    - Final action (allow/redact/block)
    - Remediation recommendations
    """
    scan_id = _make_scan_id()
    tenant_id = request.tenant_id or settings.default_tenant_id
    session_id = request.session_id or str(uuid.uuid4())
    start = time.monotonic()

    logger.info(
        "scan_prompt_start",
        scan_id=scan_id,
        tenant_id=tenant_id,
        content_type=request.content_type,
    )

    # 1. Inspect
    inspection = _inspection_engine.inspect(request.text, content_type=request.content_type)

    # 2. Policy evaluation
    policy_context = _build_policy_context(inspection, request)
    policy_result = _policy_engine.evaluate(policy_context, tenant_id=tenant_id)

    # 3. Determine final action (most restrictive of inspection + policy)
    action_priority = {"block": 3, "redact": 2, "alert": 1, "allow": 0}
    inspection_action = inspection.action
    policy_action = policy_result.final_action
    final_action = max(
        [inspection_action, policy_action],
        key=lambda a: action_priority.get(a, 0),
    )

    # 4. Redaction
    redacted_text: Optional[str] = None
    redaction_count = 0
    if final_action in ("redact", "block") and request.apply_redaction:
        from core.redaction.engine import RedactionResult
        redaction_result = _redaction_engine.redact(
            request.text, inspection, tenant_id=tenant_id, session_id=session_id
        )
        redacted_text = redaction_result.redacted_text
        redaction_count = redaction_result.redaction_count

    total_ms = (time.monotonic() - start) * 1000

    logger.info(
        "scan_prompt_complete",
        scan_id=scan_id,
        action=final_action,
        risk_score=inspection.overall_risk_score,
        entity_count=len(inspection.entities),
        duration_ms=total_ms,
    )

    return ScanResponse(
        scan_id=scan_id,
        content_hash=inspection.content_hash,
        content_type=request.content_type,
        scan_duration_ms=round(total_ms, 2),
        entities_detected=[
            DetectedEntityResponse(
                entity_type=e.entity_type.value,
                category=e.category.value,
                value_masked=e.value_masked,
                confidence=e.confidence,
                detection_method=e.detection_method,
                explanation=e.explanation,
            )
            for e in inspection.entities
        ],
        injection_attempts=[
            InjectionAttemptResponse(
                attack_type=inj.attack_type,
                severity=inj.severity,
                confidence=inj.confidence,
                explanation=inj.explanation,
                remediation=inj.remediation,
            )
            for inj in inspection.injections
        ],
        pii_detected=inspection.pii_detected,
        phi_detected=inspection.phi_detected,
        pci_detected=inspection.pci_detected,
        secrets_detected=inspection.secrets_detected,
        injection_detected=inspection.injection_detected,
        toxicity_detected=inspection.toxicity_detected,
        overall_risk_score=inspection.overall_risk_score,
        confidence_scores=inspection.confidence_scores,
        policy_action=policy_action,
        triggered_policy_rules=[
            PolicyRuleResponse(
                rule_id=r.rule_id,
                rule_name=r.rule_name,
                framework=r.framework,
                action=r.action.value,
                severity=r.severity,
                explanation=r.explanation,
                remediation=r.remediation,
            )
            for r in policy_result.triggered_rules
        ],
        compliance_frameworks=list(policy_result.compliance_frameworks_triggered),
        redacted_text=redacted_text,
        redaction_count=redaction_count,
        explanation_summary=inspection.explanation_summary,
        remediation_recommendations=(
            inspection.remediation_recommendations + policy_result.remediation_steps
        ),
        triggered_rules=inspection.triggered_rules,
        action=final_action,
        block_reason=inspection.block_reason,
        safe_to_forward=(final_action == "allow"),
    )


@router.post(
    "/file",
    response_model=FileScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan an uploaded file for sensitive data",
)
async def scan_file(
    file: UploadFile = File(...),
    tenant_id: Optional[str] = Form(default=None),
    session_id: Optional[str] = Form(default=None),
    apply_redaction: bool = Form(default=True),
) -> FileScanResponse:
    """
    Scan an uploaded file (PDF, CSV, JSON, TXT, DOCX, EML) for sensitive data.

    Supports:
    - PDF: text extraction from all pages
    - CSV: column and value scanning
    - JSON: deep key/value scanning
    - TXT/DOCX: full text scanning
    - EML: email header and body scanning

    Returns per-file risk assessment with entity detection.
    """
    scan_id = _make_scan_id()
    tenant_id = tenant_id or settings.default_tenant_id

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in settings.allowed_file_types:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{ext}' not supported. Allowed: {settings.allowed_file_types}",
        )

    content = await file.read()

    if len(content) > settings.file_upload_max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum: {settings.file_upload_max_mb}MB",
        )

    # Extract text based on file type
    text_content, pages = _extract_file_text(content, ext, file.filename)

    if not text_content:
        return FileScanResponse(
            scan_id=scan_id,
            filename=file.filename,
            file_size_bytes=len(content),
            content_type=ext,
            overall_risk_score=0.0,
            action="allow",
            summary="No extractable text content found in file.",
            entities_detected=[],
            injection_attempts=[],
        )

    # Inspect extracted text
    inspection = _inspection_engine.inspect(text_content, content_type="file")

    # Generate redacted preview (first 2000 chars)
    redacted_preview: Optional[str] = None
    if apply_redaction and inspection.entities:
        redaction = _redaction_engine.redact(
            text_content[:2000], inspection, tenant_id=tenant_id, session_id=scan_id
        )
        redacted_preview = redaction.redacted_text

    summary_parts = []
    if inspection.pii_detected:
        summary_parts.append("PII")
    if inspection.phi_detected:
        summary_parts.append("PHI")
    if inspection.pci_detected:
        summary_parts.append("PCI data")
    if inspection.secrets_detected:
        summary_parts.append("credentials/secrets")
    if inspection.injection_detected:
        summary_parts.append("injection attempts")

    summary = (
        f"File scan complete. Risk: {inspection.overall_risk_score:.1%}. "
        + (f"Detected: {', '.join(summary_parts)}." if summary_parts else "No threats detected.")
    )

    logger.info(
        "file_scan_complete",
        scan_id=scan_id,
        filename=file.filename,
        action=inspection.action,
        risk_score=inspection.overall_risk_score,
    )

    return FileScanResponse(
        scan_id=scan_id,
        filename=file.filename,
        file_size_bytes=len(content),
        content_type=ext,
        pages_scanned=pages,
        overall_risk_score=inspection.overall_risk_score,
        action=inspection.action,
        summary=summary,
        entities_detected=[
            DetectedEntityResponse(
                entity_type=e.entity_type.value,
                category=e.category.value,
                value_masked=e.value_masked,
                confidence=e.confidence,
                detection_method=e.detection_method,
                explanation=e.explanation,
            )
            for e in inspection.entities
        ],
        injection_attempts=[
            InjectionAttemptResponse(
                attack_type=inj.attack_type,
                severity=inj.severity,
                confidence=inj.confidence,
                explanation=inj.explanation,
                remediation=inj.remediation,
            )
            for inj in inspection.injections
        ],
        redacted_preview=redacted_preview,
    )


@router.post(
    "/output",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan LLM output response for data leakage",
)
async def scan_output(request: ScanPromptRequest) -> ScanResponse:
    """
    Output Firewall: inspect LLM response before delivering to user.
    Detects hallucinated PII, data leakage, and policy violations.
    Same pipeline as prompt scanning but with output-specific rules.
    """
    request.content_type = "output"
    return await scan_prompt(request, Request({"type": "http"}))


# ---------------------------------------------------------------------------
# File Text Extraction
# ---------------------------------------------------------------------------

def _extract_file_text(content: bytes, ext: str, filename: str) -> tuple[str, Optional[int]]:
    """
    Extract text from uploaded file based on extension.
    Returns (text_content, page_count).
    """
    try:
        if ext == "txt":
            import chardet
            encoding = chardet.detect(content)["encoding"] or "utf-8"
            return content.decode(encoding, errors="replace"), None

        elif ext == "pdf":
            import io
            import pdfplumber
            text_parts = []
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
            return "\n".join(text_parts), len(text_parts)

        elif ext == "csv":
            import io
            import pandas as pd
            df = pd.read_csv(io.BytesIO(content), dtype=str, nrows=10000)
            return df.to_string(), None

        elif ext == "json":
            import json
            data = json.loads(content)
            return json.dumps(data, indent=2, default=str)[:50000], None

        elif ext == "docx":
            import io
            from docx import Document
            doc = Document(io.BytesIO(content))
            text = "\n".join(p.text for p in doc.paragraphs)
            return text, None

        elif ext == "eml":
            import email
            msg = email.message_from_bytes(content)
            parts = [str(msg["From"]), str(msg["To"]), str(msg["Subject"])]
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))
            else:
                parts.append(msg.get_payload(decode=True).decode("utf-8", errors="replace"))
            return "\n".join(parts), None

        else:
            return "", None

    except Exception as e:
        logger.warning("file_extraction_error", filename=filename, ext=ext, error=str(e))
        return "", None
