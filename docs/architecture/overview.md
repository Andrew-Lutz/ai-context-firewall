# AI Context Firewall — Architecture Overview

## System Architecture

The AI Context Firewall is a middleware security layer that intercepts all traffic between applications and LLMs. It operates as a transparent proxy with zero-trust security applied at every stage.

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT APPLICATIONS                      │
│          (Web Apps · API Clients · Agent Frameworks)            │
└───────────────────────────────┬─────────────────────────────────┘
                                │  HTTPS / TLS 1.3
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      NGINX REVERSE PROXY                        │
│              Rate Limiting · TLS Termination · WAF              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FASTAPI GATEWAY (8000)                     │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  JWT Auth   │  │ Rate Limit  │  │    Audit Middleware      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   SECURITY PIPELINE                       │  │
│  │                                                           │  │
│  │  1. ┌────────────────────────────────────────────────┐   │  │
│  │     │  INSPECTION ENGINE                              │   │  │
│  │     │  PII · PHI · PCI · Secrets · Injection        │   │  │
│  │     └────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │  2. ┌────────────────────────────────────────────────┐   │  │
│  │     │  REDACTION ENGINE                               │   │  │
│  │     │  Mask · Hash · Tokenize (Fernet Token Vault)   │   │  │
│  │     └────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │  3. ┌────────────────────────────────────────────────┐   │  │
│  │     │  POLICY ENGINE (YAML-driven)                    │   │  │
│  │     │  HIPAA · GDPR · PCI-DSS · SOC2 · FINRA        │   │  │
│  │     └────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │  4. ┌────────────────────────────────────────────────┐   │  │
│  │     │  PROMPT FIREWALL                                │   │  │
│  │     │  Session Isolation · Hard Blocks · Decision    │   │  │
│  │     └────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└───────────────────────────────┬─────────────────────────────────┘
                                │ Approved / Redacted Prompts
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LLM PROVIDER GATEWAY                         │
│          OpenAI · Anthropic · Google · Self-hosted              │
└───────────────────────────────┬─────────────────────────────────┘
                                │ LLM Response
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    OUTPUT FIREWALL                               │
│    Hijack Detection · PII Scrub · URL Sanitize · Code Check     │
└───────────────────────────────┬─────────────────────────────────┘
                                │ Safe, Governed Output
                                ▼
                       CLIENT APPLICATION
```

## Core Components

### 1. Inspection Engine (`backend/core/inspection/engine.py`)

Pre-compiled regex patterns for:
- **PII**: SSN, email, phone, passport, driver's licence, date of birth
- **PHI**: MRN, ICD codes, NPI, diagnosis keywords
- **PCI**: Credit cards (Luhn-validated), CVV, bank accounts
- **Secrets**: API keys, JWTs, private keys, bearer tokens
- **Injections**: 9+ patterns covering instruction override, jailbreak, delimiter injection, prompt extraction

Outputs `InspectionResult` with risk score (0–1), entity list, and injection list.

### 2. Redaction Engine (`backend/core/redaction/engine.py`)

Three redaction modes:
- **mask**: Replace with `[ENTITY_TYPE]` label
- **hash**: SHA-256 truncated hash for correlation without exposure
- **tokenize**: Fernet AES-128-CBC encrypted token stored in Redis vault with TTL; reversible for authorized detokenization

### 3. Governance / Policy Engine (`backend/core/governance/engine.py`)

YAML-driven policy evaluation:
- Hot-reloadable policies (no restart required)
- Deterministic, explainable decisions
- 10+ condition types: `regex_match`, `keyword_match`, `entity_detected`, `context_match`, `combined`
- Actions: `allow`, `block`, `redact`, `alert`, `escalate`

### 4. Prompt Firewall (`backend/core/firewall/prompt_firewall.py`)

Orchestrates the full inbound pipeline:
- Session isolation (zero cross-tenant leakage)
- Hard-block patterns (immutable rules, not configurable)
- Inspection → Redaction → Policy → Decision
- SHA-256 audit fingerprint (never stores raw PII)

### 5. Output Firewall (`backend/core/firewall/output_firewall.py`)

Second line of defence on LLM responses:
- Jailbreak confirmation detection (was the model compromised?)
- PII/PHI in generated text
- Unsafe URLs (private IPs, localhost, SSRF vectors)
- Dangerous code in code blocks

### 6. Session Memory (`backend/core/memory/session.py`)

- Fernet AES-128-CBC encrypted at-rest sessions
- TTL enforcement (configurable, default 1 hour)
- Cross-tenant isolation via `tenant_id:session_id` namespace
- Context window manager with poisoning detection

### 7. RAG Security (`backend/core/rag/security.py`)

- Attribute-based access control (role clearance vs document classification)
- Pre-ingestion poisoning scan (7 threat patterns)
- Query injection detection and authorization
- Source attribution enforcement

### 8. Agent Controls (`backend/core/agents/controls.py`)

- 14-tool risk registry with required permissions
- Argument-level threat scanning
- Risk-ceiling enforcement per agent profile
- Rate limiting (configurable per-agent)
- Human approval workflows for HIGH+ risk tool calls

### 9. Observability (`backend/core/observability/metrics.py`)

- Prometheus metrics (counters, histograms, gauges)
- Structured JSON logging (SIEM/SOAR compatible)
- In-memory event buffer for recent-event queries

## Data Flow

```
Request → [Auth] → [Rate Limit] → [Inspection] → [Redaction]
       → [Policy Eval] → [Prompt Firewall Decision]
       → [LLM Call] (if allowed)
       → [Output Firewall] → [Audit Log] → Response
```

## Security Properties

| Property | Implementation |
|---|---|
| PII never logged | SHA-256 hashes only in audit trail |
| Zero cross-tenant leakage | Namespaced session keys, RBAC tenant isolation |
| Encrypted sessions | Fernet AES-128-CBC with configurable key |
| Immutable hard blocks | Pre-compiled regex, no policy override possible |
| Tamper-evident audit | Append-only log with content fingerprints |
| Defense in depth | 9-layer pipeline; each layer independent |

## Deployment Modes

1. **Sidecar**: Deploy alongside each AI-enabled service
2. **Gateway**: Centralized proxy for all AI traffic  
3. **SDK**: Import `PromptFirewall` directly in Python applications
4. **API**: Call via REST API from any language
