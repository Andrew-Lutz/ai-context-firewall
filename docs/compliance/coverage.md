# AI Context Firewall — Compliance Coverage

## Supported Compliance Frameworks

### HIPAA (Health Insurance Portability and Accountability Act)

**Policy file**: `policies/hipaa/hipaa_v1.yaml`

| Requirement | Coverage |
|---|---|
| PHI Protection (§164.312) | Entity detection for MRN, diagnosis, ICD codes, NPI |
| Minimum Necessary Standard | Automatic redaction of PHI not required for task |
| Audit Controls (§164.312(b)) | Full audit trail with SHA-256 content fingerprints |
| Transmission Security | TLS enforcement, session encryption |
| Access Controls | Role-based clearance levels (0–4) |

PHI entity types detected: MRN, ICD code, NPI, diagnosis keywords, treatment keywords, prescription keywords, patient name + DOB combinations.

---

### GDPR (General Data Protection Regulation)

**Policy file**: `policies/gdpr/gdpr_v1.yaml`

| Requirement | Coverage |
|---|---|
| Art. 5 — Data Minimisation | Automatic PII detection and redaction |
| Art. 17 — Right to Erasure | Bulk deletion requests flagged for review |
| Art. 25 — Privacy by Design | Redaction applied by default in pipeline |
| Art. 32 — Security | Encrypted sessions, audit logging |
| Art. 35 — DPIA | High-risk processing patterns detected and alerted |

PII entity types: name, email, phone, address, DOB, national ID, IP address, cookie/tracking IDs.

---

### PCI-DSS (Payment Card Industry Data Security Standard)

**Policy file**: `policies/pci_dss/pci_dss_v1.yaml`

| Requirement | Coverage |
|---|---|
| Req. 3 — Protect Stored CHD | Luhn-validated card number detection and blocking |
| Req. 4 — Encrypt Transmission | CHD redacted before any AI processing |
| Req. 7 — Restrict Access | Role-based access control for financial data |
| Req. 10 — Audit Logging | Full audit trail for all CHD-related events |
| Req. 12 — Security Policy | YAML-driven policy with version control |

PCI entity types: primary account number (PAN), CVV/CVC, expiry date in card context, cardholder name.

---

### FINRA (Financial Industry Regulatory Authority)

**Policy file**: `policies/finra/finra_v1.yaml`

| Requirement | Coverage |
|---|---|
| Rule 2010 — Standards of Commercial Honor | Guaranteed return claims blocked |
| Rule 2111 — Suitability | Investment recommendations flagged for human review |
| Rule 4370 — Business Continuity | Customer account data protected |
| Rule 4511 — Recordkeeping | Client communications flagged for retention |
| MNPI Controls | Material non-public information patterns blocked |

---

### SOC 2 Type II (AICPA Trust Service Criteria)

**Policy file**: `policies/soc2/soc2_v1.yaml`

| TSC | Requirement | Coverage |
|---|---|---|
| CC6.1 | Logical Access Controls | Credential exposure blocked; privilege escalation detected |
| CC6.3 | Access Removal | Bulk data deletion requests escalated |
| CC7.2 | System Monitoring | System config changes alerted; anomalous access patterns detected |
| CC8.1 | Change Management | Production deployment requests flagged |
| P3.1 | Privacy | PII redacted per privacy criteria |

---

## Audit Trail Integrity

All audit events:
- Store **only SHA-256 hashes** of sensitive content (never plaintext)
- Are **append-only** (no update/delete operations on audit records)
- Include: timestamp, user_id, tenant_id, session_id, action, risk_score, policy_id, content_hash
- Are SIEM-compatible (structured JSON, configurable export to Splunk, Elastic, Datadog)

## Evidence Generation

For compliance audits, the platform generates:

1. **Event Log Export** — JSON/CSV of all firewall events for any time range
2. **Policy Coverage Report** — Which rules fired, how many times, what actions taken
3. **Redaction Report** — Count of PII/PHI entities detected and redacted (no raw data)
4. **Access Control Log** — Who accessed what data, when, from which session
5. **Compliance Summary** — Per-framework pass/fail counts

## Encryption Standards

| Layer | Standard |
|---|---|
| Data in Transit | TLS 1.2+ (TLS 1.3 preferred) |
| Session Data | Fernet (AES-128-CBC + HMAC-SHA256) |
| Token Vault | Fernet (AES-128-CBC + HMAC-SHA256) |
| Audit Hashes | SHA-256 |
| Passwords | bcrypt (cost factor 12) |
| JWT Tokens | HS256 (configurable to RS256) |
