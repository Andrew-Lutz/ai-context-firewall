# 🔥 AI Context Firewall Platform

> **Enterprise-grade AI security middleware** — intercept, inspect, redact, and govern all context flowing to and from large language models.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-ready-blue.svg)](https://kubernetes.io/)

---

## 🏛️ Executive Summary

The AI Context Firewall is a production-grade security middleware platform that sits between your users, applications, enterprise data, vector databases, AI agents, and LLMs. It provides:

- **Input Inspection** — Scans prompts, files, and documents for PII, PHI, PCI, secrets, and attack patterns
- **Redaction Engine** — Masks, tokenizes, and vaults sensitive data before LLM exposure
- **Prompt Firewall** — Detects injection, jailbreaks, Unicode attacks, and indirect RAG injections
- **Output Firewall** — Inspects model responses for leakage, hallucinated secrets, and compliance violations
- **Governance Engine** — YAML-based policies for HIPAA, GDPR, PCI-DSS, SOC2, FINRA, and custom enterprise rules
- **Session Isolation** — Multi-tenant, zero-trust memory boundaries with encrypted session vaults
- **RAG Security** — Authorized retrieval, vector filtering, and source attribution
- **Agent Controls** — Permission boundaries, approval workflows, and execution sandboxing
- **Observability** — Real-time dashboards, audit trails, Prometheus metrics, and exportable reports

### Supported Industries
| Industry | Key Compliance | Key Protections |
|---|---|---|
| Healthcare | HIPAA, HITECH | PHI redaction, audit trails |
| Finance | FINRA, SEC, PCI-DSS | PCI masking, transaction controls |
| Insurance | SOC2, state regs | Claims data protection |
| Government | FedRAMP, NIST | Classified data isolation |
| Legal | GDPR, attorney-client | Privilege protection |
| Enterprise SaaS | SOC2, GDPR | Multi-tenant isolation |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                              │
│          (Users / Apps / Agents / External Systems)              │
└─────────────────────┬───────────────────────────────────────────┘
                      │ HTTPS/WSS
┌─────────────────────▼───────────────────────────────────────────┐
│                    API Gateway (NGINX)                            │
│              JWT Auth · Rate Limiting · TLS                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│               FastAPI Backend (ai-context-firewall)              │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Input     │  │  Prompt     │  │      Output             │  │
│  │ Inspection  │→ │  Firewall   │→ │      Firewall           │  │
│  │   Engine    │  │             │  │                         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Redaction  │  │ Governance  │  │  Session / Memory       │  │
│  │    Engine   │  │   Engine    │  │  Isolation              │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  RAG Sec    │  │   Agent     │  │  Observability          │  │
│  │   Layer     │  │  Controls   │  │  & Audit                │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
    PostgreSQL      Redis      LLM Gateway
    (Audit DB)    (Sessions)  (OpenAI/Anthropic)
```

---

## 📁 Repository Structure

```
ai-context-firewall/
├── backend/
│   ├── api/
│   │   ├── routes/          # FastAPI route handlers
│   │   └── middleware/      # Auth, logging, rate-limit middleware
│   ├── core/
│   │   ├── inspection/      # Input context inspection engine
│   │   ├── redaction/       # Redaction + tokenization engine
│   │   ├── firewall/        # Prompt + output firewall
│   │   ├── governance/      # Policy engine
│   │   ├── memory/          # Session isolation
│   │   ├── rag/             # RAG security layer
│   │   ├── agents/          # Agent security controls
│   │   └── observability/   # Metrics, audit, logging
│   ├── models/              # SQLAlchemy ORM models
│   ├── schemas/             # Pydantic request/response schemas
│   ├── services/            # External service integrations
│   └── tests/               # Unit and integration tests
├── frontend/
│   ├── app.py               # Streamlit entry point
│   └── pages/               # Multi-page Streamlit app
├── infrastructure/
│   ├── docker/              # Dockerfiles
│   ├── kubernetes/          # K8s manifests + Helm charts
│   ├── terraform/           # Infrastructure as code
│   └── nginx/               # API gateway config
├── policies/                # YAML governance policies
├── docs/                    # Architecture + security docs
└── .github/workflows/       # CI/CD pipelines
```

---

## 🚀 Quick Start

### Prerequisites
- Docker 24+
- Docker Compose 2.20+
- Python 3.11+

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/ai-context-firewall.git
cd ai-context-firewall
cp .env.example .env
# Edit .env with your API keys and secrets
```

### 2. Launch with Docker Compose

```bash
docker-compose up -d
```

### 3. Access the Platform

| Service | URL |
|---|---|
| Streamlit Dashboard | http://localhost:8501 |
| FastAPI Backend | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |

### 4. Default Credentials (change immediately)

```
Admin:    admin@firewall.local / ChangeMe123!
Analyst:  analyst@firewall.local / ChangeMe123!
```

---

## 🔧 Configuration

All configuration is via environment variables (`.env`) and YAML policy files (`policies/`).

See [docs/configuration.md](docs/configuration.md) for full reference.

---

## 🧪 Running Tests

```bash
# Unit tests
cd backend && pytest tests/unit/ -v

# Integration tests (requires running services)
pytest tests/integration/ -v

# All tests with coverage
pytest --cov=backend --cov-report=html
```

---

## 📊 Compliance Matrix

| Regulation | Status | Key Controls |
|---|---|---|
| HIPAA | ✅ Supported | PHI detection, audit trails, access control |
| GDPR | ✅ Supported | PII redaction, right-to-erasure, data residency |
| PCI-DSS | ✅ Supported | PAN masking, cardholder data controls |
| SOC2 | ✅ Supported | Audit logging, availability monitoring |
| FINRA | ✅ Supported | Communication archival, suitability checks |
| NIST 800-53 | ✅ Supported | Zero-trust, least privilege, audit |

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require signed commits and passing CI.

## 📄 License

MIT License — see [LICENSE](LICENSE).
