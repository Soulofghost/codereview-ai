# CodeReview AI

[![CI Pipeline](https://github.com/Soulofghost/codereview-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/Soulofghost/codereview-ai/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/SQLite-WAL%20Mode-003B57.svg)](https://www.sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **CodeReview AI** is an automated code review assistant and security linter powered by Python Abstract Syntax Tree (AST) static analysis and heuristic vulnerability scanning. It detects injection flaws, hardcoded credentials, cyclomatic complexity bottlenecks, and code smells, returning automated patch recommendations and letter-grade quality scores.

---

## 1. System Architecture

CodeReview AI parses source code into an AST tree and executes targeted security and architectural visitors.

```
┌─────────────────────────────────────────────────────────────┐
│                 IDE Review Workspace (SPA)                  │
│   • Split-screen editor with benchmark injection samples    │
│   • Code quality score (0 to 100) & letter grade (A+ to F)  │
│   • Severity distribution & line-by-line annotated issues   │
│   • One-click actionable patch diff recommendations         │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON
┌──────────────────────────────▼──────────────────────────────┐
│                   FastAPI Application Tier                  │
│   • Code Submission & File Ingestion Router                 │
│   • Review History & Telemetry Analytics                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┴───────────────────────┐
       ▼                                               ▼
┌─────────────────────────────┐         ┌─────────────────────────────┐
│    Static Analysis Engine   │         │   High-Throughput Storage   │
│  • Python AST Node Visitor  │         │   • SQLite 3 WAL Mode       │
│  • Secrets & API Key Regex  │         │   • Reviews & Issue Logs    │
│  • Cyclomatic Complexity M  │         │   • Foreign Key Cascade     │
│  • Patch Diff Generator     │         └─────────────────────────────┘
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│    Quality Grade Machine    │
│  • 100 - Penalties          │
│  • Critical (-25), Major(-12│
│  • A+ (>=90) down to F (<50)│
└─────────────────────────────┘
```

---

## 2. Active Rule Matrix

| Rule ID | Severity | Category | Rule Title & Description |
| :--- | :--- | :--- | :--- |
| **SEC-001** | `CRITICAL` | `SECURITY` | **Hardcoded AWS Access Key** — Scans for `AKIA[0-9A-Z]{16}` tokens. |
| **SEC-002** | `CRITICAL` | `SECURITY` | **Hardcoded GitHub PAT** — Scans for `ghp_[a-zA-Z0-9]{36}` tokens. |
| **SEC-010** | `CRITICAL` | `SECURITY` | **Insecure `os.system` Call** — Unsanitized shell execution (command injection). |
| **SEC-011** | `CRITICAL` | `SECURITY` | **Subprocess `shell=True`** — Shell execution bypasses argument escaping. |
| **SEC-012** | `CRITICAL` | `SECURITY` | **Insecure Deserialization** — `pickle.loads` allows arbitrary bytecode execution. |
| **SEC-013** | `MAJOR` | `SECURITY` | **Weak Cryptographic Hash** — `hashlib.md5` and `sha1` collision deprecations. |
| **SEC-014** | `CRITICAL` | `SECURITY` | **SQL Injection in `execute()`** — Formatted strings in database queries. |
| **BUG-001** | `MAJOR` | `BUG_RISK` | **Mutable Default Argument** — `def func(x=[])` persists state across calls. |
| **BUG-002** | `MAJOR` | `BUG_RISK` | **Bare `except:` Clause** — Intercepts `SystemExit` and critical exceptions. |
| **CMP-001** | `MAJOR` | `COMPLEXITY` | **High Cyclomatic Complexity** — Function complexity exceeding threshold $M > 8$. |
| **STY-001** | `MINOR` | `STYLE` | **Wildcard Import** — `from module import *` namespace pollution. |
| **DOC-001** | `INFO` | `DOCUMENTATION` | **Missing Docstring** — Public function lacking PEP-257 docstring. |

---

## 3. Technology Stack

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Backend Framework** | FastAPI 0.110+ | Asynchronous RESTful code inspection engine |
| **Static Analysis** | Python `ast` | Native Abstract Syntax Tree traversal |
| **Data Validation** | Pydantic v2 | Strict JSON serialization and input schemas |
| **Persistence** | SQLite 3 | WAL mode with relational review archiving |
| **Frontend UI** | Vanilla JS / CSS3 | High-end developer IDE terminal theme |
| **Testing** | Pytest + HTTPX | Automated unit tests covering all security rules |
| **DevOps** | Docker / Compose | Multi-stage production container |
| **CI/CD** | GitHub Actions | Automated build, test, and quality validation |

---

## 4. API Reference

### Analysis
- `POST /api/reviews/analyze` — Submit code for AST and vulnerability review.
  ```json
  {
    "filename": "payment_service.py",
    "repo_name": "core-backend",
    "code": "import os\ndef run(cmd): os.system(cmd)"
  }
  ```

### Audit & Telemetry
- `GET /api/reviews` — List historical code reviews with score and grade summary.
- `GET /api/reviews/{id}` — Retrieve complete review report with line-by-line annotations.
- `DELETE /api/reviews/{id}` — Delete review record.
- `GET /api/analytics/review-summary` — Aggregated metrics (total reviewed, critical CVEs, grade distribution).
- `GET /health` — Readiness probe.

---

## 5. Local Setup & Testing

### Installation
```bash
# Clone the repository
git clone https://github.com/Soulofghost/codereview-ai.git
cd codereview-ai

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt
```

### Running CodeReview AI
```bash
uvicorn app.main:app --app-dir backend --reload --port 8000
```
Open `http://localhost:8000` to interact with the static analysis IDE.

### Running Test Suite
```bash
pytest backend/tests -v
```

---

## 6. Docker Deployment

```bash
docker-compose up --build -d
docker-compose logs -f
```

---

## 7. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
