# SentinelX AI ⚡

> **Autonomous Cyber Investigation Officer** — An enterprise-grade cybersecurity platform for automated log analysis, IOC extraction, MITRE ATT&CK mapping, and incident management.

[![Phase](https://img.shields.io/badge/Phase-2%20NLP%20Engine-cyan?style=flat-square)](./)
[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](./)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square&logo=fastapi)](./)
[![React](https://img.shields.io/badge/React-18-blue?style=flat-square&logo=react)](./)
[![Tests](https://img.shields.io/badge/Tests-140%20passed-brightgreen?style=flat-square)](./)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square&logo=docker)](./)

---

## 🎯 What is SentinelX AI?

SentinelX AI is a production-ready security operations platform that automates the work of a SOC analyst:

- 🔍 **Ingests** raw security logs (Linux syslog, Windows Event Log, Apache/Nginx, Sysmon)
- 🧠 **Parses & Detects** log format automatically with confidence scoring
- 🎯 **Extracts IOCs** — IPs, domains, URLs, file hashes, CVEs, email addresses (16 types)
- 🗺️ **Maps to MITRE ATT&CK** — 47 rules across 12 tactics, technique + sub-technique IDs
- 🚨 **Creates Incidents** — auto-generated from critical threat events with severity scoring
- 📊 **Visualises** everything through a premium dark-mode React dashboard

**Current Phase: 2 — NLP Security Pipeline** (Phase 3 will add Multi-Agent AI)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SentinelX AI Platform                       │
├──────────────────────┬──────────────────────────────────────────┤
│  React 18 Frontend   │           FastAPI Backend                │
│  (Vite + CSS)        │           (Python 3.11)                  │
│                      │                                          │
│  • Log Analysis      │  ┌─────────────────────────────────┐    │
│  • IOC Explorer      │  │        NLP Pipeline              │    │
│  • Incidents         │  │  Detect → Parse → Extract →      │    │
│  • Statistics        │  │  Classify → Persist              │    │
│  • Dashboard         │  └─────────────────────────────────┘    │
└──────────────────────┴─────────┬────────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
    PostgreSQL 16           Redis 7.4            Neo4j 5.24
    (events, IOCs,          (caching,            (graph DB,
     incidents)              sessions)            future agents)
                                                         │
                                               Qdrant (vector DB,
                                               future RAG)
```

---

## 📁 Project Structure

```
SentinelX-AI/
├── backend/
│   ├── app.py                      # Application factory + admin seeder
│   ├── config.py                   # Pydantic settings (env vars)
│   ├── dependencies.py             # FastAPI DI (DB, auth, roles)
│   ├── core/
│   │   ├── exceptions.py           # SentinelXBaseException hierarchy
│   │   ├── logging.py              # Structured JSON logger
│   │   └── security.py            # JWT + bcrypt helpers
│   ├── middleware/
│   │   └── logging_middleware.py   # Request ID + timing
│   ├── models/                     # SQLAlchemy ORM models
│   │   ├── user.py                 # User + Role
│   │   ├── security_log.py         # SecurityLog (LogType, LogStatus)
│   │   ├── parsed_event.py         # ParsedEvent (MITRE fields)
│   │   ├── ioc_entity.py           # IOCEntity (16 IOC types)
│   │   └── incident_event.py       # IncidentEvent
│   ├── schemas/
│   │   ├── logs.py                 # All Phase 2 Pydantic schemas
│   │   ├── user.py                 # Auth schemas
│   │   └── common.py              # APIResponse[T] envelope
│   ├── repositories/               # Repository pattern (Clean Architecture)
│   │   ├── log_repository.py
│   │   ├── event_repository.py
│   │   ├── ioc_repository.py
│   │   └── incident_repository.py
│   ├── services/
│   │   ├── auth_service.py         # Registration, login, JWT
│   │   └── log_service.py          # Upload, parse, search, statistics
│   ├── routes/
│   │   ├── auth.py                 # POST /auth/login, /register, GET /me
│   │   ├── health.py               # GET /health (all 4 services)
│   │   ├── dashboard.py            # GET /dashboard
│   │   └── logs.py                 # 10 Phase 2 endpoints
│   └── nlp/                        # ← Core NLP Engine
│       ├── detector.py             # LogTypeDetector (auto-detection)
│       ├── pipeline.py             # NLPPipeline orchestrator
│       ├── parsers/
│       │   ├── base.py             # BaseParser abstract class
│       │   ├── registry.py         # ParserRegistry
│       │   ├── linux_syslog.py     # Linux syslog parser
│       │   ├── windows_event.py    # Windows Event Log parser
│       │   ├── apache_access.py    # Apache Combined Log parser
│       │   ├── nginx_access.py     # Nginx access log parser
│       │   └── sysmon.py           # Sysmon XML parser
│       ├── extractor/
│       │   ├── patterns.py         # 16 compiled regex patterns
│       │   └── ioc_extractor.py    # IOCExtractor engine
│       └── classifier/
│           ├── mitre_rules.py      # 47 MITRE ATT&CK rules
│           └── event_classifier.py # EventClassifier engine
│
├── frontend/
│   └── src/
│       ├── api/
│       │   ├── client.js           # Axios instance (bearer token)
│       │   └── logs.js             # Phase 2 API methods
│       ├── context/AuthContext.jsx # Global auth state
│       ├── pages/
│       │   ├── LoginPage.jsx
│       │   ├── DashboardPage.jsx
│       │   ├── LogUploadPage.jsx   # Drag-and-drop upload + parse
│       │   ├── LogViewerPage.jsx   # Events table + MITRE badges
│       │   ├── IOCExplorerPage.jsx # IOC search + type filter
│       │   ├── IncidentPage.jsx    # Incident management
│       │   └── StatisticsPage.jsx  # Metrics + bar charts
│       └── components/layout/
│           ├── Sidebar.jsx         # Collapsible nav
│           └── AppLayout.jsx       # Shell wrapper
│
├── databases/
│   ├── postgres.py                 # AsyncEngine + table init
│   ├── redis.py                    # aioredis connection pool
│   └── neo4j_driver.py            # Neo4j async driver
│
├── tests/
│   ├── fixtures/                   # 5 realistic log samples
│   │   ├── linux_syslog.log
│   │   ├── windows_event.log
│   │   ├── apache_access.log
│   │   ├── nginx_access.log
│   │   └── sysmon.log
│   └── nlp/                        # 140 unit tests
│       ├── test_detector.py        # 11 tests
│       ├── test_parsers.py         # 36 tests
│       ├── test_ioc_extractor.py   # 20 tests
│       ├── test_classifier.py      # 26 tests
│       └── test_pipeline.py        # 47 tests
│
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

---

## 🚀 Quickstart

### Prerequisites

| Tool | Min Version |
|------|-------------|
| Docker Desktop | 24+ |
| Node.js | 18+ |
| Python | 3.10+ (for local testing only) |

### 1. Clone & configure

```bash
git clone https://github.com/your-org/SentinelX-AI.git
cd SentinelX-AI
cp .env.example .env          # edit JWT_SECRET at minimum
```

### 2. Start all services

```bash
docker compose up -d
```

This starts: Postgres 16, Redis 7, Neo4j 5, Qdrant, Backend API, Frontend.

### 3. Access the app

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend | http://localhost:5173 | `admin@sentinelx.ai` / `SentinelX@2025!` |
| API Docs | http://localhost:8000/docs | Bearer token from `/auth/login` |
| Health | http://localhost:8000/health | Public |

> **Note:** The admin user is automatically created on first boot via the startup seeder.

### 4. Run locally (development)

```bash
# Backend
pip install -r requirements.txt
DATABASE_URL=postgresql+asyncpg://sentinelx_user:sentinelx_secret@localhost/sentinelx \
JWT_SECRET=your-secret \
uvicorn backend.app:app --reload --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

---

## 🔬 NLP Security Pipeline

The Phase 2 pipeline processes raw log files through 5 deterministic stages:

```
Raw File
   │
   ▼
[1] LogTypeDetector        — confidence-scored auto-detection
   │
   ▼
[2] Parser (×5)            — structured NormalizedEvent extraction
   │
   ▼
[3] IOCExtractor           — 16 IOC types via compiled regex
   │
   ▼
[4] EventClassifier        — 47 MITRE ATT&CK rules (deterministic)
   │
   ▼
[5] Persist                — atomic PostgreSQL write (events + IOCs + incidents)
```

### Supported Log Formats

| Format | Parser | Auto-Detection |
|--------|--------|---------------|
| Linux Syslog | `LinuxSyslogParser` | `Jul  1 HH:MM:SS hostname svc[pid]:` |
| Windows Event Log | `WindowsEventParser` | `EventID=NNNN Level=` |
| Apache Access Log | `ApacheAccessParser` | Combined Log Format |
| Nginx Access Log | `NginxAccessParser` | Nginx default format |
| Sysmon XML | `SysmonParser` | `<EventID>` XML tags |

### IOC Types Extracted (16)

`ipv4` · `ipv6` · `domain` · `url` · `md5` · `sha1` · `sha256` · `email` · `cve` · `username` · `hostname` · `filename` · `registry_key` · `command_line` · `port` · `mac_address`

### MITRE ATT&CK Coverage (47 rules)

| Tactic | Example Techniques |
|--------|--------------------|
| Initial Access | T1190 (Exploit Public-Facing App), T1566 (Phishing) |
| Execution | T1059 (Command Scripting), T1059.001 (PowerShell) |
| Persistence | T1547 (Registry Run Keys), T1098 (Account Manipulation) |
| Privilege Escalation | T1068 (Exploit), T1548 (Sudo/UAC Bypass) |
| Credential Access | T1110 (Brute Force), T1003 (LSASS Dump) |
| Discovery | T1083 (File Discovery), T1046 (Network Scan) |
| Lateral Movement | T1021 (Remote Services) |
| Exfiltration | T1048 (Alt Protocol), T1071 (C2) |

---

## 🌐 REST API Reference

All endpoints are versioned under `/api/v1`. Protected routes require `Authorization: Bearer <token>`.

### Authentication

```
POST /api/v1/auth/register     — Create account
POST /api/v1/auth/login        — Get JWT token
GET  /api/v1/auth/me           — Current user info
POST /api/v1/auth/refresh      — Refresh token
POST /api/v1/auth/logout       — Invalidate token
```

### Log Management

```
POST /api/v1/logs/upload             — Upload raw log file [analyst, admin]
POST /api/v1/logs/{id}/parse         — Run NLP pipeline   [analyst, admin]
GET  /api/v1/logs                    — List all logs (paginated)
GET  /api/v1/logs/{id}               — Log metadata + pipeline summary
GET  /api/v1/logs/{id}/events        — Parsed events (filterable)
GET  /api/v1/logs/{id}/iocs          — IOCs for a log
DELETE /api/v1/logs/{id}             — Delete log + all derived data [admin]
```

**Upload → Parse workflow:**

```bash
# 1. Upload file
curl -X POST http://localhost:8000/api/v1/logs/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/auth.log" \
  -F "force_log_type=linux_syslog"   # optional

# 2. Parse (run NLP pipeline)
curl -X POST http://localhost:8000/api/v1/logs/1/parse \
  -H "Authorization: Bearer $TOKEN"
```

### IOC Intelligence

```
GET /api/v1/iocs/search              — List all IOCs or search by value
  ?q=185.24.18                       — Substring search
  ?ioc_type=ipv4                     — Filter by type
  ?page=1&page_size=50
```

### Incidents

```
GET   /api/v1/incidents              — List incidents (filterable)
GET   /api/v1/incidents/{id}         — Incident detail
PATCH /api/v1/incidents/{id}/status  — Update status (open → investigating → resolved)
```

### Statistics

```
GET /api/v1/statistics               — Platform-wide metrics
  → total_logs, total_events, total_iocs, severity breakdown,
    log type distribution, top source IPs, MITRE tactic heatmap
```

---

## 🧪 Testing

### Run unit tests

```bash
cd SentinelX-AI
python3.10 -m pytest tests/nlp/ -v
```

**Results: 140/140 passed**

| File | Tests | Coverage Area |
|------|-------|---------------|
| `test_detector.py` | 11 | Auto-detection, confidence thresholds, all 5 types |
| `test_parsers.py` | 36 | All 5 parsers, field extraction, edge cases |
| `test_ioc_extractor.py` | 20 | All 16 IOC types, benign filtering, deduplication |
| `test_classifier.py` | 26 | MITRE rules, severity scoring, `to_dict()` |
| `test_pipeline.py` | 47 | End-to-end pipeline, async, IOC dedup, enrichment |

### Run with coverage

```bash
python3.10 -m pytest tests/nlp/ --cov=backend/nlp --cov-report=term-missing
```

---

## 🔐 Security Model

| Concern | Implementation |
|---------|----------------|
| Authentication | JWT (HS256), 30-min expiry, refresh tokens |
| Password hashing | bcrypt (12 rounds) |
| Role-based access | `viewer` · `analyst` · `admin` |
| Upload access | `analyst` + `admin` only |
| CORS | Configurable per-environment |
| SQL injection | SQLAlchemy ORM (parameterised queries only) |
| Secrets | Environment variables, never in source |

### Default Roles

| Role | Permissions |
|------|-------------|
| `viewer` | Read logs, events, IOCs, incidents, statistics |
| `analyst` | + Upload logs, trigger parsing |
| `admin` | + Delete logs, manage users |

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | `development` \| `production` |
| `DATABASE_URL` | — | PostgreSQL asyncpg connection string |
| `JWT_SECRET` | — | **Required.** Minimum 32 characters |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_ACCESS_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j bolt URI |
| `QDRANT_URL` | `http://localhost:6333` | Qdrant REST URL |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ Complete | Infrastructure: FastAPI, Postgres, Redis, Neo4j, Qdrant, Auth |
| **Phase 2** | ✅ Complete | NLP Pipeline: parsers, IOC extraction, MITRE classification, REST API, React UI |
| **Phase 3** | 🔜 Planned | Multi-Agent AI: LangGraph agents, autonomous investigation workflows |
| **Phase 4** | 🔜 Planned | GraphRAG: Neo4j knowledge graph, entity linking, attack chain reasoning |
| **Phase 5** | 🔜 Planned | RAG: Qdrant vector search, threat intel corpus, semantic Q&A |

---

## 🛠️ Development Guide

### Adding a new log parser

1. Create `backend/nlp/parsers/my_format.py` extending `BaseParser`
2. Implement `parse(content: str | bytes) -> list[NormalizedEvent]`
3. Register in `backend/nlp/parsers/registry.py`
4. Add detection pattern to `backend/nlp/detector.py`
5. Add fixture to `tests/fixtures/` and tests to `tests/nlp/test_parsers.py`

### Adding a new MITRE rule

Edit `backend/nlp/classifier/mitre_rules.py` and add a `ClassificationRule` to `CLASSIFICATION_RULES`:

```python
ClassificationRule(
    event_type_pattern=r"my event pattern",
    technique_id="T1234",
    technique_name="Technique Name",
    sub_technique_id="T1234.001",        # optional
    tactic="Tactic Name",
    tactic_id="TA0001",
    severity=SeverityLevel.HIGH,
    score=8,
    description="What this rule detects",
    tags=["tag1", "tag2"],
),
```

### Code style

- **Backend:** Black formatter, isort, mypy strict
- **Frontend:** ESLint + Prettier (Vite defaults)
- **Architecture:** Clean Architecture — routes → services → repositories → models
- **No AI in Phase 2:** All logic is deterministic rule-based — no LLMs, LangGraph, or agents

---

## 📄 License

MIT — see [LICENSE](./LICENSE)

---

<p align="center">Built with ⚡ by the SentinelX team</p>
