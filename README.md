# SentinelX AI ⚡

> **Autonomous Cyber Investigation Officer** — An enterprise-grade AI platform for automated cybersecurity incident investigation powered by Multi-Agent AI, RAG, GraphRAG, and LLMs.

[![Phase](https://img.shields.io/badge/Phase-1%20Infrastructure-cyan?style=flat-square)](.)
[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](.)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square&logo=fastapi)](.)
[![React](https://img.shields.io/badge/React-18-blue?style=flat-square&logo=react)](.)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square&logo=docker)](.)

---

## 🎯 What is SentinelX AI?

SentinelX AI automates the work of a Security Operations Centre (SOC) analyst:

- 🔍 **Ingests** security logs, alerts, and threat intelligence feeds
- 🤖 **Investigates** incidents using multi-agent AI workflows
- 🧠 **Reasons** over attack patterns using GraphRAG and MITRE ATT&CK
- 📊 **Reports** findings in executive and technical formats
- 🔔 **Notifies** teams via Slack, email, and webhooks

**Current Phase: 1 — Infrastructure Foundation**

---

## 🗂️ Folder Structure

```
SentinelX-AI/
│
├── backend/                    # FastAPI application
│   ├── app.py                  # Application factory
│   ├── config.py               # Pydantic settings
│   ├── dependencies.py         # FastAPI DI
│   ├── core/
│   │   ├── logging.py          # Enterprise JSON logger
│   │   ├── exceptions.py       # Custom exception hierarchy
│   │   └── security.py         # JWT + bcrypt
│   ├── middleware/             # Request logging
│   ├── models/                 # SQLAlchemy ORM models
│   ├── schemas/                # Pydantic request/response schemas
│   ├── repositories/           # Repository pattern (data access)
│   ├── services/               # Business logic layer
│   └── routes/                 # API route handlers
│
├── databases/                  # DB connection managers
│   ├── postgres.py             # SQLAlchemy async engine
│   ├── redis.py                # Redis async client
│   └── migrations/             # Alembic migrations
│
├── graph_db/
│   └── neo4j.py                # Neo4j async driver
│
├── vector_db/
│   └── qdrant_client.py        # Qdrant async client
│
├── frontend/                   # React + Vite + Tailwind
│   └── src/
│       ├── pages/              # Route-level components
│       ├── components/         # Reusable UI components
│       ├── context/            # React context (auth)
│       └── api/                # Axios client
│
├── agents/                     # Phase 2 — AI agents (empty)
├── orchestrator/               # Phase 2 — LangGraph (empty)
├── rag/                        # Phase 2 — RAG pipeline (empty)
├── graph_rag/                  # Phase 2 — GraphRAG (empty)
├── mcp/                        # Phase 2 — MCP servers (empty)
├── llm/                        # Phase 2 — LLM chains (empty)
│
├── docker/                     # Dockerfiles
├── kubernetes/                 # K8s manifests (Phase 4)
├── monitoring/                 # Prometheus + Grafana (Phase 3)
├── docs/                       # Documentation
├── tests/                      # Unit / integration / e2e
└── scripts/                    # Utility scripts
```

---

## 🚀 Quick Start

### Prerequisites

- Docker Desktop 4.x+
- Docker Compose v2+
- Node.js 20+ (for local frontend dev)
- Python 3.11+ (for local backend dev)

---

### Option A — Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/sentinelx-ai.git
cd sentinelx-ai

# 2. Copy environment file
cp .env.example .env

# 3. Start all services
docker compose up --build

# 4. Open the dashboard
open http://localhost:5173
```

All six services start automatically:

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Swagger Docs | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |
| Neo4j Browser | http://localhost:7474 |
| Qdrant Console | http://localhost:6333/dashboard |

---

### Option B — Local Development

#### Backend

```bash
# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start infrastructure only
docker compose up postgres redis neo4j qdrant -d

# Run backend
cd backend
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

---

## 🔐 Default Credentials

| Account | Email | Password |
|---|---|---|
| Admin | `admin@sentinelx.ai` | `SentinelX@2025!` |

> ⚠️ Change the admin password before any production deployment.

---

## 📡 API Reference

### Public Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | API root info |
| `GET` | `/health` | Platform health check (all DBs) |
| `POST` | `/api/v1/auth/register` | Register new user |
| `POST` | `/api/v1/auth/login` | Login → JWT tokens |

### Protected Endpoints (Bearer token required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/auth/me` | Current user profile |
| `GET` | `/api/v1/dashboard` | System dashboard |

Full interactive documentation: **http://localhost:8000/docs**

---

## 🐳 Docker Details

```bash
# Start everything
docker compose up --build

# Start in background
docker compose up --build -d

# View logs
docker compose logs -f backend
docker compose logs -f frontend

# Stop everything
docker compose down

# Stop and remove volumes (DESTROYS DATA)
docker compose down -v

# Rebuild a single service
docker compose up --build backend
```

---

## 🧪 Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html
open htmlcov/index.html
```

---

## 🗺️ Roadmap

| Phase | Description | Status |
|---|---|---|
| **1** | Infrastructure Foundation | ✅ Complete |
| **2** | Multi-Agent AI System (LangGraph) | 🔜 Next |
| **3** | RAG + GraphRAG Pipelines | 🔜 Planned |
| **4** | MCP Servers | 🔜 Planned |
| **5** | Kubernetes Deployment | 🔜 Planned |
| **6** | Production Hardening | 🔜 Planned |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  <strong>SentinelX AI</strong> — Built for enterprise security teams
</div>
