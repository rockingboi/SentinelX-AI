"""
SentinelX AI — pytest configuration
======================================
Root conftest.py — sets environment variables before any module import.
"""
import os
import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

# Required env vars before any backend module loads
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("JWT_SECRET",   "test-secret-sentinelx-pytest-2025")
os.environ.setdefault("APP_ENV",      "development")
