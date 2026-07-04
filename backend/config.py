"""
SentinelX AI — Application Configuration
=========================================
Reads all environment variables via Pydantic BaseSettings.
Single source of truth for all config values.
"""
from __future__ import annotations

from functools import lru_cache
from typing import ClassVar

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables / .env file.
    All fields are typed and validated at startup.
    """

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "SentinelX AI"
    APP_ENV: str = "development"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # -------------------------------------------------------------------------
    # API
    # -------------------------------------------------------------------------
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    BACKEND_RELOAD: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    # -------------------------------------------------------------------------
    # PostgreSQL
    # -------------------------------------------------------------------------
    DATABASE_URL: str = (
        "postgresql+asyncpg://sentinelx_user:sentinelx_secret@localhost:5432/sentinelx"
    )
    DATABASE_URL_SYNC: str = (
        "postgresql://sentinelx_user:sentinelx_secret@localhost:5432/sentinelx"
    )

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"

    # -------------------------------------------------------------------------
    # Neo4j
    # -------------------------------------------------------------------------
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "sentinelx_neo4j"
    NEO4J_DATABASE: str = "neo4j"

    # -------------------------------------------------------------------------
    # Qdrant
    # -------------------------------------------------------------------------
    QDRANT_URL: str = "http://localhost:6333"
    QDRANT_API_KEY: str = ""

    # -------------------------------------------------------------------------
    # JWT Authentication
    # -------------------------------------------------------------------------
    JWT_SECRET: str = "CHANGE_ME_IN_PRODUCTION"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------
    BCRYPT_ROUNDS: int = 12

    # -------------------------------------------------------------------------
    # Admin Seed
    # -------------------------------------------------------------------------
    ADMIN_EMAIL: str = "admin@sentinelx.ai"
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "SentinelX@2025!"

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------
    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    Use FastAPI's Depends(get_settings) for dependency injection.
    """
    return Settings()


# Module-level singleton for use outside FastAPI dependency injection
settings: Settings = get_settings()
