"""Configuration management for CyberShield AI."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # AI providers
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ai_provider: str = "openai"
    ai_model: str = "gpt-4o"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # External tool paths
    gitleaks_path: str = "gitleaks"
    trufflehog_path: str = "trufflehog"
    bearer_path: str = "bearer"

    # API URLs
    osv_api_url: str = "https://api.osv.dev/v1"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Application settings
    max_scan_size_mb: int = 50
    report_output_dir: str = "./reports"
    log_level: str = "INFO"
    cors_origins: list[str] = ["http://localhost:3004", "http://localhost:5173"]

    # Security
    secret_key: str = "changeme-in-production-use-strong-random-key"
    api_rate_limit: int = 100


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
