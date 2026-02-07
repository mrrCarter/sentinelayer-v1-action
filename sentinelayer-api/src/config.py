from functools import lru_cache
import os
import logging
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env.local", env_file_encoding="utf-8")

    # Database
    database_url: str = "postgresql+asyncpg://user:pass@localhost/sentinelayer"
    timescale_url: str = "postgresql+asyncpg://user:pass@localhost/sentinelayer_ts"
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_timeout_seconds: int = 30

    # Redis
    redis_url: str = "redis://localhost:6379"

    # S3
    s3_bucket: str = "sentinelayer-artifacts"
    s3_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""

    # Auth
    github_client_id: str = ""
    github_client_secret: str = ""
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"

    # OIDC
    github_oidc_issuer: str = "https://token.actions.githubusercontent.com"

    # Rate limits
    telemetry_rate_limit: int = 100
    api_rate_limit: int = 1000

    @field_validator("jwt_secret")
    @classmethod
    def _validate_jwt_secret(cls, v: str) -> str:
        # In AWS (ECS/Fargate), running without JWT_SECRET is a misconfiguration we should catch early.
        running_in_aws = bool(
            os.getenv("AWS_EXECUTION_ENV") or os.getenv("ECS_CONTAINER_METADATA_URI_V4")
        )

        if not v:
            if running_in_aws:
                raise ValueError("JWT_SECRET must be set in AWS environments")

            # Local/dev: allow empty but warn. Auth endpoints will fail with 500.
            logger.warning("JWT_SECRET is empty; auth endpoints will fail")

        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
