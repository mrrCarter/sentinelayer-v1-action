from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env.local", env_file_encoding="utf-8")

    # Database
    database_url: str = "postgresql+asyncpg://user:pass@localhost/sentinelayer"
    timescale_url: str = "postgresql+asyncpg://user:pass@localhost/sentinelayer_ts"

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
