from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class RunInfo(BaseModel):
    run_id: str
    timestamp_utc: datetime
    duration_ms: int
    state: Optional[str] = None


class RepoInfoTier1(BaseModel):
    repo_hash: str


class RepoInfoTier2(BaseModel):
    owner: str
    name: str
    branch: Optional[str] = None
    pr_number: Optional[int] = None
    head_sha: Optional[str] = None
    is_fork_pr: bool = False


class ScanInfo(BaseModel):
    mode: Optional[str] = None
    model_used: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_estimate_usd: float = 0.0


class FindingsSummary(BaseModel):
    P0: int = 0
    P1: int = 0
    P2: int = 0
    P3: int = 0
    total: int = 0


class GateInfo(BaseModel):
    result: Optional[str] = None
    dedupe_skipped: bool = False
    rate_limit_skipped: bool = False


class TelemetryPayload(BaseModel):
    schema_version: str = "1.0"
    tier: int = Field(ge=1, le=3)
    run: RunInfo
    repo: Dict[str, Any]
    scan: Optional[ScanInfo] = None
    findings: Optional[Dict[str, Any]] = None
    gate: Optional[GateInfo] = None
    stages: Optional[Dict[str, int]] = None
    meta: Optional[Dict[str, Any]] = None


class TelemetryResponse(BaseModel):
    status: str
    run_id: str
    tier: int
    request_id: str
    duplicate: bool = False
