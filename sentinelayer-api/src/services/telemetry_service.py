from dataclasses import dataclass
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..schemas.telemetry import TelemetryPayload
from ..models.telemetry import TelemetryRecord
from ..auth.oidc_verifier import OIDCClaims


@dataclass
class IngestResult:
    success: bool
    duplicate: bool
    record_id: Optional[int] = None


class TelemetryService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def ingest(
        self,
        payload: TelemetryPayload,
        claims: Optional[OIDCClaims],
        request_id: str,
    ) -> IngestResult:
        """
        Ingest telemetry record.

        Idempotent: duplicate run_ids are ignored.
        """
        run_id = payload.run.run_id

        existing = await self.db.execute(
            select(TelemetryRecord).where(TelemetryRecord.run_id == run_id)
        )
        if existing.scalar_one_or_none():
            return IngestResult(success=True, duplicate=True)

        record = TelemetryRecord(
            run_id=run_id,
            tier=payload.tier,
            timestamp_utc=payload.run.timestamp_utc,
            duration_ms=payload.run.duration_ms,
            gate_status=payload.run.state,
            repo_hash=payload.repo.get("repo_hash"),
            repo_owner=payload.repo.get("owner") if payload.tier >= 2 else None,
            repo_name=payload.repo.get("name") if payload.tier >= 2 else None,
            branch=payload.repo.get("branch") if payload.tier >= 2 else None,
            pr_number=payload.repo.get("pr_number") if payload.tier >= 2 else None,
            head_sha=payload.repo.get("head_sha") if payload.tier >= 2 else None,
            model_used=payload.scan.model_used if payload.scan else None,
            tokens_in=payload.scan.tokens_in if payload.scan else 0,
            tokens_out=payload.scan.tokens_out if payload.scan else 0,
            cost_usd=payload.scan.cost_estimate_usd if payload.scan else 0,
            p0_count=payload.findings.get("P0", 0) if payload.findings else 0,
            p1_count=payload.findings.get("P1", 0) if payload.findings else 0,
            p2_count=payload.findings.get("P2", 0) if payload.findings else 0,
            p3_count=payload.findings.get("P3", 0) if payload.findings else 0,
            findings_summary=payload.findings or None,
            oidc_repo=claims.repository if claims else None,
            oidc_actor=claims.actor if claims else None,
            request_id=request_id,
        )

        self.db.add(record)
        await self.db.commit()
        await self.db.refresh(record)

        return IngestResult(success=True, duplicate=False, record_id=record.id)
