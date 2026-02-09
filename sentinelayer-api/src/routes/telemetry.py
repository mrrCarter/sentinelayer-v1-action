from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Optional

from ..schemas.telemetry import TelemetryPayload, TelemetryResponse
from ..services.telemetry_service import TelemetryService
from ..auth.oidc_verifier import verify_oidc_token, OIDCClaims
from ..middleware.rate_limit import RateLimiter, get_rate_limiter
from ..db.connection import get_timescale_db
from ..config import get_settings
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


def get_telemetry_service(db: AsyncSession = Depends(get_timescale_db)) -> TelemetryService:
    return TelemetryService(db)


@router.post("/telemetry", response_model=TelemetryResponse)
async def ingest_telemetry(
    request: Request,
    payload: TelemetryPayload,
    telemetry_service: TelemetryService = Depends(get_telemetry_service),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
):
    """
    Ingest telemetry from Omar Gate Action.

    Auth:
    - Tier 1: Anonymous (no auth required)
    - Tier 2+: OIDC token or Sentinelayer API token required

    Idempotency:
    - Uses run_id as idempotency key
    - Duplicate submissions are ignored (200 OK, not error)
    """
    request_id = request.state.request_id

    settings = get_settings()

    # Rate limit by IP for anonymous, by user for authenticated
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"telemetry:{client_ip}"

    if not await rate_limiter.check(
        rate_key, limit=settings.telemetry_rate_limit, window_seconds=3600
    ):
        raise HTTPException(
            status_code=429,
            detail={
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many telemetry submissions. Retry later.",
                    "details": {
                        "limit": settings.telemetry_rate_limit,
                        "window_seconds": 3600,
                    },
                    "request_id": request_id,
                }
            },
        )

    # Validate tier vs auth
    tier = payload.tier
    auth_header = request.headers.get("Authorization")

    if tier >= 2 and not auth_header:
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "AUTH_REQUIRED",
                    "message": f"Tier {tier} telemetry requires authentication",
                    "request_id": request_id,
                }
            },
        )

    if tier >= 2 and auth_header and not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "AUTH_INVALID",
                    "message": "Authorization header must be a Bearer token",
                    "request_id": request_id,
                }
            },
        )

    # Verify OIDC token for Tier 2+
    claims: Optional[OIDCClaims] = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        claims = await verify_oidc_token(token)
        if claims is None and tier >= 2:
            # Only reject invalid tokens for Tier 2+.
            # Tier 1 is anonymous — a bad token shouldn't block it.
            raise HTTPException(
                status_code=401,
                detail={
                    "error": {
                        "code": "INVALID_OIDC_TOKEN",
                        "message": "Invalid or expired OIDC token",
                        "request_id": request_id,
                    }
                },
            )

    # Ingest
    result = await telemetry_service.ingest(
        payload=payload,
        claims=claims,
        request_id=request_id,
    )

    return TelemetryResponse(
        status="accepted",
        run_id=payload.run.run_id,
        tier=tier,
        request_id=request_id,
        duplicate=result.duplicate,
    )
