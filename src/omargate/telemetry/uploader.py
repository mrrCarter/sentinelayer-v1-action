from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Optional

import httpx

from ..logging import OmarLogger

PLEXAURA_API_URL = "https://api.sentinellayer.com"
UPLOAD_TIMEOUT_SECONDS = 10
MAX_RETRIES = 2
BACKOFF_SECONDS = 1


async def upload_telemetry(
    payload: dict,
    plexaura_token: Optional[str] = None,
    oidc_token: Optional[str] = None,
    logger: Optional[OmarLogger] = None,
) -> bool:
    """
    Upload telemetry to PlexAura API.

    Best-effort: failures are logged but don't affect gate.

    Auth priority:
    1. OIDC token (from GitHub Actions OIDC)
    2. PlexAura API token
    3. Anonymous (Tier 1 only)
    """
    headers = {"Content-Type": "application/json"}

    if oidc_token:
        headers["Authorization"] = f"Bearer {oidc_token}"
    elif plexaura_token:
        headers["Authorization"] = f"Bearer {plexaura_token}"

    tier = payload.get("tier", 1)
    endpoint = f"{PLEXAURA_API_URL}/api/v1/telemetry"

    for attempt in range(MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=UPLOAD_TIMEOUT_SECONDS) as client:
                response = await client.post(endpoint, json=payload, headers=headers)

            if response.status_code == 200:
                if logger:
                    logger.info(
                        "Telemetry uploaded",
                        tier=tier,
                        status=response.status_code,
                    )
                return True

            if response.status_code == 429:
                if logger:
                    logger.warning("Telemetry rate limited", tier=tier)
                return False

            if logger:
                logger.warning(
                    "Telemetry upload failed",
                    tier=tier,
                    status=response.status_code,
                    attempt=attempt + 1,
                )
        except httpx.TimeoutException:
            if logger:
                logger.warning(
                    "Telemetry upload timeout",
                    tier=tier,
                    attempt=attempt + 1,
                )
        except Exception as exc:
            if logger:
                logger.warning("Telemetry upload error", tier=tier, error=str(exc))

        if attempt < MAX_RETRIES - 1:
            await asyncio.sleep(BACKOFF_SECONDS * (attempt + 1))

    return False


async def upload_artifacts(
    run_dir: Path,
    manifest: dict,
    plexaura_token: str,
    logger: Optional[OmarLogger] = None,
) -> bool:
    """
    Upload Tier 3 artifacts to PlexAura S3.

    Uses presigned URLs from API.
    """
    if not plexaura_token:
        if logger:
            logger.warning("Artifact upload requires plexaura_token")
        return False


async def fetch_oidc_token(logger: Optional[OmarLogger] = None) -> Optional[str]:
    """Fetch GitHub Actions OIDC token if available."""
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        return None

    audience = os.environ.get("SENTINELLAYER_OIDC_AUDIENCE")
    if audience:
        separator = "&" if "?" in request_url else "?"
        request_url = f"{request_url}{separator}audience={audience}"

    try:
        async with httpx.AsyncClient(timeout=UPLOAD_TIMEOUT_SECONDS) as client:
            response = await client.get(
                request_url,
                headers={
                    "Authorization": f"Bearer {request_token}",
                    "Accept": "application/json",
                },
            )
        if response.status_code != 200:
            if logger:
                logger.warning("OIDC token request failed", status=response.status_code)
            return None
        payload = response.json()
        token = payload.get("value") or payload.get("id_token")
        if not token and logger:
            logger.warning("OIDC token response missing value")
        return token
    except Exception as exc:
        if logger:
            logger.warning("OIDC token request error", error=str(exc))
        return None

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{PLEXAURA_API_URL}/api/v1/artifacts/upload-urls",
                json={
                    "run_id": manifest.get("run_id"),
                    "objects": [obj.get("name") for obj in manifest.get("objects", [])],
                },
                headers={"Authorization": f"Bearer {plexaura_token}"},
            )

            if response.status_code != 200:
                if logger:
                    logger.warning(
                        "Failed to get upload URLs",
                        status=response.status_code,
                    )
                return False

            urls = response.json().get("urls", {})

        for obj in manifest.get("objects", []):
            name = obj.get("name")
            if not name:
                continue
            file_path = run_dir / name

            if not file_path.exists():
                continue

            upload_url = urls.get(name)
            if not upload_url:
                continue

            async with httpx.AsyncClient(timeout=60) as client:
                with open(file_path, "rb") as f:
                    await client.put(
                        upload_url,
                        content=f.read(),
                        headers={
                            "Content-Type": obj.get(
                                "content_type", "application/octet-stream"
                            )
                        },
                    )

        if logger:
            logger.info("Artifacts uploaded", count=len(manifest.get("objects", [])))

        return True
    except Exception as exc:
        if logger:
            logger.warning("Artifact upload error", error=str(exc))
        return False
