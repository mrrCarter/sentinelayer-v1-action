from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

SENTINELAYER_API = "https://api.sentinelayer.com"
MAX_CONTEXT_BYTES = 1_048_576


def _fetch_spec_context_sync(spec_hash: str, token: str) -> Optional[dict]:
    request = Request(
        f"{SENTINELAYER_API}/api/v1/specs/context/{spec_hash}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed HTTPS origin
            body = response.read(MAX_CONTEXT_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            logger.info("Spec context not found for hash %s", spec_hash[:12])
        else:
            logger.warning("Spec context fetch failed: %d", exc.code)
        return None
    except (OSError, TimeoutError, URLError):
        logger.warning("Spec context fetch error", exc_info=True)
        return None

    if len(body) > MAX_CONTEXT_BYTES:
        logger.warning("Spec context response exceeded byte limit")
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Spec context response was not valid JSON")
        return None
    return payload if isinstance(payload, dict) else None


async def fetch_spec_context(
    spec_hash: str,
    sentinelayer_token: str = "",
    oidc_token: str = "",
) -> Optional[dict]:
    """Fetch bounded spec context without blocking the event loop."""
    normalized_hash = str(spec_hash or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized_hash):
        return None

    token = str(sentinelayer_token or oidc_token or "").strip()
    if not token:
        logger.info("No auth token for spec context fetch; skipping")
        return None

    return await asyncio.to_thread(_fetch_spec_context_sync, normalized_hash, token)
