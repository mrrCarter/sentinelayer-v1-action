import httpx
import time
import asyncio
from jose import jwt, JWTError
from dataclasses import dataclass
from typing import Optional, Dict, Any

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_OIDC_JWKS_URL = f"{GITHUB_OIDC_ISSUER}/.well-known/jwks.json"

_JWKS_CACHE: Optional[Dict[str, Any]] = None
_JWKS_CACHE_EXPIRES_AT = 0.0
_JWKS_CACHE_TTL_SECONDS = 3600
_JWKS_LOCK = asyncio.Lock()


@dataclass
class OIDCClaims:
    repository: str
    repository_owner: str
    actor: str
    workflow: str
    run_id: str
    ref: str


async def get_jwks() -> Dict[str, Any]:
    """Fetch and cache GitHub OIDC JWKS."""
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRES_AT

    now = time.time()
    if _JWKS_CACHE and now < _JWKS_CACHE_EXPIRES_AT:
        return _JWKS_CACHE

    async with _JWKS_LOCK:
        now = time.time()
        if _JWKS_CACHE and now < _JWKS_CACHE_EXPIRES_AT:
            return _JWKS_CACHE

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(GITHUB_OIDC_JWKS_URL)
            response.raise_for_status()
            _JWKS_CACHE = response.json()
            _JWKS_CACHE_EXPIRES_AT = time.time() + _JWKS_CACHE_TTL_SECONDS
            return _JWKS_CACHE


async def verify_oidc_token(token: str) -> Optional[OIDCClaims]:
    """
    Verify GitHub Actions OIDC token.

    Returns claims if valid, None if invalid.
    """
    try:
        jwks = await get_jwks()

        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            issuer=GITHUB_OIDC_ISSUER,
            options={"verify_aud": False},
        )

        return OIDCClaims(
            repository=payload.get("repository", ""),
            repository_owner=payload.get("repository_owner", ""),
            actor=payload.get("actor", ""),
            workflow=payload.get("workflow", ""),
            run_id=payload.get("run_id", ""),
            ref=payload.get("ref", ""),
        )
    except (JWTError, httpx.HTTPError, ValueError, KeyError):
        return None
