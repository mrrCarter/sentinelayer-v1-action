from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from jose import jwt, JWTError
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..config import get_settings

router = APIRouter()


class OAuthCallbackRequest(BaseModel):
    code: str


class UserResponse(BaseModel):
    id: str
    github_username: str
    avatar_url: str
    email: str


class AuthResponse(BaseModel):
    token: str
    user: UserResponse


@router.post("/auth/github/callback", response_model=AuthResponse)
async def github_callback(request: Request, body: OAuthCallbackRequest):
    """Exchange GitHub OAuth code for access token and return JWT."""
    request_id = getattr(request.state, "request_id", "unknown")
    settings = get_settings()

    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "CONFIG_ERROR",
                    "message": "GitHub OAuth not configured",
                    "request_id": request_id,
                }
            },
        )

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": body.code,
            },
            headers={"Accept": "application/json"},
        )

    if token_response.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "OAUTH_FAILED",
                    "message": "Failed to exchange code for token",
                    "request_id": request_id,
                }
            },
        )

    token_data = token_response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        error = token_data.get("error_description", "No access token received")
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "OAUTH_FAILED",
                    "message": error,
                    "request_id": request_id,
                }
            },
        )

    # Fetch user info from GitHub
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )

    if user_response.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "GITHUB_API_ERROR",
                    "message": "Failed to fetch user info",
                    "request_id": request_id,
                }
            },
        )

    github_user = user_response.json()

    # Fetch user email if not public
    email = github_user.get("email")
    if not email:
        async with httpx.AsyncClient() as client:
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
        if emails_response.status_code == 200:
            emails = emails_response.json()
            primary = next((e for e in emails if e.get("primary")), None)
            if primary:
                email = primary.get("email")

    # Create user object
    user = UserResponse(
        id=str(github_user["id"]),
        github_username=github_user["login"],
        avatar_url=github_user.get("avatar_url", ""),
        email=email or "",
    )

    # Generate JWT token
    now = datetime.now(timezone.utc)
    jwt_payload = {
        "sub": user.id,
        "username": user.github_username,
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=7)).timestamp()),
    }

    if not settings.jwt_secret:
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "CONFIG_ERROR",
                    "message": "JWT secret not configured",
                    "request_id": request_id,
                }
            },
        )

    token = jwt.encode(
        jwt_payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    return AuthResponse(token=token, user=user)


@router.get("/auth/me", response_model=UserResponse)
async def get_current_user(request: Request):
    """Get current user from JWT token."""
    request_id = getattr(request.state, "request_id", "unknown")
    settings = get_settings()

    if not settings.jwt_secret:
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "CONFIG_ERROR",
                    "message": "JWT secret not configured",
                    "request_id": request_id,
                }
            },
        )

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "AUTH_REQUIRED",
                    "message": "Authorization header required",
                    "request_id": request_id,
                }
            },
        )

    token = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as e:
        error_message = str(e)
        if "expired" in error_message.lower():
            raise HTTPException(
                status_code=401,
                detail={
                    "error": {
                        "code": "TOKEN_EXPIRED",
                        "message": "Token has expired",
                        "request_id": request_id,
                    }
                },
            )
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "INVALID_TOKEN",
                    "message": "Invalid token",
                    "request_id": request_id,
                }
            },
        )

    return UserResponse(
        id=payload.get("sub", ""),
        github_username=payload.get("username", ""),
        avatar_url="",  # Not stored in JWT, would need to fetch from GitHub
        email=payload.get("email", ""),
    )
