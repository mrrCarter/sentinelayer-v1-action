from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Any, Dict


def _error_payload(code: str, message: str, request_id: str, details: Any = None) -> Dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "request_id": request_id,
        }
    }


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTPException and format as standard error envelope."""
    request_id = getattr(request.state, "request_id", "unknown")
    detail = exc.detail
    if isinstance(detail, dict) and "error" in detail:
        error = detail["error"]
        if error.get("request_id") in (None, "", "unknown"):
            error["request_id"] = request_id
        return JSONResponse(status_code=exc.status_code, content={"error": error})
    if isinstance(detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload("HTTP_ERROR", "Request failed", request_id, detail),
        )
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload("HTTP_ERROR", str(detail), request_id),
    )
