from pydantic import BaseModel
from typing import Optional, Any


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
