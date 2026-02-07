from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.delete("/runs/{run_id}")
async def delete_run(run_id: str, request: Request):
    request_id = request.state.request_id
    raise HTTPException(
        status_code=501,
        detail={
            "error": {
                "code": "NOT_IMPLEMENTED",
                "message": "Deletion endpoint not implemented yet",
                "request_id": request_id,
            }
        },
    )
