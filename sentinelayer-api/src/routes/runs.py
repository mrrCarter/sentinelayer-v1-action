from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.get("/runs")
async def list_runs(request: Request):
    request_id = request.state.request_id
    raise HTTPException(
        status_code=501,
        detail={
            "error": {
                "code": "NOT_IMPLEMENTED",
                "message": "Runs endpoint not implemented yet",
                "request_id": request_id,
            }
        },
    )
