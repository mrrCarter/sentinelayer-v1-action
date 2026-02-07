from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.post("/artifacts/upload-urls")
async def get_upload_urls(request: Request):
    request_id = request.state.request_id
    raise HTTPException(
        status_code=501,
        detail={
            "error": {
                "code": "NOT_IMPLEMENTED",
                "message": "Artifact uploads not implemented yet",
                "request_id": request_id,
            }
        },
    )
