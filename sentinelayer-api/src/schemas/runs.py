from pydantic import BaseModel


class RunSummary(BaseModel):
    run_id: str
    status: str
