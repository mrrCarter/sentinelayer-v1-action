from pydantic import BaseModel
from typing import List


class PublicStats(BaseModel):
    total_runs: int
    total_findings: int
    total_p0_blocked: int
    repos_protected: int
    avg_duration_ms: int
    top_categories: List
