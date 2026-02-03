from __future__ import annotations

import os
import requests
from typing import Any, Dict, Optional

from .context import GitHubContext

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")

class GitHubClient:
    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omar-gate-action",
        })

    def create_or_update_pr_comment(self, pr_number: int, body: str, marker: str) -> None:
        # Idempotent update: search recent comments for marker; update if found else create.
        url = f"{GITHUB_API}/repos/{self.repo}/issues/{pr_number}/comments"
        r = self.session.get(url, params={"per_page": 100})
        r.raise_for_status()
        comments = r.json()
        for c in comments:
            if marker in (c.get("body") or ""):
                patch_url = f"{GITHUB_API}/repos/{self.repo}/issues/comments/{c['id']}"
                pr = self.session.patch(patch_url, json={"body": body})
                pr.raise_for_status()
                return
        cr = self.session.post(url, json={"body": body})
        cr.raise_for_status()

    def create_check_run(self, name: str, head_sha: str, conclusion: str, summary: str, details_url: Optional[str]=None, external_id: Optional[str]=None) -> None:
        url = f"{GITHUB_API}/repos/{self.repo}/check-runs"
        payload: Dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": name, "summary": summary},
        }
        if details_url:
            payload["details_url"] = details_url
        if external_id:
            payload["external_id"] = external_id
        r = self.session.post(url, json=payload)
        r.raise_for_status()


def load_context() -> GitHubContext:
    """Load GitHub Actions context from environment."""
    return GitHubContext.from_environment()
