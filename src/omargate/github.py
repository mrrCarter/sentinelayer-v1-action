from __future__ import annotations

import os
from typing import Any, Dict, Optional, List

import httpx
import requests

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

    def list_check_runs(self, head_sha: str, check_name: Optional[str] = None) -> List[Dict[str, Any]]:
        url = f"{GITHUB_API}/repos/{self.repo}/commits/{head_sha}/check-runs"
        params: Dict[str, Any] = {"per_page": 100}
        if check_name:
            params["check_name"] = check_name
        r = self.session.get(url, params=params)
        r.raise_for_status()
        return r.json().get("check_runs", [])

    def find_check_run_by_external_id(self, head_sha: str, external_id: str, check_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        for run in self.list_check_runs(head_sha, check_name):
            if run.get("external_id") == external_id:
                return run
        return None

    def get_pull_request(self, pr_number: int) -> Dict[str, Any]:
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}"
        r = self.session.get(url)
        r.raise_for_status()
        return r.json()

    def list_issue_labels(self, pr_number: int) -> List[str]:
        url = f"{GITHUB_API}/repos/{self.repo}/issues/{pr_number}/labels"
        r = self.session.get(url, params={"per_page": 100})
        r.raise_for_status()
        return [label.get("name", "") for label in r.json()]

    def has_label(self, pr_number: int, label: str) -> bool:
        return label in self.list_issue_labels(pr_number)

    def get_branch_protection(self, branch: str) -> Optional[Dict[str, Any]]:
        url = f"{GITHUB_API}/repos/{self.repo}/branches/{branch}/protection"
        r = self.session.get(url)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    async def get_pr_diff(self, pr_number: int) -> str:
        """Get PR diff content."""
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3.diff",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omar-gate-action",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.text
        return ""

    async def get_pr_changed_files(self, pr_number: int) -> List[str]:
        """Get list of changed file paths in PR."""
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}/files"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "omar-gate-action",
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                files = resp.json()
                return [f.get("filename", "") for f in files if f.get("filename")]
        return []


def load_context() -> GitHubContext:
    """Load GitHub Actions context from environment."""
    return GitHubContext.from_environment()
