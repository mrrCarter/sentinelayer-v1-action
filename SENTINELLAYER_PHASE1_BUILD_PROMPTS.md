# SentinelLayer Phase 1: Staged Build Prompts
## Master Orchestration Document for AI Agent Implementation

**Version:** 1.0  
**Date:** 2026-02-03  
**Status:** READY TO EXECUTE  
**Classification:** BUILD ORCHESTRATION  

---

## DOCUMENT PURPOSE

This document provides staged prompts for AI coding agents to complete SentinelLayer Phase 1 (Core Action Infrastructure). Each stage:

- Has a dedicated prompt following proven format
- Produces testable, committable artifacts
- Has clear acceptance criteria
- Builds on previous stages

**CRITICAL:** Execute stages in order. Test before proceeding. Commit after each stage passes.

---

## SCAFFOLD STATUS (What GPT Already Built)

GPT provided `omar-gate-action-scaffold_v1_2_1.zip` containing:

| File | Status | What's Done | What's Stubbed/Missing |
|------|--------|-------------|----------------------|
| `action.yml` | ✅ Complete | All 25+ inputs, outputs, branding | — |
| `Dockerfile` | ⚠️ Minimal | Python 3.11 base | Node.js, dependencies, proper layers |
| `entrypoint.sh` | ⚠️ Minimal | Basic exec | Error handling, env setup |
| `src/omargate/main.py` | ⚠️ Skeleton | Orchestration flow | Preflight, ingest, scans, telemetry |
| `src/omargate/gate.py` | ✅ Complete | Fail-closed logic, hash verification | — |
| `src/omargate/packaging.py` | ✅ Complete | PACK_SUMMARY + FINDINGS writer | — |
| `src/omargate/idempotency.py` | ✅ Complete | Dedupe key (full 64-char) | — |
| `src/omargate/comment.py` | ⚠️ Basic | Template + marker | Full finding rendering |
| `src/omargate/github.py` | ⚠️ Basic | Check run + comment | Dedupe lookup, rate limit check |
| `src/omargate/models.py` | ⚠️ Basic | GateResult, Counts | Full config model |
| `src/omargate/utils.py` | ✅ Complete | sha256_file | — |

**Build Strategy:** Enhance scaffold rather than rebuild from scratch.

---

## COMMIT ORCHESTRATION RULES

### Commit Frequency
- **One commit per stage** (not per file)
- **Commit message format:** `feat(phase1.X): [stage description]`
- **Push after review + test passes**

### Commit Sequence
```
feat(phase1.1): container foundation - Dockerfile, entrypoint, deps
feat(phase1.2): configuration system - Pydantic models, env parsing
feat(phase1.3): logging and errors - structured logging, exceptions
feat(phase1.4): github context - event parsing, fork detection
feat(phase1.5): preflight system - dedupe check, rate limits
feat(phase1.6): tests - unit tests for all Phase 1 modules
```

### Push Checkpoints
Push after:
- Stage 1.4 (minimal working container that parses context)
- Stage 1.6 (all tests passing)

---

## TESTING STRATEGY

### Local Testing (Before Push)
```bash
# Build container
docker build -t omar-gate:dev .

# Run unit tests inside container
docker run --rm omar-gate:dev pytest tests/unit/ -v

# Test with act (local GitHub Actions)
act pull_request -W .github/workflows/test.yml \
  --secret OPENAI_API_KEY=sk_test_dummy
```

### Test Fixtures
Create `tests/fixtures/` with:
- `event_pr.json` — sample pull_request event
- `event_push.json` — sample push event
- `event_fork_pr.json` — sample fork PR event

---

# STAGE 1.1: CONTAINER FOUNDATION

## Prompt

```markdown
# SentinelLayer Build Stage 1.1: Container Foundation

## 0) PERSONA + EXPERTISE CONTEXT

You are a senior DevOps engineer with 15+ years experience building production Docker containers for CI/CD systems. You have deep expertise in:
- Multi-stage Docker builds for minimal image size
- GitHub Actions container actions
- Python + Node.js runtime environments
- Security hardening for CI containers

## 1) REFERENCE CONTEXT

You are enhancing the existing scaffold at `/scaffold/` (already extracted).

Key files to modify:
- `Dockerfile` — currently minimal, needs full production setup
- `entrypoint.sh` — needs error handling and env setup
- `requirements.txt` — needs to be created

Reference documents (already in context):
- Implementation Requirements v1.2.1 (Section 1.3 Technology Stack)
- action.yml (already complete — do not modify)

## 2) CONSTRAINT CONTEXT (NON-NEGOTIABLE)

- Base image: `python:3.11-alpine` (small, secure)
- Must include: Python 3.11, Node.js 20, pnpm
- Container size: < 500MB final
- Build time: < 3 minutes
- No `apt-get` (Alpine uses `apk`)
- Multi-stage build to minimize final image
- Never run as root in final stage
- All Python deps pinned with versions

## 3) AUDIENCE CONTEXT

Primary: GitHub Actions runner executing this container
Secondary: Developers debugging container issues

Success criteria:
- `docker build` completes without errors
- `docker run --rm omar-gate:dev python -c "import openai; print('ok')"` works
- `docker run --rm omar-gate:dev node --version` returns v20.x
- Final image size < 500MB

## 4) CHAIN-OF-THOUGHT CONTEXT

Think through:
1. What system packages does Alpine need for Python/Node?
2. What's the optimal layer order for caching?
3. How do we minimize final image with multi-stage?
4. What user should the container run as?
5. What environment variables need defaults?

## 5) OUTPUT FORMAT CONTEXT

Produce these files:
1. `Dockerfile` — complete multi-stage build
2. `entrypoint.sh` — with error handling
3. `requirements.txt` — pinned Python dependencies
4. `.dockerignore` — exclude unnecessary files

Format: Full file contents with clear section comments.

## 6) DELIVERABLES

### Dockerfile Requirements

```dockerfile
# Stage 1: Builder (install deps, compile if needed)
# Stage 2: Runtime (minimal, non-root)
```

Must install:
- Python packages: `openai>=1.0.0`, `pydantic>=2.0`, `httpx`, `pytest`
- Node.js 20 via apk
- pnpm via corepack

### entrypoint.sh Requirements

```bash
#!/bin/sh
set -e

# Validate required env vars
# Set up Python path
# Execute main with proper error handling
```

### requirements.txt

Pin all versions. Minimum packages:
- openai>=1.0.0
- pydantic>=2.0.0
- httpx>=0.25.0
- pytest>=7.0.0 (dev only, but include for now)

## 7) ACCEPTANCE CRITERIA

- [ ] `docker build -t omar-gate:dev .` completes < 3 min
- [ ] `docker images omar-gate:dev --format "{{.Size}}"` shows < 500MB
- [ ] `docker run --rm omar-gate:dev python --version` → Python 3.11.x
- [ ] `docker run --rm omar-gate:dev node --version` → v20.x.x
- [ ] `docker run --rm omar-gate:dev python -c "import openai, pydantic; print('deps ok')"`
- [ ] Container runs as non-root user
```

---

# STAGE 1.2: CONFIGURATION SYSTEM

## Prompt

```markdown
# SentinelLayer Build Stage 1.2: Configuration System

## 0) PERSONA + EXPERTISE CONTEXT

You are a senior Python engineer with 12+ years experience building configuration systems for distributed applications. You have deep expertise in:
- Pydantic v2 for validation and settings management
- Environment variable parsing for CI/CD contexts
- Type-safe configuration with sensible defaults
- GitHub Actions input/output conventions

## 1) REFERENCE CONTEXT

Existing files to enhance:
- `src/omargate/models.py` — currently has GateResult, Counts; needs full config
- `src/omargate/main.py` — currently parses env directly; should use config system

Reference:
- `action.yml` — defines all 25+ inputs (this is your schema source)
- Implementation Requirements v1.2.1 (Phase 1.2 Configuration System)

## 2) CONSTRAINT CONTEXT (NON-NEGOTIABLE)

- Use Pydantic v2 `BaseSettings` for environment parsing
- All fields must have type hints
- All fields must have defaults matching action.yml
- Sensitive values (API keys) must be masked in __repr__
- Config must be immutable after creation (frozen=True)
- Must handle GitHub Actions input format: `INPUT_FIELD_NAME`

## 3) AUDIENCE CONTEXT

Primary: main.py orchestrator loading config
Secondary: Developers debugging config issues

Success criteria:
- Config loads without error when env vars set correctly
- Config raises clear validation error on invalid input
- Config masks sensitive fields in logs
- Config matches action.yml 1:1

## 4) CHAIN-OF-THOUGHT CONTEXT

Think through:
1. How does GitHub Actions pass inputs to Docker containers?
2. What's the INPUT_ prefix convention?
3. Which fields are required vs optional?
4. What validation rules apply (e.g., severity_gate must be P0/P1/P2/none)?
5. How do we handle boolean strings ("true"/"false")?

## 5) OUTPUT FORMAT CONTEXT

Produce these files:
1. `src/omargate/config.py` — Pydantic settings class
2. `src/omargate/constants.py` — enums and constants
3. Update `src/omargate/models.py` — add any supporting types

Format: Full file contents with docstrings.

## 6) DELIVERABLES

### config.py Requirements

```python
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr
from typing import Literal

class OmarGateConfig(BaseSettings):
    """Configuration loaded from GitHub Actions inputs."""
    
    model_config = {"frozen": True, "env_prefix": "INPUT_"}
    
    # Required
    openai_api_key: SecretStr = Field(...)
    
    # Scan settings
    scan_mode: Literal["pr-diff", "deep", "nightly"] = "pr-diff"
    severity_gate: Literal["P0", "P1", "P2", "none"] = "P1"
    # ... all 25+ fields from action.yml
```

### constants.py Requirements

```python
from enum import Enum

class Severity(str, Enum):
    P0 = "P0"  # Critical
    P1 = "P1"  # High
    P2 = "P2"  # Medium
    P3 = "P3"  # Low

class ExitCode(int, Enum):
    SUCCESS = 0
    BLOCKED = 1
    ERROR = 2
    SKIPPED = 10

class Limits:
    MAX_FILE_SIZE = 1_000_000  # 1MB
    MAX_FILES = 1000
    # ... etc
```

## 7) ACCEPTANCE CRITERIA

- [ ] `OmarGateConfig()` loads from env with INPUT_ prefix
- [ ] All 25+ action.yml inputs have corresponding config fields
- [ ] `print(config)` masks openai_api_key
- [ ] Invalid severity_gate raises ValidationError
- [ ] Boolean inputs ("true"/"false") parse correctly
- [ ] Config is immutable (frozen)
```

---

# STAGE 1.3: LOGGING AND ERROR HANDLING

## Prompt

```markdown
# SentinelLayer Build Stage 1.3: Logging and Error Handling

## 0) PERSONA + EXPERTISE CONTEXT

You are a senior SRE with 10+ years experience building observable systems. You have deep expertise in:
- Structured logging (JSON format for machine parsing)
- Error handling hierarchies for complex workflows
- GitHub Actions annotation syntax (::error::, ::warning::)
- Correlation IDs and request tracing

## 1) REFERENCE CONTEXT

Create new files:
- `src/omargate/logging.py` — structured logger
- `src/omargate/errors.py` — exception hierarchy

Reference:
- Implementation Requirements v1.2.1 (Phase 1.3 Logging & Error Handling)
- GitHub Actions workflow commands documentation

## 2) CONSTRAINT CONTEXT (NON-NEGOTIABLE)

- All log entries must be valid JSON (one JSON object per line)
- Every log entry must include: timestamp, level, run_id, message
- Sensitive data (API keys, tokens) must NEVER be logged
- Errors must produce GitHub Actions annotations
- Stage timing must be tracked (start/end with duration_ms)
- Exit codes must map to specific error types

## 3) AUDIENCE CONTEXT

Primary: Developers debugging failed runs via GitHub Actions logs
Secondary: PlexAura telemetry ingestion (structured logs)

Success criteria:
- Logs are parseable by `jq`
- GitHub UI shows annotations on errors
- Timing data available for all stages
- No secrets in logs under any circumstance

## 4) CHAIN-OF-THOUGHT CONTEXT

Think through:
1. What's the GitHub Actions annotation format?
2. How do we ensure secrets are never logged?
3. What exception hierarchy makes sense for this system?
4. How do we track stage timing without cluttering the API?
5. What log levels do we need?

## 5) OUTPUT FORMAT CONTEXT

Produce these files:
1. `src/omargate/logging.py` — OmarLogger class
2. `src/omargate/errors.py` — exception hierarchy

Format: Full file contents with docstrings.

## 6) DELIVERABLES

### logging.py Requirements

```python
import json
import sys
from datetime import datetime, timezone
from typing import Any
from contextlib import contextmanager

class OmarLogger:
    """Structured JSON logger with GitHub Actions integration."""
    
    def __init__(self, run_id: str):
        self.run_id = run_id
        self._stage_starts: dict[str, datetime] = {}
    
    def info(self, message: str, **kwargs) -> None: ...
    def warning(self, message: str, **kwargs) -> None: ...
    def error(self, message: str, **kwargs) -> None: ...
    
    @contextmanager
    def stage(self, name: str):
        """Context manager that tracks stage timing."""
        ...
    
    def _emit(self, level: str, message: str, **kwargs) -> None:
        """Emit structured JSON log + GitHub annotation if error."""
        ...
```

### errors.py Requirements

```python
from .constants import ExitCode

class OmarGateError(Exception):
    """Base exception for all Omar Gate errors."""
    exit_code: ExitCode = ExitCode.ERROR
    
class ConfigError(OmarGateError):
    """Configuration validation failed."""
    exit_code = ExitCode.ERROR

class PreflightError(OmarGateError):
    """Preflight check failed (not an error, expected skip)."""
    exit_code = ExitCode.SKIPPED

class DedupeSkip(PreflightError):
    """Run skipped due to dedupe."""
    pass

class RateLimitSkip(PreflightError):
    """Run skipped due to rate limit."""
    pass

class ForkBlockedSkip(PreflightError):
    """Run blocked due to fork policy."""
    pass

class GateBlockedError(OmarGateError):
    """Gate blocked merge (this is success, not error)."""
    exit_code = ExitCode.BLOCKED

class EvidenceIntegrityError(OmarGateError):
    """Evidence bundle corrupted — fail closed."""
    exit_code = ExitCode.BLOCKED
```

## 7) ACCEPTANCE CRITERIA

- [ ] `logger.info("test")` outputs valid JSON to stderr
- [ ] `logger.error("fail")` emits `::error::fail` annotation
- [ ] `with logger.stage("scan"):` tracks duration_ms
- [ ] Log output is parseable: `docker logs ... | jq .`
- [ ] Exceptions have correct exit_code mapping
- [ ] No secrets appear in any log output
```

---

# STAGE 1.4: GITHUB CONTEXT LOADING

## Prompt

```markdown
# SentinelLayer Build Stage 1.4: GitHub Context Loading

## 0) PERSONA + EXPERTISE CONTEXT

You are a senior GitHub integrations engineer with 8+ years experience building GitHub Actions and Apps. You have deep expertise in:
- GitHub webhook event payloads
- GitHub Actions environment variables
- Fork PR detection and security implications
- GitHub API authentication patterns

## 1) REFERENCE CONTEXT

Enhance existing file:
- `src/omargate/github.py` — add context loading

Create new file:
- `src/omargate/context.py` — GitHubContext dataclass

Reference:
- GitHub Actions environment variables documentation
- GitHub webhook event payloads documentation
- Implementation Requirements v1.2.1 (Phase 1.4)

## 2) CONSTRAINT CONTEXT (NON-NEGOTIABLE)

- Must parse pull_request, push, and workflow_dispatch events
- Fork PRs must be reliably detected
- All fields must be extracted from env vars or event payload
- Must handle missing fields gracefully (None, not crash)
- Context must be immutable after creation

## 3) AUDIENCE CONTEXT

Primary: main.py orchestrator needing PR/repo context
Secondary: Preflight system needing fork detection

Success criteria:
- PR number, head SHA, base SHA correctly extracted
- Fork PRs detected with fork owner identified
- Works for all supported event types
- Clear error if required context missing

## 4) CHAIN-OF-THOUGHT CONTEXT

Think through:
1. What env vars does GitHub Actions provide?
2. Where is GITHUB_EVENT_PATH and what's in it?
3. How do we detect fork PRs from the event payload?
4. What fields differ between pull_request and push events?
5. What's the merge commit SHA vs head SHA distinction?

## 5) OUTPUT FORMAT CONTEXT

Produce these files:
1. `src/omargate/context.py` — GitHubContext dataclass
2. Update `src/omargate/github.py` — add load_context()

Format: Full file contents with docstrings.

## 6) DELIVERABLES

### context.py Requirements

```python
from dataclasses import dataclass
from typing import Optional
import json
import os
from pathlib import Path

@dataclass(frozen=True)
class GitHubContext:
    """Immutable GitHub Actions context."""
    
    # Repository
    repo_owner: str
    repo_name: str
    repo_full_name: str  # "owner/name"
    
    # Event
    event_name: str  # pull_request, push, workflow_dispatch
    
    # PR-specific (None if not a PR)
    pr_number: Optional[int]
    pr_title: Optional[str]
    head_sha: str
    base_sha: Optional[str]
    head_ref: Optional[str]
    base_ref: Optional[str]
    
    # Fork detection
    is_fork: bool
    fork_owner: Optional[str]
    
    # Actor
    actor: str
    
    @classmethod
    def from_environment(cls) -> "GitHubContext":
        """Load context from GitHub Actions environment."""
        ...
    
    @property
    def dedupe_components(self) -> dict:
        """Components used for dedupe key computation."""
        return {
            "repo": self.repo_full_name,
            "pr": self.pr_number,
            "head_sha": self.head_sha,
        }
```

### Fork Detection Logic

```python
def _detect_fork(event: dict) -> tuple[bool, Optional[str]]:
    """Detect if PR is from a fork and return fork owner."""
    pr = event.get("pull_request", {})
    head = pr.get("head", {})
    base = pr.get("base", {})
    
    head_repo = head.get("repo", {})
    base_repo = base.get("repo", {})
    
    # Fork if head repo differs from base repo
    if head_repo.get("full_name") != base_repo.get("full_name"):
        return True, head_repo.get("owner", {}).get("login")
    
    return False, None
```

## 7) ACCEPTANCE CRITERIA

- [ ] `GitHubContext.from_environment()` loads from env + event file
- [ ] PR events extract: pr_number, head_sha, base_sha, title
- [ ] Push events extract: head_sha, ref
- [ ] Fork PRs detected: is_fork=True, fork_owner populated
- [ ] Same-repo PRs: is_fork=False, fork_owner=None
- [ ] Missing optional fields → None (not crash)
```

---

# STAGE 1.5: PREFLIGHT SYSTEM

## Prompt

```markdown
# SentinelLayer Build Stage 1.5: Preflight System

## 0) PERSONA + EXPERTISE CONTEXT

You are a senior platform engineer with 12+ years experience building cost-aware, abuse-resistant systems. You have deep expertise in:
- Idempotency and deduplication patterns
- Rate limiting for CI/CD systems
- Cost estimation and approval workflows
- GitHub API for workflow and check run queries

## 1) REFERENCE CONTEXT

Create new module:
- `src/omargate/preflight/` with:
  - `__init__.py`
  - `dedupe.py` — idempotency check
  - `rate_limit.py` — cooldown and daily cap
  - `fork_policy.py` — fork handling
  - `cost.py` — cost estimation and approval

Enhance:
- `src/omargate/github.py` — add API methods for dedupe/rate checks

Reference:
- Implementation Requirements v1.2.1 (Phase 2.1 Preflight System)
- Existing `idempotency.py` (dedupe key computation — already complete)

## 2) CONSTRAINT CONTEXT (NON-NEGOTIABLE)

- Dedupe check MUST use external_id field (not parse comment/summary)
- Rate limit check MUST fail-safe (if API fails → require approval, not skip)
- Fork policy MUST block by default
- Cost estimation MUST happen BEFORE any LLM calls
- All preflight checks MUST complete in < 5 seconds total

## 3) AUDIENCE CONTEXT

Primary: main.py orchestrator deciding whether to proceed
Secondary: Users understanding why scan was skipped

Success criteria:
- Dedupe prevents redundant scans
- Rate limits prevent cost bombs
- Fork policy prevents secret exposure
- Clear skip reasons in logs and PR comments

## 4) CHAIN-OF-THOUGHT CONTEXT

Think through:
1. How do we query existing check runs by external_id?
2. What happens if GitHub API is down during preflight?
3. How do we check for approval label on a PR?
4. What's a reasonable cost estimation formula?
5. How do we handle workflow_dispatch (manual override)?

## 5) OUTPUT FORMAT CONTEXT

Produce these files:
1. `src/omargate/preflight/__init__.py` — exports
2. `src/omargate/preflight/dedupe.py` — dedupe check
3. `src/omargate/preflight/rate_limit.py` — rate limiting
4. `src/omargate/preflight/fork_policy.py` — fork handling
5. `src/omargate/preflight/cost.py` — cost estimation

Format: Full file contents with docstrings.

## 6) DELIVERABLES

### dedupe.py Requirements

```python
async def check_dedupe(
    gh: GitHubClient,
    head_sha: str,
    dedupe_key: str,
    check_name: str = "Omar Gate"
) -> tuple[bool, Optional[str]]:
    """
    Check if a completed run exists for this dedupe key.
    
    Returns:
        (should_skip, existing_run_url)
    
    Uses external_id field (preferred) with fallback to marker parsing.
    """
    ...
```

### rate_limit.py Requirements

```python
async def check_rate_limits(
    gh: GitHubClient,
    pr_number: Optional[int],
    config: OmarGateConfig,
    logger: OmarLogger
) -> tuple[bool, str]:
    """
    Check cooldown and daily limits.
    
    Returns:
        (should_proceed, reason_if_blocked)
    
    FAIL-SAFE: If GitHub API fails, return (False, "api_error_require_approval")
    """
    ...
```

### fork_policy.py Requirements

```python
def check_fork_policy(
    ctx: GitHubContext,
    config: OmarGateConfig
) -> tuple[bool, str, str]:
    """
    Check fork policy.
    
    Returns:
        (should_proceed, mode, reason)
        mode: "full", "limited", "blocked"
    """
    if not ctx.is_fork:
        return True, "full", "not_fork"
    
    if config.fork_policy == "block":
        return False, "blocked", "fork_pr_blocked_by_policy"
    elif config.fork_policy == "limited":
        return True, "limited", "fork_pr_limited_mode"
    else:
        return True, "full", "fork_pr_allowed"
```

### cost.py Requirements

```python
def estimate_cost(
    file_count: int,
    total_lines: int,
    model: str
) -> float:
    """Estimate LLM cost in USD."""
    # Rough token estimate: ~4 chars per token, ~50 chars per line
    estimated_tokens = total_lines * 12  # input + output buffer
    
    # Model pricing (approximate)
    cost_per_1k = {"gpt-4o": 0.005, "gpt-4o-mini": 0.00015}.get(model, 0.01)
    
    return (estimated_tokens / 1000) * cost_per_1k


async def check_cost_approval(
    estimated_cost: float,
    config: OmarGateConfig,
    ctx: GitHubContext,
    gh: GitHubClient
) -> tuple[bool, str]:
    """
    Check if cost approval is required and granted.
    
    Returns:
        (approved, status)
    """
    ...
```

## 7) ACCEPTANCE CRITERIA

- [ ] Dedupe check finds existing run by external_id
- [ ] Dedupe check returns existing_run_url for skip message
- [ ] Rate limit check enforces cooldown (min_scan_interval_minutes)
- [ ] Rate limit check enforces daily cap (max_daily_scans)
- [ ] Rate limit fails safe on API error
- [ ] Fork policy blocks by default
- [ ] Cost approval checks for label when over threshold
- [ ] All checks complete in < 5 seconds
```

---

# STAGE 1.6: UNIT TESTS

## Prompt

```markdown
# SentinelLayer Build Stage 1.6: Unit Tests

## 0) PERSONA + EXPERTISE CONTEXT

You are a senior QA engineer with 10+ years experience writing tests for CI/CD systems. You have deep expertise in:
- pytest for Python testing
- Mocking external services (GitHub API, OpenAI)
- Test fixtures for GitHub Actions events
- Coverage-driven test design

## 1) REFERENCE CONTEXT

Create test structure:
- `tests/` directory
- `tests/conftest.py` — shared fixtures
- `tests/fixtures/` — JSON event files
- `tests/unit/` — unit tests for each module

Modules to test:
- config.py
- logging.py
- errors.py
- context.py
- gate.py
- idempotency.py
- packaging.py
- preflight/*

## 2) CONSTRAINT CONTEXT (NON-NEGOTIABLE)

- All tests must run offline (no network calls)
- Use mocks for GitHub API, filesystem where needed
- Each test must complete in < 1 second
- Minimum 80% coverage for Phase 1 modules
- Tests must work inside Docker container

## 3) AUDIENCE CONTEXT

Primary: CI pipeline validating changes
Secondary: Developers debugging failures

Success criteria:
- `pytest tests/unit/ -v` passes
- Coverage report shows > 80%
- Tests catch regressions in core logic
- Clear failure messages

## 4) OUTPUT FORMAT CONTEXT

Produce:
1. `tests/conftest.py` — fixtures
2. `tests/fixtures/event_pr.json` — sample PR event
3. `tests/fixtures/event_fork_pr.json` — fork PR event
4. `tests/unit/test_config.py`
5. `tests/unit/test_gate.py`
6. `tests/unit/test_context.py`
7. `tests/unit/test_preflight.py`

## 5) KEY TEST CASES

### test_gate.py

```python
def test_gate_missing_summary_blocks():
    """Missing PACK_SUMMARY.json must block (fail-closed)."""
    ...

def test_gate_corrupted_summary_blocks():
    """Corrupted PACK_SUMMARY.json must block."""
    ...

def test_gate_incomplete_summary_blocks():
    """writer_complete=false must block."""
    ...

def test_gate_hash_mismatch_blocks():
    """Hash mismatch must block."""
    ...

def test_gate_p0_blocks_on_p1_threshold():
    """P0 finding blocks when severity_gate=P1."""
    ...

def test_gate_p1_passes_on_p0_threshold():
    """P1 finding passes when severity_gate=P0."""
    ...
```

### test_context.py

```python
def test_context_parses_pr_event():
    """PR event extracts pr_number, head_sha, base_sha."""
    ...

def test_context_detects_fork():
    """Fork PR sets is_fork=True and fork_owner."""
    ...

def test_context_handles_push_event():
    """Push event extracts head_sha without pr_number."""
    ...
```

### test_preflight.py

```python
def test_fork_policy_blocks_by_default():
    """fork_policy=block blocks fork PRs."""
    ...

def test_fork_policy_limited_mode():
    """fork_policy=limited allows with limited flag."""
    ...

def test_cost_estimation():
    """Cost estimation produces reasonable values."""
    ...
```

## 6) ACCEPTANCE CRITERIA

- [ ] `pytest tests/unit/ -v` — all tests pass
- [ ] `pytest --cov=src/omargate tests/unit/` — > 80% coverage
- [ ] Tests run in < 30 seconds total
- [ ] No network calls in tests
- [ ] Tests work inside Docker container
```

---

# EXECUTION CHECKLIST

## Pre-Build Setup

- [ ] Clone GPT's scaffold: `unzip omar-gate-action-scaffold_v1_2_1.zip -d omar-gate`
- [ ] Initialize git: `cd omar-gate && git init`
- [ ] Create initial commit: `git add . && git commit -m "chore: initial scaffold from GPT"`
- [ ] Set up remote: `git remote add origin git@github.com:plexaura/omar-gate.git`

## Stage Execution

### Stage 1.1: Container Foundation
```bash
# Execute prompt with AI agent
# Test:
docker build -t omar-gate:dev .
docker run --rm omar-gate:dev python -c "import openai; print('ok')"
docker run --rm omar-gate:dev node --version

# Commit:
git add Dockerfile entrypoint.sh requirements.txt .dockerignore
git commit -m "feat(phase1.1): container foundation - Dockerfile, entrypoint, deps"
```

### Stage 1.2: Configuration System
```bash
# Execute prompt with AI agent
# Test:
docker build -t omar-gate:dev .
docker run --rm -e INPUT_OPENAI_API_KEY=sk_test_dummy omar-gate:dev \
  python -c "from omargate.config import OmarGateConfig; c = OmarGateConfig(); print(c)"

# Commit:
git add src/omargate/config.py src/omargate/constants.py
git commit -m "feat(phase1.2): configuration system - Pydantic models, env parsing"
```

### Stage 1.3: Logging and Errors
```bash
# Execute prompt with AI agent
# Test:
docker run --rm omar-gate:dev \
  python -c "from omargate.logging import OmarLogger; l = OmarLogger('test'); l.info('hello')"

# Commit:
git add src/omargate/logging.py src/omargate/errors.py
git commit -m "feat(phase1.3): logging and errors - structured logging, exceptions"
```

### Stage 1.4: GitHub Context
```bash
# Execute prompt with AI agent
# Test (requires event file):
# Create tests/fixtures/event_pr.json first
docker run --rm \
  -e GITHUB_REPOSITORY=test/repo \
  -e GITHUB_EVENT_PATH=/tmp/event.json \
  -e GITHUB_SHA=abc123 \
  -e GITHUB_EVENT_NAME=pull_request \
  -v $(pwd)/tests/fixtures/event_pr.json:/tmp/event.json \
  omar-gate:dev \
  python -c "from omargate.context import GitHubContext; print(GitHubContext.from_environment())"

# Commit:
git add src/omargate/context.py
git commit -m "feat(phase1.4): github context - event parsing, fork detection"

# PUSH CHECKPOINT 1
git push -u origin main
```

### Stage 1.5: Preflight System
```bash
# Execute prompt with AI agent
# Test:
docker run --rm omar-gate:dev \
  python -c "from omargate.preflight import check_fork_policy; print('preflight ok')"

# Commit:
git add src/omargate/preflight/
git commit -m "feat(phase1.5): preflight system - dedupe, rate limits, fork policy"
```

### Stage 1.6: Unit Tests
```bash
# Execute prompt with AI agent
# Test:
docker run --rm omar-gate:dev pytest tests/unit/ -v
docker run --rm omar-gate:dev pytest --cov=src/omargate tests/unit/

# Commit:
git add tests/
git commit -m "feat(phase1.6): tests - unit tests for Phase 1 modules"

# PUSH CHECKPOINT 2
git push
```

---

# COMPLETION CRITERIA

Phase 1 is complete when:

- [ ] All 6 stages committed
- [ ] All unit tests pass
- [ ] Coverage > 80%
- [ ] Container builds < 3 min, size < 500MB
- [ ] `act pull_request` runs end-to-end (with mocked scans)
- [ ] Gate correctly blocks on P0/P1 (test with fixture)
- [ ] Gate correctly passes on P2/P3 only
- [ ] Fork PRs blocked by default

**Next Phase:** Phase 2 (Analysis Pipeline) — Ingest, Deterministic Scans, LLM Integration

---

**END OF PHASE 1 BUILD PROMPTS**

*Execute stages in order. Test before commit. Push at checkpoints.*
