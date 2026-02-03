# SENTINELLAYER MODEL 2: Implementation Requirements
## Structured Build Specification for AI Agents

**Version:** 1.2.1  
**Date:** 2026-02-03  
**Status:** APPROVED FOR IMPLEMENTATION  
**Classification:** INTERNAL BUILD DOCUMENT  

---

## CHANGELOG (v1.0 → v1.1)

| Change | Reason |
|--------|--------|
| Dedupe key now uses full 64-char hash | Prevent collision at scale |
| Dedupe check uses external_id (not summary parsing) | More robust |
| policy_pack_version added to dedupe key | Prevent false dedupe on policy change |
| Fixer Phase 9.1 rewritten for "never run repo scripts" | Security consistency |
| Added Phase 6.0: API Foundation Standards | SWE framework compliance |
| Added requestId + error schema requirements | Debugging + support |
| Rate limiting must fail closed | SWE framework compliance |
| Deletion endpoints now async (202 Accepted) | Scale readiness |
| PR comment marker stabilized | Idempotent updates |

## CHANGELOG (v1.1 → v1.2)

- Added **Model 2 IP reality check** section (container-based Actions are inspectable; do not oversell prompt secrecy).
- Added **Tier 4 training consent** requirements + dataset governance (de-identification, redaction, license hygiene, revocation workflow).
- Added **supply chain hardening**: container signing (Cosign), SLSA provenance attestation, dependency pinning guidance, and digest-pinning recommendation for enterprise users.
- Added **OpenTelemetry** instrumentation requirements (traces/metrics/log correlation) for Action + PlexAura API.
- Tightened **public metrics privacy** rules (daily aggregation, k-anonymity threshold, suppression of small buckets).
- Clarified **GitHub API rate-limit failure behavior** for cooldown/daily-cap checks (fail-safe: require approval label or skip with clear message; never silently run unbounded).
- Added **Tier 2 schema** + **Tier 3 artifact manifest** schemas to Appendix.
- Added **Appendix B** mapping of SentinelLayer outputs to SWE Excellence domains (for Model 3/premium packs).


---

## DOCUMENT PURPOSE

This document provides structured, phase-based requirements for AI coding agents to implement SentinelLayer Model 2. Each phase contains:

- Objective statement
- Deliverables checklist
- Technical specifications
- File/folder structure
- Acceptance criteria
- Dependencies on other phases

**SECURITY NOTE:** This document intentionally omits prompt contents and sensitive IP. Prompts are referenced by filename only. Actual prompt files are maintained separately and injected at build time.

## MODEL 2 IP REALITY CHECK (DO NOT OVERSell PROMPT SECRECY)

Model 2 runs a **container-based GitHub Action on the customer’s runner**. This is great for distribution, but it is **not strong IP protection**:

- If the container image is pullable, it is inspectable. A determined user can reverse-engineer prompts, policy packs, and orchestration logic.
- Practical mitigation for Model 2: keep baseline prompts compact/generic, put differentiation into **orchestration policy**, **evidence bundling**, **fail-closed semantics**, **UX**, and **HITL operations**.
- Reserve the full **multi-persona (13+) pack system** and high-value prompts for Model 3 (GitHub App + server-side execution) where prompts never leave PlexAura-controlled infrastructure.

Positioning guidance (trust-preserving):
- Say: **“Gate correctness does not depend on PlexAura availability.”**
- Say: **“Optional artifact sharing powers dashboard + HITL.”**
- Avoid: **“Prompts are private / cannot be extracted”** for Model 2.


---

## CHANGELOG (v1.2 → v1.2.1)

- Added **Quickstart integration contract** (copy/paste workflow YAML, permissions, branch protection, fork policy) to reduce install friction and prevent “security theater”.
- Added **GitHub OIDC token acquisition** snippet for Docker Actions (how to mint the OIDC JWT when `id-token: write` is enabled).

## TABLE OF CONTENTS

1. [Architecture Overview](#1-architecture-overview)
2. [Repository Structure](#2-repository-structure)
3. [Phase 1: Core Action Infrastructure](#phase-1-core-action-infrastructure)
4. [Phase 2: Analysis Pipeline](#phase-2-analysis-pipeline)
5. [Phase 3: Evidence & Packaging](#phase-3-evidence--packaging)
6. [Phase 4: Gate & Publishing](#phase-4-gate--publishing)
7. [Phase 5: Telemetry System](#phase-5-telemetry-system)
8. [Phase 6: PlexAura API](#phase-6-plexaura-api)
9. [Phase 7: Dashboard MVP](#phase-7-dashboard-mvp)
10. [Phase 8: HITL Service](#phase-8-hitl-service)
11. [Phase 9: Fixers](#phase-9-fixers)
12. [Phase 10: Production Hardening](#phase-10-production-hardening)
13. [Appendix: Schemas](#appendix-schemas)
14. [Appendix B: SWE Excellence Integration Map](#appendix-b--swe-excellence-framework-integration-map-model-3--premium)

---

## 0. QUICKSTART INTEGRATION CONTRACT (Copy/Paste)

This section exists because **SentinelLayer only functions as a real gate** when:
1) the workflow grants the correct GitHub permissions,
2) the Action publishes a check run / status,
3) the target branch is protected and **requires** that check.

If any of those are missing, the system silently degrades into “security theater”.

### 0.1 Minimal Customer Workflow (recommended default)

> This YAML is the “install in 2 minutes” promise. Keep it stable across releases.

```yaml
name: Omar Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  checks: write
  issues: write         # required if using label-based cost approval
  actions: read         # required for daily cap via workflow runs
  id-token: write       # optional: enables OIDC auth to PlexAura (no stored token)

concurrency:
  group: omar-gate-${{ github.workflow }}-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  omar-gate:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1

      - name: Run Omar Gate
        uses: plexaura/omar-gate@v1
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}

          # Optional: connect runs to a PlexAura workspace (Tier 2/3)
          plexaura_token: ${{ secrets.PLEXAURA_TOKEN }}

          # Telemetry / consent
          telemetry_tier: "1"          # default: 1 (aggregate only)
          # training_opt_in: "false"   # default: false

          # Optional: enable full artifacts (required for HITL)
          # telemetry_tier: "3"
```

### 0.2 Branch Protection Required (non-negotiable)

**Without branch protection, the Action is not enforcement.**

Required GitHub settings (per protected branch, e.g. `main`):
- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging
- ✅ Require branches to be up to date before merging
- ✅ Add required status check: **Omar Gate** (or the exact check name used by the workflow)
- (Recommended) ✅ Do not allow bypassing the above settings

**Action behavior:** If the Action detects that branch protection is not requiring its check, it MUST post a warning comment with a setup link (see Phase 4).

### 0.3 Fork PR Reality

By default, fork PRs **cannot** access repository secrets (including `OPENAI_API_KEY`), so full LLM scanning cannot run.

Supported behaviors:
- `fork_policy=block` (default): block with an explanation and link to docs
- `fork_policy=limited`: deterministic scans only (no secrets)
- `fork_policy=allow`: only via `pull_request_target` with strict safety rules (Model 2 should discourage)

-----

# 1. ARCHITECTURE OVERVIEW

## 1.1 System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    CUSTOMER GITHUB RUNNER                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              plexaura/omar-gate@v1 (Docker)               │  │
│  │                                                           │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │  │
│  │  │Preflight│→ │ Ingest  │→ │ Analyze │→ │ Package │     │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘     │  │
│  │       │                                      │           │  │
│  │       ▼                                      ▼           │  │
│  │  ┌─────────┐                          ┌─────────┐       │  │
│  │  │  Gate   │←─────────────────────────│ Summary │       │  │
│  │  └─────────┘                          └─────────┘       │  │
│  │       │                                                  │  │
│  │       ▼                                                  │  │
│  │  ┌─────────┐  ┌─────────┐                               │  │
│  │  │ Publish │→ │ Upload  │ ─ ─ ─ (best effort) ─ ─ ─ ─ ─│─ ─▶ PlexAura
│  │  └─────────┘  └─────────┘                               │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 1.2 Data Flow Principles

| Principle | Implementation |
|-----------|----------------|
| Gate Independence | Gate reads PACK_SUMMARY.json locally; never calls PlexAura for decision |
| Fail-Closed | Missing/corrupted summary = BLOCK |
| Best-Effort Upload | Telemetry failures don't affect gate |
| Cost Awareness | Estimate before LLM; require approval if over threshold |
| Dedupe First | Skip if same SHA+config already analyzed |

## 1.3 Technology Stack

| Component | Technology |
|-----------|------------|
| Action Container | Docker (Alpine base) |
| Runtime | Python 3.11 + Node 20 |
| Orchestration | Python (asyncio) |
| Ingest | Node.js (codebase_map.mjs) |
| LLM Calls | OpenAI SDK (user's key) |
| PlexAura API | FastAPI (Python) |
| PlexAura Dashboard | Next.js 14 |
| Database | PostgreSQL + TimescaleDB |
| Artifact Storage | AWS S3 (SSE-KMS) |
| Auth | GitHub OAuth + OIDC |

---

# 2. REPOSITORY STRUCTURE

## 2.1 Action Repository: `plexaura/omar-gate`

```
omar-gate/
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Action's own CI
│       ├── release.yml               # Semantic versioning + GHCR push
│       └── security-scan.yml         # Self-scan with Omar
│
├── action.yml                        # GitHub Action interface definition
├── Dockerfile                        # Container build
├── entrypoint.sh                     # Container entry point
│
├── src/
│   ├── __init__.py
│   ├── main.py                       # Orchestrator entry point
│   ├── config.py                     # Configuration loading
│   ├── constants.py                  # Severity levels, exit codes, limits
│   │
│   ├── preflight/
│   │   ├── __init__.py
│   │   ├── dedupe.py                 # Idempotency key + GitHub API check
│   │   ├── rate_limit.py             # Cooldown + daily cap
│   │   ├── cost_estimator.py         # Token estimation + approval check
│   │   ├── fork_policy.py            # Fork detection + policy application
│   │   └── branch_protection.py      # Best-effort BP verification
│   │
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── codebase_map.mjs          # Node.js ingest tool
│   │   ├── ingest_runner.py          # Python wrapper for Node tool
│   │   ├── hotspot_detector.py       # Risk hotspot identification
│   │   └── file_classifier.py        # File type/category classification
│   │
│   ├── analyze/
│   │   ├── __init__.py
│   │   ├── orchestrator.py           # Analysis stage orchestration
│   │   ├── deterministic/
│   │   │   ├── __init__.py
│   │   │   ├── pattern_scanner.py    # Regex-based pattern detection
│   │   │   ├── secret_scanner.py     # Secret/credential detection
│   │   │   ├── config_scanner.py     # Configuration validation
│   │   │   └── patterns/
│   │   │       ├── security.json     # Security patterns (non-sensitive)
│   │   │       ├── quality.json      # Code quality patterns
│   │   │       └── ci_cd.json        # CI/CD patterns
│   │   │
│   │   └── llm/
│   │       ├── __init__.py
│   │       ├── llm_client.py         # OpenAI SDK wrapper
│   │       ├── prompt_loader.py      # Load prompts from /prompts/
│   │       ├── context_builder.py    # Build LLM context from ingest
│   │       ├── response_parser.py    # Parse LLM response to findings
│   │       └── fallback_handler.py   # Model fallback logic
│   │
│   ├── package/
│   │   ├── __init__.py
│   │   ├── summary_writer.py         # PACK_SUMMARY.json generation
│   │   ├── findings_writer.py        # FINDINGS.jsonl generation
│   │   ├── fingerprint.py            # Finding fingerprint computation
│   │   ├── report_generator.py       # Human-readable report
│   │   └── artifact_hasher.py        # SHA256 hash computation
│   │
│   ├── gate/
│   │   ├── __init__.py
│   │   ├── evaluator.py              # Gate decision logic
│   │   ├── summary_validator.py      # PACK_SUMMARY validation
│   │   └── policy.py                 # Severity threshold application
│   │
│   ├── publish/
│   │   ├── __init__.py
│   │   ├── check_run.py              # GitHub Check Run API
│   │   ├── pr_comment.py             # Sticky PR comment (create/update)
│   │   ├── comment_templates.py      # Comment formatting templates
│   │   └── artifact_upload.py        # GitHub Artifact upload
│   │
│   ├── telemetry/
│   │   ├── __init__.py
│   │   ├── collector.py              # Metrics collection
│   │   ├── schemas.py                # Telemetry payload schemas
│   │   ├── uploader.py               # PlexAura API upload
│   │   └── consent.py                # Consent tier enforcement
│   │
│   └── utils/
│       ├── __init__.py
│       ├── github_api.py             # GitHub API helpers
│       ├── logging.py                # Structured logging
│       ├── errors.py                 # Custom exceptions
│       └── hashing.py                # Crypto utilities
│
├── prompts/                          # PROMPT FILES - NOT IN PUBLIC REPO
│   ├── .gitignore                    # Ignore actual prompts
│   ├── README.md                     # "Prompts injected at build time"
│   └── manifest.json                 # Prompt file manifest (names only)
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                   # Pytest fixtures
│   ├── fixtures/                     # Test repositories
│   │   ├── clean_repo/
│   │   ├── vulnerable_repo/
│   │   └── mixed_repo/
│   ├── unit/
│   │   ├── test_preflight.py
│   │   ├── test_gate.py
│   │   ├── test_fingerprint.py
│   │   └── ...
│   └── integration/
│       ├── test_full_workflow.py
│       └── test_github_api.py
│
├── docs/
│   ├── README.md                     # User-facing docs
│   ├── INSTALL.md                    # Installation guide
│   ├── CONFIGURATION.md              # All inputs documented
│   ├── BRANCH_PROTECTION.md          # Setup guide
│   └── TROUBLESHOOTING.md
│
├── scripts/
│   ├── build.sh                      # Build script
│   ├── inject_prompts.sh             # Prompt injection (CI only)
│   └── version.sh                    # Version management
│
├── .dockerignore
├── .gitignore
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
└── requirements.txt
```

## 2.2 PlexAura API Repository: `plexaura/api`

```
plexaura-api/
├── src/
│   ├── main.py                       # FastAPI app
│   ├── config.py
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── telemetry.py              # POST /api/v1/telemetry
│   │   ├── artifacts.py              # POST /api/v1/artifacts/upload
│   │   ├── runs.py                   # GET /api/v1/runs
│   │   ├── hitl.py                   # POST /api/v1/hitl/request
│   │   ├── public.py                 # GET /api/v1/public/stats
│   │   ├── consent.py                # POST /api/v1/consent
│   │   └── deletion.py               # DELETE endpoints
│   │
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── github_oauth.py
│   │   ├── oidc_verifier.py
│   │   └── token_manager.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── repo.py
│   │   ├── run.py
│   │   ├── telemetry.py
│   │   └── hitl.py
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── telemetry_service.py
│   │   ├── artifact_service.py
│   │   ├── hitl_service.py
│   │   └── stats_service.py
│   │
│   └── db/
│       ├── __init__.py
│       ├── connection.py
│       └── migrations/
│
├── tests/
├── alembic/
├── Dockerfile
└── requirements.txt
```

## 2.3 Prompt Manifest (Non-Sensitive Reference)

```json
// prompts/manifest.json
{
  "version": "1.0",
  "prompts": {
    "baseline": {
      "file": "BASELINE_PROMPT.md",
      "purpose": "Full repository security audit",
      "scan_modes": ["deep", "nightly"]
    },
    "pr_review": {
      "file": "PR_REVIEW_PROMPT.md", 
      "purpose": "PR diff-focused review",
      "scan_modes": ["pr-diff"]
    },
    "release_engineering": {
      "file": "RELEASE_ENGINEERING_PROMPT.md",
      "purpose": "CI/CD and workflow analysis",
      "persona": "omar_singh",
      "scan_modes": ["pr-diff", "deep"]
    }
  },
  "policy_packs": {
    "vibe_default": {
      "severity_gate": "P1",
      "prompts": ["pr_review"],
      "deterministic_scans": ["security", "secrets", "ci_cd"]
    },
    "strict_enterprise": {
      "severity_gate": "P0",
      "prompts": ["pr_review", "release_engineering"],
      "deterministic_scans": ["security", "secrets", "ci_cd", "quality"]
    }
  }
}
```

---

# PHASE 1: CORE ACTION INFRASTRUCTURE

## Phase 1.1: Container Foundation

**Objective:** Create a minimal Docker container that can run in GitHub Actions

### Deliverables

- [ ] `Dockerfile` with Python 3.11 + Node 20 on Alpine
- [ ] `entrypoint.sh` that routes to Python orchestrator
- [ ] `action.yml` with all inputs/outputs defined
- [ ] Basic `src/main.py` that logs "Omar Gate started"
- [ ] GitHub workflow to build and test container

### Technical Specifications

**Dockerfile:**
```dockerfile
FROM python:3.11-alpine

# Install Node.js
RUN apk add --no-cache nodejs npm git bash

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy source
COPY src/ /app/src/
COPY prompts/ /app/prompts/
COPY entrypoint.sh /app/

WORKDIR /app
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
```

**entrypoint.sh:**
```bash
#!/bin/bash
set -e

# Set up environment
export PYTHONPATH=/app

# Run orchestrator
python -m src.main "$@"
```

### Acceptance Criteria

1. Container builds in < 2 minutes
2. Container size < 500MB
3. `docker run` executes without error
4. GitHub Action workflow triggers successfully

### Dependencies

- None (first phase)

---

## Phase 1.2: Configuration System

**Objective:** Load and validate all Action inputs into typed configuration

### Deliverables

- [ ] `src/config.py` with Pydantic models for all inputs
- [ ] `src/constants.py` with severity levels, exit codes, limits
- [ ] Environment variable parsing
- [ ] Configuration validation with clear error messages

### Technical Specifications

**Config Schema (Pydantic):**
```python
from pydantic import BaseModel, Field
from typing import Literal, Optional

class OmarGateConfig(BaseModel):
    # Required
    openai_api_key: str = Field(default="")
    
    # Scan settings
    scan_mode: Literal["pr-diff", "deep", "nightly"] = "pr-diff"
    policy_pack: str = "vibe_default"
    severity_gate: Literal["P0", "P1", "P2", "none"] = "P1"
    
    # Model settings
    model: str = "gpt-4o"
    model_fallback: str = "gpt-4o-mini"
    llm_failure_policy: Literal["block", "deterministic_only", "allow_with_warning"] = "block"
    
    # Cost control
    max_input_tokens: int = 100000
    require_cost_confirmation_usd: float = 5.00
    approval_mode: Literal["pr_label", "workflow_dispatch", "none"] = "pr_label"
    approval_label: str = "sentinellayer:approved"
    
    # Rate limiting
    min_scan_interval_minutes: int = 5
    max_daily_scans: int = 20
    
    # Dedupe
    dedupe: bool = True
    
    # Fork policy
    fork_policy: Literal["block", "limited", "allow"] = "block"
    
    # PlexAura integration
    plexaura_token: Optional[str] = None
    telemetry: bool = True
    share_metadata: bool = False
    share_artifacts: bool = False
    training_consent: bool = False
    
    # Fixers
    run_deterministic_fix: bool = False
    auto_commit_fixes: bool = False
    run_llm_patch: bool = False
```

**Constants:**
```python
# Severity levels
class Severity:
    P0 = "P0"  # Critical - stop ship
    P1 = "P1"  # High - should fix before merge
    P2 = "P2"  # Medium - fix soon
    P3 = "P3"  # Low - nice to have

# Exit codes
class ExitCode:
    SUCCESS = 0
    GATE_BLOCKED = 1
    GATE_NEEDS_APPROVAL = 2
    ERROR_SYSTEM = 3
    ERROR_CONFIG = 4
    SKIPPED_DEDUPE = 10
    SKIPPED_RATE_LIMIT = 11
    SKIPPED_FORK = 12

# Limits
class Limits:
    MAX_FILE_SIZE_BYTES = 1_000_000  # 1MB
    MAX_FILES = 1000
    MAX_TOTAL_SIZE_BYTES = 50_000_000  # 50MB
    MAX_SNIPPET_LENGTH = 500
    MAX_FINDINGS_PER_FILE = 20
    MAX_TOTAL_FINDINGS = 200
```

### Acceptance Criteria

1. All inputs from action.yml have corresponding config fields
2. Invalid config raises clear validation error
3. Defaults are applied correctly
4. Sensitive values (API keys) are masked in logs

### Dependencies

- Phase 1.1 (container exists)

---

## Phase 1.3: Logging & Error Handling

**Objective:** Structured logging and consistent error handling

### Deliverables

- [ ] `src/utils/logging.py` with structured JSON logging
- [ ] `src/utils/errors.py` with custom exception hierarchy
- [ ] GitHub Actions annotation integration (`::error::`, `::warning::`)
- [ ] Step summary output (`$GITHUB_STEP_SUMMARY`)

### Technical Specifications

**Logging Format:**
```python
import json
import sys
from datetime import datetime

class OmarLogger:
    def __init__(self, run_id: str):
        self.run_id = run_id
    
    def _log(self, level: str, message: str, **kwargs):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "run_id": self.run_id,
            "message": message,
            **kwargs
        }
        print(json.dumps(entry), file=sys.stderr)
        
        # GitHub annotations
        if level == "ERROR":
            print(f"::error::{message}")
        elif level == "WARNING":
            print(f"::warning::{message}")
    
    def info(self, message: str, **kwargs):
        self._log("INFO", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log("ERROR", message, **kwargs)
    
    def stage_start(self, stage: str):
        self._log("INFO", f"Stage started: {stage}", stage=stage)
    
    def stage_end(self, stage: str, duration_ms: int, success: bool):
        self._log("INFO", f"Stage completed: {stage}", 
                  stage=stage, duration_ms=duration_ms, success=success)
```

**Exception Hierarchy:**
```python
class OmarGateError(Exception):
    """Base exception for Omar Gate"""
    exit_code = ExitCode.ERROR_SYSTEM

class ConfigurationError(OmarGateError):
    """Invalid configuration"""
    exit_code = ExitCode.ERROR_CONFIG

class PreflightError(OmarGateError):
    """Preflight check failed"""
    pass

class DedupeSkip(PreflightError):
    """Skipped due to dedupe"""
    exit_code = ExitCode.SKIPPED_DEDUPE

class RateLimitSkip(PreflightError):
    """Skipped due to rate limit"""
    exit_code = ExitCode.SKIPPED_RATE_LIMIT

class GateBlockedError(OmarGateError):
    """Gate blocked merge"""
    exit_code = ExitCode.GATE_BLOCKED

class EvidenceIntegrityError(OmarGateError):
    """Evidence bundle corrupted"""
    exit_code = ExitCode.GATE_BLOCKED  # Fail closed
```

### Acceptance Criteria

1. All log entries are valid JSON
2. Errors produce GitHub annotations visible in UI
3. Step summary is populated with human-readable output
4. Sensitive data is never logged

### Dependencies

- Phase 1.2 (config exists)

---

## Phase 1.4: GitHub Context Loading

**Objective:** Load GitHub event context and repository information

### Deliverables

- [ ] `src/utils/github_api.py` with context loading
- [ ] Parse `GITHUB_EVENT_PATH` for PR/push details
- [ ] Extract: repo, owner, PR number, head SHA, base SHA, actor
- [ ] Detect fork PRs

### Technical Specifications

**GitHub Context:**
```python
import os
import json
from dataclasses import dataclass
from typing import Optional

@dataclass
class GitHubContext:
    # Repository
    repo_owner: str
    repo_name: str
    repo_full_name: str
    
    # Event
    event_name: str  # pull_request, push, workflow_dispatch
    
    # PR specific (None if not PR)
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
    
    # Refs
    ref: str
    
    @classmethod
    def from_environment(cls) -> "GitHubContext":
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        with open(event_path) as f:
            event = json.load(f)
        
        # Parse based on event type...
        # (implementation details)
        
        return cls(...)
    
    @property
    def dedupe_key_components(self) -> dict:
        return {
            "repo": self.repo_full_name,
            "pr": self.pr_number,
            "head_sha": self.head_sha,
        }
```

### Acceptance Criteria

1. Correctly parses pull_request events
2. Correctly parses push events
3. Fork PRs detected reliably
4. All GitHub Actions environment variables used correctly

### Dependencies

- Phase 1.3 (logging exists)

---

# PHASE 2: ANALYSIS PIPELINE

## Phase 2.1: Preflight System

**Objective:** Implement all preflight checks before expensive analysis

### Deliverables

- [ ] `src/preflight/dedupe.py` - Idempotency check via GitHub API
- [ ] `src/preflight/rate_limit.py` - Cooldown and daily cap
- [ ] `src/preflight/cost_estimator.py` - Token estimation
- [ ] `src/preflight/fork_policy.py` - Fork handling
- [ ] `src/preflight/branch_protection.py` - BP verification (best-effort)

### Technical Specifications

**Dedupe Key Computation:**
```python
import hashlib

def compute_dedupe_key(
    repo: str,
    pr_number: int | None,
    head_sha: str,
    scan_mode: str,
    policy_pack: str,
    policy_pack_version: str,  # IMPORTANT: include version to prevent false dedupe
    action_version: str
) -> str:
    """
    Compute idempotency key for dedupe.
    
    Returns FULL 64-char hash (256 bits). Never truncate for storage.
    For display in PR comments, use dedupe_key[:8] only.
    """
    components = f"{repo}:{pr_number}:{head_sha}:{scan_mode}:{policy_pack}:{policy_pack_version}:{action_version}"
    return hashlib.sha256(components.encode()).hexdigest()  # Full 64 chars


def dedupe_key_short(dedupe_key: str) -> str:
    """Short form for display only (PR comments, logs)."""
    return dedupe_key[:8]


async def check_dedupe(
    github_token: str,
    repo: str,
    head_sha: str,
    dedupe_key: str
) -> bool:
    """
    Check if a completed run exists for this dedupe key.
    
    Uses external_id field (preferred) with fallback to summary parsing.
    Returns True if should skip (already analyzed).
    """
    check_runs = await list_check_runs(github_token, repo, head_sha, check_name="Omar Gate")
    
    for run in check_runs:
        if run.get("status") != "completed":
            continue
        
        # PREFERRED: Match by external_id (set during publish)
        if run.get("external_id") == dedupe_key:
            return True
        
        # FALLBACK: Parse summary (legacy or if external_id missing)
        # Only use this if external_id isn't available
        summary = run.get("output", {}).get("summary", "")
        if f"dedupe={dedupe_key[:8]}" in summary:
            # Verify by fetching full run details if needed
            return True
    
    return False
```

**Rate Limit Check:**
```python
async def check_rate_limits(
    github_token: str,
    repo: str,
    pr_number: int | None,
    config: OmarGateConfig
) -> tuple[bool, str]:
    """
    Check cooldown and daily limits.
    Returns (should_proceed, reason_if_blocked).
    """
    # Check last completed run time for this PR
    # If < min_scan_interval_minutes ago, return (False, "cooldown")
    
    # Count runs in last 24h for this repo
    # If >= max_daily_scans, return (False, "daily_cap")
    
    return (True, "")
```

**Cost Approval:**
```python
async def check_cost_approval(
    estimated_cost_usd: float,
    config: OmarGateConfig,
    github_context: GitHubContext,
    github_token: str
) -> tuple[bool, str]:
    """
    Check if cost approval is required and granted.
    Returns (approved, status_message).
    """
    if estimated_cost_usd <= config.require_cost_confirmation_usd:
        return (True, "under_threshold")
    
    if config.approval_mode == "none":
        return (True, "approval_disabled")
    
    if config.approval_mode == "pr_label":
        # Check if PR has approval label
        labels = await get_pr_labels(github_token, github_context)
        if config.approval_label in labels:
            return (True, "label_approved")
        return (False, "needs_label")
    
    if config.approval_mode == "workflow_dispatch":
        # Check if triggered via workflow_dispatch
        if github_context.event_name == "workflow_dispatch":
            return (True, "dispatch_approved")
        return (False, "needs_dispatch")
```

### Acceptance Criteria

1. Dedupe correctly skips already-analyzed SHAs
2. Cooldown enforced per-PR
3. Daily cap enforced per-repo
4. Cost approval label detection works
5. Fork PRs handled according to policy

### Dependencies

- Phase 1.4 (GitHub context)

---

## Phase 2.2: Codebase Ingest

**Objective:** Map repository structure and identify analysis targets

### Deliverables

- [ ] `src/ingest/codebase_map.mjs` - Node.js file tree walker
- [ ] `src/ingest/ingest_runner.py` - Python wrapper
- [ ] `src/ingest/file_classifier.py` - Categorize files
- [ ] `src/ingest/hotspot_detector.py` - Identify risk areas

### Technical Specifications

**Ingest Output Schema:**
```json
{
  "schema_version": "1.0",
  "timestamp_utc": "2026-02-03T12:00:00Z",
  "stats": {
    "total_files": 342,
    "text_files": 320,
    "binary_files": 22,
    "in_scope_files": 285,
    "total_lines": 45000
  },
  "files": [
    {
      "path": "src/auth/middleware.ts",
      "category": "source",
      "language": "typescript",
      "lines": 150,
      "size_bytes": 4200,
      "is_hotspot": true,
      "hotspot_reasons": ["auth_module", "middleware"]
    }
  ],
  "hotspots": {
    "auth": ["src/auth/middleware.ts", "src/auth/session.ts"],
    "payment": ["src/billing/stripe.ts"],
    "crypto": [],
    "webhook": ["src/webhooks/twilio.ts"]
  },
  "dependencies": {
    "package_manager": "pnpm",
    "lockfile": "pnpm-lock.yaml",
    "direct_deps": 45,
    "total_deps": 312
  }
}
```

**Hotspot Detection Rules:**
```python
HOTSPOT_PATTERNS = {
    "auth": [
        r"auth", r"session", r"login", r"logout",
        r"password", r"credential", r"token", r"jwt"
    ],
    "payment": [
        r"payment", r"billing", r"stripe", r"invoice",
        r"subscription", r"charge"
    ],
    "crypto": [
        r"crypto", r"encrypt", r"decrypt", r"hash",
        r"sign", r"verify", r"secret"
    ],
    "webhook": [
        r"webhook", r"callback", r"hook"
    ],
    "database": [
        r"migration", r"schema", r"model", r"query"
    ],
    "infrastructure": [
        r"terraform", r"\.tf$", r"cloudformation",
        r"kubernetes", r"k8s", r"docker"
    ]
}
```

### Acceptance Criteria

1. Ingest completes in < 30s for repos up to 1000 files
2. Binary files correctly detected and excluded
3. Hotspots identified with > 90% accuracy
4. File size limits enforced

### Dependencies

- Phase 2.1 (preflight passed)

---

## Phase 2.3: Deterministic Scanners

**Objective:** Pattern-based scanning without LLM

### Deliverables

- [ ] `src/analyze/deterministic/pattern_scanner.py` - Regex scanner
- [ ] `src/analyze/deterministic/secret_scanner.py` - Secret detection
- [ ] `src/analyze/deterministic/config_scanner.py` - Config validation
- [ ] Pattern definition files (JSON)

### Technical Specifications

**Pattern Definition Schema:**
```json
{
  "patterns": [
    {
      "id": "SEC-001",
      "name": "Hardcoded API Key",
      "severity": "P1",
      "category": "secrets",
      "regex": "(api[_-]?key|apikey)\\s*[=:]\\s*['\"][a-zA-Z0-9]{20,}['\"]",
      "file_patterns": ["*.ts", "*.js", "*.py", "*.env*"],
      "exclude_patterns": ["*.test.*", "*.spec.*", "*_test.*"],
      "message": "Potential hardcoded API key detected",
      "recommendation": "Move to environment variable or secrets manager"
    }
  ]
}
```

**Scanner Interface:**
```python
from dataclasses import dataclass
from typing import List

@dataclass
class DeterministicFinding:
    id: str
    pattern_id: str
    severity: str
    category: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    message: str
    recommendation: str
    confidence: float = 1.0  # Deterministic = 100%

class PatternScanner:
    def __init__(self, patterns_file: str):
        self.patterns = self._load_patterns(patterns_file)
    
    def scan_file(self, file_path: str, content: str) -> List[DeterministicFinding]:
        findings = []
        for pattern in self.patterns:
            if not self._file_matches(file_path, pattern):
                continue
            matches = self._find_matches(content, pattern)
            findings.extend(matches)
        return findings
    
    def scan_repo(self, files: List[dict]) -> List[DeterministicFinding]:
        all_findings = []
        for file_info in files:
            if file_info["category"] != "source":
                continue
            content = self._read_file(file_info["path"])
            findings = self.scan_file(file_info["path"], content)
            all_findings.extend(findings)
        return all_findings
```

### Acceptance Criteria

1. Scan 1000 files in < 10s
2. No false positives on test fixtures
3. All P0/P1 security patterns covered
4. Snippets truncated to safe length

### Dependencies

- Phase 2.2 (ingest complete)

---

## Phase 2.4: LLM Analysis

**Objective:** Machine-learned cross-file analysis using user's API key

### Deliverables

- [ ] `src/analyze/llm/llm_client.py` - OpenAI SDK wrapper
- [ ] `src/analyze/llm/prompt_loader.py` - Load prompts from manifest
- [ ] `src/analyze/llm/context_builder.py` - Build context window
- [ ] `src/analyze/llm/response_parser.py` - Parse findings from response
- [ ] `src/analyze/llm/fallback_handler.py` - Model fallback logic

### Technical Specifications

**LLM Client:**
```python
from openai import AsyncOpenAI
from typing import Optional

class LLMClient:
    def __init__(self, api_key: str, model: str, fallback_model: str):
        self.client = AsyncOpenAI(api_key=api_key)
        self.model = model
        self.fallback_model = fallback_model
    
    async def analyze(
        self,
        system_prompt: str,
        user_content: str,
        max_tokens: int = 4000
    ) -> tuple[str, dict]:
        """
        Run analysis with automatic fallback.
        Returns (response_text, usage_stats).
        """
        try:
            response = await self._call(self.model, system_prompt, user_content, max_tokens)
            return response
        except Exception as e:
            logger.warning(f"Primary model failed: {e}, trying fallback")
            response = await self._call(self.fallback_model, system_prompt, user_content, max_tokens)
            return response
    
    async def _call(self, model: str, system: str, user: str, max_tokens: int):
        response = await self.client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            max_tokens=max_tokens,
            temperature=0.1
        )
        return (
            response.choices[0].message.content,
            {
                "model": model,
                "tokens_in": response.usage.prompt_tokens,
                "tokens_out": response.usage.completion_tokens,
                "cost_usd": self._estimate_cost(model, response.usage)
            }
        )
```

**Context Builder:**
```python
def build_analysis_context(
    ingest: dict,
    scan_mode: str,
    deterministic_findings: list,
    diff_content: Optional[str] = None
) -> str:
    """
    Build context for LLM analysis.
    
    For pr-diff: Include diff + affected files + deterministic findings
    For deep/nightly: Include full file contents for hotspots + sample of other files
    """
    context_parts = []
    
    # Add repository summary
    context_parts.append(f"## Repository: {ingest['stats']['total_files']} files, {ingest['stats']['total_lines']} lines")
    
    # Add hotspots
    context_parts.append("## Risk Hotspots")
    for category, files in ingest['hotspots'].items():
        if files:
            context_parts.append(f"### {category}")
            for f in files[:5]:  # Limit per category
                content = read_file_bounded(f, max_lines=200)
                context_parts.append(f"```{f}\n{content}\n```")
    
    # Add deterministic findings as context
    if deterministic_findings:
        context_parts.append("## Deterministic Scanner Findings")
        for finding in deterministic_findings[:20]:
            context_parts.append(f"- {finding.severity}: {finding.message} in {finding.file_path}:{finding.line_start}")
    
    # For PR mode, add diff
    if scan_mode == "pr-diff" and diff_content:
        context_parts.append("## PR Diff")
        context_parts.append(f"```diff\n{diff_content[:50000]}\n```")
    
    return "\n\n".join(context_parts)
```

**Response Parser:**
```python
import json
import re

def parse_llm_findings(response_text: str) -> list[dict]:
    """
    Parse LLM response into structured findings.
    Expects findings in JSONL format within response.
    """
    findings = []
    
    # Try to extract JSONL block
    jsonl_match = re.search(r'```jsonl?\n(.*?)```', response_text, re.DOTALL)
    if jsonl_match:
        for line in jsonl_match.group(1).strip().split('\n'):
            try:
                finding = json.loads(line)
                # Validate required fields
                if all(k in finding for k in ['severity', 'category', 'file_path', 'message']):
                    findings.append(finding)
            except json.JSONDecodeError:
                continue
    
    return findings
```

### Acceptance Criteria

1. Graceful fallback when primary model fails
2. Token usage tracked accurately
3. Response parsing handles malformed output
4. Context stays within token limits

### Dependencies

- Phase 2.3 (deterministic findings available)

---

# PHASE 3: EVIDENCE & PACKAGING

## Phase 3.1: Finding Fingerprinting

**Objective:** Generate stable fingerprints for finding deduplication and tracking

### Deliverables

- [ ] `src/package/fingerprint.py` - Fingerprint computation
- [ ] Normalization functions for snippets
- [ ] Salt management for tenant isolation

### Technical Specifications

```python
import hashlib
import re

def normalize_snippet(snippet: str) -> str:
    """Normalize snippet for stable fingerprinting."""
    # Remove line numbers
    snippet = re.sub(r'^\s*\d+\s*[|:]?\s*', '', snippet, flags=re.MULTILINE)
    # Normalize whitespace
    snippet = re.sub(r'\s+', ' ', snippet)
    # Remove comments (basic)
    snippet = re.sub(r'//.*$', '', snippet, flags=re.MULTILINE)
    snippet = re.sub(r'/\*.*?\*/', '', snippet, flags=re.DOTALL)
    # Lowercase
    snippet = snippet.lower().strip()
    return snippet

def compute_fingerprint(
    category: str,
    severity: str,
    file_path: str,
    line_start: int,
    snippet: str,
    policy_version: str,
    tenant_salt: str = ""
) -> str:
    """Compute stable fingerprint for a finding."""
    normalized = normalize_snippet(snippet)
    components = f"{category}:{severity}:{file_path}:{line_start}:{normalized}:{policy_version}:{tenant_salt}"
    return hashlib.sha256(components.encode()).hexdigest()[:32]
```

### Acceptance Criteria

1. Same finding produces same fingerprint across runs
2. Different findings produce different fingerprints
3. Minor whitespace changes don't change fingerprint
4. Tenant salt prevents cross-tenant fingerprint comparison

### Dependencies

- Phase 2.4 (findings generated)

---

## Phase 3.2: PACK_SUMMARY Generation

**Objective:** Generate the contract summary artifact

### Deliverables

- [ ] `src/package/summary_writer.py` - Summary generation
- [ ] `src/package/artifact_hasher.py` - Hash computation
- [ ] Summary schema validation

### Technical Specifications

```python
import json
import hashlib
from datetime import datetime
from pathlib import Path

def write_pack_summary(
    run_id: str,
    dedupe_key: str,
    findings: list[dict],
    stages_completed: list[str],
    duration_ms: int,
    policy_pack: str,
    policy_version: str,
    tool_versions: dict,
    errors: list[str],
    output_dir: Path
) -> Path:
    """Write PACK_SUMMARY.json and return path."""
    
    # Write findings first
    findings_path = output_dir / "FINDINGS.jsonl"
    with open(findings_path, 'w') as f:
        for finding in findings:
            f.write(json.dumps(finding) + '\n')
    
    # Compute hash
    findings_hash = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    
    # Count by severity
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "total": len(findings)}
    for finding in findings:
        sev = finding.get("severity", "P3")
        if sev in counts:
            counts[sev] += 1
    
    # Build summary
    summary = {
        "schema_version": "1.0",
        "run_id": run_id,
        "dedupe_key": dedupe_key,
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "writer_complete": True,
        "counts": counts,
        "findings_file": "FINDINGS.jsonl",
        "findings_file_sha256": findings_hash,
        "policy_pack": policy_pack,
        "policy_pack_version": policy_version,
        "tool_versions": tool_versions,
        "stages_completed": stages_completed,
        "duration_ms": duration_ms,
        "errors": errors
    }
    
    summary_path = output_dir / "PACK_SUMMARY.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary_path
```

### Acceptance Criteria

1. Summary always written, even on 0 findings
2. Hash matches actual findings file
3. All required fields present
4. writer_complete=True only when fully written

### Dependencies

- Phase 3.1 (fingerprints computed)

---

## Phase 3.3: Human-Readable Report

**Objective:** Generate markdown report for artifacts

### Deliverables

- [ ] `src/package/report_generator.py` - Report generation
- [ ] Report template
- [ ] Finding formatting utilities

### Technical Specifications

```python
def generate_report(
    summary: dict,
    findings: list[dict],
    ingest: dict,
    config: OmarGateConfig
) -> str:
    """Generate human-readable markdown report."""
    
    lines = [
        f"# Omar Gate Audit Report",
        f"",
        f"**Run ID:** {summary['run_id']}",
        f"**Timestamp:** {summary['timestamp_utc']}",
        f"**Policy:** {summary['policy_pack']} v{summary['policy_pack_version']}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 P0 | {summary['counts']['P0']} |",
        f"| 🟠 P1 | {summary['counts']['P1']} |",
        f"| 🟡 P2 | {summary['counts']['P2']} |",
        f"| ⚪ P3 | {summary['counts']['P3']} |",
        f"| **Total** | {summary['counts']['total']} |",
        f"",
        f"## Repository",
        f"",
        f"- Files scanned: {ingest['stats']['in_scope_files']}",
        f"- Lines analyzed: {ingest['stats']['total_lines']}",
        f"- Hotspots identified: {sum(len(v) for v in ingest['hotspots'].values())}",
        f"",
    ]
    
    # Add findings by severity
    for severity in ["P0", "P1", "P2", "P3"]:
        sev_findings = [f for f in findings if f.get("severity") == severity]
        if sev_findings:
            lines.append(f"## {severity} Findings")
            lines.append("")
            for finding in sev_findings:
                lines.extend(format_finding(finding))
    
    return "\n".join(lines)
```

### Acceptance Criteria

1. Report readable by non-technical stakeholders
2. All findings included with evidence
3. Sensitive data (full snippets) appropriately bounded

### Dependencies

- Phase 3.2 (summary generated)

---

# PHASE 4: GATE & PUBLISHING

## Phase 4.1: Gate Evaluator

**Objective:** Local gate decision based on PACK_SUMMARY

### Deliverables

- [ ] `src/gate/evaluator.py` - Main evaluation logic
- [ ] `src/gate/summary_validator.py` - Summary validation
- [ ] `src/gate/policy.py` - Threshold application

### Technical Specifications

```python
from enum import Enum
from dataclasses import dataclass
from pathlib import Path

class GateStatus(Enum):
    PASSED = "passed"
    BLOCKED = "blocked"
    BYPASSED = "bypassed"
    NEEDS_APPROVAL = "needs_approval"
    ERROR = "error"

@dataclass
class GateResult:
    status: GateStatus
    reason: str
    counts: dict
    dedupe_key: str
    
def evaluate_gate(
    summary_path: Path,
    config: OmarGateConfig
) -> GateResult:
    """
    Evaluate gate decision from PACK_SUMMARY.
    
    This function MUST NOT make network calls.
    Gate decision is entirely local.
    """
    
    # 1. Validate summary exists
    if not summary_path.exists():
        return GateResult(
            status=GateStatus.ERROR,
            reason="FAIL-CLOSED: PACK_SUMMARY.json missing",
            counts={},
            dedupe_key=""
        )
    
    # 2. Parse and validate summary
    try:
        with open(summary_path) as f:
            summary = json.load(f)
    except json.JSONDecodeError as e:
        return GateResult(
            status=GateStatus.ERROR,
            reason=f"FAIL-CLOSED: PACK_SUMMARY.json corrupted: {e}",
            counts={},
            dedupe_key=""
        )
    
    # 3. Validate writer_complete
    if not summary.get("writer_complete", False):
        return GateResult(
            status=GateStatus.ERROR,
            reason="FAIL-CLOSED: Summary incomplete (writer_complete=false)",
            counts={},
            dedupe_key=""
        )
    
    # 4. Validate integrity
    findings_path = summary_path.parent / summary["findings_file"]
    if findings_path.exists():
        actual_hash = hashlib.sha256(findings_path.read_bytes()).hexdigest()
        if actual_hash != summary["findings_file_sha256"]:
            return GateResult(
                status=GateStatus.ERROR,
                reason="FAIL-CLOSED: Findings file hash mismatch",
                counts={},
                dedupe_key=""
            )
    
    # 5. Apply severity gate
    counts = summary["counts"]
    
    if config.severity_gate == "P0":
        blocked = counts["P0"] > 0
    elif config.severity_gate == "P1":
        blocked = counts["P0"] > 0 or counts["P1"] > 0
    elif config.severity_gate == "P2":
        blocked = counts["P0"] > 0 or counts["P1"] > 0 or counts["P2"] > 0
    else:
        blocked = False
    
    if blocked:
        return GateResult(
            status=GateStatus.BLOCKED,
            reason=f"Findings exceed threshold: P0={counts['P0']}, P1={counts['P1']}",
            counts=counts,
            dedupe_key=summary["dedupe_key"]
        )
    
    return GateResult(
        status=GateStatus.PASSED,
        reason=f"All checks passed: P0={counts['P0']}, P1={counts['P1']}",
        counts=counts,
        dedupe_key=summary["dedupe_key"]
    )
```

### Acceptance Criteria

1. No network calls during evaluation
2. Missing summary = BLOCKED
3. Corrupted summary = BLOCKED
4. Hash mismatch = BLOCKED
5. Threshold correctly applied

### Dependencies

- Phase 3.2 (summary exists)

---

## Phase 4.2: PR Comment Publisher

**Objective:** Create/update sticky PR comment with results

### Deliverables

- [ ] `src/publish/pr_comment.py` - Comment management
- [ ] `src/publish/comment_templates.py` - Template rendering
- [ ] Sticky comment detection (update vs create)

### Technical Specifications

**Comment Template:**
```python
# IMPORTANT: The marker line MUST be stable and never change format
# This enables idempotent comment updates (find + update vs spam new comments)

PR_COMMENT_TEMPLATE = """## 🛡️ Omar Gate: {status_badge}

**Result:** {result_line}
**Counts:** 🔴 P0={p0} • 🟠 P1={p1} • 🟡 P2={p2} • ⚪ P3={p3}
**Scan:** {scan_mode} • **Policy:** {policy_pack} • **Duration:** {duration} • **Est. cost:** ${cost:.2f}

{approval_section}

{findings_section}

---

### Next Steps

{next_steps}

<sub>Omar Gate v{version} • run_id={run_id} • dedupe={dedupe_key_short}</sub>

<!-- sentinellayer:omar-gate:v1:{repo}:{pr_number} -->
"""

# The marker line format:
# <!-- sentinellayer:omar-gate:v1:{repo}:{pr_number} -->
# 
# - "sentinellayer:omar-gate:v1" = stable prefix (never changes)
# - {repo} = repo identifier
# - {pr_number} = PR number
# 
# This allows finding the comment to update without parsing content.

def render_comment(
    gate_result: GateResult,
    top_findings: list[dict],
    config: OmarGateConfig,
    stats: dict
) -> str:
    """Render PR comment from gate result."""
    
    status_badge = {
        GateStatus.PASSED: "✅ PASSED",
        GateStatus.BLOCKED: "❌ BLOCKED",
        GateStatus.BYPASSED: "⚠️ BYPASSED",
        GateStatus.NEEDS_APPROVAL: "⏸️ NEEDS APPROVAL",
        GateStatus.ERROR: "🔴 ERROR"
    }[gate_result.status]
    
    # Render findings section
    findings_section = ""
    if top_findings:
        findings_section = "### Top Findings\n\n"
        for finding in top_findings[:3]:
            findings_section += render_finding(finding)
    
    # Render next steps based on status
    if gate_result.status == GateStatus.BLOCKED:
        next_steps = "Fix the findings above and push a new commit to re-run the scan."
    elif gate_result.status == GateStatus.NEEDS_APPROVAL:
        next_steps = f"Add label `{config.approval_label}` to approve this scan."
    else:
        next_steps = "All checks passed. This PR is ready for review."
    
    return PR_COMMENT_TEMPLATE.format(...)


async def publish_pr_comment(
    github_token: str,
    repo: str,
    pr_number: int,
    comment_body: str
):
    """
    Create or update sticky PR comment.
    
    Uses stable marker to find existing comment for idempotent updates.
    Marker format: <!-- sentinellayer:omar-gate:v1:{repo}:{pr_number} -->
    """
    
    # Build stable marker (never changes between runs for same PR)
    stable_marker = f"<!-- sentinellayer:omar-gate:v1:{repo}:{pr_number} -->"
    
    # Find existing comment by marker
    comments = await list_pr_comments(github_token, repo, pr_number)
    existing = None
    
    for comment in comments:
        if stable_marker in comment["body"]:
            existing = comment
            break
    
    if existing:
        await update_comment(github_token, repo, existing["id"], comment_body)
        logger.info("Updated existing PR comment", comment_id=existing["id"])
    else:
        await create_comment(github_token, repo, pr_number, comment_body)
        logger.info("Created new PR comment")
```

### Acceptance Criteria

1. Only one comment per PR (sticky)
2. Comment updates on subsequent runs
3. All status states render correctly
4. Findings collapsed in details tags

### Dependencies

- Phase 4.1 (gate result available)

---

## Phase 4.3: Check Run Publisher

**Objective:** Create GitHub Check Run with structured output

### Deliverables

- [ ] `src/publish/check_run.py` - Check Run API integration
- [ ] Structured output with annotations
- [ ] Conclusion mapping from gate status

### Technical Specifications

```python
async def publish_check_run(
    github_token: str,
    repo: str,
    head_sha: str,
    gate_result: GateResult,
    summary: dict,
    findings: list[dict]
):
    """Create GitHub Check Run with results."""
    
    # Map gate status to check conclusion
    conclusion_map = {
        GateStatus.PASSED: "success",
        GateStatus.BLOCKED: "failure",
        GateStatus.BYPASSED: "neutral",
        GateStatus.NEEDS_APPROVAL: "action_required",
        GateStatus.ERROR: "failure"
    }
    
    # Build annotations from findings
    annotations = []
    for finding in findings[:50]:  # GitHub limit
        annotations.append({
            "path": finding["file_path"],
            "start_line": finding["line_start"],
            "end_line": finding.get("line_end", finding["line_start"]),
            "annotation_level": severity_to_level(finding["severity"]),
            "title": f"{finding['severity']}: {finding['category']}",
            "message": finding["message"]
        })
    
    # Create check run
    await create_check_run(
        github_token,
        repo,
        name="Omar Gate",
        head_sha=head_sha,
        conclusion=conclusion_map[gate_result.status],
        title=f"Omar Gate: {gate_result.status.value}",
        summary=f"P0={summary['counts']['P0']}, P1={summary['counts']['P1']}, P2={summary['counts']['P2']}, P3={summary['counts']['P3']}",
        text=gate_result.reason,
        annotations=annotations,
        # Embed dedupe key for future lookups
        external_id=summary["dedupe_key"]
    )
```

### Acceptance Criteria

1. Check Run visible in PR
2. Annotations appear on correct lines
3. Dedupe key embedded for future lookups
4. Conclusion matches gate status

### Dependencies

- Phase 4.1 (gate result available)

---

# PHASE 5: TELEMETRY SYSTEM

## Phase 5.1: Telemetry Collector

**Objective:** Collect metrics throughout the run

### Deliverables

- [ ] `src/telemetry/collector.py` - Metrics collection
- [ ] `src/telemetry/schemas.py` - Payload schemas
- [ ] Stage timing utilities

### Technical Specifications

```python
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class TelemetryCollector:
    run_id: str
    repo_hash: str  # SHA256 of repo name
    
    # Timing
    stages: dict = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.utcnow)
    
    # Costs
    tokens_in: int = 0
    tokens_out: int = 0
    estimated_cost_usd: float = 0.0
    model_used: Optional[str] = None
    
    # Results
    gate_status: Optional[str] = None
    counts: dict = field(default_factory=dict)
    
    # Preflight
    dedupe_skipped: bool = False
    rate_limit_skipped: bool = False
    approval_state: Optional[str] = None
    fork_mode: Optional[str] = None
    
    def stage_start(self, stage: str):
        self.stages[stage] = {"start": datetime.utcnow()}
    
    def stage_end(self, stage: str, success: bool = True):
        if stage in self.stages:
            self.stages[stage]["end"] = datetime.utcnow()
            self.stages[stage]["success"] = success
            self.stages[stage]["duration_ms"] = int(
                (self.stages[stage]["end"] - self.stages[stage]["start"]).total_seconds() * 1000
            )
    
    def to_tier1_payload(self) -> dict:
        """Generate Tier 1 (anonymous) telemetry payload."""
        return {
            "schema_version": "1.0",
            "tier": 1,
            "run": {
                "run_id": self.run_id,
                "timestamp_utc": self.start_time.isoformat() + "Z",
                "duration_ms": self._total_duration_ms(),
                "state": self.gate_status
            },
            "repo": {
                "repo_hash": self.repo_hash,
                # No name, no owner, no identifiable info
            },
            "scan": {
                "model_used": self.model_used,
                "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out,
                "cost_estimate_usd": self.estimated_cost_usd
            },
            "findings": self.counts,
            "gate": {
                "result": self.gate_status,
                "dedupe_skipped": self.dedupe_skipped,
                "rate_limit_skipped": self.rate_limit_skipped
            },
            "stages": {
                name: data.get("duration_ms", 0) 
                for name, data in self.stages.items()
            }
        }
```

### Acceptance Criteria

1. All stages timed accurately
2. Tier 1 payload contains no identifying info
3. Cost tracking accurate
4. Missing stages don't crash collector

### Dependencies

- Phase 1.3 (logging available)

---

## Phase 5.2: Telemetry Uploader

**Objective:** Best-effort upload to PlexAura

### Deliverables

- [ ] `src/telemetry/uploader.py` - API upload
- [ ] `src/telemetry/consent.py` - Consent enforcement
- [ ] Retry with backoff
- [ ] Graceful failure handling

### Technical Specifications

### 5.2.0 GitHub OIDC Token Acquisition (Docker Action)

If the customer workflow grants `permissions: id-token: write`, GitHub exposes two environment variables to the Action runtime:

- `ACTIONS_ID_TOKEN_REQUEST_URL`
- `ACTIONS_ID_TOKEN_REQUEST_TOKEN`

The Action can mint an OIDC JWT by calling the request URL with an `audience` that matches the PlexAura verifier (recommended audience: `https://api.sentinellayer.com`).

**Implementation (Python example):**

```python
import os
import urllib.parse
import requests
from typing import Optional

def get_github_oidc_token(audience: str) -> Optional[str]:
    url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    req_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not req_token:
        return None

    full_url = f"{url}&audience={urllib.parse.quote(audience)}"
    resp = requests.get(
        full_url,
        headers={"Authorization": f"Bearer {req_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("value")
```

**Failure behavior:** If OIDC variables are missing or token minting fails, the uploader MUST fall back to:
1) `PLEXAURA_TOKEN` (if provided), else
2) anonymous Tier 1 telemetry (no auth), else
3) skip upload with a warning.

Gate correctness MUST NOT depend on successful OIDC minting.


```python
import aiohttp
from typing import Optional

PLEXAURA_API_URL = "https://api.sentinellayer.com"

async def upload_telemetry(
    payload: dict,
    plexaura_token: Optional[str],
    oidc_token: Optional[str],
    config: OmarGateConfig
) -> bool:
    """
    Upload telemetry to PlexAura.
    
    Returns True if successful, False otherwise.
    Failures are logged but do not affect gate.
    """
    
    # Check consent
    if not config.telemetry:
        logger.info("Telemetry disabled by config")
        return False
    
    # Determine auth header
    if oidc_token:
        headers = {"Authorization": f"Bearer {oidc_token}"}
    elif plexaura_token:
        headers = {"Authorization": f"Bearer {plexaura_token}"}
    else:
        # Anonymous upload (Tier 1 only)
        headers = {}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{PLEXAURA_API_URL}/api/v1/telemetry",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    logger.info("Telemetry uploaded successfully")
                    return True
                else:
                    logger.warning(f"Telemetry upload failed: {resp.status}")
                    return False
    except Exception as e:
        logger.warning(f"Telemetry upload error: {e}")
        return False
```

### Acceptance Criteria

1. Upload timeout is bounded (10s)
2. Failures don't affect gate
3. OIDC preferred over token
4. Consent flag respected

### Dependencies

- Phase 5.1 (collector available)

---

# PHASE 6: PLEXAURA API

## Phase 6.0: API Foundation Standards (P0)

**Objective:** Establish consistent API patterns before building any endpoints

### 6.0.1 Error Schema (MANDATORY)

All API errors MUST follow this envelope:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Retry after 60 seconds.",
    "details": {
      "limit": 100,
      "window_seconds": 3600,
      "retry_after": 60
    },
    "request_id": "req_abc123xyz"
  }
}
```

**Required fields:**
- `code`: Machine-readable error code (SCREAMING_SNAKE_CASE)
- `message`: Human-readable description
- `request_id`: Unique identifier for this request (for debugging/support)

**Optional fields:**
- `details`: Additional context (varies by error type)

### 6.0.2 Request ID (MANDATORY)

Every request MUST:
1. Generate a unique `request_id` (UUID or prefixed ID like `req_xxx`)
2. Include `request_id` in all log entries for this request
3. Return `request_id` in response headers (`X-Request-ID`)
4. Return `request_id` in error responses

```python
# middleware/request_id.py
import uuid
from fastapi import Request

async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response
```

### 6.0.3 Rate Limiting (FAIL-CLOSED)

Per SWE Excellence Framework: rate limiting must fail closed.

```python
async def check_rate_limit(request: Request) -> bool:
    """
    Check rate limit. If limiter store (Redis) is unavailable,
    FAIL CLOSED (reject request) rather than fail open.
    """
    try:
        # Check Redis/limiter
        allowed = await limiter.is_allowed(request.client.host)
        return allowed
    except Exception as e:
        # FAIL CLOSED: If we can't check, assume limit exceeded
        logger.error(f"Rate limiter unavailable: {e}", request_id=request.state.request_id)
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "RATE_LIMITER_UNAVAILABLE",
                    "message": "Service temporarily unavailable. Please retry.",
                    "request_id": request.state.request_id
                }
            }
        )
```

### 6.0.4 External Service Resilience

Default timeouts and retry policies for all external services:

| Service | Timeout | Retries | Circuit Breaker |
|---------|---------|---------|-----------------|
| OpenAI API | 60s | 2 | 5 failures / 60s |
| S3 | 30s | 3 | 10 failures / 60s |
| GitHub API | 10s | 2 | 5 failures / 60s |
| Stripe (future) | 30s | 0 | N/A (webhook-driven) |

## Phase 6.1: API Foundation

**Objective:** FastAPI application with auth

### Deliverables

- [ ] FastAPI app structure
- [ ] GitHub OAuth flow
- [ ] OIDC token verification
- [ ] Database connection

### Dependencies

- None (parallel workstream)

---

## Phase 6.2: Telemetry Endpoints

**Objective:** Ingest telemetry from Actions

### Deliverables

- [ ] POST /api/v1/telemetry
- [ ] Idempotency handling
- [ ] TimescaleDB storage

---

## Phase 6.3: Run Management

**Objective:** CRUD for runs

### Deliverables

- [ ] GET /api/v1/runs
- [ ] GET /api/v1/runs/{run_id}
- [ ] Filtering and pagination

---

## Phase 6.4: Artifact Storage

**Objective:** S3 artifact upload/download

### Deliverables

- [ ] POST /api/v1/artifacts/upload
- [ ] Presigned URL generation
- [ ] Encryption (SSE-KMS)

---

## Phase 6.5: Public Stats

**Objective:** Anonymous aggregate metrics

### Deliverables

- [ ] GET /api/v1/public/stats
- [ ] Caching layer
- [ ] Rate limiting

---

## Phase 6.6: Deletion Endpoints (Async by Design)

**Objective:** GDPR/CCPA compliance with async deletion for scale

### Why Async?

At scale, deletion cascades through:
- Telemetry records (potentially millions)
- S3 artifacts (multiple objects per run)
- Derived analytics
- Training datasets (if consented)

Synchronous deletion becomes slow/flaky. Design for async from day 1.

### Deliverables

- [ ] DELETE /api/v1/user → Returns 202 Accepted + deletion_job_id
- [ ] DELETE /api/v1/repos/{repo_id} → Returns 202 Accepted + deletion_job_id
- [ ] DELETE /api/v1/runs/{run_id} → Returns 202 Accepted + deletion_job_id
- [ ] GET /api/v1/deletion-jobs/{job_id} → Check deletion status
- [ ] Background deletion worker
- [ ] Tombstone records for audit trail

### Technical Specification

```python
# routes/deletion.py

@router.delete("/api/v1/user")
async def delete_user(request: Request, current_user: User = Depends(get_current_user)):
    """
    Request deletion of all user data.
    Returns immediately with job ID. Actual deletion happens async.
    """
    job_id = f"del_{uuid.uuid4().hex[:12]}"
    
    # Create deletion job
    await create_deletion_job(
        job_id=job_id,
        job_type="user_deletion",
        target_id=current_user.id,
        requested_by=current_user.id,
        request_id=request.state.request_id
    )
    
    # Queue background task
    await deletion_queue.enqueue(job_id)
    
    return JSONResponse(
        status_code=202,
        content={
            "status": "accepted",
            "message": "Deletion requested. This may take several minutes.",
            "deletion_job_id": job_id,
            "check_status_url": f"/api/v1/deletion-jobs/{job_id}",
            "request_id": request.state.request_id
        }
    )


# workers/deletion_worker.py

async def process_deletion_job(job_id: str):
    """
    Background worker for cascade deletion.
    
    Order matters:
    1. Delete Tier 3 artifacts (S3)
    2. Delete Tier 2 metadata (Postgres)
    3. Delete Tier 1 telemetry (TimescaleDB)
    4. Delete user record
    5. Create tombstone record
    6. Notify user (email)
    """
    job = await get_deletion_job(job_id)
    
    try:
        # Step 1: S3 artifacts
        await delete_s3_artifacts_for_user(job.target_id)
        await update_job_progress(job_id, "artifacts_deleted")
        
        # Step 2: Metadata
        await delete_metadata_for_user(job.target_id)
        await update_job_progress(job_id, "metadata_deleted")
        
        # Step 3: Telemetry (Tier 1 is anonymous - we keep aggregates)
        # Note: Tier 1 aggregates are not deleted because they contain
        # no identifying information. Document this in privacy policy.
        await delete_tier2_telemetry_for_user(job.target_id)
        await update_job_progress(job_id, "telemetry_deleted")
        
        # Step 4: User record
        await delete_user_record(job.target_id)
        
        # Step 5: Tombstone
        await create_tombstone(
            original_id=job.target_id,
            deletion_job_id=job_id,
            deleted_at=datetime.utcnow()
        )
        
        # Step 6: Complete
        await complete_deletion_job(job_id, success=True)
        
    except Exception as e:
        await complete_deletion_job(job_id, success=False, error=str(e))
        raise
```

### Acceptance Criteria

1. All DELETE endpoints return 202 Accepted (not 200 OK)
2. Deletion completes within 24 hours for any user
3. Tombstone records maintained for 7 years (legal requirement)
4. Tier 1 aggregates explicitly documented as non-deleted (anonymous)
5. User receives email when deletion completes

---

# PHASE 7: DASHBOARD MVP

## Phase 7.1: Auth Flow

- [ ] GitHub OAuth sign-in
- [ ] Session management
- [ ] Repo claim flow

## Phase 7.2: Runs List

- [ ] Display linked repos
- [ ] Show run history
- [ ] Filter/sort

## Phase 7.3: Run Detail

- [ ] Show findings
- [ ] Show summary
- [ ] Download artifacts

## Phase 7.4: Public Stats Page

- [ ] sentinellayer.com/stats
- [ ] Real-time counters
- [ ] Marketing copy

---

# PHASE 8: HITL SERVICE

## Phase 8.1: Request Flow

- [ ] "Request Expert Review" button
- [ ] Onboarding agent integration
- [ ] Scope estimation

## Phase 8.2: Queue Management

- [ ] Internal ticket creation
- [ ] SLA timers
- [ ] Assignment

## Phase 8.3: Reviewer Workspace

- [ ] Artifact viewer
- [ ] Findings browser
- [ ] Deliverable editor

## Phase 8.4: Notifications

- [ ] Email on completion
- [ ] PR comment on completion
- [ ] Slack integration

---

# PHASE 9: FIXERS

## Phase 9.1: Deterministic Fixer (Self-Contained)

**Objective:** Ship safe, self-contained formatting fixes that don't require running repo scripts

**CRITICAL CONSTRAINT:** This phase must NOT violate the "never run repo scripts" principle from abuse hardening.

### Safe Day-1 Approach

**DO ship (self-contained in container):**
- [ ] Prettier (pinned version, bundled in container, uses default config)
- [ ] Import sorting via AST manipulation (not eslint)
- [ ] Trivial JSON/YAML formatting
- [ ] Trailing whitespace removal

**DO NOT ship yet (requires npm install or repo scripts):**
- ESLint with project config (needs node_modules)
- Project-specific formatters
- Any tool requiring `npm install` or `pnpm install`

### Future "Project-Native" Mode (Phase 9.1b, Model 3 only)

When you have sandboxed infrastructure (Model 3), you can offer:
- [ ] Safe install mode (`npm install --ignore-scripts --no-optional`)
- [ ] ESLint with project config
- [ ] Explicit user opt-in with big warning

**This is deferred to Model 3 because:**
1. Model 2 runs on customer's runner (we can't enforce egress controls)
2. `npm install` can trigger malicious postinstall scripts
3. Consistent security posture is more important than convenience

### Implementation

```python
# src/fix/deterministic_fixer.py

class SelfContainedFixer:
    """
    Fixer that uses only bundled tools.
    Never runs npm/pnpm/yarn install.
    Never executes repo scripts.
    """
    
    SUPPORTED_FIXES = {
        "prettier_format": {
            "extensions": [".js", ".ts", ".jsx", ".tsx", ".json", ".md"],
            "tool": "/app/node_modules/.bin/prettier",  # Bundled in container
            "args": ["--write"]
        },
        "trailing_whitespace": {
            "extensions": ["*"],
            "builtin": True
        },
        "eof_newline": {
            "extensions": ["*"],
            "builtin": True
        }
    }
    
    def can_fix(self, file_path: str, fix_type: str) -> bool:
        """Check if we can safely fix this file."""
        if fix_type not in self.SUPPORTED_FIXES:
            return False
        
        # Never touch these regardless
        if any(p in file_path for p in [
            "node_modules", ".git", "vendor",
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock"
        ]):
            return False
        
        return True
    
    def apply_fix(self, file_path: str, fix_type: str) -> FixResult:
        """Apply fix using only bundled tools."""
        # Implementation uses subprocess with bundled tools only
        pass
```

### Acceptance Criteria

1. Fixer NEVER runs `npm install`, `pnpm install`, or any package manager
2. Fixer NEVER executes scripts from the repo
3. All tools are bundled in the container image
4. Fixer works offline (no network required except to report results)

## Phase 9.2: LLM Patch Generator

- [ ] Patch artifact generation
- [ ] Fix plan generation
- [ ] Risk assessment

---

# PHASE 10: PRODUCTION HARDENING

## Phase 10.1: Supply Chain

- [ ] Versioned releases
- [ ] SBOM generation
- [ ] Checksum publishing

## Phase 10.2: Monitoring

- [ ] Datadog/Sentry integration
- [ ] SLO dashboards
- [ ] Alerting

## Phase 10.3: Security Audit

- [ ] Self-scan with Omar
- [ ] Penetration testing
- [ ] Dependency audit

---

# APPENDIX: SCHEMAS

## A.1 PACK_SUMMARY.json

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["schema_version", "run_id", "dedupe_key", "timestamp_utc", "writer_complete", "counts", "findings_file", "findings_file_sha256", "policy_pack", "stages_completed"],
  "properties": {
    "schema_version": { "type": "string" },
    "run_id": { "type": "string", "format": "uuid" },
    "dedupe_key": { "type": "string" },
    "timestamp_utc": { "type": "string", "format": "date-time" },
    "writer_complete": { "type": "boolean" },
    "counts": {
      "type": "object",
      "properties": {
        "P0": { "type": "integer" },
        "P1": { "type": "integer" },
        "P2": { "type": "integer" },
        "P3": { "type": "integer" },
        "total": { "type": "integer" }
      }
    },
    "findings_file": { "type": "string" },
    "findings_file_sha256": { "type": "string" },
    "policy_pack": { "type": "string" },
    "policy_pack_version": { "type": "string" },
    "tool_versions": { "type": "object" },
    "stages_completed": { "type": "array", "items": { "type": "string" } },
    "duration_ms": { "type": "integer" },
    "errors": { "type": "array", "items": { "type": "string" } }
  }
}
```

## A.2 Finding Schema (JSONL entries)

```json
{
  "type": "object",
  "required": ["id", "severity", "category", "file_path", "line_start", "message"],
  "properties": {
    "id": { "type": "string" },
    "fingerprint": { "type": "string" },
    "severity": { "enum": ["P0", "P1", "P2", "P3"] },
    "category": { "type": "string" },
    "file_path": { "type": "string" },
    "line_start": { "type": "integer" },
    "line_end": { "type": "integer" },
    "snippet": { "type": "string", "maxLength": 500 },
    "message": { "type": "string" },
    "recommendation": { "type": "string" },
    "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
    "source": { "enum": ["deterministic", "llm"] }
  }
}
```

## A.3 Tier 1 Telemetry Schema

```json
{
  "type": "object",
  "properties": {
    "schema_version": { "type": "string" },
    "tier": { "const": 1 },
    "run": {
      "type": "object",
      "properties": {
        "run_id": { "type": "string" },
        "timestamp_utc": { "type": "string" },
        "duration_ms": { "type": "integer" },
        "state": { "type": "string" }
      }
    },
    "repo": {
      "type": "object",
      "properties": {
        "repo_hash": { "type": "string" }
      }
    },
    "scan": {
      "type": "object",
      "properties": {
        "model_used": { "type": "string" },
        "tokens_in": { "type": "integer" },
        "tokens_out": { "type": "integer" },
        "cost_estimate_usd": { "type": "number" }
      }
    },
    "findings": {
      "type": "object",
      "properties": {
        "P0": { "type": "integer" },
        "P1": { "type": "integer" },
        "P2": { "type": "integer" },
        "P3": { "type": "integer" },
        "total": { "type": "integer" }
      }
    },
    "gate": {
      "type": "object",
      "properties": {
        "result": { "type": "string" },
        "dedupe_skipped": { "type": "boolean" },
        "rate_limit_skipped": { "type": "boolean" }
      }
    },
    "stages": { "type": "object" }
  }
}
```

---

## A.4 Tier 2 Telemetry Schema (Findings Metadata)

Tier 2 is **opt-in** and is required for per-repo dashboards, run history, “fixed vs resurfaced” metrics, and HITL scoping. Tier 2 includes **repo identity + minimal finding metadata**, but still avoids full code snippets by default.

```json
{
  "$schema": "https://sentinellayer.com/schemas/telemetry-v1.json",
  "version": "1.0",
  "tier": 2,
  "run": {
    "run_id": "uuid-v4",
    "timestamp_utc": "2026-02-03T15:30:00Z",
    "duration_ms": 45000,
    "state": "BLOCKED"
  },
  "repo": {
    "owner": "acme-corp",
    "name": "web-app",
    "default_branch": "main",
    "branch": "feature/auth-fix",
    "pr_number": 42,
    "head_sha": "40-char-sha",
    "is_fork_pr": false
  },
  "scan": {
    "mode": "pr-diff",
    "policy_pack": "omar_gate",
    "policy_pack_version": "2026.02.03",
    "model_used": "gpt-4o",
    "tokens_in": 15000,
    "tokens_out": 3200,
    "cost_estimate_usd": 0.42
  },
  "findings": {
    "summary": [
      {
        "finding_id": "AUTH_BYPASS_001",
        "severity": "P0",
        "category": "Auth Bypass",
        "file_path": "src/routes/admin.ts",
        "line_start": 42,
        "line_end": 58,
        "fingerprint": "sha256-hex",
        "confidence": 0.82
      }
    ],
    "counts": { "P0": 1, "P1": 1, "P2": 3, "P3": 7, "total": 12 }
  },
  "gate": {
    "severity_threshold": "P1",
    "result": "blocked",
    "bypass_reason": null
  },
  "meta": {
    "action_version": "1.2.0",
    "telemetry_tier": 2,
    "request_id": "req_...",
    "idempotency_key": "sha256-hex"
  }
}
```

## A.5 Tier 3 Artifact Manifest Schema (Full Artifacts)

Tier 3 is **opt-in** and typically required for HITL. Tier 3 uploads are stored in S3 under a per-tenant prefix. A manifest makes artifact retrieval deterministic and auditable.

```json
{
  "schema_version": "1.0",
  "tenant_id": "uuid",
  "repo_id": "uuid",
  "run_id": "uuid",
  "artifact_root": "s3://sentinellayer-artifacts/{tenant_id}/{repo_id}/{run_id}/",
  "uploaded_at_utc": "2026-02-03T15:31:10Z",
  "objects": [
    {
      "name": "PACK_SUMMARY.json",
      "sha256": "sha256-hex",
      "content_type": "application/json",
      "bytes": 2048
    },
    {
      "name": "FINDINGS.jsonl",
      "sha256": "sha256-hex",
      "content_type": "application/jsonl",
      "bytes": 84219
    },
    {
      "name": "AUDIT_REPORT.md",
      "sha256": "sha256-hex",
      "content_type": "text/markdown",
      "bytes": 133701
    },
    {
      "name": "STATE_LOG.json",
      "sha256": "sha256-hex",
      "content_type": "application/json",
      "bytes": 14871
    }
  ],
  "retention_days": 90,
  "encryption": {
    "mode": "SSE-KMS",
    "kms_key_id": "arn:aws:kms:..."
  }
}
```

## A.6 Tier 4 Training Consent (Separate Opt-in) + Dataset Governance

If you intend to use customer artifacts to improve models or prompts, Tier 4 must be **separate opt-in** (not bundled with dashboard/HITL consent).

**Tier 4 rules (MUST):**
- Explicit UI toggle: “Allow de-identified artifacts to improve SentinelLayer.”
- Ability to revoke at any time.
- A revocation workflow that **stops future use** and **removes/suppresses** previously contributed artifacts from training datasets (to the extent technically feasible).
- De-identification pipeline: strip repo identifiers, normalize file paths, remove secrets/keys, redact emails/usernames, and apply conservative snippet trimming by default.
- License hygiene: track repository license metadata; exclude artifacts from repos whose licenses prohibit this use (or require explicit additional consent).
- Storage separation: training-eligible artifacts stored in a separate bucket/prefix with stricter access controls and audit logs.

**Recommended posture (trust-first):**
- Tier 1 telemetry = opt-out.
- Tier 2/3 artifacts = opt-in.
- Tier 4 training = opt-in + explicit explanation + separate terms.


# APPENDIX B — SWE Excellence Framework Integration Map (Model 3 / Premium)

The attached SWE Excellence framework can be integrated as a **policy pack family** (quality + reliability + performance) alongside security packs.

## B.1 Recommended Mapping

| SWE Excellence Domain | SentinelLayer Pack Type | Example Outputs |
|---|---|---|
| Reliability & Resilience | `maya_resilience_pack` | timeouts/retries/circuit breakers, failure-mode tests, SLO checks |
| Security & Privacy | `nina_security_pack` | authz, secrets, injection, data handling, threat model |
| CI/CD & Release | `omar_release_pack` | fail-closed gates, supply chain, signing, deterministic builds |
| Performance & Accessibility | `sofia_web_quality_pack` | Lighthouse thresholds, bundle size, a11y violations |
| Maintainability | `kat_maintainability_pack` | dependency health, code smells, refactors (non-breaking) |
| AI Safety (LLM Apps) | `amina_ai_safety_pack` | prompt injection defenses, tool constraints, cost controls |

## B.2 Model 3 Extensions Enabled by This Map
- Multi-pack orchestration with cross-pack escalation and conflict resolution.
- SWE Excellence Scorecard output (weighted composite score) computed from pack scorecards.
- HITL Gate 1/2/3 integration using the same evidence contract (PACK_SUMMARY + evidence bundles).

**END OF REQUIREMENTS DOCUMENT**

*This document is for internal use by PlexAura engineering and AI coding agents.*