# SentinelLayer v1 — Build Prompt for Codex

## Context

You are working on `sentinellayer-v1-action`, a Python-based GitHub Action that performs AI-powered security scanning on pull requests. The action already has a working foundation:

**Already implemented:**
- Codebase ingest system (file classification, hotspot detection, dependency detection)
- Deterministic scanners (pattern_scanner, secret_scanner, config_scanner with 30+ rules)
- LLM analysis via OpenAI Responses API (gpt-5.2-codex primary, gpt-4.1 fallback)
- Gate evaluation (fail-closed, severity-based P0/P1/P2 blocking)
- Artifact generation (FINDINGS.jsonl, PACK_SUMMARY.json, AUDIT_REPORT.md, REVIEW_BRIEF.md)
- GitHub integration (PR comments, Check Runs, idempotent markers)
- Telemetry (3-tier opt-in), preflight checks (dedupe, rate limit, fork, cost)
- 131 passing tests (unit + integration)

**Your job:** Build the 6 components below that make this a v1 banger release. Do NOT modify any existing working code unless explicitly required for integration. Add new modules and wire them into the existing orchestrator.

---

## TASK 1: Quick Learn — Lightweight Codebase Context Extraction

### What
Before any analysis runs, extract a concise project context summary from the target repository. This gives the LLM (and Codex) enough understanding to assess code changes intelligently without bloating the context window.

### Where
Create `src/omargate/ingest/quick_learn.py`

### Requirements

1. **Find the best doc to read** (in priority order):
   - `README.md` (root)
   - `README` (no extension)
   - `docs/README.md`
   - `CONTRIBUTING.md`
   - `package.json` (name, description, scripts keys only)
   - `pyproject.toml` ([project] section only)
   - `Cargo.toml` ([package] section only)

2. **Extract essentials only** (max 600 tokens total):
   - Project name and one-line description
   - Tech stack (framework, language, runtime)
   - Architecture pattern if stated (monorepo, microservices, serverless, etc.)
   - Key entry points mentioned (e.g., "main server is in src/server.ts")
   - DO NOT include: badges, license text, installation instructions, contributing guidelines, verbose examples

3. **Output a `QuickLearnSummary` dataclass:**
   ```python
   @dataclass
   class QuickLearnSummary:
       project_name: str
       description: str  # max 100 chars
       tech_stack: list[str]  # e.g., ["Next.js", "TypeScript", "Prisma", "PostgreSQL"]
       architecture: str  # e.g., "monorepo", "monolith", "microservices", "unknown"
       entry_points: list[str]  # e.g., ["src/app/", "src/server/"]
       source_doc: str  # which file was read
       raw_excerpt: str  # the trimmed excerpt (max 600 tokens worth)
   ```

4. **Extraction strategy:**
   - Read the first 80 lines of README.md (covers most project summaries)
   - Parse `package.json` / `pyproject.toml` for structured metadata
   - Use simple heuristics (regex for framework names, not LLM) to detect tech stack
   - If README is clearly outdated (mentions deprecated tech, broken links), fall back to package manifest

5. **Integration point:** Called at the start of `orchestrator.py` before deterministic scan. The summary is passed to the LLM context builder to prepend as project context.

### Tests
Create `tests/unit/test_quick_learn.py` with:
- Test: README with standard project description extracts correctly
- Test: package.json fallback when no README
- Test: Truncation at 600 tokens
- Test: Empty/missing docs returns sensible defaults

---

## TASK 2: Engineering Quality Scanner (Stack-Aware)

### What
Add a new deterministic scanner that detects engineering anti-patterns based on the detected tech stack. These rules are baked directly into Python code — NO external JSON pattern file, NO framework document shipped. The knowledge is embedded in the scanner logic itself so it cannot be trivially extracted or reverse-engineered.

### Where
- New scanner: `src/omargate/analyze/deterministic/eng_quality_scanner.py`
- **NO new pattern JSON file** — all rules are inline in the Python module

### Why Inline (Not JSON)
The pattern JSON files (`security.json`, `quality.json`, `ci_cd.json`) are human-readable and easily copied. The engineering quality rules represent proprietary detection logic. By embedding them as compiled regex + contextual checks in Python, we:
- Make extraction harder (code, not config)
- Enable multi-line / contextual checks that JSON patterns can't express
- Allow stack-aware filtering (only run React rules on React projects)

### Rules to Implement

Implement as private methods in an `EngQualityScanner` class. Each method returns `list[Finding]`. Category should be generic (e.g., `"frontend"`, `"backend"`, `"infrastructure"`, `"quality"`) — do NOT use any identifier that references an external framework.

**Frontend rules** (only when tech_stack includes React/Next.js/Vue/Angular):
- State updates in loops (forEach/map calling setState) → P2
- useEffect without cleanup return → P2
- dangerouslySetInnerHTML usage → P1
- Inline object/function literals in JSX props → P3
- console.log in production source files (not test files) → P3
- Empty useEffect dependency array referencing outer state → P2

**Backend reliability rules** (only when tech_stack includes Node/Express/Django/FastAPI/Go):
- N+1 query patterns (await inside for-loop body with DB calls) → P1
- eval() or Function() constructor → P0
- SQL string concatenation (query + variable) → P0
- Hardcoded large timeouts (setTimeout with 5+ digit ms values) → P3
- Auth route handlers without rate limiting middleware → P1
- fetch/axios/httpx calls without timeout configuration → P2
- Unbounded retry loops (retry without max attempts or backoff) → P1
- Rate limiting that fails open (catch block returns allow) → P1
- Write/mutation endpoints without idempotency key handling → P2
- Missing error response schema consistency (no requestId pattern) → P3
- External service calls without circuit breaker or fallback → P2

**Infrastructure rules** (always run):
- Dockerfile without USER directive (running as root) → P2
- Terraform files without remote backend block → P2
- .env file committed (not .env.example or .env.template) → P0
- Hardcoded secrets in CI/CD workflow YAML → P0
- Missing health check endpoint in server code → P2

### Architecture

```python
class EngQualityScanner:
    """Stack-aware engineering quality scanner."""

    def __init__(self, tech_stack: list[str]):
        self.tech_stack = [t.lower() for t in tech_stack]

    def scan(self, files: dict[str, str]) -> list[Finding]:
        """Scan file contents and return findings."""
        findings = []
        if self._has_frontend():
            findings.extend(self._scan_frontend(files))
        if self._has_backend():
            findings.extend(self._scan_backend(files))
        findings.extend(self._scan_infrastructure(files))
        return findings
```

- Accept `QuickLearnSummary.tech_stack` to decide which rule sets apply
- Use the same `Finding` dataclass as existing scanners
- Source: `"deterministic"`
- Pattern IDs: use opaque short codes (e.g., `EQ-001` through `EQ-018`) — do NOT name them after any framework section

### Integration
Wire into `orchestrator.py` alongside existing deterministic scanners. Run after pattern/secret/config scanners. Pass `quick_learn.tech_stack` to constructor.

### Tests
Create `tests/unit/test_eng_quality_scanner.py`:
- Test: React project triggers frontend rules, Python project does not
- Test: eval() detected as P0
- Test: Dockerfile without USER detected as P2
- Test: .env file (not .env.example) detected as P0
- Test: N+1 query pattern in loop detected
- Test: console.log in test file is NOT flagged

---

## TASK 3: Codex CLI Integration (Omar Pack Deep Audit)

### What
Install and invoke the `@openai/codex` CLI on the GitHub Actions runner for deep agentic code review. This is the differentiator — Codex operates as an autonomous agent that reads, navigates, and reasons about code in ways a single API call cannot.

### Where
- New module: `src/omargate/analyze/codex/codex_runner.py`
- New module: `src/omargate/analyze/codex/codex_prompt_builder.py`
- Update: `action.yml` (new inputs)
- Update: `orchestrator.py` (wire in Codex stage)

### Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Quick Learn  │────▶│ Build Codex  │────▶│ codex exec      │
│ Summary      │     │ Prompt       │     │ --model gpt-5.2 │
└─────────────┘     └──────────────┘     │ --sandbox ...   │
                          ▲               └────────┬────────┘
                          │                        │
                    ┌─────┴──────┐          ┌──────▼──────┐
                    │ Det scan   │          │ Parse JSONL  │
                    │ findings   │          │ output       │
                    └────────────┘          └─────────────┘
```

### Requirements

1. **Codex installation** (in action workflow):
   ```yaml
   - name: Install Codex CLI
     run: npm install -g @openai/codex
   ```
   Add to action.yml or document as prerequisite.

2. **`codex_runner.py`:**
   ```python
   class CodexRunner:
       def __init__(self, api_key: str, model: str = "gpt-5.2-codex"):
           ...

       async def run_audit(
           self,
           prompt: str,
           working_dir: str,
           sandbox: str = "read-only",
           timeout: int = 300,
       ) -> CodexResult:
           """
           Execute `codex exec` with the given prompt.

           Returns parsed findings from Codex output.
           """
   ```

   - Invoke via `asyncio.create_subprocess_exec`
   - Set env: `OPENAI_API_KEY`, `CODEX_API_KEY`, `CODEX_MODEL`
   - Use `--sandbox read-only` (Codex should read, not modify)
   - Capture stdout, parse for JSONL findings
   - Timeout: 5 minutes default (configurable)
   - Return: `CodexResult` with findings list, raw output, success flag, duration

3. **`codex_prompt_builder.py`:**

   Build the prompt that Codex receives. This is the heart of the Omar Pack.

   **CRITICAL: Persona System**

   The Codex agent adopts a persona that shapes its review mindset. For v1, the default persona is the CI/CD & Release Engineering expert. The persona definition is stored as a **Python string constant** inside `codex_prompt_builder.py` — NOT in any external file. This is proprietary.

   ```python
   # Inside codex_prompt_builder.py — persona as inline constant
   _PERSONA_SYSTEM_PROMPT = """You are Omar Singh, a senior CI/CD and release engineering specialist.

   Background: You spent years building deployment pipelines at scale. You believe that
   if something isn't automated, it doesn't exist. You are strict about deterministic
   builds, gating checks, and rollback readiness.

   Your core question for every review: "Can we deploy this safely, repeatedly, and
   recover quickly if it fails?"

   What you are strict about:
   - Deterministic, reproducible builds
   - Proper gating checks (lint → test → security → build → deploy)
   - Artifact integrity and provenance
   - Rollback procedures being tested and documented
   - Pipeline stages being complete (no skipped gates)

   Red flags you ALWAYS escalate to P0:
   - Production deployment without tests passing
   - No rollback plan or procedure
   - Secrets exposed in CI/CD workflows or logs
   - Manual steps in what should be an automated pipeline

   Your review style:
   - You read code changes through the lens of "what happens when this deploys?"
   - You check that error handling covers deployment failure scenarios
   - You verify that config changes won't break other environments
   - You look for missing validation at system boundaries
   - You consider the blast radius of every change

   Backend reliability checks (always apply):
   - Every network call must have a timeout
   - Write/mutation endpoints must be idempotent
   - Rate limiting must fail-closed (never fail-open)
   - Error responses must follow a consistent schema with requestId
   - Auth/authz enforcement must be present on all protected routes
   - Retries must have bounds (no infinite retry loops)
   - External service calls need circuit breaker or fallback patterns
   """
   ```

   The prompt builder combines this persona with the analysis context:

   The prompt should include:
   - **Persona system prompt** (the Omar Singh identity above) — injected as system/instructions
   - **Project context** from Quick Learn (name, stack, architecture) — ~100 tokens
   - **PR diff** (for pr-diff mode) or **hotspot files** (for deep mode) — budget-controlled
   - **Deterministic findings summary** — what was already found, so Codex can focus elsewhere
   - **Engineering quality checklist** — relevant items based on detected tech stack (generated dynamically, not from external file)
   - **Output format instructions** — produce JSONL with the Finding schema

   The prompt should NOT include:
   - Full README or documentation (context bloat)
   - Test files
   - Generated/minified files
   - Any internal framework documents, scoring methodology, or persona definition files

   **Prompt structure (user content, after persona is set as system/instructions):**
   ```markdown
   # Security & Engineering Audit

   ## Project Context
   {quick_learn_summary}

   ## Already Found (Deterministic)
   {count} findings already identified by automated scanners.
   Focus on issues that require code understanding beyond pattern matching:
   logic errors, architectural issues, deployment risks, and missing safeguards.

   ## Your Task
   Review the following code changes for:
   1. Security vulnerabilities (P0-P3 per severity scale below)
   2. Deployment and release safety (can this be safely shipped?)
   3. Backend reliability (timeouts, idempotency, error handling, rate limits)
   4. Logic errors, race conditions, and architectural issues
   5. Missing input validation and edge cases at system boundaries

   ## Severity Scale
   - P0: Critical — hardcoded secrets, RCE, SQL injection, auth bypass, prod deploy without tests, no rollback plan
   - P1: High — XSS, CSRF, insecure crypto, missing rate limits, rate limiting fails open, write endpoints not idempotent
   - P2: Medium — missing security headers, verbose error messages, config drift, missing timeouts on network calls
   - P3: Low — debug leftovers, minor code quality, missing documentation

   ## Code to Review
   {pr_diff OR hotspot_files}

   ## Engineering Quality Checks ({tech_stack})
   {dynamically_generated_checklist_for_stack}

   ## Output Format
   Output ONLY valid JSONL (one JSON object per line):
   {"severity":"P1","category":"auth","file_path":"src/auth.ts","line_start":42,"line_end":45,"message":"Missing rate limit on login endpoint","recommendation":"Add rate limiting middleware","confidence":0.85}

   If no findings, output: {"no_findings": true}
   ```

   **Future extensibility:** The persona system is designed so that additional personas (frontend specialist, backend reliability expert, etc.) can be added as separate prompt constants and selected via the `policy_pack` config. For v1, only the default persona ships.

4. **action.yml new inputs:**
   ```yaml
   use_codex:
     description: 'Use Codex CLI for deep agentic audit (requires Node.js)'
     required: false
     default: 'false'
   codex_model:
     description: 'Model for Codex CLI'
     required: false
     default: 'gpt-5.2-codex'
   codex_timeout:
     description: 'Timeout in seconds for Codex execution'
     required: false
     default: '300'
   ```

5. **Orchestrator integration:**
   - After deterministic scan, if `use_codex` is true:
     a. Build Codex prompt with Quick Learn + det findings + PR diff
     b. Run `codex exec` via CodexRunner
     c. Parse output as JSONL findings
     d. Merge with deterministic findings (dedupe by fingerprint)
   - If `use_codex` is false, fall back to existing OpenAI Responses API flow
   - Both paths produce the same Finding schema

### Tests
Create `tests/unit/test_codex_runner.py`:
- Test: Codex prompt builder produces valid prompt with tech-stack-appropriate quality checks
- Test: JSONL output parsing (valid, malformed, empty)
- Test: Timeout handling
- Test: Missing Codex CLI falls back gracefully

Create `tests/unit/test_codex_prompt_builder.py`:
- Test: React project gets frontend engineering checks
- Test: Python project gets backend engineering checks
- Test: PR diff mode includes diff
- Test: Deep mode includes hotspot files
- Test: Token budget respected

---

## TASK 4: Portable Security Test Harness

### What
Ship a set of SentinelLayer's own security-focused test assertions that run against ANY target codebase. Users don't need their own tests — they bring their vibe-coded project, and SentinelLayer's harness catches security issues through actual test execution.

### Where
- New directory: `src/omargate/harness/`
- New module: `src/omargate/harness/runner.py`
- New module: `src/omargate/harness/detectors.py`
- Test suites: `src/omargate/harness/suites/`

### Architecture

The harness detects the project type and runs applicable security checks:

```
┌────────────┐     ┌───────────────┐     ┌──────────────────┐
│ Quick Learn │────▶│ Suite Selector│────▶│ Run applicable   │
│ (tech stack)│     │ (what to run) │     │ security checks  │
└────────────┘     └───────────────┘     └──────────────────┘
```

### Suite Types

**1. Dependency Audit Suite** (all projects):
- `npm audit --audit-level=critical` (Node.js)
- `pip-audit` or `safety check` (Python)
- `cargo audit` (Rust)
- Produce P1 finding for any critical vulnerability found

**2. Secrets-in-Git Suite** (all projects):
- Scan git history (last 50 commits) for leaked secrets
- Uses same entropy + regex patterns as secret_scanner
- Catches secrets that were committed then "removed" (still in history)
- Produce P0 finding for any secret found in git history

**3. Config Hardening Suite** (based on detected stack):
- **Node.js**: Check for `npm_config_ignore-scripts=true`, lockfile integrity
- **Docker**: Check Dockerfile for multi-stage build, non-root USER, no COPY of secrets
- **Terraform**: Check for remote backend, state encryption
- **CI/CD**: Check workflow permissions are minimal (not `permissions: write-all`)

**4. HTTP Security Headers Suite** (web projects only):
- If a dev server can be started (`npm run dev`, `python manage.py runserver`), start it briefly
- Check response headers: CORS, CSP, X-Frame-Options, Strict-Transport-Security
- If no dev server detectable, scan code for header configuration
- Produce P2 findings for missing security headers

**5. Build Integrity Suite** (all projects):
- Verify lockfile exists and matches manifest (package-lock.json ↔ package.json)
- Check for `postinstall` scripts that could be supply-chain attacks
- Detect wildcard/floating version ranges in dependencies
- Produce P2/P1 findings

### Requirements

1. **`runner.py`:**
   ```python
   class HarnessRunner:
       def __init__(self, project_root: str, tech_stack: list[str]):
           ...

       async def run(self) -> list[Finding]:
           """Run all applicable suites and return findings."""
           suites = self._select_suites()
           findings = []
           for suite in suites:
               findings.extend(await suite.run(self.project_root))
           return findings
   ```

2. **Each suite** implements:
   ```python
   class SecuritySuite(ABC):
       @abstractmethod
       async def run(self, project_root: str) -> list[Finding]:
           ...

       @abstractmethod
       def applies_to(self, tech_stack: list[str]) -> bool:
           ...
   ```

3. **Safety constraints:**
   - NEVER execute user code (no `npm test`, no `python -m pytest` on user's code)
   - Only run trusted tools (npm audit, pip-audit, cargo audit)
   - Sandbox: read-only access to repo, write only to .sentinelayer/ output dir
   - Timeout: 60 seconds per suite, 180 seconds total
   - All findings use source: `"harness"`

4. **Integration:**
   - Runs after ingest, before deterministic scan
   - Findings merge with deterministic + LLM findings
   - New action.yml input:
     ```yaml
     run_harness:
       description: 'Run SentinelLayer security test harness'
       required: false
       default: 'true'
     ```

### Tests
Create `tests/unit/test_harness_runner.py`:
- Test: Node.js project selects dep audit + config + build integrity suites
- Test: Python project selects dep audit + config suites
- Test: Empty project runs only secrets-in-git
- Test: Suite timeout is enforced
- Test: Findings have correct source field ("harness")

---

## TASK 5: Multi-LLM Provider Support

### What
Replace the hard-wired OpenAI dependency in the LLM analysis path with a provider abstraction layer. Users can bring API keys for OpenAI, Anthropic (Claude), Google (Gemini), or xAI (Grok). The Codex CLI path (Task 3) remains OpenAI-only, but the direct LLM analysis path supports any provider.

### Where
- New directory: `src/omargate/analyze/llm/providers/`
- Refactor: `src/omargate/analyze/llm/llm_client.py` (add provider dispatch)
- Update: `config.py`, `action.yml`, `models.py`

### Architecture

```
LLMClient (existing interface — analyze(), _call_with_retry())
    │
    ├── provider dispatch based on config.llm_provider
    │
    ▼
LLMProvider (ABC)
├── OpenAIProvider     → AsyncOpenAI → client.responses.create()
├── AnthropicProvider  → AsyncAnthropic → client.messages.create()
├── GeminiProvider     → google.genai → client.models.generate_content()
└── XAIProvider        → AsyncOpenAI(base_url="https://api.x.ai/v1") → chat.completions.create()
```

### Requirements

1. **`providers/__init__.py`** — Provider registry:
   ```python
   from .base import LLMProvider
   from .openai_provider import OpenAIProvider
   from .anthropic_provider import AnthropicProvider
   from .gemini_provider import GeminiProvider
   from .xai_provider import XAIProvider

   PROVIDERS: dict[str, type[LLMProvider]] = {
       "openai": OpenAIProvider,
       "anthropic": AnthropicProvider,
       "google": GeminiProvider,
       "xai": XAIProvider,
   }
   ```

2. **`providers/base.py`** — Abstract base:
   ```python
   class LLMProvider(ABC):
       @abstractmethod
       async def call(
           self,
           model: str,
           system: str,
           user: str,
           max_tokens: int,
           temperature: float,
           timeout: int,
       ) -> ProviderResponse:
           """Make a single LLM call. Returns content + usage."""
           ...

       @abstractmethod
       def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
           ...

   @dataclass
   class ProviderResponse:
       content: str
       input_tokens: int
       output_tokens: int
       model: str
   ```

3. **Provider implementations:**

   **OpenAI** (`openai_provider.py`):
   - Uses `AsyncOpenAI` → `client.responses.create()` (Responses API)
   - Models: gpt-5.2-codex, gpt-4.1, gpt-4.1-mini, gpt-4.1-nano, gpt-4o, gpt-4o-mini
   - This is the existing LLMClient logic extracted into a provider

   **Anthropic** (`anthropic_provider.py`):
   - Uses `anthropic.AsyncAnthropic` → `client.messages.create()`
   - Models: claude-opus-4-6, claude-sonnet-4-5-20250929, claude-haiku-4-5-20251001
   - Map: `system` → `system` param, `user` → `messages=[{"role":"user","content":user}]`
   - Response: `response.content[0].text`, usage from `response.usage`
   - Pricing: opus input $15/M output $75/M, sonnet input $3/M output $15/M, haiku input $0.80/M output $4/M

   **Gemini** (`gemini_provider.py`):
   - Uses `google.genai.Client` → `client.models.generate_content()`
   - Models: gemini-2.5-pro, gemini-2.5-flash
   - Map: `system` → `config.system_instruction`, `user` → `contents`
   - Response: `response.text`, usage from `response.usage_metadata`
   - Pricing: 2.5-pro input $1.25/M output $10/M, 2.5-flash input $0.15/M output $0.60/M

   **xAI/Grok** (`xai_provider.py`):
   - Uses `AsyncOpenAI(base_url="https://api.x.ai/v1")` (OpenAI-compatible API)
   - Models: grok-3, grok-3-mini
   - Same interface as OpenAI Chat Completions (NOT Responses API)
   - Map: `system` → system message, `user` → user message
   - Pricing: grok-3 input $3/M output $15/M (estimated)

4. **Config additions:**
   ```python
   # In OmarGateConfig:
   llm_provider: LLMProviderType = Field(
       default="openai",
       description="LLM provider: openai, anthropic, google, xai",
   )
   # API keys — only the selected provider's key is required
   openai_api_key: SecretStr = Field(default="", description="OpenAI API key")
   anthropic_api_key: SecretStr = Field(default="", description="Anthropic API key")
   google_api_key: SecretStr = Field(default="", description="Google AI API key")
   xai_api_key: SecretStr = Field(default="", description="xAI API key")
   ```

   **IMPORTANT:** `openai_api_key` is currently required. Change it to optional with validation:
   the API key for the selected `llm_provider` must be provided. If `use_codex=true`,
   `openai_api_key` is always required (Codex CLI is OpenAI-only).

5. **LLMClient refactor:**
   - Keep the same public interface (`analyze()`, `_call_with_retry()`)
   - Replace internal `AsyncOpenAI` with provider dispatch
   - `_call_with_retry()` calls `self.provider.call()` instead of `self.client.responses.create()`
   - Primary/fallback model logic stays the same
   - Cost estimation delegates to `self.provider.estimate_cost()`

6. **Telemetry enrichment:**
   Update the telemetry collector to include:
   ```python
   # In telemetry payload:
   "llm_provider": "openai",        # which provider was used
   "llm_model": "gpt-5.2-codex",   # which model was used
   "llm_latency_ms": 1234,          # response time
   "llm_cost_usd": 0.05,            # estimated cost
   "llm_tokens_in": 5000,           # input tokens
   "llm_tokens_out": 800,           # output tokens
   "llm_fallback_used": false,      # did primary fail?
   "llm_fallback_provider": null,   # if fallback, which provider
   "llm_fallback_model": null,      # if fallback, which model
   ```
   This data enables cross-provider ranking on the dashboard (API-side feature, not action-side).

7. **action.yml additions:**
   ```yaml
   llm_provider:
     description: 'LLM provider: openai, anthropic, google, xai'
     required: false
     default: 'openai'
   anthropic_api_key:
     description: 'Anthropic API key (required if llm_provider=anthropic)'
     required: false
     default: ''
   google_api_key:
     description: 'Google AI API key (required if llm_provider=google)'
     required: false
     default: ''
   xai_api_key:
     description: 'xAI API key (required if llm_provider=xai)'
     required: false
     default: ''
   ```

8. **Fallback across providers:**
   Allow cross-provider fallback. Example config:
   ```yaml
   llm_provider: anthropic
   model: claude-sonnet-4-5-20250929
   model_fallback: gpt-4.1        # falls back to OpenAI
   openai_api_key: ${{ secrets.OPENAI_API_KEY }}      # needed for fallback
   anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }} # primary
   ```
   The fallback model name determines the provider automatically:
   - `claude-*` or `claude-*` → anthropic
   - `gpt-*` or `o1-*` or `o3-*` → openai
   - `gemini-*` → google
   - `grok-*` → xai

### Dependency Management
   - `anthropic` and `google-genai` should be **optional** dependencies
   - Only import the selected provider at runtime (lazy import, same pattern as current `AsyncOpenAI`)
   - If a provider's SDK is not installed, raise a clear error: "Install `anthropic` package to use Anthropic provider"

### Tests
Create `tests/unit/test_llm_providers.py`:
- Test: OpenAI provider calls responses.create with correct params
- Test: Anthropic provider calls messages.create with correct params
- Test: Gemini provider calls generate_content with correct params
- Test: xAI provider uses OpenAI client with custom base_url
- Test: Provider auto-detection from model name (claude-* → anthropic, gpt-* → openai)
- Test: Cross-provider fallback (primary anthropic, fallback openai)
- Test: Missing SDK raises clear error message
- Test: Cost estimation per provider returns correct values

---

## Integration Wiring

### Updated Orchestrator Pipeline

```
1. Quick Learn      → Extract project context from README/manifests
2. Ingest           → Map codebase, classify files, detect hotspots (existing)
3. Harness          → Run portable security test suites (NEW)
4. Deterministic    → Pattern + Secret + Config scanners (existing)
5. Eng Quality      → Stack-aware engineering quality checks (NEW)
6. Codex/LLM        → Deep agentic audit via Codex CLI or multi-provider LLM (NEW/existing)
7. Merge & Dedupe   → Combine all findings, fingerprint (existing)
8. Gate Evaluate    → Pass/Block decision (existing)
9. Publish          → PR comment, Check Run, artifacts (existing)
10. Telemetry       → Upload by tier (existing)
```

### Config Additions to `config.py`

```python
# New fields in OmarGateConfig:
use_codex: bool = Field(default=False, description="Use Codex CLI for deep audit")
codex_model: str = Field(default="gpt-5.2-codex", description="Model for Codex CLI")
codex_timeout: conint(ge=60) = Field(default=300, description="Codex timeout in seconds")
run_harness: bool = Field(default=True, description="Run security test harness")
llm_provider: LLMProviderType = Field(default="openai", description="LLM provider")
anthropic_api_key: SecretStr = Field(default="", description="Anthropic API key")
google_api_key: SecretStr = Field(default="", description="Google AI API key")
xai_api_key: SecretStr = Field(default="", description="xAI API key")
```

### action.yml Additions

```yaml
use_codex:
  description: 'Use Codex CLI for deep agentic audit'
  required: false
  default: 'false'
codex_model:
  description: 'Model for Codex CLI'
  required: false
  default: 'gpt-5.2-codex'
codex_timeout:
  description: 'Codex CLI timeout in seconds'
  required: false
  default: '300'
run_harness:
  description: 'Run SentinelLayer portable security test harness'
  required: false
  default: 'true'
```

---

## TASK 6: Fix Telemetry on Failure Paths (Bug Fix)

### What
Currently, telemetry is ONLY uploaded if the action makes it past all preflight checks to the analysis stage. Every early return path (dedupe, rate limit, fork block, cost approval, config error, LLM failure) skips telemetry entirely. This means failed runs are invisible on the dashboard. We need them there the same way github literally has pages of succcessful and failed runs for any reasons whatoever and I would love to be able to see these reasons and we can also use green checkmarks to indicate success and red x's to indicate failure.

### Where
- Fix: `src/omargate/main.py` — wrap `async_main()` in try/finally for telemetry
- Update: `src/omargate/telemetry/collector.py` — add failure-specific fields

### Requirements

1. **Move telemetry upload to an outer try/finally** that wraps the ENTIRE `async_main()` function body:
   ```python
   async def async_main() -> int:
       collector = TelemetryCollector()
       exit_code = 2  # default to error
       try:
           # ... all existing logic ...
           exit_code = _exit_code_from_gate_result(gate_result)
           return exit_code
       except Exception as exc:
           collector.record_error("unhandled", str(exc))
           raise
       finally:
           # ALWAYS upload telemetry, even on early returns
           try:
               await _upload_telemetry_always(collector, config, exit_code)
           except Exception:
               pass  # telemetry is best-effort, never fail the run
   ```

2. **Add early-return telemetry for preflight exits:**
   Before each early `return` in preflight (dedupe, fork, rate limit, cost), record a telemetry event:
   ```python
   collector.record_preflight_exit(reason="dedupe", exit_code=0)
   collector.record_preflight_exit(reason="rate_limit", exit_code=0)
   collector.record_preflight_exit(reason="fork_blocked", exit_code=12)
   collector.record_preflight_exit(reason="cost_approval", exit_code=13)
   ```

3. **Minimal error payload for failed runs:**
   Even when analysis didn't run, the telemetry payload should include:
   - `run_id`, `timestamp`, `exit_code`, `exit_reason`
   - `preflight_result` (which check caused the exit)
   - `llm_provider` and `llm_model` (from config, even if never called)
   - `errors` list (from collector)
   - Duration (wall clock from start to exit)

4. **Collector additions:**
   ```python
   # In TelemetryCollector:
   exit_code: int = 0
   exit_reason: str = ""
   preflight_exits: list[dict] = field(default_factory=list)

   def record_preflight_exit(self, reason: str, exit_code: int) -> None:
       self.exit_reason = reason
       self.exit_code = exit_code
       self.preflight_exits.append({"reason": reason, "exit_code": exit_code})
   ```

### Tests
Add to existing telemetry tests:
- Test: Preflight exit (dedupe) still produces a telemetry payload
- Test: LLM failure still produces a telemetry payload with error details
- Test: Unhandled exception still produces a telemetry payload

---

## Constraints

1. **Do NOT modify** existing passing tests (131 tests must stay green)
2. **Do NOT modify** existing scanner logic — only ADD new scanners
3. **Match existing patterns:** Use the same `Finding` dataclass, same JSONL format, same fingerprinting
4. **Fail-closed:** If Codex CLI is not installed and `use_codex=true`, produce a warning and fall back to OpenAI API
5. **Token budget:** Quick Learn context must stay under 600 tokens. Codex prompt total must stay under `max_input_tokens` config value
6. **No secrets in code:** Never log API keys, never include them in findings output
7. **Test everything:** Each new module needs unit tests. Target: maintain 100% of new code paths tested
8. **Python 3.11+** target, use `from __future__ import annotations`
9. **Async-first:** All I/O operations should be async

---

## File Tree (new files only)

```
src/omargate/
├── ingest/
│   └── quick_learn.py                    # TASK 1
├── analyze/
│   ├── deterministic/
│   │   └── eng_quality_scanner.py        # TASK 2 (all rules inline, no JSON)
│   ├── codex/
│   │   ├── __init__.py                   # TASK 3
│   │   ├── codex_runner.py               # TASK 3
│   │   └── codex_prompt_builder.py       # TASK 3
│   └── llm/
│       └── providers/
│           ├── __init__.py               # TASK 5 (registry)
│           ├── base.py                   # TASK 5 (ABC)
│           ├── openai_provider.py        # TASK 5
│           ├── anthropic_provider.py     # TASK 5
│           ├── gemini_provider.py        # TASK 5
│           └── xai_provider.py           # TASK 5
├── harness/
│   ├── __init__.py                       # TASK 4
│   ├── runner.py                         # TASK 4
│   ├── detectors.py                      # TASK 4
│   └── suites/
│       ├── __init__.py                   # TASK 4
│       ├── dep_audit.py                  # TASK 4
│       ├── secrets_in_git.py             # TASK 4
│       ├── config_hardening.py           # TASK 4
│       ├── http_headers.py              # TASK 4
│       └── build_integrity.py           # TASK 4
tests/unit/
├── test_quick_learn.py                   # TASK 1
├── test_eng_quality_scanner.py            # TASK 2
├── test_codex_runner.py                  # TASK 3
├── test_codex_prompt_builder.py          # TASK 3
├── test_harness_runner.py               # TASK 4
└── test_llm_providers.py               # TASK 5
```

## Priority Order
1. Quick Learn (unblocks Tasks 2, 3, 5)
2. Engineering Quality Scanner (adds immediate value, no external deps)
3. Multi-LLM Provider Support (refactor before adding Codex, keeps LLMClient clean)
4. Portable Security Test Harness (runs everywhere, no API key needed)
5. Codex CLI Integration (highest impact but most complex, builds on provider layer)
