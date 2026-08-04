from __future__ import annotations

from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner


def test_frontend_rules_only_apply_to_react_projects() -> None:
    files = {
        "src/App.tsx": (
            "export const App = () => {\n"
            "  items.forEach(item => { setCount(item.count); });\n"
            "  return <div />;\n"
            "};\n"
        ),
    }

    react = EngQualityScanner(tech_stack=["React", "TypeScript"])
    react_findings = react.scan(files)
    assert any(f.pattern_id == "EQ-001" for f in react_findings)

    python = EngQualityScanner(tech_stack=["Python"])
    python_findings = python.scan(files)
    assert not any(f.pattern_id == "EQ-001" for f in python_findings)


def test_eval_detected_as_p0() -> None:
    files = {"src/server.js": "const out = eval(userInput);\n"}
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-008"), None)
    assert finding is not None
    assert finding.severity == "P0"


def test_eval_string_literal_not_flagged_in_python() -> None:
    files = {
        "src/rules.py": (
            "RULE = 'Use of eval() or Function() constructor can enable arbitrary code execution.'\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-008" for f in findings)


def test_eval_call_detected_in_python() -> None:
    files = {"src/app.py": "def run(user_input):\n    return eval(user_input)\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-008" for f in findings)


def test_python_fstring_sql_interpolation_detected_as_p0() -> None:
    files = {
        "src/query.py": (
            "def load(user_id):\n"
            '    return f"SELECT email FROM users WHERE id = {user_id}"\n'
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-009"), None)
    assert finding is not None
    assert finding.severity == "P0"
    assert finding.line_start == 2


def test_python_sql_string_concatenation_detected_as_p0() -> None:
    files = {"src/query.py": 'query = "DELETE FROM users WHERE id = " + user_id\n'}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-009" and f.severity == "P0" for f in findings)


def test_dns_update_error_fstring_is_not_misclassified_as_sql() -> None:
    files = {
        "scripts/cloudflare/check_dashboard_dns_origin.py": (
            "raise DashboardDnsOriginError(\n"
            '    f"Refusing to update ambiguous DNS records for {hostname}; "\n'
            '    "clean them up explicitly."\n'
            ")\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-009" for f in findings)


def test_unparseable_python_uses_sql_anchored_fallback() -> None:
    files = {
        "src/broken.py": (
            'query = f"UPDATE users SET name = {name} WHERE id = {user_id}"\n'
            "this is invalid python\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-009" and f.line_start == 1 for f in findings)


def test_javascript_sql_template_interpolation_detected_but_update_prose_is_not() -> None:
    files = {
        "src/query.js": "const query = `SELECT email FROM users WHERE id = ${userId}`;\n",
        "src/message.js": 'const message = "Refusing to update DNS for " + hostname;\n',
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-009"]
    assert [finding.file_path for finding in findings] == ["src/query.js"]


def test_dockerfile_without_user_detected_as_p2() -> None:
    files = {"Dockerfile": "FROM python:3.11\nRUN echo hi\n"}
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-018"), None)
    assert finding is not None
    assert finding.severity == "P2"


def test_dockerfile_root_user_waiver_suppresses_finding() -> None:
    files = {
        "Dockerfile": (
            "FROM python:3.11\n"
            "# omargate:allow-root-user\n"
            "RUN echo hi\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-018" for f in findings)


def test_env_file_committed_detected_as_p0() -> None:
    files = {
        ".env": "OPENAI_API_KEY=sk-test\n",
        ".env.example": "OPENAI_API_KEY=\n",
    }
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-020" and f.severity == "P0" for f in findings)


def test_n_plus_one_query_pattern_detected() -> None:
    files = {
        "src/app.py": (
            "async def f(user_ids, session):\n"
            "    for user_id in user_ids:\n"
            "        await session.execute(\"SELECT 1\", {\"id\": user_id})\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["FastAPI", "Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-007" for f in findings)


def test_multiline_httpx_client_with_explicit_timeout_is_not_flagged() -> None:
    files = {
        "src/routes/auth.py": (
            "async def fetch_metadata():\n"
            "    async with httpx.AsyncClient(\n"
            "        follow_redirects=False,\n"
            "        timeout=_CIMD_FETCH_TIMEOUT_S,\n"
            "    ) as client:\n"
            "        return await client.get('https://example.com')\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-012" for f in findings)


def test_multiline_httpx_client_without_timeout_is_flagged() -> None:
    files = {
        "src/routes/auth.py": (
            "async def fetch_metadata():\n"
            "    async with httpx.AsyncClient(\n"
            "        follow_redirects=False,\n"
            "    ) as client:\n"
            "        return await client.get('https://example.com')\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-012"), None)
    assert finding is not None
    assert finding.line_start == 2
    assert finding.line_end == 4


def test_multiline_httpx_get_with_explicit_timeout_is_not_flagged() -> None:
    files = {
        "src/client.py": (
            "async def fetch_metadata(url):\n"
            "    return await httpx.get(\n"
            "        url,\n"
            "        timeout=5.0,\n"
            "    )\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-012" for f in findings)


def test_timeout_text_in_comment_or_string_does_not_suppress_finding() -> None:
    files = {
        "src/comment.py": "client = httpx.Client(  # timeout inherited elsewhere\n)\n",
        "src/string.py": 'response = httpx.get("timeout")\n',
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert {finding.file_path for finding in findings} == {
        "src/comment.py",
        "src/string.py",
    }


def test_nested_timeout_argument_does_not_count_as_httpx_timeout() -> None:
    files = {
        "src/client.py": (
            "response = httpx.get(\n"
            "    build_url(timeout=5.0),\n"
            ")\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 1
    assert findings[0].line_start == 1


def test_syntax_error_uses_balanced_call_fallback() -> None:
    files = {
        "src/client.py": (
            "bounded = httpx.get(\n"
            "    'https://example.com/bounded',\n"
            "    timeout=5.0,\n"
            ")\n"
            "unbounded = httpx.get(  # timeout is still missing\n"
            "    'https://example.com/unbounded',\n"
            ")\n"
            "def broken(:\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert [finding.line_start for finding in findings] == [5]


def test_one_line_httpx_call_without_timeout_is_flagged() -> None:
    files = {"src/client.py": "response = httpx.post('https://example.com')\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 1
    assert findings[0].line_start == 1


def test_same_line_httpx_calls_emit_one_unique_finding() -> None:
    files = {
        "src/nested.py": "result = httpx.get(httpx.post('https://inner'))\n",
        "src/sequential.py": (
            "first = httpx.get('https://first'); "
            "second = httpx.post('https://second')\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 2
    assert len({finding.id for finding in findings}) == len(findings)
    assert {finding.file_path for finding in findings} == set(files)


def test_httpx_module_case_matching_preserves_existing_behavior() -> None:
    files = {
        "src/parseable.py": (
            "import httpx as HTTPX\n"
            "response = HTTPX.get('https://example.com')\n"
        ),
        "src/syntax_error.py": (
            "import httpx as HTTPX\n"
            "client = HTTPX.AsyncClient()\n"
            "def broken(:\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert [(finding.file_path, finding.line_start) for finding in findings] == [
        ("src/parseable.py", 2),
        ("src/syntax_error.py", 2),
    ]


def test_workflow_secret_labels_not_flagged_as_hardcoded_secrets() -> None:
    files = {
        ".github/workflows/security-review.yml": (
            "name: Security Review\n"
            "jobs:\n"
            "  secret-scanning:\n"
            "    name: Secret Scanning\n"
            "  upload:\n"
            "    name: Upload secret scan artifacts\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-021" for f in findings)


def test_workflow_hardcoded_secret_env_value_detected() -> None:
    files = {
        ".github/workflows/security-review.yml": (
            "jobs:\n"
            "  omar-review:\n"
            "    env:\n"
            "      OPENAI_API_KEY: " + "sk" + "_live_1234567890abcdef123456" + "\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-021" for f in findings)


def test_oidc_verify_aud_false_detected_as_p1() -> None:
    files = {
        "sentinelayer-api/src/auth/oidc_verifier.py": (
            "payload = jwt.decode(token, jwks, options={\"verify_aud\": False})\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-022"), None)
    assert finding is not None
    assert finding.severity == "P1"


def test_oauth_callback_missing_state_detected_as_p1() -> None:
    files = {
        "sentinelayer-api/src/routes/auth.py": (
            "class OAuthCallbackRequest(BaseModel):\n"
            "    code: str\n\n"
            "@router.post('/auth/github/callback')\n"
            "async def github_callback():\n"
            "    pass\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-023"), None)
    assert finding is not None
    assert finding.severity == "P1"


def test_missing_health_endpoint_uses_distinct_rule_id() -> None:
    files = {
        "sentinelayer-api/src/main.py": (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/auth/me')\n"
            "async def me():\n"
            "    return {'ok': True}\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-024"), None)
    assert finding is not None
    assert finding.severity == "P2"


def test_missing_request_id_rule_has_stack_specific_fix_plan() -> None:
    files = {
        "src/api.ts": (
            "export function handler(req, res) {\n"
            "  return res.status(500).json({ error: 'boom' });\n"
            "}\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-016"), None)
    assert finding is not None
    assert "requestId" in finding.fix_plan
    assert "Express" in finding.fix_plan
