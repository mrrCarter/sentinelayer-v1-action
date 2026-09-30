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


def _n_plus_one_lines(source: str) -> list[int]:
    scanner = EngQualityScanner(tech_stack=["FastAPI", "Python"])
    findings = scanner.scan({"src/service.py": source})
    return [f.line_start for f in findings if f.pattern_id == "EQ-007"]


def test_n_plus_one_still_flags_awaits_inside_the_loop_body() -> None:
    # Deep in the body, after a blank line and a nested block, and inside a
    # nested loop: every per-item await is still a finding, reported at the
    # outer for-line exactly as before.
    source = (
        "async def f(ids, db):\n"
        "    for item_id in ids:\n"
        "        if item_id:\n"
        "            label = str(item_id)\n"
        "\n"
        "            await db.execute(\"SELECT 1\", {\"id\": label})\n"
        "    return None\n"
        "\n"
        "async def g(groups, session):\n"
        "    for group in groups:\n"
        "        for member in group:\n"
        "            await session.get(member)\n"
    )
    assert _n_plus_one_lines(source) == [2, 10]


def test_n_plus_one_ignores_an_await_after_the_loop_ends() -> None:
    # One query, an in-memory loop, then ONE commit after the loop: not N+1.
    source = (
        "async def list_rows(self):\n"
        "    rows = (await self.db.scalars(stmt)).all()\n"
        "    for row in rows:\n"
        "        self._expire_if_due(row, now)\n"
        "    result = {\"rows\": [view(r) for r in rows]}\n"
        "    await self.db.commit()\n"
        "    return result\n"
    )
    assert _n_plus_one_lines(source) == []


def test_n_plus_one_ignores_a_batched_query_grouped_in_memory() -> None:
    source = (
        "async def list_links(self, links):\n"
        "    by_link = {link.id: [] for link in links}\n"
        "    if links:\n"
        "        rows = await self.db.scalars(select(Claim).where(Claim.link_id.in_(list(by_link))))\n"
        "        for claim in rows:\n"
        "            by_link[claim.link_id].append(claim)\n"
        "    metadata = []\n"
        "    for link in links:\n"
        "        metadata.append(len(by_link[link.id]))\n"
        "    await self.db.commit()\n"
        "    return metadata\n"
    )
    assert _n_plus_one_lines(source) == []


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
