from __future__ import annotations

from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner


def test_react_project_triggers_frontend_rules_python_project_does_not() -> None:
    files = {
        "src/App.tsx": "export const App = () => <div dangerouslySetInnerHTML={{ __html: html }} />;\n",
    }

    react = EngQualityScanner(tech_stack=["React", "TypeScript"])
    react_findings = react.scan(files)
    assert any(f.pattern_id == "EQ-003" for f in react_findings)

    python = EngQualityScanner(tech_stack=["Python"])
    python_findings = python.scan(files)
    assert not any(f.pattern_id == "EQ-003" for f in python_findings)


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


def test_console_log_in_test_file_not_flagged() -> None:
    files = {"src/foo.test.tsx": "console.log('debug');\n"}
    scanner = EngQualityScanner(tech_stack=["React"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-005" for f in findings)


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
            "      OPENAI_API_KEY: sk_live_1234567890abcdef123456\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-021" for f in findings)

