from __future__ import annotations

import time
from pathlib import Path

import pytest

from omargate.analyze.deterministic.pattern_scanner import PatternScanner


@pytest.fixture
def patterns_dir() -> Path:
    return Path(__file__).parents[2] / "src" / "omargate" / "analyze" / "deterministic" / "patterns"


@pytest.fixture
def scanner(patterns_dir: Path) -> PatternScanner:
    return PatternScanner(patterns_dir)


@pytest.fixture
def benchmark_fixture(tmp_path: Path):
    repo_root = tmp_path / "repo"
    src_dir = repo_root / "src"
    src_dir.mkdir(parents=True)
    files = []
    for idx in range(1000):
        rel_path = f"src/file_{idx}.ts"
        full_path = repo_root / rel_path
        full_path.write_text("const value = 1;\n", encoding="utf-8")
        files.append({"path": rel_path, "size_bytes": full_path.stat().st_size})
    return {"files": files, "repo_root": repo_root}


def test_scanner_finds_hardcoded_api_key(scanner: PatternScanner) -> None:
    api_key_value = "sk_test_" + ("a" * 20)
    content = 'const API_KEY = "' + api_key_value + '"'
    findings = scanner.scan_file(Path("src/config.ts"), content)
    assert len(findings) == 1
    assert findings[0].pattern_id == "SEC-001"
    assert findings[0].severity == "P1"
    assert "env" in findings[0].fix_plan.lower()


def test_scanner_ignores_test_files(scanner: PatternScanner) -> None:
    api_key_value = "sk_test_" + ("a" * 20)
    content = 'const API_KEY = "' + api_key_value + '"'
    findings = scanner.scan_file(Path("src/config.test.ts"), content)
    assert len(findings) == 0


def test_scanner_masks_secrets_in_snippet(scanner: PatternScanner) -> None:
    password_value = "safe" + "password" + "123"
    content = 'password = "' + password_value + '"'
    findings = scanner.scan_file(Path("src/auth.py"), content)
    assert password_value not in findings[0].snippet
    assert "****" in findings[0].snippet


def test_scanner_respects_file_patterns(scanner: PatternScanner) -> None:
    content = 'verify = False  # disable SSL check'
    findings_py = scanner.scan_file(Path("src/client.py"), content)
    findings_md = scanner.scan_file(Path("docs/notes.md"), content)
    assert len(findings_py) >= 1
    assert findings_py[0].pattern_id == "SEC-011"
    assert len(findings_md) == 0


def test_scan_files_aggregates_findings(scanner: PatternScanner, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    file_a = repo_root / "src" / "config.ts"
    api_key_value = "sk_test_" + ("a" * 20)
    file_a.write_text('const API_KEY = "' + api_key_value + '"', encoding="utf-8")
    files = [
        {"path": "src/config.ts", "size_bytes": file_a.stat().st_size},
    ]
    findings = scanner.scan_files(files, repo_root)
    pattern_ids = {finding.pattern_id for finding in findings}
    assert "SEC-001" in pattern_ids


def test_scanner_truncates_snippet(scanner: PatternScanner) -> None:
    long_comment = "x" * 600
    content = f"verify = False  # {long_comment}"
    findings = scanner.scan_file(Path("src/client.py"), content)
    assert len(findings) >= 1
    assert len(findings[0].snippet) <= 500
    assert findings[0].snippet.endswith("...")


def test_scanner_performance_1000_files(scanner: PatternScanner, benchmark_fixture) -> None:
    start = time.time()
    scanner.scan_files(benchmark_fixture["files"], benchmark_fixture["repo_root"])
    elapsed = time.time() - start
    assert elapsed < 10.0
