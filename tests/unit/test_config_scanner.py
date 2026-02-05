from __future__ import annotations

from pathlib import Path

import pytest

from omargate.analyze.deterministic.config_scanner import ConfigScanner


@pytest.fixture
def patterns_dir() -> Path:
    return Path(__file__).parents[2] / "src" / "omargate" / "analyze" / "deterministic" / "patterns"


@pytest.fixture
def config_scanner(patterns_dir: Path) -> ConfigScanner:
    return ConfigScanner(patterns_dir)


def test_env_file_flags_secret(config_scanner: ConfigScanner) -> None:
    value = "SAFE" + "VALUE" + "123"
    content = "API_KEY=" + value
    findings = config_scanner.scan_file(Path(".env"), content)
    assert findings
    assert findings[0].pattern_id == "CONF-ENV-001"
    assert value not in findings[0].snippet
    assert "****" in findings[0].snippet


def test_package_json_http_dependency(config_scanner: ConfigScanner) -> None:
    content = '{\"dependencies\": {\"unsafe-lib\": \"http://example.com/unsafe.tgz\"}}'
    findings = config_scanner.scan_file(Path("package.json"), content)
    assert any(finding.pattern_id == "CONF-PKG-001" for finding in findings)


def test_tsconfig_strict_disabled(config_scanner: ConfigScanner) -> None:
    content = '{\"compilerOptions\": {\"strict\": false}}'
    findings = config_scanner.scan_file(Path("tsconfig.json"), content)
    assert any(finding.pattern_id == "CONF-TS-001" for finding in findings)
