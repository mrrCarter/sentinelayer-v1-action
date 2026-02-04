from __future__ import annotations

from omargate.ingest.file_classifier import classify_file


def test_classify_source_file() -> None:
    result = classify_file("src/app/main.py")
    assert result.category == "source"
    assert result.language == "python"


def test_classify_test_file() -> None:
    result = classify_file("tests/test_app.py")
    assert result.category == "test"


def test_classify_config_file() -> None:
    result = classify_file("config/settings.yaml")
    assert result.category == "config"
    assert result.language == "yaml"


def test_classify_docs_file() -> None:
    result = classify_file("README.md")
    assert result.category == "docs"
    assert result.language == "markdown"


def test_classify_env_file() -> None:
    result = classify_file(".env")
    assert result.category == "config"
