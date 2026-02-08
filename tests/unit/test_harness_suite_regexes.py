from __future__ import annotations

from pathlib import Path

import pytest

from omargate.harness.suites.config_hardening import ConfigHardeningSuite
from omargate.harness.suites.http_headers import HttpSecurityHeadersSuite


@pytest.mark.anyio
async def test_config_hardening_dockerfile_regexes_work(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "\n".join(
            [
                "FROM node:20 AS build",
                "WORKDIR /app",
                "COPY .env .env",
                "FROM gcr.io/distroless/nodejs20",
                "COPY --from=build /app /app",
            ]
        ),
        encoding="utf-8",
    )

    suite = ConfigHardeningSuite(tech_stack=[])
    findings = await suite.run(str(tmp_path))
    ids = {f.id for f in findings}

    assert "HARNESS-DOCKER-COPY-ENV" in ids
    assert "HARNESS-DOCKER-MULTISTAGE" not in ids


@pytest.mark.anyio
async def test_config_hardening_terraform_s3_backend_regex_works(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        "\n".join(
            [
                "terraform {",
                "  backend \"s3\" {",
                "    bucket = \"state-bucket\"",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    suite = ConfigHardeningSuite(tech_stack=[])
    findings = await suite.run(str(tmp_path))
    ids = {f.id for f in findings}

    assert "HARNESS-TF-STATE-ENCRYPT" in ids


@pytest.mark.anyio
async def test_config_hardening_workflow_permissions_regex_works(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "ci.yml").write_text(
        "\n".join(
            [
                "name: CI",
                "on: [push]",
                "permissions: write-all",
                "jobs:",
                "  test:",
                "    runs-on: ubuntu-latest",
                "    steps: []",
            ]
        ),
        encoding="utf-8",
    )

    suite = ConfigHardeningSuite(tech_stack=[])
    findings = await suite.run(str(tmp_path))
    pattern_ids = {f.pattern_id for f in findings}

    assert "HARNESS-CICD-PERMS" in pattern_ids


@pytest.mark.anyio
async def test_http_headers_suite_helmet_regex_works(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "\n".join(
            [
                "const helmet = require('helmet');",
                "app.use(helmet());",
            ]
        ),
        encoding="utf-8",
    )

    suite = HttpSecurityHeadersSuite(tech_stack=[])
    findings = await suite.run(str(tmp_path))

    assert findings == []

