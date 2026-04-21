"""Shared helpers for reading `.sentinelayer/scaffold.yaml`.

Before this module existed, the same 40-line ownership-map parser was
duplicated in `local_gates.py` and `fix_handoff_cli.py` (duplication
acknowledged and marked TODO at the time — the two shipped in separate
PRs that couldn't share code cleanly until both landed on main).

Now both callers import from here. Behavior is identical to the previous
inline copies:

  - Read the file at `scaffold_path`.
  - Parse `ownership_rules:` list-of-maps.
  - Return `{file_path: persona_id}` for every rule whose pattern has no
    glob wildcard. Wildcard patterns (`**/*.ts`, `app/*.tsx`, ...) are
    skipped because `dispatch_personas` expects concrete file keys.

Any parse failure (missing file, malformed YAML, no rules) returns an
empty dict — persona dispatch is opt-in and silently degrades to "no
routing" when the map isn't usable.
"""

from __future__ import annotations

from pathlib import Path


def parse_scaffold_ownership(scaffold_path: Path) -> dict[str, str]:
    """Return {file -> persona} literal-path map from scaffold.yaml."""
    try:
        text = scaffold_path.read_text(encoding="utf-8")
    except OSError:
        return {}

    rules: list[tuple[str, str]] = []
    in_rules = False
    current_pattern: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "ownership_rules:":
            in_rules = True
            continue
        if not in_rules:
            continue
        if not line.startswith(" ") and not line.startswith("-"):
            # Dedented to a new top-level key — stop consuming rules.
            in_rules = False
            continue
        if stripped.startswith("- "):
            current_pattern = None
            remainder = stripped[2:].strip()
            if remainder.startswith("pattern:"):
                current_pattern = _unquote(remainder.split(":", 1)[1].strip())
            continue
        if stripped.startswith("pattern:"):
            current_pattern = _unquote(stripped.split(":", 1)[1].strip())
            continue
        if stripped.startswith("persona:") and current_pattern:
            persona = _unquote(stripped.split(":", 1)[1].strip())
            if persona:
                rules.append((current_pattern, persona))
            current_pattern = None

    literal_map: dict[str, str] = {}
    for pattern, persona in rules:
        if any(ch in pattern for ch in "*?[]"):
            continue
        literal_map[pattern.lstrip("./")] = persona
    return literal_map


def _unquote(value: str) -> str:
    value = value.strip()
    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in ("'", '"')
    ):
        return value[1:-1]
    return value


__all__ = ["parse_scaffold_ownership"]
