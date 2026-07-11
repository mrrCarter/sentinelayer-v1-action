from __future__ import annotations

import re


_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:key|api_key|access_token|token|signature)=)([^&#\s]+)"
)
_JSON_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>["']?
      (?:api[_-]?key|access[_-]?token|token|authorization|x[-_]?api[-_]?key)
      ["']?\s*[:=]\s*["']?
    )
    (?P<value>[^"',\s}\]]{8,})
    """
)
_KEYLIKE_RE = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|"
    r"AIza[0-9A-Za-z_-]{20,}|xai-[A-Za-z0-9_-]{16,}|slrt_v1\.[A-Za-z0-9_.-]+|"
    r"sl_[A-Za-z0-9_-]{16,})\b"
)
_GOOGLE_PROJECT_RESOURCE_RE = re.compile(r"(?i)\bprojects/\d{6,}\b")
_PROVIDER_ID_RE = re.compile(
    r"""(?ix)
    \b(?:
      consumer(?:[\s_-]+project)?|
      project(?:[\s_-]+(?:number|id))?|
      provider[\s_-]+(?:consumer|project|account|tenant)
    )
    (?P<sep>\s*[:=/]\s*|\s+)
    (?P<quote>["']?)
    (?P<value>(?:projects/)?[A-Za-z0-9][A-Za-z0-9_.:-]{5,})
    (?P=quote)
    """
)


def sanitize_public_error(value: object) -> str:
    """Redact provider identifiers and key-like material from public outputs."""

    text = str(value or "")
    if not text:
        return ""

    text = _QUERY_SECRET_RE.sub(r"\1[redacted]", text)
    text = _JSON_SECRET_RE.sub(r"\g<prefix>[redacted]", text)
    text = _KEYLIKE_RE.sub("[redacted-secret]", text)

    def _provider_repl(match: re.Match[str]) -> str:
        prefix = match.group(0)[: match.start("value") - match.start()]
        quote = match.group("quote") or ""
        return f"{prefix}[redacted-provider-id]{quote}"

    text = _PROVIDER_ID_RE.sub(_provider_repl, text)
    return _GOOGLE_PROJECT_RESOURCE_RE.sub("projects/[redacted]", text)
