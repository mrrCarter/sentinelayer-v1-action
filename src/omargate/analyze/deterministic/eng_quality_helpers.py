from __future__ import annotations

import ast
from dataclasses import dataclass
import io
import re
import tokenize

from .pattern_scanner import _truncate_snippet


@dataclass(frozen=True)
class PythonHttpxCall:
    function_name: str
    line_start: int
    line_end: int
    has_timeout: bool


_HTTPX_FUNCTION_NAMES = frozenset(
    {
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.AsyncClient",
        "httpx.Client",
    }
)
_HTTPX_FUNCTION_NAMES_BY_CASEFOLD = {
    function_name.casefold(): function_name for function_name in _HTTPX_FUNCTION_NAMES
}
_MAX_FALLBACK_CALL_TOKENS = 512
_SQL_STATEMENT_PREFIX_RE = re.compile(
    r"""
    ^\s*
    (?:
        SELECT\b[\s\S]{0,400}\bFROM\b
        | INSERT\s+INTO\b
        | DELETE\s+FROM\b
        | UPDATE\s+(?:\{expr\}|[^\s;]+)\s+SET\b
        | WITH\b[\s\S]{0,400}\bAS\s*\(
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_PYTHON_FSTRING_SQL_FALLBACK_RE = re.compile(
    r"""
    (?:^|[=(,:])\s*
    (?:[rub]*f[rub]*)
    (?:'''|\"\"\"|'|\")
    \s*(?:
        SELECT\b[^\n]{0,400}\bFROM\b
        | INSERT\s+INTO\b
        | DELETE\s+FROM\b
        | UPDATE\s+[^\s;]+\s+SET\b
        | WITH\b[^\n]{0,400}\bAS\s*\(
    )
    [^\n]{0,1000}\{[^{}\n]+\}
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_PYTHON_CONCAT_SQL_FALLBACK_RE = re.compile(
    r"""
    (?:^|[=(,:])\s*
    (?P<quote>'''|\"\"\"|'|\")
    \s*(?:
        SELECT\b[^\n]{0,400}\bFROM\b
        | INSERT\s+INTO\b
        | DELETE\s+FROM\b
        | UPDATE\s+[^\s;]+\s+SET\b
        | WITH\b[^\n]{0,400}\bAS\s*\(
    )
    [^\n]{0,1000}(?P=quote)\s*\+
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_NON_CODE_TOKEN_TYPES = frozenset(
    {
        tokenize.COMMENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
        tokenize.INDENT,
        tokenize.NEWLINE,
        tokenize.NL,
    }
)


def is_test_file(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    if "/tests/" in normalized or "/test/" in normalized or "__tests__" in normalized:
        return True
    return bool(re.search(r"\.(test|spec)\.[a-z0-9]+$", normalized))


def index_to_line(content: str, idx: int) -> int:
    if idx <= 0:
        return 1
    return content.count("\n", 0, idx) + 1


def line_snippet(content: str, line_start: int, line_end: int) -> str:
    if not content:
        return ""
    lines = content.splitlines()
    start = max(line_start - 1, 0)
    end = min(line_end, len(lines))
    snippet = "\n".join(lines[start:end])
    return _truncate_snippet(snippet)


def blank_non_newlines(text: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in text)


def strip_js_comments_and_strings(content: str, comments_and_strings_re: re.Pattern[str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        return blank_non_newlines(match.group(0))

    return comments_and_strings_re.sub(_replace, content)


def python_eval_call_lines(content: str) -> set[int]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set()

    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in {"eval", "exec"}:
                lines.add(int(getattr(node, "lineno", 1) or 1))
        elif isinstance(func, ast.Attribute):
            if func.attr in {"eval", "exec"}:
                lines.add(int(getattr(node, "lineno", 1) or 1))
    return lines


def python_interpolated_sql_lines(content: str) -> set[int]:
    """Return Python source lines that dynamically construct SQL statements.

    Parsed Python is authoritative. The bounded regex fallback exists only for
    otherwise-unparseable files and requires the string itself to begin with a
    SQL statement shape; ordinary prose containing words such as ``update`` is
    intentionally not enough.
    """

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _python_interpolated_sql_lines_from_source(content)

    lines: set[int] = set()
    for node in ast.walk(tree):
        template: str | None = None
        if isinstance(node, ast.JoinedStr):
            template = _joined_string_template(node)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            template = _concatenated_string_template(node)
        if template is not None and _looks_like_sql_statement(template):
            lines.add(int(getattr(node, "lineno", 1) or 1))
    return lines


def _joined_string_template(node: ast.JoinedStr) -> str | None:
    if not any(isinstance(value, ast.FormattedValue) for value in node.values):
        return None
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            parts.append("{expr}")
    return "".join(parts)


def _concatenated_string_template(node: ast.BinOp) -> str | None:
    operands: list[ast.expr] = []

    def _flatten(current: ast.expr) -> None:
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            _flatten(current.left)
            _flatten(current.right)
        else:
            operands.append(current)

    _flatten(node)
    has_string = False
    has_dynamic = False
    parts: list[str] = []
    for operand in operands:
        if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
            has_string = True
            parts.append(operand.value)
        elif isinstance(operand, ast.JoinedStr):
            nested = _joined_string_template(operand)
            if nested is None:
                return None
            has_string = True
            has_dynamic = True
            parts.append(nested)
        else:
            has_dynamic = True
            parts.append("{expr}")
    if not has_string or not has_dynamic:
        return None
    return "".join(parts)


def _looks_like_sql_statement(template: str) -> bool:
    return bool(_SQL_STATEMENT_PREFIX_RE.search(template))


def _python_interpolated_sql_lines_from_source(content: str) -> set[int]:
    matches = [
        *_PYTHON_FSTRING_SQL_FALLBACK_RE.finditer(content),
        *_PYTHON_CONCAT_SQL_FALLBACK_RE.finditer(content),
    ]
    return {index_to_line(content, match.start()) for match in matches}


def python_httpx_calls(content: str) -> list[PythonHttpxCall]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _python_httpx_calls_from_tokens(content)

    calls: list[PythonHttpxCall] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = _qualified_name(node.func)
        canonical_name = (
            _HTTPX_FUNCTION_NAMES_BY_CASEFOLD.get(function_name.casefold())
            if function_name is not None
            else None
        )
        if canonical_name is None:
            continue
        line_start = int(getattr(node, "lineno", 1) or 1)
        calls.append(
            PythonHttpxCall(
                function_name=canonical_name,
                line_start=line_start,
                line_end=int(getattr(node, "end_lineno", line_start) or line_start),
                has_timeout=any(keyword.arg == "timeout" for keyword in node.keywords),
            )
        )

    return sorted(calls, key=lambda call: (call.line_start, call.line_end))


def _qualified_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def _python_httpx_calls_from_tokens(content: str) -> list[PythonHttpxCall]:
    tokens: list[tokenize.TokenInfo] = []
    token_stream = tokenize.generate_tokens(io.StringIO(content).readline)
    try:
        for token in token_stream:
            if token.type not in _NON_CODE_TOKEN_TYPES:
                tokens.append(token)
    except (SyntaxError, tokenize.TokenError):
        # Tokenization is still useful up to an unrelated syntax error.
        pass

    calls: list[PythonHttpxCall] = []
    for index in range(len(tokens) - 3):
        if not (
            tokens[index].type == tokenize.NAME
            and tokens[index].string.casefold() == "httpx"
            and tokens[index + 1].type == tokenize.OP
            and tokens[index + 1].string == "."
            and tokens[index + 2].type == tokenize.NAME
            and tokens[index + 3].type == tokenize.OP
            and tokens[index + 3].string == "("
        ):
            continue
        canonical_name = _HTTPX_FUNCTION_NAMES_BY_CASEFOLD.get(
            f"httpx.{tokens[index + 2].string}".casefold()
        )
        if canonical_name is None:
            continue
        call = _balanced_httpx_call(
            tokens,
            function_name=canonical_name,
            function_index=index + 2,
            open_paren_index=index + 3,
        )
        if call is not None:
            calls.append(call)

    return sorted(calls, key=lambda call: (call.line_start, call.line_end))


def _balanced_httpx_call(
    tokens: list[tokenize.TokenInfo],
    *,
    function_name: str,
    function_index: int,
    open_paren_index: int,
) -> PythonHttpxCall | None:
    opening_for_closing = {")": "(", "]": "[", "}": "{"}
    opening_tokens = frozenset(opening_for_closing.values())
    stack: list[str] = []
    has_timeout = False
    scan_limit = min(
        len(tokens),
        open_paren_index + _MAX_FALLBACK_CALL_TOKENS + 1,
    )

    for index in range(open_paren_index, scan_limit):
        token = tokens[index]
        if token.type == tokenize.OP and token.string in opening_tokens:
            stack.append(token.string)
            continue
        if token.type == tokenize.OP and token.string in opening_for_closing:
            if not stack or stack[-1] != opening_for_closing[token.string]:
                return None
            stack.pop()
            if not stack:
                return PythonHttpxCall(
                    function_name=function_name,
                    line_start=tokens[function_index - 2].start[0],
                    line_end=token.end[0],
                    has_timeout=has_timeout,
                )
            continue
        if (
            len(stack) == 1
            and token.type == tokenize.NAME
            and token.string == "timeout"
            and index + 1 < scan_limit
            and tokens[index + 1].type == tokenize.OP
            and tokens[index + 1].string == "="
            and (
                index == open_paren_index + 1
                or (
                    tokens[index - 1].type == tokenize.OP
                    and tokens[index - 1].string == ","
                )
            )
        ):
            has_timeout = True

    return None
