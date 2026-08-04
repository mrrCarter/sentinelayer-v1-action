from __future__ import annotations

import ast
from dataclasses import dataclass
import io
import re
import textwrap
import tokenize

from .pattern_scanner import _truncate_snippet


@dataclass(frozen=True)
class PythonHttpxCall:
    function_name: str
    line_start: int
    line_end: int
    has_timeout: bool


@dataclass(frozen=True)
class _PythonLogicalStatement:
    tokens: tuple[tokenize.TokenInfo, ...]
    start_line: int
    function_name: str | None


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
_SQL_LEADING_COMMENTS_PATTERN = (
    r"(?:(?:/\*[\s\S]{0,1000}?\*/|--[^\r\n]*(?:\r?\n|$))\s*)*"
)
_SQL_IDENTIFIER_PATTERN = (
    r"(?:\{expr\}|[A-Za-z_][A-Za-z0-9_$]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_$]*)*)"
)
_SQL_STRONG_STATEMENT_RE = re.compile(
    rf"""
    ^\s*{_SQL_LEADING_COMMENTS_PATTERN}
    (?:
        SELECT\s+(?:
            [\s\S]{{0,4096}}\bFROM\b
            | [A-Za-z_][A-Za-z0-9_$.]*\s*\([^)]*\{{expr\}}[^)]*\)
            | CASE\b[\s\S]{{0,4096}}\bWHEN\b[\s\S]{{0,4096}}
              \{{expr\}}[\s\S]{{0,4096}}\bTHEN\b
            | [\s\S]{{0,4096}}\{{expr\}}[\s\S]{{0,256}}
              \bAS\s+[A-Za-z_][A-Za-z0-9_$]*
            | (?=[\s\S]{{0,4096}}\{{expr\}})
              (?:[-+]?\d+(?:\.\d+)?|\{{expr\}})
              \s*[-+*/%]\s*
              (?:[-+]?\d+(?:\.\d+)?|\{{expr\}})
            | \{{expr\}}\s*(?:::|->>|->|\#>>|\#>)\s*
              [A-Za-z_'"][A-Za-z0-9_$'"]*
            | (?:DISTINCT|ALL)\s+[\s\S]{{0,4096}}\{{expr\}}
            | [\s\S]{{0,4096}}\{{expr\}}\s*,[\s\S]{{1,4096}}
        )
        | INSERT\s+(?:(?:OR\s+(?:ABORT|FAIL|IGNORE|REPLACE|ROLLBACK)|IGNORE)\s+)?
          INTO\s+{_SQL_IDENTIFIER_PATTERN}(?=\s|\()
        | DELETE\s+FROM\b
        | UPDATE\s+(?:{_SQL_IDENTIFIER_PATTERN}|[^\s;]+)\s+SET\b
        | WITH\b[\s\S]{{0,4096}}\bAS\s*\(
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SQL_AMBIGUOUS_DYNAMIC_SELECT_RE = re.compile(
    rf"^\s*{_SQL_LEADING_COMMENTS_PATTERN}SELECT\s+"
    r"\{expr\}\s*;?\s*$",
    re.IGNORECASE | re.VERBOSE,
)
_SQL_CONTEXT_NAME_RE = re.compile(
    r"(?:^|_)(?:sql|query|statement|stmt)(?:_|$)",
    re.IGNORECASE,
)
_SQL_EXECUTION_CALL_NAMES = frozenset(
    {"execute", "executemany", "executescript", "fetch", "query", "raw"}
)
_PYTHON_PERCENT_FIELD_RE = re.compile(
    r"(?<!%)%(?:\([^)]+\))?[#0+\- ]*\d*(?:\.\d+)?[diouxXeEfFgGcrsa]"
)
_PYTHON_FORMAT_FIELD_RE = re.compile(r"(?<!\{)\{[^{}]*\}(?!\})")
_QUERY_ASSIGNMENT_PREFIX_RE = re.compile(
    r"(?:^|[;])\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?P<target>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=]+)?\s*=\s*(?:\(\s*)*$",
    re.IGNORECASE,
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
    except (SyntaxError, RecursionError, ValueError):
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

    Parsed Python is authoritative. If an unrelated syntax error prevents a
    module parse, tokenized logical statements are recovered without treating
    comments or string contents as executable source.
    """

    try:
        tree = ast.parse(content)
    except (SyntaxError, RecursionError, ValueError):
        return _python_interpolated_sql_lines_from_source(content)

    return _python_interpolated_sql_lines_from_tree(tree)


def _python_interpolated_sql_lines_from_tree(
    tree: ast.AST,
    *,
    line_offset: int = 0,
) -> set[int]:
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    lines: set[int] = set()
    for node in ast.walk(tree):
        template = _dynamic_string_template(node, parents)
        if (
            template is not None
            and _looks_like_sql_statement(template)
            and (
                not _select_requires_sql_context(template)
                or _has_sql_context(node, parents)
            )
        ):
            lines.add(int(getattr(node, "lineno", 1) or 1) + line_offset)
    return lines


def _dynamic_string_template(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> str | None:
    if isinstance(node, ast.JoinedStr):
        return _joined_string_template(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parent = parents.get(node)
        if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
            return None
        return _concatenated_string_template(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _percent_formatted_string_template(node)
    if isinstance(node, ast.Call):
        return _format_call_template(node)
    return None


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
    pending: list[ast.expr] = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            pending.append(current.right)
            pending.append(current.left)
        else:
            operands.append(current)

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
        elif isinstance(operand, ast.Constant):
            return None
        else:
            has_dynamic = True
            parts.append("{expr}")
    if not has_string or not has_dynamic:
        return None
    return "".join(parts)


def _percent_formatted_string_template(node: ast.BinOp) -> str | None:
    if not isinstance(node.left, ast.Constant) or not isinstance(node.left.value, str):
        return None
    if not _PYTHON_PERCENT_FIELD_RE.search(node.left.value):
        return None
    return _PYTHON_PERCENT_FIELD_RE.sub("{expr}", node.left.value)


def _format_call_template(node: ast.Call) -> str | None:
    function = node.func
    if (
        not isinstance(function, ast.Attribute)
        or function.attr not in {"format", "format_map"}
        or not isinstance(function.value, ast.Constant)
        or not isinstance(function.value.value, str)
        or (not node.args and not node.keywords)
        or not _PYTHON_FORMAT_FIELD_RE.search(function.value.value)
    ):
        return None
    return _PYTHON_FORMAT_FIELD_RE.sub("{expr}", function.value.value)


def _looks_like_sql_statement(template: str) -> bool:
    return bool(
        _SQL_STRONG_STATEMENT_RE.search(template)
        or _SQL_AMBIGUOUS_DYNAMIC_SELECT_RE.fullmatch(template)
    )


def _select_requires_sql_context(template: str) -> bool:
    return bool(_SQL_AMBIGUOUS_DYNAMIC_SELECT_RE.fullmatch(template))


def _has_sql_context(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    """Require a direct SQL sink/binding for ambiguous dynamic SELECT text."""

    parent = parents.get(node)
    targets: list[ast.AST] = []
    if isinstance(parent, ast.Assign) and parent.value is node:
        targets.extend(parent.targets)
    elif (
        isinstance(parent, (ast.AnnAssign, ast.NamedExpr))
        and parent.value is node
    ):
        targets.append(parent.target)

    if targets:
        if any(_target_has_sql_context_name(target) for target in targets):
            return True

    call = parent if isinstance(parent, ast.Call) else None
    if isinstance(parent, ast.keyword):
        keyword_call = parents.get(parent)
        if isinstance(keyword_call, ast.Call) and parent.value is node:
            call = keyword_call
    if call is not None and _is_sql_execution_call(call):
        if node in call.args or any(
            keyword.value is node for keyword in call.keywords
        ):
            return True

    if isinstance(parent, ast.Return) and parent.value is node:
        function = _enclosing_function(parent, parents)
        return function is not None and _is_sql_context_name(function.name)

    return False


def _target_has_sql_context_name(target: ast.AST) -> bool:
    if isinstance(target, ast.Name):
        return _is_sql_context_name(target.id)
    if isinstance(target, ast.Attribute):
        return _is_sql_context_name(target.attr)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_has_sql_context_name(element) for element in target.elts)
    return False


def _is_sql_execution_call(call: ast.Call) -> bool:
    function_name = _qualified_name(call.func)
    return bool(
        function_name is not None
        and function_name.rsplit(".", 1)[-1].casefold()
        in _SQL_EXECUTION_CALL_NAMES
    )


def _enclosing_function(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parents.get(current)
    return None


def _is_sql_context_name(name: str) -> bool:
    return bool(_SQL_CONTEXT_NAME_RE.search(name))


def _python_interpolated_sql_lines_from_source(content: str) -> set[int]:
    lines: set[int] = set()
    for statement in _python_logical_statements(content):
        source = _logical_statement_source(statement.tokens)
        if source:
            wrapper_name = (
                statement.function_name
                if statement.function_name
                and statement.function_name.isidentifier()
                else "__recovered__"
            )
            wrapped = (
                f"async def {wrapper_name}():\n"
                f"{textwrap.indent(source, '    ')}\n"
            )
            try:
                tree = ast.parse(wrapped)
            except (SyntaxError, RecursionError, ValueError):
                pass
            else:
                lines.update(
                    _python_interpolated_sql_lines_from_tree(
                        tree,
                        line_offset=statement.start_line - 2,
                    )
                )
        lines.update(_tokenized_statement_sql_lines(statement))
    return lines


def _python_logical_statements(content: str) -> list[_PythonLogicalStatement]:
    statements: list[_PythonLogicalStatement] = []
    current: list[tokenize.TokenInfo] = []
    scope_stack: list[tuple[str, str]] = []
    pending_scope: tuple[str, str] | None = None
    token_stream = tokenize.generate_tokens(io.StringIO(content).readline)

    try:
        for token in token_stream:
            if token.type == tokenize.INDENT:
                if pending_scope is not None:
                    scope_stack.append(pending_scope)
                pending_scope = None
                continue
            if token.type == tokenize.DEDENT:
                if scope_stack:
                    scope_stack.pop()
                continue
            if (
                pending_scope is not None
                and token.type
                not in {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE}
            ):
                pending_scope = None
            if token.type in {tokenize.ENCODING, tokenize.ENDMARKER}:
                if token.type == tokenize.ENDMARKER:
                    _append_logical_statement(statements, current, scope_stack)
                    current = []
                continue

            current.append(token)
            if token.type == tokenize.NEWLINE:
                declaration = _append_logical_statement(
                    statements,
                    current,
                    scope_stack,
                )
                pending_scope = declaration
                current = []
    except (SyntaxError, tokenize.TokenError):
        _append_logical_statement(statements, current, scope_stack)

    return statements


def _append_logical_statement(
    statements: list[_PythonLogicalStatement],
    tokens: list[tokenize.TokenInfo],
    scope_stack: list[tuple[str, str]],
) -> tuple[str, str] | None:
    significant = [
        token for token in tokens if token.type not in _NON_CODE_TOKEN_TYPES
    ]
    if not significant:
        return None
    function_name = next(
        (name for kind, name in reversed(scope_stack) if kind == "function"),
        None,
    )
    statements.append(
        _PythonLogicalStatement(
            tokens=tuple(tokens),
            start_line=significant[0].start[0],
            function_name=function_name,
        )
    )
    return _scope_declaration(significant)


def _scope_declaration(
    tokens: list[tokenize.TokenInfo],
) -> tuple[str, str] | None:
    names = [token.string for token in tokens if token.type == tokenize.NAME]
    if not names:
        return None
    index = 1 if names[0].casefold() == "async" else 0
    if index + 1 >= len(names) or names[index].casefold() not in {"def", "class"}:
        return None
    kind = "function" if names[index].casefold() == "def" else "class"
    return kind, names[index + 1]


def _logical_statement_source(
    tokens: tuple[tokenize.TokenInfo, ...],
) -> str:
    pairs = [
        (token.type, token.string)
        for token in tokens
        if token.type
        not in {
            tokenize.COMMENT,
            tokenize.DEDENT,
            tokenize.ENCODING,
            tokenize.ENDMARKER,
            tokenize.INDENT,
        }
    ]
    return textwrap.dedent(tokenize.untokenize(pairs)).strip()


def _tokenized_statement_sql_lines(
    statement: _PythonLogicalStatement,
) -> set[int]:
    tokens = [
        token
        for token in statement.tokens
        if token.type not in _NON_CODE_TOKEN_TYPES
    ]
    declaration = _scope_declaration(tokens)
    function_name = (
        declaration[1]
        if declaration is not None and declaration[0] == "function"
        else statement.function_name
    )
    lines: set[int] = set()
    for index, token in enumerate(tokens):
        if token.type != tokenize.STRING:
            continue
        template = _token_string_template(tokens, index)
        if template is None or not _looks_like_sql_statement(template):
            continue
        if _select_requires_sql_context(template) and not _token_has_sql_context(
            tokens,
            index,
            function_name=function_name,
        ):
            continue
        lines.add(token.start[0])
    return lines


def _token_string_template(
    tokens: list[tokenize.TokenInfo],
    index: int,
) -> str | None:
    literal = tokens[index].string
    try:
        expression = ast.parse(literal, mode="eval").body
    except (SyntaxError, RecursionError, ValueError):
        expression = None
    if isinstance(expression, ast.JoinedStr):
        return _joined_string_template(expression)

    try:
        value = ast.literal_eval(literal)
    except (SyntaxError, RecursionError, ValueError):
        return None
    if not isinstance(value, str):
        return None

    following = tokens[index + 1 :]
    if following and following[0].type == tokenize.OP:
        operator = following[0].string
        if operator == "+":
            if _token_concat_has_dynamic_operand(following[1:]):
                return f"{value}{{expr}}"
        elif operator == "%" and _PYTHON_PERCENT_FIELD_RE.search(value):
            return _PYTHON_PERCENT_FIELD_RE.sub("{expr}", value)
        elif (
            operator == "."
            and len(following) >= 3
            and following[1].type == tokenize.NAME
            and following[1].string in {"format", "format_map"}
            and following[2].type == tokenize.OP
            and following[2].string == "("
            and _PYTHON_FORMAT_FIELD_RE.search(value)
        ):
            return _PYTHON_FORMAT_FIELD_RE.sub("{expr}", value)
    return None


def _token_concat_has_dynamic_operand(tokens: list[tokenize.TokenInfo]) -> bool:
    cursor = 0
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.type == tokenize.STRING:
            try:
                expression = ast.parse(token.string, mode="eval").body
            except (SyntaxError, RecursionError, ValueError):
                expression = None
            if isinstance(expression, ast.JoinedStr):
                return True
            cursor += 1
        else:
            return True
        if cursor >= len(tokens) or tokens[cursor].string != "+":
            return False
        cursor += 1
    return False


def _token_has_sql_context(
    tokens: list[tokenize.TokenInfo],
    index: int,
    *,
    function_name: str | None,
) -> bool:
    prefix = tokenize.untokenize(
        [(token.type, token.string) for token in tokens[:index]]
    )
    assignment = _QUERY_ASSIGNMENT_PREFIX_RE.search(prefix)
    if assignment is not None and _is_sql_context_name(assignment.group("target")):
        return True

    sink_names = "|".join(sorted(re.escape(name) for name in _SQL_EXECUTION_CALL_NAMES))
    if re.search(
        rf"(?:^|[^\w])(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
        rf"(?:{sink_names})\s*\(\s*"
        r"(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?(?:\(\s*)*$",
        prefix,
        re.IGNORECASE,
    ):
        return True
    return bool(
        function_name
        and _is_sql_context_name(function_name)
        and re.search(r"\breturn\s*(?:\(\s*)*$", prefix, re.IGNORECASE)
    )


def python_httpx_calls(content: str) -> list[PythonHttpxCall]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, RecursionError, ValueError):
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
