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
_SQL_LEADING_COMMENTS = r"(?:(?:/\*[\s\S]{0,400}?\*/|--[^\r\n]*(?:\r?\n|$))\s*)*"
_SQL_IDENTIFIER = (
    r'(?:\{expr\}|[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)*|'
    r'"[^"\r\n]+"|`[^`\r\n]+`|\[[^\]\r\n]+\])'
)
_STRONG_SQL_STATEMENT_RE = re.compile(
    rf"""
    ^\s*{_SQL_LEADING_COMMENTS}
    (?:
        SELECT\s+(?:
            [\s\S]{{0,400}}\bFROM\b
            | (?:DISTINCT\s+|ALL\s+)?(?:\*|[-+]?\d|NULL\b|TRUE\b|FALSE\b)
            | [A-Za-z_][A-Za-z0-9_$]*\s*\(
        )
        | INSERT\s+(?:(?:OR\s+(?:ABORT|FAIL|IGNORE|REPLACE|ROLLBACK)|IGNORE)\s+)?
          INTO\s+{_SQL_IDENTIFIER}(?:\s*\([^)]*\))?\s+
          (?:VALUES\b|SELECT\b|DEFAULT\s+VALUES\b|SET\b)
        | DELETE\s+(?:(?:LOW_PRIORITY|QUICK|IGNORE)\s+)*
          FROM\s+{_SQL_IDENTIFIER}
          (?:\s+(?:AS\s+)?{_SQL_IDENTIFIER})?
          (?:\s*(?:$|;)|\s+(?:WHERE|USING|RETURNING|ORDER\s+BY|LIMIT)\b)
        | UPDATE\s+(?:(?:LOW_PRIORITY|IGNORE|ONLY)\s+)*
          {_SQL_IDENTIFIER}(?:\s+(?:AS\s+)?{_SQL_IDENTIFIER})?\s+SET\b
        | WITH\b[\s\S]{{0,400}}\bAS\s*\(
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_AMBIGUOUS_SQL_PREFIX_RE = re.compile(
    rf"^\s*{_SQL_LEADING_COMMENTS}SELECT\s+\{{expr\}}(?:\s*(?:,|$)|\s+FROM\b)",
    re.IGNORECASE,
)
_SQL_LEADING_KEYWORD_RE = re.compile(
    rf"^\s*{_SQL_LEADING_COMMENTS}(SELECT|INSERT|DELETE|UPDATE|WITH)\b",
    re.IGNORECASE,
)
_QUERY_CONTEXT_NAME_RE = re.compile(
    r"^(?:q|query|sql|stmt|statement|sql_query|query_text|query_string)$",
    re.IGNORECASE,
)
_SQL_SINK_NAMES = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "fetch",
        "fetchrow",
        "fetchval",
        "query",
        "raw",
    }
)
_PYTHON_PERCENT_FIELD_RE = re.compile(
    r"(?<!%)%(?:\([^)]+\))?[#0+\- ]*\d*(?:\.\d+)?[diouxXeEfFgGcrsa]"
)
_PYTHON_FORMAT_FIELD_RE = re.compile(r"(?<!\{)\{[^{}]*\}(?!\})")
_JS_QUOTED_STRING_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
_JS_TEMPLATE_LITERAL_RE = re.compile(r"`(?:\\.|[^`\\])*`", re.DOTALL)
_JS_TEMPLATE_FIELD_RE = re.compile(r"\$\{[^{}]*\}")
_JS_TAG_BEFORE_TEMPLATE_RE = re.compile(
    r"([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*$"
)
_PRISMA_ESM_IMPORT_RE = re.compile(
    r"^\s*import\s*\{(?P<specifiers>[^{}]{1,1000})\}\s*"
    r"from\s*['\"]@prisma/client['\"]\s*$",
    re.DOTALL,
)
_PRISMA_CJS_IMPORT_RE = re.compile(
    r"^\s*(?:const|let|var)\s*\{(?P<specifiers>[^{}]{1,1000})\}\s*=\s*"
    r"require\(\s*['\"]@prisma/client['\"]\s*\)\s*$",
    re.DOTALL,
)
_PRISMA_CJS_PROPERTY_RE = re.compile(
    r"^\s*(?:const|let|var)\s+(?P<binding>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
    r"require\(\s*['\"]@prisma/client['\"]\s*\)\.Prisma\s*$",
    re.DOTALL,
)
_JS_VALUE_DECLARATION_RE = re.compile(
    r"\b(?:const|let|var|class|function)\s+(?P<binding>[A-Za-z_$][A-Za-z0-9_$]*)\b"
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


def javascript_interpolated_sql_lines(content: str) -> set[int]:
    """Return JS/TS lines that dynamically construct SQL outside comments.

    A small lexer masks comments and regular-expression literals without
    disturbing offsets. Templates and concatenation chains are then reduced to
    the same ``{expr}`` representation used by the Python AST path.
    """

    scrubbed = _mask_js_comments_and_regex_literals(content)
    lines: set[int] = set()

    for match in _JS_TEMPLATE_LITERAL_RE.finditer(scrubbed):
        literal = match.group(0)
        if "${" not in literal:
            continue
        if _is_proven_parameterized_js_template(scrubbed, match.start()):
            continue
        template = _JS_TEMPLATE_FIELD_RE.sub("{expr}", literal[1:-1])
        context = _js_has_query_context(scrubbed, match.start())
        if _looks_like_sql_statement(template, allow_ambiguous=context):
            lines.add(index_to_line(content, match.start()))

    for statement_start, statement in _iter_js_statements(scrubbed):
        for relative_start, template in _js_concat_templates(statement):
            context = _js_has_query_context(statement, relative_start)
            if _looks_like_sql_statement(template, allow_ambiguous=context):
                lines.add(index_to_line(content, statement_start + relative_start))

    return lines


def _mask_js_comments_and_regex_literals(content: str) -> str:
    chars = list(content)
    index = 0
    previous_significant: str | None = None
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if char in {"'", '"', "`"}:
            index = _skip_js_quoted(content, index, char)
            previous_significant = char
            continue
        if char == "/" and following == "/":
            end = content.find("\n", index + 2)
            end = len(content) if end < 0 else end
            _blank_js_span(chars, index, end)
            index = end
            continue
        if char == "/" and following == "*":
            closing = content.find("*/", index + 2)
            end = len(content) if closing < 0 else closing + 2
            _blank_js_span(chars, index, end)
            index = end
            continue
        if char == "/" and _js_can_start_regex(previous_significant):
            end = _skip_js_regex_literal(content, index)
            if end > index + 1:
                _blank_js_span(chars, index, end)
                index = end
                previous_significant = "/"
                continue
        if not char.isspace():
            previous_significant = char
        index += 1
    return "".join(chars)


def _skip_js_quoted(content: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(content):
        if content[index] == "\\":
            index += 2
            continue
        if content[index] == quote:
            return index + 1
        index += 1
    return len(content)


def _js_can_start_regex(previous_significant: str | None) -> bool:
    return previous_significant is None or previous_significant in "=([{,:;!?&|+-*%^~<>"


def _skip_js_regex_literal(content: str, start: int) -> int:
    index = start + 1
    in_character_class = False
    while index < len(content):
        char = content[index]
        if char in "\r\n":
            return start + 1
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_character_class = True
        elif char == "]":
            in_character_class = False
        elif char == "/" and not in_character_class:
            index += 1
            while index < len(content) and content[index].isalpha():
                index += 1
            return index
        index += 1
    return start + 1


def _blank_js_span(chars: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(chars))):
        if chars[index] not in "\r\n":
            chars[index] = " "


def _iter_js_statements(content: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    start = 0
    index = 0
    depth = 0
    while index < len(content):
        char = content[index]
        if char in {"'", '"', "`"}:
            index = _skip_js_quoted(content, index, char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(depth - 1, 0)
        if (char == ";" or char in "\r\n") and depth == 0:
            statements.append((start, content[start:index]))
            start = index + 1
        index += 1
    if start < len(content):
        statements.append((start, content[start:]))
    return statements


def _js_concat_templates(statement: str) -> list[tuple[int, str]]:
    templates: list[tuple[int, str]] = []
    string_matches = list(_JS_QUOTED_STRING_RE.finditer(statement))
    for string_index, first in enumerate(string_matches):
        template = _decode_js_string(first.group(0))
        cursor = first.end()
        has_dynamic = False
        next_string_index = string_index + 1
        while True:
            plus = re.match(r"\s*\+\s*", statement[cursor:])
            if plus is None:
                break
            operand_start = cursor + plus.end()
            if next_string_index < len(string_matches):
                next_string = string_matches[next_string_index]
            else:
                next_string = None
            if next_string is not None and next_string.start() == operand_start:
                template += _decode_js_string(next_string.group(0))
                cursor = next_string.end()
                next_string_index += 1
                continue
            next_plus = _find_top_level_js_plus(statement, operand_start)
            template += "{expr}"
            has_dynamic = True
            if next_plus is None:
                cursor = len(statement)
                break
            cursor = next_plus
        if has_dynamic:
            templates.append((first.start(), template))
    return templates


def _find_top_level_js_plus(statement: str, start: int) -> int | None:
    index = start
    depth = 0
    while index < len(statement):
        char = statement[index]
        if char in {"'", '"', "`"}:
            index = _skip_js_quoted(statement, index, char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(depth - 1, 0)
        elif char == "+" and depth == 0:
            return index
        index += 1
    return None


def _decode_js_string(literal: str) -> str:
    return re.sub(r"\\(.)", r"\1", literal[1:-1])


def _js_has_query_context(content: str, position: int) -> bool:
    prefix = content[:position]
    assignment = re.search(
        r"(?:^|[;{}\r\n])\s*(?:const|let|var)?\s*"
        r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;{}\r\n]*$",
        prefix,
        re.IGNORECASE,
    )
    if assignment and _is_query_context_name(assignment.group(1)):
        return True
    sink = re.search(
        r"(?:execute|executemany|executescript|fetch|fetchrow|fetchval|query|raw)\s*\([^)]*$",
        prefix,
        re.IGNORECASE,
    )
    return sink is not None


def _is_proven_parameterized_js_template(
    scrubbed: str,
    template_start: int,
) -> bool:
    tag_match = _JS_TAG_BEFORE_TEMPLATE_RE.search(scrubbed[:template_start])
    if tag_match is None:
        return False
    tag = tag_match.group(1)
    if not tag.endswith(".sql"):
        return False
    binding = tag.removesuffix(".sql")
    if "." in binding:
        return False

    imported_at = _prisma_imported_bindings(scrubbed[:template_start]).get(binding)
    if imported_at is None:
        return False
    intervening_source = scrubbed[imported_at:template_start]
    return not any(
        match.group("binding") == binding
        for match in _JS_VALUE_DECLARATION_RE.finditer(intervening_source)
    )


def _prisma_imported_bindings(source: str) -> dict[str, int]:
    bindings: dict[str, int] = {}
    for statement_start, statement in _iter_js_statements(source):
        stripped = statement.strip()
        esm_match = _PRISMA_ESM_IMPORT_RE.fullmatch(stripped)
        cjs_match = _PRISMA_CJS_IMPORT_RE.fullmatch(stripped)
        match = esm_match or cjs_match
        if match is not None:
            for specifier in match.group("specifiers").split(","):
                specifier = specifier.strip()
                if esm_match is not None:
                    binding_match = re.fullmatch(
                        r"Prisma(?:\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*))?",
                        specifier,
                    )
                else:
                    binding_match = re.fullmatch(
                        r"Prisma(?:\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*))?",
                        specifier,
                    )
                if binding_match is not None:
                    bindings[binding_match.group(1) or "Prisma"] = (
                        statement_start + len(statement)
                    )
            continue
        property_match = _PRISMA_CJS_PROPERTY_RE.fullmatch(stripped)
        if property_match is not None:
            bindings[property_match.group("binding")] = statement_start + len(statement)
    return bindings


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
        template = _interpolated_string_template(node)
        if template is None:
            continue
        has_query_context = _python_has_query_context(node, parents)
        if _looks_like_sql_statement(template, allow_ambiguous=has_query_context):
            lines.add(int(getattr(node, "lineno", 1) or 1) + line_offset)
    return lines


def _python_has_query_context(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    current = node
    while current in parents:
        parent = parents[current]
        if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = getattr(parent, "value", None)
            if value is current:
                targets: list[ast.AST] = []
                if isinstance(parent, ast.Assign):
                    targets.extend(parent.targets)
                else:
                    targets.append(parent.target)
                if any(_target_has_query_name(target) for target in targets):
                    return True
        if isinstance(parent, ast.Call) and (
            current in parent.args
            or any(current is keyword or current is keyword.value for keyword in parent.keywords)
        ):
            function_name = _qualified_name(parent.func)
            if function_name and function_name.rsplit(".", 1)[-1].casefold() in _SQL_SINK_NAMES:
                return True
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_query_context_name(parent.name):
                return True
        current = parent
    return False


def _target_has_query_name(target: ast.AST) -> bool:
    if isinstance(target, ast.Name):
        return _is_query_context_name(target.id)
    if isinstance(target, ast.Attribute):
        return _is_query_context_name(target.attr)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_has_query_name(element) for element in target.elts)
    return False


def _is_query_context_name(name: str) -> bool:
    return bool(_QUERY_CONTEXT_NAME_RE.fullmatch(name))


def _interpolated_string_template(node: ast.AST) -> str | None:
    if isinstance(node, ast.JoinedStr):
        return _joined_string_template(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
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


def _percent_formatted_string_template(node: ast.BinOp) -> str | None:
    if not isinstance(node.left, ast.Constant) or not isinstance(node.left.value, str):
        return None
    if not _PYTHON_PERCENT_FIELD_RE.search(node.left.value):
        return None
    return f"{node.left.value}{{expr}}"


def _format_call_template(node: ast.Call) -> str | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in {"format", "format_map"}:
        return None
    if not isinstance(func.value, ast.Constant) or not isinstance(func.value.value, str):
        return None
    if not node.args and not node.keywords:
        return None
    if not _PYTHON_FORMAT_FIELD_RE.search(func.value.value):
        return None
    return f"{func.value.value}{{expr}}"


def _looks_like_sql_statement(template: str, *, allow_ambiguous: bool = False) -> bool:
    candidate = template
    if allow_ambiguous:
        candidate = re.sub(r"^(?:\s*\{expr\}\s*)+", "", candidate)
    if _STRONG_SQL_STATEMENT_RE.search(candidate):
        if allow_ambiguous:
            return True
        keyword = _SQL_LEADING_KEYWORD_RE.search(candidate)
        return keyword is not None and keyword.group(1).isupper()
    return allow_ambiguous and bool(_AMBIGUOUS_SQL_PREFIX_RE.search(candidate))


def _python_interpolated_sql_lines_from_source(content: str) -> set[int]:
    lines = _python_fstring_sql_lines_from_tokens(content)
    for line_number, source_line in enumerate(content.splitlines(), start=1):
        if not source_line.strip():
            continue
        try:
            line_tree = ast.parse(source_line.lstrip())
        except SyntaxError:
            continue
        lines.update(
            _python_interpolated_sql_lines_from_tree(
                line_tree,
                line_offset=line_number - 1,
            )
        )
    return lines


def _python_fstring_sql_lines_from_tokens(content: str) -> set[int]:
    lines: set[int] = set()
    token_stream = tokenize.generate_tokens(io.StringIO(content).readline)
    try:
        for token in token_stream:
            if token.type != tokenize.STRING:
                continue
            try:
                expression = ast.parse(token.string, mode="eval").body
            except (SyntaxError, ValueError):
                continue
            if not isinstance(expression, ast.JoinedStr):
                continue
            template = _joined_string_template(expression)
            line_prefix = content.splitlines()[token.start[0] - 1][: token.start[1]]
            allow_ambiguous = bool(
                re.search(
                    r"(?:^|\b)(?:q|query|sql|stmt|statement|sql_query)\s*=\s*$",
                    line_prefix,
                    re.IGNORECASE,
                )
            )
            if template is not None and _looks_like_sql_statement(
                template,
                allow_ambiguous=allow_ambiguous,
            ):
                lines.add(token.start[0])
    except (SyntaxError, tokenize.TokenError):
        # Tokens emitted before an unrelated syntax error remain authoritative.
        pass
    return lines


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
