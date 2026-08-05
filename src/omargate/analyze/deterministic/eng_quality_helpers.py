from __future__ import annotations

import ast
from dataclasses import dataclass
import io
import re
import string
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
    scope_key: tuple[int, ...]


_SqlBindingState = dict[str, frozenset[int]]


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
_MAX_FALLBACK_EXPRESSION_TOKENS = 512
_MAX_FALLBACK_CONTEXT_TOKENS = 128
_SQL_LEADING_COMMENTS_PATTERN = (
    r"(?:(?:/\*[\s\S]{0,1000}?\*/|--[^\r\n]*(?:\r?\n|$))\s*)*"
)
_SQL_IDENTIFIER_PART_PATTERN = (
    r'(?:\{expr\}|[A-Za-z_][A-Za-z0-9_$]*|"(?:[^"]|"")*"|'
    r"`[^`]+`|\[[^\]]+\])"
)
_SQL_IDENTIFIER_PATTERN = (
    rf"{_SQL_IDENTIFIER_PART_PATTERN}"
    rf"(?:\s*\.\s*{_SQL_IDENTIFIER_PART_PATTERN})*"
)
_SQL_STRONG_STATEMENT_RE = re.compile(
    rf"""
    ^\s*{_SQL_LEADING_COMMENTS_PATTERN}
    (?:
        SELECT\s+(?:
            [\s\S]{{0,4096}}\bFROM\b
            | [A-Za-z_][A-Za-z0-9_$.]*\s*\([^)]*\{{expr\}}[^)]*\)
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
    r"(?=[\s\S]{0,4096}\{expr\})[\s\S]{1,4096}\s*;?\s*$",
    re.IGNORECASE | re.VERBOSE,
)
_SQL_CONTEXT_NAME_RE = re.compile(
    r"(?:^|_)(?:sql|query|statement|stmt)(?:_|$)",
    re.IGNORECASE,
)
_SQL_EXECUTION_CALL_NAMES = frozenset(
    {"execute", "executemany", "executescript", "fetch", "query", "raw"}
)
_SQL_EXECUTION_KEYWORD_NAMES = frozenset(
    {"operation", "query", "sql", "statement", "stmt", "text"}
)
_SQL_TRANSPARENT_STRING_METHODS = frozenset(
    {
        "casefold",
        "lower",
        "lstrip",
        "removeprefix",
        "removesuffix",
        "replace",
        "rstrip",
        "strip",
        "upper",
    }
)
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
    lines.update(
        line + line_offset
        for line in _ordered_sql_binding_lines(tree, parents)
    )
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
    return _percent_format_template(node.left.value)


def _format_call_template(node: ast.Call) -> str | None:
    function = node.func
    if (
        not isinstance(function, ast.Attribute)
        or function.attr not in {"format", "format_map"}
        or not isinstance(function.value, ast.Constant)
        or not isinstance(function.value.value, str)
    ):
        return None
    if function.attr == "format":
        if not node.args and not node.keywords:
            return None
    elif len(node.args) != 1 or node.keywords:
        return None
    return _brace_format_template(function.value.value)


def _percent_format_template(value: str) -> str | None:
    """Normalize real printf fields while treating ``%%`` as a literal percent."""

    parts: list[str] = []
    found_field = False
    cursor = 0
    while cursor < len(value):
        if value[cursor] != "%":
            parts.append(value[cursor])
            cursor += 1
            continue
        if cursor + 1 < len(value) and value[cursor + 1] == "%":
            parts.append("%")
            cursor += 2
            continue

        cursor += 1
        if cursor < len(value) and value[cursor] == "(":
            depth = 1
            cursor += 1
            key_start = cursor
            while cursor < len(value) and depth:
                if value[cursor] == "(":
                    depth += 1
                elif value[cursor] == ")":
                    depth -= 1
                cursor += 1
            if depth or cursor - 1 == key_start:
                return None

        while cursor < len(value) and value[cursor] in "#0- +":
            cursor += 1
        if cursor < len(value) and value[cursor] == "*":
            cursor += 1
        else:
            while cursor < len(value) and value[cursor].isascii() and value[cursor].isdigit():
                cursor += 1
        if cursor < len(value) and value[cursor] == ".":
            cursor += 1
            if cursor < len(value) and value[cursor] == "*":
                cursor += 1
            else:
                while (
                    cursor < len(value)
                    and value[cursor].isascii()
                    and value[cursor].isdigit()
                ):
                    cursor += 1
        if cursor < len(value) and value[cursor] in "hlL":
            cursor += 1
        if cursor >= len(value) or value[cursor] not in "diouxXeEfFgGcrsa":
            return None
        cursor += 1
        parts.append("{expr}")
        found_field = True

    return "".join(parts) if found_field else None


def _brace_format_template(value: str) -> str | None:
    """Normalize ``str.format`` fields without evaluating field names."""

    parts: list[str] = []
    found_field = False
    try:
        parsed = string.Formatter().parse(value)
        for literal, field_name, _format_spec, conversion in parsed:
            parts.append(literal)
            if field_name is not None:
                if conversion not in {None, "a", "r", "s"}:
                    return None
                parts.append("{expr}")
                found_field = True
    except ValueError:
        return None
    return "".join(parts) if found_field else None


def _looks_like_sql_statement(template: str) -> bool:
    return bool(
        _SQL_STRONG_STATEMENT_RE.search(template)
        or _SQL_AMBIGUOUS_DYNAMIC_SELECT_RE.fullmatch(template)
    )


def _select_requires_sql_context(template: str) -> bool:
    return bool(
        _SQL_AMBIGUOUS_DYNAMIC_SELECT_RE.fullmatch(template)
        and not _SQL_STRONG_STATEMENT_RE.search(template)
    )


def _has_sql_context(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    """Require a direct SQL sink/binding for ambiguous dynamic SELECT text.

    A small set of value-preserving expression wrappers is transparent. This
    covers common production forms such as ``sql.strip()``, conditional
    expressions, and assignment expressions without treating arbitrary
    containers or function calls as SQL context.
    """

    current = node
    while True:
        parent = parents.get(current)
        if parent is None:
            return False

        targets: list[ast.AST] = []
        if isinstance(parent, ast.Assign) and parent.value is current:
            targets.extend(parent.targets)
        elif (
            isinstance(parent, (ast.AnnAssign, ast.NamedExpr))
            and parent.value is current
        ):
            targets.append(parent.target)
        if targets:
            if any(_target_has_sql_context_name(target) for target in targets):
                return True
            if isinstance(parent, ast.NamedExpr):
                current = parent
                continue
            return False

        if isinstance(parent, ast.keyword) and parent.value is current:
            keyword_call = parents.get(parent)
            return bool(
                isinstance(keyword_call, ast.Call)
                and _is_sql_execution_call(keyword_call)
                and parent.arg is not None
                and parent.arg.casefold() in _SQL_EXECUTION_KEYWORD_NAMES
            )

        if isinstance(parent, ast.Call):
            if current in _sql_execution_value_arguments(parent):
                return _is_sql_execution_call(parent)
            if current is parent.func and _is_transparent_string_call(parent):
                current = parent
                continue
            return False

        if isinstance(parent, ast.Return) and parent.value is current:
            function = _enclosing_function(parent, parents)
            return function is not None and _is_sql_context_name(function.name)

        if isinstance(parent, ast.Attribute) and parent.value is current:
            attribute_call = parents.get(parent)
            if (
                isinstance(attribute_call, ast.Call)
                and attribute_call.func is parent
                and _is_transparent_string_call(attribute_call)
            ):
                current = parent
                continue
            return False

        if _is_transparent_sql_expression_parent(current, parent):
            current = parent
            continue
        return False


def _is_transparent_string_call(call: ast.Call) -> bool:
    return bool(
        isinstance(call.func, ast.Attribute)
        and call.func.attr.casefold() in _SQL_TRANSPARENT_STRING_METHODS
    )


def _is_transparent_sql_expression_parent(
    child: ast.AST,
    parent: ast.AST,
) -> bool:
    if isinstance(parent, ast.Await):
        return parent.value is child
    if isinstance(parent, ast.IfExp):
        return child in {parent.body, parent.orelse}
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


def _sql_execution_value_arguments(call: ast.Call) -> list[ast.expr]:
    arguments = list(call.args[:1])
    arguments.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg is not None
        and keyword.arg.casefold() in _SQL_EXECUTION_KEYWORD_NAMES
    )
    return arguments


def _ordered_sql_binding_lines(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> set[int]:
    """Find dynamic SQL definitions that reach a later SQL execution call.

    This is deliberately local and forward-only. Each lexical scope starts
    with an empty state, assignments kill the previous definition, and branch
    states are merged only after their mutually exclusive bodies have been
    evaluated. It supplies the context for otherwise ambiguous ``SELECT``
    text without restoring the old flow-insensitive name search.
    """

    lines: set[int] = set()
    if isinstance(tree, ast.Module):
        _analyze_sql_statement_block(tree.body, {}, parents, lines)
    elif isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        _analyze_sql_statement_block(tree.body, {}, parents, lines)
    return lines


def _analyze_sql_statement_block(
    statements: list[ast.stmt],
    initial_state: dict[str, frozenset[int]] | None,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> dict[str, frozenset[int]] | None:
    if initial_state is None:
        return None
    state: _SqlBindingState | None = dict(initial_state)
    for statement in statements:
        assert state is not None
        state = _analyze_sql_statement(statement, state, parents, lines)
        if state is None:
            break
    return state


def _analyze_sql_statement(
    statement: ast.stmt,
    state: dict[str, frozenset[int]],
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> dict[str, frozenset[int]] | None:
    current = dict(state)

    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for expression in [
            *statement.decorator_list,
            *statement.args.defaults,
            *(default for default in statement.args.kw_defaults if default is not None),
        ]:
            _record_sql_sink_binding_uses(expression, current, lines)
            _apply_named_expression_bindings(expression, current, parents)
        current.pop(statement.name, None)
        _analyze_sql_statement_block(statement.body, {}, parents, lines)
        return current

    if isinstance(statement, ast.ClassDef):
        for expression in [
            *statement.decorator_list,
            *statement.bases,
            *(keyword.value for keyword in statement.keywords),
        ]:
            _record_sql_sink_binding_uses(expression, current, lines)
            _apply_named_expression_bindings(expression, current, parents)
        current.pop(statement.name, None)
        _analyze_sql_statement_block(statement.body, {}, parents, lines)
        return current

    if isinstance(statement, ast.If):
        _record_sql_sink_binding_uses(statement.test, current, lines)
        _apply_named_expression_bindings(statement.test, current, parents)
        body_state = _analyze_sql_statement_block(
            statement.body, current, parents, lines
        )
        else_state = (
            _analyze_sql_statement_block(statement.orelse, current, parents, lines)
            if statement.orelse
            else current
        )
        return _merge_sql_binding_states(body_state, else_state)

    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _record_sql_sink_binding_uses(statement.iter, current, lines)
        _apply_named_expression_bindings(statement.iter, current, parents)
        body_input = dict(current)
        _kill_sql_binding_targets(body_input, [statement.target])
        body_state = _analyze_sql_statement_block(
            statement.body, body_input, parents, lines
        )
        loop_state = _merge_sql_binding_states(current, body_state)
        return (
            _analyze_sql_statement_block(
                statement.orelse, loop_state, parents, lines
            )
            if statement.orelse
            else loop_state
        )

    if isinstance(statement, ast.While):
        _record_sql_sink_binding_uses(statement.test, current, lines)
        _apply_named_expression_bindings(statement.test, current, parents)
        body_state = _analyze_sql_statement_block(
            statement.body, current, parents, lines
        )
        loop_state = _merge_sql_binding_states(current, body_state)
        return (
            _analyze_sql_statement_block(
                statement.orelse, loop_state, parents, lines
            )
            if statement.orelse
            else loop_state
        )

    if isinstance(statement, (ast.Try, ast.TryStar)):
        body_state = _analyze_sql_statement_block(
            statement.body, current, parents, lines
        )
        normal_state = (
            _analyze_sql_statement_block(
                statement.orelse, body_state, parents, lines
            )
            if statement.orelse
            else body_state
        )
        outcomes = [normal_state]
        for handler in statement.handlers:
            handler_state = dict(current)
            if handler.type is not None:
                _record_sql_sink_binding_uses(handler.type, handler_state, lines)
                _apply_named_expression_bindings(
                    handler.type, handler_state, parents
                )
            if handler.name:
                handler_state.pop(handler.name, None)
            outcomes.append(
                _analyze_sql_statement_block(
                    handler.body, handler_state, parents, lines
                )
            )
        merged = _merge_sql_binding_states(*outcomes)
        return (
            _analyze_sql_statement_block(
                statement.finalbody, merged, parents, lines
            )
            if statement.finalbody
            else merged
        )

    if isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            _record_sql_sink_binding_uses(item.context_expr, current, lines)
            _apply_named_expression_bindings(item.context_expr, current, parents)
            if item.optional_vars is not None:
                _kill_sql_binding_targets(current, [item.optional_vars])
        return _analyze_sql_statement_block(statement.body, current, parents, lines)

    if isinstance(statement, ast.Match):
        _record_sql_sink_binding_uses(statement.subject, current, lines)
        _apply_named_expression_bindings(statement.subject, current, parents)
        outcomes = [current]
        for case in statement.cases:
            case_state = dict(current)
            if case.guard is not None:
                _record_sql_sink_binding_uses(case.guard, case_state, lines)
                _apply_named_expression_bindings(case.guard, case_state, parents)
            outcomes.append(
                _analyze_sql_statement_block(
                    case.body, case_state, parents, lines
                )
            )
        return _merge_sql_binding_states(*outcomes)

    _record_sql_sink_binding_uses(statement, current, lines)
    _apply_named_expression_bindings(statement, current, parents)
    if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return None
    if isinstance(statement, ast.Assign):
        _assign_sql_bindings(
            current, statement.targets, statement.value, parents
        )
    elif isinstance(statement, ast.AnnAssign):
        _assign_sql_bindings(
            current,
            [statement.target],
            statement.value,
            parents,
        )
    elif isinstance(statement, ast.AugAssign):
        previous = _origins_for_binding_targets(current, [statement.target])
        origins = previous.union(
            _sql_origins_in_expression(statement.value, current, parents)
        )
        _set_sql_binding_targets(current, [statement.target], origins)
    elif isinstance(statement, ast.Delete):
        _kill_sql_binding_targets(current, statement.targets)
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        for alias in statement.names:
            current.pop(alias.asname or alias.name.split(".", 1)[0], None)
    return current


def _record_sql_sink_binding_uses(
    node: ast.AST,
    state: dict[str, frozenset[int]],
    lines: set[int],
) -> None:
    pending = [node]
    while pending:
        candidate = pending.pop()
        if candidate is not node and isinstance(
            candidate,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        if isinstance(candidate, ast.Call) and _is_sql_execution_call(candidate):
            for argument in _sql_execution_value_arguments(candidate):
                for key in _binding_reference_keys(argument):
                    lines.update(state.get(key, ()))
        pending.extend(ast.iter_child_nodes(candidate))


def _assign_sql_bindings(
    state: dict[str, frozenset[int]],
    targets: list[ast.expr],
    value: ast.expr | None,
    parents: dict[ast.AST, ast.AST],
) -> None:
    origins = (
        _sql_origins_in_expression(value, state, parents)
        if value is not None
        else set()
    )
    _set_sql_binding_targets(state, targets, origins)


def _sql_origins_in_expression(
    expression: ast.expr,
    state: dict[str, frozenset[int]],
    parents: dict[ast.AST, ast.AST],
) -> set[int]:
    origins: set[int] = set()
    pending: list[ast.expr] = [expression]
    while pending:
        candidate = pending.pop()
        template = _dynamic_string_template(candidate, parents)
        if template is not None and _looks_like_sql_statement(template):
            origins.add(int(getattr(candidate, "lineno", 1) or 1))
            continue
        reference = _qualified_name(candidate)
        if reference is not None:
            origins.update(state.get(reference, ()))
            continue
        if isinstance(candidate, ast.NamedExpr):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.IfExp):
            pending.extend((candidate.orelse, candidate.body))
        elif isinstance(candidate, ast.Await):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.Call) and _is_transparent_string_call(candidate):
            assert isinstance(candidate.func, ast.Attribute)
            pending.append(candidate.func.value)
        elif isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.Add):
            pending.extend((candidate.right, candidate.left))
    return origins


def _binding_reference_keys(expression: ast.AST) -> set[str]:
    keys: set[str] = set()
    pending = [expression]
    while pending:
        candidate = pending.pop()
        reference = (
            _qualified_name(candidate)
            if isinstance(candidate, ast.expr)
            else None
        )
        if reference is not None:
            keys.add(reference)
        elif isinstance(candidate, ast.NamedExpr):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.IfExp):
            pending.extend((candidate.orelse, candidate.body))
        elif isinstance(candidate, ast.Await):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.Call) and _is_transparent_string_call(candidate):
            assert isinstance(candidate.func, ast.Attribute)
            pending.append(candidate.func.value)
        elif isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.Add):
            pending.extend((candidate.right, candidate.left))
    return keys


def _apply_named_expression_bindings(
    node: ast.AST,
    state: dict[str, frozenset[int]],
    parents: dict[ast.AST, ast.AST],
) -> None:
    events: list[
        tuple[
            str,
            ast.AST,
            _SqlBindingState,
            _SqlBindingState | None,
            _SqlBindingState | None,
        ]
    ] = [("visit", node, state, None, None)]
    skipped = (
        ast.BoolOp,
        ast.ClassDef,
        ast.DictComp,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.GeneratorExp,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
    )
    while events:
        kind, current, current_state, body_state, else_state = events.pop()
        if kind == "bind":
            assert isinstance(current, ast.NamedExpr)
            origins = _sql_origins_in_expression(
                current.value, current_state, parents
            )
            _set_sql_binding_targets(current_state, [current.target], origins)
            continue
        if kind == "start_if":
            assert isinstance(current, ast.IfExp)
            body_state = dict(current_state)
            else_state = dict(current_state)
            events.append(
                ("merge_if", current, current_state, body_state, else_state)
            )
            events.append(("visit", current.orelse, else_state, None, None))
            events.append(("visit", current.body, body_state, None, None))
            continue
        if kind == "merge_if":
            assert body_state is not None and else_state is not None
            merged = _merge_sql_binding_states(body_state, else_state)
            current_state.clear()
            current_state.update(merged or {})
            continue
        if isinstance(current, skipped):
            continue
        if isinstance(current, ast.NamedExpr):
            events.append(("bind", current, current_state, None, None))
            events.append(("visit", current.value, current_state, None, None))
            continue
        if isinstance(current, ast.IfExp):
            events.append(("start_if", current, current_state, None, None))
            events.append(("visit", current.test, current_state, None, None))
            continue
        children = list(ast.iter_child_nodes(current))
        events.extend(
            ("visit", child, current_state, None, None)
            for child in reversed(children)
        )


def _binding_target_keys(target: ast.AST) -> set[str]:
    reference = _qualified_name(target) if isinstance(target, ast.expr) else None
    if reference is not None:
        return {reference}
    if isinstance(target, (ast.Tuple, ast.List)):
        return {
            key
            for element in target.elts
            for key in _binding_target_keys(element)
        }
    return set()


def _set_sql_binding_targets(
    state: dict[str, frozenset[int]],
    targets: list[ast.expr],
    origins: set[int],
) -> None:
    for target in targets:
        for key in _binding_target_keys(target):
            if origins:
                state[key] = frozenset(origins)
            else:
                state.pop(key, None)


def _kill_sql_binding_targets(
    state: dict[str, frozenset[int]],
    targets: list[ast.expr],
) -> None:
    _set_sql_binding_targets(state, targets, set())


def _origins_for_binding_targets(
    state: dict[str, frozenset[int]],
    targets: list[ast.expr],
) -> set[int]:
    return {
        origin
        for target in targets
        for key in _binding_target_keys(target)
        for origin in state.get(key, ())
    }


def _merge_sql_binding_states(
    *states: dict[str, frozenset[int]] | None,
) -> dict[str, frozenset[int]] | None:
    merged: dict[str, set[int]] = {}
    for state in states:
        if state is None:
            continue
        for key, origins in state.items():
            merged.setdefault(key, set()).update(origins)
    if not any(state is not None for state in states):
        return None
    return {key: frozenset(origins) for key, origins in merged.items() if origins}


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
    states_by_scope: dict[
        tuple[int, ...],
        dict[str, frozenset[int]] | None,
    ] = {}
    for statement in _python_logical_statements(content):
        if _is_compound_control_header(statement.tokens):
            # Recovery intentionally supports only straight-line def/use.
            # Without a complete CFG for malformed modules, carrying a value
            # across a conditional suite can connect mutually exclusive paths.
            states_by_scope[statement.scope_key] = {}
        source = _logical_statement_source(statement.tokens)
        parsed = False
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
                parsed = True
                ast.increment_lineno(tree, statement.start_line - 2)
                lines.update(_python_interpolated_sql_lines_from_tree(tree))
                parents = {
                    child: parent
                    for parent in ast.walk(tree)
                    for child in ast.iter_child_nodes(parent)
                }
                recovered_function = tree.body[0]
                assert isinstance(recovered_function, ast.AsyncFunctionDef)
                scope_state = states_by_scope.get(statement.scope_key, {})
                states_by_scope[statement.scope_key] = _analyze_sql_statement_block(
                    recovered_function.body,
                    scope_state,
                    parents,
                    lines,
                )
        if not parsed:
            lines.update(_tokenized_statement_sql_lines(statement))
    return lines


def _is_compound_control_header(
    tokens: tuple[tokenize.TokenInfo, ...],
) -> bool:
    significant = [
        token for token in tokens if token.type not in _NON_CODE_TOKEN_TYPES
    ]
    names = [
        token.string.casefold()
        for token in significant
        if token.type == tokenize.NAME
    ]
    first_name = names[1] if len(names) > 1 and names[0] == "async" else names[0] if names else None
    return bool(
        significant
        and significant[-1].string == ":"
        and first_name
        in {
            "case",
            "elif",
            "else",
            "except",
            "finally",
            "for",
            "if",
            "match",
            "try",
            "while",
            "with",
        }
    )


def _python_logical_statements(content: str) -> list[_PythonLogicalStatement]:
    statements: list[_PythonLogicalStatement] = []
    current: list[tokenize.TokenInfo] = []
    # Keep one frame for every INDENT, including non-declaration suites such as
    # ``if`` and ``try``.  Otherwise their DEDENT would incorrectly pop an
    # enclosing function/class declaration and lose the return-value context.
    scope_stack: list[tuple[int, tuple[str, str] | None]] = []
    pending_scope: tuple[str, str] | None = None
    next_scope_id = 1
    token_stream = tokenize.generate_tokens(io.StringIO(content).readline)

    try:
        for token in token_stream:
            if token.type == tokenize.INDENT:
                scope_stack.append((next_scope_id, pending_scope))
                next_scope_id += 1
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
    scope_stack: list[tuple[int, tuple[str, str] | None]],
) -> tuple[str, str] | None:
    significant = [
        token for token in tokens if token.type not in _NON_CODE_TOKEN_TYPES
    ]
    if not significant:
        return None
    function_name = next(
        (
            declaration[1]
            for _, declaration in reversed(scope_stack)
            if declaration is not None and declaration[0] == "function"
        ),
        None,
    )
    statements.append(
        _PythonLogicalStatement(
            tokens=tuple(tokens),
            start_line=significant[0].start[0],
            function_name=function_name,
            scope_key=tuple(scope_id for scope_id, _ in scope_stack),
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

    operator_index = index + 1
    if operator_index < len(tokens) and tokens[operator_index].type == tokenize.OP:
        operator = tokens[operator_index].string
        if operator == "+":
            if (
                _looks_like_sql_statement(f"{value}{{expr}}")
                and _token_concat_has_dynamic_operand(tokens, operator_index + 1)
            ):
                return f"{value}{{expr}}"
        elif operator == "%":
            return _percent_format_template(value)
        elif (
            operator == "."
            and operator_index + 3 < len(tokens)
            and tokens[operator_index + 1].type == tokenize.NAME
            and tokens[operator_index + 1].string in {"format", "format_map"}
            and tokens[operator_index + 2].type == tokenize.OP
            and tokens[operator_index + 2].string == "("
            and _token_call_has_argument(tokens, operator_index + 2)
        ):
            return _brace_format_template(value)
    return None


def _token_concat_has_dynamic_operand(
    tokens: list[tokenize.TokenInfo],
    start_index: int,
) -> bool:
    cursor = start_index
    scan_end = min(len(tokens), start_index + _MAX_FALLBACK_EXPRESSION_TOKENS)
    while cursor < scan_end:
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
        if cursor >= scan_end or tokens[cursor].string != "+":
            return False
        cursor += 1
    return False


def _token_call_has_argument(
    tokens: list[tokenize.TokenInfo],
    open_paren_index: int,
) -> bool:
    closing_for_opening = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    has_argument = False
    scan_end = min(
        len(tokens),
        open_paren_index + _MAX_FALLBACK_EXPRESSION_TOKENS,
    )
    for cursor in range(open_paren_index, scan_end):
        token = tokens[cursor]
        if token.string in closing_for_opening:
            stack.append(closing_for_opening[token.string])
            if cursor != open_paren_index:
                has_argument = True
            continue
        if stack and token.string == stack[-1]:
            stack.pop()
            if not stack:
                return has_argument
            continue
        if cursor != open_paren_index and token.string != ",":
            has_argument = True
    return False


def _token_has_sql_context(
    tokens: list[tokenize.TokenInfo],
    index: int,
    *,
    function_name: str | None,
) -> bool:
    window_start = max(0, index - _MAX_FALLBACK_CONTEXT_TOKENS)
    prefix = tokenize.untokenize(
        [(token.type, token.string) for token in tokens[window_start:index]]
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
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


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
