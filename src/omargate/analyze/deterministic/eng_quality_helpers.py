from __future__ import annotations

import ast
import builtins
from collections.abc import Callable, Iterable
from dataclasses import dataclass
import io
import re
import string
import textwrap
import tokenize

from ...constants import Limits
from ...errors import DeterministicAnalysisBudgetExceeded
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


_ProvRef = int


class _PythonAnalysisBudget:
    """Deterministic per-file resource accounting for Python analysis."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.ast_nodes = 0
        self.work_units = 0

    def consume_ast(self, tree: ast.AST) -> int:
        observed = 0
        pending = [tree]
        while pending:
            current = pending.pop()
            observed += 1
            self.ast_nodes += 1
            if self.ast_nodes > Limits.MAX_PYTHON_AST_NODES:
                self._raise(
                    "python_ast_nodes",
                    Limits.MAX_PYTHON_AST_NODES,
                    self.ast_nodes,
                )
            pending.extend(ast.iter_child_nodes(current))
        self.consume_work(observed)
        return observed

    def consume_source(self, content: str) -> None:
        source_bytes = len(content.encode("utf-8"))
        if source_bytes > Limits.MAX_FILE_SIZE:
            self._raise(
                "python_source_bytes",
                Limits.MAX_FILE_SIZE,
                source_bytes,
            )
        self.consume_work(source_bytes)

    def consume_work(self, amount: int = 1) -> None:
        if amount <= 0:
            return
        self.work_units += amount
        if self.work_units > Limits.MAX_PYTHON_ANALYSIS_WORK_UNITS:
            self._raise(
                "python_analysis_work_units",
                Limits.MAX_PYTHON_ANALYSIS_WORK_UNITS,
                self.work_units,
            )

    def _raise(self, budget_kind: str, limit: int, observed: int) -> None:
        raise DeterministicAnalysisBudgetExceeded(
            path=self.path,
            budget_kind=budget_kind,
            limit=limit,
            observed_at_least=observed,
        )


class PythonAnalysisContext:
    """One parsed tree and one shared deterministic budget for a Python file."""

    def __init__(self, content: str, *, file_path: str = "<memory>") -> None:
        self.content = content
        self.file_path = file_path
        self.budget = _PythonAnalysisBudget(file_path)
        self.budget.consume_source(content)
        try:
            self.tree: ast.AST | None = ast.parse(content)
        except (SyntaxError, RecursionError, ValueError):
            self.tree = None
            self.ast_node_count = 0
        else:
            self.ast_node_count = self.budget.consume_ast(self.tree)


def _python_analysis_context(
    content: str,
    file_path: str,
    context: PythonAnalysisContext | None,
) -> PythonAnalysisContext:
    if context is None:
        return PythonAnalysisContext(content, file_path=file_path)
    if context.content is not content and context.content != content:
        raise ValueError("Python analysis context content mismatch")
    return context


class _SqlProvenance:
    """Compact provenance DAG resolved only after control-flow construction."""

    def __init__(self, budget: _PythonAnalysisBudget | None = None) -> None:
        self.budget = budget or _PythonAnalysisBudget("<memory>")
        self._edges: list[list[_ProvRef]] = []
        self._source_lines: list[int | None] = []
        self._sources: dict[int, _ProvRef] = {}
        self._unions: dict[tuple[_ProvRef, ...], _ProvRef] = {}
        self._sinks: set[_ProvRef] = set()

    def source(self, line: int) -> _ProvRef:
        existing = self._sources.get(line)
        if existing is not None:
            return existing
        reference = self._new_node(source_line=line)
        self._sources[line] = reference
        return reference

    def union(self, references: Iterable[_ProvRef | None]) -> _ProvRef | None:
        unique = tuple(sorted({ref for ref in references if ref is not None}))
        self.budget.consume_work(len(unique) + 1)
        if not unique:
            return None
        if len(unique) == 1:
            return unique[0]
        existing = self._unions.get(unique)
        if existing is not None:
            return existing
        reference = self._new_node(edges=unique)
        self._unions[unique] = reference
        return reference

    def phi(self, initial: _ProvRef | None) -> _ProvRef:
        return self._new_node(edges=(() if initial is None else (initial,)))

    def add_phi_edges(
        self,
        phi: _ProvRef,
        references: Iterable[_ProvRef | None],
    ) -> None:
        candidates = tuple(references)
        self.budget.consume_work(len(candidates) + 1)
        edges = self._edges[phi]
        known = set(edges)
        for reference in candidates:
            if reference is not None and reference not in known:
                edges.append(reference)
                known.add(reference)

    def add_sink(self, reference: _ProvRef | None) -> None:
        self.budget.consume_work()
        if reference is not None:
            self._sinks.add(reference)

    def resolved_sink_lines(self) -> set[int]:
        lines: set[int] = set()
        visited: set[_ProvRef] = set()
        pending = list(self._sinks)
        while pending:
            self.budget.consume_work()
            reference = pending.pop()
            if reference in visited:
                continue
            visited.add(reference)
            source_line = self._source_lines[reference]
            if source_line is not None:
                lines.add(source_line)
            pending.extend(self._edges[reference])
        return lines

    def _new_node(
        self,
        *,
        source_line: int | None = None,
        edges: Iterable[_ProvRef] = (),
    ) -> _ProvRef:
        edge_list = list(edges)
        self.budget.consume_work(len(edge_list) + 1)
        reference = len(self._edges)
        self._edges.append(edge_list)
        self._source_lines.append(source_line)
        return reference


class _SqlBindingState(dict[str, _ProvRef]):
    def __init__(
        self,
        graph: _SqlProvenance,
        initial: dict[str, _ProvRef] | None = None,
        defined_keys: Iterable[str] = (),
    ) -> None:
        super().__init__(initial or {})
        self.graph = graph
        self.dotted_keys = {key for key in self if "." in key}
        self.defined_keys = set(defined_keys)
        self.defined_descendants: dict[str, set[str]] = {}
        for key in self.defined_keys:
            self._index_defined_descendant(key)
        self.graph.budget.consume_work(
            len(self) + len(self.defined_keys) + 1
        )

    def copy(self) -> _SqlBindingState:
        return _SqlBindingState(self.graph, self, self.defined_keys)

    def set_reference(self, key: str, reference: _ProvRef) -> None:
        super().__setitem__(key, reference)
        if "." in key:
            self.dotted_keys.add(key)
        self.define_key(key)

    def define_key(self, key: str) -> None:
        parts = key.split(".")
        self.graph.budget.consume_work(len(parts))
        for length in range(1, len(parts) + 1):
            definition = ".".join(parts[:length])
            if definition in self.defined_keys:
                continue
            self.defined_keys.add(definition)
            self._index_defined_descendant(definition)

    def undefine_key(self, key: str) -> None:
        targets = {key, *self.defined_descendants.get(key, ())}
        self.graph.budget.consume_work(len(targets))
        for target in targets:
            if target not in self.defined_keys:
                continue
            self.defined_keys.remove(target)
            self._unindex_defined_descendant(target)

    def discard_reference(self, key: str) -> None:
        super().pop(key, None)
        self.dotted_keys.discard(key)

    def replace_with(self, other: _SqlBindingState) -> None:
        assert self.graph is other.graph
        super().clear()
        super().update(other)
        self.dotted_keys = set(other.dotted_keys)
        self.defined_keys = set(other.defined_keys)
        self.defined_descendants = {
            prefix: set(descendants)
            for prefix, descendants in other.defined_descendants.items()
        }

    def _index_defined_descendant(self, key: str) -> None:
        parts = key.split(".")
        for length in range(1, len(parts)):
            prefix = ".".join(parts[:length])
            self.defined_descendants.setdefault(prefix, set()).add(key)

    def _unindex_defined_descendant(self, key: str) -> None:
        parts = key.split(".")
        for length in range(1, len(parts)):
            prefix = ".".join(parts[:length])
            descendants = self.defined_descendants.get(prefix)
            if descendants is None:
                continue
            descendants.discard(key)
            if not descendants:
                self.defined_descendants.pop(prefix, None)


@dataclass
class _SqlFlow:
    """May-analysis states partitioned by Python completion kind."""

    normal: _SqlBindingState | None = None
    breaks: _SqlBindingState | None = None
    continues: _SqlBindingState | None = None
    returns: _SqlBindingState | None = None
    raises: _SqlBindingState | None = None


@dataclass
class _SqlExpressionEvent:
    kind: str
    node: ast.AST
    state: _SqlBindingState
    branches: tuple[_SqlBindingState, _SqlBindingState] | None = None


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
    ^\s*
    (?:
        SELECT\s+(?:
            [\s\S]*\bFROM\b
            | [A-Za-z_][A-Za-z0-9_$.]*\s*\([^)]*\{{expr\}}[^)]*\)
        )
        | INSERT\s+(?:(?:OR\s+(?:ABORT|FAIL|IGNORE|REPLACE|ROLLBACK)|IGNORE)\s+)?
          INTO\s+{_SQL_IDENTIFIER_PATTERN}(?=\s|\()
        | DELETE\s+FROM\b
        | UPDATE\s+(?:{_SQL_IDENTIFIER_PATTERN}|[^\s;]+)\s+SET\b
        | WITH\b[\s\S]*\bAS\s*\(
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SQL_AMBIGUOUS_DYNAMIC_SELECT_RE = re.compile(
    r"^\s*SELECT\s+"
    r"(?=[\s\S]*\{expr\})[\s\S]+\s*;?\s*$",
    re.IGNORECASE | re.VERBOSE,
)
_PYTHON_BUILTIN_NAMES = frozenset(vars(builtins))
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


def python_eval_call_lines(
    content: str,
    *,
    file_path: str = "<memory>",
    context: PythonAnalysisContext | None = None,
) -> set[int]:
    analysis = _python_analysis_context(content, file_path, context)
    if analysis.tree is None:
        return set()

    analysis.budget.consume_work(analysis.ast_node_count)
    lines: set[int] = set()
    for node in ast.walk(analysis.tree):
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


def python_interpolated_sql_lines(
    content: str,
    *,
    file_path: str = "<memory>",
    context: PythonAnalysisContext | None = None,
) -> set[int]:
    """Return Python source lines that dynamically construct SQL statements.

    Parsed Python is authoritative. If an unrelated syntax error prevents a
    module parse, tokenized logical statements are recovered without treating
    comments or string contents as executable source.
    """

    analysis = _python_analysis_context(content, file_path, context)
    if analysis.tree is None:
        return _python_interpolated_sql_lines_from_source(
            content,
            analysis.budget,
        )

    analysis.budget.consume_work(analysis.ast_node_count * 2)
    return _python_interpolated_sql_lines_from_tree(
        analysis.tree,
        budget=analysis.budget,
    )


def _python_interpolated_sql_lines_from_tree(
    tree: ast.AST,
    *,
    line_offset: int = 0,
    budget: _PythonAnalysisBudget | None = None,
) -> set[int]:
    analysis_budget = budget or _PythonAnalysisBudget("<memory>")
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    lines = _direct_python_interpolated_sql_lines(tree, parents)
    lines.update(_ordered_sql_binding_lines(tree, parents, analysis_budget))
    if line_offset:
        return {line + line_offset for line in lines}
    return lines


def _direct_python_interpolated_sql_lines(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> set[int]:
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
            lines.add(int(getattr(node, "lineno", 1) or 1))
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
            while cursor < len(value) and depth:
                if value[cursor] == "(":
                    depth += 1
                elif value[cursor] == ")":
                    depth -= 1
                cursor += 1
            if depth:
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
    template = _without_leading_sql_comments(template)
    return bool(
        _SQL_STRONG_STATEMENT_RE.search(template)
        or _SQL_AMBIGUOUS_DYNAMIC_SELECT_RE.fullmatch(template)
    )


def _select_requires_sql_context(template: str) -> bool:
    template = _without_leading_sql_comments(template)
    return bool(
        _SQL_AMBIGUOUS_DYNAMIC_SELECT_RE.fullmatch(template)
        and not _SQL_STRONG_STATEMENT_RE.search(template)
    )


def _without_leading_sql_comments(template: str) -> str:
    """Strip SQL leading trivia in linear time.

    A repeated regex around a variable-width block-comment matcher can
    catastrophically backtrack on attacker-controlled input.  This cursor is
    deliberately boring: every character is visited at most once and an
    unterminated block comment leaves no statement to classify.
    """

    cursor = 0
    length = len(template)
    while cursor < length:
        while cursor < length and template[cursor].isspace():
            cursor += 1
        if template.startswith("--", cursor):
            cursor += 2
            while cursor < length and template[cursor] not in "\r\n":
                cursor += 1
            if cursor == length:
                return ""
            cursor += 1
            continue
        if template.startswith("/*", cursor):
            closing = template.find("*/", cursor + 2)
            if closing < 0:
                return ""
            cursor = closing + 2
            continue
        break
    return template[cursor:]


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


def _call_argument_expressions_in_order(call: ast.Call) -> list[ast.expr]:
    """Return positional/starred and keyword values in source order.

    CPython stores ``args`` and ``keywords`` in separate lists even though
    starred arguments and keyword arguments may be interleaved in source.
    Evaluation follows lexical order, so the flow model must reconstruct it.
    """

    return sorted(
        [*call.args, *(keyword.value for keyword in call.keywords)],
        key=lambda expression: (
            int(getattr(expression, "lineno", 0) or 0),
            int(getattr(expression, "col_offset", 0) or 0),
        ),
    )


def _ordered_sql_binding_lines(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    budget: _PythonAnalysisBudget | None = None,
) -> set[int]:
    """Find dynamic SQL definitions that reach a later SQL execution call.

    This is deliberately local and forward-only. Each lexical scope starts
    with an empty state, assignments kill the previous definition, and branch
    states are merged only after their mutually exclusive bodies have been
    evaluated. It supplies the context for otherwise ambiguous ``SELECT``
    text without restoring the old flow-insensitive name search.
    """

    graph = _SqlProvenance(budget)
    initial = _SqlBindingState(graph)
    lines: set[int] = set()
    if isinstance(tree, ast.Module):
        _analyze_sql_statement_block(tree.body, initial, parents, lines)
    elif isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        _analyze_sql_statement_block(tree.body, initial, parents, lines)
    return graph.resolved_sink_lines()


def _analyze_sql_statement_block(
    statements: list[ast.stmt],
    initial_state: _SqlBindingState | None,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    if initial_state is None:
        return _SqlFlow()

    flow = _SqlFlow(normal=initial_state.copy())
    for statement in statements:
        if flow.normal is None:
            break
        step = _analyze_sql_statement(statement, flow.normal, parents, lines)
        flow = _SqlFlow(
            normal=step.normal,
            breaks=_merge_sql_binding_states(flow.breaks, step.breaks),
            continues=_merge_sql_binding_states(flow.continues, step.continues),
            returns=_merge_sql_binding_states(flow.returns, step.returns),
            raises=_merge_sql_binding_states(flow.raises, step.raises),
        )
    return flow


def _analyze_sql_statement(
    statement: ast.stmt,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    current = state
    exceptions: list[_SqlBindingState] = []

    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for expression in [
            *statement.decorator_list,
            *statement.args.defaults,
            *(default for default in statement.args.kw_defaults if default is not None),
        ]:
            _process_sql_expression(expression, current, parents, lines, exceptions)
        _kill_sql_binding_key(current, statement.name)
        function_state = _SqlBindingState(
            current.graph,
            defined_keys=_function_parameter_keys(statement.args),
        )
        _analyze_sql_statement_block(
            statement.body, function_state, parents, lines
        )
        return _SqlFlow(
            normal=current,
            raises=_merge_sql_binding_states(*exceptions),
        )

    if isinstance(statement, ast.ClassDef):
        for expression in [
            *statement.decorator_list,
            *statement.bases,
            *(keyword.value for keyword in statement.keywords),
        ]:
            _process_sql_expression(expression, current, parents, lines, exceptions)
        _kill_sql_binding_key(current, statement.name)
        _analyze_sql_statement_block(
            statement.body, _SqlBindingState(current.graph), parents, lines
        )
        return _SqlFlow(
            normal=current,
            raises=_merge_sql_binding_states(*exceptions),
        )

    if isinstance(statement, ast.If):
        return _analyze_sql_if(statement, current, parents, lines)

    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return _analyze_sql_for(statement, current, parents, lines)

    if isinstance(statement, ast.While):
        return _analyze_sql_while(statement, current, parents, lines)

    if isinstance(statement, (ast.Try, ast.TryStar)):
        return _analyze_sql_try(statement, current, parents, lines)

    if isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            _process_sql_expression(
                item.context_expr, current, parents, lines, exceptions
            )
            if item.optional_vars is not None:
                _kill_sql_binding_targets(current, [item.optional_vars])
        body = _analyze_sql_statement_block(statement.body, current, parents, lines)
        # A context manager may suppress an exception. Preserve both the
        # exceptional channel and the corresponding may-continue state.
        suppressed = body.raises.copy() if body.raises is not None else None
        body.normal = _merge_sql_binding_states(body.normal, suppressed)
        body.raises = _merge_sql_binding_states(*exceptions, body.raises)
        return body

    if isinstance(statement, ast.Match):
        return _analyze_sql_match(statement, current, parents, lines)

    if isinstance(statement, ast.Assign):
        _process_sql_expression(statement.value, current, parents, lines, exceptions)
        _apply_sql_assignment_targets(
            current,
            statement.targets,
            statement.value,
            parents,
            lines,
            exceptions,
        )
    elif isinstance(statement, ast.AnnAssign):
        _process_sql_expression(
            statement.annotation, current, parents, lines, exceptions
        )
        if statement.value is not None:
            _process_sql_expression(
                statement.value, current, parents, lines, exceptions
            )
        _apply_sql_assignment_targets(
            current,
            [statement.target],
            statement.value,
            parents,
            lines,
            exceptions,
        )
    elif isinstance(statement, ast.AugAssign):
        _process_sql_expression(statement.target, current, parents, lines, exceptions)
        _process_sql_expression(statement.value, current, parents, lines, exceptions)
        previous = _origins_for_binding_targets(current, [statement.target])
        origin = current.graph.union(
            (
                previous,
                _sql_origins_in_expression(statement.value, current, parents),
            )
        )
        _set_sql_binding_targets(current, [statement.target], origin)
    elif isinstance(statement, ast.Delete):
        for target in statement.targets:
            _process_sql_expression(target, current, parents, lines, exceptions)
            _undefine_sql_binding_targets(current, [target])
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        for alias in statement.names:
            _kill_sql_binding_key(
                current, alias.asname or alias.name.split(".", 1)[0]
            )
    elif isinstance(statement, ast.Return):
        if statement.value is not None:
            _process_sql_expression(
                statement.value, current, parents, lines, exceptions
            )
        return _SqlFlow(
            returns=current,
            raises=_merge_sql_binding_states(*exceptions),
        )
    elif isinstance(statement, ast.Raise):
        if statement.exc is not None:
            _process_sql_expression(statement.exc, current, parents, lines, exceptions)
        if statement.cause is not None:
            _process_sql_expression(statement.cause, current, parents, lines, exceptions)
        return _SqlFlow(raises=_merge_sql_binding_states(state, current, *exceptions))
    elif isinstance(statement, ast.Break):
        return _SqlFlow(breaks=current)
    elif isinstance(statement, ast.Continue):
        return _SqlFlow(continues=current)
    elif isinstance(statement, ast.Expr):
        _process_sql_expression(statement.value, current, parents, lines, exceptions)
    elif isinstance(statement, ast.Assert):
        _process_sql_expression(statement.test, current, parents, lines, exceptions)
        truth = _literal_truth(statement.test)
        assertion_raises: list[_SqlBindingState] = []
        if truth is not True:
            failed = current.copy()
            if statement.msg is not None:
                _process_sql_expression(
                    statement.msg,
                    failed,
                    parents,
                    lines,
                    assertion_raises,
                )
            assertion_raises.append(failed)
        return _SqlFlow(
            normal=current if truth is not False else None,
            raises=_merge_sql_binding_states(*exceptions, *assertion_raises),
        )
    else:
        _process_sql_expression(statement, current, parents, lines, exceptions)

    return _SqlFlow(
        normal=current,
        raises=_merge_sql_binding_states(*exceptions),
    )


def _analyze_sql_if(
    statement: ast.If,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    """Analyze an if/elif chain iteratively to avoid AST-depth crashes."""

    aggregate = _SqlFlow()
    fallthrough: _SqlBindingState | None = state.copy()
    current_if: ast.If | None = statement
    while current_if is not None and fallthrough is not None:
        test_input = fallthrough.copy()
        test_exceptions: list[_SqlBindingState] = []
        _process_sql_expression(
            current_if.test, test_input, parents, lines, test_exceptions
        )
        aggregate.raises = _merge_sql_binding_states(
            aggregate.raises, *test_exceptions
        )
        truth = _literal_truth(current_if.test)
        if truth is not False:
            aggregate = _merge_sql_flows(
                aggregate,
                _analyze_sql_statement_block(
                    current_if.body, test_input, parents, lines
                ),
            )
        if truth is True:
            fallthrough = None
            break

        fallthrough = test_input
        if len(current_if.orelse) == 1 and isinstance(current_if.orelse[0], ast.If):
            current_if = current_if.orelse[0]
            continue
        if current_if.orelse:
            aggregate = _merge_sql_flows(
                aggregate,
                _analyze_sql_statement_block(
                    current_if.orelse, fallthrough, parents, lines
                ),
            )
            fallthrough = None
        current_if = None

    if fallthrough is not None:
        aggregate.normal = _merge_sql_binding_states(
            aggregate.normal, fallthrough
        )
    return aggregate


def _analyze_sql_for(
    statement: ast.For | ast.AsyncFor,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    entry = state.copy()
    exceptions: list[_SqlBindingState] = []
    _process_sql_expression(statement.iter, entry, parents, lines, exceptions)
    cardinality = _literal_iterable_cardinality(statement.iter)
    if cardinality == 0:
        else_flow = (
            _analyze_sql_statement_block(
                statement.orelse, entry, parents, lines
            )
            if statement.orelse
            else _SqlFlow(normal=entry)
        )
        else_flow.raises = _merge_sql_binding_states(
            *exceptions, else_flow.raises
        )
        return else_flow

    header, phis = _sql_loop_header(
        entry,
        statement.body,
        extra_keys=_binding_target_keys(statement.target),
    )
    body_input = header.copy()
    _process_sql_expression(
        statement.target, body_input, parents, lines, exceptions
    )
    _set_sql_binding_targets(
        body_input,
        [statement.target],
        _iterated_sql_origins(statement.iter, entry, parents),
    )
    body = _analyze_sql_statement_block(
        statement.body, body_input, parents, lines
    )
    _complete_sql_loop_phis(phis, body.normal, body.continues)

    natural = header
    else_flow = (
        _analyze_sql_statement_block(statement.orelse, natural, parents, lines)
        if statement.orelse
        else _SqlFlow(normal=natural)
    )
    return _SqlFlow(
        normal=_merge_sql_binding_states(body.breaks, else_flow.normal),
        breaks=else_flow.breaks,
        continues=else_flow.continues,
        returns=_merge_sql_binding_states(body.returns, else_flow.returns),
        raises=_merge_sql_binding_states(
            *exceptions, body.raises, else_flow.raises
        ),
    )


def _literal_iterable_cardinality(expression: ast.expr) -> int | None:
    if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        return len(expression.elts)
    if isinstance(expression, ast.Dict):
        return len(expression.keys)
    if isinstance(expression, ast.Constant) and isinstance(
        expression.value, (bytes, str)
    ):
        return len(expression.value)
    return None


def _iterated_sql_origins(
    expression: ast.expr,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> _ProvRef | None:
    if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        return state.graph.union(
            _sql_origins_in_expression(element, state, parents)
            for element in expression.elts
        )
    if isinstance(expression, ast.Dict):
        return state.graph.union(
            _sql_origins_in_expression(key, state, parents)
            for key in expression.keys
            if key is not None
        )
    # Iterating a string yields individual characters, not the SQL string.
    return None


def _analyze_sql_while(
    statement: ast.While,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    header, phis = _sql_loop_header(
        state,
        [*statement.body, ast.Expr(value=statement.test)],
    )
    test_state = header.copy()
    truth = _literal_truth(statement.test)
    exceptions: list[_SqlBindingState] = []
    _process_sql_expression(
        statement.test, test_state, parents, lines, exceptions
    )
    test_raises = _merge_sql_binding_states(header, *exceptions)
    body = (
        _analyze_sql_statement_block(
            statement.body, test_state, parents, lines
        )
        if truth is not False
        else _SqlFlow()
    )
    _complete_sql_loop_phis(phis, body.normal, body.continues)

    natural = None if truth is True else test_state
    else_flow = (
        _analyze_sql_statement_block(statement.orelse, natural, parents, lines)
        if statement.orelse and natural is not None
        else _SqlFlow(normal=natural)
    )
    return _SqlFlow(
        normal=_merge_sql_binding_states(body.breaks, else_flow.normal),
        breaks=else_flow.breaks,
        continues=else_flow.continues,
        returns=_merge_sql_binding_states(body.returns, else_flow.returns),
        raises=_merge_sql_binding_states(
            test_raises, body.raises, else_flow.raises
        ),
    )


def _sql_loop_header(
    entry: _SqlBindingState,
    nodes: Iterable[ast.AST],
    *,
    extra_keys: Iterable[str] = (),
) -> tuple[_SqlBindingState, dict[str, _ProvRef]]:
    keys = set(entry).union(_assigned_sql_binding_keys(nodes), extra_keys)
    phis: dict[str, _ProvRef] = {}
    for key in keys:
        phi = entry.graph.phi(entry.get(key))
        phis[key] = phi
    header = _SqlBindingState(
        entry.graph,
        phis,
        defined_keys=entry.defined_keys,
    )
    return header, phis


def _complete_sql_loop_phis(
    phis: dict[str, _ProvRef],
    *backedges: _SqlBindingState | None,
) -> None:
    graph = next(
        (state.graph for state in backedges if state is not None),
        None,
    )
    if graph is None:
        return
    for key, phi in phis.items():
        graph.add_phi_edges(phi, (state.get(key) for state in backedges if state))


def _assigned_sql_binding_keys(nodes: Iterable[ast.AST]) -> set[str]:
    keys: set[str] = set()
    pending = list(nodes)
    nested_scopes = (
        ast.ClassDef,
        ast.DictComp,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.GeneratorExp,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
    )
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            keys.add(current.name)
            continue
        if isinstance(current, nested_scopes):
            continue
        if isinstance(current, (ast.Name, ast.Attribute)) and isinstance(
            current.ctx, ast.Store
        ):
            reference = _qualified_name(current)
            if reference is not None:
                keys.add(reference)
        if isinstance(current, ast.Match):
            for case in current.cases:
                keys.update(_match_capture_names(case.pattern))
        pending.extend(ast.iter_child_nodes(current))
    return keys


def _function_parameter_keys(arguments: ast.arguments) -> set[str]:
    parameters = [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    ]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return {parameter.arg for parameter in parameters}


def _analyze_sql_try(
    statement: ast.Try | ast.TryStar,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    body = _analyze_sql_statement_block(statement.body, state, parents, lines)
    normal = (
        _analyze_sql_statement_block(statement.orelse, body.normal, parents, lines)
        if statement.orelse and body.normal is not None
        else _SqlFlow(normal=body.normal)
    )
    combined = _SqlFlow(
        normal=normal.normal,
        breaks=_merge_sql_binding_states(body.breaks, normal.breaks),
        continues=_merge_sql_binding_states(body.continues, normal.continues),
        returns=_merge_sql_binding_states(body.returns, normal.returns),
        raises=_merge_sql_binding_states(
            None
            if any(
                _handler_catches_modeled_exceptions(handler)
                for handler in statement.handlers
            )
            else body.raises,
            normal.raises,
        ),
    )

    if body.raises is not None:
        for handler in statement.handlers:
            handler_state = body.raises.copy()
            exceptions: list[_SqlBindingState] = []
            if handler.type is not None:
                _process_sql_expression(
                    handler.type, handler_state, parents, lines, exceptions
                )
            if handler.name:
                _kill_sql_binding_key(handler_state, handler.name)
            handled = _analyze_sql_statement_block(
                handler.body, handler_state, parents, lines
            )
            if handler.name:
                handled = _map_sql_flow_states(
                    handled,
                    lambda candidate, name=handler.name: _state_without_key(
                        candidate, name
                    ),
                )
            handled.raises = _merge_sql_binding_states(
                handled.raises, *exceptions
            )
            combined = _merge_sql_flows(combined, handled)

    return (
        _apply_sql_finally(combined, statement.finalbody, parents, lines)
        if statement.finalbody
        else combined
    )


def _handler_catches_modeled_exceptions(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    candidates = (
        handler.type.elts
        if isinstance(handler.type, ast.Tuple)
        else [handler.type]
    )
    return any(
        (name := _qualified_name(candidate)) is not None
        and name.rsplit(".", 1)[-1] in {"BaseException", "Exception"}
        for candidate in candidates
    )


def _apply_sql_finally(
    incoming: _SqlFlow,
    statements: list[ast.stmt],
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    outgoing = _SqlFlow()
    for channel in ("normal", "breaks", "continues", "returns", "raises"):
        channel_state = getattr(incoming, channel)
        if channel_state is None:
            continue
        final = _analyze_sql_statement_block(
            statements, channel_state, parents, lines
        )
        if final.normal is not None:
            setattr(
                outgoing,
                channel,
                _merge_sql_binding_states(
                    getattr(outgoing, channel), final.normal
                ),
            )
        outgoing.breaks = _merge_sql_binding_states(
            outgoing.breaks, final.breaks
        )
        outgoing.continues = _merge_sql_binding_states(
            outgoing.continues, final.continues
        )
        outgoing.returns = _merge_sql_binding_states(
            outgoing.returns, final.returns
        )
        outgoing.raises = _merge_sql_binding_states(
            outgoing.raises, final.raises
        )
    return outgoing


def _analyze_sql_match(
    statement: ast.Match,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    current = state.copy()
    exceptions: list[_SqlBindingState] = []
    _process_sql_expression(
        statement.subject, current, parents, lines, exceptions
    )
    outcomes = _SqlFlow()
    fallthrough: _SqlBindingState | None = current
    for case in statement.cases:
        if fallthrough is None:
            break
        unmatched = fallthrough
        case_state = unmatched.copy()
        for name, origin in _match_capture_origins(
            case.pattern,
            statement.subject,
            case_state,
            parents,
        ).items():
            _set_sql_binding_key(case_state, name, origin)
        guard_truth: bool | None = True
        if case.guard is not None:
            _process_sql_expression(
                case.guard, case_state, parents, lines, exceptions
            )
            guard_truth = _literal_truth(case.guard)
        if guard_truth is not False:
            outcomes = _merge_sql_flows(
                outcomes,
                _analyze_sql_statement_block(
                    case.body, case_state, parents, lines
                ),
            )

        failed: list[_SqlBindingState] = []
        if not _match_pattern_is_irrefutable(case.pattern):
            failed.append(unmatched)
        if case.guard is not None and guard_truth is not True:
            failed.append(case_state)
        fallthrough = _merge_sql_binding_states(*failed)

    outcomes.normal = _merge_sql_binding_states(outcomes.normal, fallthrough)
    outcomes.raises = _merge_sql_binding_states(
        outcomes.raises, *exceptions
    )
    return outcomes


def _match_capture_origins(
    pattern: ast.pattern,
    subject: ast.expr | None,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> dict[str, _ProvRef | None]:
    captures = {name: None for name in _match_capture_names(pattern)}
    if isinstance(pattern, ast.MatchAs):
        if pattern.pattern is not None:
            captures.update(
                _match_capture_origins(
                    pattern.pattern, subject, state, parents
                )
            )
        if pattern.name is not None:
            captures[pattern.name] = (
                _sql_origins_in_expression(subject, state, parents)
                if subject is not None
                else None
            )
        return captures
    if isinstance(pattern, ast.MatchOr):
        alternatives = [
            _match_capture_origins(item, subject, state, parents)
            for item in pattern.patterns
        ]
        return {
            name: state.graph.union(
                alternative.get(name) for alternative in alternatives
            )
            for name in captures
        }
    if isinstance(pattern, ast.MatchSequence) and isinstance(
        subject, (ast.List, ast.Tuple)
    ):
        return _match_sequence_capture_origins(
            pattern, subject, state, parents
        )
    if isinstance(pattern, ast.MatchMapping) and isinstance(subject, ast.Dict):
        return _match_mapping_capture_origins(
            pattern, subject, state, parents
        )
    return captures


def _match_sequence_capture_origins(
    pattern: ast.MatchSequence,
    subject: ast.List | ast.Tuple,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> dict[str, _ProvRef | None]:
    captures = {name: None for name in _match_capture_names(pattern)}
    starred = [
        index for index, item in enumerate(pattern.patterns)
        if isinstance(item, ast.MatchStar)
    ]
    if len(starred) > 1 or (
        not starred and len(pattern.patterns) != len(subject.elts)
    ):
        return captures
    if starred and len(subject.elts) < len(pattern.patterns) - 1:
        return captures

    star_index = starred[0] if starred else len(pattern.patterns)
    trailing = len(pattern.patterns) - star_index - bool(starred)
    for child_pattern, child_subject in zip(
        pattern.patterns[:star_index],
        subject.elts[:star_index],
        strict=True,
    ):
        captures.update(
            _match_capture_origins(
                child_pattern, child_subject, state, parents
            )
        )
    if starred:
        star = pattern.patterns[star_index]
        assert isinstance(star, ast.MatchStar)
        if star.name is not None:
            middle_end = len(subject.elts) - trailing if trailing else len(subject.elts)
            captures[star.name] = state.graph.union(
                _sql_origins_in_expression(element, state, parents)
                for element in subject.elts[star_index:middle_end]
            )
    if trailing:
        for child_pattern, child_subject in zip(
            pattern.patterns[-trailing:],
            subject.elts[-trailing:],
            strict=True,
        ):
            captures.update(
                _match_capture_origins(
                    child_pattern, child_subject, state, parents
                )
            )
    return captures


def _match_mapping_capture_origins(
    pattern: ast.MatchMapping,
    subject: ast.Dict,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> dict[str, _ProvRef | None]:
    captures = {name: None for name in _match_capture_names(pattern)}
    subject_values: dict[object, ast.expr] = {}
    for key, value in zip(subject.keys, subject.values, strict=True):
        if key is None:
            continue
        try:
            literal_key = ast.literal_eval(key)
            hash(literal_key)
        except (TypeError, ValueError):
            continue
        subject_values[literal_key] = value

    matched_keys: set[object] = set()
    for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
        try:
            literal_key = ast.literal_eval(key)
            hash(literal_key)
        except (TypeError, ValueError):
            continue
        child_subject = subject_values.get(literal_key)
        if child_subject is not None:
            matched_keys.add(literal_key)
        captures.update(
            _match_capture_origins(
                child_pattern, child_subject, state, parents
            )
        )
    if pattern.rest is not None:
        captures[pattern.rest] = state.graph.union(
            _sql_origins_in_expression(value, state, parents)
            for key, value in subject_values.items()
            if key not in matched_keys
        )
    return captures


def _match_capture_names(pattern: ast.pattern) -> set[str]:
    names: set[str] = set()
    pending: list[ast.AST] = [pattern]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.MatchAs) and current.name is not None:
            names.add(current.name)
        elif isinstance(current, ast.MatchStar) and current.name is not None:
            names.add(current.name)
        elif isinstance(current, ast.MatchMapping) and current.rest is not None:
            names.add(current.rest)
        pending.extend(ast.iter_child_nodes(current))
    return names


def _match_pattern_is_irrefutable(pattern: ast.pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _match_pattern_is_irrefutable(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_match_pattern_is_irrefutable(item) for item in pattern.patterns)
    return False


def _literal_truth(expression: ast.expr) -> bool | None:
    if isinstance(expression, ast.Constant):
        try:
            return bool(expression.value)
        except Exception:
            return None
    return None


def _merge_sql_flows(*flows: _SqlFlow) -> _SqlFlow:
    return _SqlFlow(
        normal=_merge_sql_binding_states(*(flow.normal for flow in flows)),
        breaks=_merge_sql_binding_states(*(flow.breaks for flow in flows)),
        continues=_merge_sql_binding_states(*(flow.continues for flow in flows)),
        returns=_merge_sql_binding_states(*(flow.returns for flow in flows)),
        raises=_merge_sql_binding_states(*(flow.raises for flow in flows)),
    )


def _map_sql_flow_states(
    flow: _SqlFlow,
    transform: Callable[[_SqlBindingState], _SqlBindingState],
) -> _SqlFlow:
    return _SqlFlow(
        **{
            channel: transform(state) if state is not None else None
            for channel in ("normal", "breaks", "continues", "returns", "raises")
            for state in [getattr(flow, channel)]
        }
    )


def _state_without_key(state: _SqlBindingState, key: str) -> _SqlBindingState:
    result = state.copy()
    _undefine_sql_binding_key(result, key)
    return result


def _process_sql_expression(
    node: ast.AST,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: list[_SqlBindingState],
) -> None:
    """Apply expression side effects in Python evaluation order.

    The previous implementation first read every sink and only then applied
    assignment expressions.  That inverted real evaluation order.  This
    explicit event stack keeps deep addition trees iterative while binding a
    walrus immediately after its value and recording each SQL argument before
    later call arguments can mutate the same name.
    """

    events = [_SqlExpressionEvent("visit", node, state)]
    skipped = (
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.GeneratorExp,
        ast.Lambda,
    )
    while events:
        state.graph.budget.consume_work()
        event = events.pop()
        kind = event.kind
        current = event.node
        current_state = event.state
        if kind == "bind":
            assert isinstance(current, ast.NamedExpr)
            _assign_sql_bindings(
                current_state, [current.target], current.value, parents
            )
            continue
        if kind == "sink":
            assert isinstance(current, ast.expr)
            current_state.graph.add_sink(
                _sql_origins_in_expression(current, current_state, parents)
            )
            continue
        if kind == "raise":
            exceptions.append(current_state.copy())
            continue
        if kind == "ifexp":
            assert isinstance(current, ast.IfExp)
            truth = _literal_truth(current.test)
            if truth is True:
                events.append(
                    _SqlExpressionEvent("visit", current.body, current_state)
                )
            elif truth is False:
                events.append(
                    _SqlExpressionEvent("visit", current.orelse, current_state)
                )
            else:
                body_state = current_state.copy()
                else_state = current_state.copy()
                events.append(
                    _SqlExpressionEvent(
                        "merge",
                        current,
                        current_state,
                        (body_state, else_state),
                    )
                )
                events.append(
                    _SqlExpressionEvent("visit", current.orelse, else_state)
                )
                events.append(
                    _SqlExpressionEvent("visit", current.body, body_state)
                )
            continue
        if kind == "merge":
            assert event.branches is not None
            merged = _merge_sql_binding_states(*event.branches)
            assert merged is not None
            current_state.replace_with(merged)
            continue
        if isinstance(current, skipped):
            continue
        if isinstance(current, ast.NamedExpr):
            events.append(_SqlExpressionEvent("bind", current, current_state))
            events.append(
                _SqlExpressionEvent("visit", current.value, current_state)
            )
            continue
        if isinstance(current, ast.IfExp):
            events.append(_SqlExpressionEvent("ifexp", current, current_state))
            events.append(
                _SqlExpressionEvent("visit", current.test, current_state)
            )
            continue
        if isinstance(current, ast.BoolOp):
            _process_sql_bool_expression(
                current, current_state, parents, lines, exceptions
            )
            continue
        if isinstance(current, (ast.DictComp, ast.ListComp, ast.SetComp)):
            _process_eager_sql_comprehension(
                current,
                current_state,
                parents,
                lines,
                exceptions,
            )
            continue
        if isinstance(current, ast.Call):
            sql_arguments = {
                id(argument) for argument in _sql_execution_value_arguments(current)
            } if _is_sql_execution_call(current) else set()
            ordered = [
                _SqlExpressionEvent("visit", current.func, current_state)
            ]
            for argument in _call_argument_expressions_in_order(current):
                ordered.append(
                    _SqlExpressionEvent("visit", argument, current_state)
                )
                if id(argument) in sql_arguments:
                    ordered.append(
                        _SqlExpressionEvent("sink", argument, current_state)
                    )
            ordered.append(_SqlExpressionEvent("raise", current, current_state))
            events.extend(reversed(ordered))
            continue
        if isinstance(current, ast.Dict):
            ordered = []
            for key, value in zip(current.keys, current.values, strict=True):
                if key is not None:
                    ordered.append(
                        _SqlExpressionEvent("visit", key, current_state)
                    )
                ordered.append(
                    _SqlExpressionEvent("visit", value, current_state)
                )
            events.extend(reversed(ordered))
            continue

        children = [
            child
            for child in ast.iter_child_nodes(current)
            if not isinstance(child, ast.expr_context)
        ]
        if isinstance(
            current,
            (
                ast.Attribute,
                ast.Await,
                ast.BinOp,
                ast.Compare,
                ast.JoinedStr,
                ast.Starred,
                ast.Subscript,
                ast.UnaryOp,
            ),
        ) or (
            isinstance(current, ast.Name)
            and isinstance(current.ctx, ast.Load)
            and current.id not in _PYTHON_BUILTIN_NAMES
            and current.id not in current_state.defined_keys
        ):
            events.append(_SqlExpressionEvent("raise", current, current_state))
        events.extend(
            _SqlExpressionEvent("visit", child, current_state)
            for child in reversed(children)
        )


def _process_sql_bool_expression(
    node: ast.BoolOp,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: list[_SqlBindingState],
) -> None:
    exits: list[_SqlBindingState] = []
    working = state.copy()
    is_and = isinstance(node.op, ast.And)
    for index, value in enumerate(node.values):
        _process_sql_expression(value, working, parents, lines, exceptions)
        if index == len(node.values) - 1:
            break
        truth = _literal_truth(value)
        stops = truth is not True if is_and else truth is not False
        continues = truth is not False if is_and else truth is not True
        if stops:
            exits.append(working.copy())
        if not continues:
            working = _SqlBindingState(state.graph)
            break
        if truth is None:
            working = working.copy()
    merged = _merge_sql_binding_states(*exits, working)
    assert merged is not None
    state.replace_with(merged)


def _process_eager_sql_comprehension(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: list[_SqlBindingState],
) -> None:
    """Model eager comprehension effects with zero/representative paths.

    Comprehension iteration variables are local in Python 3, while walrus
    targets bind in the containing scope.  A representative iteration is
    sufficient for this may-analysis; an unknown iterable/filter also keeps a
    no-element path.  Generator expressions remain lazy and are not evaluated
    here.
    """

    outer = state.copy()
    local_keys = {
        key
        for generator in node.generators
        for key in _binding_target_keys(generator.target)
    }
    outcomes: list[_SqlBindingState] = []

    def evaluate_generator(index: int, candidate: _SqlBindingState) -> None:
        if index == len(node.generators):
            if isinstance(node, ast.DictComp):
                _process_sql_expression(
                    node.key, candidate, parents, lines, exceptions
                )
                _process_sql_expression(
                    node.value, candidate, parents, lines, exceptions
                )
            else:
                _process_sql_expression(
                    node.elt, candidate, parents, lines, exceptions
                )
            outcomes.append(candidate)
            return

        generator = node.generators[index]
        _process_sql_expression(
            generator.iter, candidate, parents, lines, exceptions
        )
        cardinality = _literal_iterable_cardinality(generator.iter)
        if cardinality is None:
            outcomes.append(candidate.copy())
        elif cardinality == 0:
            outcomes.append(candidate)
            return

        iteration = candidate.copy()
        _process_sql_expression(
            generator.target, iteration, parents, lines, exceptions
        )
        _set_sql_binding_targets(
            iteration,
            [generator.target],
            _iterated_sql_origins(generator.iter, candidate, parents),
        )
        for condition in generator.ifs:
            _process_sql_expression(
                condition, iteration, parents, lines, exceptions
            )
            truth = _literal_truth(condition)
            if truth is not True:
                outcomes.append(iteration.copy())
            if truth is False:
                return
        evaluate_generator(index + 1, iteration)

    evaluate_generator(0, state.copy())
    merged = _merge_sql_binding_states(*outcomes)
    assert merged is not None
    for key in local_keys:
        _undefine_sql_binding_key(merged, key)
    for key, origin in outer.items():
        if any(key == local or key.startswith(f"{local}.") for local in local_keys):
            merged.set_reference(key, origin)
    for key in outer.defined_keys:
        if any(key == local or key.startswith(f"{local}.") for local in local_keys):
            merged.define_key(key)
    state.replace_with(merged)


def _apply_sql_assignment_targets(
    state: _SqlBindingState,
    targets: list[ast.expr],
    value: ast.expr | None,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: list[_SqlBindingState],
) -> None:
    """Evaluate and bind assignment targets in Python's left-to-right order.

    The right-hand value has already been evaluated.  Capture its provenance
    before a subscript/attribute target can mutate bindings through a walrus,
    then evaluate each target and commit that target before moving to the next
    one.  This preserves both chained-assignment order and the state visible
    when a later target operation raises.
    """

    plans = [
        binding
        for target in targets
        for binding in _sql_assignment_plan(target, value, state, parents)
    ]
    for target, origin in plans:
        _process_sql_expression(target, state, parents, lines, exceptions)
        _set_sql_binding_targets(state, [target], origin)


def _sql_assignment_plan(
    target: ast.expr,
    value: ast.expr | None,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> list[tuple[ast.expr, _ProvRef | None]]:
    if isinstance(target, ast.Starred):
        return _sql_assignment_plan(target.value, value, state, parents)
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(
        value, (ast.Tuple, ast.List)
    ):
        elements = list(value.elts)
        starred = [
            index for index, element in enumerate(target.elts)
            if isinstance(element, ast.Starred)
        ]
        if not starred and len(target.elts) == len(elements):
            return [
                binding
                for child_target, child_value in zip(
                    target.elts, elements, strict=True
                )
                for binding in _sql_assignment_plan(
                    child_target, child_value, state, parents
                )
            ]
        if len(starred) == 1 and len(elements) >= len(target.elts) - 1:
            star_index = starred[0]
            trailing = len(target.elts) - star_index - 1
            plans: list[tuple[ast.expr, _ProvRef | None]] = []
            for child_target, child_value in zip(
                target.elts[:star_index],
                elements[:star_index],
                strict=True,
            ):
                plans.extend(
                    _sql_assignment_plan(
                        child_target, child_value, state, parents
                    )
                )
            star_target = target.elts[star_index]
            assert isinstance(star_target, ast.Starred)
            middle_end = len(elements) - trailing if trailing else len(elements)
            star_origin = state.graph.union(
                _sql_origins_in_expression(element, state, parents)
                for element in elements[star_index:middle_end]
            )
            plans.append((star_target.value, star_origin))
            if trailing:
                for child_target, child_value in zip(
                    target.elts[-trailing:],
                    elements[-trailing:],
                    strict=True,
                ):
                    plans.extend(
                        _sql_assignment_plan(
                            child_target, child_value, state, parents
                        )
                    )
            return plans

    origin = (
        _sql_origins_in_expression(value, state, parents)
        if value is not None
        else None
    )
    return [(target, origin)]


def _assign_sql_bindings(
    state: _SqlBindingState,
    targets: list[ast.expr],
    value: ast.expr | None,
    parents: dict[ast.AST, ast.AST],
) -> None:
    if len(targets) == 1:
        _assign_sql_binding_target(state, targets[0], value, parents)
        return
    origin = _sql_origins_in_expression(value, state, parents) if value else None
    _set_sql_binding_targets(state, targets, origin)


def _assign_sql_binding_target(
    state: _SqlBindingState,
    target: ast.expr,
    value: ast.expr | None,
    parents: dict[ast.AST, ast.AST],
) -> None:
    if isinstance(target, ast.Starred):
        _assign_sql_binding_target(state, target.value, value, parents)
        return
    if (
        isinstance(target, (ast.Tuple, ast.List))
        and isinstance(value, (ast.Tuple, ast.List))
        and len(target.elts) == len(value.elts)
        and not any(isinstance(element, ast.Starred) for element in target.elts)
    ):
        for child_target, child_value in zip(target.elts, value.elts, strict=True):
            _assign_sql_binding_target(
                state, child_target, child_value, parents
            )
        return
    origin = (
        _sql_origins_in_expression(value, state, parents)
        if value is not None
        else None
    )
    _set_sql_binding_targets(state, [target], origin)


def _sql_origins_in_expression(
    expression: ast.expr,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> _ProvRef | None:
    references: list[_ProvRef] = []
    pending: list[ast.expr] = [expression]
    while pending:
        candidate = pending.pop()
        template = _dynamic_string_template(candidate, parents)
        if template is not None and _looks_like_sql_statement(template):
            references.append(
                state.graph.source(int(getattr(candidate, "lineno", 1) or 1))
            )
            continue
        reference = _qualified_name(candidate)
        if reference is not None:
            bound = state.get(reference)
            if bound is not None:
                references.append(bound)
            continue
        if isinstance(candidate, ast.NamedExpr):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.IfExp):
            truth = _literal_truth(candidate.test)
            if truth is True:
                pending.append(candidate.body)
            elif truth is False:
                pending.append(candidate.orelse)
            else:
                pending.extend((candidate.orelse, candidate.body))
        elif isinstance(candidate, ast.BoolOp):
            if isinstance(candidate.op, ast.Or):
                for value in reversed(_reachable_or_values(candidate.values)):
                    pending.append(value)
            else:
                final = _reachable_and_result(candidate.values)
                if final is not None:
                    pending.append(final)
        elif isinstance(candidate, ast.Await):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.Call) and _is_transparent_string_call(candidate):
            assert isinstance(candidate.func, ast.Attribute)
            pending.append(candidate.func.value)
        elif isinstance(candidate, ast.JoinedStr):
            pending.extend(
                reversed(_transparent_joined_string_values(candidate))
            )
        elif isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.Add):
            pending.extend((candidate.right, candidate.left))
        elif isinstance(candidate, (ast.Tuple, ast.List, ast.Set)):
            pending.extend(reversed(candidate.elts))
    return state.graph.union(references)


def _transparent_joined_string_values(node: ast.JoinedStr) -> tuple[ast.expr, ...]:
    """Return embedded values only when an f-string adds no semantic text."""

    values: list[ast.expr] = []
    for part in node.values:
        if isinstance(part, ast.FormattedValue):
            if part.format_spec is not None or part.conversion not in {-1, ord("s")}:
                return ()
            values.append(part.value)
        elif not (
            isinstance(part, ast.Constant)
            and isinstance(part.value, str)
            and not part.value.strip()
        ):
            return ()
    return tuple(values) if len(values) == 1 else ()


def _reachable_or_values(values: list[ast.expr]) -> list[ast.expr]:
    reachable: list[ast.expr] = []
    for value in values:
        reachable.append(value)
        if _literal_truth(value) is True:
            break
    return reachable


def _reachable_and_result(values: list[ast.expr]) -> ast.expr | None:
    for index, value in enumerate(values):
        if index == len(values) - 1:
            return value
        if _literal_truth(value) is False:
            return None
    return None


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
    state: _SqlBindingState,
    targets: list[ast.expr],
    origin: _ProvRef | None,
) -> None:
    for target in targets:
        for key in _binding_target_keys(target):
            _set_sql_binding_key(state, key, origin)


def _set_sql_binding_key(
    state: _SqlBindingState,
    key: str,
    origin: _ProvRef | None,
) -> None:
    _kill_sql_binding_key(state, key)
    if origin is not None:
        state.set_reference(key, origin)


def _kill_sql_binding_key(state: _SqlBindingState, key: str) -> None:
    """Replace a binding with a definitely-defined, untainted value."""

    _clear_sql_binding_key(state, key)
    state.define_key(key)


def _undefine_sql_binding_key(state: _SqlBindingState, key: str) -> None:
    """Remove a binding after ``del`` or scope-local cleanup."""

    _clear_sql_binding_key(state, key)
    state.undefine_key(key)


def _clear_sql_binding_key(state: _SqlBindingState, key: str) -> None:
    state.graph.budget.consume_work(len(state.dotted_keys) + 1)
    state.discard_reference(key)
    prefix = f"{key}."
    for candidate in [
        candidate for candidate in state.dotted_keys if candidate.startswith(prefix)
    ]:
        state.discard_reference(candidate)
    state.undefine_key(key)


def _kill_sql_binding_targets(
    state: _SqlBindingState,
    targets: list[ast.expr],
) -> None:
    _set_sql_binding_targets(state, targets, None)


def _undefine_sql_binding_targets(
    state: _SqlBindingState,
    targets: list[ast.expr],
) -> None:
    for target in targets:
        for key in _binding_target_keys(target):
            _undefine_sql_binding_key(state, key)


def _origins_for_binding_targets(
    state: _SqlBindingState,
    targets: list[ast.expr],
) -> _ProvRef | None:
    return state.graph.union(
        state.get(key)
        for target in targets
        for key in _binding_target_keys(target)
    )


def _merge_sql_binding_states(
    *states: _SqlBindingState | None,
) -> _SqlBindingState | None:
    active = [state for state in states if state is not None]
    if not active:
        return None
    if len(active) == 1:
        return active[0]
    graph = active[0].graph
    assert all(state.graph is graph for state in active)
    graph.budget.consume_work(
        sum(len(state) + len(state.defined_keys) for state in active) + 1
    )
    references: dict[str, _ProvRef] = {}
    for key in {key for state in active for key in state}:
        reference = graph.union(state.get(key) for state in active)
        if reference is not None:
            references[key] = reference
    defined_keys = set(active[0].defined_keys)
    for candidate in active[1:]:
        defined_keys.intersection_update(candidate.defined_keys)
    return _SqlBindingState(graph, references, defined_keys)


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


def _python_interpolated_sql_lines_from_source(
    content: str,
    budget: _PythonAnalysisBudget | None = None,
) -> set[int]:
    lines: set[int] = set()
    analysis_budget = budget or _PythonAnalysisBudget("<memory>")
    graph = _SqlProvenance(analysis_budget)
    states_by_scope: dict[
        tuple[int, ...],
        _SqlBindingState | None,
    ] = {}
    for statement in _python_logical_statements(content):
        analysis_budget.consume_work(len(statement.tokens) + 1)
        if _is_compound_control_header(statement.tokens):
            # Recovery intentionally supports only straight-line def/use.
            # Without a complete CFG for malformed modules, carrying a value
            # across a conditional suite can connect mutually exclusive paths.
            states_by_scope[statement.scope_key] = _SqlBindingState(graph)
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
                node_count = analysis_budget.consume_ast(tree)
                analysis_budget.consume_work(node_count * 2)
                ast.increment_lineno(tree, statement.start_line - 2)
                parents = {
                    child: parent
                    for parent in ast.walk(tree)
                    for child in ast.iter_child_nodes(parent)
                }
                lines.update(_direct_python_interpolated_sql_lines(tree, parents))
                recovered_function = tree.body[0]
                assert isinstance(recovered_function, ast.AsyncFunctionDef)
                scope_state = states_by_scope.get(statement.scope_key)
                if scope_state is None:
                    scope_state = _SqlBindingState(graph)
                states_by_scope[statement.scope_key] = _analyze_sql_statement_block(
                    recovered_function.body,
                    scope_state,
                    parents,
                    lines,
                ).normal
        if not parsed:
            lines.update(_tokenized_statement_sql_lines(statement))
            scope_state = states_by_scope.get(statement.scope_key)
            if scope_state is None:
                scope_state = _SqlBindingState(graph)
            _recover_token_sql_assignment(statement, scope_state)
            states_by_scope[statement.scope_key] = scope_state
    lines.update(graph.resolved_sink_lines())
    return lines


def _recover_token_sql_assignment(
    statement: _PythonLogicalStatement,
    state: _SqlBindingState,
) -> None:
    """Recover one malformed straight-line assignment for later sink use."""

    tokens = [
        token
        for token in statement.tokens
        if token.type not in _NON_CODE_TOKEN_TYPES
    ]
    targets = _token_assignment_targets(tokens)
    if not targets:
        return
    references = [
        state.graph.source(tokens[index].start[0])
        for index, template in _token_statement_templates(tokens)
        if _looks_like_sql_statement(template)
    ]
    origin = state.graph.union(references)
    for target in targets:
        _set_sql_binding_key(state, target, origin)


def _token_assignment_targets(tokens: list[tokenize.TokenInfo]) -> set[str]:
    opening = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    equals: list[int] = []
    for index, token in enumerate(tokens):
        if token.string in opening:
            stack.append(opening[token.string])
        elif stack and token.string == stack[-1]:
            stack.pop()
        elif not stack and token.string == "=":
            equals.append(index)
    if not equals:
        return set()

    targets: set[str] = set()
    segment_start = 0
    for equals_index in equals:
        segment = tokens[segment_start:equals_index]
        target = _token_assignment_target(segment)
        if target is not None:
            targets.add(target)
        segment_start = equals_index + 1
    return targets


def _token_assignment_target(tokens: list[tokenize.TokenInfo]) -> str | None:
    if not tokens:
        return None
    colon = next(
        (index for index, token in enumerate(tokens) if token.string == ":"),
        None,
    )
    if colon is not None:
        tokens = tokens[:colon]
    if not tokens or tokens[-1].type != tokenize.NAME:
        return None
    parts = [tokens[-1].string]
    cursor = len(tokens) - 2
    while (
        cursor >= 1
        and tokens[cursor].string == "."
        and tokens[cursor - 1].type == tokenize.NAME
    ):
        parts.append(tokens[cursor - 1].string)
        cursor -= 2
    return ".".join(reversed(parts))


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
    templates = _token_statement_templates(tokens)
    context_indices = _token_sql_context_indices(
        tokens,
        function_name=function_name,
    )
    for index, template in templates:
        if not _looks_like_sql_statement(template):
            continue
        if _select_requires_sql_context(template) and index not in context_indices:
            continue
        lines.add(tokens[index].start[0])
    return lines


def _token_statement_templates(
    tokens: list[tokenize.TokenInfo],
) -> list[tuple[int, str]]:
    templates: list[tuple[int, str]] = []
    consumed_strings: set[int] = set()
    delimiter_mates = _token_delimiter_mates(tokens)
    for index, token in enumerate(tokens):
        if token.type != tokenize.STRING or index in consumed_strings:
            continue
        template, consumed = _token_concat_template(tokens, index)
        consumed_strings.update(consumed)
        if template is None:
            template = _token_string_template(tokens, index, delimiter_mates)
        if template is not None:
            templates.append((index, template))
    return templates


def _token_concat_template(
    tokens: list[tokenize.TokenInfo],
    index: int,
) -> tuple[str | None, set[int]]:
    """Fold one ``+`` suffix once without a semantic token lookahead cap."""

    initial = _token_literal_part(tokens[index])
    if initial is None or index + 1 >= len(tokens) or tokens[index + 1].string != "+":
        return None, {index}

    parts = [initial[0]]
    has_dynamic = initial[1]
    has_string = True
    consumed_strings = {index}
    cursor = index + 1
    while cursor < len(tokens) and tokens[cursor].string == "+":
        operand_start = cursor + 1
        operand_end = _token_concat_operand_end(tokens, operand_start)
        if operand_end <= operand_start:
            break
        operand = tokens[operand_start:operand_end]
        consumed_strings.update(
            position
            for position in range(operand_start, operand_end)
            if tokens[position].type == tokenize.STRING
        )
        part = _token_concat_operand_part(operand)
        if part is None:
            parts.append("{expr}")
            has_dynamic = True
        else:
            parts.append(part[0])
            has_dynamic = has_dynamic or part[1]
            has_string = True
        cursor = operand_end

    if not has_string or not has_dynamic:
        return None, consumed_strings
    return "".join(parts), consumed_strings


def _token_concat_operand_part(
    tokens: list[tokenize.TokenInfo],
) -> tuple[str, bool] | None:
    """Return a direct literal/grouping operand without rescanning suffixes."""

    if not tokens:
        return None
    mates = _token_delimiter_mates(tokens)
    start = 0
    end = len(tokens)
    while (
        start < end
        and tokens[start].string == "("
        and mates.get(start) == end - 1
    ):
        start += 1
        end -= 1
    parts = [_token_literal_part(token) for token in tokens[start:end]]
    if not parts or any(part is None for part in parts):
        return None
    literal_parts = [part for part in parts if part is not None]
    return (
        "".join(part[0] for part in literal_parts),
        any(part[1] for part in literal_parts),
    )


def _token_literal_part(token: tokenize.TokenInfo) -> tuple[str, bool] | None:
    if token.type != tokenize.STRING:
        return None
    try:
        expression = ast.parse(token.string, mode="eval").body
    except (SyntaxError, RecursionError, ValueError):
        expression = None
    if isinstance(expression, ast.JoinedStr):
        template = _joined_string_template(expression)
        return (template, True) if template is not None else None
    try:
        value = ast.literal_eval(token.string)
    except (SyntaxError, RecursionError, ValueError):
        return None
    return (value, False) if isinstance(value, str) else None


def _token_concat_operand_end(
    tokens: list[tokenize.TokenInfo],
    start: int,
) -> int:
    closing_for_opening = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    cursor = start
    while cursor < len(tokens):
        text = tokens[cursor].string
        if text in closing_for_opening:
            stack.append(closing_for_opening[text])
        elif stack and text == stack[-1]:
            stack.pop()
        elif not stack and text in {")", "]", "}", ",", ";", ":"}:
            break
        elif not stack and text == "+":
            break
        cursor += 1
    return cursor


def _token_string_template(
    tokens: list[tokenize.TokenInfo],
    index: int,
    delimiter_mates: dict[int, int],
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
        if operator == "%":
            return _percent_format_template(value)
        elif (
            operator == "."
            and operator_index + 3 < len(tokens)
            and tokens[operator_index + 1].type == tokenize.NAME
            and tokens[operator_index + 1].string in {"format", "format_map"}
            and tokens[operator_index + 2].type == tokenize.OP
            and tokens[operator_index + 2].string == "("
            and _token_call_has_argument(operator_index + 2, delimiter_mates)
        ):
            return _brace_format_template(value)
    return None


def _token_delimiter_mates(
    tokens: list[tokenize.TokenInfo],
) -> dict[int, int]:
    closing_for_opening = {"(": ")", "[": "]", "{": "}"}
    opening_for_closing = {closing: opening for opening, closing in closing_for_opening.items()}
    stack: list[tuple[str, int]] = []
    mates: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.string in closing_for_opening:
            stack.append((token.string, index))
        elif token.string in opening_for_closing:
            if not stack or stack[-1][0] != opening_for_closing[token.string]:
                continue
            _, opening_index = stack.pop()
            mates[opening_index] = index
    return mates


def _token_call_has_argument(
    open_paren_index: int,
    delimiter_mates: dict[int, int],
) -> bool:
    closing_index = delimiter_mates.get(open_paren_index)
    return bool(closing_index is not None and closing_index > open_paren_index + 1)


def _token_sql_context_indices(
    tokens: list[tokenize.TokenInfo],
    *,
    function_name: str | None,
) -> set[int]:
    """Locate direct token-level SQL contexts in one linear scan.

    Malformed modules cannot use the AST flow analyzer, but reconstructing and
    regex-scanning the whole token prefix for every string made a statement
    containing many f-strings quadratic.  This state machine recognizes only
    the same direct contexts needed by the fallback: query-named assignments,
    the first SQL execution argument, and returns from query-named functions.
    Parentheses may group the value; intervening calls or containers are not
    treated as transparent.
    """

    contexts: set[int] = set()
    opening = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    segment_start = 0
    chained_targets: list[str] = []
    query_return = bool(function_name and _is_sql_context_name(function_name))

    def direct_string(start: int) -> int | None:
        cursor = start
        while cursor < len(tokens) and tokens[cursor].string == "(":
            cursor += 1
        if cursor < len(tokens) and tokens[cursor].type == tokenize.STRING:
            return cursor
        return None

    for index, token in enumerate(tokens):
        text = token.string

        if token.type == tokenize.NAME:
            folded = text.casefold()
            if folded in _SQL_EXECUTION_CALL_NAMES:
                open_index = index + 1
                if open_index < len(tokens) and tokens[open_index].string == "(":
                    value_start = open_index + 1
                    if (
                        value_start + 1 < len(tokens)
                        and tokens[value_start].type == tokenize.NAME
                        and tokens[value_start].string.casefold()
                        in _SQL_EXECUTION_KEYWORD_NAMES
                        and tokens[value_start + 1].string == "="
                    ):
                        value_start += 2
                    string_index = direct_string(value_start)
                    if string_index is not None:
                        contexts.add(string_index)
            if query_return and folded == "return":
                string_index = direct_string(index + 1)
                if string_index is not None:
                    contexts.add(string_index)

        if text in opening:
            stack.append(opening[text])
            continue
        if stack and text == stack[-1]:
            stack.pop()
            continue
        if stack:
            continue
        if text == ";":
            segment_start = index + 1
            chained_targets.clear()
            continue
        if text != "=":
            continue

        target = _token_assignment_target(tokens[segment_start:index])
        if target is not None:
            chained_targets.append(target)
        string_index = direct_string(index + 1)
        if string_index is not None and any(
            _is_sql_context_name(target) for target in chained_targets
        ):
            contexts.add(string_index)
        segment_start = index + 1

    return contexts


def python_httpx_calls(
    content: str,
    *,
    file_path: str = "<memory>",
    context: PythonAnalysisContext | None = None,
) -> list[PythonHttpxCall]:
    analysis = _python_analysis_context(content, file_path, context)
    if analysis.tree is None:
        return _python_httpx_calls_from_tokens(
            content,
            budget=analysis.budget,
        )

    analysis.budget.consume_work(analysis.ast_node_count)
    calls: list[PythonHttpxCall] = []
    for node in ast.walk(analysis.tree):
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


def _python_httpx_calls_from_tokens(
    content: str,
    *,
    budget: _PythonAnalysisBudget | None = None,
) -> list[PythonHttpxCall]:
    analysis_budget = budget or _PythonAnalysisBudget("<memory>")
    tokens: list[tokenize.TokenInfo] = []
    token_stream = tokenize.generate_tokens(io.StringIO(content).readline)
    try:
        for token in token_stream:
            analysis_budget.consume_work()
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
