from __future__ import annotations

import ast
import builtins
from collections.abc import Callable, Iterable, Iterator
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
        except (MemoryError, RecursionError) as exc:
            raise DeterministicAnalysisBudgetExceeded(
                path=file_path,
                budget_kind="python_parser_resources",
                limit=0,
                observed_at_least=1,
            ) from exc
        except (SyntaxError, ValueError):
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


@dataclass
class _SqlDescendantNode:
    children: dict[str, _SqlDescendantNode]
    key: str | None = None


class _SqlDescendantIndex:
    """Copy-on-write prefix trie for qualified-binding invalidation."""

    def __init__(
        self,
        budget: _PythonAnalysisBudget,
        keys: Iterable[str] = (),
        *,
        root: _SqlDescendantNode | None = None,
        shared: bool = False,
    ) -> None:
        self.budget = budget
        self.root = root or _SqlDescendantNode({})
        self.shared = shared
        for key in keys:
            self.add(key)

    def add(self, key: str) -> None:
        self.budget.consume_work(len(key) + 1)
        self._ensure_owned()
        parts = key.split(".")
        current = self.root
        for part in parts:
            child = current.children.get(part)
            if child is None:
                child = _SqlDescendantNode({})
                current.children[part] = child
            current = child
        current.key = key

    def discard(self, key: str) -> None:
        self.budget.consume_work(len(key) + 1)
        self._ensure_owned()
        parts = key.split(".")
        nodes = [self.root]
        current = self.root
        for part in parts:
            child = current.children.get(part)
            if child is None:
                return
            current = child
            nodes.append(current)
        if nodes[-1].key != key:
            return
        nodes[-1].key = None
        for index in range(len(parts) - 1, -1, -1):
            child = nodes[index + 1]
            if child.key is not None or child.children:
                break
            nodes[index].children.pop(parts[index], None)

    def get(self, key: str, default: Iterable[str] = ()) -> Iterable[str]:
        self.budget.consume_work(len(key) + 1)
        current = self.root
        for part in key.split("."):
            child = current.children.get(part)
            if child is None:
                return default
            current = child
        descendants: list[str] = []
        pending = list(current.children.values())
        while pending:
            self.budget.consume_work()
            candidate = pending.pop()
            if candidate.key is not None:
                descendants.append(candidate.key)
            pending.extend(candidate.children.values())
        return descendants

    def copy(self) -> _SqlDescendantIndex:
        self.budget.consume_work()
        self.shared = True
        return _SqlDescendantIndex(self.budget, root=self.root, shared=True)

    def _ensure_owned(self) -> None:
        if not self.shared:
            return
        root = _SqlDescendantNode({}, self.root.key)
        pending = [(self.root, root)]
        while pending:
            self.budget.consume_work()
            source, target = pending.pop()
            for part, child in source.children.items():
                cloned = _SqlDescendantNode({}, child.key)
                target.children[part] = cloned
                pending.append((child, cloned))
        self.root = root
        self.shared = False


class _SqlBindingState(dict[str, _ProvRef]):
    def __init__(
        self,
        graph: _SqlProvenance,
        initial: dict[str, _ProvRef] | None = None,
        defined_keys: Iterable[str] | None = None,
        possible_defined_keys: Iterable[str] | None = None,
        shadowed_keys: Iterable[str] | None = None,
        active_exception_channels: Iterable[str] = (),
    ) -> None:
        super().__init__(initial or {})
        self.graph = graph
        self.defined_keys = set(self) if defined_keys is None else set(defined_keys)
        self.possible_defined_keys = (
            set(self.defined_keys).union(self)
            if possible_defined_keys is None
            else set(possible_defined_keys)
        )
        self.shadowed_keys = (
            set(self.possible_defined_keys)
            if shadowed_keys is None
            else set(shadowed_keys)
        )
        self.active_exception_channels = frozenset(active_exception_channels)
        self.binding_values: dict[str, _SqlValue] = {}
        self.class_comprehension_outer: _SqlBindingState | None = None
        self.reference_descendants = _SqlDescendantIndex(graph.budget, self)
        self.defined_descendants = _SqlDescendantIndex(graph.budget, self.defined_keys)
        self.possible_defined_descendants = _SqlDescendantIndex(
            graph.budget, self.possible_defined_keys
        )
        graph.budget.consume_work(
            len(self)
            + len(self.defined_keys)
            + len(self.possible_defined_keys)
            + len(self.shadowed_keys)
            + 1
        )

    def copy(self) -> _SqlBindingState:
        self.graph.budget.consume_work(
            len(self)
            + len(self.defined_keys)
            + len(self.possible_defined_keys)
            + len(self.shadowed_keys)
            + len(self.binding_values)
            + 1
        )
        duplicate = _SqlBindingState(self.graph)
        dict.update(duplicate, self)
        duplicate.defined_keys = set(self.defined_keys)
        duplicate.possible_defined_keys = set(self.possible_defined_keys)
        duplicate.shadowed_keys = set(self.shadowed_keys)
        duplicate.active_exception_channels = self.active_exception_channels
        duplicate.binding_values = dict(self.binding_values)
        duplicate.class_comprehension_outer = self.class_comprehension_outer
        duplicate.reference_descendants = self.reference_descendants.copy()
        duplicate.defined_descendants = self.defined_descendants.copy()
        duplicate.possible_defined_descendants = (
            self.possible_defined_descendants.copy()
        )
        return duplicate

    def set_reference(
        self,
        key: str,
        reference: _ProvRef,
        *,
        definitely_defined: bool = True,
    ) -> None:
        if key not in self:
            self.reference_descendants.add(key)
        super().__setitem__(key, reference)
        if definitely_defined:
            self.define_key(key)

    def define_key(self, key: str) -> None:
        for definition in self._missing_prefixes(key, self.defined_keys):
            self.defined_keys.add(definition)
            self.defined_descendants.add(definition)
        self.possibly_define_key(key)

    def possibly_define_key(self, key: str) -> None:
        definitions = self._missing_prefixes(key, self.possible_defined_keys)
        for definition in definitions:
            self.possible_defined_keys.add(definition)
            self.possible_defined_descendants.add(definition)
        self.shadowed_keys.update(definitions)

    @staticmethod
    def _missing_prefixes(key: str, known: set[str]) -> list[str]:
        if key in known:
            return []
        parent, separator, _ = key.rpartition(".")
        if not separator or parent in known:
            return [key]
        parts = key.split(".")
        missing: list[str] = []
        prefix = parts[0]
        if prefix not in known:
            missing.append(prefix)
        for part in parts[1:]:
            prefix = f"{prefix}.{part}"
            if prefix not in known:
                missing.append(prefix)
        return missing

    def discard_reference(self, key: str) -> None:
        if key in self:
            super().pop(key)
            self.reference_descendants.discard(key)

    def undefine_key(self, key: str) -> None:
        if key in self.defined_keys:
            self.defined_keys.remove(key)
            self.defined_descendants.discard(key)
        if key in self.possible_defined_keys:
            self.possible_defined_keys.remove(key)
            self.possible_defined_descendants.discard(key)

    def replace_with(self, other: _SqlBindingState) -> None:
        assert self.graph is other.graph
        self.graph.budget.consume_work(
            len(other)
            + len(other.defined_keys)
            + len(other.possible_defined_keys)
            + len(other.shadowed_keys)
            + len(other.binding_values)
            + 1
        )
        super().clear()
        super().update(other)
        self.defined_keys = set(other.defined_keys)
        self.possible_defined_keys = set(other.possible_defined_keys)
        self.shadowed_keys = set(other.shadowed_keys)
        self.active_exception_channels = other.active_exception_channels
        self.binding_values = dict(other.binding_values)
        self.class_comprehension_outer = other.class_comprehension_outer
        self.reference_descendants = other.reference_descendants.copy()
        self.defined_descendants = other.defined_descendants.copy()
        self.possible_defined_descendants = other.possible_defined_descendants.copy()


@dataclass
class _SqlFlow:
    """May-analysis states partitioned by Python completion kind."""

    normal: _SqlBindingState | None = None
    breaks: _SqlBindingState | None = None
    continues: _SqlBindingState | None = None
    returns: _SqlBindingState | None = None
    raises: _SqlBindingState | None = None
    base_raises: _SqlBindingState | None = None


@dataclass
class _SqlExceptions:
    ordinary: list[_SqlBindingState]
    base: list[_SqlBindingState]
    enabled: bool = True

    @classmethod
    def empty(cls, *, enabled: bool = True) -> _SqlExceptions:
        return cls([], [], enabled)

    def append(self, state: _SqlBindingState) -> None:
        if self.enabled:
            self.ordinary.append(state)

    def append_base(self, state: _SqlBindingState) -> None:
        if self.enabled:
            self.base.append(state)

    def capture(
        self,
        state: _SqlBindingState,
        *,
        ordinary: bool = True,
        base: bool = False,
    ) -> None:
        if not self.enabled:
            return
        snapshot = state.copy()
        if ordinary:
            self.ordinary.append(snapshot)
        if base:
            self.base.append(snapshot)


@dataclass
class _SqlExpressionEvent:
    kind: str
    node: ast.AST
    state: _SqlBindingState
    branches: tuple[_SqlBindingState, _SqlBindingState] | None = None
    sink_nodes: frozenset[int] = frozenset()


@dataclass(frozen=True)
class _SqlValue:
    origin: _ProvRef | None
    elements: tuple[_SqlValue, ...] | None = None
    mapping: tuple[tuple[ast.expr | None, _SqlValue], ...] | None = None
    iterated_values: tuple[_SqlValue, ...] | None = None
    iterated_origin: _ProvRef | None = None


_MAX_EXACT_SQL_ITERATIONS = 16


@dataclass
class _SqlHandlerEvaluation:
    ordinary: _SqlBindingState | None
    base: _SqlBindingState | None
    body: _SqlBindingState | None
    matching: _SqlBindingState | None
    exceptions: _SqlExceptions


@dataclass
class _SqlComprehensionFrame:
    header: _SqlBindingState | None
    phis: dict[str, _ProvRef]
    skipped: list[_SqlBindingState]


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
_PYTHON_BUILTIN_EXCEPTION_NAMES = frozenset(
    name
    for name, value in vars(builtins).items()
    if isinstance(value, type) and issubclass(value, BaseException)
)
_PYTHON_REQUIRED_ARGUMENT_EXCEPTION_NAMES = frozenset(
    {
        "BaseExceptionGroup",
        "ExceptionGroup",
        "UnicodeDecodeError",
        "UnicodeEncodeError",
        "UnicodeTranslateError",
    }
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


def strip_js_comments_and_strings(
    content: str, comments_and_strings_re: re.Pattern[str]
) -> str:
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
    try:
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
    except (MemoryError, RecursionError) as exc:
        raise DeterministicAnalysisBudgetExceeded(
            path=file_path,
            budget_kind="python_analysis_resources",
            limit=0,
            observed_at_least=1,
        ) from exc


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
    lines = _direct_python_interpolated_sql_lines(
        tree,
        parents,
        analysis_budget,
    )
    lines.update(_ordered_sql_binding_lines(tree, parents, analysis_budget))
    if line_offset:
        return {line + line_offset for line in lines}
    return lines


def _direct_python_interpolated_sql_lines(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    budget: _PythonAnalysisBudget | None = None,
) -> set[int]:
    analysis_budget = budget or _PythonAnalysisBudget("<memory>")
    lines: set[int] = set()
    context_cache: dict[ast.AST, bool] = {}
    for node in ast.walk(tree):
        analysis_budget.consume_work()
        template = _dynamic_string_template(node, parents)
        if (
            template is not None
            and _looks_like_sql_statement(template)
            and (
                not _select_requires_sql_context(template)
                or _has_sql_context(node, parents, analysis_budget, context_cache)
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
            while (
                cursor < len(value)
                and value[cursor].isascii()
                and value[cursor].isdigit()
            ):
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
    budget: _PythonAnalysisBudget,
    cache: dict[ast.AST, bool] | None = None,
) -> bool:
    """Require a direct SQL sink/binding for ambiguous dynamic SELECT text.

    A small set of value-preserving expression wrappers is transparent. This
    covers common production forms such as ``sql.strip()``, conditional
    expressions, and assignment expressions without treating arbitrary
    containers or function calls as SQL context.
    """

    if cache is not None and node in cache:
        return cache[node]

    current = node
    traversed: list[ast.AST] = []

    def finish(result: bool) -> bool:
        if cache is not None:
            for candidate in traversed:
                cache[candidate] = result
        return result

    while True:
        budget.consume_work()
        if cache is not None and current in cache:
            return finish(cache[current])
        traversed.append(current)
        parent = parents.get(current)
        if parent is None:
            return finish(False)

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
                return finish(True)
            if isinstance(parent, ast.NamedExpr):
                current = parent
                continue
            return finish(False)

        if isinstance(parent, ast.keyword) and parent.value is current:
            keyword_call = parents.get(parent)
            return finish(
                bool(
                    isinstance(keyword_call, ast.Call)
                    and _is_sql_execution_call(keyword_call)
                    and parent.arg is not None
                    and parent.arg.casefold() in _SQL_EXECUTION_KEYWORD_NAMES
                )
            )

        if isinstance(parent, ast.Call):
            if current in _sql_execution_value_arguments(parent, budget):
                return finish(_is_sql_execution_call(parent))
            if current is parent.func and _is_transparent_string_call(parent):
                current = parent
                continue
            return finish(False)

        if isinstance(parent, ast.Return) and parent.value is current:
            function = _enclosing_function(parent, parents)
            return finish(function is not None and _is_sql_context_name(function.name))

        if isinstance(parent, ast.Attribute) and parent.value is current:
            attribute_call = parents.get(parent)
            if (
                isinstance(attribute_call, ast.Call)
                and attribute_call.func is parent
                and _is_transparent_string_call(attribute_call)
            ):
                current = parent
                continue
            return finish(False)

        if _is_transparent_sql_expression_parent(current, parent):
            current = parent
            continue
        return finish(False)


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
        and function_name.rsplit(".", 1)[-1].casefold() in _SQL_EXECUTION_CALL_NAMES
    )


def _static_keyword_unpack_items(
    expression: ast.expr,
    budget: _PythonAnalysisBudget,
) -> tuple[tuple[str, ast.expr], ...]:
    """Return statically guaranteed final items of a ``**`` mapping.

    An unknown nested unpack invalidates all keys established before it because
    it may overwrite any of them.  Literal keys that follow it are guaranteed
    again.  This models dict construction order without guessing which keys an
    arbitrary mapping supplies, while each retained value node still records
    its real lexical evaluation point.
    """

    items: dict[str, ast.expr] = {}
    events: list[tuple[str, ast.expr, str | None]] = [("mapping", expression, None)]
    while events:
        budget.consume_work()
        kind, current, name = events.pop()
        if kind == "item":
            assert name is not None
            items[name] = current
            continue
        if kind == "invalidate":
            items.clear()
            continue
        if not isinstance(current, ast.Dict):
            items.clear()
            continue
        entries = list(zip(current.keys, current.values, strict=True))
        budget.consume_work(len(entries))
        for key, value in reversed(entries):
            if key is None:
                events.append(("mapping", value, None))
                continue
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                events.append(("invalidate", value, None))
                continue
            events.append(("item", value, key.value))
    return tuple(items.items())


def _starred_positional_first_values(
    expression: ast.expr,
    budget: _PythonAnalysisBudget,
) -> tuple[tuple[ast.expr, ...], bool]:
    """Return possible first values and whether an expansion may be empty."""

    values: list[ast.expr] = []
    events: list[tuple[str, ast.expr]] = [("expand", expression)]
    stream_open = True
    while events and stream_open:
        budget.consume_work()
        kind, current = events.pop()
        if kind == "value":
            values.append(current)
            stream_open = False
            continue
        if isinstance(current, (ast.Tuple, ast.List)):
            budget.consume_work(len(current.elts))
            for element in reversed(current.elts):
                if isinstance(element, ast.Starred):
                    events.append(("expand", element.value))
                else:
                    events.append(("value", element))
            continue

        # An arbitrary iterable can provide the first value or be empty.
        values.append(current)

    return tuple(values), stream_open


def _sql_execution_argument_projections(
    call: ast.Call,
    budget: _PythonAnalysisBudget,
) -> dict[int, tuple[ast.expr, ...]]:
    """Map each outer call argument to its possible SQL-value expressions.

    Python's first effective positional value can come from a starred
    expansion rather than from ``call.args[0]``.  Literal tuple/list
    expansions are exact.  An unknown expansion may be empty, so both it and
    the next definite positional expression remain possible under the
    scanner's conservative may-analysis.
    """

    projected: dict[int, list[ast.expr]] = {}

    def add(outer: ast.expr, value: ast.expr) -> None:
        projected.setdefault(id(outer), []).append(value)

    first_positional_open = True
    for argument in call.args:
        budget.consume_work()
        if not first_positional_open:
            break
        if not isinstance(argument, ast.Starred):
            add(argument, argument)
            first_positional_open = False
            continue

        values, first_positional_open = _starred_positional_first_values(
            argument.value,
            budget,
        )
        for value in values:
            add(argument, value)

    for keyword in call.keywords:
        budget.consume_work()
        if keyword.arg is not None:
            if keyword.arg.casefold() in _SQL_EXECUTION_KEYWORD_NAMES:
                add(keyword.value, keyword.value)
            continue
        unpacked = _static_keyword_unpack_items(keyword.value, budget)
        for name, value in unpacked:
            if name.casefold() in _SQL_EXECUTION_KEYWORD_NAMES:
                add(keyword.value, value)

    return {outer: tuple(values) for outer, values in projected.items()}


def _sql_execution_value_arguments(
    call: ast.Call,
    budget: _PythonAnalysisBudget,
) -> list[ast.expr]:
    """Return statically projected SQL values for direct ancestry checks."""

    return [
        value
        for values in _sql_execution_argument_projections(call, budget).values()
        for value in values
    ]


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
        collect_raises = _sql_statement_raises_are_observed(statement, parents)
        step = _analyze_sql_statement(
            statement,
            flow.normal,
            parents,
            lines,
            collect_raises=collect_raises,
        )
        flow = _SqlFlow(
            normal=step.normal,
            breaks=_merge_sql_binding_states(flow.breaks, step.breaks),
            continues=_merge_sql_binding_states(flow.continues, step.continues),
            returns=_merge_sql_binding_states(flow.returns, step.returns),
            raises=(
                _merge_sql_binding_states(flow.raises, step.raises)
                if collect_raises
                else None
            ),
            base_raises=(
                _merge_sql_binding_states(flow.base_raises, step.base_raises)
                if collect_raises
                else None
            ),
        )
    return flow


def _sql_statement_raises_are_observed(
    statement: ast.stmt,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    current = parents.get(statement)
    while current is not None:
        if isinstance(current, (ast.Try, ast.TryStar, ast.With, ast.AsyncWith)):
            return True
        if isinstance(current, ast.ClassDef):
            # Class bodies execute immediately; the enclosing ClassDef
            # transfer translates their exception state back to outer scope.
            return True
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return False
        current = parents.get(current)
    return False


def _analyze_sql_statement(
    statement: ast.stmt,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    *,
    collect_raises: bool,
) -> _SqlFlow:
    exceptions = _SqlExceptions.empty(enabled=collect_raises)
    for analyzer in (
        _analyze_sql_definition_statement,
        _analyze_sql_compound_statement,
        _analyze_sql_mutation_statement,
        _analyze_sql_completion_statement,
    ):
        flow = analyzer(statement, state, parents, lines, exceptions)
        if flow is not None:
            return flow
    _process_sql_expression(statement, state, parents, lines, exceptions)
    return _sql_normal_flow(state, exceptions)


def _analyze_sql_definition_statement(
    statement: ast.stmt,
    current: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlFlow | None:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for expression in _function_definition_expressions(
            statement,
            include_annotations=not _future_annotations_enabled(statement, parents),
        ):
            _process_sql_expression(expression, current, parents, lines, exceptions)
        if statement.decorator_list:
            exceptions.capture(current, base=True)
        _kill_sql_binding_key(current, statement.name)
        _analyze_sql_statement_block(
            statement.body,
            _function_sql_initial_state(statement, current.graph),
            parents,
            lines,
        )
        return _sql_normal_flow(current, exceptions)

    if isinstance(statement, ast.ClassDef):
        for expression in [
            *statement.decorator_list,
            *statement.bases,
            *(keyword.value for keyword in statement.keywords),
        ]:
            _process_sql_expression(expression, current, parents, lines, exceptions)
        class_entry = current.copy()
        _kill_sql_binding_key(current, statement.name)
        class_state = class_entry.copy()
        class_state.class_comprehension_outer = (
            class_entry.class_comprehension_outer or class_entry
        )
        class_flow = _analyze_sql_statement_block(
            statement.body, class_state, parents, lines
        )
        external_names = _class_declared_external_names(statement.body)
        normal = _project_sql_class_completion(
            current, class_entry, class_flow.normal, external_names
        )
        class_raises = _project_sql_class_completion(
            class_entry, class_entry, class_flow.raises, external_names
        )
        class_base_raises = _project_sql_class_completion(
            class_entry, class_entry, class_flow.base_raises, external_names
        )
        class_constructs = _project_sql_class_completion(
            class_entry, class_entry, class_flow.normal, external_names
        )
        return _SqlFlow(
            normal=normal,
            raises=_merge_sql_binding_states(
                *exceptions.ordinary,
                class_raises,
                class_constructs,
            ),
            base_raises=_merge_sql_binding_states(
                *exceptions.base,
                class_base_raises,
                class_constructs,
            ),
        )
    return None


def _function_definition_expressions(
    statement: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    include_annotations: bool,
) -> list[ast.expr]:
    """Return definition-time expressions in CPython 3.11 evaluation order."""

    arguments = statement.args
    annotated = [
        *arguments.args,
        *arguments.posonlyargs,
        *([arguments.vararg] if arguments.vararg is not None else []),
        *arguments.kwonlyargs,
        *([arguments.kwarg] if arguments.kwarg is not None else []),
    ]
    expressions = [
        *statement.decorator_list,
        *arguments.defaults,
        *(default for default in arguments.kw_defaults if default is not None),
    ]
    if include_annotations:
        expressions.extend(
            argument.annotation
            for argument in annotated
            if argument.annotation is not None
        )
        if statement.returns is not None:
            expressions.append(statement.returns)
    return expressions


def _future_annotations_enabled(
    statement: ast.stmt,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    root: ast.AST = statement
    while root in parents:
        root = parents[root]
    return bool(
        isinstance(root, ast.Module)
        and any(
            isinstance(candidate, ast.ImportFrom)
            and candidate.module == "__future__"
            and any(alias.name == "annotations" for alias in candidate.names)
            for candidate in root.body
        )
    )


def _class_declared_external_names(statements: Iterable[ast.stmt]) -> set[str]:
    names: set[str] = set()
    pending: list[ast.AST] = list(statements)
    while pending:
        current = pending.pop()
        if isinstance(current, (ast.Global, ast.Nonlocal)):
            names.update(current.names)
            continue
        if isinstance(
            current,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
        ):
            continue
        pending.extend(ast.iter_child_nodes(current))
    return names


def _project_sql_class_completion(
    outer: _SqlBindingState,
    class_entry: _SqlBindingState,
    completion: _SqlBindingState | None,
    external_names: set[str],
) -> _SqlBindingState | None:
    if completion is None:
        return None
    projected = outer.copy()
    candidates = set(completion).union(
        completion.defined_keys,
        completion.possible_defined_keys,
        completion.binding_values,
        class_entry,
        class_entry.defined_keys,
        class_entry.possible_defined_keys,
        class_entry.binding_values,
    )
    changed_qualified = {
        key
        for key in candidates
        if "." in key and _sql_binding_changed(key, class_entry, completion)
    }
    for key in sorted(
        external_names.union(changed_qualified), key=lambda item: item.count(".")
    ):
        _replace_sql_binding_from_state(projected, completion, key)
    return projected


def _sql_binding_changed(
    key: str,
    before: _SqlBindingState,
    after: _SqlBindingState,
) -> bool:
    return bool(
        before.get(key) != after.get(key)
        or (key in before.defined_keys) != (key in after.defined_keys)
        or (key in before.possible_defined_keys) != (key in after.possible_defined_keys)
        or before.binding_values.get(key) != after.binding_values.get(key)
    )


def _replace_sql_binding_from_state(
    target: _SqlBindingState,
    source: _SqlBindingState,
    key: str,
) -> None:
    _undefine_sql_binding_key(target, key)
    origin = source.get(key)
    if origin is not None:
        target.set_reference(key, origin, definitely_defined=False)
    if key in source.defined_keys:
        target.define_key(key)
    elif key in source.possible_defined_keys:
        target.possibly_define_key(key)
    if key in source.shadowed_keys:
        target.shadowed_keys.add(key)
    else:
        target.shadowed_keys.discard(key)
    if key in source.binding_values:
        target.binding_values[key] = source.binding_values[key]


def _analyze_sql_compound_statement(
    statement: ast.stmt,
    current: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlFlow | None:
    if isinstance(statement, ast.If):
        return _analyze_sql_if(statement, current, parents, lines)
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return _analyze_sql_for(statement, current, parents, lines)
    if isinstance(statement, ast.While):
        return _analyze_sql_while(statement, current, parents, lines)
    if isinstance(statement, (ast.Try, ast.TryStar)):
        return _analyze_sql_try(statement, current, parents, lines)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return _analyze_sql_with(statement, current, parents, lines, exceptions)
    if isinstance(statement, ast.Match):
        return _analyze_sql_match(statement, current, parents, lines)
    return None


def _analyze_sql_with(
    statement: ast.With | ast.AsyncWith,
    current: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlFlow:
    for item in statement.items:
        _process_sql_expression(item.context_expr, current, parents, lines, exceptions)
        exceptions.capture(current, base=True)
        if item.optional_vars is not None:
            _kill_sql_binding_targets(current, [item.optional_vars])
    body = _analyze_sql_statement_block(statement.body, current, parents, lines)
    exit_failures = _merge_sql_binding_states(
        body.normal,
        body.breaks,
        body.continues,
        body.returns,
        body.raises,
        body.base_raises,
    )
    suppressed = _merge_sql_binding_states(body.raises, body.base_raises)
    body.normal = _merge_sql_binding_states(
        body.normal,
        suppressed.copy() if suppressed is not None else None,
    )
    body.raises = _merge_sql_binding_states(
        *exceptions.ordinary, body.raises, exit_failures
    )
    body.base_raises = _merge_sql_binding_states(
        *exceptions.base, body.base_raises, exit_failures
    )
    return body


def _analyze_sql_mutation_statement(
    statement: ast.stmt,
    current: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlFlow | None:
    if isinstance(statement, ast.Assign):
        value = _evaluate_sql_assignment_value(
            statement.value, current, parents, lines, exceptions
        )
        if not _apply_sql_assignment_targets(
            current,
            statement.targets,
            value,
            parents,
            lines,
            exceptions,
        ):
            return _SqlFlow(
                raises=_merge_sql_binding_states(*exceptions.ordinary),
                base_raises=_merge_sql_binding_states(*exceptions.base),
            )
        return _sql_normal_flow(current, exceptions)
    if isinstance(statement, ast.AnnAssign):
        if statement.value is None:
            _process_sql_annotation_target(
                statement.target,
                current,
                parents,
                lines,
                exceptions,
                evaluate_name=not bool(statement.simple),
            )
            if _annotation_evaluates_at_runtime(statement, parents):
                _process_sql_expression(
                    statement.annotation, current, parents, lines, exceptions
                )
            return _sql_normal_flow(current, exceptions)
        value = _evaluate_sql_assignment_value(
            statement.value, current, parents, lines, exceptions
        )
        if not _apply_sql_assignment_targets(
            current,
            [statement.target],
            value,
            parents,
            lines,
            exceptions,
        ):
            return _SqlFlow(
                raises=_merge_sql_binding_states(*exceptions.ordinary),
                base_raises=_merge_sql_binding_states(*exceptions.base),
            )
        if _annotation_evaluates_at_runtime(statement, parents):
            _process_sql_expression(
                statement.annotation, current, parents, lines, exceptions
            )
        return _sql_normal_flow(current, exceptions)
    if isinstance(statement, ast.AugAssign):
        _process_sql_expression(statement.target, current, parents, lines, exceptions)
        _process_sql_expression(statement.value, current, parents, lines, exceptions)
        previous = _origins_for_binding_targets(current, [statement.target])
        dynamic_append = (
            current.graph.source(int(getattr(statement.value, "lineno", 1) or 1))
            if isinstance(statement.op, ast.Add)
            and _dynamic_string_template(statement.value, parents) is not None
            else None
        )
        origin = current.graph.union(
            (
                previous,
                _sql_origins_in_expression(statement.value, current, parents),
                dynamic_append,
            )
        )
        exceptions.capture(current, base=True)
        _set_sql_binding_targets(current, [statement.target], origin)
        return _sql_normal_flow(current, exceptions)
    if isinstance(statement, ast.Delete):
        for target in statement.targets:
            _process_sql_expression(target, current, parents, lines, exceptions)
            _undefine_sql_binding_targets(current, [target])
        return _sql_normal_flow(current, exceptions)
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        exceptions.capture(current, base=True)
        for alias in statement.names:
            _kill_sql_binding_key(current, alias.asname or alias.name.split(".", 1)[0])
        return _sql_normal_flow(current, exceptions)
    return None


def _process_sql_annotation_target(
    target: ast.expr,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
    *,
    evaluate_name: bool,
) -> None:
    """Evaluate an annotation-only expression target without performing a store."""

    if isinstance(target, ast.Name) and evaluate_name:
        # Parentheses make a name annotation target non-simple.  Python loads
        # that name (and can therefore raise NameError) without storing it.
        loaded = ast.copy_location(ast.Name(id=target.id, ctx=ast.Load()), target)
        _process_sql_expression(loaded, state, parents, lines, exceptions)
    elif isinstance(target, ast.Attribute):
        _process_sql_expression(target.value, state, parents, lines, exceptions)
    elif isinstance(target, ast.Subscript):
        _process_sql_expression(target.value, state, parents, lines, exceptions)
        _process_sql_expression(target.slice, state, parents, lines, exceptions)


def _analyze_sql_completion_statement(
    statement: ast.stmt,
    current: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlFlow | None:
    if isinstance(statement, ast.Return):
        if statement.value is not None:
            _process_sql_expression(
                statement.value, current, parents, lines, exceptions
            )
        return _SqlFlow(
            returns=current,
            raises=_merge_sql_binding_states(*exceptions.ordinary),
            base_raises=_merge_sql_binding_states(*exceptions.base),
        )
    if isinstance(statement, ast.Raise):
        if statement.exc is not None:
            _process_sql_expression(statement.exc, current, parents, lines, exceptions)
        if statement.cause is not None:
            _process_sql_expression(
                statement.cause, current, parents, lines, exceptions
            )
        raised = current.copy()
        raises = list(exceptions.ordinary)
        base_raises = list(exceptions.base)
        if statement.exc is None:
            channels = _bare_raise_channels(statement, current, parents)
        else:
            channels = _raised_exception_channels(statement.exc, current)
        if "ordinary" in channels:
            raises.append(raised)
        if "base" in channels:
            base_raises.append(raised)
        return _SqlFlow(
            raises=_merge_sql_binding_states(*raises),
            base_raises=_merge_sql_binding_states(*base_raises),
        )
    if isinstance(statement, ast.Break):
        return _SqlFlow(breaks=current)
    if isinstance(statement, ast.Continue):
        return _SqlFlow(continues=current)
    if isinstance(statement, ast.Expr):
        _process_sql_expression(statement.value, current, parents, lines, exceptions)
        return _sql_normal_flow(current, exceptions)
    if isinstance(statement, ast.Assert):
        _process_sql_expression(statement.test, current, parents, lines, exceptions)
        truth = _literal_truth(statement.test)
        assertion_raises = _SqlExceptions.empty()
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
            raises=_merge_sql_binding_states(
                *exceptions.ordinary, *assertion_raises.ordinary
            ),
            base_raises=_merge_sql_binding_states(
                *exceptions.base, *assertion_raises.base
            ),
        )
    return None


def _sql_normal_flow(
    current: _SqlBindingState,
    exceptions: _SqlExceptions,
) -> _SqlFlow:
    return _SqlFlow(
        normal=current,
        raises=_merge_sql_binding_states(*exceptions.ordinary),
        base_raises=_merge_sql_binding_states(*exceptions.base),
    )


def _raised_exception_channels(
    expression: ast.expr,
    state: _SqlBindingState,
) -> frozenset[str]:
    candidate = expression.func if isinstance(expression, ast.Call) else expression
    if (
        isinstance(candidate, ast.Name)
        and candidate.id not in state.shadowed_keys
        and candidate.id in _PYTHON_BUILTIN_EXCEPTION_NAMES
    ):
        value = vars(builtins)[candidate.id]
        assert isinstance(value, type) and issubclass(value, BaseException)
        return frozenset({"ordinary"} if issubclass(value, Exception) else {"base"})
    if isinstance(candidate, ast.Constant):
        # Raising a known non-exception value produces TypeError.
        return frozenset({"ordinary"})
    return frozenset({"ordinary", "base"})


def _bare_raise_channels(
    statement: ast.Raise,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> frozenset[str]:
    if state.active_exception_channels:
        return state.active_exception_channels
    current = parents.get(statement)
    while current is not None:
        if isinstance(current, ast.ExceptHandler):
            if current.type is None:
                return frozenset({"ordinary", "base"})
            return _handler_possible_channels(current.type, state) or frozenset(
                {"ordinary", "base"}
            )
        if isinstance(
            current,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
        ):
            break
        current = parents.get(current)
    # A bare raise in an active finally can re-raise either channel. The
    # surrounding flow does not retain that runtime stack, so keep both.
    return frozenset({"ordinary", "base"})


def _function_sql_initial_state(
    statement: ast.FunctionDef | ast.AsyncFunctionDef,
    graph: _SqlProvenance,
) -> _SqlBindingState:
    state = _SqlBindingState(
        graph,
        shadowed_keys=_assigned_sql_binding_keys(statement.body),
    )
    arguments = [
        *statement.args.posonlyargs,
        *statement.args.args,
        *statement.args.kwonlyargs,
    ]
    if statement.args.vararg is not None:
        arguments.append(statement.args.vararg)
    if statement.args.kwarg is not None:
        arguments.append(statement.args.kwarg)
    for argument in arguments:
        state.define_key(argument.arg)
    return state


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
        test_exceptions = _SqlExceptions.empty()
        _process_sql_expression(
            current_if.test, test_input, parents, lines, test_exceptions
        )
        aggregate.raises = _merge_sql_binding_states(
            aggregate.raises, *test_exceptions.ordinary
        )
        aggregate.base_raises = _merge_sql_binding_states(
            aggregate.base_raises, *test_exceptions.base
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
        aggregate.normal = _merge_sql_binding_states(aggregate.normal, fallthrough)
    return aggregate


def _analyze_sql_for(
    statement: ast.For | ast.AsyncFor,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    entry = state.copy()
    exceptions = _SqlExceptions.empty()
    iterable_value = _evaluate_sql_assignment_value(
        statement.iter, entry, parents, lines, exceptions
    )
    cardinality = _literal_iterable_cardinality(statement.iter)
    _record_sql_iteration_exceptions(
        entry,
        exceptions,
        unknown=cardinality is None or isinstance(statement, ast.AsyncFor),
    )
    if cardinality == 0:
        else_flow = (
            _analyze_sql_statement_block(statement.orelse, entry, parents, lines)
            if statement.orelse
            else _SqlFlow(normal=entry)
        )
        else_flow.raises = _merge_sql_binding_states(
            *exceptions.ordinary, else_flow.raises
        )
        else_flow.base_raises = _merge_sql_binding_states(
            *exceptions.base, else_flow.base_raises
        )
        return else_flow

    iterated_values = _literal_iterated_values(statement.iter, iterable_value)
    if (
        iterated_values is not None
        and len(iterated_values) <= _MAX_EXACT_SQL_ITERATIONS
        and not isinstance(statement, ast.AsyncFor)
    ):
        return _analyze_exact_sql_for(
            statement,
            entry,
            iterated_values,
            parents,
            lines,
            exceptions,
        )
    successful_values: list[_SqlValue] = []
    unpack_failure = False
    if iterated_values is not None:
        for value in iterated_values:
            if _literal_unpack_succeeds(statement.target, value) is False:
                unpack_failure = True
                break
            successful_values.append(value)
        if unpack_failure and not successful_values:
            exceptions.capture(entry)
            return _SqlFlow(
                raises=_merge_sql_binding_states(*exceptions.ordinary),
                base_raises=_merge_sql_binding_states(*exceptions.base),
            )

    header, phis = _sql_loop_header(
        entry,
        statement.body,
        extra_keys=_binding_target_keys(statement.target),
    )
    body_input = header.copy()
    target_value = (
        _merge_sql_values(successful_values, entry.graph)
        if successful_values
        else _iterated_sql_value(statement.iter, iterable_value, entry, parents)
    )
    target_bound = _apply_sql_assignment_targets(
        body_input,
        [statement.target],
        target_value,
        parents,
        lines,
        exceptions,
    )
    if not target_bound:
        return _SqlFlow(
            raises=_merge_sql_binding_states(*exceptions.ordinary),
            base_raises=_merge_sql_binding_states(*exceptions.base),
        )
    body = _analyze_sql_statement_block(statement.body, body_input, parents, lines)
    _complete_sql_loop_phis(phis, body.normal, body.continues)

    if unpack_failure:
        exceptions.capture(header)
        return _SqlFlow(
            normal=body.breaks,
            returns=body.returns,
            raises=_merge_sql_binding_states(*exceptions.ordinary, body.raises),
            base_raises=_merge_sql_binding_states(*exceptions.base, body.base_raises),
        )

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
            *exceptions.ordinary, body.raises, else_flow.raises
        ),
        base_raises=_merge_sql_binding_states(
            *exceptions.base, body.base_raises, else_flow.base_raises
        ),
    )


def _analyze_exact_sql_for(
    statement: ast.For,
    entry: _SqlBindingState,
    values: tuple[_SqlValue, ...],
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlFlow:
    """Execute a small literal loop in source order.

    A merged loop body is conservative for unknown or large iterables, but it
    retains overwritten provenance after a statically known final iteration.
    Bounded unrolling preserves Python's last-binding behavior without making
    generated literal inputs quadratic in the loop-body size.
    """

    active: _SqlBindingState | None = entry
    break_exits: _SqlBindingState | None = None
    returns: _SqlBindingState | None = None
    raises: _SqlBindingState | None = None
    base_raises: _SqlBindingState | None = None
    for value in values:
        if active is None:
            break
        iteration = active.copy()
        if not _apply_sql_assignment_targets(
            iteration,
            [statement.target],
            value,
            parents,
            lines,
            exceptions,
        ):
            active = None
            break
        body = _analyze_sql_statement_block(statement.body, iteration, parents, lines)
        break_exits = _merge_sql_binding_states(break_exits, body.breaks)
        returns = _merge_sql_binding_states(returns, body.returns)
        raises = _merge_sql_binding_states(raises, body.raises)
        base_raises = _merge_sql_binding_states(base_raises, body.base_raises)
        active = _merge_sql_binding_states(body.normal, body.continues)

    else_flow = (
        _analyze_sql_statement_block(statement.orelse, active, parents, lines)
        if statement.orelse and active is not None
        else _SqlFlow(normal=active)
    )
    return _SqlFlow(
        normal=_merge_sql_binding_states(break_exits, else_flow.normal),
        breaks=else_flow.breaks,
        continues=else_flow.continues,
        returns=_merge_sql_binding_states(returns, else_flow.returns),
        raises=_merge_sql_binding_states(
            *exceptions.ordinary,
            raises,
            else_flow.raises,
        ),
        base_raises=_merge_sql_binding_states(
            *exceptions.base,
            base_raises,
            else_flow.base_raises,
        ),
    )


def _literal_iterable_cardinality(expression: ast.expr) -> int | None:
    results: dict[int, int | None] = {}
    pending: list[tuple[ast.expr, bool]] = [(expression, False)]
    while pending:
        current, ready = pending.pop()
        if not ready:
            pending.append((current, True))
            if isinstance(current, (ast.List, ast.Tuple)):
                pending.extend(
                    (element.value, False)
                    for element in current.elts
                    if isinstance(element, ast.Starred)
                )
            continue
        cardinality: int | None = None
        if isinstance(current, (ast.List, ast.Tuple)):
            cardinality = 0
            for element in current.elts:
                if not isinstance(element, ast.Starred):
                    cardinality += 1
                    continue
                expanded = results.get(id(element.value))
                if expanded is None:
                    cardinality = None
                    break
                cardinality += expanded
        elif isinstance(current, ast.Set):
            cardinality = _literal_set_display_cardinality(current)
        elif isinstance(current, ast.Dict):
            cardinality = _literal_dict_cardinality(current)
        elif isinstance(current, ast.Constant) and isinstance(
            current.value, (bytes, str)
        ):
            cardinality = len(current.value)
        results[id(current)] = cardinality
    return results[id(expression)]


def _static_display_elements(
    expression: ast.expr,
) -> tuple[ast.expr, ...] | None:
    """Flatten exact starred list/tuple/set displays without Python recursion."""

    if not isinstance(expression, (ast.List, ast.Set, ast.Tuple)):
        return None
    flattened: list[ast.expr] = []
    pending = list(reversed(expression.elts))
    while pending:
        element = pending.pop()
        if not isinstance(element, ast.Starred):
            flattened.append(element)
            continue
        # A list/tuple display has deterministic iteration order and no user
        # iterator. Set displays can invoke user hashing and have unstable
        # order, so they remain an unknown expansion here.
        if not isinstance(element.value, (ast.List, ast.Tuple)):
            return None
        pending.extend(reversed(element.value.elts))
    return tuple(flattened)


def _literal_set_display_cardinality(expression: ast.Set) -> int | None:
    """Return exact cardinality for literal set displays, including ``*``.

    This deliberately computes only membership, not iteration order.  Literal
    built-in operands have no user iterator or hashing hooks, so expanding
    them is exact while an arbitrary starred expression remains unknown.
    """

    values: set[object] = set()
    try:
        for element in expression.elts:
            if isinstance(element, ast.Starred):
                expanded = ast.literal_eval(element.value)
                for value in iter(expanded):
                    hash(value)
                    values.add(value)
                continue
            value = ast.literal_eval(element)
            hash(value)
            values.add(value)
    except (TypeError, ValueError):
        return None
    return len(values)


def _literal_dict_cardinality(expression: ast.Dict) -> int | None:
    keys: set[object] = set()
    pending: list[Iterator[tuple[ast.expr | None, ast.expr]]] = [
        iter(zip(expression.keys, expression.values, strict=True))
    ]
    while pending:
        try:
            key, value = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        if key is None:
            if not isinstance(value, ast.Dict):
                return None
            pending.append(iter(zip(value.keys, value.values, strict=True)))
            continue
        try:
            literal_key = ast.literal_eval(key)
            hash(literal_key)
        except (TypeError, ValueError):
            return None
        keys.add(literal_key)
    return len(keys)


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


def _iterated_sql_value(
    expression: ast.expr,
    iterable: _SqlValue,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> _SqlValue:
    """Project a precise value for a statically singleton iterable."""

    iterated = iterable.iterated_values or iterable.elements
    if iterated is not None:
        if len(iterated) == 1:
            return iterated[0]
        return _merge_sql_values(list(iterated), state.graph)
    if iterable.iterated_origin is not None:
        return _SqlValue(iterable.iterated_origin)
    if isinstance(expression, (ast.Dict, ast.List, ast.Set, ast.Tuple)):
        # A literal display has already projected its runtime items.  ``None``
        # here can be an exact clean result (for example ``[*sql_string]``
        # yields characters), so do not fall back to the container's origin.
        return _SqlValue(None)
    return _SqlValue(_iterated_sql_origins(expression, state, parents))


def _literal_iterated_values(
    expression: ast.expr,
    iterable: _SqlValue,
) -> tuple[_SqlValue, ...] | None:
    if isinstance(expression, (ast.List, ast.Tuple)):
        return iterable.iterated_values
    if (
        isinstance(expression, ast.Set)
        and iterable.iterated_values is not None
        and len(iterable.iterated_values) <= 1
    ):
        return iterable.iterated_values
    return None


def _annotation_evaluates_at_runtime(
    statement: ast.AnnAssign,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    if _future_annotations_enabled(statement, parents):
        return False
    current = parents.get(statement)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return False
        if isinstance(current, (ast.ClassDef, ast.Module)):
            return True
        current = parents.get(current)
    return True


def _merge_sql_values(
    values: list[_SqlValue] | tuple[_SqlValue, ...],
    graph: _SqlProvenance,
) -> _SqlValue:
    root = tuple(values)
    pending: list[tuple[tuple[_SqlValue, ...], bool]] = [(root, False)]
    merged: dict[tuple[int, ...], _SqlValue] = {}
    while pending:
        candidates, ready = pending.pop()
        key = tuple(id(candidate) for candidate in candidates)
        element_sets = [candidate.elements for candidate in candidates]
        structured = bool(
            candidates
            and all(elements is not None for elements in element_sets)
            and len({len(elements or ()) for elements in element_sets}) == 1
        )
        if not ready and structured:
            pending.append((candidates, True))
            width = len(element_sets[0] or ())
            for index in range(width):
                child_values = tuple(
                    elements[index] for elements in element_sets if elements is not None
                )
                child_key = tuple(id(child) for child in child_values)
                if child_key not in merged:
                    pending.append((child_values, False))
            continue
        elements = None
        if structured:
            width = len(element_sets[0] or ())
            elements = tuple(
                merged[
                    tuple(
                        id(candidate_elements[index])
                        for candidate_elements in element_sets
                        if candidate_elements is not None
                    )
                ]
                for index in range(width)
            )
        merged[key] = _SqlValue(
            graph.union(candidate.origin for candidate in candidates),
            elements=elements,
        )
    return merged[tuple(id(candidate) for candidate in root)]


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
    exceptions = _SqlExceptions.empty()
    _process_sql_expression(statement.test, test_state, parents, lines, exceptions)
    test_raises = _merge_sql_binding_states(*exceptions.ordinary)
    test_base_raises = _merge_sql_binding_states(*exceptions.base)
    body = (
        _analyze_sql_statement_block(statement.body, test_state, parents, lines)
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
        raises=_merge_sql_binding_states(test_raises, body.raises, else_flow.raises),
        base_raises=_merge_sql_binding_states(
            test_base_raises, body.base_raises, else_flow.base_raises
        ),
    )


def _sql_loop_header(
    entry: _SqlBindingState,
    nodes: Iterable[ast.AST],
    *,
    extra_keys: Iterable[str] = (),
) -> tuple[_SqlBindingState, dict[str, _ProvRef]]:
    assigned = set(_assigned_sql_binding_keys(nodes)).union(extra_keys)
    keys = set(entry).union(assigned)
    entry.graph.budget.consume_work(
        len(assigned) + len(keys) + len(entry.binding_values) + 1
    )
    header = _SqlBindingState(
        entry.graph,
        defined_keys=entry.defined_keys,
        possible_defined_keys=entry.possible_defined_keys.union(assigned),
        shadowed_keys=entry.shadowed_keys.union(assigned),
        active_exception_channels=entry.active_exception_channels,
    )
    phis: dict[str, _ProvRef] = {}
    for key in keys:
        phi = entry.graph.phi(entry.get(key))
        header.set_reference(key, phi, definitely_defined=False)
        phis[key] = phi
    header.binding_values = {
        key: value for key, value in entry.binding_values.items() if key not in assigned
    }
    header.class_comprehension_outer = entry.class_comprehension_outer
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
            current.ctx, (ast.Store, ast.Del)
        ):
            reference = _qualified_name(current)
            if reference is not None:
                keys.add(reference)
        if isinstance(current, ast.Match):
            for case in current.cases:
                keys.update(_match_capture_names(case.pattern))
        if isinstance(current, ast.ExceptHandler) and current.name:
            keys.add(current.name)
        if isinstance(current, (ast.Import, ast.ImportFrom)):
            keys.update(
                alias.asname or alias.name.split(".", 1)[0] for alias in current.names
            )
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
    outer_active = state.active_exception_channels
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
        raises=normal.raises,
        base_raises=normal.base_raises,
    )

    pending_ordinary = body.raises
    pending_base = body.base_raises
    if pending_ordinary is not None or pending_base is not None:
        for handler in statement.handlers:
            evaluation = _evaluate_sql_handler(
                handler,
                pending_ordinary,
                pending_base,
                parents,
                lines,
            )
            pending_ordinary = evaluation.ordinary
            pending_base = evaluation.base
            combined.raises = _merge_sql_binding_states(
                combined.raises, *evaluation.exceptions.ordinary
            )
            combined.base_raises = _merge_sql_binding_states(
                combined.base_raises, *evaluation.exceptions.base
            )

            handled = _SqlFlow()
            if evaluation.body is not None:
                handler_state = evaluation.body.copy()
                handler_state.active_exception_channels = _handler_caught_channels(
                    handler, evaluation
                )
                handler_name = handler.name
                if handler_name:
                    _kill_sql_binding_key(handler_state, handler_name)
                handled = _analyze_sql_statement_block(
                    handler.body, handler_state, parents, lines
                )
                if handler_name:
                    handled = _map_sql_flow_states(
                        handled,
                        lambda candidate: _state_without_key(candidate, handler_name),
                    )
                combined = _merge_sql_flows(combined, handled)

            if isinstance(statement, ast.TryStar):
                effects = _merge_sql_binding_states(
                    handled.normal,
                    handled.breaks,
                    handled.continues,
                    handled.returns,
                    handled.raises,
                    handled.base_raises,
                )
                if effects is not None:
                    if pending_ordinary is not None:
                        pending_ordinary = _merge_sql_binding_states(
                            pending_ordinary, effects
                        )
                    if pending_base is not None:
                        pending_base = _merge_sql_binding_states(pending_base, effects)

            coverage = (
                _definite_handler_coverage(handler, evaluation.matching)
                if evaluation.matching is not None
                else None
            )
            if coverage in {"ordinary", "both"}:
                pending_ordinary = None
            if coverage in {"base", "both"}:
                pending_base = None
            if pending_ordinary is None and pending_base is None:
                break

    combined.raises = _merge_sql_binding_states(combined.raises, pending_ordinary)
    combined.base_raises = _merge_sql_binding_states(combined.base_raises, pending_base)

    combined = _restore_sql_flow_active_channels(combined, outer_active)

    return (
        _apply_sql_finally(combined, statement.finalbody, parents, lines)
        if statement.finalbody
        else combined
    )


def _evaluate_sql_handler(
    handler: ast.ExceptHandler,
    ordinary: _SqlBindingState | None,
    base: _SqlBindingState | None,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlHandlerEvaluation:
    exceptions = _SqlExceptions.empty()

    def evaluate(candidate: _SqlBindingState | None) -> _SqlBindingState | None:
        if candidate is None:
            return None
        evaluated = candidate.copy()
        if handler.type is not None:
            _process_sql_expression(handler.type, evaluated, parents, lines, exceptions)
        return evaluated

    evaluated_ordinary = evaluate(ordinary)
    evaluated_base = evaluate(base)
    matching = _merge_sql_binding_states(evaluated_ordinary, evaluated_base)
    if (
        handler.type is not None
        and matching is not None
        and not _handler_type_is_definitely_valid(handler.type, matching)
    ):
        # Exception matching can itself raise TypeError after the handler type
        # expression's side effects have occurred.
        for candidate in (evaluated_ordinary, evaluated_base):
            if candidate is not None:
                exceptions.capture(candidate)
    return _SqlHandlerEvaluation(
        ordinary=evaluated_ordinary,
        base=evaluated_base,
        body=_handler_input_state(handler, evaluated_ordinary, evaluated_base),
        matching=matching,
        exceptions=exceptions,
    )


def _handler_caught_channels(
    handler: ast.ExceptHandler,
    evaluation: _SqlHandlerEvaluation,
) -> frozenset[str]:
    available = {
        channel
        for channel, candidate in (
            ("ordinary", evaluation.ordinary),
            ("base", evaluation.base),
        )
        if candidate is not None
    }
    if handler.type is None or evaluation.matching is None:
        return frozenset(available)
    possible = _handler_possible_channels(handler.type, evaluation.matching)
    return frozenset(
        available if possible is None else available.intersection(possible)
    )


def _restore_sql_flow_active_channels(
    flow: _SqlFlow,
    channels: frozenset[str],
) -> _SqlFlow:
    for name in ("normal", "breaks", "continues", "returns"):
        candidate = getattr(flow, name)
        if candidate is not None:
            candidate.active_exception_channels = channels
    return flow


def _handler_input_state(
    handler: ast.ExceptHandler,
    ordinary: _SqlBindingState | None,
    base: _SqlBindingState | None,
) -> _SqlBindingState | None:
    if handler.type is None:
        return _merge_sql_binding_states(ordinary, base)
    combined = _merge_sql_binding_states(ordinary, base)
    if combined is None:
        return None
    channels = _handler_possible_channels(handler.type, combined)
    if channels is None:
        # Dynamic or shadowed handler types can denote classes from either
        # channel. Keep both as possible body inputs without consuming either.
        return combined
    return _merge_sql_binding_states(
        ordinary if "ordinary" in channels else None,
        base if "base" in channels else None,
    )


def _definite_handler_coverage(
    handler: ast.ExceptHandler,
    state: _SqlBindingState,
) -> str | None:
    if handler.type is None:
        return "both"
    if not _handler_type_is_definitely_valid(handler.type, state):
        return None
    coverage = _broad_handler_channels(handler.type)
    if coverage == {"ordinary", "base"}:
        return "both"
    if coverage == {"ordinary"}:
        return "ordinary"
    return None


def _record_sql_iteration_exceptions(
    state: _SqlBindingState,
    exceptions: _SqlExceptions,
    *,
    unknown: bool,
) -> None:
    if not unknown:
        return
    # ``iter``/``next`` and their async variants may execute arbitrary user
    # code. Literal built-in containers avoid this synthetic may-path.
    exceptions.capture(state, base=True)


def _handler_possible_channels(
    expression: ast.expr,
    state: _SqlBindingState,
) -> frozenset[str] | None:
    if isinstance(expression, ast.Tuple):
        channels: set[str] = set()
        for item in expression.elts:
            item_channels = _handler_possible_channels(item, state)
            if item_channels is None:
                return None
            channels.update(item_channels)
        return frozenset(channels)
    if not isinstance(expression, ast.Name):
        return None
    name = expression.id
    if name in state.shadowed_keys or name not in _PYTHON_BUILTIN_EXCEPTION_NAMES:
        return None
    value = vars(builtins).get(name)
    assert isinstance(value, type) and issubclass(value, BaseException)
    if value is BaseException:
        return frozenset({"ordinary", "base"})
    return frozenset({"ordinary"} if issubclass(value, Exception) else {"base"})


def _broad_handler_channels(expression: ast.expr) -> set[str]:
    names: set[str] = set()
    pending = [expression]
    while pending:
        candidate = pending.pop()
        if isinstance(candidate, ast.Tuple):
            pending.extend(candidate.elts)
        elif isinstance(candidate, ast.Name):
            names.add(candidate.id)
    if "BaseException" in names:
        return {"ordinary", "base"}
    if "Exception" in names:
        return {"ordinary"}
    return set()


def _handler_type_is_definitely_valid(
    expression: ast.expr,
    state: _SqlBindingState,
) -> bool:
    if isinstance(expression, ast.Tuple):
        return all(
            _handler_type_is_definitely_valid(item, state) for item in expression.elts
        )
    return bool(
        isinstance(expression, ast.Name)
        and expression.id not in state.shadowed_keys
        and expression.id in _PYTHON_BUILTIN_EXCEPTION_NAMES
    )


def _apply_sql_finally(
    incoming: _SqlFlow,
    statements: list[ast.stmt],
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    outgoing = _SqlFlow()
    for channel in (
        "normal",
        "breaks",
        "continues",
        "returns",
        "raises",
        "base_raises",
    ):
        channel_state = getattr(incoming, channel)
        if channel_state is None:
            continue
        final_state = channel_state.copy()
        if channel == "raises":
            final_state.active_exception_channels = frozenset({"ordinary"})
        elif channel == "base_raises":
            final_state.active_exception_channels = frozenset({"base"})
        final = _analyze_sql_statement_block(statements, final_state, parents, lines)
        if final.normal is not None:
            setattr(
                outgoing,
                channel,
                _merge_sql_binding_states(getattr(outgoing, channel), final.normal),
            )
        outgoing.breaks = _merge_sql_binding_states(outgoing.breaks, final.breaks)
        outgoing.continues = _merge_sql_binding_states(
            outgoing.continues, final.continues
        )
        outgoing.returns = _merge_sql_binding_states(outgoing.returns, final.returns)
        outgoing.raises = _merge_sql_binding_states(outgoing.raises, final.raises)
        outgoing.base_raises = _merge_sql_binding_states(
            outgoing.base_raises, final.base_raises
        )
    return outgoing


def _analyze_sql_match(
    statement: ast.Match,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlFlow:
    current = state.copy()
    exceptions = _SqlExceptions.empty()
    subject_value = _evaluate_sql_assignment_value(
        statement.subject, current, parents, lines, exceptions
    )
    outcomes = _SqlFlow()
    fallthrough: _SqlBindingState | None = current
    for case in statement.cases:
        if fallthrough is None:
            break
        unmatched = fallthrough
        case_state = unmatched.copy()
        _process_sql_match_pattern(case.pattern, case_state, parents, lines, exceptions)
        pattern_truth = _match_pattern_truth(case.pattern, statement.subject)
        if pattern_truth is False:
            fallthrough = unmatched
            continue
        for name, origin in _match_capture_origins(
            case.pattern,
            subject_value,
            case_state.graph,
        ).items():
            _set_sql_binding_key(case_state, name, origin)
        guard_truth: bool | None = True
        if case.guard is not None:
            _process_sql_expression(case.guard, case_state, parents, lines, exceptions)
            guard_truth = _literal_truth(case.guard)
        if guard_truth is not False:
            outcomes = _merge_sql_flows(
                outcomes,
                _analyze_sql_statement_block(case.body, case_state, parents, lines),
            )

        failed: list[_SqlBindingState] = []
        if not (_match_pattern_is_irrefutable(case.pattern) or pattern_truth is True):
            failed.append(unmatched)
        if case.guard is not None and guard_truth is not True:
            failed.append(case_state)
        fallthrough = _merge_sql_binding_states(*failed)

    outcomes.normal = _merge_sql_binding_states(outcomes.normal, fallthrough)
    outcomes.raises = _merge_sql_binding_states(outcomes.raises, *exceptions.ordinary)
    outcomes.base_raises = _merge_sql_binding_states(
        outcomes.base_raises, *exceptions.base
    )
    return outcomes


def _process_sql_match_pattern(
    pattern: ast.pattern,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> None:
    """Evaluate pattern-time expressions and implicit user-code boundaries."""

    pending: list[ast.pattern] = [pattern]
    while pending:
        current = pending.pop()
        children: list[ast.pattern] = []
        if isinstance(current, ast.MatchValue):
            _process_sql_expression(current.value, state, parents, lines, exceptions)
        elif isinstance(current, ast.MatchClass):
            _process_sql_expression(current.cls, state, parents, lines, exceptions)
            exceptions.capture(state, base=True)
            children.extend((*current.patterns, *current.kwd_patterns))
        elif isinstance(current, ast.MatchMapping):
            for key in current.keys:
                _process_sql_expression(key, state, parents, lines, exceptions)
            exceptions.capture(state, base=True)
            children.extend(current.patterns)
        elif isinstance(current, ast.MatchSequence):
            exceptions.capture(state, base=True)
            children.extend(current.patterns)
        elif isinstance(current, ast.MatchOr):
            children.extend(current.patterns)
        elif isinstance(current, ast.MatchAs) and current.pattern is not None:
            children.append(current.pattern)
        pending.extend(reversed(children))


def _match_capture_origins(
    pattern: ast.pattern,
    subject: _SqlValue | None,
    graph: _SqlProvenance,
) -> dict[str, _ProvRef | None]:
    captures: dict[str, _ProvRef | None] = {
        name: subject.origin if subject is not None else None
        for name in _match_capture_names(pattern)
    }
    if isinstance(pattern, ast.MatchAs):
        if pattern.pattern is not None:
            captures.update(_match_capture_origins(pattern.pattern, subject, graph))
        if pattern.name is not None:
            captures[pattern.name] = subject.origin if subject is not None else None
        return captures
    if isinstance(pattern, ast.MatchOr):
        alternatives = [
            _match_capture_origins(item, subject, graph) for item in pattern.patterns
        ]
        return {
            name: graph.union(alternative.get(name) for alternative in alternatives)
            for name in captures
        }
    if (
        isinstance(pattern, ast.MatchSequence)
        and subject is not None
        and subject.elements is not None
    ):
        return _match_sequence_capture_origins(pattern, subject, graph)
    if (
        isinstance(pattern, ast.MatchMapping)
        and subject is not None
        and subject.mapping is not None
    ):
        return _match_mapping_capture_origins(pattern, subject, graph)
    return captures


def _match_sequence_capture_origins(
    pattern: ast.MatchSequence,
    subject: _SqlValue,
    graph: _SqlProvenance,
) -> dict[str, _ProvRef | None]:
    captures: dict[str, _ProvRef | None] = {
        name: None for name in _match_capture_names(pattern)
    }
    assert subject.elements is not None
    elements = subject.elements
    starred = [
        index
        for index, item in enumerate(pattern.patterns)
        if isinstance(item, ast.MatchStar)
    ]
    if len(starred) > 1 or (not starred and len(pattern.patterns) != len(elements)):
        return captures
    if starred and len(elements) < len(pattern.patterns) - 1:
        return captures

    star_index = starred[0] if starred else len(pattern.patterns)
    trailing = len(pattern.patterns) - star_index - bool(starred)
    for child_pattern, child_subject in zip(
        pattern.patterns[:star_index],
        elements[:star_index],
        strict=True,
    ):
        captures.update(_match_capture_origins(child_pattern, child_subject, graph))
    if starred:
        star = pattern.patterns[star_index]
        assert isinstance(star, ast.MatchStar)
        if star.name is not None:
            middle_end = len(elements) - trailing if trailing else len(elements)
            captures[star.name] = graph.union(
                element.origin for element in elements[star_index:middle_end]
            )
    if trailing:
        for child_pattern, child_subject in zip(
            pattern.patterns[-trailing:],
            elements[-trailing:],
            strict=True,
        ):
            captures.update(_match_capture_origins(child_pattern, child_subject, graph))
    return captures


def _match_mapping_capture_origins(
    pattern: ast.MatchMapping,
    subject: _SqlValue,
    graph: _SqlProvenance,
) -> dict[str, _ProvRef | None]:
    captures: dict[str, _ProvRef | None] = {
        name: None for name in _match_capture_names(pattern)
    }
    assert subject.mapping is not None
    events = _flatten_sql_mapping_entries(subject.mapping)
    subject_values: dict[object, _SqlValue] = {}
    unknown_values: list[_SqlValue] = []
    for known, key, value in events:
        if not known:
            unknown_values.append(value)
            continue
        subject_values[key] = value

    matched_keys: set[object] = set()
    for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
        try:
            literal_key = ast.literal_eval(key)
            hash(literal_key)
        except (TypeError, ValueError):
            child_subject: _SqlValue | None = _SqlValue(
                graph.union(value.origin for _, _, value in events)
            )
            captures.update(_match_capture_origins(child_pattern, child_subject, graph))
            continue
        child_subject = _sql_mapping_value_for_key(events, literal_key, graph)
        if child_subject is not None:
            matched_keys.add(literal_key)
        captures.update(_match_capture_origins(child_pattern, child_subject, graph))
    if pattern.rest is not None:
        captures[pattern.rest] = graph.union(
            [
                value.origin
                for key, value in subject_values.items()
                if key not in matched_keys
            ]
            + [value.origin for value in unknown_values]
        )
    return captures


def _flatten_sql_mapping_entries(
    mapping: tuple[tuple[ast.expr | None, _SqlValue], ...],
) -> list[tuple[bool, object, _SqlValue]]:
    """Expand statically known ``**`` mappings while preserving update order."""

    flattened: list[tuple[bool, object, _SqlValue]] = []
    pending: list[Iterator[tuple[ast.expr | None, _SqlValue]]] = [iter(mapping)]
    while pending:
        try:
            key, value = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        if key is None:
            if value.mapping is not None:
                pending.append(iter(value.mapping))
            else:
                flattened.append((False, None, value))
            continue
        try:
            literal_key = ast.literal_eval(key)
            hash(literal_key)
        except (TypeError, ValueError):
            flattened.append((False, None, value))
            continue
        flattened.append((True, literal_key, value))
    return flattened


def _sql_mapping_value_for_key(
    events: list[tuple[bool, object, _SqlValue]],
    requested: object,
    graph: _SqlProvenance,
) -> _SqlValue | None:
    exact: _SqlValue | None = None
    uncertain: list[_SqlValue] = []
    for known, key, value in events:
        if known and key == requested:
            exact = value
            uncertain.clear()
        elif not known:
            uncertain.append(value)
    if not uncertain:
        return exact
    return _SqlValue(
        graph.union(
            [exact.origin if exact is not None else None]
            + [value.origin for value in uncertain]
        )
    )


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


def _match_pattern_truth(
    pattern: ast.pattern,
    subject: ast.expr,
) -> bool | None:
    if isinstance(pattern, ast.MatchAs):
        return (
            True
            if pattern.pattern is None
            else _match_pattern_truth(pattern.pattern, subject)
        )
    if isinstance(pattern, ast.MatchOr):
        truths = [_match_pattern_truth(item, subject) for item in pattern.patterns]
        if any(truth is True for truth in truths):
            return True
        return False if all(truth is False for truth in truths) else None
    if isinstance(pattern, ast.MatchSingleton) and isinstance(subject, ast.Constant):
        return subject.value is pattern.value
    if isinstance(pattern, ast.MatchValue):
        try:
            return ast.literal_eval(pattern.value) == ast.literal_eval(subject)
        except (TypeError, ValueError):
            return None
    if isinstance(pattern, ast.MatchSequence) and isinstance(
        subject, (ast.List, ast.Tuple)
    ):
        subject_elements = _static_display_elements(subject)
        if subject_elements is None:
            return None
        starred = [
            index
            for index, item in enumerate(pattern.patterns)
            if isinstance(item, ast.MatchStar)
        ]
        if len(starred) > 1 or (
            not starred and len(pattern.patterns) != len(subject_elements)
        ):
            return False
        if starred and len(subject_elements) < len(pattern.patterns) - 1:
            return False
        star_index = starred[0] if starred else len(pattern.patterns)
        trailing = len(pattern.patterns) - star_index - (1 if starred else 0)
        pairs = list(
            zip(
                pattern.patterns[:star_index],
                subject_elements[:star_index],
                strict=True,
            )
        )
        if trailing:
            pairs.extend(
                zip(
                    pattern.patterns[-trailing:],
                    subject_elements[-trailing:],
                    strict=True,
                )
            )
        truths = [
            _match_pattern_truth(child_pattern, child_subject)
            for child_pattern, child_subject in pairs
        ]
        if any(truth is False for truth in truths):
            return False
        return True if all(truth is True for truth in truths) else None
    if isinstance(pattern, ast.MatchMapping) and isinstance(subject, ast.Dict):
        subject_keys: dict[object, ast.expr] = {}
        unknown_keys = False
        for key, value in zip(subject.keys, subject.values, strict=True):
            if key is None:
                unknown_keys = True
                continue
            try:
                literal_key = ast.literal_eval(key)
                hash(literal_key)
            except (TypeError, ValueError):
                unknown_keys = True
                continue
            subject_keys[literal_key] = value
        mapping_truths: list[bool | None] = []
        for key, child_pattern in zip(pattern.keys, pattern.patterns, strict=True):
            try:
                literal_key = ast.literal_eval(key)
                hash(literal_key)
            except (TypeError, ValueError):
                return None
            child_subject = subject_keys.get(literal_key)
            if child_subject is None:
                if unknown_keys:
                    mapping_truths.append(None)
                    continue
                return False
            child_truth = _match_pattern_truth(child_pattern, child_subject)
            if child_truth is False:
                return False
            mapping_truths.append(child_truth)
        return True if all(truth is True for truth in mapping_truths) else None
    return None


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
        base_raises=_merge_sql_binding_states(*(flow.base_raises for flow in flows)),
    )


def _map_sql_flow_states(
    flow: _SqlFlow,
    transform: Callable[[_SqlBindingState], _SqlBindingState],
) -> _SqlFlow:
    return _SqlFlow(
        **{
            channel: transform(state) if state is not None else None
            for channel in (
                "normal",
                "breaks",
                "continues",
                "returns",
                "raises",
                "base_raises",
            )
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
    exceptions: _SqlExceptions,
) -> None:
    """Apply expression side effects in Python evaluation order.

    The previous implementation first read every sink and only then applied
    assignment expressions.  That inverted real evaluation order.  This
    explicit event stack keeps deep addition trees iterative while binding a
    walrus immediately after its value and recording each SQL argument before
    later call arguments can mutate the same name.
    """

    events = [_SqlExpressionEvent("visit", node, state)]
    while events:
        state.graph.budget.consume_work()
        event = events.pop()
        if event.kind == "visit" and id(event.node) in event.sink_nodes:
            events.append(_SqlExpressionEvent("sink", event.node, event.state))
            event = _SqlExpressionEvent(
                "visit",
                event.node,
                event.state,
                sink_nodes=event.sink_nodes - {id(event.node)},
            )
        if _apply_sql_expression_event(event, events, parents, exceptions):
            continue
        if _enqueue_special_sql_expression(
            event.node,
            event.state,
            events,
            parents,
            lines,
            exceptions,
            event.sink_nodes,
        ):
            continue
        _enqueue_generic_sql_expression(
            event.node,
            event.state,
            events,
            parents,
            event.sink_nodes,
        )


def _apply_sql_expression_event(
    event: _SqlExpressionEvent,
    events: list[_SqlExpressionEvent],
    parents: dict[ast.AST, ast.AST],
    exceptions: _SqlExceptions,
) -> bool:
    current = event.node
    state = event.state
    if event.kind == "visit":
        return False
    if event.kind == "bind":
        assert isinstance(current, ast.NamedExpr)
        _assign_sql_bindings(state, [current.target], current.value, parents)
    elif event.kind == "sink":
        assert isinstance(current, ast.expr)
        state.graph.add_sink(_sql_origins_in_expression(current, state, parents))
    elif event.kind == "raise":
        exceptions.capture(state, base=not isinstance(current, ast.Name))
    elif event.kind == "ifexp":
        assert isinstance(current, ast.IfExp)
        _enqueue_sql_ifexp_branches(current, state, events, event.sink_nodes)
    else:
        assert event.kind == "merge" and event.branches is not None
        merged = _merge_sql_binding_states(*event.branches)
        assert merged is not None
        state.replace_with(merged)
    return True


def _enqueue_sql_ifexp_branches(
    node: ast.IfExp,
    state: _SqlBindingState,
    events: list[_SqlExpressionEvent],
    sink_nodes: frozenset[int],
) -> None:
    truth = _literal_truth(node.test)
    if truth is not None:
        branch = node.body if truth else node.orelse
        events.append(
            _SqlExpressionEvent("visit", branch, state, sink_nodes=sink_nodes)
        )
        return
    body_state = state.copy()
    else_state = state.copy()
    events.append(_SqlExpressionEvent("merge", node, state, (body_state, else_state)))
    events.append(
        _SqlExpressionEvent("visit", node.orelse, else_state, sink_nodes=sink_nodes)
    )
    events.append(
        _SqlExpressionEvent("visit", node.body, body_state, sink_nodes=sink_nodes)
    )


def _enqueue_special_sql_expression(
    node: ast.AST,
    state: _SqlBindingState,
    events: list[_SqlExpressionEvent],
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
    sink_nodes: frozenset[int],
) -> bool:
    if isinstance(
        node,
        (
            ast.ClassDef,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Lambda,
        ),
    ):
        return True
    if isinstance(node, ast.NamedExpr):
        events.append(_SqlExpressionEvent("bind", node, state))
        events.append(
            _SqlExpressionEvent("visit", node.value, state, sink_nodes=sink_nodes)
        )
    elif isinstance(node, ast.IfExp):
        events.append(_SqlExpressionEvent("ifexp", node, state, sink_nodes=sink_nodes))
        events.append(
            _SqlExpressionEvent("visit", node.test, state, sink_nodes=sink_nodes)
        )
    elif isinstance(node, ast.BoolOp):
        _process_sql_bool_expression(node, state, parents, lines, exceptions)
    elif isinstance(node, (ast.DictComp, ast.ListComp, ast.SetComp)):
        _process_eager_sql_comprehension(node, state, parents, lines, exceptions)
    elif isinstance(node, ast.GeneratorExp):
        outer = node.generators[0]
        _process_sql_expression(outer.iter, state, parents, lines, exceptions)
        _record_sql_iteration_exceptions(
            state,
            exceptions,
            unknown=(
                _literal_iterable_cardinality(outer.iter) is None
                or bool(outer.is_async)
            ),
        )
    elif isinstance(node, ast.Call):
        _enqueue_sql_call(node, state, events, sink_nodes)
    elif isinstance(node, (ast.Dict, ast.Set)):
        _enqueue_sql_container(node, state, events, sink_nodes)
    else:
        return False
    return True


def _enqueue_sql_call(
    node: ast.Call,
    state: _SqlBindingState,
    events: list[_SqlExpressionEvent],
    sink_nodes: frozenset[int],
) -> None:
    sql_projections = (
        _sql_execution_argument_projections(node, state.graph.budget)
        if _is_sql_execution_call(node)
        else {}
    )
    ordered = [_SqlExpressionEvent("visit", node.func, state, sink_nodes=sink_nodes)]
    for argument in _call_argument_expressions_in_order(node):
        argument_sinks = sink_nodes.union(
            id(value) for value in sql_projections.get(id(argument), ())
        )
        ordered.append(
            _SqlExpressionEvent(
                "visit", argument, state, sink_nodes=frozenset(argument_sinks)
            )
        )
    if not _is_total_zero_argument_exception_call(node, state):
        ordered.append(_SqlExpressionEvent("raise", node, state))
    events.extend(reversed(ordered))


def _is_total_zero_argument_exception_call(
    node: ast.Call,
    state: _SqlBindingState,
) -> bool:
    return bool(
        isinstance(node.func, ast.Name)
        and not node.args
        and not node.keywords
        and node.func.id not in state.shadowed_keys
        and node.func.id in _PYTHON_BUILTIN_EXCEPTION_NAMES
        and node.func.id not in _PYTHON_REQUIRED_ARGUMENT_EXCEPTION_NAMES
    )


def _enqueue_sql_container(
    node: ast.Dict | ast.Set,
    state: _SqlBindingState,
    events: list[_SqlExpressionEvent],
    sink_nodes: frozenset[int],
) -> None:
    ordered: list[_SqlExpressionEvent] = []
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is not None:
                ordered.append(
                    _SqlExpressionEvent("visit", key, state, sink_nodes=sink_nodes)
                )
            ordered.append(
                _SqlExpressionEvent("visit", value, state, sink_nodes=sink_nodes)
            )
            ordered.append(_SqlExpressionEvent("raise", node, state))
    else:
        for element in node.elts:
            ordered.append(
                _SqlExpressionEvent("visit", element, state, sink_nodes=sink_nodes)
            )
            ordered.append(_SqlExpressionEvent("raise", node, state))
    events.extend(reversed(ordered))


def _enqueue_generic_sql_expression(
    node: ast.AST,
    state: _SqlBindingState,
    events: list[_SqlExpressionEvent],
    parents: dict[ast.AST, ast.AST],
    sink_nodes: frozenset[int],
) -> None:
    if _sql_expression_may_raise(node, state, parents):
        events.append(_SqlExpressionEvent("raise", node, state))
    events.extend(
        _SqlExpressionEvent("visit", child, state, sink_nodes=sink_nodes)
        for child in reversed(list(ast.iter_child_nodes(node)))
        if not isinstance(child, ast.expr_context)
    )


def _sql_expression_may_raise(
    node: ast.AST,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    read_state = _sql_read_state(node, state, parents)
    if isinstance(
        node,
        (
            ast.Await,
            ast.BinOp,
            ast.Compare,
            ast.JoinedStr,
            ast.Starred,
            ast.Subscript,
            ast.UnaryOp,
        ),
    ):
        return True
    if isinstance(node, ast.Attribute):
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            return False
        reference = _qualified_name(node)
        return reference is None or reference not in read_state.defined_keys
    return bool(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and not (
            node.id in _PYTHON_BUILTIN_NAMES and node.id not in read_state.shadowed_keys
        )
        and node.id not in read_state.defined_keys
    )


def _process_sql_bool_expression(
    node: ast.BoolOp,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
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
    exceptions: _SqlExceptions,
) -> None:
    """Model eager comprehension effects with explicit iteration flow.

    Comprehension iteration variables are local in Python 3, while walrus
    targets bind in the containing scope.  Single-generator comprehensions use
    the same mutable-phi loop model as statements so later iterations can feed
    earlier sinks. Multiple generator clauses use an iterative worklist (not
    Python recursion), retaining zero-element paths for unknown inputs.
    Generator expressions remain lazy and are not evaluated here.
    """

    outer = state.copy()
    local_keys = {
        key
        for generator in node.generators
        for key in _comprehension_local_keys(generator.target)
    }
    outcomes = (
        _process_single_generator_sql_comprehension(
            node, state.copy(), parents, lines, exceptions
        )
        if len(node.generators) == 1
        else _process_nested_sql_comprehension(
            node, state.copy(), parents, lines, exceptions
        )
    )
    merged = _merge_sql_binding_states(*outcomes)
    if merged is None:
        return
    for key in local_keys:
        _restore_sql_comprehension_local(merged, outer, key)
    state.replace_with(merged)


def _process_single_generator_sql_comprehension(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    entry: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> list[_SqlBindingState]:
    generator = node.generators[0]
    iterable_value = _evaluate_sql_assignment_value(
        generator.iter, entry, parents, lines, exceptions
    )
    cardinality = _literal_iterable_cardinality(generator.iter)
    _record_sql_iteration_exceptions(
        entry,
        exceptions,
        unknown=cardinality is None or bool(generator.is_async),
    )
    iterated_values = _literal_iterated_values(generator.iter, iterable_value)
    if (
        iterated_values is not None
        and len(iterated_values) <= _MAX_EXACT_SQL_ITERATIONS
        and not generator.is_async
    ):
        return _process_exact_single_generator_sql_comprehension(
            node,
            generator,
            iterated_values,
            entry,
            parents,
            lines,
            exceptions,
        )
    target_value = _iterated_sql_value(generator.iter, iterable_value, entry, parents)
    if cardinality == 0:
        return [entry]
    if cardinality == 1:
        return _process_sql_comprehension_iteration(
            node, generator, target_value, entry, parents, lines, exceptions
        )

    outcomes = [entry.copy()] if cardinality is None else []
    first = (
        [entry]
        if cardinality is None
        else _process_sql_comprehension_iteration(
            node, generator, target_value, entry, parents, lines, exceptions
        )
    )
    loop_entry = _merge_sql_binding_states(*first)
    assert loop_entry is not None
    header, phis = _sql_loop_header(
        loop_entry,
        _sql_comprehension_value_nodes(node, generator),
        extra_keys=_binding_target_keys(generator.target),
    )
    backedges = _process_sql_comprehension_iteration(
        node,
        generator,
        target_value,
        header.copy(),
        parents,
        lines,
        exceptions,
    )
    _complete_sql_loop_phis(phis, *backedges)
    outcomes.append(header)
    return outcomes


def _process_exact_single_generator_sql_comprehension(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    generator: ast.comprehension,
    values: tuple[_SqlValue, ...],
    entry: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> list[_SqlBindingState]:
    """Execute a bounded eager comprehension in literal iteration order."""

    active: _SqlBindingState | None = entry
    for value in values:
        if active is None:
            break
        passed, skipped = _process_sql_comprehension_filters(
            generator,
            value,
            active,
            parents,
            lines,
            exceptions,
        )
        completed = list(skipped)
        for candidate in passed:
            _process_sql_comprehension_value(
                node,
                candidate,
                parents,
                lines,
                exceptions,
            )
            completed.append(candidate)
        active = _merge_sql_binding_states(*completed)
    return [] if active is None else [active]


def _process_nested_sql_comprehension(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    initial: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> list[_SqlBindingState]:
    frames: list[_SqlComprehensionFrame] = []
    candidate = initial
    completions: list[_SqlBindingState] | None = None
    for index, generator in enumerate(node.generators):
        iterable_value = _evaluate_sql_assignment_value(
            generator.iter, candidate, parents, lines, exceptions
        )
        target_value = _iterated_sql_value(
            generator.iter, iterable_value, candidate, parents
        )
        cardinality = _literal_iterable_cardinality(generator.iter)
        _record_sql_iteration_exceptions(
            candidate,
            exceptions,
            unknown=cardinality is None or bool(generator.is_async),
        )
        if cardinality == 0:
            completions = [candidate]
            break
        header: _SqlBindingState | None = None
        phis: dict[str, _ProvRef] = {}
        iteration_entry = candidate
        if cardinality is None or cardinality > 1:
            header, phis = _sql_loop_header(
                candidate,
                _sql_nested_comprehension_loop_nodes(node, index),
                extra_keys=_binding_target_keys(generator.target),
            )
            iteration_entry = header.copy()
        passed, skipped = _process_sql_comprehension_filters(
            generator,
            target_value,
            iteration_entry,
            parents,
            lines,
            exceptions,
        )
        frames.append(_SqlComprehensionFrame(header, phis, skipped))
        if not passed:
            completions = []
            break
        candidate = passed[0]
    else:
        _process_sql_comprehension_value(node, candidate, parents, lines, exceptions)
        completions = [candidate]

    assert completions is not None
    for frame in reversed(frames):
        iteration_completions = [*frame.skipped, *completions]
        if frame.header is None:
            completions = iteration_completions
            continue
        _complete_sql_loop_phis(frame.phis, *iteration_completions)
        completions = [frame.header]
    return completions


def _sql_nested_comprehension_loop_nodes(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    index: int,
) -> list[ast.AST]:
    nodes: list[ast.AST] = [*node.generators[index].ifs]
    for generator in node.generators[index + 1 :]:
        nodes.extend((generator.iter, *generator.ifs))
    if isinstance(node, ast.DictComp):
        nodes.extend((node.key, node.value))
    else:
        nodes.append(node.elt)
    return nodes


def _process_sql_comprehension_iteration(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    generator: ast.comprehension,
    target_value: _SqlValue,
    entry: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> list[_SqlBindingState]:
    filtered, skipped = _process_sql_comprehension_filters(
        generator, target_value, entry, parents, lines, exceptions
    )
    completed = list(skipped)
    for candidate in filtered:
        _process_sql_comprehension_value(node, candidate, parents, lines, exceptions)
        completed.append(candidate)
    return completed


def _process_sql_comprehension_filters(
    generator: ast.comprehension,
    target_value: _SqlValue,
    entry: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> tuple[list[_SqlBindingState], list[_SqlBindingState]]:
    iteration = entry.copy()
    if not _apply_sql_assignment_targets(
        iteration,
        [generator.target],
        target_value,
        parents,
        lines,
        exceptions,
    ):
        return [], []
    skipped: list[_SqlBindingState] = []
    for condition in generator.ifs:
        _process_sql_expression(condition, iteration, parents, lines, exceptions)
        truth = _literal_truth(condition)
        if truth is not True:
            skipped.append(iteration.copy())
        if truth is False:
            return [], skipped
    return [iteration], skipped


def _process_sql_comprehension_value(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> None:
    if isinstance(node, ast.DictComp):
        _process_sql_expression(node.key, state, parents, lines, exceptions)
        _process_sql_expression(node.value, state, parents, lines, exceptions)
        exceptions.capture(state, base=True)
    else:
        _process_sql_expression(node.elt, state, parents, lines, exceptions)
        if isinstance(node, ast.SetComp):
            exceptions.capture(state, base=True)


def _sql_comprehension_value_nodes(
    node: ast.DictComp | ast.ListComp | ast.SetComp,
    generator: ast.comprehension,
) -> list[ast.AST]:
    values: list[ast.AST] = [*generator.ifs]
    if isinstance(node, ast.DictComp):
        values.extend((node.key, node.value))
    else:
        values.append(node.elt)
    return values


def _evaluate_sql_assignment_value(
    expression: ast.expr,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlValue:
    """Evaluate a value while snapshotting literal container members in order."""

    reference = _qualified_name(expression)
    read_state = _sql_read_state(expression, state, parents)
    if reference is not None and reference in read_state.binding_values:
        _process_sql_expression(expression, state, parents, lines, exceptions)
        return read_state.binding_values[reference]
    if isinstance(expression, (ast.List, ast.Tuple)):
        evaluated_values: list[_SqlValue] = []
        exact_values: list[_SqlValue] = []
        exact = True
        for element in expression.elts:
            if not isinstance(element, ast.Starred):
                value = _evaluate_sql_assignment_value(
                    element, state, parents, lines, exceptions
                )
                evaluated_values.append(value)
                exact_values.append(value)
                continue
            candidate = _evaluate_sql_assignment_value(
                element.value, state, parents, lines, exceptions
            )
            expanded = _ordered_starred_sql_values(candidate)
            if expanded is None:
                exact = False
                if candidate.iterated_origin is not None:
                    evaluated_values.append(_SqlValue(candidate.iterated_origin))
            else:
                evaluated_values.extend(expanded)
                exact_values.extend(expanded)
            exceptions.capture(state, base=True)
        evaluated = tuple(evaluated_values)
        elements = tuple(exact_values) if exact else None
        return _SqlValue(
            state.graph.union(element.origin for element in evaluated),
            elements,
            iterated_values=elements,
            iterated_origin=state.graph.union(element.origin for element in evaluated),
        )
    if isinstance(expression, (ast.DictComp, ast.ListComp, ast.SetComp)):
        projection_entry = state.copy()
        _process_sql_expression(expression, state, parents, lines, exceptions)
        projected = _project_singleton_sql_comprehension_value(
            expression,
            projection_entry,
            parents,
            lines,
        )
        if projected is not None:
            return projected
        return _SqlValue(_sql_origins_in_expression(expression, state, parents))
    if isinstance(expression, ast.Dict):
        entries: list[tuple[ast.expr | None, _SqlValue]] = []
        origins: list[_ProvRef | None] = []
        iterated_values: list[_SqlValue] = []
        for key, item in zip(expression.keys, expression.values, strict=True):
            if key is not None:
                key_value = _evaluate_sql_assignment_value(
                    key, state, parents, lines, exceptions
                )
                origins.append(key_value.origin)
                iterated_values.append(key_value)
            item_value = _evaluate_sql_assignment_value(
                item, state, parents, lines, exceptions
            )
            if key is None:
                iterated_values.extend(
                    item_value.iterated_values or (_SqlValue(item_value.origin),)
                )
            origins.append(item_value.origin)
            entries.append((key, item_value))
            # Hashing a key or applying ``**`` happens after that entry's
            # expressions have run, so a handler observes their side effects.
            exceptions.capture(state, base=True)
        return _SqlValue(
            state.graph.union(origins),
            mapping=tuple(entries),
            iterated_values=tuple(iterated_values),
            iterated_origin=state.graph.union(
                value.origin for value in iterated_values
            ),
        )
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "dict"
        and expression.func.id not in state.shadowed_keys
        and len(expression.args) <= 1
    ):
        _process_sql_expression(expression.func, state, parents, lines, exceptions)
        constructed_entries: list[tuple[ast.expr | None, _SqlValue]] = []
        if expression.args:
            argument = expression.args[0]
            positional = (
                _consume_exact_singleton_sql_generator(
                    argument, state, parents, lines, exceptions
                )
                if _is_exact_singleton_sql_generator(argument)
                else _evaluate_sql_assignment_value(
                    argument, state, parents, lines, exceptions
                )
            )
            pair_entries = _sql_pair_mapping_entries(argument, positional)
            if pair_entries is None:
                constructed_entries.append((None, positional))
            else:
                constructed_entries.extend(pair_entries)
        for keyword in expression.keywords:
            item_value = _evaluate_sql_assignment_value(
                keyword.value, state, parents, lines, exceptions
            )
            key = ast.Constant(value=keyword.arg) if keyword.arg is not None else None
            constructed_entries.append((key, item_value))
        exceptions.capture(state, base=True)
        constructed_iterated_values: list[_SqlValue] = []
        for constructed_key, constructed_item in constructed_entries:
            if constructed_key is None:
                constructed_iterated_values.extend(
                    constructed_item.iterated_values
                    or (_SqlValue(constructed_item.origin),)
                )
            else:
                constructed_iterated_values.append(_SqlValue(None))
        return _SqlValue(
            state.graph.union(
                constructed_value.origin for _, constructed_value in constructed_entries
            ),
            mapping=tuple(constructed_entries),
            iterated_values=tuple(constructed_iterated_values),
            iterated_origin=state.graph.union(
                value.origin for value in constructed_iterated_values
            ),
        )
    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id in {"list", "set", "tuple"}
        and expression.func.id not in state.shadowed_keys
        and len(expression.args) == 1
        and not expression.keywords
        and _is_exact_singleton_sql_generator(expression.args[0])
    ):
        _process_sql_expression(expression.func, state, parents, lines, exceptions)
        consumed = _consume_exact_singleton_sql_generator(
            expression.args[0], state, parents, lines, exceptions
        )
        exceptions.capture(state, base=True)
        return consumed
    if isinstance(expression, ast.Set):
        values: list[_SqlValue] = []
        for element in expression.elts:
            candidate = _evaluate_sql_assignment_value(
                element.value if isinstance(element, ast.Starred) else element,
                state,
                parents,
                lines,
                exceptions,
            )
            if isinstance(element, ast.Starred):
                expanded_values = _ordered_starred_sql_values(candidate)
                if expanded_values is not None:
                    values.extend(expanded_values)
                elif candidate.iterated_origin is not None:
                    values.append(_SqlValue(candidate.iterated_origin))
            else:
                values.append(candidate)
            exceptions.capture(state, base=True)
        set_expanded_nodes = _static_display_elements(expression)
        unique: list[_SqlValue] | None = [] if set_expanded_nodes is not None else None
        seen: set[object] = set()
        if unique is not None:
            try:
                for element, set_value in zip(
                    set_expanded_nodes or (), values, strict=True
                ):
                    literal = ast.literal_eval(element)
                    hash(literal)
                    if literal not in seen:
                        seen.add(literal)
                        unique.append(set_value)
            except (TypeError, ValueError):
                unique = None
        return _SqlValue(
            state.graph.union(value.origin for value in values),
            iterated_values=tuple(unique) if unique is not None else None,
            iterated_origin=state.graph.union(value.origin for value in values),
        )
    _process_sql_expression(expression, state, parents, lines, exceptions)
    return _SqlValue(_sql_origins_in_expression(expression, state, parents))


def _ordered_starred_sql_values(value: _SqlValue) -> tuple[_SqlValue, ...] | None:
    """Return item snapshots only when their iteration order is trustworthy."""

    values = value.iterated_values
    if values is None:
        values = value.elements
    if values is None:
        return None
    if value.elements is not None or value.mapping is not None or len(values) <= 1:
        return values
    # A multi-element set snapshot has no stable iteration order.
    return None


def _is_exact_singleton_sql_generator(expression: ast.expr) -> bool:
    if not isinstance(expression, ast.GeneratorExp):
        return False
    return all(
        not generator.is_async
        and _literal_iterable_cardinality(generator.iter) == 1
        and all(_literal_truth(condition) is True for condition in generator.ifs)
        for generator in expression.generators
    )


def _consume_exact_singleton_sql_generator(
    expression: ast.expr,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> _SqlValue:
    """Exhaust a proven-singleton generator at a synchronous consumer."""

    assert isinstance(expression, ast.GeneratorExp)
    outer = state.copy()
    local_keys = {
        key
        for generator in expression.generators
        for key in _comprehension_local_keys(generator.target)
    }
    result: _SqlValue | None = None
    try:
        for generator in expression.generators:
            iterable = _evaluate_sql_assignment_value(
                generator.iter, state, parents, lines, exceptions
            )
            values = _literal_iterated_values(generator.iter, iterable)
            target_value = (
                values[0]
                if values is not None and len(values) == 1
                else _iterated_sql_value(generator.iter, iterable, state, parents)
            )
            if not _apply_sql_assignment_targets(
                state,
                [generator.target],
                target_value,
                parents,
                lines,
                exceptions,
            ):
                return _SqlValue(None)
            for condition in generator.ifs:
                _process_sql_expression(condition, state, parents, lines, exceptions)
        result = _evaluate_sql_assignment_value(
            expression.elt, state, parents, lines, exceptions
        )
    finally:
        for key in local_keys:
            _restore_sql_comprehension_local(state, outer, key)
    if result is None:
        return _SqlValue(None)
    return _SqlValue(
        result.origin,
        elements=(result,),
        iterated_values=(result,),
        iterated_origin=result.origin,
    )


def _sql_pair_mapping_entries(
    expression: ast.expr,
    value: _SqlValue,
) -> list[tuple[ast.expr | None, _SqlValue]] | None:
    pair_expressions = (
        (expression.elt,)
        if isinstance(expression, ast.GeneratorExp)
        else _static_display_elements(expression)
    )
    pair_values = value.iterated_values
    if (
        pair_expressions is None
        or pair_values is None
        or len(pair_expressions) != len(pair_values)
    ):
        return None
    entries: list[tuple[ast.expr | None, _SqlValue]] = []
    for pair_expression, pair_value in zip(pair_expressions, pair_values, strict=True):
        components = _static_display_elements(pair_expression)
        if (
            components is None
            or len(components) != 2
            or pair_value.elements is None
            or len(pair_value.elements) != 2
        ):
            return None
        entries.append((components[0], pair_value.elements[1]))
    return entries


def _project_singleton_sql_comprehension_value(
    expression: ast.DictComp | ast.ListComp | ast.SetComp,
    entry: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
) -> _SqlValue | None:
    """Project the result of a bounded, replay-safe eager comprehension.

    The real comprehension has already been evaluated against the live state.
    This bounded copy only recovers its returned value shape.  Unknown filters,
    async clauses, side-effectful replay, and large products remain opaque.
    """

    ignored_exceptions = _SqlExceptions.empty(enabled=False)
    candidates = [entry]
    for generator in expression.generators:
        if generator.is_async or not _sql_comprehension_projection_is_replay_safe(
            generator.iter
        ):
            return None
        truths = tuple(_literal_truth(condition) for condition in generator.ifs)
        if any(truth is None for truth in truths) or any(
            not _sql_comprehension_projection_is_replay_safe(condition)
            for condition in generator.ifs
        ):
            return None
        expanded: list[_SqlBindingState] = []
        for candidate in candidates:
            iterable = _evaluate_sql_assignment_value(
                generator.iter,
                candidate,
                parents,
                lines,
                ignored_exceptions,
            )
            values = _literal_iterated_values(generator.iter, iterable)
            if values is None:
                return None
            for value in values:
                iteration = candidate.copy()
                if not _apply_sql_assignment_targets(
                    iteration,
                    [generator.target],
                    value,
                    parents,
                    lines,
                    ignored_exceptions,
                ):
                    return None
                if all(truth is True for truth in truths):
                    expanded.append(iteration)
                if len(expanded) > _MAX_EXACT_SQL_ITERATIONS:
                    return None
        candidates = expanded
    value_nodes = (
        (expression.key, expression.value)
        if isinstance(expression, ast.DictComp)
        else (expression.elt,)
    )
    if any(
        not _sql_comprehension_projection_is_replay_safe(node) for node in value_nodes
    ):
        return None
    if isinstance(expression, ast.DictComp):
        entries: list[tuple[ast.expr | None, _SqlValue]] = []
        keys: list[_SqlValue] = []
        origins: list[_ProvRef | None] = []
        for candidate in candidates:
            key = _evaluate_sql_assignment_value(
                expression.key,
                candidate,
                parents,
                lines,
                ignored_exceptions,
            )
            value = _evaluate_sql_assignment_value(
                expression.value,
                candidate,
                parents,
                lines,
                ignored_exceptions,
            )
            entries.append((expression.key, value))
            keys.append(key)
            origins.extend((key.origin, value.origin))
        return _SqlValue(
            entry.graph.union(origins),
            mapping=tuple(entries),
            iterated_values=tuple(keys) if len(keys) <= 1 else None,
            iterated_origin=entry.graph.union(key.origin for key in keys),
        )
    results = tuple(
        _evaluate_sql_assignment_value(
            expression.elt,
            candidate,
            parents,
            lines,
            ignored_exceptions,
        )
        for candidate in candidates
    )
    ordered = not isinstance(expression, ast.SetComp) or len(results) <= 1
    return _SqlValue(
        entry.graph.union(result.origin for result in results),
        elements=results if ordered else None,
        iterated_values=results if ordered else None,
        iterated_origin=entry.graph.union(result.origin for result in results),
    )


def _sql_comprehension_projection_is_replay_safe(expression: ast.AST) -> bool:
    """Keep the value-shape replay free of modeled state mutations or calls."""

    return not any(
        isinstance(
            node,
            (
                ast.Await,
                ast.Call,
                ast.NamedExpr,
                ast.Yield,
                ast.YieldFrom,
            ),
        )
        for node in ast.walk(expression)
    )


def _apply_sql_assignment_targets(
    state: _SqlBindingState,
    targets: list[ast.expr],
    value: _SqlValue,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> bool:
    """Evaluate and bind assignment targets in Python's left-to-right order.

    The right-hand value has already been evaluated.  Capture its provenance
    before a subscript/attribute target can mutate bindings through a walrus,
    then evaluate each target and commit that target before moving to the next
    one.  This preserves both chained-assignment order and the state visible
    when a later target operation raises.
    """

    for assignment_target in targets:
        unpack_succeeds = _literal_unpack_succeeds(assignment_target, value)
        if unpack_succeeds is False:
            exceptions.capture(state)
            return False
        if unpack_succeeds is None and isinstance(
            assignment_target, (ast.List, ast.Tuple)
        ):
            exceptions.capture(state, base=True)
        plans = _sql_assignment_plan(assignment_target, value, state)
        for target, target_value in plans:
            _process_sql_store_target(target, state, parents, lines, exceptions)
            _set_sql_binding_value(state, target, target_value)
    return True


def _literal_unpack_succeeds(
    target: ast.expr,
    value: _SqlValue,
) -> bool | None:
    result: bool | None = True
    pending = [(target, value)]
    while pending:
        current_target, current_value = pending.pop()
        if isinstance(current_target, ast.Starred) or not isinstance(
            current_target, (ast.List, ast.Tuple)
        ):
            continue
        if current_value.elements is None:
            result = None
            continue
        elements = current_value.elements
        starred = [
            index
            for index, element in enumerate(current_target.elts)
            if isinstance(element, ast.Starred)
        ]
        if len(starred) > 1:
            return False
        if not starred:
            if len(current_target.elts) != len(elements):
                return False
            pending.extend(zip(current_target.elts, elements, strict=True))
            continue
        if len(elements) < len(current_target.elts) - 1:
            return False
        star_index = starred[0]
        trailing = len(current_target.elts) - star_index - 1
        pending.extend(
            zip(
                current_target.elts[:star_index],
                elements[:star_index],
                strict=True,
            )
        )
        if trailing:
            pending.extend(
                zip(
                    current_target.elts[-trailing:],
                    elements[-trailing:],
                    strict=True,
                )
            )
    return result


def _process_sql_store_target(
    target: ast.expr,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
    lines: set[int],
    exceptions: _SqlExceptions,
) -> None:
    if isinstance(target, ast.Starred):
        _process_sql_store_target(target.value, state, parents, lines, exceptions)
        return
    if isinstance(target, (ast.List, ast.Tuple)):
        for element in target.elts:
            _process_sql_store_target(element, state, parents, lines, exceptions)
        return
    if isinstance(target, ast.Attribute):
        _process_sql_expression(target.value, state, parents, lines, exceptions)
        exceptions.capture(state, base=True)
        return
    if isinstance(target, ast.Subscript):
        _process_sql_expression(target.value, state, parents, lines, exceptions)
        _process_sql_expression(target.slice, state, parents, lines, exceptions)
        exceptions.capture(state, base=True)


def _sql_assignment_plan(
    target: ast.expr,
    value: _SqlValue,
    state: _SqlBindingState,
) -> list[tuple[ast.expr, _SqlValue]]:
    if isinstance(target, ast.Starred):
        return _sql_assignment_plan(target.value, value, state)
    if isinstance(target, (ast.Tuple, ast.List)) and value.elements is not None:
        elements = list(value.elements)
        starred = [
            index
            for index, element in enumerate(target.elts)
            if isinstance(element, ast.Starred)
        ]
        if not starred and len(target.elts) == len(elements):
            return [
                binding
                for child_target, child_value in zip(target.elts, elements, strict=True)
                for binding in _sql_assignment_plan(child_target, child_value, state)
            ]
        if len(starred) == 1 and len(elements) >= len(target.elts) - 1:
            star_index = starred[0]
            trailing = len(target.elts) - star_index - 1
            plans: list[tuple[ast.expr, _SqlValue]] = []
            for child_target, child_value in zip(
                target.elts[:star_index],
                elements[:star_index],
                strict=True,
            ):
                plans.extend(_sql_assignment_plan(child_target, child_value, state))
            star_target = target.elts[star_index]
            assert isinstance(star_target, ast.Starred)
            middle_end = len(elements) - trailing if trailing else len(elements)
            star_origin = state.graph.union(
                element.origin for element in elements[star_index:middle_end]
            )
            plans.append(
                (
                    star_target.value,
                    _SqlValue(
                        star_origin,
                        elements=tuple(elements[star_index:middle_end]),
                    ),
                )
            )
            if trailing:
                for child_target, child_value in zip(
                    target.elts[-trailing:],
                    elements[-trailing:],
                    strict=True,
                ):
                    plans.extend(_sql_assignment_plan(child_target, child_value, state))
            return plans

    return [(target, value)]


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
            _assign_sql_binding_target(state, child_target, child_value, parents)
        return
    origin = (
        _sql_origins_in_expression(value, state, parents) if value is not None else None
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
            bound = _sql_read_state(candidate, state, parents).get(reference)
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
        elif isinstance(candidate, ast.Starred):
            pending.append(candidate.value)
        elif isinstance(candidate, ast.Call) and _is_transparent_string_call(candidate):
            assert isinstance(candidate.func, ast.Attribute)
            pending.append(candidate.func.value)
        elif isinstance(candidate, ast.JoinedStr):
            pending.extend(reversed(_transparent_joined_string_values(candidate)))
        elif isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.Add):
            pending.extend((candidate.right, candidate.left))
        elif isinstance(candidate, (ast.Tuple, ast.List, ast.Set)):
            pending.extend(reversed(candidate.elts))
    return state.graph.union(references)


def _sql_read_state(
    node: ast.AST,
    state: _SqlBindingState,
    parents: dict[ast.AST, ast.AST],
) -> _SqlBindingState:
    outer = state.class_comprehension_outer
    if outer is None:
        return state
    child = node
    current = parents.get(node)
    while current is not None:
        if isinstance(
            current,
            (ast.DictComp, ast.GeneratorExp, ast.ListComp, ast.SetComp),
        ):
            return state if child is current.generators[0].iter else outer
        if isinstance(
            current,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
        ):
            break
        child = current
        current = parents.get(current)
    return state


def _transparent_joined_string_values(node: ast.JoinedStr) -> tuple[ast.expr, ...]:
    """Return values only when an f-string adds no semantic text.

    ``f"{query}"`` and whitespace-only variants preserve the SQL value. A
    non-whitespace literal prefix/suffix changes the statement and therefore
    remains outside this narrow provenance rule.
    """

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
    if isinstance(target, ast.Starred):
        return _binding_target_keys(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return {key for element in target.elts for key in _binding_target_keys(element)}
    return set()


def _comprehension_local_keys(target: ast.AST) -> set[str]:
    """Return only lexical names isolated by a Python 3 comprehension scope."""

    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Starred):
        return _comprehension_local_keys(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return {
            key for element in target.elts for key in _comprehension_local_keys(element)
        }
    return set()


def _restore_sql_comprehension_local(
    state: _SqlBindingState,
    outer: _SqlBindingState,
    key: str,
) -> None:
    """Restore a lexical target while retaining qualified mutation effects."""

    state.discard_reference(key)
    state.undefine_key(key)
    if key in outer:
        state.set_reference(key, outer[key], definitely_defined=False)
    if key in outer.defined_keys:
        state.define_key(key)
    elif key in outer.possible_defined_keys:
        state.possibly_define_key(key)
    if key in outer.shadowed_keys:
        state.shadowed_keys.add(key)
    else:
        state.shadowed_keys.discard(key)
    if key in outer.binding_values:
        state.binding_values[key] = outer.binding_values[key]

    prefix = f"{key}."
    for descendant, origin in outer.items():
        if descendant.startswith(prefix) and descendant not in state:
            state.set_reference(descendant, origin, definitely_defined=False)
    for descendant in outer.defined_keys:
        if descendant.startswith(prefix) and descendant not in state.defined_keys:
            state.define_key(descendant)
    for descendant in outer.possible_defined_keys:
        if (
            descendant.startswith(prefix)
            and descendant not in state.possible_defined_keys
        ):
            state.possibly_define_key(descendant)
    for descendant, value in outer.binding_values.items():
        if descendant.startswith(prefix) and descendant not in state.binding_values:
            state.binding_values[descendant] = value


def _set_sql_binding_targets(
    state: _SqlBindingState,
    targets: list[ast.expr],
    origin: _ProvRef | None,
) -> None:
    for target in targets:
        for key in _binding_target_keys(target):
            _set_sql_binding_key(state, key, origin)


def _set_sql_binding_value(
    state: _SqlBindingState,
    target: ast.expr,
    value: _SqlValue,
) -> None:
    for key in _binding_target_keys(target):
        _set_sql_binding_key(state, key, value.origin)
        state.binding_values[key] = value


def _set_sql_binding_key(
    state: _SqlBindingState,
    key: str,
    origin: _ProvRef | None,
) -> None:
    _kill_sql_binding_key(state, key)
    if origin is not None:
        state.set_reference(key, origin)


def _kill_sql_binding_key(state: _SqlBindingState, key: str) -> None:
    state.binding_values.pop(key, None)
    for candidate in list(state.possible_defined_descendants.get(key, ())):
        state.binding_values.pop(candidate, None)
    state.discard_reference(key)
    for candidate in list(state.reference_descendants.get(key, ())):
        state.discard_reference(candidate)
    removed_definitions = list(state.defined_descendants.get(key, ()))
    for candidate in removed_definitions:
        state.undefine_key(candidate)
    removed_possible = list(state.possible_defined_descendants.get(key, ()))
    for candidate in removed_possible:
        state.undefine_key(candidate)
    state.undefine_key(key)
    state.define_key(key)


def _undefine_sql_binding_key(state: _SqlBindingState, key: str) -> None:
    state.binding_values.pop(key, None)
    for candidate in list(state.possible_defined_descendants.get(key, ())):
        state.binding_values.pop(candidate, None)
    state.discard_reference(key)
    for candidate in list(state.reference_descendants.get(key, ())):
        state.discard_reference(candidate)
    removed_definitions = list(state.defined_descendants.get(key, ()))
    for candidate in removed_definitions:
        state.undefine_key(candidate)
    removed_possible = list(state.possible_defined_descendants.get(key, ()))
    for candidate in removed_possible:
        state.undefine_key(candidate)
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
        state.get(key) for target in targets for key in _binding_target_keys(target)
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
        sum(
            len(state)
            + len(state.defined_keys)
            + len(state.possible_defined_keys)
            + len(state.shadowed_keys)
            + len(state.binding_values)
            for state in active
        )
        + 1
    )
    merged = _SqlBindingState(
        graph,
        defined_keys=set.intersection(*(set(state.defined_keys) for state in active)),
        possible_defined_keys={
            key for state in active for key in state.possible_defined_keys
        },
        shadowed_keys={key for state in active for key in state.shadowed_keys},
        active_exception_channels={
            channel for state in active for channel in state.active_exception_channels
        },
    )
    merged.class_comprehension_outer = active[0].class_comprehension_outer
    for key in {key for state in active for key in state}:
        reference = graph.union(state.get(key) for state in active)
        if reference is not None:
            merged.set_reference(key, reference, definitely_defined=False)
    common_values = set.intersection(*(set(state.binding_values) for state in active))
    for key in common_values:
        value = active[0].binding_values[key]
        if all(state.binding_values[key] == value for state in active[1:]):
            merged.binding_values[key] = value
    return merged


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
                if statement.function_name and statement.function_name.isidentifier()
                else "__recovered__"
            )
            wrapped = (
                f"async def {wrapper_name}():\n{textwrap.indent(source, '    ')}\n"
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
                lines.update(
                    _direct_python_interpolated_sql_lines(
                        tree,
                        parents,
                        analysis_budget,
                    )
                )
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
        token for token in statement.tokens if token.type not in _NON_CODE_TOKEN_TYPES
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
    significant = [token for token in tokens if token.type not in _NON_CODE_TOKEN_TYPES]
    names = [
        token.string.casefold() for token in significant if token.type == tokenize.NAME
    ]
    first_name = (
        names[1]
        if len(names) > 1 and names[0] == "async"
        else names[0]
        if names
        else None
    )
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
            if pending_scope is not None and token.type not in {
                tokenize.COMMENT,
                tokenize.NL,
                tokenize.NEWLINE,
            }:
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
    significant = [token for token in tokens if token.type not in _NON_CODE_TOKEN_TYPES]
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
        token for token in statement.tokens if token.type not in _NON_CODE_TOKEN_TYPES
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
    while start < end and tokens[start].string == "(" and mates.get(start) == end - 1:
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
    except (MemoryError, SyntaxError, RecursionError, ValueError):
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
    except (MemoryError, SyntaxError, RecursionError, ValueError):
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
    opening_for_closing = {
        closing: opening for opening, closing in closing_for_opening.items()
    }
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
                has_timeout=_python_httpx_call_has_timeout(
                    node,
                    analysis.budget,
                ),
            )
        )

    return sorted(calls, key=lambda call: (call.line_start, call.line_end))


def _python_httpx_call_has_timeout(
    call: ast.Call,
    budget: _PythonAnalysisBudget,
) -> bool:
    """Recognize exact timeout keys without resolving arbitrary mappings."""

    literal_mappings: list[ast.Dict] = []
    for keyword in call.keywords:
        budget.consume_work()
        if keyword.arg == "timeout":
            return True
        if keyword.arg is None and isinstance(keyword.value, ast.Dict):
            literal_mappings.append(keyword.value)

    while literal_mappings:
        budget.consume_work()
        mapping = literal_mappings.pop()
        for key, value in zip(mapping.keys, mapping.values, strict=True):
            budget.consume_work()
            if key is None:
                if isinstance(value, ast.Dict):
                    literal_mappings.append(value)
                continue
            if (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and key.value == "timeout"
            ):
                return True
    return False


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
            budget=analysis_budget,
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
    budget: _PythonAnalysisBudget,
) -> PythonHttpxCall | None:
    opening_for_closing = {")": "(", "]": "[", "}": "{"}
    opening_tokens = frozenset(opening_for_closing.values())
    stack: list[str] = []
    has_timeout = False
    has_keyword_unpack = False
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
                recovered_timeout = (
                    _balanced_httpx_timeout(
                        tokens,
                        function_index=function_index,
                        close_paren_index=index,
                        budget=budget,
                    )
                    if has_keyword_unpack and not has_timeout
                    else False
                )
                return PythonHttpxCall(
                    function_name=function_name,
                    line_start=tokens[function_index - 2].start[0],
                    line_end=token.end[0],
                    has_timeout=has_timeout or recovered_timeout,
                )
            continue
        if len(stack) == 1 and token.type == tokenize.OP and token.string == "**":
            has_keyword_unpack = True
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


def _balanced_httpx_timeout(
    tokens: list[tokenize.TokenInfo],
    *,
    function_index: int,
    close_paren_index: int,
    budget: _PythonAnalysisBudget,
) -> bool:
    """Parse one bounded, balanced call recovered from a malformed module."""

    call_tokens = tokens[function_index - 2 : close_paren_index + 1]
    budget.consume_work(len(call_tokens))
    try:
        expression = tokenize.untokenize(
            (token.type, token.string) for token in call_tokens
        )
        recovered = ast.parse(expression, mode="eval").body
    except (SyntaxError, ValueError):
        return False
    except (MemoryError, RecursionError) as exc:
        raise DeterministicAnalysisBudgetExceeded(
            path=budget.path,
            budget_kind="python_analysis_resources",
            limit=0,
            observed_at_least=1,
        ) from exc
    if not isinstance(recovered, ast.Call):
        return False

    pending: list[ast.AST] = [recovered]
    while pending:
        budget.consume_work()
        current = pending.pop()
        pending.extend(ast.iter_child_nodes(current))
    return _python_httpx_call_has_timeout(recovered, budget)
