from __future__ import annotations

import pytest

from omargate.analyze.deterministic import eng_quality_helpers
from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner
from omargate.constants import Limits
from omargate.errors import DeterministicAnalysisBudgetExceeded


def test_frontend_rules_only_apply_to_react_projects() -> None:
    files = {
        "src/App.tsx": (
            "export const App = () => {\n"
            "  items.forEach(item => { setCount(item.count); });\n"
            "  return <div />;\n"
            "};\n"
        ),
    }

    react = EngQualityScanner(tech_stack=["React", "TypeScript"])
    react_findings = react.scan(files)
    assert any(f.pattern_id == "EQ-001" for f in react_findings)

    python = EngQualityScanner(tech_stack=["Python"])
    python_findings = python.scan(files)
    assert not any(f.pattern_id == "EQ-001" for f in python_findings)


def test_eval_detected_as_p0() -> None:
    files = {"src/server.js": "const out = eval(userInput);\n"}
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-008"), None)
    assert finding is not None
    assert finding.severity == "P0"


def test_eval_string_literal_not_flagged_in_python() -> None:
    files = {
        "src/rules.py": (
            "RULE = 'Use of eval() or Function() constructor can enable arbitrary code execution.'\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-008" for f in findings)


def test_eval_call_detected_in_python() -> None:
    files = {"src/app.py": "def run(user_input):\n    return eval(user_input)\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-008" for f in findings)


def test_python_fstring_sql_interpolation_detected_as_p0() -> None:
    files = {
        "src/query.py": (
            "def load(user_id):\n"
            '    return f"SELECT email FROM users WHERE id = {user_id}"\n'
        ),
        "src/lowercase.py": (
            'payload = f"select * from users where id = {user_id}"\n'
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    sql_findings = [finding for finding in findings if finding.pattern_id == "EQ-009"]
    assert {finding.file_path for finding in sql_findings} == {
        "src/lowercase.py",
        "src/query.py",
    }
    assert all(finding.severity == "P0" for finding in sql_findings)
    assert next(
        finding for finding in sql_findings if finding.file_path == "src/query.py"
    ).line_start == 2


def test_python_sql_string_concatenation_detected_as_p0() -> None:
    files = {"src/query.py": 'query = "DELETE FROM users WHERE id = " + user_id\n'}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-009" and f.severity == "P0" for f in findings)


def test_javascript_sql_interpolation_detected_without_prose_false_positives() -> None:
    files = {
        "src/template.js": (
            "const query = `SELECT email FROM users WHERE id = ${userId}`;\n"
        ),
        "src/lowercase.ts": (
            "const query = `select email from users where id = ${userId}`;\n"
        ),
        "src/concat.js": (
            'const query = "DELETE FROM users WHERE id = " + userId;\n'
        ),
        "src/update-prose.js": (
            'const message = "Refusing to update DNS for " + hostname;\n'
        ),
        "src/select-prose.js": (
            'const message = "Please select a server for " + region;\n'
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])

    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-009"
    ]

    assert [finding.file_path for finding in findings] == [
        "src/concat.js",
        "src/lowercase.ts",
        "src/template.js",
    ]
    assert all(finding.severity == "P0" for finding in findings)


def test_python_sql_interpolation_preserves_supported_statement_variants() -> None:
    cases = {
        "select_expression": 'query = f"SELECT {user_expression}"\n',
        "select_alias": 'query = f"SELECT {value} AS result"\n',
        "select_arithmetic": 'query = f"SELECT 1 + {value}"\n',
        "select_case": (
            'query = f"SELECT CASE WHEN {condition} THEN 1 ELSE 0 END"\n'
        ),
        "select_function": 'payload = f"select pg_sleep({delay})"\n',
        "leading_comment": (
            'query = f"/* audit */ SELECT * FROM users WHERE id = {user_id}"\n'
        ),
        "sqlite_insert": (
            'query = f"INSERT OR IGNORE INTO users(id) VALUES ({user_id})"\n'
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    for name, source in cases.items():
        findings = scanner.scan({f"src/{name}.py": source})
        assert any(finding.pattern_id == "EQ-009" for finding in findings), name


def test_bare_dynamic_select_requires_query_context() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])

    query_findings = scanner.scan(
        {"src/query.py": 'query = f"SELECT {user_expression}"\n'}
    )
    prose_findings = scanner.scan(
        {"src/message.py": 'message = f"select {option}"\n'}
    )

    assert any(finding.pattern_id == "EQ-009" for finding in query_findings)
    assert not any(finding.pattern_id == "EQ-009" for finding in prose_findings)


def test_dynamic_select_tracks_direct_sink_without_broad_ancestry() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/executed.py": (
            'payload = f"SELECT {value} AS result"\n'
            "cursor.execute(payload)\n"
        ),
        "src/container.py": (
            'query = {"message": f"select {option}"}\n'
            "def build_query():\n"
            '    message = f"select {option}"\n'
        ),
    }

    findings = scanner.scan(files)
    sql_findings = [finding for finding in findings if finding.pattern_id == "EQ-009"]

    assert [(finding.file_path, finding.line_start) for finding in sql_findings] == [
        ("src/executed.py", 1)
    ]


def test_python_sql_concatenation_handles_large_expression_iteratively() -> None:
    source = (
        'query = "SELECT * FROM users WHERE id = " + '
        + " + ".join("user_id" for _ in range(999))
        + "\n"
    )
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan({"src/large_query.py": source})
    assert sum(finding.pattern_id == "EQ-009" for finding in findings) == 1


def test_python_sql_concatenation_cannot_crash_gate_at_5000_operands() -> None:
    source = (
        'query = "SELECT * FROM users WHERE id = " + '
        + " + ".join("user_id" for _ in range(5000))
        + "\n"
    )
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan({"src/stress_query.py": source})
    assert sum(finding.pattern_id == "EQ-009" for finding in findings) == 1


def test_javascript_sql_matching_is_anchored_and_supports_templates() -> None:
    files = {
        "src/query.js": (
            "const query = `SELECT email FROM users WHERE id = "
            "${userId}`;\n"
        ),
        "src/dns.js": (
            'const message = "Refusing to update ambiguous DNS records for " '
            "+ hostname;\n"
        ),
        "src/ui.js": 'const message = "Please select a server for " + user;\n',
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = [f for f in scanner.scan(files) if f.pattern_id == "EQ-009"]
    assert [(finding.file_path, finding.line_start) for finding in findings] == [
        ("src/query.js", 1)
    ]


def test_dns_update_error_fstring_is_not_misclassified_as_sql() -> None:
    files = {
        "scripts/cloudflare/check_dashboard_dns_origin.py": (
            "raise DashboardDnsOriginError(\n"
            '    f"Refusing to update ambiguous DNS records for {hostname}; "\n'
            '    "clean them up explicitly."\n'
            ")\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-009" for f in findings)


def test_unparseable_python_uses_sql_anchored_fallback() -> None:
    files = {
        "src/broken.py": (
            'query = f"UPDATE users SET name = {name} WHERE id = {user_id}"\n'
            "this is invalid python\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-009" and f.line_start == 1 for f in findings)


def test_unparseable_python_fallback_handles_dynamic_select_variants() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/query.py": (
            'query = f"SELECT {user_expression}"\n'
            'payload = f"select pg_sleep({delay})"\n'
            'message = f"select {option}"\n'
            'sql = "SELECT " + user_expression\n'
            "this is invalid python\n"
        )
    }

    findings = scanner.scan(files)
    sql_lines = {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    }

    assert sql_lines == {1, 2, 4}


def test_unparseable_python_recovers_call_return_and_dataflow_context() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/broken.py": (
            'cursor.execute(f"SELECT 1 + {value}")\n'
            'payload = f"SELECT {other_value} AS result"\n'
            "cursor.execute(payload)\n"
            "def build_query():\n"
            '    return f"SELECT {final_value}"\n'
            "this is invalid python\n"
        )
    }

    findings = scanner.scan(files)
    sql_lines = {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    }

    assert sql_lines == {1, 2, 5}


def test_unparseable_python_recovers_multiline_logical_statements_only() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    source = (
        "# query = f\"SELECT * FROM users WHERE id = {commented}\"\n"
        'documentation = """\n'
        'query = f"SELECT * FROM users WHERE id = {example}"\n'
        '"""\n'
        "cursor.execute(\n"
        '    f"SELECT {direct_value}"\n'
        ")\n"
        "query = (\n"
        '    f"SELECT {assigned_value}"\n'
        ")\n"
        "def build_query():\n"
        "    return (\n"
        '        f"SELECT {returned_value}"\n'
        "    )\n"
        "this is invalid python\n"
    )

    findings = scanner.scan({"src/broken_multiline.py": source})
    sql_lines = {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    }

    assert sql_lines == {6, 9, 13}


def test_unparseable_python_recovers_one_line_query_function() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    source = (
        'def build_query(): return f"SELECT {value}"\n'
        "this is invalid python\n"
    )
    findings = scanner.scan({"src/broken_one_line.py": source})
    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_unparseable_python_preserves_function_scope_across_nested_dedent() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    source = (
        "def build_query():\n"
        "    if flag:\n"
        "        pass\n"
        '    return f"SELECT {value}"\n'
        "this is invalid python\n"
    )

    findings = scanner.scan({"src/broken_nested_scope.py": source})

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 4
        for finding in findings
    )


def test_dynamic_select_does_not_infer_flow_from_later_execute() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    source = (
        'payload = f"select {option}"\n'
        "render(payload)\n"
        'payload = "SELECT 1"\n'
        "cursor.execute(payload)\n"
        'cursor.execute("SELECT ?", message)\n'
    )
    findings = scanner.scan({"src/safe_flow.py": source})
    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_dynamic_select_uses_ordered_local_def_use_with_kills() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/direct.py": (
            'payload = f"SELECT {column}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/keyword.py": (
            "def run():\n"
            '    payload = f"SELECT {column}"\n'
            "    cursor.execute(statement=payload)\n"
        ),
        "src/killed.py": (
            'payload = f"SELECT {column}"\n'
            'payload = "SELECT 1"\n'
            "cursor.execute(payload)\n"
        ),
        "src/late.py": (
            "cursor.execute(payload)\n"
            'payload = f"SELECT {column}"\n'
        ),
    }

    findings = scanner.scan(files)
    locations = {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    }

    assert locations == {("src/direct.py", 1), ("src/keyword.py", 2)}


def test_dynamic_select_flow_respects_branches_and_termination() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/siblings.py": (
            "if flag:\n"
            '    payload = f"SELECT {column}"\n'
            "else:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/returned.py": (
            "def run():\n"
            '    payload = f"SELECT {column}"\n'
            "    return\n"
            "    cursor.execute(payload)\n"
        ),
        "src/branch_return.py": (
            "def run(flag):\n"
            "    if flag:\n"
            '        payload = f"SELECT {column}"\n'
            "        return\n"
            "    cursor.execute(payload)\n"
        ),
    }

    findings = scanner.scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_dynamic_select_only_propagates_through_value_preserving_wrappers() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/positive.py": (
            'payload = f"SELECT {column}"\n'
            "cursor.execute(payload.strip())\n"
            'cursor.execute(f"SELECT {other}".strip())\n'
            'cursor.execute(f"SELECT {third}" if flag else "SELECT 1")\n'
            'cursor.execute(bound := f"SELECT {fourth}")\n'
        ),
        "src/negative.py": (
            'payload = f"SELECT {column}"\n'
            "cursor.execute(sanitize(payload))\n"
            'cursor.execute(not f"SELECT {other}")\n'
            'cursor.execute(f"SELECT {third}" and "SELECT 1")\n'
            'cursor.execute("SELECT ?", payload)\n'
            'cursor.execute(f"SELECT {fourth}".imag)\n'
        ),
    }

    findings = scanner.scan(files)
    locations = {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    }

    assert locations == {
        ("src/positive.py", 1),
        ("src/positive.py", 3),
        ("src/positive.py", 4),
        ("src/positive.py", 5),
    }


def test_dynamic_select_walrus_paths_merge_without_order_bias() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/left.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            '(payload := source) if flag else (payload := "safe")\n'
            "cursor.execute(payload)\n"
        ),
        "src/right.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            '(payload := "safe") if flag else (payload := source)\n'
            "cursor.execute(payload)\n"
        ),
        "src/short_circuit.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "False and (payload := source)\n"
            "True or (payload := source)\n"
            "[(payload := source) for _ in []]\n"
            "cursor.execute(payload)\n"
        ),
    }

    findings = scanner.scan(files)
    locations = {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    }

    assert locations == {("src/left.py", 1), ("src/right.py", 1)}


def test_dynamic_select_flow_handles_deep_addition_iteratively() -> None:
    expression = " + ".join(["payload", *(['\"\"'] * 1200)])
    source = f'payload = f"SELECT {{column}}"\ncursor.execute({expression})\n'

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/deep.py": source}
    )

    assert sum(finding.pattern_id == "EQ-009" for finding in findings) == 1


def test_percent_and_format_sql_interpolation_remain_detected() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    cases = {
        "percent.py": '"SELECT * FROM users WHERE id = %s" % user_id\n',
        "format.py": '"SELECT * FROM users WHERE id = {}".format(user_id)\n',
        "format_map.py": (
            '"SELECT * FROM users WHERE id = {user_id}".format_map(values)\n'
        ),
    }
    findings = scanner.scan(cases)
    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == set(cases)


def test_sql_dialect_identifiers_and_contextual_selects_remain_detected() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    cases = {
        "quoted.py": 'payload = f\'INSERT INTO "users" VALUES ("{name}")\'\n',
        "bracketed.py": 'payload = f"INSERT INTO [users] VALUES ({value})"\n',
        "backtick.py": 'payload = f"INSERT INTO `users` VALUES ({value})"\n',
        "schema.py": 'payload = f"INSERT INTO schema.{table} VALUES (1)"\n',
        "concat.py": 'query = f"SELECT \'hello \' || {name}"\n',
        "comparison.py": 'cursor.execute(f"SELECT {left} = {right}")\n',
        "order.py": 'query = f"SELECT true ORDER BY {column}"\n',
        "setting.py": (
            'query = f"SELECT current_setting(\'x\') || {suffix}"\n'
        ),
    }

    findings = scanner.scan(cases)

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == set(cases)


def test_context_free_select_prose_is_not_treated_as_sql() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    source = (
        'a = f"Select {option}, then click Continue"\n'
        'b = f"Select all {count} available items"\n'
        'c = f"Select {option} as your default"\n'
        'd = f"Select 1 + {extra} choices"\n'
        'e = f"Select {label} -> next"\n'
        'f = f"Select CASE when ready then {choice}"\n'
    )

    findings = scanner.scan({"src/messages.py": source})

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_percent_and_brace_format_parsers_handle_escapes_and_nested_specs() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    positives = {
        "percent.py": 'query = "SELECT * FROM users WHERE name LIKE \'%%%s%%\'" % name\n',
        "mapping.py": (
            'query = "SELECT * FROM users WHERE name LIKE \'%%%(name)s%%\'" % values\n'
        ),
        "balanced.py": (
            'query = "SELECT * FROM users WHERE name = %(user(id))s" % values\n'
        ),
        "empty_mapping_key.py": (
            'query = "SELECT * FROM users WHERE name = %()s" % values\n'
        ),
        "width.py": (
            'query = "SELECT * FROM users WHERE amount = %*.*f" % values\n'
        ),
        "nested.py": (
            'query = "SELECT * FROM {table:{width}}".format_map(values)\n'
        ),
        "escaped.py": (
            'query = "SELECT * FROM {{{table}}}".format(table=name)\n'
        ),
    }
    negatives = {
        "literal_percent.py": (
            'query = "SELECT * FROM users WHERE literal=\'%%s\'" % ()\n'
        ),
        "literal_mapping.py": (
            'query = "SELECT * FROM users WHERE literal=\'%%(name)s\'" % {}\n'
        ),
        "escaped_brace.py": (
            'query = "SELECT * FROM {{tenant}}".format(unused)\n'
        ),
        "malformed_brace.py": (
            'query = "SELECT * FROM {table".format(table=name)\n'
        ),
    }

    findings = scanner.scan({**positives, **negatives})

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == set(positives)


def test_malformed_python_flow_is_limited_to_straight_line_blocks() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/direct_broken.py": (
            'payload = f"SELECT {column}"\n'
            "cursor.execute(payload)\n"
            "this is invalid python\n"
        ),
        "src/branch_broken.py": (
            'payload = f"SELECT {column}"\n'
            "if flag:\n"
            '    payload = "SELECT 1"\n'
            "else:\n"
            '    payload = "SELECT 2"\n'
            "cursor.execute(payload)\n"
            "this is invalid python\n"
        ),
    }

    findings = scanner.scan(files)
    locations = {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    }

    assert locations == {("src/direct_broken.py", 1)}


def test_malformed_python_literal_recovery_does_not_rescan_suffixes() -> None:
    source = (
        "query = "
        + " + ".join('\"x\"' for _ in range(4000))
        + "\nthis is invalid python\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/large_broken.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_malformed_python_concat_has_no_semantic_lookahead_cap() -> None:
    source = (
        'payload = "SELECT " + '
        + " + ".join('"x"' for _ in range(5000))
        + " + column\ncursor.execute(payload)\nthis is invalid python\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/large_dynamic_broken.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_sql_leading_comment_recovery_is_linear_and_detects_statement() -> None:
    comments = "/**/" * 1000
    source = f'query = f"{comments}SELECT * FROM users WHERE id = {{user_id}}"\n'

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/commented_query.py": source}
    )

    assert any(finding.pattern_id == "EQ-009" for finding in findings)


def test_sql_flow_handles_large_elif_chain_without_recursion() -> None:
    arms = []
    for index in range(500):
        keyword = "if" if index == 0 else "elif"
        arms.extend(
            (
                f"{keyword} flag_{index}:\n",
                f'    payload = f"SELECT {{column_{index}}}"\n',
            )
        )
    source = "".join([*arms, "cursor.execute(payload)\n"])

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/large_branch.py": source}
    )

    assert any(finding.pattern_id == "EQ-009" for finding in findings)


def test_sql_flow_tracks_loop_backedges_and_break_exits() -> None:
    files = {
        "src/backedge.py": (
            'payload = "safe"\n'
            "for item in items:\n"
            "    cursor.execute(payload)\n"
            '    payload = f"SELECT {item}"\n'
        ),
        "src/break_exit.py": (
            "while True:\n"
            '    payload = f"SELECT {column}"\n'
            "    break\n"
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/backedge.py", 4), ("src/break_exit.py", 2)}


def test_sql_flow_tracks_exception_and_finally_channels() -> None:
    files = {
        "src/handler.py": (
            "try:\n"
            '    payload = f"SELECT {column}"\n'
            "    risky()\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/finally.py": (
            "def run():\n"
            "    try:\n"
            '        payload = f"SELECT {column}"\n'
            "        return\n"
            "    finally:\n"
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/handler.py", 2), ("src/finally.py", 3)}


def test_sql_flow_evaluates_walrus_and_unpacking_in_order() -> None:
    files = {
        "src/walrus.py": (
            'source = f"SELECT {column}"\n'
            "((payload := source), cursor.execute(payload))\n"
        ),
        "src/unpack.py": (
            'payload, safe = (f"SELECT {other}", "safe")\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/walrus.py", 1), ("src/unpack.py", 1)}


def test_exhaustive_match_kills_stale_sql_binding() -> None:
    source = (
        'payload = f"SELECT {column}"\n'
        "match choice:\n"
        "    case 1:\n"
        '        payload = "safe"\n'
        "    case _:\n"
        '        payload = "safe"\n'
        "cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/exhaustive_match.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_sql_flow_resolves_later_iteration_aliases_without_pass_cap() -> None:
    aliases = 80
    initializers = "\n".join(f'q{index} = "safe"' for index in range(aliases))
    transfers = "\n".join(
        f"    q{index} = q{index + 1}" for index in range(aliases - 1)
    )
    source = (
        'source = f"SELECT {column}"\n'
        f"{initializers}\n"
        "while condition:\n"
        "    cursor.execute(q0)\n"
        f"{transfers}\n"
        f"    q{aliases - 1} = source\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/alias_ring.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_sql_flow_routes_loop_else_and_exception_side_effects() -> None:
    files = {
        "src/continue_else.py": (
            'payload = "safe"\n'
            "for item in items:\n"
            '    payload = f"SELECT {item}"\n'
            "    continue\n"
            "else:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/break_else.py": (
            'payload = f"SELECT {column}"\n'
            "while True:\n"
            "    break\n"
            "else:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/walrus_handler.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    ((payload := source), risky())\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/return_finally.py": (
            "def run():\n"
            "    try:\n"
            '        return (payload := f"SELECT {column}")\n'
            "    finally:\n"
            "        cursor.execute(payload)\n"
        ),
        "src/with_suppression.py": (
            'source = f"SELECT {column}"\n'
            "with suppress(Exception):\n"
            "    payload = source\n"
            "    risky()\n"
            "cursor.execute(payload)\n"
        ),
        "src/final_override.py": (
            "def run():\n"
            '    payload = f"SELECT {column}"\n'
            "    try:\n"
            "        raise ValueError\n"
            "    finally:\n"
            '        return "safe"\n'
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/continue_else.py", 3),
        ("src/return_finally.py", 3),
        ("src/walrus_handler.py", 1),
        ("src/with_suppression.py", 1),
    }


def test_sql_flow_preserves_sanitizer_parameter_and_kill_barriers() -> None:
    files = {
        "src/sanitizer.py": (
            'payload = f"SELECT {column}"\n'
            "cursor.execute(sanitize(payload))\n"
        ),
        "src/parameters.py": (
            'payload = f"SELECT {column}"\n'
            'cursor.execute("SELECT ?", payload)\n'
        ),
        "src/inverse_unpack.py": (
            'safe, payload = (f"SELECT {column}", "safe")\n'
            "cursor.execute(payload)\n"
        ),
        "src/match_capture.py": (
            'payload = f"SELECT {column}"\n'
            "match safe_value:\n"
            "    case payload:\n"
            "        pass\n"
            "cursor.execute(payload)\n"
        ),
        "src/base_rebind.py": (
            'request.payload = f"SELECT {column}"\n'
            "request = safe_request\n"
            "cursor.execute(request.payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_sql_flow_respects_constant_and_unknown_conditional_values() -> None:
    files = {
        "src/constant.py": (
            'source = f"SELECT {column}"\n'
            'payload = source if False else "safe"\n'
            "cursor.execute(payload)\n"
        ),
        "src/unknown.py": (
            'source = f"SELECT {column}"\n'
            'payload = source if condition else "safe"\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == {"src/unknown.py"}


def test_sql_comment_trivia_supports_cr_and_crlf() -> None:
    files = {
        "src/cr.py": (
            'query = f"-- generated\\rSELECT * FROM users WHERE id={user_id}"\n'
        ),
        "src/crlf.py": (
            'query = f"-- generated\\r\\nSELECT * FROM users WHERE id={user_id}"\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == set(files)


def test_malformed_concat_detects_dynamic_operand_at_any_large_position() -> None:
    before = " + ".join('"x"' for _ in range(2500))
    after = " + ".join('"y"' for _ in range(2500))
    prefix = 'payload = "SELECT * FROM users WHERE id = " + '
    files = {
        "src/first.py": f"{prefix}column + {before} + {after}\ninvalid syntax here\n",
        "src/middle.py": f"{prefix}{before} + column + {after}\ninvalid syntax here\n",
        "src/last.py": f"{prefix}{before} + {after} + column\ninvalid syntax here\n",
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == set(files)


def test_sql_flow_records_expression_exception_boundaries() -> None:
    files = {
        "src/name.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload = source\n"
            "    missing_name\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/unary.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    -(payload := source)\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/await.py": (
            "async def run():\n"
            '    source = f"SELECT {column}"\n'
            "    try:\n"
            "        await (payload := source)\n"
            "    except Exception:\n"
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/await.py", 2),
        ("src/name.py", 1),
        ("src/unary.py", 1),
    }


def test_caught_inner_exception_does_not_leak_to_outer_handler() -> None:
    source = (
        'source = f"SELECT {column}"\n'
        "try:\n"
        "    try:\n"
        "        payload = source\n"
        "        risky()\n"
        "    except Exception:\n"
        '        payload = "safe"\n'
        "except Exception:\n"
        "    cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/nested_try.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_sql_flow_models_assert_as_conditional_raise() -> None:
    files = {
        "src/caught.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    assert False, (payload := source)\n"
            "except AssertionError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/true_msg.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "assert True, (payload := source)\n"
            "cursor.execute(payload)\n"
        ),
        "src/unknown_normal.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "assert condition, (payload := source)\n"
            "cursor.execute(payload)\n"
        ),
        "src/unreachable.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            "assert False\n"
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/caught.py", 1)}


def test_sql_flow_evaluates_store_targets_in_python_order() -> None:
    files = {
        "src/side_effect.py": (
            'source = f"SELECT {column}"\n'
            'values[(payload := source)] = "safe"\n'
            "cursor.execute(payload)\n"
        ),
        "src/target_raise.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    ()[0] = (payload := source)\n"
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/chained_positive.py": (
            'source = f"SELECT {column}"\n'
            'payload = observed = "safe"\n'
            "payload = values[(observed := payload)] = source\n"
            "cursor.execute(observed)\n"
        ),
        "src/chained_negative.py": (
            'payload = f"SELECT {column}"\n'
            'observed = "safe"\n'
            'payload = values[(observed := payload)] = "safe"\n'
            "cursor.execute(observed)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/chained_positive.py", 1),
        ("src/side_effect.py", 1),
        ("src/target_raise.py", 1),
    }


def test_sql_flow_binds_for_targets_from_literal_elements() -> None:
    files = {
        "src/direct.py": (
            'for payload in [f"SELECT {column}"]:\n'
            "    cursor.execute(payload)\n"
        ),
        "src/post_loop.py": (
            'payload = "safe"\n'
            'for payload in [f"SELECT {column}"]:\n'
            "    pass\n"
            "cursor.execute(payload)\n"
        ),
        "src/scalar.py": (
            'for character in f"SELECT {column}":\n'
            "    cursor.execute(character)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/direct.py", 1), ("src/post_loop.py", 2)}


def test_eager_comprehension_effects_respect_cardinality_and_scope() -> None:
    files = {
        "src/nonempty.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(payload := source) for _ in [0]]\n"
            "cursor.execute(payload)\n"
        ),
        "src/unknown.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(payload := source) for _ in items]\n"
            "cursor.execute(payload)\n"
        ),
        "src/empty.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(payload := source) for _ in []]\n"
            "cursor.execute(payload)\n"
        ),
        "src/lazy.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "((payload := source) for _ in [0])\n"
            "cursor.execute(payload)\n"
        ),
        "src/eager_sink.py": (
            'source = f"SELECT {column}"\n'
            "[cursor.execute(source) for _ in [0]]\n"
        ),
        "src/scope.py": (
            'payload = f"SELECT {column}"\n'
            '[payload for payload in ["safe"]]\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/eager_sink.py", 1),
        ("src/nonempty.py", 1),
        ("src/scope.py", 1),
        ("src/unknown.py", 1),
    }


def test_boolop_result_provenance_tracks_returned_operands() -> None:
    files = {
        "src/or_bound.py": (
            'source = f"SELECT {column}"\n'
            'payload = source or "safe"\n'
            "cursor.execute(payload)\n"
        ),
        "src/and_bound.py": (
            'source = f"SELECT {column}"\n'
            'payload = source and "safe"\n'
            "cursor.execute(payload)\n"
        ),
        "src/or_direct.py": 'cursor.execute(f"SELECT {column}" or "safe")\n',
        "src/and_direct.py": 'cursor.execute(f"SELECT {column}" and "safe")\n',
        "src/last_and.py": (
            'source = f"SELECT {column}"\n'
            'cursor.execute("safe" and source)\n'
        ),
        "src/dead.py": (
            'source = f"SELECT {column}"\n'
            "cursor.execute(False and source)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/last_and.py", 1),
        ("src/or_bound.py", 1),
        ("src/or_direct.py", 1),
    }


def test_match_projects_structured_captures_and_routes_guard_fallthrough() -> None:
    files = {
        "src/sequence_safe.py": (
            'source = f"SELECT {column}"\n'
            'match ("safe", source):\n'
            "    case (safe, unsafe):\n"
            "        cursor.execute(safe)\n"
        ),
        "src/sequence_unsafe.py": (
            'source = f"SELECT {column}"\n'
            'match ("safe", source):\n'
            "    case (safe, unsafe):\n"
            "        cursor.execute(unsafe)\n"
        ),
        "src/mapping.py": (
            'source = f"SELECT {column}"\n'
            'match {"safe": "safe", "unsafe": source}:\n'
            '    case {"unsafe": unsafe}:\n'
            "        cursor.execute(unsafe)\n"
        ),
        "src/false_guard.py": (
            'source = f"SELECT {column}"\n'
            "match source:\n"
            "    case payload if False:\n"
            "        cursor.execute(payload)\n"
        ),
        "src/guard_fallthrough.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "match value:\n"
            "    case _ if not (payload := source):\n"
            "        pass\n"
            "    case _:\n"
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/guard_fallthrough.py", 1),
        ("src/mapping.py", 1),
        ("src/sequence_unsafe.py", 1),
    }


def test_sql_flow_preserves_dict_order_and_precise_starred_unpacking() -> None:
    files = {
        "src/dict_order.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "{(payload := source): cursor.execute(payload), "
            '(payload := "safe"): 0}\n'
        ),
        "src/star_prefix.py": (
            'safe, *rest = ("safe", f"SELECT {column}")\n'
            "cursor.execute(safe)\n"
        ),
        "src/star_suffix.py": (
            '*rest, safe = (f"SELECT {column}", "safe")\n'
            "cursor.execute(safe)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/dict_order.py", 1)}


def test_sql_flow_evaluates_call_arguments_in_lexical_order() -> None:
    files = {
        "src/positive.py": (
            'payload = f"SELECT {column}"\n'
            'cursor.execute(query=payload, *((payload := "safe") and ()))\n'
        ),
        "src/negative.py": (
            'payload = "safe"\n'
            'cursor.execute(query=payload, '
            '*((payload := f"SELECT {column}") and ()))\n'
        ),
        "src/star_first_safe.py": (
            'payload = f"SELECT {column}"\n'
            'cursor.execute(*((payload := "safe") and ()), query=payload)\n'
        ),
        "src/star_first_dynamic.py": (
            'payload = "safe"\n'
            'cursor.execute('
            '*((payload := f"SELECT {column}") and ()), query=payload)\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/positive.py", 1), ("src/star_first_dynamic.py", 2)}


def test_sql_flow_tracks_value_preserving_fstring_wrappers() -> None:
    files = {
        "src/direct.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"{source}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/whitespace.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"  {source}\t"\n'
            "cursor.execute(payload)\n"
        ),
        "src/not_transparent.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"log: {source}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/repr.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"{source!r}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/ascii.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"{source!a}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/format_spec.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"{source:.3}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/string_conversion.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"{source!s}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/multiple.py": (
            'source = f"SELECT {column}"\n'
            'payload = f"{source}{source}"\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/direct.py", 1),
        ("src/string_conversion.py", 1),
        ("src/whitespace.py", 1),
    }


def test_defined_name_loads_do_not_create_spurious_exception_paths() -> None:
    files = {
        "src/local.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload = source\n"
            "    observed = payload\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/parameter.py": (
            "def run(parameter):\n"
            '    source = f"SELECT {column}"\n'
            "    try:\n"
            "        payload = source\n"
            "        parameter\n"
            "    except Exception:\n"
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_descending_loop_alias_flow_uses_linear_state_copy_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    aliases = 800
    copied_slots = 0
    copy_calls = 0
    original_copy = eng_quality_helpers._SqlBindingState.copy

    def measured_copy(
        state: eng_quality_helpers._SqlBindingState,
    ) -> eng_quality_helpers._SqlBindingState:
        nonlocal copied_slots, copy_calls
        copy_calls += 1
        copied_slots += len(state) + len(state.defined_keys)
        return original_copy(state)

    monkeypatch.setattr(
        eng_quality_helpers._SqlBindingState,
        "copy",
        measured_copy,
    )
    initializers = "\n".join(
        f'q{index} = "safe"' for index in range(aliases)
    )
    transfers = "\n".join(
        f"    q{index} = q{index + 1}" for index in range(aliases - 1)
    )
    source = (
        'source = f"SELECT {column}"\n'
        f"{initializers}\n"
        "while condition:\n"
        "    cursor.execute(q0)\n"
        f"{transfers}\n"
        f"    q{aliases - 1} = source\n"
    )

    assert eng_quality_helpers.python_interpolated_sql_lines(source) == {1}
    assert copy_calls <= 20
    assert copied_slots <= aliases * 20


def test_deep_dotted_binding_index_is_compact_and_fully_metered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_units: list[int] = []
    for depth in (25, 50, 100, 200):
        key = "root." + ".".join(f"a{index}" for index in range(depth))
        source = f'{key} = f"SELECT {{value}}"\ncursor.execute({key})\n'
        context = eng_quality_helpers.PythonAnalysisContext(
            source,
            file_path=f"deep-{depth}.py",
        )

        assert eng_quality_helpers.python_interpolated_sql_lines(
            source,
            file_path=f"deep-{depth}.py",
            context=context,
        ) == {1}
        work_units.append(context.budget.work_units)

    assert all(
        larger <= smaller * 5
        for smaller, larger in zip(work_units, work_units[1:])
    )

    monkeypatch.setattr(Limits, "MAX_PYTHON_ANALYSIS_WORK_UNITS", 50_000)
    key = "root." + ".".join(f"a{index}" for index in range(200))
    source = f'{key} = f"SELECT {{value}}"\ncursor.execute({key})\n'
    with pytest.raises(DeterministicAnalysisBudgetExceeded):
        eng_quality_helpers.python_interpolated_sql_lines(
            source,
            file_path="deep-budget.py",
        )


def test_parent_rebind_and_delete_clear_deep_dotted_provenance() -> None:
    key = "root." + ".".join(f"a{index}" for index in range(200))
    files = {
        "src/rebound.py": (
            f'{key} = f"SELECT {{value}}"\n'
            "root = object()\n"
            f"cursor.execute({key})\n"
        ),
        "src/deleted.py": (
            f'{key} = f"SELECT {{value}}"\n'
            "del root\n"
            f"cursor.execute({key})\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_additive_assignment_tracks_dynamic_sql_fragments_to_later_sinks() -> None:
    files = {
        "src/fstring.py": (
            'payload = "SELECT * FROM users"\n'
            'payload += f" WHERE id={value}"\n'
            "cursor.execute(payload)\n"
        ),
        "src/percent.py": (
            'payload = "SELECT * FROM users"\n'
            'payload += " WHERE id=%s" % value\n'
            "cursor.execute(payload)\n"
        ),
        "src/format.py": (
            'payload = "SELECT * FROM users"\n'
            'payload += " WHERE id={}".format(value)\n'
            "cursor.execute(payload)\n"
        ),
        "src/no_sink.py": (
            'payload = "ordinary text"\n'
            'payload += f" {value}"\n'
            "print(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/format.py", 2),
        ("src/fstring.py", 2),
        ("src/percent.py", 2),
    }


def test_python_ast_budget_is_exact_and_fails_closed_with_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Limits, "MAX_PYTHON_AST_NODES", 2)
    scanner = EngQualityScanner(tech_stack=["Python"])

    assert scanner.scan({"src/at_limit.py": "pass\n"}) == []

    with pytest.raises(DeterministicAnalysisBudgetExceeded) as caught:
        scanner.scan({"src/over_limit.py": "x = 1\n"})

    error = caught.value
    assert error.path == "src/over_limit.py"
    assert error.budget_kind == "python_ast_nodes"
    assert error.limit == 2
    assert error.observed_at_least == 3
    assert "x = 1" not in str(error)


def test_python_work_budget_never_returns_partial_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Limits, "MAX_PYTHON_ANALYSIS_WORK_UNITS", 20)
    source = (
        'payload = f"SELECT {column}"\n'
        "cursor.execute(payload)\n"
    )

    with pytest.raises(DeterministicAnalysisBudgetExceeded) as caught:
        EngQualityScanner(tech_stack=["Python"]).scan(
            {"src/work_budget.py": source}
        )

    assert caught.value.path == "src/work_budget.py"
    assert caught.value.budget_kind == "python_analysis_work_units"


def test_python_source_size_guard_is_exact_and_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Limits, "MAX_FILE_SIZE", 4)
    scanner = EngQualityScanner(tech_stack=["Python"])

    assert scanner.scan({"src/at_limit.py": "pass"}) == []

    with pytest.raises(DeterministicAnalysisBudgetExceeded) as caught:
        scanner.scan({"src/over_limit.py": "pass\n"})

    assert caught.value.path == "src/over_limit.py"
    assert caught.value.budget_kind == "python_source_bytes"
    assert caught.value.observed_at_least == 5


def _nested_conditional_sql_source(depth: int = 8_000) -> str:
    expression = '"safe"'
    for index in reversed(range(depth)):
        expression = (
            f'f"SELECT {{v{index}}}" if c{index} else {expression}'
        )
    return f"payload={expression}\ncursor.execute(payload)\n"


def test_python_parser_resource_failure_is_typed_at_helper_boundary() -> None:
    source = _nested_conditional_sql_source()

    with pytest.raises(DeterministicAnalysisBudgetExceeded) as caught:
        eng_quality_helpers.python_interpolated_sql_lines(
            source,
            file_path="src/nested.py",
        )

    error = caught.value
    assert error.path == "src/nested.py"
    assert error.budget_kind == "python_parser_resources"
    assert error.limit == 0
    assert error.observed_at_least == 1


def test_python_parser_resource_failure_never_returns_partial_findings() -> None:
    not_returned = object()
    result: object = not_returned

    with pytest.raises(DeterministicAnalysisBudgetExceeded) as caught:
        result = EngQualityScanner(tech_stack=["Python"]).scan(
            {
                "src/00_prior_finding.py": "eval(user_input)\n",
                "src/nested.py": _nested_conditional_sql_source(),
            }
        )

    assert result is not_returned
    assert caught.value.path == "src/nested.py"
    assert caught.value.budget_kind == "python_parser_resources"


def test_python_rules_share_one_parse_and_one_per_file_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse_calls = 0
    original_parse = eng_quality_helpers.ast.parse

    def measured_parse(*args, **kwargs):
        nonlocal parse_calls
        parse_calls += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(eng_quality_helpers.ast, "parse", measured_parse)
    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {
            "src/shared.py": (
                'payload = f"SELECT {column}"\n'
                "cursor.execute(payload)\n"
                'httpx.get("https://example.test")\n'
            )
        }
    )

    assert parse_calls == 1
    assert {finding.pattern_id for finding in findings} == {"EQ-009", "EQ-012"}


def test_sql_flow_handles_deep_conditional_expression_without_recursion() -> None:
    expression = '"safe"'
    for index in reversed(range(1000)):
        expression = f'f"SELECT {{column_{index}}}" if flag_{index} else {expression}'
    source = f"payload = {expression}\ncursor.execute(payload)\n"

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/deep_ifexp.py": source}
    )

    assert any(finding.pattern_id == "EQ-009" for finding in findings)


def test_malformed_concat_preserves_sql_position_and_leading_trivia() -> None:
    files = {
        "src/spaces.py": (
            "query = "
            + repr(" " * 5000 + "SELECT * FROM users WHERE id = ")
            + " + user_value\ninvalid syntax here\n"
        ),
        "src/comments.py": (
            "query = "
            + repr("/**/" * 2000 + "SELECT * FROM users WHERE id = ")
            + " + user_value\ninvalid syntax here\n"
        ),
        "src/update.py": (
            'query = "UPDATE " + table + " SET value = 1"\n'
            "invalid syntax here\n"
        ),
        "src/insert.py": (
            'query = "INSERT INTO " + table + "(id) VALUES (1)"\n'
            "invalid syntax here\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == set(files)


def test_malformed_static_grouping_does_not_become_dynamic_sql() -> None:
    source = (
        'query = "SELECT " + '
        + " + ".join('("x")' for _ in range(3000))
        + "\ninvalid syntax here\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/static_grouping.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_malformed_token_recovery_handles_many_templates_and_nested_concat() -> None:
    templates = "values = (\n" + "".join(
        f'f"SELECT {{column_{index}}}",\n' for index in range(2000)
    )
    nested = "user_value"
    for _ in range(1000):
        nested = f'"x" + ({nested})'
    files = {
        "src/templates.py": templates,
        "src/nested.py": (
            f'query = "SELECT " + ({nested})\ninvalid syntax here\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        finding.file_path for finding in findings if finding.pattern_id == "EQ-009"
    } == {"src/nested.py"}


def test_dockerfile_without_user_detected_as_p2() -> None:
    files = {"Dockerfile": "FROM python:3.11\nRUN echo hi\n"}
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-018"), None)
    assert finding is not None
    assert finding.severity == "P2"


def test_dockerfile_root_user_waiver_suppresses_finding() -> None:
    files = {
        "Dockerfile": (
            "FROM python:3.11\n"
            "# omargate:allow-root-user\n"
            "RUN echo hi\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-018" for f in findings)


def test_env_file_committed_detected_as_p0() -> None:
    files = {
        ".env": "OPENAI_API_KEY=sk-test\n",
        ".env.example": "OPENAI_API_KEY=\n",
    }
    scanner = EngQualityScanner(tech_stack=[])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-020" and f.severity == "P0" for f in findings)


def test_n_plus_one_query_pattern_detected() -> None:
    files = {
        "src/app.py": (
            "async def f(user_ids, session):\n"
            "    for user_id in user_ids:\n"
            "        await session.execute(\"SELECT 1\", {\"id\": user_id})\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["FastAPI", "Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-007" for f in findings)


def test_multiline_httpx_client_with_explicit_timeout_is_not_flagged() -> None:
    files = {
        "src/routes/auth.py": (
            "async def fetch_metadata():\n"
            "    async with httpx.AsyncClient(\n"
            "        follow_redirects=False,\n"
            "        timeout=_CIMD_FETCH_TIMEOUT_S,\n"
            "    ) as client:\n"
            "        return await client.get('https://example.com')\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-012" for f in findings)


def test_multiline_httpx_client_without_timeout_is_flagged() -> None:
    files = {
        "src/routes/auth.py": (
            "async def fetch_metadata():\n"
            "    async with httpx.AsyncClient(\n"
            "        follow_redirects=False,\n"
            "    ) as client:\n"
            "        return await client.get('https://example.com')\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-012"), None)
    assert finding is not None
    assert finding.line_start == 2
    assert finding.line_end == 4


def test_multiline_httpx_get_with_explicit_timeout_is_not_flagged() -> None:
    files = {
        "src/client.py": (
            "async def fetch_metadata(url):\n"
            "    return await httpx.get(\n"
            "        url,\n"
            "        timeout=5.0,\n"
            "    )\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-012" for f in findings)


def test_timeout_text_in_comment_or_string_does_not_suppress_finding() -> None:
    files = {
        "src/comment.py": "client = httpx.Client(  # timeout inherited elsewhere\n)\n",
        "src/string.py": 'response = httpx.get("timeout")\n',
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert {finding.file_path for finding in findings} == {
        "src/comment.py",
        "src/string.py",
    }


def test_nested_timeout_argument_does_not_count_as_httpx_timeout() -> None:
    files = {
        "src/client.py": (
            "response = httpx.get(\n"
            "    build_url(timeout=5.0),\n"
            ")\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 1
    assert findings[0].line_start == 1


def test_syntax_error_uses_balanced_call_fallback() -> None:
    files = {
        "src/client.py": (
            "bounded = httpx.get(\n"
            "    'https://example.com/bounded',\n"
            "    timeout=5.0,\n"
            ")\n"
            "unbounded = httpx.get(  # timeout is still missing\n"
            "    'https://example.com/unbounded',\n"
            ")\n"
            "def broken(:\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert [finding.line_start for finding in findings] == [5]


def test_one_line_httpx_call_without_timeout_is_flagged() -> None:
    files = {"src/client.py": "response = httpx.post('https://example.com')\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 1
    assert findings[0].line_start == 1


def test_same_line_httpx_calls_emit_one_unique_finding() -> None:
    files = {
        "src/nested.py": "result = httpx.get(httpx.post('https://inner'))\n",
        "src/sequential.py": (
            "first = httpx.get('https://first'); "
            "second = httpx.post('https://second')\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert len(findings) == 2
    assert len({finding.id for finding in findings}) == len(findings)
    assert {finding.file_path for finding in findings} == set(files)


def test_httpx_module_case_matching_preserves_existing_behavior() -> None:
    files = {
        "src/parseable.py": (
            "import httpx as HTTPX\n"
            "response = HTTPX.get('https://example.com')\n"
        ),
        "src/syntax_error.py": (
            "import httpx as HTTPX\n"
            "client = HTTPX.AsyncClient()\n"
            "def broken(:\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"]
    assert [(finding.file_path, finding.line_start) for finding in findings] == [
        ("src/parseable.py", 2),
        ("src/syntax_error.py", 2),
    ]


def test_workflow_secret_labels_not_flagged_as_hardcoded_secrets() -> None:
    files = {
        ".github/workflows/security-review.yml": (
            "name: Security Review\n"
            "jobs:\n"
            "  secret-scanning:\n"
            "    name: Secret Scanning\n"
            "  upload:\n"
            "    name: Upload secret scan artifacts\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert not any(f.pattern_id == "EQ-021" for f in findings)


def test_workflow_hardcoded_secret_env_value_detected() -> None:
    files = {
        ".github/workflows/security-review.yml": (
            "jobs:\n"
            "  omar-review:\n"
            "    env:\n"
            "      OPENAI_API_KEY: " + "sk" + "_live_1234567890abcdef123456" + "\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    assert any(f.pattern_id == "EQ-021" for f in findings)


def test_oidc_verify_aud_false_detected_as_p1() -> None:
    files = {
        "sentinelayer-api/src/auth/oidc_verifier.py": (
            "payload = jwt.decode(token, jwks, options={\"verify_aud\": False})\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-022"), None)
    assert finding is not None
    assert finding.severity == "P1"


def test_oauth_callback_missing_state_detected_as_p1() -> None:
    files = {
        "sentinelayer-api/src/routes/auth.py": (
            "class OAuthCallbackRequest(BaseModel):\n"
            "    code: str\n\n"
            "@router.post('/auth/github/callback')\n"
            "async def github_callback():\n"
            "    pass\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-023"), None)
    assert finding is not None
    assert finding.severity == "P1"


def test_missing_health_endpoint_uses_distinct_rule_id() -> None:
    files = {
        "sentinelayer-api/src/main.py": (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/auth/me')\n"
            "async def me():\n"
            "    return {'ok': True}\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Python", "FastAPI"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-024"), None)
    assert finding is not None
    assert finding.severity == "P2"


def test_missing_request_id_rule_has_stack_specific_fix_plan() -> None:
    files = {
        "src/api.ts": (
            "export function handler(req, res) {\n"
            "  return res.status(500).json({ error: 'boom' });\n"
            "}\n"
        )
    }
    scanner = EngQualityScanner(tech_stack=["Node.js"])
    findings = scanner.scan(files)
    finding = next((f for f in findings if f.pattern_id == "EQ-016"), None)
    assert finding is not None
    assert "requestId" in finding.fix_plan
    assert "Express" in finding.fix_plan
