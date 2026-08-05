from __future__ import annotations

import ast

from omargate.analyze.deterministic.eng_quality_scanner import EngQualityScanner


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
        "src/lowercase.py": ('payload = f"select * from users where id = {user_id}"\n'),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = scanner.scan(files)
    sql_findings = [finding for finding in findings if finding.pattern_id == "EQ-009"]
    assert {finding.file_path for finding in sql_findings} == {
        "src/lowercase.py",
        "src/query.py",
    }
    assert all(finding.severity == "P0" for finding in sql_findings)
    assert (
        next(
            finding for finding in sql_findings if finding.file_path == "src/query.py"
        ).line_start
        == 2
    )


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
        "src/concat.js": ('const query = "DELETE FROM users WHERE id = " + userId;\n'),
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
        "select_case": ('query = f"SELECT CASE WHEN {condition} THEN 1 ELSE 0 END"\n'),
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
    prose_findings = scanner.scan({"src/message.py": 'message = f"select {option}"\n'})

    assert any(finding.pattern_id == "EQ-009" for finding in query_findings)
    assert not any(finding.pattern_id == "EQ-009" for finding in prose_findings)


def test_dynamic_select_tracks_direct_sink_without_broad_ancestry() -> None:
    scanner = EngQualityScanner(tech_stack=["Python"])
    files = {
        "src/executed.py": (
            'payload = f"SELECT {value} AS result"\ncursor.execute(payload)\n'
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
            "const query = `SELECT email FROM users WHERE id = ${userId}`;\n"
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
        '# query = f"SELECT * FROM users WHERE id = {commented}"\n'
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
    source = 'def build_query(): return f"SELECT {value}"\nthis is invalid python\n'
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
        "src/direct.py": ('payload = f"SELECT {column}"\ncursor.execute(payload)\n'),
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
        "src/late.py": ('cursor.execute(payload)\npayload = f"SELECT {column}"\n'),
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
    expression = " + ".join(["payload", *(['""'] * 1200)])
    source = f'payload = f"SELECT {{column}}"\ncursor.execute({expression})\n'

    findings = EngQualityScanner(tech_stack=["Python"]).scan({"src/deep.py": source})

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
        "concat.py": "query = f\"SELECT 'hello ' || {name}\"\n",
        "comparison.py": 'cursor.execute(f"SELECT {left} = {right}")\n',
        "order.py": 'query = f"SELECT true ORDER BY {column}"\n',
        "setting.py": ("query = f\"SELECT current_setting('x') || {suffix}\"\n"),
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
        "percent.py": "query = \"SELECT * FROM users WHERE name LIKE '%%%s%%'\" % name\n",
        "mapping.py": (
            "query = \"SELECT * FROM users WHERE name LIKE '%%%(name)s%%'\" % values\n"
        ),
        "balanced.py": (
            'query = "SELECT * FROM users WHERE name = %(user(id))s" % values\n'
        ),
        "empty_mapping_key.py": (
            'query = "SELECT * FROM users WHERE name = %()s" % values\n'
        ),
        "width.py": ('query = "SELECT * FROM users WHERE amount = %*.*f" % values\n'),
        "nested.py": ('query = "SELECT * FROM {table:{width}}".format_map(values)\n'),
        "escaped.py": ('query = "SELECT * FROM {{{table}}}".format(table=name)\n'),
    }
    negatives = {
        "literal_percent.py": (
            "query = \"SELECT * FROM users WHERE literal='%%s'\" % ()\n"
        ),
        "literal_mapping.py": (
            "query = \"SELECT * FROM users WHERE literal='%%(name)s'\" % {}\n"
        ),
        "escaped_brace.py": ('query = "SELECT * FROM {{tenant}}".format(unused)\n'),
        "malformed_brace.py": ('query = "SELECT * FROM {table".format(table=name)\n'),
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
        + " + ".join('"x"' for _ in range(4000))
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
    arms: list[str] = []
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


def test_while_false_does_not_create_a_spurious_raise_path() -> None:
    source = (
        'payload = f"SELECT {column}"\n'
        "try:\n"
        "    while False:\n"
        "        pass\n"
        '    payload = "safe"\n'
        "except Exception:\n"
        "    cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/while_false.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


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
            'payload, safe = (f"SELECT {other}", "safe")\ncursor.execute(payload)\n'
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


def test_sql_flow_handles_large_straight_alias_chain() -> None:
    aliases = 4000
    source = (
        'query_0 = f"SELECT {column}"\n'
        + "".join(
            f"query_{index} = query_{index - 1}\n" for index in range(1, aliases + 1)
        )
        + f"cursor.execute(query_{aliases})\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/straight_aliases.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_sql_flow_handles_growing_qualified_binding_paths() -> None:
    path = "record"
    assignments: list[str] = []
    for index in range(250):
        path = f"{path}.field_{index}"
        assignments.append(f"{path} = source\n")
    source = (
        'source = f"SELECT {column}"\n'
        + "".join(assignments)
        + f"cursor.execute({path})\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/qualified_chain.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_sql_binding_prefix_index_copies_are_isolated() -> None:
    from omargate.analyze.deterministic import eng_quality_helpers

    graph = eng_quality_helpers._SqlProvenance()
    state = eng_quality_helpers._SqlBindingState(graph)
    state.set_reference("record.first", graph.source(1))
    snapshot = state.copy()

    state.set_reference("record.second", graph.source(2))
    eng_quality_helpers._kill_sql_binding_key(state, "record")
    snapshot.set_reference("record.third", graph.source(3))

    assert set(snapshot.reference_descendants.get("record")) == {
        "record.first",
        "record.third",
    }
    assert not set(state.reference_descendants.get("record"))


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
            'payload = f"SELECT {column}"\ncursor.execute(sanitize(payload))\n'
        ),
        "src/parameters.py": (
            'payload = f"SELECT {column}"\ncursor.execute("SELECT ?", payload)\n'
        ),
        "src/inverse_unpack.py": (
            'safe, payload = (f"SELECT {column}", "safe")\ncursor.execute(payload)\n'
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


def test_sql_flow_records_implicit_user_code_exception_boundaries() -> None:
    files = {
        "src/with_exit.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    with manager:\n"
            "        payload = source\n"
            '    payload = "safe"\n'
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/class_body.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload = source\n"
            "    class Generated:\n"
            "        risky()\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/class_base.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload = source\n"
            "    class Generated:\n"
            "        raise KeyboardInterrupt\n"
            "except BaseException:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/import.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload = source\n"
            "    import definitely_missing_module_xyz\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/decorator.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload = source\n"
            "    @decorator\n"
            "    def generated():\n"
            "        pass\n"
            '    payload = "safe"\n'
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/unknown_iterator.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            "try:\n"
            "    for item in items:\n"
            "        pass\n"
            '    payload = "safe"\n'
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/comprehension_iterator.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    [item for item in ((payload := source) and items)]\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/literal_iterator.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            "try:\n"
            "    for item in []:\n"
            "        pass\n"
            '    payload = "safe"\n'
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files if path != "src/literal_iterator.py"}


def test_class_bodies_read_outer_sql_provenance_without_leaking_class_writes() -> None:
    source = (
        'source = f"SELECT {column}"\nclass Generated:\n    cursor.execute(source)\n'
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/class_outer_read.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_function_annotations_apply_definition_time_sql_flow_effects() -> None:
    files = {
        "src/argument.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "def generated(value: (payload := source)):\n"
            "    pass\n"
            "cursor.execute(payload)\n"
        ),
        "src/return.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "def generated() -> (payload := source):\n"
            "    pass\n"
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_future_annotations_do_not_apply_definition_time_flow_effects() -> None:
    source = (
        "from __future__ import annotations\n"
        'payload = f"SELECT {column}"\n'
        "try:\n"
        "    def generated(value: Missing.Type):\n"
        "        pass\n"
        "except NameError:\n"
        "    cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/future_annotations.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


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


def test_handler_after_broad_exception_handler_is_unreachable() -> None:
    source = (
        'source = f"SELECT {column}"\n'
        "try:\n"
        "    risky()\n"
        "except Exception:\n"
        "    pass\n"
        "except ValueError:\n"
        "    cursor.execute(source)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/unreachable_handler.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_typed_exception_handlers_preserve_escaping_raise_paths() -> None:
    files = {
        "src/keyboard.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            "    raise KeyboardInterrupt()\n"
            "except Exception:\n"
            '    payload = "safe"\n'
            "finally:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/invalid_tuple.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            "    raise ValueError()\n"
            "except (42, Exception):\n"
            '    payload = "safe"\n'
            "finally:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/shadowed.py": (
            "Exception = 42\n"
            'payload = f"SELECT {column}"\n'
            "try:\n"
            "    raise TypeError()\n"
            "except Exception:\n"
            '    payload = "safe"\n'
            "finally:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/shadowed_base_handler.py": (
            "Exception = BaseException\n"
            'payload = f"SELECT {column}"\n'
            "try:\n"
            "    raise KeyboardInterrupt\n"
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/invalid_tuple_base.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            "    try:\n"
            "        raise KeyboardInterrupt\n"
            "    except (42, Exception):\n"
            '        payload = "safe"\n'
            "except Exception:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/outer_base.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            "    try:\n"
            "        raise KeyboardInterrupt\n"
            "    except Exception:\n"
            '        payload = "safe"\n'
            "except BaseException:\n"
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/invalid_tuple.py", 1),
        ("src/invalid_tuple_base.py", 1),
        ("src/keyboard.py", 1),
        ("src/outer_base.py", 1),
        ("src/shadowed.py", 2),
        ("src/shadowed_base_handler.py", 2),
    }


def test_exception_handlers_preserve_matching_order_and_reraise_channels() -> None:
    files = {
        "src/handler_type_effect.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    raise ValueError\n"
            "except ((payload := source) and KeyError):\n"
            "    pass\n"
            "except ValueError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/exception_group.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            '    raise ExceptionGroup("group", [ValueError(), TypeError()])\n'
            "except* ValueError:\n"
            "    payload = source\n"
            "except* TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/dynamic_raise.py": (
            'source = f"SELECT {column}"\n'
            "error = KeyboardInterrupt()\n"
            "payload = source\n"
            "try:\n"
            "    raise error\n"
            "except Exception:\n"
            '    payload = "safe"\n'
            "finally:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/ordinary_reraise.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    try:\n"
            "        raise ValueError\n"
            "    except Exception:\n"
            "        Exception = 42\n"
            "        raise\n"
            "except KeyboardInterrupt:\n"
            "    cursor.execute(source)\n"
        ),
        "src/specific_tuple.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    raise ValueError\n"
            "except (KeyboardInterrupt,):\n"
            "    cursor.execute(source)\n"
        ),
        "src/broad_nested_tuple.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    raise ValueError\n"
            "except ((Exception,), KeyboardInterrupt):\n"
            "    pass\n"
            "except ValueError:\n"
            "    cursor.execute(source)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/dynamic_raise.py", 1),
        ("src/exception_group.py", 1),
        ("src/handler_type_effect.py", 1),
    }


def test_builtin_exception_constructors_preserve_known_raise_channels() -> None:
    files = {
        "src/base_not_ordinary.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    raise KeyboardInterrupt()\n"
            "except Exception:\n"
            "    cursor.execute(source)\n"
        ),
        "src/ordinary_not_base.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    raise ValueError()\n"
            "except KeyboardInterrupt:\n"
            "    cursor.execute(source)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


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


def test_name_exception_paths_require_definite_runtime_bindings() -> None:
    files = {
        "src/branch.py": (
            "def run(condition, column, cursor):\n"
            '    source = f"SELECT {column}"\n'
            "    try:\n"
            "        if condition:\n"
            "            marker = 1\n"
            "        marker\n"
            "    except NameError:\n"
            "        cursor.execute(source)\n"
        ),
        "src/while_header.py": (
            "def run(column, cursor):\n"
            '    source = f"SELECT {column}"\n'
            "    try:\n"
            "        while marker:\n"
            "            marker = False\n"
            "    except NameError:\n"
            "        cursor.execute(source)\n"
        ),
        "src/zero_iteration.py": (
            "def run(items, column, cursor):\n"
            '    source = f"SELECT {column}"\n'
            "    try:\n"
            "        for item in items:\n"
            "            marker = item\n"
            "        marker\n"
            "    except NameError:\n"
            "        cursor.execute(source)\n"
        ),
        "src/deleted_local.py": (
            "def run(column, cursor):\n"
            "    Exception = ValueError\n"
            "    del Exception\n"
            '    source = f"SELECT {column}"\n'
            "    try:\n"
            "        try:\n"
            "            raise ValueError\n"
            "        except Exception:\n"
            "            pass\n"
            "    except UnboundLocalError:\n"
            "        cursor.execute(source)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/branch.py", 2),
        ("src/deleted_local.py", 4),
        ("src/while_header.py", 2),
        ("src/zero_iteration.py", 2),
    }


def test_compile_local_builtin_shadowing_raises_before_call_arguments() -> None:
    source = (
        "def run(column, cursor):\n"
        '    source = f"SELECT {column}"\n'
        "    payload = source\n"
        "    try:\n"
        '        len((payload := "safe"))\n'
        "        len = lambda value: value\n"
        "    except UnboundLocalError:\n"
        "        cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/local_builtin.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 2
        for finding in findings
    )


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


def test_unpacking_captures_rhs_values_before_later_walrus_effects() -> None:
    files = {
        "src/positive.py": (
            'payload = f"SELECT {column}"\n'
            'first, payload = (payload, (payload := "safe"))\n'
            "cursor.execute(first)\n"
        ),
        "src/negative.py": (
            'payload = "safe"\n'
            'first, payload = (payload, (payload := f"SELECT {column}"))\n'
            "cursor.execute(first)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/positive.py", 1)}


def test_failed_literal_unpack_preserves_preassignment_binding_for_handler() -> None:
    source = (
        'payload = f"SELECT {column}"\n'
        "try:\n"
        '    payload, other = ("safe",)\n'
        "except ValueError:\n"
        "    cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/unpack_failure.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_failed_literal_for_unpack_preserves_preassignment_binding_for_handler() -> (
    None
):
    source = (
        'payload = f"SELECT {column}"\n'
        "try:\n"
        '    for payload, other in [("safe",)]:\n'
        "        pass\n"
        "except ValueError:\n"
        "    cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/for_unpack_failure.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_nested_and_comprehension_unpack_failures_reach_handlers() -> None:
    files = {
        "src/nested_for.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            '    for (payload, other), tail in [(("safe",), 0)]:\n'
            "        pass\n"
            "except ValueError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/comprehension.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            '    [None for payload, other in [("safe",)]]\n'
            "except ValueError:\n"
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_sql_flow_binds_for_targets_from_literal_elements() -> None:
    files = {
        "src/direct.py": (
            'for payload in [f"SELECT {column}"]:\n    cursor.execute(payload)\n'
        ),
        "src/post_loop.py": (
            'payload = "safe"\n'
            'for payload in [f"SELECT {column}"]:\n'
            "    pass\n"
            "cursor.execute(payload)\n"
        ),
        "src/scalar.py": (
            'for character in f"SELECT {column}":\n    cursor.execute(character)\n'
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
            'source = f"SELECT {column}"\n[cursor.execute(source) for _ in [0]]\n'
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


def test_comprehension_qualified_targets_persist_outside_local_scope() -> None:
    source = (
        'source = f"SELECT {column}"\n'
        'obj.attr = "safe"\n'
        "[None for obj.attr in [source]]\n"
        "cursor.execute(obj.attr)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/comprehension_attribute_target.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_sql_flow_evaluates_call_arguments_in_lexical_order() -> None:
    files = {
        "src/positive.py": (
            'payload = f"SELECT {column}"\n'
            'cursor.execute(query=payload, *((payload := "safe") and ()))\n'
        ),
        "src/negative.py": (
            'payload = "safe"\n'
            "cursor.execute(query=payload, "
            '*((payload := f"SELECT {column}") and ()))\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/positive.py", 1)}


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
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/direct.py", 1), ("src/whitespace.py", 1)}


def test_comprehension_loop_backedge_reaches_earlier_sink() -> None:
    source = (
        'source = f"SELECT {column}"\n'
        'payload = "safe"\n'
        "[(cursor.execute(payload), (payload := source)) for _ in [0, 1]]\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/comprehension_backedge.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_nested_comprehension_loop_backedge_reaches_earlier_sink() -> None:
    files = {
        "src/literal.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) "
            "for _ in [0, 1] for inner in [0]]\n"
        ),
        "src/unknown.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) "
            "for _ in items for inner in [0]]\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_many_comprehension_clauses_do_not_recurse_in_analyzer() -> None:
    clauses = " ".join(f"for item_{index} in [0]" for index in range(1100))
    source = f"[0 {clauses}]\n"

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/deep_comprehension.py": source}
    )

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_sql_scan_falls_back_when_valid_ast_analysis_recurses(monkeypatch) -> None:
    from omargate.analyze.deterministic import eng_quality_helpers

    def recurse(*_args: object, **_kwargs: object) -> set[int]:
        raise RecursionError

    monkeypatch.setattr(
        eng_quality_helpers,
        "_ordered_sql_binding_lines",
        recurse,
    )

    assert eng_quality_helpers.python_interpolated_sql_lines(
        'query = f"SELECT * FROM {table}"\n'
    ) == {1}


def test_sql_context_classification_path_compresses_deep_conditionals() -> None:
    from omargate.analyze.deterministic import eng_quality_helpers

    expression: ast.expr = ast.Constant(value="safe")
    expected: set[int] = set()
    for line in range(1, 2001):
        template = ast.JoinedStr(
            values=[
                ast.Constant(value="SELECT "),
                ast.FormattedValue(
                    value=ast.Name(id=f"column_{line}", ctx=ast.Load()),
                    conversion=-1,
                ),
            ],
        )
        template.lineno = line
        expected.add(line)
        expression = ast.IfExp(
            test=ast.Name(id=f"flag_{line}", ctx=ast.Load()),
            body=template,
            orelse=expression,
        )
    tree = ast.Module(
        body=[
            ast.Assign(
                targets=[ast.Name(id="query", ctx=ast.Store())],
                value=expression,
            )
        ],
        type_ignores=[],
    )
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    assert (
        eng_quality_helpers._direct_python_interpolated_sql_lines(tree, parents)
        == expected
    )


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
            'source = f"SELECT {column}"\ncursor.execute("safe" and source)\n'
        ),
        "src/dead.py": (
            'source = f"SELECT {column}"\ncursor.execute(False and source)\n'
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
        "src/sequence_post_match.py": (
            'payload = f"SELECT {column}"\n'
            'match ("safe", payload):\n'
            "    case (safe, unsafe):\n"
            '        payload = "safe"\n'
            "cursor.execute(payload)\n"
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


def test_match_captures_use_subject_values_at_their_evaluation_time() -> None:
    files = {
        "src/sequence_positive.py": (
            'payload = f"SELECT {column}"\n'
            'match (payload, (payload := "safe")):\n'
            "    case (first, _):\n"
            "        cursor.execute(first)\n"
        ),
        "src/sequence_negative.py": (
            'payload = "safe"\n'
            'source = f"SELECT {column}"\n'
            "match (payload, (payload := source)):\n"
            "    case (first, _):\n"
            "        cursor.execute(first)\n"
        ),
        "src/mapping_positive.py": (
            'payload = f"SELECT {column}"\n'
            'match {"first": payload, "second": (payload := "safe")}:\n'
            '    case {"first": first}:\n'
            "        cursor.execute(first)\n"
        ),
        "src/mapping_negative.py": (
            'payload = "safe"\n'
            'source = f"SELECT {column}"\n'
            'match {"first": payload, "second": (payload := source)}:\n'
            '    case {"first": first}:\n'
            "        cursor.execute(first)\n"
        ),
        "src/duplicate_safe.py": (
            'source = f"SELECT {column}"\n'
            'match {"key": source, "key": "safe"}:\n'
            '    case {"key": value}:\n'
            "        cursor.execute(value)\n"
        ),
        "src/duplicate_unsafe.py": (
            'source = f"SELECT {column}"\n'
            'match {"key": "safe", "key": source}:\n'
            '    case {"key": value}:\n'
            "        cursor.execute(value)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/duplicate_unsafe.py", 1),
        ("src/mapping_positive.py", 1),
        ("src/sequence_positive.py", 1),
    }


def test_match_pattern_evaluation_errors_reach_handlers_before_captures() -> None:
    source = (
        'payload = f"SELECT {column}"\n'
        "try:\n"
        "    match 0:\n"
        "        case Missing.VALUE:\n"
        "            pass\n"
        "except NameError:\n"
        "    cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/match_pattern_error.py": source}
    )

    assert any(
        finding.pattern_id == "EQ-009" and finding.line_start == 1
        for finding in findings
    )


def test_match_mapping_projection_applies_ordered_unpack_overwrites() -> None:
    files = {
        "src/direct.py": (
            'source = f"SELECT {column}"\n'
            'match {"key": "safe", **{"key": source}}:\n'
            '    case {"key": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/bound.py": (
            'source = f"SELECT {column}"\n'
            'subject = {"key": "safe", **{"key": source}}\n'
            "match subject:\n"
            '    case {"key": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_sql_flow_preserves_dict_order_and_precise_starred_unpacking() -> None:
    files = {
        "src/dict_order.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "{(payload := source): cursor.execute(payload), "
            '(payload := "safe"): 0}\n'
        ),
        "src/star_prefix.py": (
            'safe, *rest = ("safe", f"SELECT {column}")\ncursor.execute(safe)\n'
        ),
        "src/star_suffix.py": (
            '*rest, safe = (f"SELECT {column}", "safe")\ncursor.execute(safe)\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/dict_order.py", 1)}


def test_dict_and_set_construction_errors_reach_handlers_in_order() -> None:
    files = {
        "src/dict_key.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    {(payload := source): 0, []: 1}\n"
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/set_item.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    {(payload := source), []}\n"
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/dict_unpack.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    {(payload := source): 0, **42}\n"
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/value_before_hash.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            "    {[]: (payload := source)}\n"
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


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
            'query = "UPDATE " + table + " SET value = 1"\ninvalid syntax here\n'
        ),
        "src/insert.py": (
            'query = "INSERT INTO " + table + "(id) VALUES (1)"\ninvalid syntax here\n'
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
        "src/nested.py": (f'query = "SELECT " + ({nested})\ninvalid syntax here\n'),
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
        "Dockerfile": ("FROM python:3.11\n# omargate:allow-root-user\nRUN echo hi\n")
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
            '        await session.execute("SELECT 1", {"id": user_id})\n'
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
    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"
    ]
    assert {finding.file_path for finding in findings} == {
        "src/comment.py",
        "src/string.py",
    }


def test_nested_timeout_argument_does_not_count_as_httpx_timeout() -> None:
    files = {
        "src/client.py": ("response = httpx.get(\n    build_url(timeout=5.0),\n)\n")
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"
    ]
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
    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"
    ]
    assert [finding.line_start for finding in findings] == [5]


def test_one_line_httpx_call_without_timeout_is_flagged() -> None:
    files = {"src/client.py": "response = httpx.post('https://example.com')\n"}
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"
    ]
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
    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"
    ]
    assert len(findings) == 2
    assert len({finding.id for finding in findings}) == len(findings)
    assert {finding.file_path for finding in findings} == set(files)


def test_httpx_module_case_matching_preserves_existing_behavior() -> None:
    files = {
        "src/parseable.py": (
            "import httpx as HTTPX\nresponse = HTTPX.get('https://example.com')\n"
        ),
        "src/syntax_error.py": (
            "import httpx as HTTPX\nclient = HTTPX.AsyncClient()\ndef broken(:\n"
        ),
    }
    scanner = EngQualityScanner(tech_stack=["Python"])
    findings = [
        finding for finding in scanner.scan(files) if finding.pattern_id == "EQ-012"
    ]
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
            'payload = jwt.decode(token, jwks, options={"verify_aud": False})\n'
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


def test_class_scope_projects_external_writes_and_uses_comprehension_lexicals() -> None:
    positive = {
        "src/qualified.py": (
            'source = f"SELECT {column}"\n'
            'obj.attr = "safe"\n'
            "class C:\n"
            "    obj.attr = source\n"
            "cursor.execute(obj.attr)\n"
        ),
        "src/global.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "class C:\n"
            "    global payload\n"
            "    payload = source\n"
            "cursor.execute(payload)\n"
        ),
        "src/nonlocal.py": (
            "def outer():\n"
            '    source = f"SELECT {column}"\n'
            '    payload = "safe"\n'
            "    class C:\n"
            "        nonlocal payload\n"
            "        payload = source\n"
            "    cursor.execute(payload)\n"
        ),
        "src/comprehension_global.py": (
            'source = f"SELECT {column}"\n'
            "class C:\n"
            '    source = "safe"\n'
            "    [cursor.execute(source) for _ in [0] for __ in [0]]\n"
        ),
    }
    negative = {
        "src/comprehension_class_local.py": (
            "class C:\n"
            '    source = f"SELECT {column}"\n'
            "    [cursor.execute(source) for _ in [0]]\n"
        )
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan({**positive, **negative})

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/comprehension_global.py", 1),
        ("src/global.py", 1),
        ("src/nonlocal.py", 2),
        ("src/qualified.py", 1),
    }


def test_iterable_cardinality_expands_stars_and_deduplicates_mappings_and_sets() -> (
    None
):
    files = {
        "src/starred.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) for _ in [*[0, 1]]]\n"
        ),
        "src/duplicate_dict.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) "
            'for _ in {"x": 0, "x": 1}]\n'
        ),
        "src/duplicate_set.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) for _ in {0, 0}]\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/starred.py", 1)}


def test_bound_container_and_dict_constructor_preserve_match_and_iteration_values() -> (
    None
):
    files = {
        "src/nested_iteration.py": (
            'source = f"SELECT {column}"\n'
            "[cursor.execute(inner) "
            "for outer in [[source]] for inner in outer]\n"
        ),
        "src/dict_constructor.py": (
            'source = f"SELECT {column}"\n'
            'match {"key": "safe", **dict(key=source)}:\n'
            '    case {"key": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_generator_expression_eagerly_evaluates_only_the_outer_iterable() -> None:
    files = {
        "src/eager.py": (
            'source = f"SELECT {column}"\n(0 for _ in [cursor.execute(source)])\n'
        ),
        "src/lazy.py": (
            'source = f"SELECT {column}"\n(cursor.execute(source) for _ in [0])\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/eager.py", 1)}


def test_local_annotations_and_impossible_match_bodies_do_not_execute() -> None:
    files = {
        "src/local_annotation.py": (
            "def run():\n"
            '    source = f"SELECT {column}"\n'
            "    payload: cursor.execute(source)\n"
        ),
        "src/value_match.py": (
            'source = f"SELECT {column}"\n'
            "match 1:\n"
            "    case 2:\n"
            "        cursor.execute(source)\n"
        ),
        "src/mapping_match.py": (
            'source = f"SELECT {column}"\n'
            'match {"x": 0, "y": source}:\n'
            '    case {"x": 1, "y": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_multi_element_for_destructuring_preserves_components_and_first_failure() -> (
    None
):
    files = {
        "src/first_failure.py": (
            'source = f"SELECT {column}"\n'
            "for payload, other in [(source,), (source, 'ok')]:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/safe_component.py": (
            'source = f"SELECT {column}"\n'
            'for safe, unsafe in [("safe", source), ("safe", source)]:\n'
            "    cursor.execute(safe)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_small_literal_loops_preserve_ordered_last_binding_and_failure_state() -> None:
    files = {
        "src/failure_after_safe.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            "try:\n"
            '    for payload, other in [("safe", "ok"), ("bad",)]:\n'
            "        pass\n"
            "except ValueError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/unsafe_safe_failure.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "try:\n"
            '    for payload, other in [(source, "ok"), ("safe", "ok"), ("bad",)]:\n'
            "        pass\n"
            "except ValueError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/post_loop.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            'for payload in [source, "safe"]:\n'
            "    pass\n"
            "cursor.execute(payload)\n"
        ),
        "src/loop_else.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            'for payload in [source, "safe"]:\n'
            "    pass\n"
            "else:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/singleton.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            'for payload in ["safe"]:\n'
            "    pass\n"
            "cursor.execute(payload)\n"
        ),
        "src/comprehension.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            '[(payload := item) for item in [source, "safe"]]\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert not any(finding.pattern_id == "EQ-009" for finding in findings)


def test_small_literal_unrolling_retains_cross_iteration_provenance() -> None:
    files = {
        "src/loop.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            'for item in [source, "safe"]:\n'
            "    cursor.execute(payload)\n"
            "    payload = item\n"
        ),
        "src/comprehension.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := item)) "
            'for item in [source, "safe"]]\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_bound_dict_and_set_iteration_preserve_key_and_element_snapshots() -> None:
    files = {
        "src/dict_loop.py": (
            'source = f"SELECT {column}"\n'
            "values = {source: 0}\n"
            "for key in values:\n"
            "    cursor.execute(key)\n"
        ),
        "src/dict_comprehension.py": (
            'source = f"SELECT {column}"\n'
            "values = {source: 0}\n"
            "[cursor.execute(key) for key in values]\n"
        ),
        "src/set_loop.py": (
            'source = f"SELECT {column}"\n'
            "values = {source}\n"
            "for value in values:\n"
            "    cursor.execute(value)\n"
        ),
        "src/set_comprehension.py": (
            'source = f"SELECT {column}"\n'
            "values = {source}\n"
            "[cursor.execute(value) for value in values]\n"
        ),
        "src/key_snapshot.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            'values = {payload: 0, (payload := "safe"): 1}\n'
            "for key in values:\n"
            "    cursor.execute(key)\n"
        ),
        "src/nested_unpack.py": (
            'source = f"SELECT {column}"\n'
            "values = {**{source: 0}}\n"
            "for key in values:\n"
            "    cursor.execute(key)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_annotated_assignments_preserve_runtime_order_and_no_value_bindings() -> None:
    files = {
        "src/annotation_only.py": (
            "def run():\n"
            '    payload = f"SELECT {column}"\n'
            "    payload: str\n"
            "    cursor.execute(payload)\n"
        ),
        "src/rhs_before_annotation.py": (
            'payload = "safe"\n'
            'source = f"SELECT {column}"\n'
            "payload: (observed := payload) = source\n"
            "cursor.execute(observed)\n"
        ),
        "src/safe_rhs_before_annotation.py": (
            'source = f"SELECT {column}"\n'
            "payload = source\n"
            'payload: (observed := payload) = "safe"\n'
            "cursor.execute(observed)\n"
        ),
        "src/expression_target.py": (
            "def run(items):\n"
            '    payload = "safe"\n'
            '    source = f"SELECT {column}"\n'
            "    items[(payload := source)]: int\n"
            "    cursor.execute(payload)\n"
        ),
        "src/safe_expression_target.py": (
            "def run(items):\n"
            '    payload = f"SELECT {column}"\n'
            '    items[(payload := "safe")]: int\n'
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/annotation_only.py", 2),
        ("src/expression_target.py", 3),
        ("src/rhs_before_annotation.py", 2),
    }


def test_dict_pair_constructor_preserves_exact_overwrite_order() -> None:
    files = {
        "src/safe_last.py": (
            'source = f"SELECT {column}"\n'
            'subject = dict([("query", source), ("query", "safe")])\n'
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/unsafe_last.py": (
            'source = f"SELECT {column}"\n'
            'subject = dict([("query", "safe"), ("query", source)])\n'
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/literal_mapping.py": (
            'source = f"SELECT {column}"\n'
            'subject = dict({"query": source})\n'
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/dstar_mapping.py": (
            'source = f"SELECT {column}"\n'
            'subject = dict(**{"query": source})\n'
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/dstar_mapping.py", 1),
        ("src/literal_mapping.py", 1),
        ("src/unsafe_last.py", 1),
    }


def test_starred_displays_preserve_shape_iteration_and_match_provenance() -> None:
    files = {
        "src/destructure.py": (
            'source = f"SELECT {column}"\n'
            'first, payload, last = (*("safe", source), "safe")\n'
            "cursor.execute(payload)\n"
        ),
        "src/iteration.py": (
            'source = f"SELECT {column}"\n'
            "for payload in [*[source]]:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/match.py": (
            'source = f"SELECT {column}"\n'
            'match [*("safe", source)]:\n'
            "    case [_, payload]:\n"
            "        cursor.execute(payload)\n"
        ),
        "src/set_duplicate.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) "
            "for _ in {*[0], 0}]\n"
        ),
        "src/unknown_star_target.py": (
            "def run(values):\n"
            '    payload = f"SELECT {column}"\n'
            "    *payload, = values\n"
            "    cursor.execute(payload)\n"
        ),
        "src/unknown_star_and_tail.py": (
            "def run(values):\n"
            '    payload = f"SELECT {column}"\n'
            "    tail = payload\n"
            "    *payload, tail = values\n"
            "    cursor.execute(payload)\n"
            "    cursor.execute(tail)\n"
        ),
        "src/star_failure_before_walrus.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            '    [*values, (payload := "safe")]\n'
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/walrus_before_star_failure.py": (
            'payload = f"SELECT {column}"\n'
            "try:\n"
            '    [(payload := "safe"), *values]\n'
            "except TypeError:\n"
            "    cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/destructure.py", 1),
        ("src/iteration.py", 1),
        ("src/match.py", 1),
        ("src/star_failure_before_walrus.py", 1),
    }


def test_singleton_nested_comprehension_preserves_result_provenance() -> None:
    source = (
        'source = f"SELECT {column}"\n'
        "payload, = [value for _ in [0] for value in [source]]\n"
        "cursor.execute(payload)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/comprehension_result.py": source}
    )

    assert {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    } == {1}


def test_singleton_dict_comprehension_preserves_mapping_and_key_provenance() -> None:
    files = {
        "src/mapping.py": (
            'source = f"SELECT {column}"\n'
            'subject = {key: value for key in ["query"] for value in [source]}\n'
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/keys.py": (
            'source = f"SELECT {column}"\n'
            "for key in {source: 0 for _ in [0]}:\n"
            "    cursor.execute(key)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {(path, 1) for path in files}


def test_exact_generator_consumers_preserve_eager_result_provenance() -> None:
    files = {
        "src/dict_generator.py": (
            'source = f"SELECT {column}"\n'
            'subject = dict((("query", source) for _ in [0]))\n'
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/nested_dict_generator.py": (
            'source = f"SELECT {column}"\n'
            'subject = dict((key, value) for key in ["query"] '
            "for value in [source])\n"
            "match subject:\n"
            '    case {"query": payload}:\n'
            "        cursor.execute(payload)\n"
        ),
        "src/list_generator.py": (
            'source = f"SELECT {column}"\n'
            "payload, = list(value for value in [source])\n"
            "cursor.execute(payload)\n"
        ),
        "src/tuple_generator.py": (
            'source = f"SELECT {column}"\n'
            "payload, = tuple(value for value in [source])\n"
            "cursor.execute(payload)\n"
        ),
        "src/safe_generator.py": (
            'source = f"SELECT {column}"\n'
            'payload, = list(value for value in ["safe"])\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/dict_generator.py", 1),
        ("src/list_generator.py", 1),
        ("src/nested_dict_generator.py", 1),
        ("src/tuple_generator.py", 1),
    }


def test_exact_comprehension_projection_preserves_filters_and_multiple_results() -> (
    None
):
    files = {
        "src/literal_true.py": (
            'source = f"SELECT {column}"\n'
            "payload, = [value for value in [source] if True]\n"
            "cursor.execute(payload)\n"
        ),
        "src/multiple.py": (
            'source = f"SELECT {column}"\n'
            'first, payload = [value for value in ["safe", source]]\n'
            "cursor.execute(payload)\n"
        ),
        "src/literal_false.py": (
            'source = f"SELECT {column}"\n'
            "try:\n"
            "    payload, = [value for value in [source] if False]\n"
            "except ValueError:\n"
            "    pass\n"
            'payload = "safe"\n'
            "cursor.execute(payload)\n"
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {
        ("src/literal_true.py", 1),
        ("src/multiple.py", 1),
    }


def test_parenthesized_annotation_target_preserves_name_lookup_failure() -> None:
    source = (
        'source = f"SELECT {column}"\n'
        "try:\n"
        "    (missing): int\n"
        "except NameError:\n"
        "    cursor.execute(source)\n"
    )

    findings = EngQualityScanner(tech_stack=["Python"]).scan(
        {"src/parenthesized_annotation.py": source}
    )

    assert {
        finding.line_start for finding in findings if finding.pattern_id == "EQ-009"
    } == {1}


def test_starred_iteration_uses_items_not_container_provenance() -> None:
    files = {
        "src/string_characters.py": (
            'source = f"SELECT {column}"\n'
            "for character in [*source]:\n"
            "    cursor.execute(character)\n"
        ),
        "src/mapping_keys.py": (
            'source = f"SELECT {column}"\n'
            'mapping = {"safe": source}\n'
            "for key in [*mapping]:\n"
            "    cursor.execute(key)\n"
        ),
        "src/structured_values.py": (
            'source = f"SELECT {column}"\n'
            "values = [source]\n"
            "for payload in [*values]:\n"
            "    cursor.execute(payload)\n"
        ),
        "src/singleton_starred_set.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) "
            "for _ in {*{0}, 0}]\n"
        ),
        "src/singleton_starred_string.py": (
            'source = f"SELECT {column}"\n'
            'payload = "safe"\n'
            "[(cursor.execute(payload), (payload := source)) "
            'for _ in {*"a", "a"}]\n'
        ),
    }

    findings = EngQualityScanner(tech_stack=["Python"]).scan(files)

    assert {
        (finding.file_path, finding.line_start)
        for finding in findings
        if finding.pattern_id == "EQ-009"
    } == {("src/structured_values.py", 1)}
