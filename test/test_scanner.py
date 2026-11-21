from gitpurge.scanner import scan

STRIPE = "sk_" + "live_" + "a" * 24


def test_clean_text_has_no_findings() -> None:
    result = scan("print('hello')\n")
    assert result.findings == []
    assert result.scanned_characters == len("print('hello')\n")


def test_reports_zero_based_line_and_column() -> None:
    text = f"one\ntwo\nkey = {STRIPE}\n"
    (finding,) = [f for f in scan(text).findings if f.rule_id == "stripe-api-key"]
    assert (finding.line, finding.column) == (2, 6)
    assert (finding.end_line, finding.end_column) == (2, 6 + len(STRIPE))
    assert finding.evidence == STRIPE
    assert finding.severity == "error"


def test_overlapping_matches_at_same_span_are_merged() -> None:
    value = "q8Zx3LmP9vTrW2nKb7YdF4sH"
    findings = scan(f"api_key = {value}\n").findings
    spans = [(f.line, f.column, f.end_line, f.end_column) for f in findings]
    assert len(spans) == len(set(spans))


def test_merged_finding_keeps_entropy() -> None:
    value = "q8Zx3LmP9vTrW2nKb7YdF4sH"
    findings = scan(f"api_key = {value}\n").findings
    assert any(f.entropy is not None for f in findings)


def test_findings_are_ordered_by_position() -> None:
    text = f"a = {STRIPE}\nb = mysql://root:hunter2@host/db\n"
    lines = [f.line for f in scan(text).findings]
    assert lines == sorted(lines)


def test_to_dict_is_json_serialisable() -> None:
    import json

    payload = scan(f"key = {STRIPE}").to_dict()
    assert json.loads(json.dumps(payload))["findings"][0]["rule_id"] == "stripe-api-key"
    assert "git_status" not in payload


def test_anthropic_key_is_not_reported_as_openai() -> None:
    key = "sk-ant-api03-" + "A1b2C3d4" * 10
    rule_ids = [f.rule_id for f in scan(f"value = {key}").findings]
    assert rule_ids == ["anthropic-api-key"]
