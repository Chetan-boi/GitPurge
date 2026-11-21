import io
import json

import pytest

from gitpurge import server
from gitpurge.server import handle_request

SECRET = "sk_" + "live_" + "a" * 24


def test_handle_request_returns_findings() -> None:
    response = handle_request({"text": f"key = {SECRET}"})
    assert response["findings"][0]["rule_id"] == "stripe-api-key"
    assert response["scanned_characters"] == len(f"key = {SECRET}")


@pytest.mark.parametrize("bad", [None, [], "text", 3])
def test_non_object_request_is_rejected(bad: object) -> None:
    with pytest.raises(ValueError, match="JSON object"):
        handle_request(bad)


@pytest.mark.parametrize("bad", [{}, {"text": 5}, {"text": None}])
def test_missing_or_non_string_text_is_rejected(bad: dict) -> None:
    with pytest.raises(ValueError, match="string 'text'"):
        handle_request(bad)


def test_main_reads_stdin_and_prints_json(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"text": f"k = {SECRET}"})))
    server.main()
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "stripe-api-key"


def test_main_exits_two_on_bad_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    with pytest.raises(SystemExit) as exit_info:
        server.main()
    assert exit_info.value.code == 2
