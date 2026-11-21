import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gitpurge import cli

SECRET = "sk_" + "live_" + "a" * 24  # stripe-api-key, severity "error"
WARNING_LINE = "password = 'abcdefgh12345678'\n"  # generic assignment, severity "warning"


def run(*argv: str, stdin: str = "") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.run(list(argv), stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_clean_file_exits_zero(tmp_path: Path) -> None:
    f = tmp_path / "ok.py"
    f.write_text("print('hi')\n")
    assert run(str(f)) == (0, "", "")


def test_finding_exits_one_and_reports_one_based_position(tmp_path: Path) -> None:
    f = tmp_path / "bad.py"
    f.write_text(f"x = 1\nkey = '{SECRET}'\n")
    code, out, _ = run(str(f))
    assert code == 1
    assert f"{f}:2:8: error [stripe-api-key]" in out


def test_output_never_contains_the_full_secret(tmp_path: Path) -> None:
    f = tmp_path / "bad.py"
    f.write_text(f"key = '{SECRET}'\n")
    for fmt in ("text", "json"):
        _, out, _ = run("--format", fmt, str(f))
        assert SECRET not in out
        assert SECRET[:4] in out


def test_json_format(tmp_path: Path) -> None:
    f = tmp_path / "bad.py"
    f.write_text(f"key = '{SECRET}'\n")
    _, out, _ = run("--format", "json", str(f))
    (finding,) = json.loads(out)["findings"]
    assert finding["path"] == str(f)
    assert finding["rule_id"] == "stripe-api-key"
    assert finding["line"] == 1


def test_fail_on_error_ignores_warnings(tmp_path: Path) -> None:
    f = tmp_path / "w.py"
    f.write_text(WARNING_LINE)
    assert run(str(f))[0] == 1
    code, out, _ = run("--fail-on", "error", str(f))
    assert code == 0
    assert "warning" in out  # still reported, just not fatal


def test_directories_are_walked_and_skip_dirs_ignored(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "src" / "a.py").write_text(f"k = '{SECRET}'\n")
    (tmp_path / "node_modules" / "b.js").write_text(f"k = '{SECRET}'\n")
    _, out, _ = run(str(tmp_path))
    assert "a.py" in out
    assert "b.js" not in out


def test_binary_and_oversized_files_are_skipped(tmp_path: Path) -> None:
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\0\1\2" + SECRET.encode())
    big = tmp_path / "big.txt"
    big.write_text(f"k = '{SECRET}'\n")
    assert run(str(binary))[0] == 0
    assert run("--max-file-size", "5", str(big))[0] == 0


def test_missing_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    assert run(str(tmp_path / "nope.txt"))[0] == 0


def test_stdin(tmp_path: Path) -> None:
    code, out, _ = run("-", stdin=f"k = '{SECRET}'\n")
    assert code == 1
    assert out.startswith("<stdin>:1:")


def test_no_arguments_is_a_usage_error() -> None:
    code, _, err = run()
    assert code == 2
    assert "no paths" in err


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_staged_scans_the_index_not_the_working_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _git(tmp_path, "init", "-q")
    f = tmp_path / "app.py"
    f.write_text(f"k = '{SECRET}'\n")
    _git(tmp_path, "add", "app.py")
    f.write_text("k = os.environ['KEY']\n")  # fixed after staging, index still dirty
    monkeypatch.chdir(tmp_path)
    code, out, _ = run("--staged")
    assert code == 1
    assert "app.py:1:" in out


def test_staged_with_clean_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "ok.py").write_text("print(1)\n")
    _git(tmp_path, "add", "ok.py")
    monkeypatch.chdir(tmp_path)
    assert run("--staged")[0] == 0


def test_staged_outside_a_repo_is_a_usage_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    code, _, err = run("--staged")
    assert code == 2
    assert "git index" in err


def test_python_dash_m_entry_point(tmp_path: Path) -> None:
    f = tmp_path / "bad.py"
    f.write_text(f"k = '{SECRET}'\n")
    src = Path(__file__).resolve().parent.parent / "src"
    proc = subprocess.run(
        [sys.executable, "-m", "gitpurge", str(f)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(src)},
    )
    assert proc.returncode == 1
    assert "stripe-api-key" in proc.stdout


def test_redact() -> None:
    assert cli.redact("short") == "*****"
    assert cli.redact("abcd" + "x" * 40) == "abcd" + "*" * 12
