"""Command line interface: scan files, staged changes, or stdin for secrets."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass

from .models import Finding
from .scanner import scan

DEFAULT_MAX_FILE_SIZE = 1_048_576
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "out"}
SEVERITY_RANK = {"warning": 1, "error": 2}

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


@dataclass(frozen=True, slots=True)
class FileFinding:
    path: str
    finding: Finding


def redact(value: str) -> str:
    """Show enough of a secret to recognise it without leaking it."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 4, 12)}"


def iter_files(paths: Iterable[str]) -> Iterator[str]:
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    yield os.path.join(root, name)
        else:
            yield path


def read_text(path: str, max_size: int) -> str | None:
    """Return file text, or None for unreadable, oversized, or binary files."""
    try:
        if os.path.getsize(path) > max_size:
            return None
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def staged_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
        capture_output=True,
        check=True,
    )
    return [name for name in result.stdout.decode("utf-8").split("\0") if name]


def staged_text(path: str, max_size: int) -> str | None:
    """Read the staged (index) version of a file, not the working tree copy."""
    result = subprocess.run(["git", "show", f":{path}"], capture_output=True)
    if result.returncode != 0 or len(result.stdout) > max_size:
        return None
    if b"\0" in result.stdout[:8192]:
        return None
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(path: str, text: str) -> list[FileFinding]:
    return [FileFinding(path, finding) for finding in scan(text).findings]


def format_text(results: Sequence[FileFinding]) -> str:
    lines = []
    for item in results:
        f = item.finding
        lines.append(
            f"{item.path}:{f.line + 1}:{f.column + 1}: {f.severity} "
            f"[{f.rule_id}] {f.message} ({redact(f.evidence)})"
        )
    return "\n".join(lines)


def format_json(results: Sequence[FileFinding]) -> str:
    payload = [
        {
            "path": item.path,
            "rule_id": item.finding.rule_id,
            "message": item.finding.message,
            "severity": item.finding.severity,
            "line": item.finding.line + 1,
            "column": item.finding.column + 1,
            "end_line": item.finding.end_line + 1,
            "end_column": item.finding.end_column + 1,
            "evidence": redact(item.finding.evidence),
            "entropy": item.finding.entropy,
        }
        for item in results
    ]
    return json.dumps({"findings": payload}, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gitpurge",
        description="Detect API keys, tokens, and other secrets before they are committed.",
        epilog="Exit status: 0 clean, 1 findings at or above --fail-on, 2 usage or git error.",
    )
    parser.add_argument("paths", nargs="*", help="files or directories to scan; '-' reads stdin")
    parser.add_argument("--staged", action="store_true", help="scan the staged version of files in the git index")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    parser.add_argument(
        "--fail-on",
        choices=("warning", "error"),
        default="warning",
        help="lowest severity that produces a non-zero exit status (default: warning)",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        metavar="BYTES",
        help=f"skip files larger than this (default: {DEFAULT_MAX_FILE_SIZE})",
    )
    return parser


def run(argv: Sequence[str] | None = None, stdin=None, stdout=None, stderr=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)

    results: list[FileFinding] = []

    if args.staged:
        try:
            names = staged_files()
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"gitpurge: could not read the git index: {error}", file=stderr)
            return EXIT_USAGE
        for name in names:
            text = staged_text(name, args.max_file_size)
            if text is not None:
                results.extend(scan_text(name, text))
    elif not args.paths:
        print("gitpurge: no paths given (use --staged, '-', or one or more files)", file=stderr)
        return EXIT_USAGE

    for path in iter_files(args.paths):
        if path == "-":
            results.extend(scan_text("<stdin>", stdin.read()))
            continue
        text = read_text(path, args.max_file_size)
        if text is not None:
            results.extend(scan_text(path, text))

    output = format_json(results) if args.format == "json" else format_text(results)
    if output:
        print(output, file=stdout)

    threshold = SEVERITY_RANK[args.fail_on]
    failing = any(SEVERITY_RANK.get(r.finding.severity, 1) >= threshold for r in results)
    return EXIT_FINDINGS if failing else EXIT_CLEAN


def main() -> None:
    sys.exit(run())
