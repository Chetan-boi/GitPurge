from dataclasses import replace

from .detectors import Candidate, detect_known_secrets
from .entropy import find_contextual_entropy_candidates
from .models import Finding, ScanResult


def scan(text: str) -> ScanResult:
    candidates = [
        *detect_known_secrets(text),
        *find_contextual_entropy_candidates(text),
    ]

    return ScanResult(
        findings=_build_findings(text, candidates),
        scanned_characters=len(text),
    )


def _build_findings(
    text: str,
    candidates: list[Candidate],
) -> list[Finding]:
    unique: dict[tuple[int, int], Candidate] = {}

    for candidate in sorted(candidates, key=lambda item: (item.start, item.end)):
        key = (candidate.start, candidate.end)
        existing = unique.get(key)

        if existing is None:
            unique[key] = candidate
        elif existing.entropy is None and candidate.entropy is not None:
            unique[key] = replace(existing, entropy=candidate.entropy)

    findings = []

    for candidate in unique.values():
        line, column = _line_and_column(text, candidate.start)
        end_line, end_column = _line_and_column(text, candidate.end)

        findings.append(
            Finding(
                rule_id=candidate.rule_id,
                message=candidate.message,
                severity=candidate.severity,
                line=line,
                column=column,
                end_line=end_line,
                end_column=end_column,
                evidence=_redact(candidate.value),
                entropy=candidate.entropy,
            )
        )

    return findings


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    before = text[:offset]
    line = before.count("\n")
    column = offset - (before.rfind("\n") + 1)
    return line, column


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)

    return f"{value[:4]}{'*' * min(12, len(value) - 8)}{value[-4:]}"