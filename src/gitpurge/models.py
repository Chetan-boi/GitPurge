from dataclasses import asdict, dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class GitStatus:
    is_repository: bool
    is_tracked: bool
    is_ignored: bool

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    message: str
    severity: str
    line: int
    column: int
    end_line: int
    end_column: int
    evidence: str
    entropy: float | None = None

@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    scanned_characters: int
    git_status: GitStatus | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "findings": [asdict(finding) for finding in self.findings],
            "scanned_characters": self.scanned_characters,
        }

        if self.git_status is not None:
            result["git_status"] = asdict(self.git_status)

        return result
