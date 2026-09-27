from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class Candidate:
    rule_id: str
    message: str
    severity: str
    start: int
    end: int
    value: str
    entropy: float | None = None


RULES = (
    #
    (
        "aws-access-key-id", # Rule ID
        "AWS access key ID detected.", # Message
        "error", # Severity
        re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b"), # Pattern
    ),
    (
        "github-token", # Rule ID
        "GitHub token detected.", # Message
        "error", # Severity
        re.compile(
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"
            r"|\bgithub_pat_[A-Za-z0-9_]{20,255}\b"
        ), # Pattern
    ),
    (
        "private-key", # Rule ID
        "Private key material detected.", # Message
        "error", # Severity
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), # Pattern
    ),
    (
        "jwt-secret", # Rule ID
        "JWT secret detected.", # Message
        "error", # Severity
        re.compile(r"\bJWT_SECRET\b\s*[:=]\s*[\'\"]?([A-Za-z0-9_./+=-]{16,})"), # Pattern
    ),
    (
        "generic-secret", # Rule ID
        "Generic secret detected.", # Message
        "warning", # Severity
        re.compile(r"\b(?:API_KEY|SECRET|TOKEN)\b\s*[:=]\s*[\'\"]?([A-Za-z0-9_./+=-]{16,})"), # Pattern
    ),
    (
        "mongoose-url", # Rule ID
        "MongoDB URI detected.", # Message
        "error", # Severity
        re.compile(
            r"\bmongodb(?:\+srv)?://[^:/\s@]+:[^@/\s]+@[^/\s?#]+"
            r"(?:/[^\s?#]*)?(?:\?[^\s#]*)?"
        ), # Pattern
    )
)

ASSIGNMENT = re.compile(
    r'(?im)\b(?:api[_-]?(?:key|token)|secret|token|password|passwd)\b'
    r'\s*[:=]\s*[\'"]?([A-Za-z0-9_./+=-]{16,})'
)
ENVIRONMENT_REFERENCE = re.compile(
    r"(?i)^(?:process\.env|import\.meta\.env)\.[A-Za-z_$][A-Za-z0-9_$]*$"
)


def detect_known_secrets(text: str) -> list[Candidate]:
    candidates: list[Candidate] = []

    for rule_id, message, severity, pattern in RULES:
        for match in pattern.finditer(text):
            candidates.append(
                Candidate(
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    start=match.start(),
                    end=match.end(),
                    value=match.group(),
                )
            )

    for match in ASSIGNMENT.finditer(text):
        value = match.group(1)
        if ENVIRONMENT_REFERENCE.fullmatch(value):
            continue

        candidates.append(
            Candidate(
                rule_id="generic-secret-assignment",
                message="Possible secret assigned to a sensitive variable.",
                severity="warning",
                start=match.start(1),
                end=match.end(1),
                value=value,
            )
        )

    return candidates