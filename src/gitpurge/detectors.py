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
    (
        "slack-token",
        "Slack token detected.",
        "error",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9_-]{10,250}\b"),
    ),
    (
        "stripe-api-key",
        "Stripe secret or restricted API key detected.",
        "error",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"),
    ),
    (
        "google-api-key",
        "Google Cloud or Maps API key detected.",
        "error",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "postgres-url",
        "PostgreSQL connection string with credentials detected.",
        "error",
        re.compile(
            r"\bpostgres(?:ql)?://[^:/\s@]+:[^@/\s]+@[^/\s?#]+(?::\d+)?(?:/[^\s?#]*)?"
        ),
    ),
    (
        "mysql-url",
        "MySQL connection string with credentials detected.",
        "error",
        re.compile(
            r"\bmysql://[^:/\s@]+:[^@/\s]+@[^/\s?#]+(?::\d+)?(?:/[^\s?#]*)?"
        ),
    ),
    (
        "openai-api-key",
        "OpenAI API key detected.",
        "error",
        re.compile(r"\bsk-(?:proj-|admin-)?[A-Za-z0-9_-]{32,120}\b"),
    ),
    (
        "anthropic-api-key",
        "Anthropic API key detected.",
        "error",
        re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{80,120}\b"),
    ),
    (
        "sendgrid-api-key",
        "SendGrid API key detected.",
        "error",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ),
    (
        "discord-bot-token",
        "Discord bot token detected.",
        "error",
        re.compile(r"\b[MN][A-Za-z\d]{23,26}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b"),
    ),
    (
        "aws-secret-access-key",
        "AWS secret access key detected.",
        "warning",
        re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?"),
    ),
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
