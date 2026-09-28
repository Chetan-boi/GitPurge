from collections import Counter
import math
import re

from .detectors import Candidate


TOKEN = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9])"
)

SECRET_CONTEXT = re.compile(
    r"(?i)\b(api[_-]?(?:key|token)|secret|token|password|credential|auth)\b"
)


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def find_entropy(
    text: str,
    threshold: float = 3.5,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    offset = 0

    for line in text.splitlines(keepends=True):
        if SECRET_CONTEXT.search(line):
            for match in TOKEN.finditer(line):
                value = match.group()
                entropy = calculate_entropy(value)

                if entropy >= threshold:
                    candidates.append(
                        Candidate(
                            rule_id="high-entropy-secret",
                            message="High-entropy value in a secret-like context.",
                            severity="warning",
                            start=offset + match.start(),
                            end=offset + match.end(),
                            value=value,
                            entropy=round(entropy, 2),
                        )
                    )

        offset += len(line)

    return candidates
