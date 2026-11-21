import pytest

from gitpurge.detectors import detect_known_secrets


def _ids(text: str) -> list[str]:
    return [candidate.rule_id for candidate in detect_known_secrets(text)]


# Fixtures are assembled at runtime so this file never contains a
# literal that secret scanners would flag.
SAMPLES = {
    "slack-token": "xoxb-" + "1234567890-" + "abcdefghij",
    "stripe-api-key": "sk_" + "live_" + "a" * 24,
    "google-api-key": "AIza" + "A" * 35,
    "postgres-url": "postgres://admin:hunter2@db.example.com:5432/app",
    "mysql-url": "mysql://root:hunter2@db.example.com/app",
    "openai-api-key": "sk-" + "A1b2C3d4" * 5,
    "anthropic-api-key": "sk-ant-api03-" + "A1b2C3d4" * 10,
    "sendgrid-api-key": "SG." + "a" * 22 + "." + "b" * 43,
    "discord-bot-token": "M" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27,
}


@pytest.mark.parametrize(("rule_id", "secret"), SAMPLES.items())
def test_known_rule_matches(rule_id: str, secret: str) -> None:
    assert rule_id in _ids(f"value = {secret}\n")


def test_aws_secret_access_key_assignment() -> None:
    text = "aws_secret_access_key = " + "A" * 40
    assert "aws-secret-access-key" in _ids(text)


def test_match_offsets_cover_the_secret() -> None:
    secret = SAMPLES["stripe-api-key"]
    text = f"key = {secret}"
    candidate = next(
        c for c in detect_known_secrets(text) if c.rule_id == "stripe-api-key"
    )
    assert text[candidate.start:candidate.end] == secret
    assert candidate.value == secret


def test_generic_assignment_flags_long_values() -> None:
    assert "generic-secret-assignment" in _ids("password = 'abcdefgh12345678'")


def test_generic_assignment_ignores_short_values() -> None:
    assert _ids("password = 'short'") == []


def test_generic_assignment_ignores_env_references() -> None:
    assert _ids("api_key = process.env.SOME_LONG_VARIABLE_NAME") == []
    assert _ids("token = import.meta.env.VITE_SOME_LONG_VALUE") == []


def test_plain_code_has_no_findings() -> None:
    text = "int main() {\n  std::cout << \"Hello World\";\n  return 0;\n}\n"
    assert detect_known_secrets(text) == []


@pytest.mark.parametrize("name", ["client_secret", "DB_PASSWORD", "auth_token", "api-key"])
def test_generic_assignment_matches_prefixed_names(name: str) -> None:
    assert "generic-secret-assignment" in _ids(f"{name} = 'abcdefgh12345678'")
