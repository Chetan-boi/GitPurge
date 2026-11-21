import pytest

from gitpurge.entropy import calculate_entropy, find_entropy


def test_empty_string_has_zero_entropy() -> None:
    assert calculate_entropy("") == 0.0


def test_repeated_character_has_zero_entropy() -> None:
    assert calculate_entropy("aaaaaaaa") == 0.0


def test_two_symbols_equally_likely_is_one_bit() -> None:
    assert calculate_entropy("abababab") == pytest.approx(1.0)


def test_entropy_grows_with_variety() -> None:
    assert calculate_entropy("abcdefgh") > calculate_entropy("aabbccdd")


def test_random_looking_value_in_secret_context_is_flagged() -> None:
    value = "q8Zx3LmP9vTrW2nKb7YdF4sH"
    findings = find_entropy(f"auth_token = {value}\n")
    assert [f.value for f in findings] == [value]
    assert findings[0].rule_id == "high-entropy-secret"
    assert findings[0].entropy is not None and findings[0].entropy >= 3.5


def test_same_value_without_secret_context_is_ignored() -> None:
    assert find_entropy("name = q8Zx3LmP9vTrW2nKb7YdF4sH\n") == []


def test_low_entropy_value_is_ignored() -> None:
    assert find_entropy("secret = aaaaaaaaaaaaaaaaaaaaaaaa\n") == []


def test_threshold_is_configurable() -> None:
    line = "secret = abababababababababab\n"
    assert find_entropy(line) == []
    assert len(find_entropy(line, threshold=0.5)) == 1


def test_offsets_are_absolute_across_lines() -> None:
    value = "q8Zx3LmP9vTrW2nKb7YdF4sH"
    text = f"first line\ntoken = {value}\n"
    (candidate,) = find_entropy(text)
    assert text[candidate.start:candidate.end] == value
