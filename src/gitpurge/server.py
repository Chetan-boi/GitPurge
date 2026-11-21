import json

from .scanner import scan


def handle_request(request: object) -> dict[str, object]:
    # Validate the request structure
    if not isinstance(request, dict):
        raise ValueError("Request must be a JSON object.")

    # if request.get("method") != "scan":
        # raise ValueError("Only the 'scan' method is supported.")

    text = request.get("text")

    if not isinstance(text, str):
        raise ValueError("Scan requests require a string 'text' field.")

    result = scan(text)

    return result.to_dict()


def main() -> None:
    """Read one JSON scan request from stdin and print the JSON response."""
    import sys

    try:
        response = handle_request(json.load(sys.stdin))
    except (json.JSONDecodeError, ValueError) as error:
        print(f"gitpurge: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(json.dumps(response))
