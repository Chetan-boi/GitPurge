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
    try:
        with open("test/sample.json", "r", encoding="utf-8") as in_file:
            request = json.load(in_file)

        response = handle_request(request)
        print(json.dumps(response))

        with open("test/output.json", "w", encoding="utf-8") as out_file:
            json.dump(response, out_file, indent=2)

    except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"gitpurge: {error}")

