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
    # Read each line from test/sample.json
    try:
        input = open("test/sample.json", "r")
        request = json.load(input)
        response = handle_request(request)
        print(json.dumps(response))
        input.close()

        with open("test/output.json", "w") as output:
            json.dump(response, output, indent=2)

    except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"gitpurge: {error}")