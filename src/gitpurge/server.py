import json
import sys
from typing import TextIO

from .scanner import scan


def handle_request(request: object) -> dict[str, object]:
    # Validate the request structure
    if not isinstance(request, dict):
        raise ValueError("Request must be a JSON object.")

    # if request.get("method") != "scan":
        # raise ValueError("Only the 'scan' method is supported.")

    # Get the text to scan
    params = request.get("params", request)

    if not isinstance(params, dict):
        raise ValueError("Request params must be a JSON object.")

    text = params.get("text")

    if not isinstance(text, str):
        raise ValueError("Scan requests require a string 'text' field.")

    result = scan(text)

    return {
        "id": request.get("id"),
        "ok": True,
        "result": result.to_dict(),
    }


def run(
    stdin: TextIO = sys.stdin, # Receive Requests
    stdout: TextIO = sys.stdout, # Send Responses
    stderr: TextIO = sys.stderr, # Send Errors
) -> None:
    # Read each line from stdin
    for line_number, line in enumerate(stdin, start=1):

        # Check if the line is empty or just whitespace
        if not line.strip():
            continue

        try:
            request = json.loads(line)
            response = handle_request(request)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            print(
                f"gitpurge: request {line_number}: {error}",
                file=stderr,
            )
            response = {
                "id": None,
                "ok": False,
                "error": str(error),
            }

        print(json.dumps(response), file=stdout, flush=True)


def main() -> None:
    run()