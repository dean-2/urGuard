"""Official Track 4 judging adapter entry point (one JSON request per process)."""
import json
import sys

from team_app import dispatch


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object")
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be a JSON object")
        encoded = json.dumps(response, allow_nan=False)
    except Exception:
        # Never print request fields, secrets, or protected content to stderr.
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return 1
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
