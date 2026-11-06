"""Local test client that verifies the generated Layer 3 CA (never verify=False)."""
import base64
import json
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

SECURITY = Path(__file__).parent / "runtime" / "security"
PORTS = {8013, 8014, 8015, 8016, 8019}


def call(method, url, body=None, headers=None, authenticated=True):
    parsed = urlsplit(url)
    headers = dict(headers or {})
    context = None
    if parsed.port in PORTS:
        parsed = parsed._replace(scheme="https", netloc=f"127.0.0.1:{parsed.port}")
        url = urlunsplit(parsed)
        context = ssl.create_default_context(cafile=str(SECURITY / "ca.crt"))
        if authenticated:
            headers.update({"X-Service-ID": "operator",
                            "X-Service-Token": (SECURITY / "operator" / "client.key").read_text().strip()})
    payload = None if body is None else json.dumps(body, allow_nan=False).encode()
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=payload, method=method.upper(), headers=headers)
    try:
        with urlopen(request, context=context, timeout=120) as response:
            return response.status, json.load(response)
    except HTTPError as exc:
        raw = exc.read().decode()
        try:
            result = json.loads(raw)
        except ValueError:
            result = {"detail": raw}
        return exc.code, result


if __name__ == "__main__":
    method, url = sys.argv[1:3]
    body = json.loads(base64.b64decode(sys.argv[3])) if len(sys.argv) > 3 else None
    try:
        status, result = call(method, url, body)
    except (URLError, OSError) as exc:
        status, result = 503, {"detail": f"Service connection failed: {exc}"}
    print(json.dumps({"status": status, "body": result}))
