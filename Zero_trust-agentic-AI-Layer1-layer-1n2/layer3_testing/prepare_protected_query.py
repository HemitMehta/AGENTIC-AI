"""Generate a fresh short-lived grant and agent-signed SQL request for Swagger."""
import json
from pathlib import Path

from enforcement_flow import grant, query_body

directory = Path(__file__).parent / "swagger_demo"
fixture = json.loads((directory / "12-enforcement-fixture.json").read_text(encoding="utf-8"))
decision = grant(fixture)
body = query_body(fixture, decision["accessToken"])
(directory / "13-protected-query.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
(directory / "14-query-grant.json").write_text(json.dumps(decision, indent=2), encoding="utf-8")
print("Fresh grant: layer3_testing/swagger_demo/14-query-grant.json")
print("Signed request: layer3_testing/swagger_demo/13-protected-query.json")
print("Within 60 seconds: https://localhost:8019/docs -> Authorize (HTTPBearer: accessToken) -> POST /query.")
print("The proof is single-use. Run this helper again for a fresh request.")
