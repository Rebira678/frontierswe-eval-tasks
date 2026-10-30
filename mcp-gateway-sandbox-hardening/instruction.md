# Task: Incident Forensics & Hardening of an AI Agent Tool Gateway (`/workspace/mcp-gateway`)

## Scenario
You are responding to a security incident on an internal AI Agent Tool Gateway located at `/workspace/mcp-gateway`.
The gateway exposes three endpoints used by autonomous LLM workers:
- `POST /api/v1/fetch` — Fetches remote documentation URLs for RAG ingestion (authenticated via Bearer JWT).
- `POST /api/v1/tools/read_file` — Reads files from `/workspace/sandbox_docs` on behalf of the agent (authenticated via Bearer JWT).
- `POST /api/v1/admin/exec_diagnostic` — Runs diagnostic checks (requires `"role": "admin"` in the verified JWT claims).

## Part 1: Incident Forensics (`/workspace/mcp-gateway/logs/audit.jsonl`)
An attacker exploited a chain of vulnerabilities in `/workspace/mcp-gateway/app.py` to escalate privileges from a low-privilege `viewer` token and exfiltrate a canary secret during an incident reflected in `/workspace/mcp-gateway/logs/audit.jsonl`.

Analyze `/workspace/mcp-gateway/logs/audit.jsonl` and write `/workspace/mcp-gateway/forensics_report.json` with the following exact JSON schema:
```json
{
  "attacker_ip": "<IPv4 address string of the attacker>",
  "forged_kid_payload": "<exact malicious JWT header 'kid' string used to hijack signing key lookup>",
  "ssrf_redirect_url": "<initial external URL submitted to /api/v1/fetch that redirected to internal metadata>",
  "compromised_request_id": "<request_id of the successful /api/v1/admin/exec_diagnostic call>"
}
```

## Part 2: Vulnerability Remediation & Hardening (`/workspace/mcp-gateway/app.py`)
Modify `/workspace/mcp-gateway/app.py` to remediate the security flaws while preserving existing legitimate agent functionality:

1. **SSRF Mitigation (`POST /api/v1/fetch`)**:
   - Only allow `http` and `https` schemes.
   - Resolve DNS hostnames and deny requests targeting private RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.0.0/16`, `fe80::/10`), multicast, broadcast, and `0.0.0.0`.
   - Re-validate the target IP of any HTTP redirect before following it.
   - Return HTTP `400 Bad Request` with an appropriate error JSON if a forbidden target is requested.

2. **JWT Authentication & `kid` Traversal Hardening**:
   - Ensure the token algorithm is strictly `HS256`. Reject algorithm `none` and unsupported algorithms.
   - Enforce strict validation on the `kid` header parameter: accept only alphanumeric characters, underscores, and dashes (`^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9]+)?$`).
   - Disallow path traversal (`..` or `/`) and verify that the resolved key file resides strictly within `/workspace/mcp-gateway/keys/`.
   - Reject unauthenticated, malformed, or untrusted requests with HTTP `401 Unauthorized`.

3. **Sandbox Directory Traversal Hardening (`POST /api/v1/tools/read_file`)**:
   - Canonicalize requested document paths and ensure they strictly reside within `/workspace/sandbox_docs/`.
   - Reject any directory traversal attempts (e.g. `../` or `/etc/...`) with HTTP `403 Forbidden`. Return HTTP `404 Not Found` if a valid file within the sandbox does not exist.

4. **Command Injection Mitigation (`POST /api/v1/admin/exec_diagnostic`)**:
   - Do NOT pass user input through a shell interpreter (`shell=True`).
   - Validate `target` to ensure it only contains valid hostname or IP characters (`^[a-zA-Z0-9.\-]+$`), rejecting shell metacharacters (`;`, `&`, `|`, `$`, `` ` ``).
   - Execute the diagnostic command using an argument array: `["ping", "-c", "1", "-W", "1", target]`.
   - Return HTTP `400 Bad Request` if the target is invalid.

## Verification Criteria
Your solution will be verified by:
- Verifying exact accuracy of `/workspace/mcp-gateway/forensics_report.json`.
- Testing that legitimate documentation fetching, sandbox file reads, and admin diagnostics function correctly.
- Subjecting the hardened `/workspace/mcp-gateway/app.py` to an automated red-team exploit suite verifying that SSRF, sandbox breakout, JWT header injection, and command injection attacks are thoroughly blocked.
