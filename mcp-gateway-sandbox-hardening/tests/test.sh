#!/usr/bin/env bash
set -u

mkdir -p /logs/verifier
SCORE_FILE="/logs/verifier/reward.txt"
echo "0.0" > "$SCORE_FILE"

cd /workspace/mcp-gateway || exit 0

python3 - << 'PYVERIFY'
import sys
import os
import json
import time
import subprocess
import requests
import jwt

SCORE_FILE = "/logs/verifier/reward.txt"

def fail(msg):
    print(f"[VERIFIER FAIL] {msg}")
    with open(SCORE_FILE, "w") as f:
        f.write("0.0\n")
    sys.exit(0)

# 1. Verify forensics report
report_path = "/workspace/mcp-gateway/forensics_report.json"
if not os.path.exists(report_path):
    fail("forensics_report.json does not exist")

try:
    with open(report_path, "r") as f:
        rep = json.load(f)
except Exception as e:
    fail(f"Invalid JSON in forensics_report.json: {e}")

expected_forensics = {
    "attacker_ip": "198.51.100.42",
    "forged_kid_payload": "../../../../etc/issue",
    "ssrf_redirect_url": "http://attacker-controlled.site/relay-metadata",
    "compromised_request_id": "req-9a7c3f82"
}

for k, expected_v in expected_forensics.items():
    if rep.get(k) != expected_v:
        fail(f"Forensics mismatch for '{k}': expected '{expected_v}', got '{rep.get(k)}'")

print("[VERIFIER PASS] Forensics report verified")

# 2. Start gateway server
server_proc = subprocess.Popen(["python3", "/workspace/mcp-gateway/app.py"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
time.sleep(1.5)

try:
    base_url = "http://127.0.0.1:5000"
    try:
        r = requests.get(f"{base_url}/healthz", timeout=3)
        if r.status_code != 200:
            fail(f"/healthz failed with status {r.status_code}")
    except Exception as e:
        fail(f"Could not connect to /healthz: {e}")

    # Generate valid tokens using legitimate key
    with open("/workspace/mcp-gateway/keys/default.key", "rb") as f:
        secret = f.read().strip()

    admin_token = jwt.encode({"user": "admin", "role": "admin"}, secret, algorithm="HS256", headers={"kid": "default.key"})
    viewer_token = jwt.encode({"user": "alice", "role": "viewer"}, secret, algorithm="HS256", headers={"kid": "default.key"})

    # 3. Functional verification
    # Legitimate read doc
    r = requests.post(f"{base_url}/api/v1/tools/read_file",
                      headers={"Authorization": f"Bearer {viewer_token}"},
                      json={"path": "architecture.md"},
                      timeout=3)
    if r.status_code != 200 or "MCP Tool Gateway" not in r.text:
        fail(f"Legitimate read_file failed: {r.status_code} {r.text}")

    # Legitimate diagnostic ping
    r = requests.post(f"{base_url}/api/v1/admin/exec_diagnostic",
                      headers={"Authorization": f"Bearer {admin_token}"},
                      json={"target": "127.0.0.1"},
                      timeout=5)
    if r.status_code != 200:
        fail(f"Legitimate admin exec_diagnostic failed: {r.status_code} {r.text}")

    # 4. Red-Team Exploit Suite
    # 4a. SSRF Protection (must return 400)
    ssrf_targets = [
        "http://127.0.0.1:5000/healthz",
        "http://localhost:5000/healthz",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/router",
        "http://172.16.0.1/"
    ]
    for ssrf_url in ssrf_targets:
        r = requests.post(f"{base_url}/api/v1/fetch",
                          headers={"Authorization": f"Bearer {viewer_token}"},
                          json={"url": ssrf_url},
                          timeout=3)
        if r.status_code != 400:
            fail(f"SSRF target was not rejected with HTTP 400: '{ssrf_url}' (got {r.status_code})")

    # 4b. Sandbox Path Traversal Protection
    traversal_paths = [
        os.path.join("..", "..", "..", "..", "workspace", "canary.txt"),
        "../../keys/default.key",
        "../keys/default.key",
        "/etc/passwd",
        "../../../../etc/issue"
    ]
    for trav in traversal_paths:
        r = requests.post(f"{base_url}/api/v1/tools/read_file",
                          headers={"Authorization": f"Bearer {viewer_token}"},
                          json={"path": trav},
                          timeout=3)
        if r.status_code not in (400, 403, 404):
            fail(f"Path traversal '{trav}' returned unexpected status: {r.status_code}")
        if "CANARY_SECRET" in r.text or "super-secret" in r.text or "root:" in r.text:
            fail(f"Path traversal '{trav}' leaked file contents!")

    # 4c. JWT Header Injection / Key Confusion Protection
    with open("/etc/issue", "rb") as f:
        issue_content = f.read().strip()
    forged_token = jwt.encode({"user": "attacker", "role": "admin"},
                              issue_content,
                              algorithm="HS256",
                              headers={"kid": "../../../../etc/issue"})

    r = requests.post(f"{base_url}/api/v1/admin/exec_diagnostic",
                      headers={"Authorization": f"Bearer {forged_token}"},
                      json={"target": "127.0.0.1"},
                      timeout=3)
    if r.status_code != 401:
        fail(f"Forged JWT with traversal kid was not rejected with 401: got {r.status_code}")

    none_alg_token = jwt.encode({"user": "attacker", "role": "admin"}, "", algorithm="none")
    r = requests.post(f"{base_url}/api/v1/admin/exec_diagnostic",
                      headers={"Authorization": f"Bearer {none_alg_token}"},
                      json={"target": "127.0.0.1"},
                      timeout=3)
    if r.status_code != 401:
        fail(f"JWT with algorithm 'none' was not rejected with 401: got {r.status_code}")

    # 4d. Command Injection Protection
    cmd_injections = [
        "127.0.0.1; cat /workspace/canary.txt",
        "127.0.0.1 && id",
        "127.0.0.1 | whoami",
        "`id`",
        "$(id)"
    ]
    for injection in cmd_injections:
        r = requests.post(f"{base_url}/api/v1/admin/exec_diagnostic",
                          headers={"Authorization": f"Bearer {admin_token}"},
                          json={"target": injection},
                          timeout=3)
        if "CANARY_SECRET" in r.text or "uid=" in r.text:
            fail(f"Command injection payload '{injection}' executed arbitrary code!")
        if r.status_code != 400:
            fail(f"Command injection payload '{injection}' did not return HTTP 400: got {r.status_code}")

    print("[VERIFIER PASS] All security and functionality tests passed")
    with open(SCORE_FILE, "w") as f:
        f.write("1.0\n")

finally:
    server_proc.terminate()
    try:
        server_proc.wait(timeout=2)
    except Exception:
        server_proc.kill()
PYVERIFY
