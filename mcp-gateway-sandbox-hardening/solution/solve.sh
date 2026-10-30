#!/usr/bin/env bash
set -euo pipefail

cd /workspace/mcp-gateway

# Part 1: Write forensics report
cat << 'EOF_REPORT' > /workspace/mcp-gateway/forensics_report.json
{
  "attacker_ip": "198.51.100.42",
  "forged_kid_payload": "../../../../etc/issue",
  "ssrf_redirect_url": "http://attacker-controlled.site/relay-metadata",
  "compromised_request_id": "req-9a7c3f82"
}
EOF_REPORT

# Part 2: Patch and harden app.py
cat << 'EOF_HARDENED' > /workspace/mcp-gateway/app.py
import os
import re
import socket
import ipaddress
import subprocess
import requests
import jwt
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)
KEYS_DIR = os.path.realpath("/workspace/mcp-gateway/keys")
DOCS_DIR = os.path.realpath("/workspace/sandbox_docs")

KID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9]+)?$")
TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-]+$")

def is_forbidden_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True

def validate_url_safe(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Unsupported scheme"
        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname"
        
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_forbidden_ip(ip_str):
                return False, f"Forbidden IP target: {ip_str}"
        return True, ""
    except Exception as e:
        return False, str(e)

class SafeRedirectSession(requests.Session):
    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None, yield_requests=False, **kwargs):
        for redirect_req in super().resolve_redirects(resp, req, stream=stream, timeout=timeout,
                                                      verify=verify, cert=cert, proxies=proxies,
                                                      yield_requests=True, **kwargs):
            safe, err = validate_url_safe(redirect_req.url)
            if not safe:
                raise requests.exceptions.RequestException(f"SSRF in redirect: {err}")
            if yield_requests:
                yield redirect_req
            else:
                resp = self.send(
                    redirect_req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    **kwargs
                )
                yield resp

def verify_token(token):
    if not token:
        return None
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if alg != "HS256":
            return None
        
        kid = header.get("kid", "default.key")
        if not KID_PATTERN.match(kid):
            return None
        
        resolved_key_path = os.path.realpath(os.path.join(KEYS_DIR, kid))
        if not resolved_key_path.startswith(KEYS_DIR + os.sep) and resolved_key_path != KEYS_DIR:
            return None
        if not os.path.isfile(resolved_key_path):
            return None
        
        with open(resolved_key_path, "rb") as f:
            secret = f.read().strip()
            
        return jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        return None

def get_auth_claims():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    return verify_token(token)

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})

@app.route("/api/v1/fetch", methods=["POST"])
def fetch_url():
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing url"}), 400
    
    safe, reason = validate_url_safe(url)
    if not safe:
        return jsonify({"error": f"Invalid URL target: {reason}"}), 400
    
    try:
        session = SafeRedirectSession()
        resp = session.get(url, timeout=5, allow_redirects=True)
        return jsonify({"content": resp.text[:4096], "status_code": resp.status_code})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/v1/tools/read_file", methods=["POST"])
def read_doc():
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    rel_path = data.get("path", "").strip()
    if not rel_path:
        return jsonify({"error": "Missing path"}), 400
    
    resolved_path = os.path.realpath(os.path.join(DOCS_DIR, rel_path))
    if not resolved_path.startswith(DOCS_DIR + os.sep):
        return jsonify({"error": "Forbidden: Path traversal outside sandbox"}), 403
    if not os.path.isfile(resolved_path):
        return jsonify({"error": "File not found"}), 404
        
    try:
        with open(resolved_path, "r", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/admin/exec_diagnostic", methods=["POST"])
def exec_diag():
    claims = get_auth_claims()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
    if claims.get("role") != "admin":
        return jsonify({"error": "Forbidden: Requires admin"}), 403
        
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target or not TARGET_PATTERN.match(target):
        return jsonify({"error": "Invalid diagnostic target"}), 400
    
    proc = subprocess.run(["ping", "-c", "1", "-W", "1", target], capture_output=True, text=True)
    return jsonify({"output": proc.stdout or proc.stderr, "exit_code": proc.returncode})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
EOF_HARDENED
