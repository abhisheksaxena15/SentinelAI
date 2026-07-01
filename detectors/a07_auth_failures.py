"""
detectors/a07_auth_failures.py
--------------------------------
OWASP A07:2021 — Identification and Authentication Failures

Detects:
  - Missing or malformed JWT tokens
  - Weak/default credentials in requests
  - Brute-force indicators (repeated 401 responses)
  - Token in URL (insecure token transmission)
  - JWT algorithm confusion (alg: none)
"""

import re
import json
import base64
from typing import Optional
from collections import defaultdict
from datetime import datetime

# In-memory: track 401 count per IP in the last 60 seconds
_auth_fail_log: dict = defaultdict(list)

# WEAK_CREDENTIALS = re.compile(
#     r"(?i)(username|user|login)\s*[:=]\s*(admin|root|test|guest|user|administrator).*"
#     r"(password|pass|pwd)\s*[:=]\s*(admin|password|1234|123456|test|root|guest|letmein)"
# )
WEAK_CREDENTIALS = re.compile(
    r'(?i)(admin|root|guest|test).{0,50}(admin|password|123456|guest|root|letmein)'
)
TOKEN_IN_URL = re.compile(
    r"(?i)[?&](token|api_key|apikey|access_token|secret|key)\s*=\s*[^&\s]{8,}"
)

def _decode_jwt_header(token: str) -> Optional[dict]:
    try:
        header_b64 = token.split(".")[0]
        padding = 4 - len(header_b64) % 4
        decoded = base64.urlsafe_b64decode(header_b64 + "=" * padding)
        return json.loads(decoded)
    except Exception:
        return None

def detect(
    path: str,
    query_params: str,
    headers: dict,
    request_body: str,
    status_code: int,
    client_ip: str = "unknown",
) -> Optional[list]:

    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    auth_header = (
        lower_headers.get("authorization")
        or lower_headers.get("x-access-token")
        or lower_headers.get("x-auth-token")
        or ""
    )
    # 1. Token / API key in URL query params (credential exposure in logs)
    match = TOKEN_IN_URL.search(f"{path}?{query_params}")
    if match:
        findings.append({
            "owasp_id":    "A07",
            "owasp_name":  "Authentication Failures",
            "threat_type": "Token transmitted in URL",
            "severity":    "HIGH",
            "risk_score":  75,
            "detail":      "Auth token or API key found in URL query string — appears in server logs.",
            "payload":     match.group(0)[:80],
        })

    # 2. JWT — alg:none or suspicious header
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
        header = _decode_jwt_header(token)
        if header:
            alg = header.get("alg", "").lower()
            if alg == "none":
                findings.append({
                    "owasp_id":    "A07",
                    "owasp_name":  "Authentication Failures",
                    "threat_type": "JWT with alg:none (unsigned token)",
                    "severity":    "CRITICAL",
                    "risk_score":  95,
                    "detail":      "JWT presents alg:none — token signature is bypassed entirely.",
                    "payload":     f"alg: {header.get('alg')}",
                })
            if alg in ("hs256", "hs384", "hs512") and header.get("kid"):
                findings.append({
                    "owasp_id":    "A07",
                    "owasp_name":  "Authentication Failures",
                    "threat_type": "JWT kid injection risk",
                    "severity":    "HIGH",
                    "risk_score":  80,
                    "detail":      "JWT contains 'kid' header — potential SQL/path injection via kid parameter.",
                    "payload":     f"kid: {header.get('kid')}",
                })

    # 3. Weak/default credentials in request body
    match = WEAK_CREDENTIALS.search(request_body)
    if match:
        findings.append({
            "owasp_id":    "A07",
            "owasp_name":  "Authentication Failures",
            "threat_type": "Weak / default credentials detected",
            "severity":    "HIGH",
            "risk_score":  80,
            "detail":      "Request body contains known weak or default username/password combination.",
            "payload":     match.group(0)[:80],
        })

    # 4. Brute-force detection: multiple 401s from same IP
    now = datetime.utcnow().timestamp()
    if status_code == 401:
        _auth_fail_log[client_ip] = [
            t for t in _auth_fail_log[client_ip] if now - t < 60
        ]
        _auth_fail_log[client_ip].append(now)
        count = len(_auth_fail_log[client_ip])
        if count >= 5:
            findings.append({
                "owasp_id":    "A07",
                "owasp_name":  "Authentication Failures",
                "threat_type": "Brute-force / credential stuffing",
                "severity":    "HIGH" if count < 15 else "CRITICAL",
                "risk_score":  min(60 + count * 2, 95),
                "detail":      f"IP {client_ip} triggered {count} auth failures in the last 60 seconds.",
                "payload":     f"{client_ip} — {count} × 401",
            })

    return findings if findings else None
