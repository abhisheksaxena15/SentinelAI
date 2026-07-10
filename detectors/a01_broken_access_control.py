"""
detectors/a01_broken_access_control.py
---------------------------------------
OWASP A01:2021 — Broken Access Control

Detects:
  - Forced browsing to admin/internal paths
  - HTTP verb tampering (unexpected methods on sensitive routes)
  - Missing or bypassed authorization headers
  - Insecure Direct Object Reference (IDOR) patterns
"""

import re
from typing import Optional

# Sensitive path patterns that should require auth
ADMIN_PATH_PATTERNS = [
    r"(?i)^/admin(/|$)",
    r"(?i)^/internal(/|$)",
    r"(?i)^/superuser(/|$)",
    r"(?i)^/manage(/|$)",
    r"(?i)^/dashboard(/|$)",
    r"(?i)^/config(/|$)",
    r"(?i)^/actuator(/|$)",
    r"(?i)^/debug(/|$)",
]
# IDOR: numeric IDs in URL paths — flag if auth header is absent
IDOR_PATTERN = re.compile(r"/\d{1,10}(/|$)")

# Methods that should not appear on sensitive paths
DANGEROUS_METHODS_ON_SAFE_PATHS = {"DELETE", "PUT", "PATCH"}

def detect(
    method: str,
    path: str,
    headers: dict,
    status_code: int,
    response_body: str,
) -> Optional[dict]:

    findings = []
    auth_present = bool(
        headers.get("authorization") or
        headers.get("x-api-key") or
        headers.get("cookie")
    )

    # 1. Access to sensitive/admin paths without auth
    for pattern in ADMIN_PATH_PATTERNS:
        if re.search(pattern, "/" + path.strip("/")):
            if not auth_present:
                findings.append({
                    "owasp_id":    "A01",
                    "owasp_name":  "Broken Access Control",
                    "threat_type": "Unauthenticated admin path access",
                    "severity":    "HIGH",
                    "risk_score":  80,
                    "detail":      f"Request to sensitive path '{path}' without any auth credentials.",
                    "payload":     path,
                })
            # If server returned 200 on admin path — even worse
        
            if status_code in [200, 201, 202, 301, 302] and not auth_present:       
                findings.append({
                    "owasp_id":    "A01",
                    "owasp_name":  "Broken Access Control",
                    "threat_type": "Unauthorized access granted (403 bypass)",
                    "severity":    "CRITICAL",
                    "risk_score":  95,
                    "detail":      f"Server returned 200 on admin path '{path}' with no auth — possible ACL bypass.",
                    "payload":     path,
                })

    # 2. IDOR — direct object reference in URL without auth
    if IDOR_PATTERN.search(path) and not auth_present:
        findings.append({
            "owasp_id":    "A01",
            "owasp_name":  "Broken Access Control",
            "threat_type": "Potential IDOR (Insecure Direct Object Reference)",
            "severity":    "MEDIUM",
            "risk_score":  55,
            "detail":      f"Numeric object ID found in path '{path}' with no authorization header.",
            "payload":     path,
        })

    # 3. Verb tampering on sensitive paths
    if method in DANGEROUS_METHODS_ON_SAFE_PATHS:
        for pattern in ADMIN_PATH_PATTERNS:
            if re.search(pattern, path):
                findings.append({
                    "owasp_id":    "A01",
                    "owasp_name":  "Broken Access Control",
                    "threat_type": "HTTP verb tampering on admin path",
                    "severity":    "HIGH",
                    "risk_score":  75,
                    "detail":      f"Method {method} used on sensitive path '{path}'.",
                    "payload":     f"{method} {path}",
                })

    return findings if findings else None
