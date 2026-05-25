"""
detectors/a05_security_misconfiguration.py
--------------------------------------------
OWASP A05:2021 — Security Misconfiguration

Detects:
  - Server/framework version disclosed in response headers
  - Directory listing enabled (HTML response contains "Index of /")
  - CORS wildcard (*) misconfiguration
  - Insecure cookie flags (missing HttpOnly, Secure, SameSite)
  - HTTP used instead of HTTPS (detected from headers)
"""

import re
from typing import Optional

SERVER_DISCLOSURE = re.compile(
    r"(?i)(apache/\d|nginx/\d|express|flask/\d|django/\d|php/\d|iis/\d)"
)

DIRECTORY_LISTING = re.compile(
    r"(?i)(index of /|parent directory|directory listing for|listing directory)"
)
INSECURE_COOKIE = re.compile(
    r"(?i)set-cookie\s*:[^\n]+"
)


DANGEROUS_METHODS = {
    "TRACE",
    "OPTIONS",
}

def detect(
    method: str,
    response_headers: dict,
    response_body: str,
    request_headers: dict,
) -> Optional[list]:

    findings = []
    lower_h = {k.lower(): v for k, v in response_headers.items()}

    # 1. Server version disclosure
    server_val = lower_h.get("server", "") + " " + lower_h.get("x-powered-by", "")
    match = SERVER_DISCLOSURE.search(server_val)
    if match:
        findings.append({
            "owasp_id":    "A05",
            "owasp_name":  "Security Misconfiguration",
            "threat_type": "Server version disclosed in headers",
            "severity":    "LOW",
            "risk_score":  35,
            "detail":      f"Response headers disclose backend technology: '{server_val}'",
            "payload":     server_val[:120],
        })

    # 2. Directory listing
    if DIRECTORY_LISTING.search(response_body):
        findings.append({
            "owasp_id":    "A05",
            "owasp_name":  "Security Misconfiguration",
            "threat_type": "Directory listing enabled",
            "severity":    "HIGH",
            "risk_score":  72,
            "detail":      "Server responded with a directory index page — directory listing is ON.",
            "payload":     "Index of /",
        })

    # 3. CORS wildcard
    cors = lower_h.get("access-control-allow-origin", "")
    if cors.strip() == "*":
        findings.append({
            "owasp_id":    "A05",
            "owasp_name":  "Security Misconfiguration",
            "threat_type": "CORS wildcard misconfiguration",
            "severity":    "MEDIUM",
            "risk_score":  55,
            "detail":     f"Access-Control-Allow-Origin is dangerously permissive: '{cors}'",
            "payload":     f"Access-Control-Allow-Origin: {cors}",
        })

    # 4. Insecure Set-Cookie flags
    for key, val in response_headers.items():
        if key.lower() == "set-cookie":
            cookie_lower = val.lower()
            missing_flags = []
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append({
                    "owasp_id":    "A05",
                    "owasp_name":  "Security Misconfiguration",
                    "threat_type": "Insecure cookie configuration",
                    "severity":    "MEDIUM",
                    "risk_score":  50,
                    "detail":      f"Cookie missing flags: {', '.join(missing_flags)}",
                    "payload":     val[:120],
                })
    # 5. HTTP instead of HTTPS
    forwarded_proto = request_headers.get("x-forwarded-proto", "")
    if forwarded_proto and forwarded_proto.lower() == "http":
        findings.append({
            "owasp_id":    "A05",
            "owasp_name":  "Security Misconfiguration",
        "threat_type": "Insecure HTTP transport",
        "severity":    "MEDIUM",
        "risk_score":  60,
       "detail":      f"HTTP method '{method}' may expose unsafe functionality.",
        "payload":     method,
    })
        # =========================================================
    # 6. Dangerous HTTP methods exposed
    # =========================================================

    if method.upper() in DANGEROUS_METHODS:

        findings.append({
            "owasp_id":    "A05",
            "owasp_name":  "Security Misconfiguration",
            "threat_type": "Dangerous HTTP method enabled",
            "severity":    "HIGH",
            "risk_score":  70,
            "detail":      f"HTTP method '{method}' may expose unsafe functionality.",
            "payload":     method,
        })
        
    return findings if findings else None
