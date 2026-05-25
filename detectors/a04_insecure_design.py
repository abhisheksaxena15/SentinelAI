"""
detectors/a04_insecure_design.py
----------------------------------
OWASP A04:2021 — Insecure Design

Detects:
  - Missing security headers in responses
  - Overly verbose error messages leaking stack traces
  - Debug endpoints left exposed
  - Unrestricted file upload indicators
"""

import re
from typing import Optional

SENSITIVE_ENUM_PATHS = [
    "admin",
    "backup",
    "config",
    "debug",
    ".git",
    ".env",
    "phpinfo",
    "swagger",
    "graphql",
    "actuator",
]

REQUIRED_SECURITY_HEADERS = {
    "x-content-type-options":        "Prevents MIME-sniffing",
    "x-frame-options":               "Prevents clickjacking",
    "strict-transport-security":     "Enforces HTTPS",
    "content-security-policy":       "Prevents XSS",
    "x-xss-protection":              "Legacy XSS filter",
    "referrer-policy":               "Controls referrer leakage",
    "permissions-policy":            "Restricts browser features",
}

# Stack trace / error disclosure patterns
ERROR_PATTERNS = [
    re.compile(r"(?i)(traceback\s*\(most recent call last\)|stack trace|exception in)"),
    re.compile(r"(?i)(syntaxerror|nameerror|typeerror|valueerror)\s*:"),
    re.compile(r"(?i)(at\s+[\w$\.]+\([\w\.]+:\d+:\d+\))"),   # JS stack frame
    re.compile(r"(?i)(mysql_fetch|pg_query|ora-\d{5}|sql server)"),  # DB errors
]

DEBUG_PATHS = re.compile(
    r"(?i)/(debug|test|phpinfo|_profiler|swagger|openapi|graphql|__debug__|actuator)(/|$)"
)
DANGEROUS_UPLOADS = re.compile(
    r"(?i)(content-type:\s*(application/x-php|text/x-script|application/x-msdownload))"
)

SUSPICIOUS_PROBES = re.compile(
    r"(?i)(\.\./|etc/passwd|select.+from|union.+select|<script|169\.254\.169\.254)"
)

def detect(
    path: str,
    response_body: str,
    response_headers: dict,
    request_headers: dict,
) -> Optional[list]:

    findings = []
    lower_resp_headers = {k.lower(): v for k, v in response_headers.items()}

    # 1. Missing security headers
    missing = [
        f"{h} ({desc})"
        for h, desc in REQUIRED_SECURITY_HEADERS.items()
        if h not in lower_resp_headers
    ]
    if missing:
        findings.append({
            "owasp_id":    "A04",
            "owasp_name":  "Insecure Design",
            "threat_type": "Missing security response headers",
            "severity":    "MEDIUM",
            "risk_score":  50,
            "detail":      f"Headers absent: {', '.join(missing[:4])}{'...' if len(missing)>4 else ''}",
            "payload":     str(missing),
        })

    # 2. Stack trace / verbose error in response
    for pattern in ERROR_PATTERNS:
        match = pattern.search(response_body)
        if match:
            findings.append({
                "owasp_id":    "A04",
                "owasp_name":  "Insecure Design",
                "threat_type": "Verbose error / stack trace disclosure",
                "severity":    "HIGH",
                "risk_score":  70,
                "detail":      "Server returned a detailed error message or stack trace in the response.",
                "payload":     match.group(0)[:120],
            })
            break

    # 3. Debug / introspection endpoint accessed
    normalized_path = "/" + path.strip("/")
    if DEBUG_PATHS.search(normalized_path):
        findings.append({
            "owasp_id":    "A04",
            "owasp_name":  "Insecure Design",
            "threat_type": "Debug/introspection endpoint exposed",
            "severity":    "HIGH",
            "risk_score":  75,
            "detail":      f"Debug endpoint '{normalized_path}' is publicly accessible.",
            "payload":     normalized_path,
        })

    # 4. Dangerous file upload content-type
    all_headers_str = " ".join(f"{k}: {v}" for k, v in request_headers.items())
    match = DANGEROUS_UPLOADS.search(all_headers_str)
    if match:
        findings.append({
            "owasp_id":    "A04",
            "owasp_name":  "Insecure Design",
            "threat_type": "Dangerous file upload detected",
            "severity":    "HIGH",
            "risk_score":  80,
            "detail":      "Request uploads an executable or script file type.",
            "payload":     match.group(0),
        })

    combined = f"{path} {response_body}"

    if SUSPICIOUS_PROBES.search(combined):
        findings.append({
        "owasp_id": "A04",
        "owasp_name": "Insecure Design",
        "threat_type": "Suspicious attack reconnaissance",
        "severity": "HIGH",
        "risk_score": 70,
        "detail": "Attacker probing sensitive/internal application surfaces.",
        "payload": SUSPICIOUS_PROBES.search(combined).group(0),
    })

    # 5. Sensitive endpoint enumeration / reconnaissance
    normalized_path = path.lower()

    if response_body and any(p in normalized_path for p in SENSITIVE_ENUM_PATHS):

        findings.append({
            "owasp_id":    "A04",
            "owasp_name":  "Insecure Design",
            "threat_type": "Sensitive endpoint enumeration attempt",
            "severity":    "HIGH",
            "risk_score":  72,
            "detail":      f"Attacker probing sensitive/internal endpoint '{path}'.",
            "payload":     path,
        })

    return findings if findings else None
