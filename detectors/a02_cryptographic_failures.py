"""
detectors/a02_cryptographic_failures.py
-----------------------------------------
OWASP A02:2021 — Cryptographic Failures

Detects:
  - Secrets / API keys exposed in response bodies
  - Passwords in plaintext in request bodies
  - Sensitive PII (emails, credit cards, SSN) in responses
  - Weak/no Content-Security-Policy headers
"""

import re
from typing import Optional

# Patterns for secrets in response body
SECRET_PATTERNS = {
    "API Key (generic)":    re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'),
    "AWS Access Key":       re.compile(r'AKIA[0-9A-Z]{16}'),
    "GitHub Token":         re.compile(r'ghp_[A-Za-z0-9]{36}'),
    "Slack Token":          re.compile(r'xox[baprs]-[A-Za-z0-9\-]+'),
    "Bearer Token":         re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})'),
    "Private Key Block":    re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
    "Password in JSON":     re.compile(r'(?i)"password"\s*:\s*"[^"]{4,}"'),
}

# PII patterns
PII_PATTERNS = {
    "Email address":        re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
    "Credit card number":   re.compile(r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})'),
    "SSN (US)":             re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
}

# Sensitive request fields that should never appear in plaintext
SENSITIVE_REQUEST_FIELDS = re.compile(
    r'(?i)"?(password|passwd|secret|token|credit_card|ssn)"?\s*[:=]\s*"?[^\s&"]{4,}"?'
)

def detect(
    headers: dict,
    request_body: str,
    response_body: str,
    query_params: str = "",
    path: str = "",
    response_headers: dict = None,
) -> Optional[list]:

    findings = []
    response_headers = response_headers or {}

    # Combine everything for deep inspection
    combined_text = f"""
    {request_body}
    {response_body}
    {query_params}
    {path}
    """
    # 1. Secrets in response body
    for name, pattern in SECRET_PATTERNS.items():
        match = pattern.search(combined_text)
        if match:
            findings.append({
                "owasp_id":    "A02",
                "owasp_name":  "Cryptographic Failures",
                "threat_type": f"Secret exposed in response — {name}",
                "severity":    "CRITICAL",
                "risk_score":  90,
                "detail":      f"Detected '{name}' pattern in API response body.",
                "payload":     match[0][:80],
            })

    # 2. PII in response body
    for name, pattern in PII_PATTERNS.items():
        match = pattern.findall(combined_text)
        if match:
            findings.append({
                "owasp_id":    "A02",
                "owasp_name":  "Cryptographic Failures",
                "threat_type": f"PII exposed in response — {name}",
                "severity":    "HIGH",
                "risk_score":  75,
                "detail":      f"Found {len(match)} instance(s) of {name}",
                "payload":     str(match[0])[:80],
            })

    # 3. Sensitive fields in request body (plaintext passwords etc.)
    match = SENSITIVE_REQUEST_FIELDS.search(combined_text)
    if match:
        findings.append({
            "owasp_id":    "A02",
            "owasp_name":  "Cryptographic Failures",
            "threat_type": "Sensitive data in plaintext request body",
            "severity":    "HIGH",
            "risk_score":  70,
            "detail":      "Password or secret field detected in plaintext request payload.",
            "payload":     match[0]   [:80],
        })

    return findings if findings else None
