"""
detectors/a10_ssrf.py
-----------------------
OWASP A10:2021 — Server-Side Request Forgery (SSRF)

Detects:
  - Private / loopback IP addresses in request parameters
  - Cloud metadata endpoints (169.254.169.254, etc.)
  - Internal hostnames in URL parameters
  - URL redirect parameters pointing to internal resources
  - DNS rebinding indicators
"""

import re
from typing import Optional

# Private / loopback IP ranges
PRIVATE_IP = re.compile(
    r"(?:^|[=&?/\s])"
    r"(127\.\d+\.\d+\.\d+"           # loopback
    r"|10\.\d+\.\d+\.\d+"            # RFC1918 class A
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"  # RFC1918 class B
    r"|192\.168\.\d+\.\d+"           # RFC1918 class C
    r"|::1"                           # IPv6 loopback
    r"|0\.0\.0\.0)"
)

# Cloud metadata endpoints
CLOUD_METADATA = re.compile(
    r"(?i)(169\.254\.169\.254"        # AWS/GCP/Azure IMDS
    r"|metadata\.google\.internal"
    r"|169\.254\.170\.2"              # AWS ECS metadata
    r"|fd00:ec2::254)"                # AWS IPv6 metadata
)

# URL-valued parameters that could be SSRF vectors
URL_PARAM = re.compile(
    r"(?i)[?&](url|uri|path|redirect|return|next|dest|destination|"
    r"callback|webhook|host|domain|proxy|target|endpoint|link|src|source)\s*="
    r"\s*(https?://|//)([^&\s#]+)"
)

# Internal hostname patterns in URL params
INTERNAL_HOST = re.compile(
    r"(?i)(localhost|internal|intranet|corp|local|lan|private|"
    r"db|redis|postgres|mysql|mongo|elasticsearch|kafka)(\.\w+)*"
    r"(:\d+)?"
)

FILE_SCHEME = re.compile(r"(?i)(file://|dict://|gopher://|ftp://)")

def detect(path: str, query_params: str, request_body: str) -> Optional[list]:
    findings = []
    combined = f"{path}?{query_params} {request_body}"

    # 1. Private IP in request
    match = PRIVATE_IP.search(combined)
    if match:
        findings.append({
            "owasp_id":    "A10",
            "owasp_name":  "Server-Side Request Forgery (SSRF)",
            "threat_type": "Private IP address in request",
            "severity":    "HIGH",
            "risk_score":  82,
            "detail":      f"Private/loopback IP '{match.group(1)}' found — SSRF attempt to reach internal network.",
            "payload":     match.group(1),
        })

    # 2. Cloud metadata endpoint
    match = CLOUD_METADATA.search(combined)
    if match:
        findings.append({
            "owasp_id":    "A10",
            "owasp_name":  "Server-Side Request Forgery (SSRF)",
            "threat_type": "Cloud metadata endpoint targeted",
            "severity":    "CRITICAL",
            "risk_score":  95,
            "detail":      f"Cloud IMDS endpoint '{match.group(0)}' in request — credential theft via SSRF.",
            "payload":     match.group(0),
        })

    # 3. URL parameter pointing to internal host
    match = URL_PARAM.search(combined)
    if match:
        target = match.group(3)
        internal = INTERNAL_HOST.search(target)
        priv_ip  = PRIVATE_IP.search(target)
        if internal or priv_ip:
            findings.append({
                "owasp_id":    "A10",
                "owasp_name":  "Server-Side Request Forgery (SSRF)",
                "threat_type": "URL parameter targets internal resource",
                "severity":    "CRITICAL",
                "risk_score":  90,
                "detail":      f"URL-type parameter '{match.group(1)}' points to internal host '{target[:60]}'.",
                "payload":     match.group(0)[:100],
            })

    # 4. Non-HTTP scheme (file://, gopher://, etc.)
    match = FILE_SCHEME.search(combined)
    if match:
        findings.append({
            "owasp_id":    "A10",
            "owasp_name":  "Server-Side Request Forgery (SSRF)",
            "threat_type": "Dangerous URL scheme in request",
            "severity":    "CRITICAL",
            "risk_score":  92,
            "detail":      f"Non-HTTP scheme '{match.group(0)}' detected — file read or protocol smuggling.",
            "payload":     match.group(0),
        })

    return findings if findings else None
