"""
detectors/a09_logging_failures.py
------------------------------------
OWASP A09:2021 — Security Logging and Monitoring Failures

This detector is meta — SentinelAI IS the logging layer.
It flags:
  - Requests with no User-Agent (likely automated scanners)
  - Abnormally large request bodies (potential DoS / log flooding)
  - Requests that produce 5xx errors (server-side failures worth tracking)
  - Unusually long URL paths (path-based scanner probes)
"""

from typing import Optional

MAX_BODY_SIZE   = 1_000_000   # 1 MB
MAX_PATH_LENGTH = 512

def detect(
    method: str,
    path: str,
    headers: dict,
    request_body: str,
    status_code: int,
) -> Optional[list]:

    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    user_agent = lower_headers.get("user-agent", "")

    # 1. Missing User-Agent — common in scanners/scripts
    if not user_agent:
        findings.append({
            "owasp_id":    "A09",
            "owasp_name":  "Security Logging and Monitoring Failures",
            "threat_type": "Missing User-Agent (possible automated scanner)",
            "severity":    "LOW",
            "risk_score":  30,
            "detail":      "Request arrived with no User-Agent header — typical of automated tools.",
            "payload":     f"{method} {path}",
        })

    # 2. Known scanner User-Agents
    scanner_keywords = ("sqlmap", "nikto", "nessus", "burpsuite", "zgrab",
                        "masscan", "nmap", "dirbuster", "gobuster", "wfuzz")
    if any(kw in user_agent.lower() for kw in scanner_keywords):
        findings.append({
            "owasp_id":    "A09",
            "owasp_name":  "Security Logging and Monitoring Failures",
            "threat_type": "Known security scanner detected",
            "severity":    "HIGH",
            "risk_score":  80,
            "detail":      f"User-Agent matches known scanner: '{user_agent[:80]}'",
            "payload":     user_agent[:80],
        })

    # 3. Abnormally large request body
    if len(request_body) > MAX_BODY_SIZE:
        findings.append({
            "owasp_id":    "A09",
            "owasp_name":  "Security Logging and Monitoring Failures",
            "threat_type": "Abnormally large request body",
            "severity":    "MEDIUM",
            "risk_score":  45,
            "detail":      f"Request body is {len(request_body):,} bytes — potential DoS or log flooding.",
            "payload":     f"{len(request_body):,} bytes",
        })

    # 4. Server-side errors (5xx) — unhandled exceptions worth investigating
    if 500 <= status_code < 600:
        findings.append({
            "owasp_id":    "A09",
            "owasp_name":  "Security Logging and Monitoring Failures",
            "threat_type": f"Server error {status_code} — unhandled exception",
            "severity":    "MEDIUM",
            "risk_score":  50,
            "detail":      f"Target API returned HTTP {status_code} — may indicate triggered vulnerability.",
            "payload":     f"HTTP {status_code} on {method} {path}",
        })

    # 5. Abnormally long URL path (scanner fuzzing / path traversal probing)
    if len(path) > MAX_PATH_LENGTH:
        findings.append({
            "owasp_id":    "A09",
            "owasp_name":  "Security Logging and Monitoring Failures",
            "threat_type": "Abnormally long URL path",
            "severity":    "LOW",
            "risk_score":  35,
            "detail":      f"Path length is {len(path)} characters — scanner fuzzing indicator.",
            "payload":     path[:120] + "...",
        })

    return findings if findings else None
