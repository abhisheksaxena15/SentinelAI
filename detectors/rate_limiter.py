"""
detectors/rate_limiter.py
--------------------------
Sliding window rate limiter — in-memory, no Redis needed.
Tracks requests per IP and per endpoint.
"""

from collections import defaultdict
from datetime import datetime
from typing import Optional
import os

WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_REQ = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", 100))

_ip_log: dict       = defaultdict(list)
_endpoint_log: dict = defaultdict(list)

def detect(client_ip: str, path: str) -> Optional[list]:
    now = datetime.utcnow().timestamp()
    findings = []

    # Prune old timestamps
    _ip_log[client_ip] = [t for t in _ip_log[client_ip] if now - t < WINDOW]
    _ip_log[client_ip].append(now)
    ip_count = len(_ip_log[client_ip])

    endpoint_key = f"{client_ip}:{path}"
    _endpoint_log[endpoint_key] = [t for t in _endpoint_log[endpoint_key] if now - t < WINDOW]
    _endpoint_log[endpoint_key].append(now)
    ep_count = len(_endpoint_log[endpoint_key])

    if ip_count > MAX_REQ:
        findings.append({
            "owasp_id":    "A07",
            "owasp_name":  "Authentication Failures",
            "threat_type": "Rate limit exceeded — possible DoS or scraping",
            "severity":    "HIGH" if ip_count < MAX_REQ * 2 else "CRITICAL",
            "risk_score":  min(55 + ip_count // 10, 95),
            "detail":      f"IP {client_ip} made {ip_count} requests in {WINDOW}s (limit: {MAX_REQ}).",
            "payload":     f"{client_ip} — {ip_count} req/{WINDOW}s",
        })

    # Endpoint-specific hammering (e.g. /login or /api/token)
    if ep_count > MAX_REQ // 5 and any(
        kw in path.lower() for kw in ("login", "auth", "token", "password", "signin")
    ):
        findings.append({
            "owasp_id":    "A07",
            "owasp_name":  "Authentication Failures",
            "threat_type": "Auth endpoint brute-force (rate)",
            "severity":    "CRITICAL",
            "risk_score":  90,
            "detail":      f"IP {client_ip} hit auth endpoint '{path}' {ep_count} times in {WINDOW}s.",
            "payload":     f"{client_ip}:{path} — {ep_count}×",
        })

    return findings if findings else None
