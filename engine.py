"""
engine.py
---------
Central threat analysis orchestrator.
Calls all 10 OWASP detectors and returns a unified findings list.
Each finding is also persisted to SQLite and triggers alerts if HIGH/CRITICAL.
"""

import logging
from typing import Optional
from utils.database import log_threat
from utils.alerts import send_alert

from detectors import (
    a01_broken_access_control,
    a02_cryptographic_failures,
    a03_injection,
    a04_insecure_design,
    a05_security_misconfiguration,
    a06_vulnerable_components,
    a07_auth_failures,
    a08_integrity_failures,
    a09_logging_failures,
    a10_ssrf,
    rate_limiter,
)

logger = logging.getLogger(__name__)


def analyze(
    request_id: int,
    method: str,
    path: str,
    query_params: str,
    headers: dict,
    request_body: str,
    status_code: int,
    response_body: str,
    response_headers: dict,
    client_ip: str = "unknown",
) -> list:
    """
    Run all detectors. Returns list of finding dicts, each saved to DB.
    """
    all_findings = []

    def _collect(result):
        if result:
            if isinstance(result, list):
                all_findings.extend(result)
            else:
                all_findings.append(result)

    # ── A01: Broken Access Control ────────────────────────────────────────────
    _collect(a01_broken_access_control.detect(
        method=method, path=path, headers=headers,
        status_code=status_code, response_body=response_body,
    ))

    # ── A02: Cryptographic Failures ───────────────────────────────────────────
    _collect(a02_cryptographic_failures.detect(
        headers=headers, request_body=request_body,
        response_body=response_body, response_headers=response_headers,
    ))
    

    # ── A03: Injection ────────────────────────────────────────────────────────
    _collect(a03_injection.detect(
        request_body=request_body,
        query_params=query_params,
        path=path,
    ))

    # ── A04: Insecure Design ──────────────────────────────────────────────────
    _collect(a04_insecure_design.detect(
        path=path, response_body=response_body,
        response_headers=response_headers, request_headers=headers,
    ))

    # ── A05: Security Misconfiguration ────────────────────────────────────────
    _collect(a05_security_misconfiguration.detect(
        response_headers=response_headers,
        response_body=response_body,
        request_headers=headers,
    ))

    # ── A06: Vulnerable Components ────────────────────────────────────────────
    _collect(a06_vulnerable_components.detect(
        response_headers=response_headers,
        response_body=response_body,
        request_headers=headers,
    ))

    # ── A07: Auth Failures (JWT + brute force) ────────────────────────────────
    _collect(a07_auth_failures.detect(
        path=path, query_params=query_params, headers=headers,
        request_body=request_body, status_code=status_code, client_ip=client_ip,
    ))

    # ── A08: Integrity Failures ───────────────────────────────────────────────
    _collect(a08_integrity_failures.detect(
        request_body=request_body,
        query_params=query_params,
    ))

    # ── A09: Logging Failures ─────────────────────────────────────────────────
    _collect(a09_logging_failures.detect(
        method=method, path=path, headers=headers,
        request_body=request_body, status_code=status_code,
    ))

    # ── A10: SSRF ─────────────────────────────────────────────────────────────
    _collect(a10_ssrf.detect(
        path=path, query_params=query_params, request_body=request_body,
    ))

    # ── Rate Limiter (maps to A07) ────────────────────────────────────────────
    _collect(rate_limiter.detect(client_ip=client_ip, path=path))

    # ── Persist and alert ─────────────────────────────────────────────────────
    for finding in all_findings:
        finding["request_id"] = request_id
        try:
            log_threat(finding)
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
        try:
            send_alert(finding)
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    if all_findings:
        logger.warning(
            f"[{request_id}] {len(all_findings)} threat(s) detected on {method} {path}"
        )

    return all_findings
