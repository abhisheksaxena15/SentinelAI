"""
tests/test_detectors.py
------------------------
Basic smoke tests for all OWASP detectors.
Run: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detectors import (
    a03_injection,
    a02_cryptographic_failures,
    a07_auth_failures,
    a10_ssrf,
    a05_security_misconfiguration,
)


# ── A03: Injection ────────────────────────────────────────────────────────────

def test_sqli_union_detected():
    result = a03_injection.detect(
        request_body="' UNION SELECT username,password FROM users--",
        query_params="",
        path="/search",
    )
    assert result is not None
    assert any("SQL Injection" in f["threat_type"] for f in result)

def test_xss_script_detected():
    result = a03_injection.detect(
        request_body='<script>alert("xss")</script>',
        query_params="",
        path="/comment",
    )
    assert result is not None
    assert any("XSS" in f["threat_type"] for f in result)

def test_cmd_injection_detected():
    result = a03_injection.detect(
        request_body="; cat /etc/passwd",
        query_params="",
        path="/exec",
    )
    assert result is not None
    assert any("Command Injection" in f["threat_type"] or "Sensitive file" in f["threat_type"] for f in result)

def test_clean_request_no_injection():
    result = a03_injection.detect(
        request_body='{"username": "alice", "action": "view_profile"}',
        query_params="page=1",
        path="/profile",
    )
    assert result is None


# ── A02: Cryptographic Failures ───────────────────────────────────────────────

def test_api_key_in_response():
    result = a02_cryptographic_failures.detect(
        headers={},
        request_body="",
        response_body='{"api_key": "sk-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"}',
    )
    assert result is not None
    assert any("Secret exposed" in f["threat_type"] for f in result)

def test_email_pii_in_response():
    result = a02_cryptographic_failures.detect(
        headers={},
        request_body="",
        response_body='{"email": "victim@example.com", "name": "Test User"}',
    )
    assert result is not None
    assert any("PII" in f["threat_type"] for f in result)


# ── A07: Auth Failures ────────────────────────────────────────────────────────

def test_jwt_alg_none():
    import base64, json
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').decode().rstrip("=")
    token = f"{header}.{payload}."
    result = a07_auth_failures.detect(
        path="/api/data",
        query_params="",
        headers={"authorization": f"Bearer {token}"},
        request_body="",
        status_code=200,
    )
    assert result is not None
    assert any("alg:none" in f["threat_type"] for f in result)

def test_token_in_url():
    result = a07_auth_failures.detect(
        path="/api/data",
        query_params="token=supersecrettoken123",
        headers={},
        request_body="",
        status_code=200,
    )
    assert result is not None
    assert any("URL" in f["threat_type"] for f in result)


# ── A10: SSRF ─────────────────────────────────────────────────────────────────

def test_ssrf_private_ip():
    result = a10_ssrf.detect(
        path="/fetch",
        query_params="url=http://192.168.1.1/admin",
        request_body="",
    )
    assert result is not None
    assert any("Private IP" in f["threat_type"] or "internal" in f["threat_type"].lower() for f in result)

def test_ssrf_cloud_metadata():
    result = a10_ssrf.detect(
        path="/proxy",
        query_params="",
        request_body='{"url": "http://169.254.169.254/latest/meta-data/"}',
    )
    assert result is not None
    assert any("metadata" in f["threat_type"].lower() for f in result)


# ── A05: Misconfiguration ─────────────────────────────────────────────────────

def test_cors_wildcard():
    result = a05_security_misconfiguration.detect(
        response_headers={"access-control-allow-origin": "*"},
        response_body="",
        request_headers={},
    )
    assert result is not None
    assert any("CORS" in f["threat_type"] for f in result)
