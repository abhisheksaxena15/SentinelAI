"""
detectors/a08_integrity_failures.py
--------------------------------------
OWASP A08:2021 — Software and Data Integrity Failures

Detects:
  - Insecure deserialization patterns (pickle, Java serialized objects)
  - Mass assignment (over-posting) attempts
  - Unsigned / unverified data in critical fields
  - Suspicious __class__, __import__ in JSON (Python prototype pollution)
"""

import re
import json
from typing import Optional

# Java serialized object magic bytes (base64 encoded: rO0AB...)
JAVA_SERIAL_B64 = re.compile(r"rO0AB[A-Za-z0-9+/=]{10,}")

# Python pickle magic in base64 or raw
PYTHON_PICKLE = re.compile(r'(?i)(pickle\.loads|pickle\.load|cPickle|\.pkl)')

# PHP object injection
PHP_OBJECT = re.compile(r'O:\d+:"[A-Za-z_\\][\w\\]*":\d+:\{')

# Mass assignment / over-posting indicators
MASS_ASSIGN_FIELDS = re.compile(
    r'(?i)"(is_admin|role|is_staff|is_superuser|permissions|group_id|privilege|admin)"\s*:\s*(true|1|"admin"|"root"|"superadmin")'
)

# Python prototype / dunder injection
DUNDER_INJECTION = re.compile(
    r'(?i)(__class__|__import__|__globals__|__builtins__|__reduce__)'
)

# SSTI (Server-Side Template Injection) patterns
SSTI_PATTERNS = re.compile(
    r"(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|\#\{.*\})"
)
# Node.js prototype pollution
PROTOTYPE_POLLUTION = re.compile(
    r'(?i)(__proto__|prototype|constructor)'
)

# Suspicious package names / supply-chain attacks
PACKAGE_ATTACKS = re.compile(
    r'(?i)(event-stream|ua-parser-js|node-ipc|ctx|coa)'
)

# Base64-encoded PowerShell payloads
ENCODED_PAYLOADS = re.compile(
    r'(?i)(powershell\s+-enc|base64_decode|eval\s*\()'
)

def detect(request_body: str, query_params: str) -> Optional[list]:
    findings = []
    combined = f"{query_params} {request_body}"

    # 1. Java deserialization
    if JAVA_SERIAL_B64.search(request_body):
        findings.append({
            "owasp_id":    "A08",
            "owasp_name":  "Software and Data Integrity Failures",
            "threat_type": "Java deserialization attack",
            "severity":    "CRITICAL",
            "risk_score":  92,
            "detail":      "Request body contains Java serialized object (magic bytes rO0AB). Remote code execution risk.",
            "payload":     "rO0AB... (Java serialized object)",
        })

    # 2. PHP object injection
    match = PHP_OBJECT.search(request_body)
    if match:
        findings.append({
            "owasp_id":    "A08",
            "owasp_name":  "Software and Data Integrity Failures",
            "threat_type": "PHP object injection",
            "severity":    "CRITICAL",
            "risk_score":  90,
            "detail":      "PHP serialized object pattern found in request — possible RCE via __wakeup().",
            "payload":     match.group(0)[:80],
        })

    # 3. Python pickle / dunder injection
    if PYTHON_PICKLE.search(combined):
        findings.append({
            "owasp_id":    "A08",
            "owasp_name":  "Software and Data Integrity Failures",
            "threat_type": "Python pickle deserialization",
            "severity":    "CRITICAL",
            "risk_score":  90,
            "detail":      "Pickle-related keyword found — Python deserialization is RCE-capable.",
            "payload":     "pickle/cPickle reference",
        })

    match = DUNDER_INJECTION.search(request_body)
    if match:
        findings.append({
            "owasp_id":    "A08",
            "owasp_name":  "Software and Data Integrity Failures",
            "threat_type": "Python dunder / prototype injection",
            "severity":    "HIGH",
            "risk_score":  82,
            "detail":      "Python special attribute in request body — sandbox escape attempt.",
            "payload":     match.group(0)[:80],
        })

    # 4. Mass assignment / privilege escalation via JSON body
    match = MASS_ASSIGN_FIELDS.search(request_body)
    if match:
        findings.append({
            "owasp_id":    "A08",
            "owasp_name":  "Software and Data Integrity Failures",
            "threat_type": "Mass assignment / privilege escalation attempt",
            "severity":    "HIGH",
            "risk_score":  78,
            "detail":      "Privileged field (is_admin, role, etc.) found in request body — mass assignment attack.",
            "payload":     match.group(0)[:80],
        })

    # 5. SSTI
    match = SSTI_PATTERNS.search(combined)
    if match:
        findings.append({
            "owasp_id":    "A08",
            "owasp_name":  "Software and Data Integrity Failures",
            "threat_type": "Server-Side Template Injection (SSTI)",
            "severity":    "CRITICAL",
            "risk_score":  90,
            "detail":      "Template expression syntax detected in input — Jinja2/Twig/EL injection attempt.",
            "payload":     match.group(0)[:80],
        })
    
    # 6. Prototype pollution
    match = PROTOTYPE_POLLUTION.search(combined)
    if match:
        findings.append({
            "owasp_id": "A08",
            "owasp_name": "Software and Data Integrity Failures",
            "threat_type": "Prototype pollution attempt",
            "severity": "HIGH",
            "risk_score": 80,
            "detail": "Prototype pollution keywords detected in request.",
            "payload": match.group(0)
        })

    # 7. Supply chain package indicators
    match = PACKAGE_ATTACKS.search(combined)
    if match:
        findings.append({
            "owasp_id": "A08",
            "owasp_name": "Software and Data Integrity Failures",
            "threat_type": "Suspicious package reference",
            "severity": "MEDIUM",
            "risk_score": 65,
            "detail": "Known supply-chain attack package detected.",
            "payload": match.group(0)
        })

    # 8. Encoded payload execution
    match = ENCODED_PAYLOADS.search(combined)
    if match:
        findings.append({
            "owasp_id": "A08",
            "owasp_name": "Software and Data Integrity Failures",
            "threat_type": "Encoded execution payload",
            "severity": "CRITICAL",
            "risk_score": 92,
            "detail": "Encoded execution or code evaluation payload detected.",
            "payload": match.group(0)
        })

    return findings if findings else None
