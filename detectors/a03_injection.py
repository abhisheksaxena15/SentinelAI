"""
detectors/a03_injection.py
---------------------------
OWASP A03:2021 — Injection

Detects:
  - SQL Injection (error-based, union-based, blind, tautology)
  - XSS (reflected, DOM, event handlers)
  - Command injection (OS shell metacharacters)
  - LDAP injection
  - NoSQL injection (MongoDB operators)
"""

import re
from typing import Optional

# ── SQL Injection ────────────────────────────────────────────────────────────
SQLI_PATTERNS = [
    (re.compile(r"(?i)(\bunion\b.{0,20}\bselect\b)"),            "UNION-based SQLi",   90),
    (re.compile(r"(?i)(\bdrop\s+table\b)"),                      "DDL injection",      95),
    (re.compile(r"(?i)(\bor\b\s+[\w'\"]+\s*=\s*[\w'\"]+)"),     "Tautology (OR 1=1)", 80),
    (re.compile(r"(?i)(\band\b\s+[\w'\"]+\s*=\s*[\w'\"]+)"),    "Tautology (AND)",    75),
    (re.compile(r"('|%27)\s*(--|#|%23)"),                        "Comment injection",  70),
    (re.compile(r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\()"), "Time-based blind",   85),
    (re.compile(r"(?i)(into\s+outfile|load_file\s*\()"),         "File read/write",    90),
    (re.compile(r"(?i)(select.+from\s+information_schema)"),     "Schema enumeration", 85),
]

# ── XSS ───────────────────────────────────────────────────────────────────────
XSS_PATTERNS = [
    (re.compile(r"(?i)<script[\s>]"),                                 "Script tag injection",   85),
    (re.compile(r"(?i)javascript\s*:"),                               "JavaScript URI",         80),
    (re.compile(r"(?i)on(error|load|click|mouseover|focus)\s*="),    "Event handler injection", 80),
    (re.compile(r"(?i)<(iframe|object|embed|applet|meta|link)[\s>]"), "HTML tag injection",     75),
    (re.compile(r"(?i)(alert|confirm|prompt)\s*\("),                  "JS dialog injection",    70),
    (re.compile(r"(?i)document\.(cookie|domain|location)"),           "DOM manipulation",       80),
    (re.compile(r"(?i)<img[^>]+src\s*=\s*['\"]?javascript"),         "Image XSS",              85),
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMD_PATTERNS = [
    (re.compile(r"[;&|`$]\s*(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby)"),
     "OS command injection",   90),
    (re.compile(r"(\.\./){2,}"),                                      "Path traversal",         80),
    (re.compile(r"(?i)/etc/(passwd|shadow|hosts|sudoers)"),           "Sensitive file read",    85),
    (re.compile(r"(?i)(cmd\.exe|powershell|/bin/(ba)?sh)"),           "Shell execution",        90),
]

# ── NoSQL Injection ───────────────────────────────────────────────────────────
NOSQL_PATTERNS = [
    (re.compile(r"(?i)(\$where|\$gt|\$ne|\$regex|\$or|\$and)\s*[:{]"), "MongoDB operator injection", 80),
    (re.compile(r"(?i)\{\s*\$[a-z]+\s*:"),                             "NoSQL operator in body",    75),
]

# ── LDAP Injection ────────────────────────────────────────────────────────────
LDAP_PATTERNS = [
    (re.compile(r"[)(|*\\]"),  "LDAP metacharacters", 65),
]

def _scan(text: str, patterns: list, category: str) -> list:
    findings = []
    for pattern, name, score in patterns:
        match = pattern.search(text)
        if match:
            findings.append({
                "owasp_id":    "A03",
                "owasp_name":  "Injection",
                "threat_type": f"{category} — {name}",
                "severity":    "CRITICAL" if score >= 90 else "HIGH" if score >= 75 else "MEDIUM",
                "risk_score":  score,
                "detail":      f"Injection pattern '{name}' found in request payload.",
                "payload":     match.group(0)[:120],
            })
    return findings

def detect(
    request_body: str, query_params: str, path: str, headers: str = "", cookies: str = "" ) -> Optional[list]:
    combined = f""" {path} {query_params} {request_body} {headers} {cookies} """
    findings = []
    findings += _scan(combined, SQLI_PATTERNS,  "SQL Injection")
    findings += _scan(combined, XSS_PATTERNS,   "XSS")
    findings += _scan(combined, CMD_PATTERNS,   "Command Injection")
    findings += _scan(combined, NOSQL_PATTERNS, "NoSQL Injection")
    findings += _scan(combined, LDAP_PATTERNS,  "LDAP Injection")
    # Deduplicate by threat_type
    seen = set()
    unique = []
    for f in findings:
        if f["threat_type"] not in seen:
            seen.add(f["threat_type"])
            unique.append(f)
    return unique if unique else None
