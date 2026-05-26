"""
detectors/a06_vulnerable_components.py
----------------------------------------
OWASP A06:2021 — Vulnerable and Outdated Components

Detects:
  - Known vulnerable library versions from response headers
  - Outdated jQuery, Bootstrap versions in HTML responses
  - Deprecated/EOL framework signatures
"""

import re
from typing import Optional

# Format: (regex_pattern, component_name, note)
VULNERABLE_VERSIONS = [
    # jQuery < 3.5.0 — multiple XSS CVEs
    (re.compile(r"jquery[/-]?(1\.[0-9]\.|2\.[0-2]\.|3\.[0-4]\.)", re.I),
     "jQuery < 3.5.0", "CVE-2020-11022 / XSS vulnerabilities"),

    # Bootstrap < 4.3.1
    (re.compile(r"bootstrap[/-]?(3\.[0-3]\.|4\.[0-2]\.)", re.I),
     "Bootstrap < 4.3.1", "CVE-2019-8331 / XSS in tooltip"),

    # Angular < 12
    (re.compile(r"angular[/-]?(1\.|2\.|3\.|4\.|5\.|6\.|7\.|8\.|9\.|10\.|11\.)", re.I),
     "AngularJS / Angular < 12", "Multiple template injection CVEs"),

    # Log4j via User-Agent / headers (Log4Shell)
    (re.compile(r"\$\{jndi:", re.I),
     "Log4Shell (CVE-2021-44228)", "Critical RCE — Log4j JNDI injection"),

    # PHP old versions in Server header
    (re.compile(r"php/(5\.|7\.[0-3]\.)", re.I),
     "PHP < 7.4 (EOL)", "End-of-life PHP version — no security patches"),

    # Apache Struts 2 (CVE-2017-5638)
    (re.compile(r"struts2?[/-]?(2\.[0-4]\.|2\.5\.0)", re.I),
     "Apache Struts < 2.5.10", "CVE-2017-5638 / Equifax breach RCE"),

    # OpenSSL old — from Server/Via headers
    (re.compile(r"openssl/(0\.|1\.0\.)", re.I),
     "OpenSSL < 1.1.1 (EOL)", "Heartbleed era or end-of-life OpenSSL"),
]

def detect(
    response_headers: dict,
    response_body: str,
    request_headers: dict,
) -> Optional[list]:

    findings = []
    all_text = (
        " ".join(f"{k}: {v}" for k, v in response_headers.items()) + " " +
        " ".join(f"{k}: {v}" for k, v in request_headers.items()) + " " +
        response_body[:5000]   # scan first 5KB of HTML for <script src="...">
    )

    for pattern, component, note in VULNERABLE_VERSIONS:
        match = pattern.search(all_text)
        if match:
            findings.append({
                "owasp_id":    "A06",
                "owasp_name":  "Vulnerable and Outdated Components",
                "threat_type": f"Vulnerable component: {component}",
                "severity":    "HIGH",
                "risk_score":  78,
                "detail":      f"{component} detected. {note}",
                "payload":     match.group(0)[:80],
            })

    return findings if findings else None

###
# """
# detectors/a06_vulnerable_components.py
# ----------------------------------------
# OWASP A06:2021 — Vulnerable and Outdated Components

# Detects:
#   - Vulnerable frontend libraries
#   - Outdated server frameworks
#   - Log4Shell payload attempts
#   - Vulnerable PHP/OpenSSL versions
#   - CDN-disclosed vulnerable JS libraries
# """

# import re
# from typing import Optional

# # =========================================================
# # Vulnerable component patterns
# # Format:
# # (pattern, component, note, severity, risk_score)
# # =========================================================

# VULNERABLE_VERSIONS = [

#     # jQuery < 3.5.0
#     (
#         re.compile(
#             r"jquery(?:[-/ ]|\.min\.js| v)?(1\.\d+|2\.[0-2]\d*|3\.[0-4]\d*)",
#             re.I
#         ),
#         "jQuery < 3.5.0",
#         "CVE-2020-11022 / XSS vulnerabilities",
#         "HIGH",
#         80
#     ),

#     # Bootstrap < 4.3.1
#     (
#         re.compile(
#             r"bootstrap(?:[-/ ]|\.min\.css|\.min\.js| v)?(3\.[0-3]\d*|4\.[0-2]\d*)",
#             re.I
#         ),
#         "Bootstrap < 4.3.1",
#         "CVE-2019-8331 / XSS in tooltip",
#         "HIGH",
#         75
#     ),

#     # Angular old versions
#     (
#         re.compile(
#             r"angular(?:js)?(?:[-/ ]| v)?(1\d?|[2-9]|10|11)\.",
#             re.I
#         ),
#         "AngularJS / Angular < 12",
#         "Multiple template injection vulnerabilities",
#         "HIGH",
#         78
#     ),

#     # Log4Shell payload
#     (
#         re.compile(r"\$\{jndi:", re.I),
#         "Log4Shell (CVE-2021-44228)",
#         "Critical RCE attempt detected",
#         "CRITICAL",
#         98
#     ),

#     # Old PHP versions
#     (
#         re.compile(
#             r"php[/ ](5\.\d+|7\.[0-3]\d*)",
#             re.I
#         ),
#         "PHP < 7.4 (EOL)",
#         "End-of-life PHP version detected",
#         "HIGH",
#         82
#     ),

#     # Apache Struts
#     (
#         re.compile(
#             r"struts2?(?:[-/ ]| v)?(2\.[0-4]\d*|2\.5\.0)",
#             re.I
#         ),
#         "Apache Struts < 2.5.10",
#         "CVE-2017-5638 / Equifax breach RCE",
#         "CRITICAL",
#         95
#     ),

#     # OpenSSL
#     (
#         re.compile(
#             r"openssl/(0\.|1\.0\.)",
#             re.I
#         ),
#         "OpenSSL < 1.1.1",
#         "Outdated OpenSSL / possible Heartbleed-era crypto",
#         "HIGH",
#         85
#     ),
# ]

# # =========================================================
# # CDN references
# # =========================================================

# CDN_PATTERNS = re.compile(
#     r"(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com)",
#     re.I
# )

# # =========================================================
# # Script source detection
# # =========================================================

# SCRIPT_VERSION_PATTERN = re.compile(
#     r'<script[^>]+src=["\'][^"\']*(jquery|bootstrap|angular)[^"\']*["\']',
#     re.I
# )

# # =========================================================
# # Main detector
# # =========================================================

# def detect(
#     response_headers: dict,
#     response_body: str,
#     request_headers: dict,
# ) -> Optional[list]:

#     findings = []

#     # Prevent duplicate alerts
#     seen = set()

#     # Combine headers + request + body
#     all_text = (
#         " ".join(f"{k}: {v}" for k, v in response_headers.items()) + " " +
#         " ".join(f"{k}: {v}" for k, v in request_headers.items()) + " " +
#         response_body[:5000]
#     )

#     # =====================================================
#     # Vulnerable component detection
#     # =====================================================

#     for pattern, component, note, severity, score in VULNERABLE_VERSIONS:

#         match = pattern.search(all_text)

#         if match:

#             if component in seen:
#                 continue

#             seen.add(component)

#             findings.append({
#                 "owasp_id":    "A06",
#                 "owasp_name":  "Vulnerable and Outdated Components",
#                 "threat_type": f"Vulnerable component detected: {component}",
#                 "severity":    severity,
#                 "risk_score":  score,
#                 "detail":      f"{component} detected. {note}",
#                 "payload":     match.group(0)[:120],
#             })

#     # =====================================================
#     # CDN-based frontend library detection
#     # =====================================================

#     cdn_match = CDN_PATTERNS.search(response_body)

#     if cdn_match:

#         findings.append({
#             "owasp_id":    "A06",
#             "owasp_name":  "Vulnerable and Outdated Components",
#             "threat_type": "Frontend CDN dependency detected",
#             "severity":    "LOW",
#             "risk_score":  40,
#             "detail":      "Application loads JavaScript libraries from public CDN.",
#             "payload":     cdn_match.group(0),
#         })

#     # =====================================================
#     # Script source detection
#     # =====================================================

#     script_match = SCRIPT_VERSION_PATTERN.search(response_body)

#     if script_match:

#         findings.append({
#             "owasp_id":    "A06",
#             "owasp_name":  "Vulnerable and Outdated Components",
#             "threat_type": "Frontend library script reference detected",
#             "severity":    "MEDIUM",
#             "risk_score":  55,
#             "detail":      "Frontend JavaScript framework detected in script source.",
#             "payload":     script_match.group(0)[:120],
#         })

#     # =====================================================
#     # Return findings
#     # =====================================================

#     return findings if findings else None
###