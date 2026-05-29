# """
# detectors/a06_vulnerable_components.py
# ----------------------------------------
# OWASP A06:2021 — Vulnerable and Outdated Components

# Detects:
#   - Known vulnerable library versions from response headers
#   - Outdated jQuery, Bootstrap versions in HTML responses
#   - Deprecated/EOL framework signatures
# """

# import re
# from typing import Optional

# # Format: (regex_pattern, component_name, note)
# VULNERABLE_VERSIONS = [
#     # jQuery < 3.5.0 — multiple XSS CVEs
#     (re.compile(r"jquery[/-]?(1\.[0-9]\.|2\.[0-2]\.|3\.[0-4]\.)", re.I),
#      "jQuery < 3.5.0", "CVE-2020-11022 / XSS vulnerabilities"),

#     # Bootstrap < 4.3.1
#     (re.compile(r"bootstrap[/-]?(3\.[0-3]\.|4\.[0-2]\.)", re.I),
#      "Bootstrap < 4.3.1", "CVE-2019-8331 / XSS in tooltip"),

#     # Angular < 12
#     (re.compile(r"angular[/-]?(1\.|2\.|3\.|4\.|5\.|6\.|7\.|8\.|9\.|10\.|11\.)", re.I),
#      "AngularJS / Angular < 12", "Multiple template injection CVEs"),

#     # Log4j via User-Agent / headers (Log4Shell)
#     (re.compile(r"\$\{jndi:", re.I),
#      "Log4Shell (CVE-2021-44228)", "Critical RCE — Log4j JNDI injection"),

#     # PHP old versions in Server header
#     (re.compile(r"php/(5\.|7\.[0-3]\.)", re.I),
#      "PHP < 7.4 (EOL)", "End-of-life PHP version — no security patches"),

#     # Apache Struts 2 (CVE-2017-5638)
#     (re.compile(r"struts2?[/-]?(2\.[0-4]\.|2\.5\.0)", re.I),
#      "Apache Struts < 2.5.10", "CVE-2017-5638 / Equifax breach RCE"),

#     # OpenSSL old — from Server/Via headers
#     (re.compile(r"openssl/(0\.|1\.0\.)", re.I),
#      "OpenSSL < 1.1.1 (EOL)", "Heartbleed era or end-of-life OpenSSL"),
# ]

# def detect(
#     response_headers: dict,
#     response_body: str,
#     request_headers: dict,
# ) -> Optional[list]:

#     findings = []
#     all_text = (
#         " ".join(f"{k}: {v}" for k, v in response_headers.items()) + " " +
#         " ".join(f"{k}: {v}" for k, v in request_headers.items()) + " " +
#         response_body[:5000]   # scan first 5KB of HTML for <script src="...">
#     )

#     for pattern, component, note in VULNERABLE_VERSIONS:
#         match = pattern.search(all_text)
#         if match:
#             findings.append({
#                 "owasp_id":    "A06",
#                 "owasp_name":  "Vulnerable and Outdated Components",
#                 "threat_type": f"Vulnerable component: {component}",
#                 "severity":    "HIGH",
#                 "risk_score":  78,
#                 "detail":      f"{component} detected. {note}",
#                 "payload":     match.group(0)[:80],
#             })

#     return findings if findings else None

###

###