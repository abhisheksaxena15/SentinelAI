"""
utils/alerts.py
---------------
Email alert dispatcher.
Uses smtplib (Python stdlib) — zero cost, no external service.
"""

import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

def send_alert(threat: dict):
    """Send an email alert for a HIGH or CRITICAL threat."""
    sender   = os.getenv("ALERT_EMAIL_FROM")
    receiver = os.getenv("ALERT_EMAIL_TO")
    password = os.getenv("ALERT_EMAIL_PASSWORD")
    host     = os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com")
    port     = int(os.getenv("ALERT_SMTP_PORT", 465))

    if not all([sender, receiver, password]):
        logger.warning("Email alerts not configured — skipping alert send.")
        return

    severity = threat.get("severity", "UNKNOWN")
    if severity not in ("HIGH", "CRITICAL"):
        return  # Only alert on serious threats

    subject = f"[SentinelAI] {severity} — {threat.get('threat_type')} detected"
    body = f"""
SentinelAI Threat Alert
========================
OWASP Category : {threat.get('owasp_id')} — {threat.get('owasp_name')}
Threat Type    : {threat.get('threat_type')}
Severity       : {severity}
Risk Score     : {threat.get('risk_score')}/100
Detail         : {threat.get('detail')}
Payload Snippet: {threat.get('payload', 'N/A')}
Timestamp      : {threat.get('timestamp')}
Request ID     : {threat.get('request_id')}
"""
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = receiver
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL(host, port) as server:
            server.login(sender, password)
            server.send_message(msg)
        logger.info(f"Alert sent for threat: {threat.get('threat_type')}")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")
