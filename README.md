# 🛡️ SentinelAI — API Security Monitor

Runtime OWASP Top 10 threat detection proxy built with Python.
Zero cloud cost. Runs 100% locally.

## Quick Start

```bash
# 1. Clone / enter project
cd sentinelAI

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your target API
cp .env.example .env
# Edit .env and set TARGET_API=https://your-api.com

# 5. Start the proxy (Terminal 1)
uvicorn proxy:app --host 0.0.0.0 --port 8080 --reload

# 6. Start the dashboard (Terminal 2)
streamlit run dashboard.py

# 7. Send traffic through the proxy
# Change your API client's base URL to http://localhost:8080
```

## Project Structure

```
sentinelAI/
├── proxy.py                          Main proxy server (FastAPI)
├── engine.py                         Threat orchestrator
├── dashboard.py                      Streamlit UI
├── requirements.txt
├── .env.example                      Config template
├── detectors/
│   ├── a01_broken_access_control.py  OWASP A01
│   ├── a02_cryptographic_failures.py OWASP A02
│   ├── a03_injection.py              OWASP A03 (SQLi, XSS, CMDi)
│   ├── a04_insecure_design.py        OWASP A04
│   ├── a05_security_misconfiguration.py OWASP A05
│   ├── a06_vulnerable_components.py  OWASP A06
│   ├── a07_auth_failures.py          OWASP A07
│   ├── a08_integrity_failures.py     OWASP A08
│   ├── a09_logging_failures.py       OWASP A09
│   ├── a10_ssrf.py                   OWASP A10
│   └── rate_limiter.py               Sliding window rate limiter
├── utils/
│   ├── database.py                   SQLite helper
│   └── alerts.py                     Email alerting (smtplib)
├── reports/
│   └── report_generator.py           PDF compliance report
└── tests/
    ├── test_detectors.py             pytest unit tests
    └── test_payloads.http            Manual REST test file
```

## Running Tests

```bash
pip install pytest
python -m pytest tests/test_detectors.py -v
```

## Generating a PDF Report

```bash
python reports/report_generator.py
# Output: reports/SentinelAI_Report_YYYYMMDD_HHMM.pdf
```
