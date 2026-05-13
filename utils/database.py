"""
utils/database.py
-----------------
Central database helper.
All tables are created here on first run.
"""

import sqlite_utils
import json
from datetime import datetime

DB_PATH = "sentinel.db"

def get_db() -> sqlite_utils.Database:
    return sqlite_utils.Database(DB_PATH)

def init_db():
    db = get_db()

    # Requests log — every proxied HTTP transaction
    if "requests" not in db.table_names():
        db["requests"].create({
            "id":            int,
            "timestamp":     str,
            "method":        str,
            "path":          str,
            "query_params":  str,
            "headers":       str,
            "body":          str,
            "status_code":   int,
            "response_body": str,
            "client_ip":     str,
        }, pk="id", if_not_exists=True)

    # Threats log — one row per detected threat per request
    if "threats" not in db.table_names():
        db["threats"].create({
            "id":          int,
            "request_id":  int,
            "timestamp":   str,
            "owasp_id":    str,   # e.g. A03
            "owasp_name":  str,   # e.g. Injection
            "threat_type": str,   # e.g. SQL Injection
            "severity":    str,   # LOW / MEDIUM / HIGH / CRITICAL
            "risk_score":  int,   # 0-100
            "detail":      str,   # human-readable description
            "payload":     str,   # matched snippet
        }, pk="id", if_not_exists=True)

    db.execute("CREATE INDEX IF NOT EXISTS idx_threats_request ON threats(request_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_requests_time   ON requests(timestamp)")

def log_request(data: dict) -> int:
    db = get_db()
    data["timestamp"] = datetime.utcnow().isoformat()
    result = db["requests"].insert(data, alter=True)
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]

def log_threat(data: dict):
    db = get_db()
    data["timestamp"] = datetime.utcnow().isoformat()
    db["threats"].insert(data, alter=True)
