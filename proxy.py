"""
proxy.py
--------
SentinelAI — FastAPI proxy server entry point.

Every HTTP request is:
  1. Intercepted here
  2. Forwarded to TARGET_API via httpx
  3. Logged to SQLite
  4. Analyzed by the threat engine
  5. Response returned to caller unchanged
"""

from importlib.resources import path
import os
import json
import logging
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from streamlit import query_params

from utils.database import init_db, log_request
from engine import analyze

from urllib.parse import unquote

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sentinelai.proxy")

TARGET_API = os.getenv("TARGET_API", "https://httpbin.org").rstrip("/")

app = FastAPI(
    title="SentinelAI Proxy",
    description="OWASP Top 10 runtime API threat monitor",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    init_db()
    logger.info(f"SentinelAI started — proxying to: {TARGET_API}")


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def proxy_handler(request: Request, path: str):
    # ── 1. Read request details ───────────────────────────────────────────────
    body_bytes    = await request.body()
    request_body  = unquote(
        body_bytes.decode("utf-8", errors="replace")
    )

    query_params = unquote(str(request.query_params))
# Clean endpoint for dashboard display
    clean_endpoint = f"/{path}"

    if query_params:
        clean_endpoint += f"?{query_params}"   
    client_ip     = request.client.host if request.client else "unknown"
    req_headers   = dict(request.headers)

    # Strip hop-by-hop headers before forwarding
    for h in ("host", "content-length", "transfer-encoding"):
        req_headers.pop(h, None)

    # ── 2. Forward to target API ──────────────────────────────────────────────
    target_url = f"{TARGET_API}/{path}"
    status_code    = 502
    response_body  = ""
    response_content = b""
    resp_headers   = {}

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            upstream = await client.request(
                method=request.method,
                url=target_url,
                headers=req_headers,
                content=body_bytes,
                params=dict(request.query_params),
            )
        status_code   = upstream.status_code
        response_body = upstream.text
        response_content = upstream.content
        resp_headers  = dict(upstream.headers)

    except httpx.ConnectError:
        logger.error(f"Could not connect to target: {target_url}")
        response_body = json.dumps({"error": "SentinelAI: Target API unreachable"})
        status_code   = 502
    except httpx.TimeoutException:
        logger.error(f"Timeout on: {target_url}")
        response_body = json.dumps({"error": "SentinelAI: Target API timed out"})
        status_code   = 504

    # ── 3. Log request to SQLite ──────────────────────────────────────────────
    request_id = log_request({
        "method":       request.method,
        "path":         clean_endpoint,
        "query_params": query_params,
        "headers":      json.dumps(req_headers),
        "body":         request_body[:4000],
        "status_code":  status_code,
        "response_body": response_body[:4000],
        "client_ip":    client_ip,
    })

    # ── 4. Analyze for threats ────────────────────────────────────────────────
    analyze(
        request_id=request_id,
        method=request.method,
        path=path,
        query_params=query_params,
        headers=req_headers,
        request_body=request_body,
        status_code=status_code,
        response_body=response_body,
        response_headers=resp_headers,
        client_ip=client_ip,
    )

    # ── 5. Return upstream response to caller ─────────────────────────────────
    # Clean hop-by-hop headers before sending downstream
    for h in ("content-encoding", "transfer-encoding", "connection"):
        resp_headers.pop(h, None)

    return Response(
    content=response_content,
    status_code=status_code,
    headers=resp_headers,
    media_type=resp_headers.get("content-type"),
)
