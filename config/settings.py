# config/settings.py
# ─── Centralised configuration using pydantic-settings ───────────────────────
# All env variables are read once here and imported across the project.

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Proxy
    target_api: str = "https://httpbin.org"
    proxy_port: int = 8080
    proxy_host: str = "0.0.0.0"

    # Database
    db_path: str = "sentinel.db"

    # Rate limiting
    rate_limit_max_requests: int = 100
    rate_limit_window_seconds: int = 60

    # Alerts
    alert_email_enabled: bool = False
    alert_from_email: str = "you@gmail.com"
    alert_to_email: str = "you@gmail.com"
    alert_email_password: str = ""
    alert_severity_threshold: str = "HIGH"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
