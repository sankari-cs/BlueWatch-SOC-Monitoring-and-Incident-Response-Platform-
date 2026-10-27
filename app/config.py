"""Environment-backed application configuration."""

import os


def _int_setting(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


class Config:
    """Local-first configuration; secrets and integration settings stay in env."""

    SECRET_KEY = os.environ.get("BLUEWATCH_SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("BLUEWATCH_DATABASE_URL", "sqlite:///bluewatch.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("BLUEWATCH_COOKIE_SECURE", "false").lower() == "true"
    FAILED_AUTH_THRESHOLD = _int_setting("BLUEWATCH_FAILED_AUTH_THRESHOLD", 5, 2, 100)
    FAILED_AUTH_WINDOW_MINUTES = _int_setting("BLUEWATCH_FAILED_AUTH_WINDOW_MINUTES", 10, 1, 1440)
    AUTH_SEQUENCE_WINDOW_MINUTES = _int_setting("BLUEWATCH_AUTH_SEQUENCE_WINDOW_MINUTES", 15, 1, 1440)
    CORRELATION_WINDOW_MINUTES = _int_setting("BLUEWATCH_CORRELATION_WINDOW_MINUTES", 60, 1, 1440)
    ALERTS_PER_PAGE = 20
    UPLOAD_MAX_RECORDS = 10000
    UPLOAD_MAX_LINE_BYTES = 262144
    RULES_PATH = os.environ.get("BLUEWATCH_RULES_PATH")
    PLAYBOOKS_PATH = os.environ.get("BLUEWATCH_PLAYBOOKS_PATH")
    WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL")
    WAZUH_INDEXER_USERNAME = os.environ.get("WAZUH_INDEXER_USERNAME")
    WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD")
    WAZUH_INDEX_PATTERN = os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
    WAZUH_CA_BUNDLE = os.environ.get("WAZUH_CA_BUNDLE")
    WAZUH_TIMEOUT_SECONDS = _int_setting("WAZUH_TIMEOUT_SECONDS", 10, 2, 60)
    WAZUH_PAGE_SIZE = _int_setting("WAZUH_PAGE_SIZE", 100, 1, 500)
    WAZUH_MAX_PAGES = _int_setting("WAZUH_MAX_PAGES", 10, 1, 50)
    ANALYST_NAME = os.environ.get("BLUEWATCH_ANALYST", "local-analyst")[:80]
