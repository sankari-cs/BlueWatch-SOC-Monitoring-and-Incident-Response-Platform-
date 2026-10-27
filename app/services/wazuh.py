"""Read-only Wazuh Indexer alerts client with bounded search_after paging."""

from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

import requests
from flask import current_app


class WazuhIntegrationError(RuntimeError):
    """Safe, user-facing integration error without credential details."""


class WazuhIndexerClient:
    def __init__(self, config=None, session=None):
        self.config = config or current_app.config
        self.session = session or requests.Session()
        self.base_url = (self.config.get("WAZUH_INDEXER_URL") or "").rstrip("/")
        self.username = self.config.get("WAZUH_INDEXER_USERNAME") or ""
        self.password = self.config.get("WAZUH_INDEXER_PASSWORD") or ""
        self.pattern = self.config.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
        self.timeout = int(self.config.get("WAZUH_TIMEOUT_SECONDS", 10))
        self.page_size = int(self.config.get("WAZUH_PAGE_SIZE", 100))
        self.max_pages = int(self.config.get("WAZUH_MAX_PAGES", 10))
        self.verify = self.config.get("WAZUH_CA_BUNDLE") or True
        self._validate_config()

    def _validate_config(self):
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path not in {"", "/"}:
            raise WazuhIntegrationError("Wazuh Indexer URL must be an HTTPS origin such as https://indexer.example:9200")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise WazuhIntegrationError("Wazuh Indexer URL cannot contain credentials, a query, or a fragment")
        if not self.username or not self.password:
            raise WazuhIntegrationError("Wazuh Indexer username and password are not configured")
        if not re.fullmatch(r"[A-Za-z0-9*_.-]{1,128}", self.pattern) or not self.pattern.startswith("wazuh-alerts-"):
            raise WazuhIntegrationError("Wazuh index pattern must be a safe wazuh-alerts-* pattern")
        self.page_size = max(1, min(self.page_size, 500))
        self.max_pages = max(1, min(self.max_pages, 50))

    def _post(self, url: str, body: dict) -> dict:
        for attempt in range(3):
            try:
                response = self.session.post(
                    url,
                    json=body,
                    auth=(self.username, self.password),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    timeout=(self.timeout, self.timeout),
                    verify=self.verify,
                )
                if response.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                response.raise_for_status()
                result = response.json()
                if not isinstance(result, dict):
                    raise WazuhIntegrationError("Wazuh Indexer returned an unexpected response")
                return result
            except requests.Timeout as exc:
                if attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise WazuhIntegrationError("Wazuh Indexer request timed out") from exc
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else "unknown"
                raise WazuhIntegrationError(f"Wazuh Indexer returned HTTP {status}") from exc
            except requests.exceptions.JSONDecodeError as exc:
                raise WazuhIntegrationError("Wazuh Indexer returned invalid JSON") from exc
            except requests.RequestException as exc:
                if attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise WazuhIntegrationError("Could not connect to the Wazuh Indexer") from exc
            except ValueError as exc:
                raise WazuhIntegrationError("Wazuh Indexer returned invalid JSON") from exc
        raise WazuhIntegrationError("Wazuh Indexer request failed")

    def fetch_alerts(self) -> tuple[list[dict], bool]:
        """Fetch at most max_pages pages. Returns records and whether capped."""
        url = f"{self.base_url}/{self.pattern}/_search"
        body = {
            "size": self.page_size,
            "query": {"match_all": {}},
            "sort": [
                {"timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"id": {"order": "asc", "unmapped_type": "keyword"}},
            ],
        }
        records: list[dict] = []
        search_after = None
        truncated = False
        for page in range(self.max_pages):
            if search_after is not None:
                body["search_after"] = search_after
            result = self._post(url, body)
            if result.get("timed_out"):
                raise WazuhIntegrationError("Wazuh Indexer search timed out; no records were imported")
            shards = result.get("_shards", {})
            if isinstance(shards, dict) and shards.get("failed", 0):
                raise WazuhIntegrationError("Wazuh Indexer reported failed search shards; no records were imported")
            hits_body = result.get("hits")
            hits = hits_body.get("hits") if isinstance(hits_body, dict) else None
            if not isinstance(hits, list):
                raise WazuhIntegrationError("Wazuh Indexer response did not contain a valid hits list")
            if not hits:
                break
            for hit in hits:
                if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                    continue
                record = dict(hit["_source"])
                record["_wazuh_alert_id"] = hit.get("_id")
                record["_source_name"] = "wazuh-indexer"
                records.append({"__bluewatch_source": "wazuh-indexer", "__bluewatch_source_id": hit.get("_id"), "__bluewatch_record": hit["_source"]})
            if len(hits) < self.page_size:
                break
            cursor = hits[-1].get("sort")
            if not isinstance(cursor, list) or not cursor:
                raise WazuhIntegrationError("Wazuh Indexer omitted the pagination cursor; sync stopped safely")
            search_after = cursor
            if page == self.max_pages - 1:
                truncated = True
        return records, truncated



