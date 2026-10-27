import pytest

from app.services.wazuh import WazuhIndexerClient, WazuhIntegrationError


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(response=self)

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def settings(**overrides):
    values = {
        "WAZUH_INDEXER_URL": "https://indexer.example:9200",
        "WAZUH_INDEXER_USERNAME": "reader",
        "WAZUH_INDEXER_PASSWORD": "do-not-print",
        "WAZUH_INDEX_PATTERN": "wazuh-alerts-*",
        "WAZUH_CA_BUNDLE": None,
        "WAZUH_TIMEOUT_SECONDS": 4,
        "WAZUH_PAGE_SIZE": 2,
        "WAZUH_MAX_PAGES": 4,
    }
    values.update(overrides)
    return values


def hit(identifier, timestamp):
    return {"_id": identifier, "sort": [timestamp, identifier], "_source": {
        "timestamp": timestamp, "id": identifier, "rule": {"id": "5710"}
    }}


def test_wazuh_client_paginates_with_timeouts_tls_and_basic_auth():
    fake = FakeSession([
        FakeResponse({"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": [
            hit("a", "2026-10-27T10:00:00Z"), hit("b", "2026-10-27T10:01:00Z")
        ]}}),
        FakeResponse({"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": [
            hit("c", "2026-10-27T10:02:00Z")
        ]}}),
    ])
    client = WazuhIndexerClient(settings(), session=fake)
    records, truncated = client.fetch_alerts()
    assert len(records) == 3
    assert truncated is False
    assert records[0]["__bluewatch_source_id"] == "a"
    from app.services.normalization import normalize_record
    normalized = normalize_record(records[0])
    assert normalized.source_name == "wazuh-indexer"
    assert "__bluewatch_source" not in normalized.original_fields_json
    assert fake.calls[0][0] == "https://indexer.example:9200/wazuh-alerts-*/_search"
    assert fake.calls[0][1]["auth"] == ("reader", "do-not-print")
    assert fake.calls[0][1]["verify"] is True
    assert fake.calls[0][1]["timeout"] == (4, 4)
    assert fake.calls[1][1]["json"]["search_after"] == ["2026-10-27T10:01:00Z", "b"]


def test_wazuh_client_stops_at_page_cap():
    full = {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": [
        hit("a", "2026-10-27T10:00:00Z"), hit("b", "2026-10-27T10:01:00Z")
    ]}}
    fake = FakeSession([FakeResponse(full), FakeResponse(full)])
    client = WazuhIndexerClient(settings(WAZUH_MAX_PAGES=2), session=fake)
    records, truncated = client.fetch_alerts()
    assert len(records) == 4
    assert truncated is True


def test_wazuh_client_rejects_bad_url_credentials_and_index_pattern():
    with pytest.raises(WazuhIntegrationError, match="HTTPS"):
        WazuhIndexerClient(settings(WAZUH_INDEXER_URL="http://indexer.example:9200"), session=FakeSession([]))
    with pytest.raises(WazuhIntegrationError, match="safe wazuh-alerts"):
        WazuhIndexerClient(settings(WAZUH_INDEX_PATTERN="../../_all"), session=FakeSession([]))
    with pytest.raises(WazuhIntegrationError, match="not configured"):
        WazuhIndexerClient(settings(WAZUH_INDEXER_PASSWORD=""), session=FakeSession([]))


def test_wazuh_timeout_and_partial_shard_failure_are_errors():
    timed_out = FakeSession([FakeResponse({"timed_out": True, "hits": {"hits": []}})])
    with pytest.raises(WazuhIntegrationError, match="timed out"):
        WazuhIndexerClient(settings(), session=timed_out).fetch_alerts()
    failed_shards = FakeSession([FakeResponse({"timed_out": False, "_shards": {"failed": 1}, "hits": {"hits": []}})])
    with pytest.raises(WazuhIntegrationError, match="shards"):
        WazuhIndexerClient(settings(), session=failed_shards).fetch_alerts()

