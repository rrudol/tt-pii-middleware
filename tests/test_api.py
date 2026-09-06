"""HTTP API tests via the FastAPI TestClient (real engine, no Redis)."""

from tests.test_checksums import VALID_NIP, VALID_PESEL, VALID_REGON9


class TestHealth:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["models_loaded"] == {
            "pl": "pl_core_news_md",
            "en": "en_core_web_sm",
        }
        assert "PiiCoreRecognizer" in body["recognizers_loaded"]
        assert "SpacyRecognizer" in body["recognizers_loaded"]
        assert body["redis_vault"] == "disabled"
        assert "PESEL" in body["labels"]

    def test_openapi_docs(self, client):
        assert client.get("/docs").status_code == 200
        paths = client.get("/openapi.json").json()["paths"]
        assert {"/health", "/v1/analyze", "/v1/redact", "/v1/anonymize", "/v1/restore"} <= set(paths)


class TestAnalyze:
    def test_spans(self, client):
        response = client.post(
            "/v1/analyze",
            json={"text": f"PESEL {VALID_PESEL}, email jan@example.pl"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["language"] == "pl"
        by_label = {s["label"]: s for s in body["spans"]}
        assert by_label["PESEL"]["text"] == VALID_PESEL
        assert by_label["PESEL"]["score"] == 1.0
        assert by_label["EMAIL"]["text"] == "jan@example.pl"
        span = by_label["PESEL"]
        assert span["end"] - span["start"] == len(VALID_PESEL)

    def test_include_text_false(self, client):
        response = client.post(
            "/v1/analyze",
            json={"text": f"PESEL {VALID_PESEL}", "include_text": False},
        )
        assert all("text" not in s for s in response.json()["spans"])

    def test_entities_filter(self, client):
        response = client.post(
            "/v1/analyze",
            json={"text": f"PESEL {VALID_PESEL}, email jan@example.pl", "entities": ["EMAIL"]},
        )
        assert {s["label"] for s in response.json()["spans"]} == {"EMAIL"}

    def test_unknown_entity_rejected(self, client):
        response = client.post(
            "/v1/analyze", json={"text": "abc", "entities": ["SSN"]}
        )
        assert response.status_code == 422

    def test_unsupported_language_rejected(self, client):
        response = client.post("/v1/analyze", json={"text": "abc", "language": "de"})
        assert response.status_code == 422

    def test_oversize_text_rejected(self, client):
        response = client.post("/v1/analyze", json={"text": "a" * 100_001})
        assert response.status_code == 413


class TestRedact:
    def test_default_mode_replace(self, client):
        response = client.post(
            "/v1/redact",
            json={"text": f"PESEL {VALID_PESEL}, NIP {VALID_NIP}, REGON {VALID_REGON9}, mail jan@example.pl"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["redacted_text"] == "PESEL <PESEL>, NIP <NIP>, REGON <REGON>, mail <EMAIL>"
        assert {e["label"] for e in body["entities"]} == {"PESEL", "NIP", "REGON", "EMAIL"}

    def test_mask_mode(self, client):
        response = client.post(
            "/v1/redact", json={"text": f"PESEL {VALID_PESEL}", "mode": "mask"}
        )
        assert response.json()["redacted_text"] == "PESEL " + "*" * 11

    def test_hash_mode(self, client):
        response = client.post(
            "/v1/redact", json={"text": f"PESEL {VALID_PESEL}", "mode": "hash"}
        )
        assert VALID_PESEL not in response.json()["redacted_text"]

    def test_invalid_mode(self, client):
        response = client.post(
            "/v1/redact", json={"text": "abc", "mode": "rot13"}
        )
        assert response.status_code == 422


class TestAnonymizeRestore:
    def test_roundtrip(self, client):
        text = f"Klient PESEL {VALID_PESEL}, kontakt jan@example.pl"
        anon = client.post("/v1/anonymize", json={"text": text}).json()
        assert VALID_PESEL not in anon["anonymized_text"]
        assert anon["mapping"]["[PESEL_001]"] == VALID_PESEL
        assert "session_id" not in anon  # no Redis in tests

        restored = client.post(
            "/v1/restore",
            json={"text": anon["anonymized_text"], "mapping": anon["mapping"]},
        ).json()
        assert restored["restored_text"] == text

    def test_restore_requires_mapping_or_session(self, client):
        response = client.post("/v1/restore", json={"text": "abc"})
        assert response.status_code == 400

    def test_restore_session_without_redis(self, client):
        response = client.post(
            "/v1/restore", json={"text": "abc", "session_id": "deadbeef"}
        )
        assert response.status_code == 400
