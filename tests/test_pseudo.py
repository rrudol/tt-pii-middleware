"""HMAC-HKDF linkable pseudonyms — synthetic IDs only."""

from __future__ import annotations

import base64

import pytest

from tt_pii_middleware.analyzer import PiiEngine, Span
from tt_pii_middleware.config import Settings
from tt_pii_middleware.pseudo.canonical import canonicalize
from tt_pii_middleware.pseudo.kdf import hkdf_sha256, purpose_info
from tt_pii_middleware.pseudo.keystore import KeystoreError, MasterKeyStore
from tt_pii_middleware.pseudo.profiles import Profile, resolve_profile
from tt_pii_middleware.pseudo.pseudonymizer import Pseudonymizer
from tt_pii_middleware.pseudo.tokens import TOKEN_RE, format_token
from tests.test_checksums import VALID_NIP, VALID_PESEL


MASTER = bytes([0x11] * 32)


@pytest.fixture
def store() -> MasterKeyStore:
    return MasterKeyStore({"v1": MASTER, "v2": bytes([0x22] * 32)}, active_kid="v1")


@pytest.fixture
def engine(store: MasterKeyStore) -> PiiEngine:
    return PiiEngine(Settings(enable_krs=True, hash_salt="legacy"), Pseudonymizer(store))


class TestCanonical:
    def test_pesel_spaces(self):
        assert canonicalize("PESEL", VALID_PESEL) == VALID_PESEL
        assert canonicalize("PESEL", "4405 1401 359") == VALID_PESEL

    def test_nip_hyphen(self):
        assert canonicalize("NIP", VALID_NIP) == VALID_NIP
        assert canonicalize("NIP", "123-456-32-18") == VALID_NIP

    def test_email_domain_lower(self):
        assert canonicalize("EMAIL", "Jan@Example.PL") == "Jan@example.pl"

    def test_phone_bare_to_e164(self):
        assert canonicalize("PHONE", "601234567") == "+48601234567"
        assert canonicalize("PHONE", "+48 601 234 567") == "+48601234567"

    def test_bad_pesel(self):
        assert canonicalize("PESEL", "123") is None


class TestKdfAndTokens:
    def test_hkdf_length(self):
        out = hkdf_sha256(MASTER, salt=b"salt", info=b"info", length=32)
        assert len(out) == 32
        assert out != MASTER

    def test_purpose_isolates(self, store: MasterKeyStore):
        a = store.derive("v1", "llm-gateway", "acme")
        b = store.derive("v1", "logs", "acme")
        c = store.derive("v1", "llm-gateway", "other")
        assert a != b != c

    def test_token_format(self):
        tok = format_token("PESEL", "v1", bytes(range(32)), 15)
        assert TOKEN_RE.fullmatch(tok)
        assert tok.startswith("PESEL_v1_")


class TestPseudonymizer:
    def test_same_pesel_same_token(self, store: MasterKeyStore):
        pz = Pseudonymizer(store)
        spans = [
            Span(0, 11, "PESEL", 1.0, VALID_PESEL),
            Span(20, 31, "PESEL", 1.0, "4405 1401 359"),
        ]
        text = f"{VALID_PESEL} xxxx 4405 1401 359"
        # fix offsets
        t2 = f"{VALID_PESEL} xxxx {VALID_PESEL}"
        spans = [
            Span(0, 11, "PESEL", 1.0, VALID_PESEL),
            Span(17, 28, "PESEL", 1.0, VALID_PESEL),
        ]
        r = pz.apply(t2, spans, profile=Profile.LINKABLE, purpose="eval", tenant_id="_")
        assert VALID_PESEL not in r.text
        tokens = TOKEN_RE.findall(r.text)
        assert len(tokens) == 2
        assert tokens[0] == tokens[1]
        assert r.privacy["classification"] == "pseudonymised_personal_data"
        assert r.privacy["linkable"] is True
        assert r.stats["pseudonymised"] == 2

    def test_different_purpose_different_token(self, store: MasterKeyStore):
        pz = Pseudonymizer(store)
        spans = [Span(0, 11, "PESEL", 1.0, VALID_PESEL)]
        a = pz.apply(VALID_PESEL, spans, profile=Profile.LINKABLE, purpose="eval")
        b = pz.apply(VALID_PESEL, spans, profile=Profile.LINKABLE, purpose="logs")
        assert a.text != b.text

    def test_fail_closed_without_store(self):
        pz = Pseudonymizer(None)
        with pytest.raises(KeystoreError):
            pz.apply(
                VALID_PESEL,
                [Span(0, 11, "PESEL", 1.0, VALID_PESEL)],
                profile=Profile.LINKABLE,
            )

    def test_linkable_strict_replaces_person(self, store: MasterKeyStore):
        pz = Pseudonymizer(store)
        text = "Jan Kowalski PESEL " + VALID_PESEL
        spans = [
            Span(0, 12, "PERSON", 0.9, "Jan Kowalski"),
            Span(19, 30, "PESEL", 1.0, VALID_PESEL),
        ]
        r = pz.apply(text, spans, profile=Profile.LINKABLE_STRICT, purpose="eval")
        assert "<PERSON>" in r.text
        assert VALID_PESEL not in r.text
        assert "PESEL_v1_" in r.text


class TestEngineIntegration:
    def test_redact_linkable_roundtrip_shape(self, engine: PiiEngine):
        text = f"PESEL {VALID_PESEL} oraz mail jan@example.pl. Znowu {VALID_PESEL}."
        out, spans, meta = engine.redact(
            text,
            profile="linkable",
            purpose="eval",
            tenant_id="t1",
        )
        assert VALID_PESEL not in out
        assert "jan@example.pl" not in out
        assert meta["privacy"]["algorithm"] == "HMAC-SHA256-HKDF-v1"
        assert out.count("PESEL_v1_") == 2
        # both PESEL tokens identical
        import re
        pesels = re.findall(r"PESEL_v1_[A-Za-z0-9_-]+", out)
        assert len(pesels) == 2 and pesels[0] == pesels[1]

    def test_legacy_replace_still_works(self, engine: PiiEngine):
        out, _, meta = engine.redact(f"PESEL {VALID_PESEL}", "replace")
        assert out == "PESEL <PESEL>"
        assert meta["profile"] == "strict"

    def test_resolve_profile(self):
        assert resolve_profile("linkable", None) is Profile.LINKABLE
        assert resolve_profile(None, "mask") is Profile.MASK
