"""Presidio HTTP shim mapping — no spaCy, just the translator."""

from tt_pii_middleware.presidio_compat import (
    PresidioAnalyzerResult,
    apply_analyzer_results,
    coerce_language,
    incoming_to_tt,
    map_incoming_entities,
)


def test_coerce_language_defaults_pl():
    assert coerce_language(None) == "pl"
    assert coerce_language("") == "pl"
    assert coerce_language("en-US") == "en"
    assert coerce_language("de") == "pl"


def test_incoming_entity_aliases():
    assert incoming_to_tt("PESEL") == "PESEL"
    assert incoming_to_tt("EMAIL_ADDRESS") == "EMAIL"
    assert incoming_to_tt("PHONE_NUMBER") == "PHONE"
    assert incoming_to_tt("CREDIT_CARD") == "CARD"
    assert incoming_to_tt("PL_PESEL") == "PESEL"
    assert incoming_to_tt("US_SSN") is None


def test_map_incoming_entities_empty_means_all():
    assert map_incoming_entities(None) is None
    assert map_incoming_entities([]) is None


def test_map_incoming_entities_unknown_only_is_empty_list():
    assert map_incoming_entities(["US_SSN"]) == []


def test_apply_analyzer_results_replaces_from_the_end():
    text = "PESEL 44051401359 mail a@b.pl"
    outcome = apply_analyzer_results(
        text,
        [
            PresidioAnalyzerResult(entity_type="PESEL", start=6, end=17, score=1.0),
            PresidioAnalyzerResult(entity_type="EMAIL_ADDRESS", start=23, end=29, score=0.9),
        ],
    )
    assert outcome["text"] == "PESEL <PESEL> mail <EMAIL>"
    assert "44051401359" not in outcome["text"]
