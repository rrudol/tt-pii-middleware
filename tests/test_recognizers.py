"""End-to-end detection on synthetic Polish strings (no real PII)."""

import pytest

from tests.conftest import labels_of
from tests.test_checksums import (
    VALID_DOWOD,
    VALID_IBAN,
    VALID_NIP,
    VALID_PESEL,
    VALID_REGON9,
    VALID_REGON14,
)


class TestChecksummedIdentifiers:
    def test_pesel(self, engine):
        found = labels_of(engine, f"Mój PESEL to {VALID_PESEL}.")
        assert found["PESEL"] == [VALID_PESEL]

    def test_pesel_invalid_checksum_rejected(self, engine):
        found = labels_of(engine, "Mój PESEL to 44051401358.")
        assert "PESEL" not in found

    def test_nip_plain_and_hyphenated(self, engine):
        found = labels_of(engine, f"NIP: {VALID_NIP} lub 123-456-32-18")
        assert found["NIP"] == [VALID_NIP, "123-456-32-18"]

    def test_nip_invalid_checksum_rejected(self, engine):
        assert "NIP" not in labels_of(engine, "NIP: 1234563217")

    def test_regon_9_and_14_digits(self, engine):
        assert labels_of(engine, f"REGON {VALID_REGON9}")["REGON"] == [VALID_REGON9]
        assert labels_of(engine, f"REGON {VALID_REGON14}")["REGON"] == [VALID_REGON14]

    def test_regon_invalid_checksum_rejected(self, engine):
        assert "REGON" not in labels_of(engine, "REGON 123456786")

    def test_iban(self, engine):
        found = labels_of(engine, f"przelew na konto {VALID_IBAN}")
        assert found["IBAN"] == [VALID_IBAN]

    def test_dowod_with_checksum(self, engine):
        found = labels_of(engine, f"dowód osobisty seria {VALID_DOWOD}")
        assert found["DOWOD"] == [VALID_DOWOD]

    def test_dowod_lookalike_rejected(self, engine):
        # Matches the 3-letters + 6-digits shape but fails the checksum --
        # exactly the FP class the eval flagged for regex-only detection.
        assert "DOWOD" not in labels_of(engine, "dowód osobisty seria ABA123456")

    def test_credit_card(self, engine):
        found = labels_of(engine, "karta 4111 1111 1111 1111")
        assert found["CARD"] == ["4111 1111 1111 1111"]


class TestPhones:
    @pytest.mark.parametrize(
        "number",
        [
            "+48601234567",
            "+48 601 234 567",
            "+48 22 123 45 67",
            "601 234 567",
            "22 123 45 67",
        ],
    )
    def test_polish_formats(self, engine, number):
        found = labels_of(engine, f"Zadzwoń: {number}, dziękuję.")
        assert found.get("PHONE") == [number], f"missed {number!r}"

    def test_bare_nine_digits_needs_context(self, engine):
        assert labels_of(engine, "tel. 601234567")["PHONE"] == ["601234567"]
        # Without phone context a bare 9-digit run stays below the threshold.
        assert "PHONE" not in labels_of(engine, "identyfikator 601234567")


class TestContextGatedAndRegexRecognizers:
    def test_email(self, engine):
        found = labels_of(engine, "napisz na jan.kowalski@example.pl")
        assert found["EMAIL"] == ["jan.kowalski@example.pl"]

    def test_postal_code(self, engine):
        found = labels_of(engine, "adres: 00-950 Warszawa")
        assert found["POSTAL"] == ["00-950"]

    @pytest.mark.parametrize("plate", ["WW 12345", "KR 1A234", "WWL 1234A"])
    def test_plates(self, engine, plate):
        found = labels_of(engine, f"tablica rejestracyjna {plate}")
        assert found.get("PLATE") == [plate], f"missed {plate!r}"

    def test_plate_lowercase_not_matched(self, engine):
        assert "PLATE" not in labels_of(engine, "tablica ww 12345")

    def test_krs_requires_context(self, engine):
        found = labels_of(engine, "spółka zarejestrowana pod KRS 0000123456")
        assert found["KRS"] == ["0000123456"]
        # The same 10 digits with no "KRS" nearby must NOT be reported.
        assert "KRS" not in labels_of(engine, "identyfikator wpisu 0000123456")

    def test_address_street(self, engine):
        found = labels_of(engine, "mieszka przy ul. Marszałkowska 1/5 w Warszawie")
        assert "ul. Marszałkowska 1/5" in found["ADDRESS"]

    def test_dob_requires_birth_context(self, engine):
        found = labels_of(engine, "Jan, ur. 01.02.1990, Warszawa")
        assert found["DOB"] == ["01.02.1990"]
        assert "DOB" not in labels_of(engine, "spotkanie odbyło się 01.02.1990")

    def test_passport(self, engine):
        found = labels_of(engine, "paszport AA1234567")
        assert found["PASSPORT"] == ["AA1234567"]


class TestOrgLegalForm:
    def test_sp_zoo(self, engine):
        found = labels_of(engine, "Sprzedawca: Sigma Consulting Sp. z o.o.")
        assert any("Sp. z o.o." in x for x in found.get("ORG", []))

    def test_sa(self, engine):
        found = labels_of(engine, "Nabywca: Beta S.A. z siedzibą w Warszawie")
        assert any("S.A." in x for x in found.get("ORG", []))


class TestNerEntities:
    def test_person_polish(self, engine):
        found = labels_of(engine, "Sprawę prowadzi Jan Kowalski z Krakowa.")
        assert "Jan Kowalski" in found["PERSON"]

    def test_english_language(self, engine):
        found = labels_of(
            engine,
            "John Smith from Boston, email john.smith@example.com",
            language="en",
        )
        assert "John Smith" in found.get("PERSON", [])
        assert found["EMAIL"] == ["john.smith@example.com"]


class TestEngineBehaviour:
    def test_entities_filter(self, engine):
        text = f"PESEL {VALID_PESEL}, email jan@example.pl"
        found = labels_of(engine, text, labels=["PESEL"])
        assert set(found) == {"PESEL"}

    def test_threshold_override(self, engine):
        # Bare plate score stays under default threshold without vehicle context.
        text = "kod WW 12345"
        assert "PLATE" not in labels_of(engine, text)
        assert "PLATE" in labels_of(engine, "tablica rejestracyjna WW 12345")

    def test_plate_standards_prefix_rejected(self, engine):
        assert "PLATE" not in labels_of(engine, "kod produktu PN 12345")
        assert "PLATE" not in labels_of(engine, "norma EN 16001")

    def test_postal_range_without_context_rejected(self, engine):
        assert "POSTAL" not in labels_of(engine, "zakres 10-100 szt.")
        assert labels_of(engine, "adres: 00-950 Warszawa")["POSTAL"] == ["00-950"]

    def test_krs_beats_nip_with_context(self, engine):
        # 10 digits that happen to look NIP-shaped still resolve to KRS when
        # the keyword is present (overlap disambiguation).
        found = labels_of(engine, "wpis KRS 0000123456 w rejestrze")
        assert found.get("KRS") == ["0000123456"]
        assert "NIP" not in found

    def test_regon14_not_swallowed_by_card(self, engine):
        from tests.test_checksums import VALID_REGON14

        found = labels_of(engine, f"REGON {VALID_REGON14}")
        assert found.get("REGON") == [VALID_REGON14]
        assert "CARD" not in found

    def test_spans_do_not_overlap(self, engine):
        text = f"NIP {VALID_NIP} tel 601 234 567, ul. Długa 5, 00-950 Warszawa"
        spans = engine.analyze(text)
        ordered = sorted(spans, key=lambda s: s.start)
        for left, right in zip(ordered, ordered[1:]):
            assert left.end <= right.start

    def test_redact_modes(self, engine):
        text = f"PESEL {VALID_PESEL}"
        replaced, _ = engine.redact(text, "replace")
        assert replaced == "PESEL <PESEL>"
        masked, _ = engine.redact(text, "mask")
        assert masked == "PESEL " + "*" * len(VALID_PESEL)
        hashed, _ = engine.redact(text, "hash")
        digest = hashed.removeprefix("PESEL ")
        assert len(digest) == 16 and VALID_PESEL not in hashed

    def test_redact_unknown_mode_raises(self, engine):
        with pytest.raises(ValueError):
            engine.redact("cokolwiek", "rot13")

    def test_anonymize_restore_roundtrip(self, engine):
        text = f"PESEL {VALID_PESEL} oraz email jan@example.pl. Powtórka: {VALID_PESEL}."
        anonymized, spans, mapping = engine.anonymize(text)
        assert VALID_PESEL not in anonymized
        assert "jan@example.pl" not in anonymized
        # Same value -> same token, so the mapping has one PESEL entry.
        assert anonymized.count("[PESEL_001]") == 2
        assert mapping["[PESEL_001]"] == VALID_PESEL
        assert engine.restore(anonymized, mapping) == text
