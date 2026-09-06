"""Checksum logic: our DOWOD implementation + sanity checks that the
pii-core validators we depend on behave as the eval assumed."""

import pytest
from pii_core import is_valid_iban, is_valid_luhn, is_valid_nip, is_valid_pesel, is_valid_regon

from tt_pii_middleware.recognizers import is_valid_dowod

# Synthetic numbers: checksum-valid but not issued to anyone.
VALID_PESEL = "44051401359"
VALID_NIP = "1234563218"
VALID_REGON9 = "123456785"
VALID_REGON14 = "12345678512347"
VALID_IBAN = "PL61109010140000071219812874"
VALID_DOWOD = "ABA300000"


class TestDowodChecksum:
    def test_valid(self):
        assert is_valid_dowod(VALID_DOWOD)

    def test_valid_with_space_and_lowercase(self):
        assert is_valid_dowod("aba 300000")

    @pytest.mark.parametrize(
        "candidate",
        [
            "ABA123456",  # regex lookalike, wrong check digit
            "ABA300001",  # single digit flipped
            "ABC000000",  # wrong check digit for ABC
            "AB1300000",  # digit in the series part
            "ABA30000",  # too short
            "ABAX00000",  # letter in the numeric part
            "",
        ],
    )
    def test_invalid(self, candidate):
        assert not is_valid_dowod(candidate)

    def test_check_digit_position(self):
        # For series "ABC" the correct check digit is unique; all others fail.
        valid = [d for d in range(10) if is_valid_dowod(f"ABC{d}00000")]
        assert len(valid) == 1


class TestPiiCoreValidators:
    def test_pesel(self):
        assert is_valid_pesel(VALID_PESEL)
        assert not is_valid_pesel("44051401358")

    def test_nip(self):
        assert is_valid_nip(VALID_NIP)
        assert not is_valid_nip("1234563217")

    def test_regon(self):
        assert is_valid_regon(VALID_REGON9)
        assert is_valid_regon(VALID_REGON14)
        assert not is_valid_regon("123456786")
        assert not is_valid_regon("12345678512346")

    def test_iban(self):
        assert is_valid_iban(VALID_IBAN)
        assert not is_valid_iban("PL61109010140000071219812875")

    def test_luhn(self):
        assert is_valid_luhn("4111111111111111")
        assert not is_valid_luhn("4111111111111112")
