"""Deterministic generators of *checksum-valid synthetic* Polish identifiers.

All values are invented for evaluation. They pass the same checksum rules as
real identifiers so detectors exercise the full validation path, but they are
never claimed to have been issued by any authority. Seeded RNGs make corpora
reproducible across machines.
"""

from __future__ import annotations

import random
import string
from datetime import date, timedelta

from pii_core import is_valid_iban, is_valid_luhn, is_valid_nip, is_valid_pesel, is_valid_regon

from tt_pii_middleware.recognizers import is_valid_dowod

_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
_NIP_WEIGHTS = (6, 5, 7, 2, 3, 4, 5, 6, 7)
_REGON9_WEIGHTS = (8, 9, 2, 3, 4, 5, 6, 7)
_REGON14_WEIGHTS = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)
_DOWOD_WEIGHTS = (7, 3, 1, 0, 7, 3, 1, 7, 3)

# Voivodeship first letters accepted by PlPlateRecognizer.
_PLATE_PREFIX_LETTERS = "BCDEFGKLNOPRSTWZ"
_PLATE_SUFFIX_ALPHABET = "0123456789ACEFGHJKLMNPRSTUVWXY"


def _pesel_check(body10: str) -> str:
    total = sum(int(d) * w for d, w in zip(body10, _PESEL_WEIGHTS))
    return str((10 - total % 10) % 10)


def gen_pesel(rng: random.Random, *, birth: date | None = None, sex: str | None = None) -> str:
    """11-digit PESEL. Sex: 'M' odd 10th digit, 'F' even 10th digit."""
    if birth is None:
        birth = date(1950, 1, 1) + timedelta(days=rng.randint(0, 20_000))
    year, month, day = birth.year, birth.month, birth.day
    century = year // 100
    # Century encoding in month (official PESEL rules).
    month_offset = {18: 80, 19: 0, 20: 20, 21: 40, 22: 60}.get(century, 0)
    yy = year % 100
    mm = month + month_offset
    serial = rng.randint(0, 999)
    if sex == "M":
        sex_digit = rng.choice([1, 3, 5, 7, 9])
    elif sex == "F":
        sex_digit = rng.choice([0, 2, 4, 6, 8])
    else:
        sex_digit = rng.randint(0, 9)
    body10 = f"{yy:02d}{mm:02d}{day:02d}{serial:03d}{sex_digit}"
    pesel = body10 + _pesel_check(body10)
    assert is_valid_pesel(pesel), pesel
    return pesel


def gen_nip(rng: random.Random) -> str:
    for _ in range(200):
        body = "".join(str(rng.randint(0, 9)) for _ in range(9))
        check = sum(int(d) * w for d, w in zip(body, _NIP_WEIGHTS)) % 11
        if check == 10:
            continue
        nip = body + str(check)
        assert is_valid_nip(nip)
        return nip
    raise RuntimeError("failed to sample NIP")


def gen_regon9(rng: random.Random) -> str:
    body = "".join(str(rng.randint(0, 9)) for _ in range(8))
    check = sum(int(d) * w for d, w in zip(body, _REGON9_WEIGHTS)) % 11
    if check == 10:
        check = 0
    regon = body + str(check)
    assert is_valid_regon(regon)
    return regon


def gen_regon14(rng: random.Random) -> str:
    base = gen_regon9(rng)
    mid = "".join(str(rng.randint(0, 9)) for _ in range(4))
    body13 = base + mid
    check = sum(int(d) * w for d, w in zip(body13, _REGON14_WEIGHTS)) % 11
    if check == 10:
        check = 0
    regon = body13 + str(check)
    assert is_valid_regon(regon)
    return regon


def gen_iban_pl(rng: random.Random) -> str:
    """PL IBAN: PL + 2 check digits + 8-digit bank + 16-digit account = 28 chars."""
    for _ in range(200):
        bban = "".join(str(rng.randint(0, 9)) for _ in range(24))
        # Check digits via mod-97: rearrange BBAN + "PL00", convert, compute.
        rearranged = bban + "PL00"
        numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
        check = 98 - (int(numeric) % 97)
        iban = f"PL{check:02d}{bban}"
        if is_valid_iban(iban):
            return iban
    raise RuntimeError("failed to sample IBAN")


def gen_dowod(rng: random.Random) -> str:
    series = "".join(rng.choice(string.ascii_uppercase) for _ in range(3))
    # Positions: 0,1,2 letters; 3 = check; 4..8 digits. Find check digit.
    tail = "".join(str(rng.randint(0, 9)) for _ in range(5))
    for check in range(10):
        candidate = f"{series}{check}{tail}"
        if is_valid_dowod(candidate):
            return candidate
    raise RuntimeError("failed to sample DOWOD")


def gen_invalid_dowod(rng: random.Random) -> str:
    """Shape-correct 3 letters + 6 digits that fails the checksum."""
    for _ in range(100):
        series = "".join(rng.choice(string.ascii_uppercase) for _ in range(3))
        digits = "".join(str(rng.randint(0, 9)) for _ in range(6))
        candidate = series + digits
        if not is_valid_dowod(candidate):
            return candidate
    raise RuntimeError("failed to sample invalid DOWOD")


def gen_passport(rng: random.Random) -> str:
    """Two letters + 7 digits (regex shape used by PlPassportDetector)."""
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(2)) + "".join(
        str(rng.randint(0, 9)) for _ in range(7)
    )


def gen_card(rng: random.Random) -> str:
    """Visa-like 16-digit Luhn-valid number, formatted with spaces."""
    for _ in range(200):
        body = "4" + "".join(str(rng.randint(0, 9)) for _ in range(14))
        # Compute Luhn check digit.
        def luhn_sum(digits: str) -> int:
            total = 0
            for position, ch in enumerate(reversed(digits)):
                d = int(ch)
                if position % 2 == 0:
                    d *= 2
                    if d > 9:
                        d -= 9
                total += d
            return total

        # body is 15 digits; we need 16th such that full passes.
        # Iterate last digit.
        for check in range(10):
            card = body + str(check)
            if is_valid_luhn(card):
                return f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
    raise RuntimeError("failed to sample card")


def gen_phone(rng: random.Random, style: str | None = None) -> tuple[str, str]:
    """Return (formatted_number, style_name)."""
    mobile = f"{rng.choice(['50', '51', '53', '57', '60', '66', '69', '72', '73', '78', '79', '88'])}{rng.randint(0, 9)}{rng.randint(100000, 999999):06d}"
    # mobile is 9 digits starting with known prefixes
    mobile = mobile[:9]
    landline_area = rng.choice(["12", "22", "32", "42", "52", "58", "61", "71", "81", "91"])
    landline = landline_area + f"{rng.randint(1000000, 9999999)}"
    landline = landline[:9]
    style = style or rng.choice(
        ["intl_compact", "intl_spaced", "intl_landline", "mobile_grouped", "landline_grouped", "bare"]
    )
    if style == "intl_compact":
        return f"+48{mobile}", style
    if style == "intl_spaced":
        return f"+48 {mobile[:3]} {mobile[3:6]} {mobile[6:]}", style
    if style == "intl_landline":
        return f"+48 {landline[:2]} {landline[2:5]} {landline[5:7]} {landline[7:]}", style
    if style == "mobile_grouped":
        return f"{mobile[:3]} {mobile[3:6]} {mobile[6:]}", style
    if style == "landline_grouped":
        return f"{landline[:2]} {landline[2:5]} {landline[5:7]} {landline[7:]}", style
    return mobile, "bare"


def gen_plate(rng: random.Random) -> str:
    prefix_len = rng.choice([2, 2, 3])
    first = rng.choice(_PLATE_PREFIX_LETTERS)
    rest = "".join(rng.choice(string.ascii_uppercase.replace("Q", "")) for _ in range(prefix_len - 1))
    # second letter must be A-PR-Z (no Q) — keep simple: A-Z minus Q
    prefix = first + rest
    # suffix 4-5 chars from plate alphabet with at least one digit
    suffix_len = rng.choice([4, 5])
    while True:
        suffix = "".join(rng.choice(_PLATE_SUFFIX_ALPHABET) for _ in range(suffix_len))
        if any(c.isdigit() for c in suffix):
            break
    sep = " " if rng.random() < 0.7 else ""
    return f"{prefix}{sep}{suffix}"


def gen_postal(rng: random.Random) -> str:
    return f"{rng.randint(0, 99):02d}-{rng.randint(0, 999):03d}"


def gen_email(rng: random.Random, local: str | None = None) -> str:
    local = local or rng.choice(
        ["jan.kowalski", "anna.nowak", "biuro", "kontakt", "m.wisniewska", "piotr.zielinski"]
    )
    domain = rng.choice(
        ["example.pl", "example.com", "firma-testowa.pl", "poczta.example.pl", "mail.example.org"]
    )
    return f"{local}@{domain}"


def gen_krs(rng: random.Random) -> str:
    return f"{rng.randint(0, 9_999_999_999):010d}"


def gen_dob(rng: random.Random, style: str = "dmy") -> str:
    d = date(1955, 1, 1) + timedelta(days=rng.randint(0, 18_000))
    if style == "iso":
        return d.isoformat()
    if style == "dmy_slash":
        return d.strftime("%d/%m/%Y")
    return d.strftime("%d.%m.%Y")


# --- invalid variants for negative / FP tests --------------------------------

def gen_invalid_pesel(rng: random.Random) -> str:
    base = gen_pesel(rng)
    flipped = base[:10] + str((int(base[10]) + 1) % 10)
    assert not is_valid_pesel(flipped)
    return flipped


def gen_invalid_nip(rng: random.Random) -> str:
    for _ in range(50):
        body = "".join(str(rng.randint(0, 9)) for _ in range(9))
        check = sum(int(d) * w for d, w in zip(body, _NIP_WEIGHTS)) % 11
        wrong = (check + 1) % 10
        if check != 10 and wrong != check:
            nip = body + str(wrong)
            if not is_valid_nip(nip):
                return nip
    return "1234563217"


def gen_invalid_iban(rng: random.Random) -> str:
    good = gen_iban_pl(rng)
    # Flip last digit.
    last = str((int(good[-1]) + 1) % 10)
    bad = good[:-1] + last
    assert not is_valid_iban(bad)
    return bad
