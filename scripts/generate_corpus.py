#!/usr/bin/env python3
"""Generate a synthetic Polish PII evaluation corpus with gold character spans.

Every identifier is checksum-valid (or deliberately invalid in negative docs).
No real personal data is used — names, streets and companies are common
fictional placeholders drawn from fixed lists.

Output JSONL (one document per line)::

    {
      "id": "doc-000042",
      "template": "umowa",
      "language": "pl",
      "text": "...",
      "entities": [{"start": 12, "end": 23, "label": "PESEL", "text": "..."}]
    }

Usage::

    python scripts/generate_corpus.py --n 3000 --seed 42 -o data/synthetic/pl_pii_v1.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

# Allow `python scripts/generate_corpus.py` without installing editable path hacks
# beyond the project venv (package is installed editable via make install).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pii_core import is_valid_nip, is_valid_regon  # noqa: E402

from synthetic_ids import (  # noqa: E402
    gen_card,
    gen_dob,
    gen_dowod,
    gen_email,
    gen_iban_pl,
    gen_invalid_dowod,
    gen_invalid_iban,
    gen_invalid_nip,
    gen_invalid_pesel,
    gen_krs,
    gen_nip,
    gen_passport,
    gen_pesel,
    gen_phone,
    gen_plate,
    gen_postal,
    gen_regon14,
    gen_regon9,
)


def _krs_not_nip(rng: random.Random) -> str:
    """KRS is 10 digits with no checksum; avoid values that accidentally pass NIP."""
    for _ in range(50):
        krs = gen_krs(rng)
        if not is_valid_nip(krs):
            return krs
    return "0000123456"  # known non-NIP placeholder

# Gender-agreeing name pairs so spaCy PERSON and humans both see natural PL names.
MALE_FIRST = [
    "Jan", "Piotr", "Krzysztof", "Andrzej", "Tomasz", "Paweł", "Michał", "Marcin",
    "Jakub", "Łukasz", "Adam", "Marek", "Stanisław", "Wojciech", "Grzegorz",
]
FEMALE_FIRST = [
    "Anna", "Maria", "Katarzyna", "Agnieszka", "Magdalena", "Joanna", "Barbara",
    "Ewa", "Aleksandra", "Natalia", "Monika", "Karolina", "Paulina", "Zofia",
]
MALE_LAST = [
    "Kowalski", "Nowak", "Wiśniewski", "Wójcik", "Kowalczyk", "Kamiński", "Lewandowski",
    "Zieliński", "Szymański", "Woźniak", "Dąbrowski", "Kozłowski", "Jankowski", "Mazur",
    "Kwiatkowski", "Krawczyk", "Piotrowski", "Grabowski", "Nowakowski", "Pawłowski",
]
FEMALE_LAST = [
    "Kowalska", "Nowak", "Wiśniewska", "Wójcik", "Kowalczyk", "Kamińska", "Lewandowska",
    "Zielińska", "Szymańska", "Woźniak", "Dąbrowska", "Kozłowska", "Jankowska", "Mazur",
    "Kwiatkowska", "Krawczyk", "Piotrowska", "Grabowska", "Nowakowska", "Pawłowska",
]
STREETS = [
    "Marszałkowska", "Piękna", "Długa", "Krótka", "Słoneczna", "Lipowa", "Kościuszki",
    "Mickiewicza", "Sienkiewicza", "Polna", "Leśna", "Ogrodowa", "Szkolna", "Kwiatowa",
    "Warszawska", "Krakowska", "Gdańska", "Poznańska", "Wrocławska", "Lubelska",
]
CITIES = [
    "Warszawa", "Kraków", "Gdańsk", "Wrocław", "Poznań", "Łódź", "Lublin", "Katowice",
    "Białystok", "Szczecin", "Bydgoszcz", "Gdynia", "Częstochowa", "Radom", "Toruń",
]
COMPANIES = [
    "Alpha Sp. z o.o.", "Beta S.A.", "Gamma sp.j.", "Delta Polska Sp. z o.o.",
    "Epsilon Handlowy S.A.", "Zeta Usługi Sp. z o.o.", "Sigma Consulting Sp. z o.o.",
    "Omega Transport S.A.", "Nova IT Sp. z o.o.", "Helios Budownictwo Sp. z o.o.",
]


@dataclass
class Entity:
    start: int
    end: int
    label: str
    text: str


@dataclass
class Document:
    id: str
    template: str
    language: str
    text: str
    entities: list[Entity]


def _name(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return f"{rng.choice(MALE_FIRST)} {rng.choice(MALE_LAST)}"
    return f"{rng.choice(FEMALE_FIRST)} {rng.choice(FEMALE_LAST)}"


def _street_addr(rng: random.Random) -> str:
    prefix = rng.choice(["ul.", "ulica", "al.", "os."])
    street = rng.choice(STREETS)
    num = rng.randint(1, 120)
    if rng.random() < 0.4:
        return f"{prefix} {street} {num}/{rng.randint(1, 40)}"
    return f"{prefix} {street} {num}"


def _add(text: str, entities: list[Entity], fragment: str, label: str) -> str:
    """Append fragment and record a gold span covering it exactly."""
    start = len(text)
    text = text + fragment
    entities.append(Entity(start=start, end=len(text), label=label, text=fragment))
    return text


# --- document templates ------------------------------------------------------

def tpl_umowa(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = _name(rng)
    pesel = gen_pesel(rng)
    dowod = gen_dowod(rng)
    addr = _street_addr(rng)
    postal = gen_postal(rng)
    city = rng.choice(CITIES)
    email = gen_email(rng)
    phone, _ = gen_phone(rng, style=rng.choice(["intl_spaced", "mobile_grouped"]))
    dob = gen_dob(rng)

    text = "Umowa nr U/" + str(rng.randint(1000, 9999)) + "/2026\n\nZawarta pomiędzy:\n"
    text = _add(text, entities, person, "PERSON")
    text += ", PESEL "
    text = _add(text, entities, pesel, "PESEL")
    text += ", dowód osobisty seria "
    text = _add(text, entities, dowod, "DOWOD")
    text += ", ur. "
    text = _add(text, entities, dob, "DOB")
    text += ", zamieszkały "
    text = _add(text, entities, addr, "ADDRESS")
    text += ", "
    text = _add(text, entities, postal, "POSTAL")
    text += " "
    text = _add(text, entities, city, "ADDRESS")
    text += ", e-mail: "
    text = _add(text, entities, email, "EMAIL")
    text += ", tel. "
    text = _add(text, entities, phone, "PHONE")
    text += ".\n\nPrzedmiotem umowy jest świadczenie usług doradczych."
    return text, entities


def tpl_faktura(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    company = rng.choice(COMPANIES)
    nip = gen_nip(rng)
    # Hyphenated NIP variant ~ half the time.
    nip_fmt = f"{nip[:3]}-{nip[3:6]}-{nip[6:8]}-{nip[8:]}" if rng.random() < 0.5 else nip
    regon = gen_regon9(rng) if rng.random() < 0.7 else gen_regon14(rng)
    iban = gen_iban_pl(rng)
    addr = _street_addr(rng)
    postal = gen_postal(rng)
    city = rng.choice(CITIES)
    email = gen_email(rng, local="faktury")

    text = f"Faktura VAT nr FV/{rng.randint(1, 999):03d}/2026\nSprzedawca: "
    text = _add(text, entities, company, "ORG")
    text += "\nNIP: "
    text = _add(text, entities, nip_fmt, "NIP")
    text += "  REGON: "
    text = _add(text, entities, regon, "REGON")
    text += "\nAdres: "
    text = _add(text, entities, addr, "ADDRESS")
    text += ", "
    text = _add(text, entities, postal, "POSTAL")
    text += " "
    text = _add(text, entities, city, "ADDRESS")
    text += "\nKonto do przelewu: "
    text = _add(text, entities, iban, "IBAN")
    text += "\nKontakt: "
    text = _add(text, entities, email, "EMAIL")
    text += f"\nKwota brutto: {rng.randint(100, 50_000)},{rng.randint(0, 99):02d} PLN"
    return text, entities


def tpl_email_korespondencja(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = _name(rng)
    email = gen_email(rng)
    phone, _ = gen_phone(rng, style="intl_compact")
    pesel = gen_pesel(rng)

    text = "Od: "
    text = _add(text, entities, email, "EMAIL")
    text += "\nTemat: Prośba o aktualizację danych\n\nDzień dobry,\nproszę o weryfikację danych klienta "
    text = _add(text, entities, person, "PERSON")
    text += " (PESEL "
    text = _add(text, entities, pesel, "PESEL")
    text += "). Numer kontaktowy: "
    text = _add(text, entities, phone, "PHONE")
    text += ".\n\nPozdrawiam"
    return text, entities


def tpl_crm_notatka(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = _name(rng)
    company = rng.choice(COMPANIES)
    phone, style = gen_phone(rng)
    # bare phones need context word "tel"
    email = gen_email(rng)
    card = gen_card(rng)
    krs = _krs_not_nip(rng)

    text = "Notatka CRM #" + str(rng.randint(10_000, 99_999)) + "\nKlient: "
    text = _add(text, entities, person, "PERSON")
    text += " z firmy "
    text = _add(text, entities, company, "ORG")
    text += " (KRS "
    text = _add(text, entities, krs, "KRS")
    text += "). "
    if style == "bare":
        text += "tel. "
    else:
        text += "Telefon: "
    text = _add(text, entities, phone, "PHONE")
    text += ", mail "
    text = _add(text, entities, email, "EMAIL")
    text += ". Karta płatnicza do weryfikacji: "
    text = _add(text, entities, card, "CARD")
    text += "."
    return text, entities


def tpl_pojazd(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = _name(rng)
    plate = gen_plate(rng)
    pesel = gen_pesel(rng)
    addr = _street_addr(rng)
    postal = gen_postal(rng)
    city = rng.choice(CITIES)

    text = "Zgłoszenie szkody komunikacyjnej.\nWłaściciel: "
    text = _add(text, entities, person, "PERSON")
    text += ", PESEL "
    text = _add(text, entities, pesel, "PESEL")
    text += ". Tablica rejestracyjna "
    text = _add(text, entities, plate, "PLATE")
    text += ". Adres korespondencyjny: "
    text = _add(text, entities, addr, "ADDRESS")
    text += ", "
    text = _add(text, entities, postal, "POSTAL")
    text += " "
    text = _add(text, entities, city, "ADDRESS")
    text += "."
    return text, entities


def tpl_wniosek_paszport(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = _name(rng)
    passport = gen_passport(rng)
    dob = gen_dob(rng, style=rng.choice(["dmy", "iso", "dmy_slash"]))
    pesel = gen_pesel(rng)
    addr = _street_addr(rng)

    text = "Wniosek o wydanie paszportu.\nImię i nazwisko: "
    text = _add(text, entities, person, "PERSON")
    text += "\nPESEL: "
    text = _add(text, entities, pesel, "PESEL")
    text += "\nData urodzenia: ur. "
    text = _add(text, entities, dob, "DOB")
    text += "\nDotychczasowy paszport: "
    text = _add(text, entities, passport, "PASSPORT")
    text += "\nAdres: "
    text = _add(text, entities, addr, "ADDRESS")
    return text, entities


def tpl_przelew(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = _name(rng)
    iban = gen_iban_pl(rng)
    nip = gen_nip(rng)
    title = f"FV/{rng.randint(1, 999)}/2026"

    text = "Zlecenie przelewu krajowego\nOdbiorca: "
    text = _add(text, entities, person, "PERSON")
    text += "\nRachunek: "
    text = _add(text, entities, iban, "IBAN")
    text += f"\nTytuł: {title} NIP "
    text = _add(text, entities, nip, "NIP")
    text += f"\nKwota: {rng.randint(50, 20_000)}.00 PLN"
    return text, entities


def tpl_mixed_dense(rng: random.Random) -> tuple[str, list[Entity]]:
    """Kitchen-sink document stressing overlap / multi-entity paths."""
    entities: list[Entity] = []
    person = _name(rng)
    pesel = gen_pesel(rng)
    nip = gen_nip(rng)
    regon = gen_regon9(rng)
    iban = gen_iban_pl(rng)
    email = gen_email(rng)
    phone, _ = gen_phone(rng, style="intl_spaced")
    postal = gen_postal(rng)
    plate = gen_plate(rng)
    dowod = gen_dowod(rng)
    card = gen_card(rng)
    addr = _street_addr(rng)

    text = "Pakiet danych klienta: "
    text = _add(text, entities, person, "PERSON")
    text += " | PESEL "
    text = _add(text, entities, pesel, "PESEL")
    text += " | NIP "
    text = _add(text, entities, nip, "NIP")
    text += " | REGON "
    text = _add(text, entities, regon, "REGON")
    text += " | IBAN "
    text = _add(text, entities, iban, "IBAN")
    text += " | "
    text = _add(text, entities, email, "EMAIL")
    text += " | tel "
    text = _add(text, entities, phone, "PHONE")
    text += " | "
    text = _add(text, entities, addr, "ADDRESS")
    text += ", "
    text = _add(text, entities, postal, "POSTAL")
    text += " " + rng.choice(CITIES) + " | rej. "
    text = _add(text, entities, plate, "PLATE")
    text += " | dowód "
    text = _add(text, entities, dowod, "DOWOD")
    text += " | karta "
    text = _add(text, entities, card, "CARD")
    return text, entities


def tpl_negative_checksums(rng: random.Random) -> tuple[str, list[Entity]]:
    """Invalid identifiers must NOT be labeled. Gold entities empty for those IDs."""
    entities: list[Entity] = []
    bad_pesel = gen_invalid_pesel(rng)
    bad_nip = gen_invalid_nip(rng)
    bad_iban = gen_invalid_iban(rng)
    bad_dowod = gen_invalid_dowod(rng)
    # Real email still counts — keeps the doc from being pure noise.
    email = gen_email(rng)

    text = (
        f"Weryfikacja odrzucona: PESEL {bad_pesel}, NIP {bad_nip}, "
        f"IBAN {bad_iban}, dowód {bad_dowod}. "
        f"Kontakt awaryjny: "
    )
    text = _add(text, entities, email, "EMAIL")
    text += "."
    return text, entities


def tpl_negative_noise(rng: random.Random) -> tuple[str, list[Entity]]:
    """Near-miss shapes that should stay unlabeled for pattern labels.

    Gold is empty on purpose; any PESEL/NIP/PLATE/POSTAL/… prediction is an FP.
    Variants cover standards codes, numeric ranges, bare digit runs, and dates
    without birth context.
    """
    product = rng.choice(["PN 12345", "EN 16001", "ISO 9001", "DIN 12345", "REF 99887"])
    scope = rng.choice(["10-100", "20-500", "01-250", "15-300"])
    # Deliberately checksum-invalid digit runs (NIP/REGON FP bait).
    bare_id = f"{rng.randint(100_000_000, 999_999_999)}"
    while is_valid_regon(bare_id):
        bare_id = f"{(int(bare_id) + 1) % 1_000_000_000:09d}"
    bare_10 = f"{rng.randint(0, 9_999_999_999):010d}"
    while is_valid_nip(bare_10) or is_valid_regon(bare_10[:9]):
        bare_10 = f"{(int(bare_10) + 1) % 10_000_000_000:010d}"
    date = rng.choice(["01.02.1990", "15/03/2012", "2020-11-05"])
    text = (
        f"Notatka wewnętrzna #{rng.randint(1000, 9999)}: kod produktu {product}, "
        f"zakres {scope} szt., identyfikator {bare_id}, wpis {bare_10}, "
        f"spotkanie odbyło się {date} w sali A. Brak danych osobowych."
    )
    return text, []


def tpl_english_mixed(rng: random.Random) -> tuple[str, list[Entity]]:
    entities: list[Entity] = []
    person = rng.choice(["John Smith", "Alice Johnson", "Robert Brown"])
    email = gen_email(rng, local="john.smith")
    card = gen_card(rng)
    pesel = gen_pesel(rng)  # PL id appearing in EN context still valid

    text = "Customer record: "
    text = _add(text, entities, person, "PERSON")
    text += ", email "
    text = _add(text, entities, email, "EMAIL")
    text += ", card "
    text = _add(text, entities, card, "CARD")
    text += ", Polish PESEL "
    text = _add(text, entities, pesel, "PESEL")
    text += "."
    return text, entities


TEMPLATES: dict[str, callable] = {
    "umowa": tpl_umowa,
    "faktura": tpl_faktura,
    "email": tpl_email_korespondencja,
    "crm": tpl_crm_notatka,
    "pojazd": tpl_pojazd,
    "paszport": tpl_wniosek_paszport,
    "przelew": tpl_przelew,
    "mixed": tpl_mixed_dense,
    "neg_checksum": tpl_negative_checksums,
    "neg_noise": tpl_negative_noise,
    "en_mixed": tpl_english_mixed,
}

# Sampling weights: heavy on real document shapes, light on negatives / EN.
TEMPLATE_WEIGHTS = {
    "umowa": 14,
    "faktura": 14,
    "email": 10,
    "crm": 10,
    "pojazd": 8,
    "paszport": 8,
    "przelew": 8,
    "mixed": 10,
    "neg_checksum": 8,
    "neg_noise": 6,
    "en_mixed": 4,
}


def generate(n: int, seed: int) -> list[Document]:
    rng = random.Random(seed)
    names = list(TEMPLATE_WEIGHTS)
    weights = [TEMPLATE_WEIGHTS[k] for k in names]
    docs: list[Document] = []
    for i in range(n):
        name = rng.choices(names, weights=weights, k=1)[0]
        text, entities = TEMPLATES[name](rng)
        lang = "en" if name == "en_mixed" else "pl"
        # Validate offsets.
        for e in entities:
            assert text[e.start : e.end] == e.text, (name, e, text[e.start : e.end])
        docs.append(
            Document(
                id=f"doc-{i:06d}",
                template=name,
                language=lang,
                text=text,
                entities=entities,
            )
        )
    return docs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=3000, help="number of documents")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("data/synthetic/pl_pii_v1.jsonl"),
    )
    parser.add_argument("--stats", action="store_true", help="print label histogram")
    args = parser.parse_args()

    docs = generate(args.n, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for doc in docs:
            row = {
                "id": doc.id,
                "template": doc.template,
                "language": doc.language,
                "text": doc.text,
                "entities": [asdict(e) for e in doc.entities],
            }
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    if args.stats or True:
        from collections import Counter

        labels = Counter(e.label for d in docs for e in d.entities)
        templates = Counter(d.template for d in docs)
        print(f"wrote {len(docs)} docs -> {args.output}")
        print("templates:", dict(templates.most_common()))
        print("labels:", dict(labels.most_common()))


if __name__ == "__main__":
    main()
