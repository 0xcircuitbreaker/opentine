"""Checksum and structure validators for the PII detectors (0.46, ``opentine-redaction/3``).

A detector's pattern only proposes a candidate; one of these decides whether it
is the thing it looks like. Digit runs are everywhere in agent transcripts
(timestamps, ids, hashes, line numbers), so a card number must pass Luhn and an
issuer prefix, an IBAN mod-97 and its country's length, and a government id its
issuing scheme's own rules. Standard library only; every function is total
(a malformed candidate returns ``False``, never raises).
"""

from __future__ import annotations

import re

#: IBAN lengths by country (ISO 13616 registry, the countries a corpus is likely to hold).
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21,
    "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27,
    "GB": 22, "GI": 23, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26,
    "IT": 27, "KW": 30, "KZ": 20, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27,
    "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26, "UA": 29,
}  # fmt: skip
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_NINO_BAD_PREFIX = {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}
_NANP = re.compile(r"(?:1[ .-]?)?(?:\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}")
_ISSUER = re.compile(r"4|5[1-5]|2[2-7]|3[47]|6(?:011|5|4[4-9])|3(?:0[0-5]|[68])|35")


def digits(text: str) -> str:
    return "".join(ch for ch in text if ch.isdigit())


def luhn(number: str) -> bool:
    """The Luhn (mod 10) check over an all-digit string."""
    if not number.isdigit() or len(number) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        value = int(char)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def card(candidate: str) -> bool:
    """A payment card number: 13-19 digits, a known issuer prefix, Luhn."""
    number = digits(candidate)
    if not 13 <= len(number) <= 19 or len(set(number)) == 1:
        return False
    return _ISSUER.match(number) is not None and luhn(number)


def iban(candidate: str) -> bool:
    """ISO 13616: the country's length and ISO 7064 mod 97-10 == 1."""
    code = candidate.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{8,30}", code):
        return False
    if IBAN_LENGTHS.get(code[:2]) != len(code):
        return False
    moved = code[4:] + code[:4]
    return int("".join(str(int(ch, 36)) for ch in moved)) % 97 == 1


def us_ssn(candidate: str) -> bool:
    """SSA rules: area not 000, 666 or 9xx; group not 00; serial not 0000."""
    match = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", candidate)
    if not match:
        return False
    area, group, serial = match.groups()
    if area in {"000", "666"} or area[0] == "9" or group == "00" or serial == "0000":
        return False
    return candidate not in {"123-45-6789", "078-05-1120"}  # published sample numbers


def uk_nino(candidate: str) -> bool:
    """HMRC National Insurance number: prefix letters and the excluded pairs."""
    code = candidate.replace(" ", "").upper()
    if not re.fullmatch(r"[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]", code):
        return False
    return code[:2] not in _NINO_BAD_PREFIX


def es_dni(candidate: str) -> bool:
    """Spanish DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter), mod 23."""
    code = candidate.replace("-", "").upper()
    if re.fullmatch(r"[XYZ]\d{7}[A-Z]", code):
        code = str("XYZ".index(code[0])) + code[1:]
    if not re.fullmatch(r"\d{8}[A-Z]", code):
        return False
    return _DNI_LETTERS[int(code[:8]) % 23] == code[8]


def phone(candidate: str) -> bool:
    """10-15 digits (E.164 bounds); a NANP number's area and exchange cannot start 0/1."""
    number = digits(candidate)
    if not 10 <= len(number) <= 15 or len(set(number)) < 3:
        return False
    if candidate.lstrip().startswith("+"):
        return True
    if not _NANP.fullmatch(candidate.strip()):
        return False  # without a country code only the NANP shape: dates and ids stay
    number = number[1:] if len(number) == 11 else number
    return number[0] not in "01" and number[3] not in "01"


def email(candidate: str) -> bool:
    local, _, domain = candidate.rpartition("@")
    if not local or len(candidate) > 254 or len(local) > 64:
        return False
    if local[0] == "." or local[-1] == "." or ".." in local:
        return False
    labels = domain.split(".")
    return all(label and label[0] != "-" and label[-1] != "-" for label in labels)


__all__ = ["IBAN_LENGTHS", "card", "digits", "email", "es_dni", "iban", "luhn", "phone",
           "uk_nino", "us_ssn"]  # fmt: skip
