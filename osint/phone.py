"""Phone number analysis, fully offline (Google's libphonenumber via ``phonenumbers``)."""

from __future__ import annotations

from .models import ScanResult, kv, text

DEFAULT_REGION = "TR"


class PhoneError(Exception):
    """The input could not be parsed as a phone number."""


def _lib():
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
    except ImportError as e:  # pragma: no cover - depends on the install
        raise PhoneError(
            "the 'phonenumbers' package is missing; reinstall osint to get the new dependencies"
        ) from e
    return phonenumbers, carrier, geocoder, timezone


def region_valid(region: str) -> bool:
    phonenumbers = _lib()[0]
    return region.upper() in phonenumbers.SUPPORTED_REGIONS


def analyze(raw: str, region: str = DEFAULT_REGION) -> ScanResult:
    """Parse ``raw`` and describe it. ``region`` is used when there is no ``+`` prefix."""
    phonenumbers, carrier, geocoder, timezone = _lib()
    cleaned = raw.strip()
    if not cleaned:
        raise PhoneError("empty phone number")
    try:
        num = phonenumbers.parse(cleaned, None if cleaned.startswith("+") else region.upper())
    except phonenumbers.NumberParseException as e:
        raise PhoneError(f"cannot parse '{raw}' as a phone number ({e})") from e

    fmt = phonenumbers.PhoneNumberFormat
    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    type_names = {
        v: k.replace("_", " ").lower() for k, v in vars(phonenumbers.PhoneNumberType).items()
        if k.isupper() and isinstance(v, int)
    }
    line = type_names.get(phonenumbers.number_type(num), "unknown")
    zones = [z for z in timezone.time_zones_for_number(num) if z != "Etc/Unknown"]

    items = {
        "Valid": "yes" if valid else ("possible but not assigned" if possible else "no"),
        "E.164": phonenumbers.format_number(num, fmt.E164),
        "International": phonenumbers.format_number(num, fmt.INTERNATIONAL),
        "National": phonenumbers.format_number(num, fmt.NATIONAL),
        "Country code": f"+{num.country_code}",
        "Country": geocoder.country_name_for_number(num, "en") or "",
        "Region": geocoder.description_for_number(num, "en") or "",
        "Carrier": carrier.name_for_number(num, "en") or "",
        "Line type": line,
        "Timezones": ", ".join(zones),
    }
    result = ScanResult("phone", items["E.164"])
    result.sections["Number"] = kv({k: v for k, v in items.items() if v})
    if not valid:
        result.notes.append("The number is not valid for its country; the details above may be incomplete.")
    result.notes.append(
        "Carrier is the original carrier of the number range; the number may have been ported since."
    )
    return result
