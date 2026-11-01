import pytest

from osint import phone


def test_turkish_mobile_without_prefix_uses_default_region():
    r = phone.analyze("0555 111 22 33")
    body = r.sections["Number"]["items"]
    assert r.kind == "phone" and r.target == "+905551112233"
    assert body["E.164"] == "+905551112233"
    assert body["Country"] == "Türkiye" or body["Country"] == "Turkey"
    assert body["Line type"] == "mobile"
    assert body["Country code"] == "+90"


def test_international_prefix_ignores_region():
    r = phone.analyze("+1 650 253 0000", region="TR")
    items = r.sections["Number"]["items"]
    assert items["E.164"] == "+16502530000"
    assert items["Country"] == "United States"
    assert "America/Los_Angeles" in items["Timezones"]


def test_region_option_changes_interpretation():
    r = phone.analyze("650 253 0000", region="US")
    assert r.target == "+16502530000"


def test_invalid_number_is_reported_not_raised():
    r = phone.analyze("+90 123")
    assert r.sections["Number"]["items"]["Valid"] != "yes"
    assert any("not valid" in n for n in r.notes)


@pytest.mark.parametrize("bad", ["", "   ", "abc"])
def test_unparseable_raises_phone_error(bad):
    with pytest.raises(phone.PhoneError):
        phone.analyze(bad)


def test_region_valid():
    assert phone.region_valid("tr") and not phone.region_valid("ZZ")


def test_json_roundtrip():
    d = phone.analyze("+905551112233").to_dict()
    assert d["kind"] == "phone" and d["sections"]["Number"]["type"] == "kv"
