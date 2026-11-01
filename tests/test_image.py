import pytest
from PIL import Image

from osint import image


def make_jpeg(path, gps=True, meta=True):
    img = Image.new("RGB", (64, 48), "red")
    exif = Image.Exif()
    if meta:
        exif[0x010F] = "TestCam"
        exif[0x0110] = "Model X"
        exif[0x0131] = "UnitTest 1.0"
        exif.get_ifd(0x8769)[0x9003] = "2024:05:01 10:20:30"
    if gps:
        g = exif.get_ifd(0x8825)
        g[1], g[2] = "N", (41.0, 0.0, 30.0)
        g[3], g[4] = "W", (29.0, 30.0, 0.0)
        g[6] = 12.5
    img.save(path, exif=exif)
    return path


def test_exif_and_gps_extracted(tmp_path):
    r = image.analyze(str(make_jpeg(tmp_path / "a.jpg")))
    meta = r.sections["Metadata"]["items"]
    assert meta["Camera make"] == "TestCam" and meta["Camera model"] == "Model X"
    assert meta["Software"] == "UnitTest 1.0" and meta["Taken"] == "2024:05:01 10:20:30"
    loc = r.sections["GPS location"]["items"]
    assert loc["Latitude"] == "41.008333" and loc["Longitude"] == "-29.5"
    assert "google.com/maps?q=41.008333,-29.5" in loc["Google Maps"]
    assert "openstreetmap.org" in loc["OpenStreetMap"]
    assert r.sections["File"]["items"]["Size"] == "64x48"


def test_no_exif_is_graceful(tmp_path):
    p = tmp_path / "plain.png"
    Image.new("RGB", (8, 8)).save(p)
    r = image.analyze(str(p))
    assert "No EXIF" in r.sections["Metadata"]["text"]
    assert "GPS location" not in r.sections


def test_meta_without_gps_adds_note(tmp_path):
    r = image.analyze(str(make_jpeg(tmp_path / "b.jpg", gps=False)))
    assert "GPS location" not in r.sections and any("No GPS" in n for n in r.notes)


def test_tilde_is_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    make_jpeg(tmp_path / "h.jpg")
    assert image.analyze("~/h.jpg").target == "h.jpg"


def test_missing_and_non_image_files(tmp_path):
    with pytest.raises(image.ImageError):
        image.analyze(str(tmp_path / "nope.jpg"))
    bad = tmp_path / "bad.jpg"
    bad.write_text("not an image")
    with pytest.raises(image.ImageError, match="cannot read"):
        image.analyze(str(bad))


def test_dms_to_decimal_edge_cases():
    assert image.dms_to_decimal((10, 30, 0), "S") == -10.5
    assert image.dms_to_decimal((10, 30, 0), b"E") == 10.5
    assert image.dms_to_decimal("garbage", "N") is None
    assert image.gps_from_ifd({1: "N", 2: (95.0, 0, 0), 3: "E", 4: (1, 0, 0)}) is None
