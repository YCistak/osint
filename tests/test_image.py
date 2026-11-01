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


# ---- reverse image search and URL download ---------------------------------------

import io as _io

import httpx


def jpeg_bytes(**kw):
    buf = _io.BytesIO()
    Image.new("RGB", (8, 8), "blue").save(buf, "JPEG")
    return buf.getvalue()


def image_client(body=None, ctype="image/jpeg", status=200, headers=None):
    body = jpeg_bytes() if body is None else body

    def handler(request):
        return httpx.Response(status, content=body, headers={"content-type": ctype, **(headers or {})})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_reverse_search_links_are_encoded():
    links = image.reverse_search_links("https://example.com/a b.jpg?x=1&y=2")
    assert list(links) == ["Google Lens", "Yandex Images", "Bing Visual Search", "TinEye"]
    assert links["Google Lens"] == "https://lens.google.com/uploadbyurl?url=https%3A%2F%2Fexample.com%2Fa%20b.jpg%3Fx%3D1%26y%3D2"
    assert links["Yandex Images"].startswith("https://yandex.com/images/search?rpt=imageview&url=")
    assert links["Bing Visual Search"].startswith("https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:")
    assert links["TinEye"].startswith("https://tineye.com/search?url=https%3A")
    assert all(" " not in v and "&y=2" not in v for v in links.values())


def test_is_url():
    assert image.is_url("https://a.test/x.jpg") and image.is_url(" HTTP://a.test/x.jpg")
    assert not image.is_url("/home/me/x.jpg") and not image.is_url("ftp://a.test/x.jpg")


def test_download_image_writes_temp_file_and_analyze_target_cleans_up():
    import glob
    import tempfile

    before = set(glob.glob(f"{tempfile.gettempdir()}/osint-img-*"))
    r = image.analyze_target("https://cdn.test/pics/photo.jpg?size=2", image_client())
    assert r.target == "photo.jpg"
    assert r.sections["File"]["items"]["Source"] == "https://cdn.test/pics/photo.jpg?size=2"
    assert r.sections["File"]["items"]["Format"] == "JPEG"
    assert "TinEye" in r.sections["Reverse image search"]["items"]
    assert set(glob.glob(f"{tempfile.gettempdir()}/osint-img-*")) == before


def test_download_rejects_non_image_error_status_and_oversize():
    with pytest.raises(image.ImageError, match="not an image"):
        image.download_image("https://x.test/a", image_client(b"<html>", "text/html"))
    with pytest.raises(image.ImageError, match="HTTP 404"):
        image.download_image("https://x.test/a", image_client(b"", status=404))
    with pytest.raises(image.ImageError, match="larger than"):
        image.download_image("https://x.test/a", image_client(headers={"content-length": str(21 * 1024 * 1024)}))
    with pytest.raises(image.ImageError, match="larger than"):
        image.download_image("https://x.test/a", image_client(b"x" * 5000), limit=1000)


def test_download_leaves_no_temp_file_on_failure():
    import glob
    import tempfile

    before = set(glob.glob(f"{tempfile.gettempdir()}/osint-img-*"))
    with pytest.raises(image.ImageError):
        image.download_image("https://x.test/a", image_client(b"x" * 5000), limit=1000)
    assert set(glob.glob(f"{tempfile.gettempdir()}/osint-img-*")) == before


def test_download_network_error_is_image_error():
    def boom(request):
        raise httpx.ConnectError("down")

    with pytest.raises(image.ImageError, match="could not download"):
        image.download_image("https://x.test/a", httpx.Client(transport=httpx.MockTransport(boom)))


def test_url_that_is_not_a_real_image_fails_cleanly():
    with pytest.raises(image.ImageError, match="cannot read"):
        image.analyze_target("https://x.test/a.jpg", image_client(b"not really an image"))


def test_local_file_gets_upload_pages_and_manual_note(tmp_path):
    p = make_jpeg(tmp_path / "me.jpg")
    r = image.analyze_target(str(p))
    pages = r.sections["Reverse image search"]["items"]
    assert pages["TinEye"] == "https://tineye.com/" and "Google Lens" in pages
    assert any("upload the file yourself" in n for n in r.notes)
