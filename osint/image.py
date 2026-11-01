"""EXIF metadata and GPS extraction with Pillow. The file is read as data only."""

from __future__ import annotations

from pathlib import Path

from .models import ScanResult, kv, text

MAX_BYTES = 100 * 1024 * 1024

# EXIF tag ids we report, in display order.
TAGS = {
    0x010F: "Camera make",
    0x0110: "Camera model",
    0xA434: "Lens",
    0x0131: "Software",
    0x9003: "Taken",  # DateTimeOriginal (Exif IFD)
    0x0132: "Modified",  # DateTime
    0x013B: "Artist",
    0x8298: "Copyright",
    0x010E: "Description",
}
EXIF_IFD = 0x8769
GPS_IFD = 0x8825


class ImageError(Exception):
    """The file is missing or is not an image we can read."""


def _pil():
    try:
        from PIL import Image
    except ImportError as e:  # pragma: no cover - depends on the install
        raise ImageError("the 'Pillow' package is missing; reinstall osint to get the new dependencies") from e
    return Image


def _ratio(v) -> float:
    return float(v)


def dms_to_decimal(dms, ref) -> float | None:
    """Convert EXIF degrees/minutes/seconds + N/S/E/W to a signed decimal."""
    try:
        d, m, s = (_ratio(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    value = d + m / 60 + s / 3600
    if isinstance(ref, bytes):
        ref = ref.decode(errors="ignore")
    if str(ref).upper() in ("S", "W"):
        value = -value
    return round(value, 6)


def gps_from_ifd(gps: dict) -> tuple[float, float] | None:
    lat = dms_to_decimal(gps.get(2), gps.get(1)) if gps.get(2) and gps.get(1) else None
    lon = dms_to_decimal(gps.get(4), gps.get(3)) if gps.get(4) and gps.get(3) else None
    if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return lat, lon


def map_links(lat: float, lon: float) -> dict[str, str]:
    return {
        "Google Maps": f"https://www.google.com/maps?q={lat},{lon}",
        "OpenStreetMap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
    }


def _clean(v) -> str:
    if isinstance(v, bytes):
        v = v.decode(errors="ignore")
    return str(v).replace("\x00", "").strip()


def analyze(path: str) -> ScanResult:
    """Read EXIF from a local image. Raises ImageError for unreadable files."""
    Image = _pil()
    p = Path(path).expanduser()
    if not p.is_file():
        raise ImageError(f"file not found: {p}")
    if p.stat().st_size > MAX_BYTES:
        raise ImageError("file is larger than 100 MB")
    try:
        with Image.open(p) as img:
            exif = img.getexif()
            info = {
                "File": p.name,
                "Format": img.format or "",
                "Size": f"{img.width}x{img.height}",
            }
            tags = {t: exif.get(t) for t in TAGS}
            try:
                tags.update({t: v for t, v in exif.get_ifd(EXIF_IFD).items() if t in TAGS})
            except Exception:  # damaged sub-IFD: ignore, keep the main one
                pass
            try:
                gps = dict(exif.get_ifd(GPS_IFD))
            except Exception:
                gps = {}
    except ImageError:
        raise
    except Exception as e:
        raise ImageError(f"cannot read '{p.name}' as an image ({type(e).__name__})") from e

    result = ScanResult("image", p.name)
    result.sections["File"] = kv({k: v for k, v in info.items() if v})
    meta = {label: _clean(tags[t]) for t, label in TAGS.items() if tags.get(t) not in (None, "")}
    meta = {k: v for k, v in meta.items() if v}
    if meta:
        result.sections["Metadata"] = kv(meta)
    coords = gps_from_ifd(gps) if gps else None
    if coords:
        lat, lon = coords
        loc = {"Latitude": f"{lat}", "Longitude": f"{lon}"}
        if gps.get(6) is not None:
            try:
                loc["Altitude"] = f"{_ratio(gps[6]):.1f} m"
            except (TypeError, ValueError, ZeroDivisionError):
                pass
        loc.update(map_links(lat, lon))
        result.sections["GPS location"] = kv(loc)
    if not meta and not coords:
        result.sections["Metadata"] = text("No EXIF metadata found (stripped, or a format without EXIF).")
    elif not coords:
        result.notes.append("No GPS coordinates in this image.")
    return result


# ---------------------------------------------------------------- reverse image search

DOWNLOAD_LIMIT = 20 * 1024 * 1024
UPLOAD_PAGES = {
    "Google Lens": "https://lens.google.com/",
    "Yandex Images": "https://yandex.com/images/",
    "Bing Visual Search": "https://www.bing.com/visualsearch",
    "TinEye": "https://tineye.com/",
}


def is_url(target: str) -> bool:
    return target.strip().lower().startswith(("http://", "https://"))


def reverse_search_links(url: str) -> dict[str, str]:
    """Search-by-URL links of the four big reverse image engines (nothing is fetched)."""
    from urllib.parse import quote

    q = quote(url.strip(), safe="")
    return {
        "Google Lens": f"https://lens.google.com/uploadbyurl?url={q}",
        "Yandex Images": f"https://yandex.com/images/search?rpt=imageview&url={q}",
        "Bing Visual Search": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}",
        "TinEye": f"https://tineye.com/search?url={q}",
    }


def download_image(url: str, client=None, limit: int = DOWNLOAD_LIMIT) -> Path:
    """Download an image URL to a temporary file (data only, never executed).

    Checks the content type and stops at ``limit`` bytes. The caller deletes the file.
    """
    import tempfile

    import httpx

    from . import net

    own = client is None
    client = client or net.sync_client(timeout=20.0, follow_redirects=True,
                                       headers={"User-Agent": "osint-cli (+https://github.com/YCistak/osint)"})
    path: Path | None = None
    try:
        with client.stream("GET", url) as resp:
            if resp.status_code != 200:
                raise ImageError(f"could not download the image (HTTP {resp.status_code})")
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if not ctype.startswith("image/"):
                raise ImageError(f"the URL is not an image (content type '{ctype or 'unknown'}')")
            declared = resp.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > limit:
                raise ImageError(f"the image is larger than {limit // (1024 * 1024)} MB")
            fd, name = tempfile.mkstemp(prefix="osint-img-", suffix=".bin")
            path = Path(name)
            size = 0
            with open(fd, "wb") as out:
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > limit:
                        raise ImageError(f"the image is larger than {limit // (1024 * 1024)} MB")
                    out.write(chunk)
        return path
    except ImageError:
        if path:
            path.unlink(missing_ok=True)
        raise
    except httpx.HTTPError as e:
        if path:
            path.unlink(missing_ok=True)
        raise ImageError(f"could not download the image ({type(e).__name__})") from None
    finally:
        if own:
            client.close()


def analyze_target(target: str, client=None) -> ScanResult:
    """EXIF of a local file or an image URL, plus reverse image search links."""
    from urllib.parse import urlsplit

    from .models import kv, text

    target = target.strip()
    if is_url(target):
        path = download_image(target, client)
        try:
            result = analyze(str(path))
        finally:
            path.unlink(missing_ok=True)
        name = Path(urlsplit(target).path).name or urlsplit(target).netloc
        result.target = name
        file_items = dict(result.sections.get("File", {}).get("items", {}))
        file_items["File"] = name
        file_items["Source"] = target
        result.sections["File"] = kv(file_items)
        result.sections["Reverse image search"] = kv(reverse_search_links(target))
    else:
        result = analyze(target)
        links = dict(UPLOAD_PAGES)
        result.sections["Reverse image search"] = kv(links)
        result.notes.append(
            "Reverse search for a local file: open one of the pages above and upload the file yourself; "
            "osint does not upload your image anywhere. For a public image URL, the search links are built automatically.")
    return result
