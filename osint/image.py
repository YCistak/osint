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
