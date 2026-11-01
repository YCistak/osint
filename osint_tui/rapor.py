"""Markdown rapor üretimi ve kaydı."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

from .alan_ip import DNS_TURLERI

PROJE_KOKU = Path(__file__).resolve().parent.parent
VARSAYILAN_DIZIN = PROJE_KOKU / "raporlar"

DURUM_SIMGE = {"var": "✔", "yok": "✘", "belirsiz": "?"}

YASAL_NOT = (
    "> Bu rapor yalnızca kişinin kendi dijital izini denetlemesi veya CTF/eğitim "
    "amacıyla hazırlanmıştır. Başkası hakkında dosya hazırlamak KVKK ve TCK 136 "
    "kapsamına girebilir."
)


def rapor_dizini() -> Path:
    """Ortam değişkeniyle değiştirilebilir (testler için)."""
    return Path(os.environ.get("OSINT_TUI_RAPOR_DIZIN", VARSAYILAN_DIZIN))


def dosya_adi_icin_temizle(hedef: str) -> str:
    """Hedefi güvenli bir dosya adı parçasına çevirir (yol kaçışını engeller)."""
    t = re.sub(r"[^A-Za-z0-9._@-]+", "_", hedef.strip()).strip("._")
    return t[:80] or "hedef"


def raporu_kaydet(
    tur: str,
    hedef: str,
    icerik: str,
    dizin: Path | None = None,
    simdi: datetime | None = None,
) -> Path:
    """`<dizin>/<tür>-<hedef>-<tarih>.md` olarak kaydeder.

    Aynı ad varsa üzerine yazmaz; saat bilgisi ekler, o da varsa sayaç ekler.
    """
    simdi = simdi or datetime.now()
    dizin = Path(dizin) if dizin else rapor_dizini()
    dizin.mkdir(parents=True, exist_ok=True)
    taban = f"{tur}-{dosya_adi_icin_temizle(hedef)}-{simdi:%Y-%m-%d}"
    yol = dizin / f"{taban}.md"
    if yol.exists():
        yol = dizin / f"{taban}-{simdi:%H%M%S}.md"
    sayac = 2
    while yol.exists():
        yol = dizin / f"{taban}-{simdi:%H%M%S}-{sayac}.md"
        sayac += 1
    yol.write_text(icerik, encoding="utf-8")
    return yol


def _baslik(baslik: str, hedef: str, simdi: datetime) -> list[str]:
    return [
        f"# {baslik}: {hedef}",
        "",
        f"- Tarih: {simdi:%Y-%m-%d %H:%M}",
        f"- Hedef: `{hedef}`",
        "",
        YASAL_NOT,
        "",
    ]


def _hucre(metin: str) -> str:
    return str(metin).replace("|", "\\|").replace("\n", " ")


def kullanici_adi_raporu(hedef: str, sonuclar: list, simdi: datetime | None = None) -> str:
    """`sonuclar`: .site .url .durum .ayrinti alanlı nesneler."""
    simdi = simdi or datetime.now()
    bulunan = [s for s in sonuclar if s.durum == "var"]
    belirsiz = [s for s in sonuclar if s.durum == "belirsiz"]
    yok = [s for s in sonuclar if s.durum == "yok"]
    satir = _baslik("Kullanıcı adı raporu", hedef, simdi)
    satir += [
        f"Taranan site: {len(sonuclar)} · Bulunan: {len(bulunan)} · "
        f"Bulunamayan: {len(yok)} · Belirsiz: {len(belirsiz)}",
        "",
        "## Bulunan hesaplar",
        "",
    ]
    if bulunan:
        satir += ["| Site | Adres |", "|---|---|"]
        satir += [f"| {_hucre(s.site)} | {_hucre(s.url)} |" for s in sorted(bulunan, key=lambda x: x.site)]
    else:
        satir.append("Hiçbir sitede hesap bulunamadı.")
    satir += ["", "## Belirsiz sonuçlar (elle kontrol edin)", ""]
    if belirsiz:
        satir += ["| Site | Sebep |", "|---|---|"]
        satir += [f"| {_hucre(s.site)} | {_hucre(s.ayrinti)} |" for s in sorted(belirsiz, key=lambda x: x.site)]
    else:
        satir.append("Yok.")
    return "\n".join(satir) + "\n"


def eposta_raporu(hedef: str, sonuclar: list, simdi: datetime | None = None) -> str:
    """`sonuclar`: .servis .alan_adi .durum .ek alanlı nesneler."""
    simdi = simdi or datetime.now()
    var = [s for s in sonuclar if s.durum == "var"]
    belirsiz = [s for s in sonuclar if s.durum == "belirsiz"]
    satir = _baslik("E-posta raporu", hedef, simdi)
    satir += [
        f"Denetlenen servis: {len(sonuclar)} · Kayıtlı: {len(var)} · "
        f"Belirsiz (istek sınırı/hata): {len(belirsiz)}",
        "",
        "## Kayıtlı olduğu servisler",
        "",
    ]
    if var:
        satir += ["| Servis | Alan adı | Ek bilgi |", "|---|---|---|"]
        satir += [
            f"| {_hucre(s.servis)} | {_hucre(s.alan_adi)} | {_hucre(s.ek)} |"
            for s in sorted(var, key=lambda x: x.servis)
        ]
    else:
        satir.append("Denetlenen servislerin hiçbirinde kayıt bulunamadı.")
    satir += [
        "",
        "## Belirsiz servisler",
        "",
        ", ".join(sorted(s.servis for s in belirsiz)) or "Yok.",
        "",
        "## Not",
        "",
        "Veri sızıntısı denetimi için haveibeenpwned.com adresini elle kontrol edin "
        "(bu araç ücretli HIBP API anahtarı kullanmaz).",
        "Şifre sıfırlama akışını tetikleyen servisler (Adobe, Mail.ru, Odnoklassniki, "
        "Samsung) hedefe e-posta gitmesin diye atlanmıştır.",
    ]
    return "\n".join(satir) + "\n"


def alan_ip_raporu(
    hedef: str, tur: str, bolumler: dict[str, str], simdi: datetime | None = None
) -> str:
    """`bolumler`: bölüm başlığı -> hazır Markdown gövdesi (sıralı sözlük)."""
    simdi = simdi or datetime.now()
    satir = _baslik("Alan adı / IP raporu", hedef, simdi)
    satir.append(f"- Tür: {'IP adresi' if tur == 'ip' else 'Alan adı'}")
    satir.append("")
    for baslik, govde in bolumler.items():
        satir += [f"## {baslik}", "", govde.rstrip(), ""]
    return "\n".join(satir)


def sozluk_md(veri: dict[str, str]) -> str:
    return "\n".join(f"- **{k}:** {v}" for k, v in veri.items())


def dns_md(kayitlar: dict[str, list[str]]) -> str:
    satir = ["| Tür | Değerler |", "|---|---|"]
    for tur in DNS_TURLERI:
        degerler = kayitlar.get(tur, [])
        satir.append(f"| {tur} | {_hucre('; '.join(degerler)) if degerler else '—'} |")
    return "\n".join(satir)


def liste_md(ogeler: list[str]) -> str:
    return "\n".join(f"- `{o}`" for o in ogeler)
