"""Kullanıcı adı tarama mantığı (arayüzden bağımsız, test edilebilir)."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

SITE_DOSYASI = Path(__file__).parent / "siteler.json"
GECERLI_YONTEMLER = {"durum", "bulunamadi_metni", "bulundu_metni"}

VAR = "var"
YOK = "yok"
BELIRSIZ = "belirsiz"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
# Kullanıcı adı olarak kabul edilen karakterler (URL'ye güvenle gömülür).
KULLANICI_ADI_DESENI = re.compile(r"^[A-Za-z0-9._-]{1,40}$")


class SiteListesiHatasi(Exception):
    """Site listesi dosyası bozuk veya eksikse fırlatılır."""


@dataclass(frozen=True)
class Site:
    ad: str
    url: str
    yontem: str = "durum"
    metin: str = ""
    profil: str = ""
    yok_kodlari: tuple[int, ...] = ()

    def istek_url(self, kullanici: str) -> str:
        return self.url.replace("{}", quote(kullanici, safe=""))

    def profil_url(self, kullanici: str) -> str:
        sablon = self.profil or self.url
        return sablon.replace("{}", quote(kullanici, safe=""))


@dataclass(frozen=True)
class Sonuc:
    site: str
    url: str
    durum: str  # VAR | YOK | BELIRSIZ
    ayrinti: str = ""


def siteleri_yukle(yol: Path | str | None = None) -> list[Site]:
    """JSON dosyasından site listesini okur ve doğrular."""
    yol = Path(yol) if yol else SITE_DOSYASI
    try:
        veri = json.loads(yol.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise SiteListesiHatasi(f"Site listesi bulunamadı: {yol}") from e
    except json.JSONDecodeError as e:
        raise SiteListesiHatasi(f"Site listesi geçerli JSON değil: {e}") from e

    ham = veri.get("siteler") if isinstance(veri, dict) else None
    if not isinstance(ham, list) or not ham:
        raise SiteListesiHatasi("Site listesinde 'siteler' dizisi yok veya boş.")

    siteler: list[Site] = []
    gorulen: set[str] = set()
    for i, kayit in enumerate(ham, 1):
        if not isinstance(kayit, dict):
            raise SiteListesiHatasi(f"{i}. kayıt bir nesne değil.")
        ad = kayit.get("ad")
        url = kayit.get("url")
        yontem = kayit.get("yontem", "durum")
        metin = kayit.get("metin", "")
        if not ad or not url or "{}" not in url:
            raise SiteListesiHatasi(f"{i}. kayıt: 'ad' ve '{{}}' içeren 'url' zorunlu.")
        if yontem not in GECERLI_YONTEMLER:
            raise SiteListesiHatasi(f"{ad}: bilinmeyen yöntem '{yontem}'.")
        if yontem != "durum" and not metin:
            raise SiteListesiHatasi(f"{ad}: '{yontem}' yöntemi için 'metin' gerekli.")
        if ad in gorulen:
            raise SiteListesiHatasi(f"{ad}: aynı site iki kez tanımlanmış.")
        gorulen.add(ad)
        yok = tuple(int(k) for k in kayit.get("yok_kodlari", []))
        siteler.append(Site(ad, url, yontem, metin, kayit.get("profil", ""), yok))
    return siteler


def siniflandir(site: Site, kod: int, govde: str) -> tuple[str, str]:
    """HTTP yanıtından (durum, ayrıntı) çıkarır. Emin değilse BELIRSIZ döner."""
    if kod == 429:
        return BELIRSIZ, "istek sınırı (429)"
    if kod in (401, 403) or kod >= 500:
        return BELIRSIZ, f"site engelledi/hata (HTTP {kod})"

    if kod in site.yok_kodlari:
        return YOK, f"HTTP {kod}"

    if site.yontem == "durum":
        if 200 <= kod < 300:
            return VAR, f"HTTP {kod}"
        if kod in (404, 410):
            return YOK, f"HTTP {kod}"
        return BELIRSIZ, f"beklenmeyen kod (HTTP {kod})"

    # Metin tabanlı yöntemler: sadece 200 ve 404 anlamlı.
    if kod == 404 and site.yontem == "bulundu_metni":
        return YOK, "HTTP 404"
    if not (200 <= kod < 300):
        return BELIRSIZ, f"beklenmeyen kod (HTTP {kod})"
    icerir = site.metin in govde
    if site.yontem == "bulunamadi_metni":
        return (YOK, "bulunamadı metni var") if icerir else (VAR, "bulunamadı metni yok")
    return (VAR, "profil işareti bulundu") if icerir else (YOK, "profil işareti yok")


async def site_kontrol(
    client: httpx.AsyncClient, site: Site, kullanici: str
) -> Sonuc:
    """Tek siteyi kontrol eder; hiçbir hata dışarı sızmaz."""
    profil = site.profil_url(kullanici)
    try:
        yanit = await client.get(site.istek_url(kullanici))
        durum, ayrinti = siniflandir(site, yanit.status_code, yanit.text[:200_000])
    except httpx.TimeoutException:
        durum, ayrinti = BELIRSIZ, "zaman aşımı"
    except httpx.HTTPError as e:
        durum, ayrinti = BELIRSIZ, f"bağlantı hatası ({type(e).__name__})"
    except Exception as e:  # beklenmeyen ne olursa olsun çökme
        durum, ayrinti = BELIRSIZ, f"hata ({type(e).__name__})"
    return Sonuc(site.ad, profil, durum, ayrinti)


def yeni_istemci(zaman_asimi: float = 8.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=zaman_asimi,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
    )


def kullanici_adi_gecerli_mi(kullanici: str) -> bool:
    return bool(KULLANICI_ADI_DESENI.match(kullanici))


async def tara(
    kullanici: str,
    siteler: list[Site],
    sonuc_geldi: Callable[[Sonuc], None] | None = None,
    *,
    es_zamanli: int = 20,
    zaman_asimi: float = 8.0,
    client: httpx.AsyncClient | None = None,
) -> list[Sonuc]:
    """Kullanıcı adını tüm sitelerde eşzamanlı arar; her sonuç geldikçe bildirir."""
    sinir = asyncio.Semaphore(es_zamanli)
    kendi_client = client is None
    client = client or yeni_istemci(zaman_asimi)
    sonuclar: list[Sonuc] = []

    async def calis(site: Site) -> None:
        async with sinir:
            s = await site_kontrol(client, site, kullanici)
        sonuclar.append(s)
        if sonuc_geldi:
            sonuc_geldi(s)

    try:
        await asyncio.gather(*(calis(s) for s in siteler))
    finally:
        if kendi_client:
            await client.aclose()
    return sonuclar
