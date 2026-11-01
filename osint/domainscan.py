"""Alan adı / IP sorguları: whois, DNS, crt.sh alt alan adları, ters DNS, coğrafi konum."""

from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime

import dns.exception
import dns.resolver
import dns.reversename
import httpx

DNS_TURLERI = ["A", "AAAA", "MX", "NS", "TXT"]
CRT_URL = "https://crt.sh/?q=%25.{alan}&output=json"
IPAPI_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
)
ALAN_DESENI = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I
)


def hedef_turu(hedef: str) -> str:
    """'ip', 'alan' ya da 'gecersiz' döner."""
    hedef = hedef.strip()
    try:
        ipaddress.ip_address(hedef)
        return "ip"
    except ValueError:
        pass
    # IDN (ör. türkçe karakterli) alan adlarını punycode'a çevirip dene
    try:
        ascii_hedef = hedef.encode("idna").decode("ascii")
    except UnicodeError:
        return "gecersiz"
    return "alan" if ALAN_DESENI.match(ascii_hedef) else "gecersiz"


def hedefi_temizle(ham: str) -> str:
    """URL/boşluk/sondaki nokta gibi artıkları temizler (ör. https://a.com/x -> a.com)."""
    h = ham.strip()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h, flags=re.I)
    h = h.split("/")[0].split("?")[0]
    if h.count(":") == 1:  # alan:port
        h = h.split(":")[0]
    return h.rstrip(".").lower()


# ---------------------------------------------------------------- whois

def _tarih_str(v) -> str:
    if isinstance(v, list):
        v = v[0] if v else None
    if isinstance(v, (datetime, date)):
        return v.strftime("%Y-%m-%d")
    return str(v) if v else ""


def _liste_str(v) -> str:
    if not v:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ", ".join(sorted({str(x).lower() for x in v}))
    return str(v)


def whois_sorgula(alan: str) -> dict[str, str]:
    """python-whois ile sorgular (bloklayan çağrı; thread içinde çalıştırın)."""
    import whois

    w = whois.whois(alan)
    alanlar = {
        "Alan adı": _liste_str(w.get("domain_name")),
        "Kayıt kuruluşu": _liste_str(w.get("registrar")),
        "Oluşturulma": _tarih_str(w.get("creation_date")),
        "Güncellenme": _tarih_str(w.get("updated_date")),
        "Bitiş": _tarih_str(w.get("expiration_date")),
        "Ad sunucuları": _liste_str(w.get("name_servers")),
        "Durum": _liste_str(w.get("status")),
        "Kuruluş": _liste_str(w.get("org")),
        "Ülke": _liste_str(w.get("country")),
        "E-posta": _liste_str(w.get("emails")),
    }
    dolu = {k: v for k, v in alanlar.items() if v}
    if not dolu:
        raise ValueError("Whois kaydı bulunamadı (alan adı kayıtsız olabilir).")
    return dolu


# ---------------------------------------------------------------- DNS

def dns_sorgula(alan: str, turler: list[str] | None = None) -> dict[str, list[str]]:
    """Her kayıt türü için değer listesi döner; bulunamayan türler boş liste olur."""
    cozucu = dns.resolver.Resolver()
    cozucu.lifetime = 6.0
    sonuc: dict[str, list[str]] = {}
    for tur in turler or DNS_TURLERI:
        try:
            yanit = cozucu.resolve(alan, tur)
            sonuc[tur] = sorted(r.to_text() for r in yanit)
        except dns.resolver.NXDOMAIN:
            raise ValueError(f"'{alan}' alan adı DNS'te bulunamadı (NXDOMAIN).")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            sonuc[tur] = []
        except dns.exception.Timeout:
            sonuc[tur] = []
    return sonuc


# ---------------------------------------------------------------- crt.sh

def alt_alanlari_ayikla(kayitlar: list[dict], alan: str) -> list[str]:
    """crt.sh JSON kayıtlarından alt alan adlarını tekilleştirip sıralı döner.

    name_value alanı satır sonlarıyla birden çok ad içerebilir; '*.' önekleri
    atılır, küçük harfe çevrilir, hedef alana ait olmayanlar elenir.
    """
    alan = alan.lower().rstrip(".")
    bulunan: set[str] = set()
    for kayit in kayitlar:
        if not isinstance(kayit, dict):
            continue
        for alan_alan in ("name_value", "common_name"):
            for ad in str(kayit.get(alan_alan, "")).splitlines():
                ad = ad.strip().lower().lstrip("*.").rstrip(".")
                if not ad or "@" in ad or " " in ad:
                    continue
                if ad == alan or ad.endswith("." + alan):
                    bulunan.add(ad)
    return sorted(bulunan)


def crtsh_sorgula(alan: str, client: httpx.Client | None = None) -> list[str]:
    kendi = client is None
    client = client or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        try:
            yanit = client.get(CRT_URL.format(alan=alan))
        except httpx.TimeoutException:  # crt.sh sık yoğundur: bir kez daha dene
            yanit = client.get(CRT_URL.format(alan=alan))
        if yanit.status_code != 200:
            raise RuntimeError(f"crt.sh yanıt vermedi (HTTP {yanit.status_code}); biraz sonra tekrar deneyin.")
        try:
            kayitlar = yanit.json()
        except ValueError:
            raise RuntimeError("crt.sh geçersiz yanıt döndürdü (JSON değil).")
        return alt_alanlari_ayikla(kayitlar, alan)
    except httpx.TimeoutException:
        raise RuntimeError("crt.sh zaman aşımına uğradı (servis sık sık yoğundur).")
    except httpx.HTTPError as e:
        raise RuntimeError(f"crt.sh'e bağlanılamadı: {type(e).__name__}")
    finally:
        if kendi:
            client.close()


# ---------------------------------------------------------------- IP

def ters_dns(ip: str) -> list[str]:
    cozucu = dns.resolver.Resolver()
    cozucu.lifetime = 6.0
    try:
        yanit = cozucu.resolve(dns.reversename.from_address(ip), "PTR")
        return sorted(r.to_text().rstrip(".") for r in yanit)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        raise RuntimeError("Ters DNS sorgusu zaman aşımına uğradı.")


def ip_konum(ip: str, client: httpx.Client | None = None) -> dict[str, str]:
    """ip-api.com (ücretsiz, anahtarsız, yalnızca HTTP) ile temel konum bilgisi."""
    kendi = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        yanit = client.get(IPAPI_URL.format(ip=ip))
        veri = yanit.json()
    except httpx.HTTPError as e:
        raise RuntimeError(f"ip-api.com'a ulaşılamadı: {type(e).__name__}")
    except ValueError:
        raise RuntimeError("ip-api.com geçersiz yanıt döndürdü.")
    finally:
        if kendi:
            client.close()
    if veri.get("status") != "success":
        raise RuntimeError(f"Konum bulunamadı: {veri.get('message', 'bilinmeyen sebep')}")
    harita = {
        "Ülke": "country", "Bölge": "regionName", "Şehir": "city", "Posta kodu": "zip",
        "Saat dilimi": "timezone", "Servis sağlayıcı (ISP)": "isp",
        "Kuruluş": "org", "AS": "as",
    }
    sonuc = {k: str(veri[v]) for k, v in harita.items() if veri.get(v)}
    if "lat" in veri and "lon" in veri:
        sonuc["Koordinat"] = f"{veri['lat']}, {veri['lon']}"
    return sonuc
