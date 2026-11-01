"""Alan adı / IP modülü: ayıklama, hedef türü, sahte ağ ve sahte DNS."""

import dns.resolver
import httpx
import pytest

from osint_tui import alan_ip


def test_hedef_turu():
    assert alan_ip.hedef_turu("1.1.1.1") == "ip"
    assert alan_ip.hedef_turu("2606:4700:4700::1111") == "ip"
    assert alan_ip.hedef_turu("example.com") == "alan"
    assert alan_ip.hedef_turu("alt.alan.example.co.uk") == "alan"
    assert alan_ip.hedef_turu("türkiye.gov.tr") == "alan"
    for kotu in ["", "localhost", "a b.com", "-x.com", "http://x"]:
        assert alan_ip.hedef_turu(kotu) == "gecersiz"


def test_hedefi_temizle():
    assert alan_ip.hedefi_temizle("  https://Example.COM/yol?x=1 ") == "example.com"
    assert alan_ip.hedefi_temizle("example.com.") == "example.com"
    assert alan_ip.hedefi_temizle("example.com:8080") == "example.com"
    assert alan_ip.hedefi_temizle("1.1.1.1") == "1.1.1.1"


def test_crtsh_tekillestirme():
    kayitlar = [
        {"name_value": "example.com\nwww.example.com", "common_name": "example.com"},
        {"name_value": "*.example.com", "common_name": "*.example.com"},
        {"name_value": "WWW.example.com", "common_name": "www.example.com"},
        {"name_value": "mail.example.com\nbaska.org", "common_name": "mail.example.com"},
        {"name_value": "kullanici@example.com", "common_name": "x"},  # e-posta sertifikası
        {"name_value": "evil-example.com", "common_name": "evil-example.com"},  # ek alan değil
        "bozuk kayıt",
        {},
    ]
    assert alan_ip.alt_alanlari_ayikla(kayitlar, "example.com") == [
        "example.com", "mail.example.com", "www.example.com",
    ]


def _istemci(isle) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(isle))


def test_crtsh_sorgula_basarili():
    def isle(istek):
        assert "crt.sh" in istek.url.host and "output=json" in str(istek.url)
        return httpx.Response(200, json=[{"name_value": "a.example.com\nb.example.com"}])

    assert alan_ip.crtsh_sorgula("example.com", _istemci(isle)) == ["a.example.com", "b.example.com"]


@pytest.mark.parametrize("yanit,parca", [
    (httpx.Response(502), "502"),
    (httpx.Response(200, text="<html>json değil</html>"), "JSON"),
])
def test_crtsh_hatalari(yanit, parca):
    with pytest.raises(RuntimeError, match=parca):
        alan_ip.crtsh_sorgula("example.com", _istemci(lambda r: yanit))


def test_crtsh_zaman_asimi_bir_kez_tekrar_dener():
    sayac = {"n": 0}

    def isle(istek):
        sayac["n"] += 1
        raise httpx.ReadTimeout("yavaş", request=istek)

    with pytest.raises(RuntimeError, match="zaman aşımı"):
        alan_ip.crtsh_sorgula("example.com", _istemci(isle))
    assert sayac["n"] == 2


def test_ip_konum():
    def isle(istek):
        return httpx.Response(200, json={
            "status": "success", "country": "Türkiye", "city": "Ankara", "lat": 39.9, "lon": 32.8,
            "isp": "X", "query": "1.2.3.4"})

    s = alan_ip.ip_konum("1.2.3.4", _istemci(isle))
    assert s["Ülke"] == "Türkiye" and s["Koordinat"] == "39.9, 32.8"


def test_ip_konum_hata():
    hatali = lambda r: httpx.Response(200, json={"status": "fail", "message": "private range"})
    with pytest.raises(RuntimeError, match="private range"):
        alan_ip.ip_konum("10.0.0.1", _istemci(hatali))


class _SahteCozucu:
    """dns.resolver.Resolver yerine geçer."""

    def __init__(self):
        self.lifetime = 0

    def resolve(self, ad, tur):
        if str(ad) == "yok.test":
            raise dns.resolver.NXDOMAIN()
        if tur == "A":
            return [type("R", (), {"to_text": lambda s: "9.9.9.9"})(),
                    type("R", (), {"to_text": lambda s: "1.1.1.1"})()]
        raise dns.resolver.NoAnswer()


def test_dns_sorgula_sahte(monkeypatch):
    monkeypatch.setattr(alan_ip.dns.resolver, "Resolver", _SahteCozucu)
    s = alan_ip.dns_sorgula("ornek.test")
    assert s["A"] == ["1.1.1.1", "9.9.9.9"]  # sıralı
    assert s["MX"] == [] and set(s) == set(alan_ip.DNS_TURLERI)
    with pytest.raises(ValueError, match="NXDOMAIN"):
        alan_ip.dns_sorgula("yok.test")
