"""Kullanıcı adı modülü: liste ayrıştırma, sınıflandırma ve (sahte ağla) tarama."""

import json

import httpx
import pytest

from osint_tui import kullanici_adi as ka


def _liste_yaz(tmp_path, siteler):
    yol = tmp_path / "s.json"
    yol.write_text(json.dumps({"siteler": siteler}), encoding="utf-8")
    return yol


def test_gercek_site_listesi_gecerli():
    siteler = ka.siteleri_yukle()
    assert 30 <= len(siteler) <= 60
    assert all("{}" in s.url for s in siteler)
    assert len({s.ad for s in siteler}) == len(siteler)


def test_liste_ayristirma(tmp_path):
    yol = _liste_yaz(tmp_path, [
        {"ad": "A", "url": "https://a.test/{}"},
        {"ad": "B", "url": "https://b.test/{}", "yontem": "bulunamadi_metni", "metin": "yok",
         "profil": "https://b.test/u/{}", "yok_kodlari": [400]},
    ])
    a, b = ka.siteleri_yukle(yol)
    assert a.yontem == "durum"
    assert b.profil_url("ali") == "https://b.test/u/ali"
    assert b.istek_url("ali") == "https://b.test/ali"
    assert b.yok_kodlari == (400,)


@pytest.mark.parametrize("kayit", [
    {"ad": "X", "url": "https://x.test/"},                       # {} yok
    {"ad": "X", "url": "https://x.test/{}", "yontem": "sihir"},  # bilinmeyen yöntem
    {"ad": "X", "url": "https://x.test/{}", "yontem": "bulundu_metni"},  # metin eksik
])
def test_liste_hatalari(tmp_path, kayit):
    with pytest.raises(ka.SiteListesiHatasi):
        ka.siteleri_yukle(_liste_yaz(tmp_path, [kayit]))


def test_liste_mukerrer_ve_bozuk(tmp_path):
    with pytest.raises(ka.SiteListesiHatasi):
        ka.siteleri_yukle(_liste_yaz(tmp_path, [
            {"ad": "A", "url": "https://a/{}"}, {"ad": "A", "url": "https://b/{}"}]))
    bozuk = tmp_path / "bozuk.json"
    bozuk.write_text("{degil json", encoding="utf-8")
    with pytest.raises(ka.SiteListesiHatasi):
        ka.siteleri_yukle(bozuk)
    with pytest.raises(ka.SiteListesiHatasi):
        ka.siteleri_yukle(tmp_path / "yok.json")


def test_siniflandirma_durum():
    s = ka.Site("A", "https://a/{}")
    assert ka.siniflandir(s, 200, "")[0] == ka.VAR
    assert ka.siniflandir(s, 404, "")[0] == ka.YOK
    assert ka.siniflandir(s, 410, "")[0] == ka.YOK
    assert ka.siniflandir(s, 403, "")[0] == ka.BELIRSIZ
    assert ka.siniflandir(s, 429, "")[0] == ka.BELIRSIZ
    assert ka.siniflandir(s, 503, "")[0] == ka.BELIRSIZ
    assert ka.siniflandir(s, 302, "")[0] == ka.BELIRSIZ


def test_siniflandirma_metin_ve_ek_kod():
    yok_metni = ka.Site("S", "https://s/{}", "bulunamadi_metni", "bulunamadı")
    assert ka.siniflandir(yok_metni, 200, "profil bulunamadı!")[0] == ka.YOK
    assert ka.siniflandir(yok_metni, 200, "merhaba")[0] == ka.VAR
    var_metni = ka.Site("S", "https://s/{}", "bulundu_metni", '"id"')
    assert ka.siniflandir(var_metni, 200, '{"id": 1}')[0] == ka.VAR
    assert ka.siniflandir(var_metni, 200, "[]")[0] == ka.YOK
    assert ka.siniflandir(var_metni, 404, "")[0] == ka.YOK
    ek = ka.Site("B", "https://b/{}", yok_kodlari=(400,))
    assert ka.siniflandir(ek, 400, "")[0] == ka.YOK


def test_kullanici_adi_dogrulama():
    assert ka.kullanici_adi_gecerli_mi("torvalds")
    assert ka.kullanici_adi_gecerli_mi("a.b_c-9")
    for kotu in ["", "a b", "../etc", "a/b", "x" * 41, "a?b=1"]:
        assert not ka.kullanici_adi_gecerli_mi(kotu)


async def test_tarama_sahte_ag():
    siteler = [
        ka.Site("Var", "https://var.test/{}"),
        ka.Site("Yok", "https://yok.test/{}"),
        ka.Site("Engel", "https://engel.test/{}"),
        ka.Site("Koptu", "https://koptu.test/{}"),
        ka.Site("Zaman", "https://zaman.test/{}"),
    ]

    def isle(istek: httpx.Request) -> httpx.Response:
        host = istek.url.host
        if host == "var.test":
            return httpx.Response(200, text="ok")
        if host == "yok.test":
            return httpx.Response(404)
        if host == "engel.test":
            return httpx.Response(403)
        if host == "zaman.test":
            raise httpx.ReadTimeout("yavaş", request=istek)
        raise httpx.ConnectError("kopuk", request=istek)

    gelenler = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(isle)) as c:
        sonuclar = await ka.tara("ali", siteler, gelenler.append, client=c)
    d = {s.site: s for s in sonuclar}
    assert len(sonuclar) == len(gelenler) == 5
    assert d["Var"].durum == ka.VAR and d["Var"].url == "https://var.test/ali"
    assert d["Yok"].durum == ka.YOK
    assert d["Engel"].durum == ka.BELIRSIZ
    assert d["Koptu"].durum == ka.BELIRSIZ and "bağlantı" in d["Koptu"].ayrinti
    assert d["Zaman"].durum == ka.BELIRSIZ and "zaman" in d["Zaman"].ayrinti


async def test_es_zamanlilik_siniri():
    import asyncio

    anlik = 0
    en_fazla = 0

    async def isle(istek: httpx.Request) -> httpx.Response:
        nonlocal anlik, en_fazla
        anlik += 1
        en_fazla = max(en_fazla, anlik)
        await asyncio.sleep(0.01)
        anlik -= 1
        return httpx.Response(404)

    siteler = [ka.Site(f"S{i}", f"https://s{i}.test/{{}}") for i in range(40)]
    async with httpx.AsyncClient(transport=httpx.MockTransport(isle)) as c:
        await ka.tara("ali", siteler, es_zamanli=5, client=c)
    assert 1 <= en_fazla <= 5
