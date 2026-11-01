"""Textual arayüz testleri (Pilot, başsız; ağ tamamen sahte)."""

import asyncio

import pytest
from textual.widgets import Button, DataTable, Input, Static, Switch, TabbedContent

from osint_tui import alan_ip, eposta, kullanici_adi as ka
from osint_tui.app import OsintTui

BOYUT = (140, 45)


@pytest.fixture(autouse=True)
def rapor_dizini(tmp_path, monkeypatch):
    monkeypatch.setenv("OSINT_TUI_RAPOR_DIZIN", str(tmp_path / "raporlar"))
    return tmp_path / "raporlar"


def _metin(app, kimlik: str) -> str:
    return str(app.query_one(kimlik, Static).render())


async def _bekle(app, pilot):
    await pilot.pause()
    await app.workers.wait_for_complete()
    await pilot.pause()


@pytest.fixture
def sahte_tarama(monkeypatch):
    async def sahte(kullanici, siteler, cb=None, **kw):
        sonuclar = [
            ka.Sonuc("GitHub", f"https://github.com/{kullanici}", ka.VAR),
            ka.Sonuc("Vimeo", f"https://vimeo.com/{kullanici}", ka.YOK),
            ka.Sonuc("Steam", f"https://steam/{kullanici}", ka.BELIRSIZ, "429"),
        ]
        for s in sonuclar:
            cb(s)
            await asyncio.sleep(0)
        return sonuclar

    monkeypatch.setattr(ka, "tara", sahte)


async def test_acilis_ve_sekmeler():
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.pause()
        sekmeler = app.query_one(TabbedContent)
        assert sekmeler.active == "sekme-kadi"
        await pilot.press("f2")
        assert sekmeler.active == "sekme-eposta"
        await pilot.press("f3")
        assert sekmeler.active == "sekme-alan"
        await pilot.press("f1")
        assert sekmeler.active == "sekme-kadi"
        assert "hazır" in _metin(app, "#kadi-durum")


async def test_kullanici_adi_akisi_ve_anahtar(sahte_tarama, rapor_dizini):
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        app.query_one("#kadi-giris", Input).value = "ali"
        await pilot.click("#kadi-tara")
        await _bekle(app, pilot)
        tablo = app.query_one("#kadi-tablo", DataTable)
        assert tablo.row_count == 1  # varsayılan: yalnız bulunanlar
        assert "1 hesap bulundu" in _metin(app, "#kadi-durum")
        app.query_one("#kadi-hepsi", Switch).value = True
        await pilot.pause()
        assert tablo.row_count == 3
        app.query_one("#kadi-hepsi", Switch).value = False
        await pilot.pause()
        assert tablo.row_count == 1
        # rapor
        await pilot.click("#kadi-rapor")
        await pilot.pause()
        dosyalar = list(rapor_dizini.glob("kullanici-adi-ali-*.md"))
        assert len(dosyalar) == 1
        assert "https://github.com/ali" in dosyalar[0].read_text(encoding="utf-8")


async def test_gecersiz_giris_cokmez(sahte_tarama):
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        for deger in ["", "a b/c"]:
            app.query_one("#kadi-giris", Input).value = deger
            await pilot.click("#kadi-tara")
            await pilot.pause()
            assert app.query_one("#kadi-durum").has_class("hata")
        app.query_one("#eposta-giris", Input).value = "bozuk"
        await pilot.press("f2")
        await pilot.click("#eposta-tara")
        await pilot.pause()
        assert "e-posta" in _metin(app, "#eposta-durum").lower()
        await pilot.press("f3")
        app.query_one("#alan-giris", Input).value = "http://"
        await pilot.click("#alan-tara")
        await pilot.pause()
        assert app.query_one("#alan-durum").has_class("hata")


async def test_tarama_hatasi_arayuzde_gosterilir(monkeypatch):
    async def patlayan(*a, **k):
        raise RuntimeError("deneme hatası")

    monkeypatch.setattr(ka, "tara", patlayan)
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        app.query_one("#kadi-giris", Input).value = "ali"
        await pilot.click("#kadi-tara")
        await _bekle(app, pilot)
        assert "deneme hatası" in _metin(app, "#kadi-durum")
        assert not app.query_one("#kadi-tara", Button).disabled  # yeniden denenebilir


async def test_rapor_taramadan_once_uyarir(rapor_dizini):
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert not rapor_dizini.exists() or not list(rapor_dizini.glob("*.md"))


async def test_eposta_akisi(monkeypatch, rapor_dizini):
    def sahte(adres, cb=None, **kw):
        sonuclar = [
            eposta.Sonuc("github", "github.com", eposta.VAR),
            eposta.Sonuc("ebay", "ebay.com", eposta.BELIRSIZ, "istek sınırı"),
            eposta.Sonuc("imgur", "imgur.com", eposta.YOK),
        ]
        for s in sonuclar:
            cb(s)
        return sonuclar

    monkeypatch.setattr(eposta, "tara", sahte)
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.press("f2")
        app.query_one("#eposta-giris", Input).value = "ali@ornek.com"
        await pilot.click("#eposta-tara")
        await _bekle(app, pilot)
        tablo = app.query_one("#eposta-tablo", DataTable)
        assert tablo.row_count == 1
        assert "haveibeenpwned" in str(app.query_one(".not", Static).render())
        app.query_one("#eposta-hepsi", Switch).value = True
        await pilot.pause()
        assert tablo.row_count == 3
        await pilot.click("#eposta-rapor")
        await pilot.pause()
        assert len(list(rapor_dizini.glob("eposta-ali@ornek.com-*.md"))) == 1


async def test_alan_adi_akisi(monkeypatch, rapor_dizini):
    monkeypatch.setattr(alan_ip, "whois_sorgula", lambda a: {"Kayıt kuruluşu": "Deneme AŞ"})
    monkeypatch.setattr(alan_ip, "dns_sorgula", lambda a: {"A": ["1.2.3.4"], "MX": [], "NS": [], "TXT": [], "AAAA": []})

    def crt_patlar(a):
        raise RuntimeError("crt.sh zaman aşımına uğradı")

    monkeypatch.setattr(alan_ip, "crtsh_sorgula", crt_patlar)
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.press("f3")
        app.query_one("#alan-giris", Input).value = "https://Ornek.com/x"
        await pilot.click("#alan-tara")
        await _bekle(app, pilot)
        assert "Deneme AŞ" in _metin(app, "#alan-whois")
        assert "1.2.3.4" in _metin(app, "#alan-dns")
        assert "zaman aşımı" in _metin(app, "#alan-alt")  # hata bölümde, uygulama ayakta
        assert app.query_one("#alan-ters").display is False
        await pilot.click("#alan-rapor")
        await pilot.pause()
        dosyalar = list(rapor_dizini.glob("alan-ip-ornek.com-*.md"))
        assert len(dosyalar) == 1
        md = dosyalar[0].read_text(encoding="utf-8")
        assert "Deneme AŞ" in md and "Hata: crt.sh" in md


async def test_ip_akisi(monkeypatch):
    monkeypatch.setattr(alan_ip, "ters_dns", lambda ip: ["one.one.one.one"])
    monkeypatch.setattr(alan_ip, "ip_konum", lambda ip: {"Ülke": "Avustralya"})
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.press("f3")
        app.query_one("#alan-giris", Input).value = "1.1.1.1"
        await pilot.click("#alan-tara")
        await _bekle(app, pilot)
        assert "one.one.one.one" in _metin(app, "#alan-ters")
        assert "Avustralya" in _metin(app, "#alan-konum")
        assert app.query_one("#alan-whois").display is False


async def test_yerlesim_giris_alani_genis():
    """Regresyon: giriş kutusu etiket yüzünden büzülmemeli."""
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.pause()
        assert app.query_one("#kadi-giris").region.width > 40
        assert app.query_one("#kadi-hepsi").region.x < BOYUT[0]


async def test_ekran_goruntusu(sahte_tarama):
    from pathlib import Path

    app = OsintTui()
    async with app.run_test(size=(120, 30)) as pilot:
        app.query_one("#kadi-giris", Input).value = "torvalds"
        await pilot.click("#kadi-tara")
        await _bekle(app, pilot)
        app.query_one("#kadi-hepsi", Switch).value = True
        await pilot.pause()
        hedef = Path(__file__).resolve().parent.parent / "docs"
        hedef.mkdir(exist_ok=True)
        app.save_screenshot("ekran.svg", path=str(hedef))
    assert (hedef / "ekran.svg").exists()


async def test_cikis_tuslari():
    app = OsintTui()
    async with app.run_test(size=BOYUT) as pilot:
        await pilot.press("escape")  # girişten çık
        await pilot.press("q")
        await pilot.pause()
        assert app._exit
    app2 = OsintTui()
    async with app2.run_test(size=BOYUT) as pilot:
        await pilot.press("q")  # girişteyken 'q' harf olarak yazılır, çıkmaz
        await pilot.pause()
        assert not app2._exit
        assert app2.query_one("#kadi-giris", Input).value == "q"
        await pilot.press("ctrl+q")
        await pilot.pause()
        assert app2._exit
