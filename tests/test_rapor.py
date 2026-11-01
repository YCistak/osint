"""Rapor yazma ve Markdown üretimi."""

from datetime import datetime

from osint_tui import eposta, kullanici_adi as ka, rapor

ZAMAN = datetime(2026, 11, 1, 14, 30, 5)


def test_dosya_adi_temizleme():
    assert rapor.dosya_adi_icin_temizle("ad@ornek.com") == "ad@ornek.com"
    assert "/" not in rapor.dosya_adi_icin_temizle("../../etc/passwd")
    assert rapor.dosya_adi_icin_temizle("   ") == "hedef"
    assert len(rapor.dosya_adi_icin_temizle("a" * 500)) <= 80


def test_rapor_kaydi_ve_cakisma(tmp_path):
    y1 = rapor.raporu_kaydet("kullanici-adi", "ali", "bir", tmp_path, ZAMAN)
    assert y1.name == "kullanici-adi-ali-2026-11-01.md"
    assert y1.read_text(encoding="utf-8") == "bir"
    y2 = rapor.raporu_kaydet("kullanici-adi", "ali", "iki", tmp_path, ZAMAN)
    assert y2 != y1 and y1.read_text(encoding="utf-8") == "bir"  # üzerine yazmadı
    y3 = rapor.raporu_kaydet("kullanici-adi", "ali", "uc", tmp_path, ZAMAN)
    assert len({y1, y2, y3}) == 3


def test_rapor_dizin_olusturur(tmp_path):
    hedef = tmp_path / "ic" / "raporlar"
    yol = rapor.raporu_kaydet("eposta", "a@b.co", "x", hedef, ZAMAN)
    assert yol.parent == hedef and yol.exists()


def test_kullanici_adi_raporu():
    sonuclar = [
        ka.Sonuc("GitHub", "https://github.com/ali", ka.VAR),
        ka.Sonuc("Vimeo", "https://vimeo.com/ali", ka.YOK),
        ka.Sonuc("Steam", "https://steam/ali", ka.BELIRSIZ, "istek sınırı (429)"),
    ]
    md = rapor.kullanici_adi_raporu("ali", sonuclar, ZAMAN)
    assert "# Kullanıcı adı raporu: ali" in md
    assert "| GitHub | https://github.com/ali |" in md
    assert "Vimeo" not in md  # bulunamayanlar listelenmez
    assert "istek sınırı (429)" in md
    assert "KVKK" in md


def test_eposta_raporu():
    sonuclar = [
        eposta.Sonuc("github", "github.com", eposta.VAR, "telefon: 5**"),
        eposta.Sonuc("ebay", "ebay.com", eposta.BELIRSIZ),
        eposta.Sonuc("imgur", "imgur.com", eposta.YOK),
    ]
    md = rapor.eposta_raporu("a@b.co", sonuclar, ZAMAN)
    assert "| github | github.com | telefon: 5** |" in md
    assert "ebay" in md and "imgur" not in md
    assert "haveibeenpwned.com" in md


def test_alan_ip_raporu():
    md = rapor.alan_ip_raporu("example.com", "alan", {
        "Whois": rapor.sozluk_md({"Kayıt kuruluşu": "X"}),
        "DNS kayıtları": rapor.dns_md({"A": ["1.2.3.4"], "MX": []}),
        "Alt alan adları (crt.sh)": rapor.liste_md(["www.example.com"]),
    }, ZAMAN)
    assert "## Whois" in md and "**Kayıt kuruluşu:** X" in md
    assert "| A | 1.2.3.4 |" in md and "| MX | — |" in md
    assert "- `www.example.com`" in md


def test_tablo_hucresinde_boru_kacisi():
    md = rapor.kullanici_adi_raporu("x", [ka.Sonuc("A|B", "https://a/x", ka.VAR)], ZAMAN)
    assert "A\\|B" in md
