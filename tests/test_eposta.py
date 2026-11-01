"""E-posta modülü: holehe çıktısının çevrilmesi ve sahte modüllerle tarama."""

from osint_tui import eposta


def test_eposta_dogrulama():
    assert eposta.eposta_gecerli_mi("ad.soyad+etiket@ornek.com.tr")
    for kotu in ["", "ad@", "@ornek.com", "ad ornek@x.com", "ad@ornek"]:
        assert not eposta.eposta_gecerli_mi(kotu)


def test_ham_sonuc_cevirme():
    var = eposta.ham_sonucu_cevir({"name": "github", "domain": "github.com", "rateLimit": False,
                                   "exists": True, "emailrecovery": "a***@x.com", "phoneNumber": None, "others": None})
    assert var.durum == eposta.VAR and "a***@x.com" in var.ek
    yok = eposta.ham_sonucu_cevir({"name": "x", "domain": "x.com", "rateLimit": False, "exists": False})
    assert yok.durum == eposta.YOK
    # istek sınırı: exists=False olsa bile "?" olmalı
    sinir = eposta.ham_sonucu_cevir({"name": "y", "domain": "y.com", "rateLimit": True, "exists": False})
    assert sinir.durum == eposta.BELIRSIZ and "istek sınırı" in sinir.ek


def test_sifre_sifirlama_modulleri_atlanir():
    adlar = {f.__name__ for f in eposta.modulleri_yukle()}
    assert len(adlar) > 50
    assert not (adlar & eposta.SIFRE_SIFIRLAMA_MODULLERI)
    dahil = {f.__name__ for f in eposta.modulleri_yukle(sifre_sifirlama_dahil=True)}
    assert eposta.SIFRE_SIFIRLAMA_MODULLERI <= dahil


def test_tara_sahte_moduller():
    import trio

    async def bulundu(email, client, out):
        out.append({"name": "bulundu", "domain": "b.com", "rateLimit": False, "exists": True})

    async def yok(email, client, out):
        out.append({"name": "yok", "domain": "y.com", "rateLimit": False, "exists": False})

    async def patlar(email, client, out):
        raise RuntimeError("beklenmedik")

    async def asili(email, client, out):
        await trio.sleep(30)

    gelen = []
    sonuc = eposta.tara("a@b.co", gelen.append, zaman_asimi=0.3,
                        moduller=[bulundu, yok, patlar, asili])
    d = {s.servis: s.durum for s in sonuc}
    assert d["bulundu"] == eposta.VAR
    assert d["yok"] == eposta.YOK
    assert d["patlar"] == eposta.BELIRSIZ
    assert d["asili"] == eposta.BELIRSIZ
    assert len(gelen) == 4
