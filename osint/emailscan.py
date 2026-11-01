"""E-posta kaydı denetimi: `holehe` kütüphanesini programatik olarak sarar."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

EPOSTA_DESENI = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# Bu modüller "şifremi unuttum" akışını tetikler ve hedef adrese gerçek e-posta
# gönderebilir. Pasif denetim için varsayılan olarak ATLANIR (holehe -NP ile aynı).
SIFRE_SIFIRLAMA_MODULLERI = {"adobe", "mail_ru", "odnoklassniki", "samsung"}

VAR = "var"
YOK = "yok"
BELIRSIZ = "belirsiz"


@dataclass(frozen=True)
class Sonuc:
    servis: str
    alan_adi: str
    durum: str  # VAR | YOK | BELIRSIZ
    ek: str = ""


def eposta_gecerli_mi(eposta: str) -> bool:
    return bool(EPOSTA_DESENI.match(eposta))


def ham_sonucu_cevir(ham: dict) -> Sonuc:
    """holehe'nin sözlük çıktısını bizim Sonuc nesnemize çevirir.

    rateLimit=True ise (holehe, istek hatalarını da böyle işaretler) sonuç
    güvenilmezdir; bu yüzden "?" (belirsiz) sayılır.
    """
    ek_parcalar = []
    if ham.get("emailrecovery"):
        ek_parcalar.append(f"kurtarma e-postası: {ham['emailrecovery']}")
    if ham.get("phoneNumber"):
        ek_parcalar.append(f"telefon: {ham['phoneNumber']}")
    if ham.get("others"):
        ek_parcalar.append(str(ham["others"]))
    if ham.get("rateLimit"):
        durum = BELIRSIZ
        ek_parcalar.insert(0, "istek sınırı / yanıt alınamadı")
    elif ham.get("exists"):
        durum = VAR
    else:
        durum = YOK
    return Sonuc(
        servis=str(ham.get("name", "?")),
        alan_adi=str(ham.get("domain", "")),
        durum=durum,
        ek="; ".join(ek_parcalar),
    )


def modulleri_yukle(sifre_sifirlama_dahil: bool = False) -> list:
    """holehe modül fonksiyonlarını yükler (ağ erişimi yapmaz)."""
    from holehe import core  # geç içe aktarım: açılışı yavaşlatmasın

    modul_haritasi = core.import_submodules("holehe.modules")
    fonksiyonlar = core.get_functions(modul_haritasi)
    if not sifre_sifirlama_dahil:
        fonksiyonlar = [
            f for f in fonksiyonlar if f.__name__ not in SIFRE_SIFIRLAMA_MODULLERI
        ]
    return fonksiyonlar


def tara(
    eposta: str,
    sonuc_geldi: Callable[[Sonuc], None] | None = None,
    *,
    zaman_asimi: float = 12.0,
    es_zamanli: int = 20,
    moduller: list | None = None,
) -> list[Sonuc]:
    """E-postayı holehe modülleriyle denetler. EŞZAMANLI (bloklayan) çağrıdır;
    arayüzden thread worker içinde çağrılmalıdır (holehe trio kullanır)."""
    import httpx
    import trio

    moduller = moduller if moduller is not None else modulleri_yukle()
    sonuclar: list[Sonuc] = []

    async def modul_calistir(modul, client, sinir) -> None:
        async with sinir:
            cikti: list[dict] = []
            with trio.move_on_after(zaman_asimi) as kapsam:
                try:
                    await modul(eposta, client, cikti)
                except Exception:
                    # holehe kendi içinde yakalar; yine de sızan hata olursa "?" say.
                    cikti = [{"name": modul.__name__, "domain": "", "rateLimit": True}]
            if kapsam.cancelled_caught or not cikti:
                cikti = [{"name": modul.__name__, "domain": "", "rateLimit": True}]
        for ham in cikti:
            s = ham_sonucu_cevir(ham)
            sonuclar.append(s)
            if sonuc_geldi:
                sonuc_geldi(s)

    async def ana() -> None:
        sinir = trio.Semaphore(es_zamanli)
        async with httpx.AsyncClient(timeout=zaman_asimi) as client:
            async with trio.open_nursery() as nursery:
                for modul in moduller:
                    nursery.start_soon(modul_calistir, modul, client, sinir)

    trio.run(ana)
    return sonuclar
