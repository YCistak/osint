"""osint-tui ana uygulaması (Textual)."""

from __future__ import annotations

from datetime import datetime

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

from . import __version__, alan_ip, eposta, kullanici_adi, rapor

DURUM_HUCRE = {
    "var": ("✔", "bold green"),
    "yok": ("✘", "red"),
    "belirsiz": ("?", "bold yellow"),
}

SEKMELER = {"kadi": "sekme-kadi", "eposta": "sekme-eposta", "alan": "sekme-alan"}

ALAN_BOLUMLERI = {
    "whois": "Whois",
    "dns": "DNS kayıtları",
    "alt": "Alt alan adları (crt.sh)",
    "ters": "Ters DNS",
    "konum": "Coğrafi konum (ip-api.com)",
}


def _durum_hucresi(durum: str) -> Text:
    simge, stil = DURUM_HUCRE.get(durum, ("?", "yellow"))
    return Text(simge, style=stil)


class OsintTui(App):
    """Kullanıcı adı, e-posta ve alan adı/IP sekmeleri olan OSINT arayüzü."""

    TITLE = "OSINT-TUI · Dijital İz Denetimi"
    SUB_TITLE = f"v{__version__} · yalnızca kendi izin / CTF için"

    CSS = """
    .satir { height: 3; padding: 0 1; }
    .satir Input { width: 1fr; }
    .satir Button { margin-left: 1; }
    .satir Switch { margin-left: 2; }
    .satir .etiket { margin-left: 1; padding-top: 1; }
    .durum { height: auto; min-height: 1; padding: 0 2; color: $text-muted; }
    .durum.hata { color: $error; text-style: bold; }
    .durum.tamam { color: $success; }
    .not { height: auto; padding: 0 2; color: $text-muted; }
    DataTable { height: 1fr; margin: 0 1; }
    .bolum { border: round $primary; margin: 0 1 1 1; padding: 0 1; height: auto; }
    #alan-sonuc { height: 1fr; }
    """

    BINDINGS = [
        Binding("q", "quit", "Çıkış"),
        Binding("ctrl+q", "quit", "Çıkış", show=False, priority=True),
        Binding("f1", "sekme('kadi')", "Kullanıcı adı"),
        Binding("f2", "sekme('eposta')", "E-posta"),
        Binding("f3", "sekme('alan')", "Alan adı/IP"),
        Binding("ctrl+s", "raporu_kaydet", "Raporu kaydet", priority=True),
        Binding("ctrl+t", "hepsini_goster", "Tümünü göster/gizle", priority=True),
        Binding("escape", "girisi_birak", "Girişten çık"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._siteler: list[kullanici_adi.Site] = []
        self._kadi_no = 0
        self._kadi_sonuclar: list[kullanici_adi.Sonuc] = []
        self._kadi_hedef = ""
        self._kadi_calisiyor = False
        self._eposta_no = 0
        self._eposta_sonuclar: list[eposta.Sonuc] = []
        self._eposta_hedef = ""
        self._eposta_calisiyor = False
        self._alan_no = 0
        self._alan_hedef = ""
        self._alan_tur = ""
        self._alan_bolumler: dict[str, str] = {}
        self._alan_bekleyen = 0

    # ------------------------------------------------------------ arayüz
    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial=SEKMELER["kadi"]):
            with TabPane("Kullanıcı adı", id=SEKMELER["kadi"]):
                with Horizontal(classes="satir"):
                    yield Input(placeholder="Kullanıcı adı (ör. torvalds)", id="kadi-giris")
                    yield Button("Tara", id="kadi-tara", variant="primary")
                    yield Button("Raporu kaydet", id="kadi-rapor")
                    yield Static("Tümünü göster", classes="etiket")
                    yield Switch(value=False, id="kadi-hepsi")
                yield Static("Bir kullanıcı adı girip Enter'a basın.", id="kadi-durum", classes="durum")
                yield DataTable(id="kadi-tablo", cursor_type="row", zebra_stripes=True)
            with TabPane("E-posta", id=SEKMELER["eposta"]):
                with Horizontal(classes="satir"):
                    yield Input(placeholder="E-posta adresi (ör. ad@ornek.com)", id="eposta-giris")
                    yield Button("Tara", id="eposta-tara", variant="primary")
                    yield Button("Raporu kaydet", id="eposta-rapor")
                    yield Static("Tümünü göster", classes="etiket")
                    yield Switch(value=False, id="eposta-hepsi")
                yield Static(
                    "Servislerde kayıt kontrolü holehe ile yapılır. Veri sızıntısı için "
                    "haveibeenpwned.com adresini elle kontrol edin. Şifre sıfırlama "
                    "tetikleyen 4 servis (Adobe, Mail.ru, OK.ru, Samsung) atlanır.",
                    classes="not",
                )
                yield Static("Bir e-posta adresi girip Enter'a basın.", id="eposta-durum", classes="durum")
                yield DataTable(id="eposta-tablo", cursor_type="row", zebra_stripes=True)
            with TabPane("Alan adı / IP", id=SEKMELER["alan"]):
                with Horizontal(classes="satir"):
                    yield Input(placeholder="Alan adı veya IP (ör. example.com / 1.1.1.1)", id="alan-giris")
                    yield Button("Sorgula", id="alan-tara", variant="primary")
                    yield Button("Raporu kaydet", id="alan-rapor")
                yield Static("Bir alan adı ya da IP adresi girip Enter'a basın.", id="alan-durum", classes="durum")
                with VerticalScroll(id="alan-sonuc"):
                    for anahtar, baslik in ALAN_BOLUMLERI.items():
                        bolum = Static("", id=f"alan-{anahtar}", classes="bolum")
                        bolum.border_title = baslik
                        bolum.display = False
                        yield bolum
        yield Footer()

    def on_mount(self) -> None:
        kadi = self.query_one("#kadi-tablo", DataTable)
        kadi.add_columns("Site", "Adres", "Durum")
        ep = self.query_one("#eposta-tablo", DataTable)
        ep.add_columns("Servis", "Alan adı", "Durum", "Ek bilgi")
        try:
            self._siteler = kullanici_adi.siteleri_yukle()
        except kullanici_adi.SiteListesiHatasi as e:
            self._durum("kadi", f"Site listesi yüklenemedi: {e}", "hata")
            self.query_one("#kadi-tara", Button).disabled = True
        else:
            self._durum("kadi", f"{len(self._siteler)} site hazır. Kullanıcı adını girip Enter'a basın.")
        self.query_one("#kadi-giris", Input).focus()

    # ------------------------------------------------------------ yardımcılar
    def _durum(self, on_ek: str, mesaj: str, sinif: str = "") -> None:
        w = self.query_one(f"#{on_ek}-durum", Static)
        w.remove_class("hata", "tamam")
        if sinif:
            w.add_class(sinif)
        w.update(Text(mesaj))

    def _aktif_sekme(self) -> str:
        aktif = self.query_one(TabbedContent).active
        for k, v in SEKMELER.items():
            if v == aktif:
                return k
        return "kadi"

    # ------------------------------------------------------------ eylemler
    def action_sekme(self, hangisi: str) -> None:
        self.query_one(TabbedContent).active = SEKMELER[hangisi]

    @on(TabbedContent.TabActivated)
    def _sekme_degisti(self, olay: TabbedContent.TabActivated) -> None:
        for k, v in SEKMELER.items():
            if v == olay.pane.id:
                try:
                    self.query_one(f"#{k}-giris", Input).focus()
                except Exception:
                    pass

    def action_girisi_birak(self) -> None:
        self.set_focus(None)

    def action_raporu_kaydet(self) -> None:
        {"kadi": self._kadi_rapor, "eposta": self._eposta_rapor, "alan": self._alan_rapor}[
            self._aktif_sekme()
        ]()

    def action_hepsini_goster(self) -> None:
        k = self._aktif_sekme()
        if k in ("kadi", "eposta"):
            sw = self.query_one(f"#{k}-hepsi", Switch)
            sw.value = not sw.value

    @on(Button.Pressed)
    def _dugme(self, olay: Button.Pressed) -> None:
        islem = {
            "kadi-tara": self._kadi_basla,
            "kadi-rapor": self._kadi_rapor,
            "eposta-tara": self._eposta_basla,
            "eposta-rapor": self._eposta_rapor,
            "alan-tara": self._alan_basla,
            "alan-rapor": self._alan_rapor,
        }.get(olay.button.id or "")
        if islem:
            islem()

    @on(Input.Submitted)
    def _giris_enter(self, olay: Input.Submitted) -> None:
        {"kadi-giris": self._kadi_basla, "eposta-giris": self._eposta_basla, "alan-giris": self._alan_basla}.get(
            olay.input.id or "", lambda: None
        )()

    @on(Switch.Changed)
    def _anahtar(self, olay: Switch.Changed) -> None:
        if olay.switch.id == "kadi-hepsi":
            self._kadi_tabloyu_yenile()
        elif olay.switch.id == "eposta-hepsi":
            self._eposta_tabloyu_yenile()

    def _rapor_yaz(self, tur: str, hedef: str, icerik: str, on_ek: str) -> None:
        try:
            yol = rapor.raporu_kaydet(tur, hedef, icerik)
        except OSError as e:
            self._durum(on_ek, f"Rapor kaydedilemedi: {e}", "hata")
            self.notify(f"Rapor kaydedilemedi: {e}", severity="error")
            return
        self._durum(on_ek, f"Rapor kaydedildi: {yol}", "tamam")
        self.notify(f"Rapor kaydedildi:\n{yol}", title="Tamam")

    # ============================================================ KULLANICI ADI
    def _kadi_basla(self) -> None:
        if self._kadi_calisiyor:
            self.notify("Tarama zaten sürüyor, bitmesini bekleyin.", severity="warning")
            return
        kullanici = self.query_one("#kadi-giris", Input).value.strip().lstrip("@")
        if not kullanici:
            self._durum("kadi", "Lütfen bir kullanıcı adı girin.", "hata")
            return
        if not kullanici_adi.kullanici_adi_gecerli_mi(kullanici):
            self._durum(
                "kadi",
                "Geçersiz kullanıcı adı: yalnızca harf, rakam, nokta, tire ve alt çizgi (en çok 40 karakter).",
                "hata",
            )
            return
        if not self._siteler:
            self._durum("kadi", "Site listesi yüklü değil.", "hata")
            return
        self._kadi_no += 1
        self._kadi_sonuclar = []
        self._kadi_hedef = kullanici
        self._kadi_calisiyor = True
        self.query_one("#kadi-tablo", DataTable).clear()
        self.query_one("#kadi-tara", Button).disabled = True
        self._durum("kadi", f"'{kullanici}' {len(self._siteler)} sitede aranıyor…")
        self.run_worker(
            self._kadi_calistir(self._kadi_no, kullanici),
            group="kadi",
            exclusive=True,
            exit_on_error=False,
        )

    async def _kadi_calistir(self, no: int, kullanici: str) -> None:
        def geldi(s: kullanici_adi.Sonuc) -> None:
            if no != self._kadi_no:
                return
            self._kadi_sonuclar.append(s)
            if s.durum == "var" or self.query_one("#kadi-hepsi", Switch).value:
                self._kadi_satir_ekle(s)
            bul = sum(1 for x in self._kadi_sonuclar if x.durum == "var")
            self._durum(
                "kadi",
                f"Taranan: {len(self._kadi_sonuclar)}/{len(self._siteler)} · Bulunan: {bul}",
            )

        hata = None
        try:
            await kullanici_adi.tara(kullanici, self._siteler, geldi)
        except Exception as e:  # hiçbir hata uygulamayı çökertmesin
            hata = e
        finally:
            if no == self._kadi_no:
                self._kadi_calisiyor = False
                self.query_one("#kadi-tara", Button).disabled = False
        if no != self._kadi_no:
            return
        if hata:
            self._durum("kadi", f"Tarama sırasında hata: {type(hata).__name__}: {hata}", "hata")
            return
        bul = sum(1 for x in self._kadi_sonuclar if x.durum == "var")
        bel = sum(1 for x in self._kadi_sonuclar if x.durum == "belirsiz")
        mesaj = f"Bitti: {len(self._kadi_sonuclar)} site tarandı · {bul} hesap bulundu · {bel} belirsiz."
        if bul == 0:
            mesaj += " Hiç hesap bulunamadı; 'Tümünü göster' ile tüm sonuçlara bakabilirsiniz."
        self._durum("kadi", mesaj, "tamam")

    def _kadi_satir_ekle(self, s: kullanici_adi.Sonuc) -> None:
        self.query_one("#kadi-tablo", DataTable).add_row(s.site, s.url, _durum_hucresi(s.durum))

    def _kadi_tabloyu_yenile(self) -> None:
        tablo = self.query_one("#kadi-tablo", DataTable)
        tablo.clear()
        hepsi = self.query_one("#kadi-hepsi", Switch).value
        sira = {"var": 0, "belirsiz": 1, "yok": 2}
        for s in sorted(self._kadi_sonuclar, key=lambda x: (sira[x.durum], x.site)):
            if hepsi or s.durum == "var":
                self._kadi_satir_ekle(s)

    def _kadi_rapor(self) -> None:
        if not self._kadi_sonuclar or self._kadi_calisiyor:
            self.notify("Önce bir tarama yapın ve bitmesini bekleyin.", severity="warning")
            return
        icerik = rapor.kullanici_adi_raporu(self._kadi_hedef, self._kadi_sonuclar)
        self._rapor_yaz("kullanici-adi", self._kadi_hedef, icerik, "kadi")

    # ============================================================ E-POSTA
    def _eposta_basla(self) -> None:
        if self._eposta_calisiyor:
            self.notify("Tarama zaten sürüyor, bitmesini bekleyin.", severity="warning")
            return
        adres = self.query_one("#eposta-giris", Input).value.strip()
        if not eposta.eposta_gecerli_mi(adres):
            self._durum("eposta", "Geçerli bir e-posta adresi girin (ör. ad@ornek.com).", "hata")
            return
        self._eposta_no += 1
        self._eposta_sonuclar = []
        self._eposta_hedef = adres
        self._eposta_calisiyor = True
        self.query_one("#eposta-tablo", DataTable).clear()
        self.query_one("#eposta-tara", Button).disabled = True
        self._durum("eposta", f"'{adres}' servislerde aranıyor… (yarım dakika sürebilir)")
        no = self._eposta_no
        self.run_worker(
            lambda: self._eposta_calistir(no, adres),
            thread=True,
            group="eposta",
            exclusive=True,
            exit_on_error=False,
        )

    def _eposta_calistir(self, no: int, adres: str) -> None:
        """Thread worker: holehe (trio) burada bloklayarak çalışır."""

        def geldi(s: eposta.Sonuc) -> None:
            self.call_from_thread(self._eposta_sonuc_geldi, no, s)

        hata = None
        try:
            eposta.tara(adres, geldi)
        except Exception as e:
            hata = e
        self.call_from_thread(self._eposta_bitti, no, hata)

    def _eposta_sonuc_geldi(self, no: int, s: eposta.Sonuc) -> None:
        if no != self._eposta_no:
            return
        self._eposta_sonuclar.append(s)
        if s.durum == "var" or self.query_one("#eposta-hepsi", Switch).value:
            self._eposta_satir_ekle(s)
        var = sum(1 for x in self._eposta_sonuclar if x.durum == "var")
        self._durum("eposta", f"Denetlenen: {len(self._eposta_sonuclar)} servis · Kayıtlı: {var}")

    def _eposta_bitti(self, no: int, hata: Exception | None) -> None:
        if no != self._eposta_no:
            return
        self._eposta_calisiyor = False
        self.query_one("#eposta-tara", Button).disabled = False
        if hata:
            self._durum("eposta", f"Tarama sırasında hata: {type(hata).__name__}: {hata}", "hata")
            return
        var = sum(1 for x in self._eposta_sonuclar if x.durum == "var")
        bel = sum(1 for x in self._eposta_sonuclar if x.durum == "belirsiz")
        mesaj = f"Bitti: {len(self._eposta_sonuclar)} servis · {var} kayıt bulundu · {bel} belirsiz (?)."
        if var == 0:
            mesaj += " Kayıt bulunamadı; 'Tümünü göster' ile belirsizleri görebilirsiniz."
        self._durum("eposta", mesaj, "tamam")

    def _eposta_satir_ekle(self, s: eposta.Sonuc) -> None:
        self.query_one("#eposta-tablo", DataTable).add_row(
            s.servis, s.alan_adi, _durum_hucresi(s.durum), s.ek
        )

    def _eposta_tabloyu_yenile(self) -> None:
        tablo = self.query_one("#eposta-tablo", DataTable)
        tablo.clear()
        hepsi = self.query_one("#eposta-hepsi", Switch).value
        sira = {"var": 0, "belirsiz": 1, "yok": 2}
        for s in sorted(self._eposta_sonuclar, key=lambda x: (sira[x.durum], x.servis)):
            if hepsi or s.durum == "var":
                self._eposta_satir_ekle(s)

    def _eposta_rapor(self) -> None:
        if not self._eposta_sonuclar or self._eposta_calisiyor:
            self.notify("Önce bir tarama yapın ve bitmesini bekleyin.", severity="warning")
            return
        icerik = rapor.eposta_raporu(self._eposta_hedef, self._eposta_sonuclar)
        self._rapor_yaz("eposta", self._eposta_hedef, icerik, "eposta")

    # ============================================================ ALAN ADI / IP
    def _alan_basla(self) -> None:
        if self._alan_bekleyen > 0:
            self.notify("Sorgu zaten sürüyor, bitmesini bekleyin.", severity="warning")
            return
        ham = self.query_one("#alan-giris", Input).value
        hedef = alan_ip.hedefi_temizle(ham)
        tur = alan_ip.hedef_turu(hedef) if hedef else "gecersiz"
        if tur == "gecersiz":
            self._durum("alan", "Geçerli bir alan adı (ör. example.com) ya da IP adresi girin.", "hata")
            return
        self._alan_no += 1
        no = self._alan_no
        self._alan_hedef, self._alan_tur = hedef, tur
        self._alan_bolumler = {}
        gorunen = ["whois", "dns", "alt"] if tur == "alan" else ["ters", "konum"]
        for anahtar in ALAN_BOLUMLERI:
            w = self.query_one(f"#alan-{anahtar}", Static)
            w.display = anahtar in gorunen
            if anahtar in gorunen:
                w.update(Text("Yükleniyor…", style="italic"))
        self._alan_bekleyen = len(gorunen)
        self.query_one("#alan-tara", Button).disabled = True
        self._durum("alan", f"'{hedef}' sorgulanıyor…")
        gorevler = {
            "whois": lambda: alan_ip.whois_sorgula(hedef),
            "dns": lambda: alan_ip.dns_sorgula(hedef),
            "alt": lambda: alan_ip.crtsh_sorgula(hedef),
            "ters": lambda: alan_ip.ters_dns(hedef),
            "konum": lambda: alan_ip.ip_konum(hedef),
        }
        for anahtar in gorunen:
            self.run_worker(
                lambda a=anahtar: self._alan_bolum_calistir(no, a, gorevler[a]),
                thread=True,
                group=f"alan-{anahtar}",
                exit_on_error=False,
            )

    def _alan_bolum_calistir(self, no: int, anahtar: str, gorev) -> None:
        sonuc, hata = None, None
        try:
            sonuc = gorev()
        except Exception as e:
            hata = str(e) or type(e).__name__
        self.call_from_thread(self._alan_bolum_bitti, no, anahtar, sonuc, hata)

    def _alan_bolum_bitti(self, no: int, anahtar: str, sonuc, hata: str | None) -> None:
        if no != self._alan_no:
            return
        w = self.query_one(f"#alan-{anahtar}", Static)
        baslik = ALAN_BOLUMLERI[anahtar]
        if hata:
            w.update(Text(f"Hata: {hata}", style="red"))
            self._alan_bolumler[baslik] = f"Hata: {hata}"
        else:
            metin, md = self._bolum_bicimle(anahtar, sonuc)
            w.update(metin)
            self._alan_bolumler[baslik] = md
        self._alan_bekleyen -= 1
        if self._alan_bekleyen == 0:
            self.query_one("#alan-tara", Button).disabled = False
            self._durum("alan", f"'{self._alan_hedef}' için sorgu tamamlandı.", "tamam")

    @staticmethod
    def _bolum_bicimle(anahtar: str, sonuc) -> tuple[Text, str]:
        """Bölüm sonucunu (ekran metni, Markdown) çiftine çevirir."""
        if anahtar in ("whois", "konum"):
            t = Text()
            for k, v in sonuc.items():
                t.append(f"{k}: ", style="bold")
                t.append(f"{v}\n")
            return t, rapor.sozluk_md(sonuc)
        if anahtar == "dns":
            t = Text()
            for tur in alan_ip.DNS_TURLERI:
                degerler = sonuc.get(tur, [])
                t.append(f"{tur:<5}", style="bold cyan")
                t.append(("\n     ".join(degerler) if degerler else "—") + "\n")
            return t, rapor.dns_md(sonuc)
        # alt alan adları, ters DNS: düz liste
        if not sonuc:
            bos = "Kayıt bulunamadı."
            return Text(bos, style="italic"), bos
        baslik = f"{len(sonuc)} kayıt\n" if anahtar == "alt" else ""
        return Text(baslik + "\n".join(sonuc)), (f"{len(sonuc)} kayıt\n\n" if anahtar == "alt" else "") + rapor.liste_md(sonuc)

    def _alan_rapor(self) -> None:
        if not self._alan_bolumler or self._alan_bekleyen > 0:
            self.notify("Önce bir sorgu yapın ve bitmesini bekleyin.", severity="warning")
            return
        sirali = {b: self._alan_bolumler[b] for b in ALAN_BOLUMLERI.values() if b in self._alan_bolumler}
        icerik = rapor.alan_ip_raporu(self._alan_hedef, self._alan_tur, sirali)
        self._rapor_yaz("alan-ip", self._alan_hedef, icerik, "alan")


def main() -> None:
    OsintTui().run()


if __name__ == "__main__":
    main()
