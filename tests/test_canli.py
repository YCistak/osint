"""Gerçek ağ erişimli duman testleri. Çalıştırmak için: python -m pytest -m canli"""

import pytest

from osint_tui import alan_ip, kullanici_adi as ka

pytestmark = pytest.mark.canli


async def _tara(kullanici):
    siteler = [s for s in ka.siteleri_yukle() if s.ad in ("GitHub", "GitLab", "Docker Hub", "Lichess")]
    return {s.site: s for s in await ka.tara(kullanici, siteler)}


async def test_github_torvalds_var():
    d = await _tara("torvalds")
    assert d["GitHub"].durum == ka.VAR, d["GitHub"]


async def test_sacma_ad_hicbir_yerde_yok():
    d = await _tara("zq8xkv3pp91wwq7")
    assert d["GitHub"].durum == ka.YOK
    assert not [s for s in d.values() if s.durum == ka.VAR]


async def test_tum_liste_sacma_adda_yanlis_pozitif_vermez():
    sonuc = await ka.tara("zq8xkv3pp91wwq7", ka.siteleri_yukle())
    assert [s.site for s in sonuc if s.durum == ka.VAR] == []


def test_example_com_dns():
    s = alan_ip.dns_sorgula("example.com")
    assert s["A"], s
    assert any("v=spf1" in t for t in s["TXT"]) or s["NS"]
