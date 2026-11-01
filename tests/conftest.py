"""Keep every test away from the user's real history, proxy and token settings."""

import pytest

from osint import history, net


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(history, "enabled", True)
    net.set_proxy(None)
    yield
    net.set_proxy(None)
