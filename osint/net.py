"""Network layer: one place that builds every HTTP client and owns the proxy setting.

All ``httpx`` clients in the program come from :func:`async_client` and
:func:`sync_client`, so a proxy (or Tor) set once applies everywhere.
DNS lookups (dnspython) and the TLS certificate probe use raw sockets and
cannot go through an HTTP/SOCKS proxy; :func:`bypass_warning` tells the user.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import httpx

TOR_PROXY = "socks5h://127.0.0.1:9050"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")
ENV_VAR = "OSINT_PROXY"

_proxy: str | None = None


class ProxyError(ValueError):
    """The proxy URL is not usable."""


def validate_proxy(url: str) -> str:
    """Return the normalised proxy URL or raise :class:`ProxyError`."""
    url = (url or "").strip()
    parts = urlsplit(url)
    if parts.scheme.lower() not in PROXY_SCHEMES:
        raise ProxyError(f"unsupported proxy scheme in '{redact(url)}' (use one of: {', '.join(PROXY_SCHEMES)})")
    try:
        port = parts.port
    except ValueError:
        raise ProxyError("invalid proxy port")
    if not parts.hostname or port is None:
        raise ProxyError("proxy URL needs a host and a port, e.g. socks5h://127.0.0.1:9050")
    return url


def redact(url: str) -> str:
    """Hide the password of ``scheme://user:pass@host`` before printing."""
    parts = urlsplit(url)
    if parts.password:
        netloc = parts.netloc.replace(f":{parts.password}@", ":***@")
        return parts._replace(netloc=netloc).geturl()
    return url


def set_proxy(url: str | None) -> None:
    """Set (validated) or clear (``None``/empty) the global proxy."""
    global _proxy
    _proxy = validate_proxy(url) if url else None


def get_proxy() -> str | None:
    return _proxy


def load_env_proxy() -> None:
    """Apply ``OSINT_PROXY`` if no proxy is active yet. Raises :class:`ProxyError` if invalid."""
    value = os.environ.get(ENV_VAR, "").strip()
    if value and _proxy is None:
        set_proxy(value)


def describe() -> str:
    """Short text for the banner: the active proxy (password hidden) or ''."""
    if not _proxy:
        return ""
    return "tor" if _proxy == TOR_PROXY else redact(_proxy)


def bypass_warning(what: str = "DNS lookups and the TLS probe") -> str:
    """Warning for parts that cannot use the proxy; '' when no proxy is active."""
    if not _proxy:
        return ""
    return (f"{what} do not go through the proxy ({describe()}); "
            "they use direct connections and can reveal your IP address.")


def async_client(**kwargs) -> httpx.AsyncClient:
    if _proxy:
        kwargs.setdefault("proxy", _proxy)
    return httpx.AsyncClient(**kwargs)


def sync_client(**kwargs) -> httpx.Client:
    if _proxy:
        kwargs.setdefault("proxy", _proxy)
    return httpx.Client(**kwargs)


def check_tor(client: httpx.Client | None = None) -> tuple[bool, str]:
    """Ask check.torproject.org whether traffic leaves through Tor.

    Returns ``(is_tor, message)``. Network problems become ``(False, reason)``.
    """
    own = client is None
    client = client or sync_client(timeout=15.0)
    try:
        data = client.get(TOR_CHECK_URL).json()
    except httpx.HTTPError as e:
        return False, f"could not reach the Tor check service ({type(e).__name__}); is Tor running on 127.0.0.1:9050?"
    except ValueError:
        return False, "the Tor check service returned an invalid answer"
    finally:
        if own:
            client.close()
    if data.get("IsTor"):
        return True, f"traffic leaves through Tor (exit IP {data.get('IP', '?')})"
    return False, f"this connection is NOT using Tor (public IP {data.get('IP', '?')})"
