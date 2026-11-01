"""Banner rendering."""

from io import StringIO

from rich.console import Console

from osint import __version__, banner


def render(count=512) -> str:
    buf = StringIO()
    banner.print_banner(Console(file=buf, force_terminal=False, width=100), count)
    return buf.getvalue()


def test_logo_is_block_letters_without_clearing_screen():
    out = render()
    assert "██████╗" in out and "╚═╝" in out
    assert "\x1b[2J" not in out and "\x1b[H" not in out
    assert len(banner.LOGO) == 6


def test_subtitle_line():
    last = [l for l in render(512).splitlines() if l.strip()][-1]
    assert last.strip() == "v0.3 · 512 sites · type 'help'"
    assert __version__.startswith("0.3")


def test_gradient_goes_from_cyan_to_blue():
    colored = Console(file=StringIO(), force_terminal=True, color_system="truecolor", width=100)
    with colored.capture() as cap:
        colored.print(banner.logo_text())
    out = cap.get()
    assert "38;2;" in out  # truecolor escapes
    first = banner._lerp(banner.START, banner.END, 0.0)
    last = banner._lerp(banner.START, banner.END, 1.0)
    assert first == "#00e5ff" and last == "#2962ff"


def test_all_logo_lines_same_visual_width_after_padding():
    widths = {len(l) for l in banner.LOGO}
    assert len(widths) == 1
