"""
The chain ladder, actually painted.

A painted widget can only be trusted if something has made it paint. These
tests render the ladder off-screen for every sample in both themes and assert
that ink reached the pixmap — which catches the whole class of bug where a
paint path raises, divides by zero on a degenerate validity span, or quietly
draws nothing.

Qt is imported lazily and the application lives for the module, because a
second QApplication in one process is a crash rather than an error.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the ladder needs PyQt6 to paint")

from PyQt6.QtCore import QSize  # noqa: E402
from PyQt6.QtGui import QColor, QPixmap  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from attest.core.grade import analyze  # noqa: E402
from attest.ui import theme  # noqa: E402
from attest.ui.chain import ChainLadder  # noqa: E402


@pytest.fixture(scope="module")
def app():
    existing = QApplication.instance()
    yield existing or QApplication([])


def _render(bundle, mode: str, size: QSize = QSize(520, 900)) -> QPixmap:
    ladder = ChainLadder()
    ladder.set_data(bundle, mode)
    ladder.resize(size)
    pixmap = QPixmap(ladder.size())
    pixmap.fill(QColor(theme.color("canvas", mode)))
    ladder.render(pixmap)
    return pixmap


def _ink_fraction(pixmap: QPixmap, mode: str) -> float:
    """How much of the pixmap differs from the background."""
    image = pixmap.toImage()
    background = QColor(theme.color("canvas", mode)).rgb()
    total = 0
    different = 0
    for y in range(0, image.height(), 3):
        for x in range(0, image.width(), 3):
            total += 1
            if image.pixel(x, y) != background:
                different += 1
    return different / max(1, total)


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
def test_the_ladder_paints_something_for_every_sample(app, samples, now, mode):
    for name, text in samples.items():
        bundle = analyze(text, now=now)
        pixmap = _render(bundle, mode)
        assert not pixmap.isNull(), name
        assert _ink_fraction(pixmap, mode) > 0.05, f"{name} in {mode}"


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
def test_an_empty_bundle_paints_its_own_message(app, mode):
    bundle = analyze("nothing here at all")
    pixmap = _render(bundle, mode, QSize(420, 160))
    assert not pixmap.isNull()
    assert _ink_fraction(pixmap, mode) > 0.0


def test_the_ladder_grows_with_the_number_of_rungs(app, samples, now):
    one = ChainLadder()
    one.set_data(analyze(samples["no-san-leaf.pem"], now=now), theme.LIGHT)
    three = ChainLadder()
    three.set_data(analyze(samples["modern-chain.pem"], now=now), theme.LIGHT)
    assert three.sizeHint().height() > one.sizeHint().height() * 2


def test_a_single_rung_still_has_room_for_its_footnote(app, samples, now):
    ladder = ChainLadder()
    ladder.set_data(analyze(samples["expired-leaf.pem"], now=now), theme.LIGHT)
    assert ladder.sizeHint().height() >= 130


def test_a_zero_length_validity_span_does_not_divide_by_zero(app, gen, now):
    from datetime import datetime, timezone
    import base64

    moment = datetime(2026, 5, 1, tzinfo=timezone.utc)
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME, not_before=moment, not_after=moment,
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 1),
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=1)
    body = base64.b64encode(der).decode()
    text = ("-----BEGIN CERTIFICATE-----\n"
            + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
            + "\n-----END CERTIFICATE-----\n")
    pixmap = _render(analyze(text, now=now), theme.LIGHT, QSize(480, 200))
    assert not pixmap.isNull()


def test_a_certificate_with_unreadable_dates_paints_a_caption(app, gen, now):
    import base64
    from datetime import datetime, timezone

    tbs = gen.seq(
        gen.explicit(0, gen.integer(2)), gen.integer(1),
        gen.alg_rsa(gen.OID_SHA256_RSA), gen.ROOT_NAME,
        gen.seq(gen.tlv(0x17, b"not-a-time-Z"), gen.tlv(0x17, b"not-a-time-Z")),
        gen.LEAF_NAME, gen.rsa_spki(2048, 2))
    der = gen.seq(tbs, gen.alg_rsa(gen.OID_SHA256_RSA),
                  gen.bit_string(b"\x00" * 8))
    body = base64.b64encode(der).decode()
    text = ("-----BEGIN CERTIFICATE-----\n"
            + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
            + "\n-----END CERTIFICATE-----\n")
    bundle = analyze(text, now=now)
    assert bundle.certificates[0].not_before is None
    pixmap = _render(bundle, theme.DARK, QSize(480, 200))
    assert _ink_fraction(pixmap, theme.DARK) > 0.0


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
def test_the_whole_window_builds_and_renders(app, samples, mode):
    """The window itself, end to end, with a real report on screen."""
    from attest.ui.main_window import MainWindow

    window = MainWindow(mode=mode)
    window.resize(1180, 820)
    window.source.setPlainText(samples["modern-chain.pem"])
    window._on_read()
    app.processEvents()
    assert window._bundle is not None
    assert window._bundle.grade.letter == "A+"
    pixmap = window.grab()
    assert not pixmap.isNull()
    assert _ink_fraction(pixmap, mode) > 0.2
    window.close()


def test_clearing_the_window_returns_it_to_the_placeholder(app, samples):
    from attest.ui.main_window import MainWindow

    window = MainWindow(mode=theme.LIGHT)
    window.source.setPlainText(samples["self-signed-sha1.pem"])
    window._on_read()
    assert window._bundle is not None
    window._on_clear()
    assert window._bundle is None
    assert not window.source.toPlainText()
    window.close()


def test_switching_theme_re_renders_the_report(app, samples):
    from attest.ui.main_window import MainWindow

    window = MainWindow(mode=theme.LIGHT)
    window.source.setPlainText(samples["broken-chain.pem"])
    window._on_read()
    window._on_theme_changed("Dark")
    assert window._mode == theme.DARK
    assert window._bundle is not None
    assert not window.grab().isNull()
    window.close()
