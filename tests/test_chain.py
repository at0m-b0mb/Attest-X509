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


def _ladder(bundle, mode: str = theme.LIGHT) -> ChainLadder:
    ladder = ChainLadder()
    ladder.set_data(bundle, mode)
    return ladder


def _colours(pixmap: QPixmap, box: tuple[int, int, int, int]) -> set[int]:
    """Every distinct pixel value inside *box* — (x0, y0, x1, y1)."""
    image = pixmap.toImage()
    x0, y0, x1, y1 = box
    return {image.pixel(x, y)
            for y in range(y0, y1) for x in range(x0, x1)}


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


# --- the rung has to show the grade -----------------------------------------
# The ladder is the element the whole tool is built around, so the thing most
# worth protecting is that it cannot draw a failing certificate as a sound one.
# These tests check the painter's choice of token *and* the pixels that choice
# produces, because a correct decision that never reaches the canvas is still
# an F certificate that looks healthy.

def test_a_weak_certificate_and_a_sound_one_choose_different_accents(
        app, samples, now):
    weak = _ladder(analyze(samples["self-signed-sha1.pem"], now=now))
    sound = _ladder(analyze(samples["modern-chain.pem"], now=now))

    weak_token = weak.accent_token(weak._bundle.certificates[0], now)
    assert weak_token == "sev_alert"
    for cert in sound._bundle.certificates:
        assert sound.accent_token(cert, now) == theme.MARK_SOUND
        assert sound.accent_token(cert, now) != weak_token


def test_each_badge_answers_to_the_findings_about_its_own_subject(
        app, samples, now):
    weak = _ladder(analyze(samples["self-signed-sha1.pem"], now=now))
    cert = weak._bundle.certificates[0]
    assert weak.badge_token(cert, "key") == "sev_alert"        # RSA-1024
    assert weak.badge_token(cert, "algorithm") == "sev_alert"  # SHA-1

    sound = _ladder(analyze(samples["modern-chain.pem"], now=now))
    for other in sound._bundle.certificates:
        assert sound.badge_token(other, "key") == theme.MARK_SOUND
        assert sound.badge_token(other, "algorithm") == theme.MARK_SOUND


def test_every_badge_has_a_finding_to_take_its_colour_from(app, samples, now):
    """A badge falls back to gold when the grader said nothing about it.

    That fallback is the same shape as the bug this tinting fixes, so the
    guard is on the other side: the grader must never be silent about a key
    or a signature algorithm.
    """
    for name, text in samples.items():
        bundle = analyze(text, now=now)
        for cert in bundle.certificates:
            categories = {f.category for f in bundle.findings_for(cert.index)}
            assert "key" in categories, f"{name}, certificate {cert.index + 1}"
            assert "algorithm" in categories, f"{name}, certificate {cert.index + 1}"


def test_a_weak_key_leaves_a_sound_signature_badge_alone(app, gen, now):
    """Per-badge, not per-certificate: one bad parameter, one red badge."""
    from datetime import datetime, timezone

    der = gen.certificate(
        serial=7, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 6, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 5, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(1024, 4),
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=4)
    bundle = analyze(gen.pem(der), now=now)
    cert = bundle.certificates[0]
    ladder = _ladder(bundle)

    assert cert.public_key.badge == "RSA-1024"
    assert ladder.badge_token(cert, "key") == "sev_alert"
    assert ladder.badge_token(cert, "algorithm") == theme.MARK_SOUND
    assert ladder.accent_token(cert, now) == "sev_alert"


def test_a_warning_and_an_alert_are_not_the_same_accent(app, gen, now):
    """A 2048-bit key on a 10-year leaf is a warning, not an alert."""
    from datetime import datetime, timezone

    der = gen.certificate(
        serial=8, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 6, 1, tzinfo=timezone.utc),
        not_after=datetime(2036, 6, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 5),
        extensions=[gen.ext_san(dns=["shop.northwind.example"]),
                    gen.ext_key_usage("digitalSignature"),
                    gen.ext_ext_key_usage(gen.OID_SERVER_AUTH),
                    gen.ext_basic_constraints(False)],
        signature_seed=5)
    bundle = analyze(gen.pem(der), now=now)
    cert = bundle.certificates[0]
    ladder = _ladder(bundle)

    assert ladder.worst_severity(cert) == "warning"
    assert ladder.accent_token(cert, now) == "sev_warning"
    for mode in (theme.LIGHT, theme.DARK):
        assert (theme.color("sev_warning", mode)
                != theme.color("sev_alert", mode))


def test_an_ungraded_bundle_still_judges_the_rung_by_its_dates(app, samples, now):
    """``read`` without ``grade_bundle`` leaves no findings to colour by."""
    from attest.core.grade import read

    expired = read(samples["expired-leaf.pem"])
    assert not expired.findings
    assert _ladder(expired).accent_token(expired.certificates[0], now) \
        == "sev_alert"

    current = read(samples["modern-chain.pem"])
    ladder = _ladder(current)
    for cert in current.certificates:
        assert ladder.accent_token(cert, now) == theme.MARK_SOUND
    assert not _render(current, theme.LIGHT).isNull()


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
def test_the_severity_colour_reaches_the_painted_pixels(app, samples, now, mode):
    """Tokens are a decision; this is the canvas the reader actually sees."""
    alert = QColor(theme.color("sev_alert", mode)).rgb()
    gold = QColor(theme.color(theme.MARK_SOUND, mode)).rgb()
    # The top rung's spine and its two badges, which is where the verdict is.
    box = (0, 10, 320, 102)

    weak = _colours(_render(analyze(samples["self-signed-sha1.pem"], now=now),
                            mode), box)
    sound = _colours(_render(analyze(samples["modern-chain.pem"], now=now),
                             mode), box)

    assert alert in weak, f"the F rung carries no alert colour in {mode}"
    assert gold not in weak, f"the F rung is still painted gold in {mode}"
    assert gold in sound, f"the A+ rung lost its gold in {mode}"
    assert alert not in sound, f"the A+ rung gained an alert colour in {mode}"


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


def test_the_capture_tool_covers_every_sample_in_both_themes(app, samples):
    """The art is a claim about the whole sample set, so it has to be one."""
    import capture_screenshots

    planned = capture_screenshots.shots()
    assert sorted(capture_screenshots.sample_names()) == sorted(samples)
    for name in samples:
        for mode in (theme.LIGHT, theme.DARK):
            assert (name, mode) in planned, f"{name} is missing in {mode}"
    assert len(planned) == len(samples) * 2

    images = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "images")
    for name, mode in planned:
        shot = os.path.join(images,
                            capture_screenshots.shot_filename(name, mode))
        assert os.path.exists(shot), f"{os.path.basename(shot)} was never captured"


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
