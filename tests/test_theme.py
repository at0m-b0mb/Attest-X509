"""
Contrast.

Not ceremony — reading these by eye passes pairings that fail WCAG. Every text
colour must clear AA on every ground it can land on, and every severity badge
must clear AA on its own wash.
"""

import pytest

from attest.ui import theme

TEXT_TOKENS = ["ink", "ink_muted", "ink_faint", "brass",
               "sev_good", "sev_info", "sev_notice", "sev_warning", "sev_alert",
               "hop_external", "hop_internal"]
GROUNDS = ["canvas", "surface", "surface_alt", "sunken", "rail"]
WASHES = {
    "brass": "brass_wash",
    "sev_good": "sev_good_wash",
    "sev_notice": "sev_notice_wash",
    "sev_warning": "sev_warning_wash",
    "sev_alert": "sev_alert_wash",
}


def _required(token: str) -> float:
    # ink_faint is only used large or decoratively -> large-text threshold.
    return 3.0 if token == "ink_faint" else 4.5


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("token", TEXT_TOKENS)
@pytest.mark.parametrize("ground", GROUNDS)
def test_text_is_legible_on_every_ground(mode, token, ground):
    ratio = theme.contrast(theme.color(token, mode), theme.color(ground, mode))
    assert ratio >= _required(token), f"{token} on {ground} in {mode}: {ratio:.2f}:1"


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
@pytest.mark.parametrize("token,wash", sorted(WASHES.items()))
def test_badge_text_is_legible_on_its_own_wash(mode, token, wash):
    ratio = theme.contrast(theme.color(token, mode), theme.color(wash, mode))
    assert ratio >= 4.5, f"{token} on {wash} in {mode}: {ratio:.2f}:1"


def test_dark_mode_is_true_black_and_never_blue():
    assert theme.color("canvas", theme.DARK) == "#000000"
    for name, pair in theme.PALETTE.items():
        h = pair.dark.lstrip("#")
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        assert b <= max(r, g) + 12, f"{name} reads as blue in the dark theme"


def test_every_colour_declares_both_themes():
    for name, pair in theme.PALETTE.items():
        assert pair.light.startswith("#") and len(pair.light) == 7, name
        assert pair.dark.startswith("#") and len(pair.dark) == 7, name


def test_there_are_two_golds_and_they_differ():
    for mode in (theme.LIGHT, theme.DARK):
        assert theme.color("brass", mode) != theme.color("shine", mode)


def test_stylesheet_builds_for_both_modes():
    for mode in (theme.LIGHT, theme.DARK):
        sheet = theme.stylesheet(mode)
        assert "QPushButton" in sheet
        assert "{{" not in sheet, "an unescaped brace leaked into the QSS"


def test_grade_tokens_cover_every_letter():
    for letter in ["A+", "A", "A-", "B+", "B", "C", "C-", "D", "F"]:
        assert theme.grade_token(letter) in theme.PALETTE


# --- marks: the colours the ladder paints with -------------------------------
# A mark carries no words, so these are the only vocabulary a painted rung has
# for "how bad is this". If two severities collapse onto the same colour, the
# widget cannot tell the reader them apart however carefully it is drawn.

def test_the_mark_map_covers_every_severity_the_model_can_report():
    from attest.core.model import Severity

    for severity in Severity:
        assert severity.value in theme.MARK_TOKEN, severity


def test_a_mark_stays_gold_until_something_is_actually_wrong():
    assert theme.mark_token("good") == theme.MARK_SOUND
    assert theme.mark_token("info") == theme.MARK_SOUND
    assert theme.mark_token(None) == theme.MARK_SOUND
    assert theme.mark_token("warning") == "sev_warning"
    assert theme.mark_token("alert") == "sev_alert"


def test_a_real_weakness_is_a_different_colour_from_sound():
    for severity in ("warning", "alert"):
        for mode in (theme.LIGHT, theme.DARK):
            weak = theme.color(theme.mark_token(severity), mode)
            sound = theme.color(theme.MARK_SOUND, mode)
            assert weak != sound, f"{severity} is indistinguishable in {mode}"


def test_every_mark_token_resolves_to_a_real_wash_and_edge():
    for severity in theme.MARK_TOKEN:
        token = theme.mark_token(severity)
        assert token in theme.PALETTE, severity
        assert theme.wash_token(token) in theme.PALETTE, severity
        assert theme.edge_token(token) in theme.PALETTE, severity


@pytest.mark.parametrize("mode", [theme.LIGHT, theme.DARK])
def test_mark_ink_is_legible_on_the_wash_it_chooses(mode):
    for severity in theme.MARK_TOKEN:
        token = theme.mark_token(severity)
        ratio = theme.contrast(theme.color(token, mode),
                               theme.color(theme.wash_token(token), mode))
        assert ratio >= 4.5, f"{token} on its wash in {mode}: {ratio:.2f}:1"


def test_an_unknown_token_still_gets_a_usable_wash_and_edge():
    assert theme.wash_token("ink") == "surface_alt"
    assert theme.edge_token("ink") == "ink"
