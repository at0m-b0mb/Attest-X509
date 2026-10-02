#!/usr/bin/env python3
"""
Render the window off-screen and save PNGs — proof the interface works, and the
source of the README's contact sheet.

Runs headless (``QT_QPA_PLATFORM=offscreen``), so it needs no display. It grabs
each sample in both themes, writing ``images/shot-<sample>-<mode>.png``.

The list of shots is *derived* from ``samples/`` rather than written out, so a
sample cannot be added — or a theme quietly dropped — and leave a gap in the
art. A test asserts the same thing from the other side.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from attest.ui import theme  # noqa: E402
from attest.ui.main_window import MainWindow  # noqa: E402

SIZE = (1180, 860)
SAMPLES = os.path.join(ROOT, "samples")
MODES = (theme.LIGHT, theme.DARK)


def sample_names() -> list[str]:
    return sorted(f for f in os.listdir(SAMPLES) if f.endswith(".pem"))


def shots() -> list[tuple[str, str]]:
    """Every sample, in every theme. Nothing hand-listed, nothing missed."""
    return [(name, mode) for name in sample_names() for mode in MODES]


def shot_filename(name: str, mode: str) -> str:
    return f"shot-{os.path.splitext(name)[0]}-{mode}.png"


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out_dir = os.path.join(ROOT, "images")
    os.makedirs(out_dir, exist_ok=True)
    samples = SAMPLES

    for name, mode in shots():
        window = MainWindow(mode=mode)
        window.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as handle:
            window.source.setPlainText(handle.read())
        window._on_read()
        window.show()
        app.processEvents()
        app.processEvents()
        path = os.path.join(out_dir, shot_filename(name, mode))
        window.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}  ({mode})")
        window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
