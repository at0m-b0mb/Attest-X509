#!/usr/bin/env python3
"""
Render the window off-screen and save PNGs — proof the interface works, and the
source of the README's contact sheet.

Runs headless (``QT_QPA_PLATFORM=offscreen``), so it needs no display. It grabs
each sample in both themes, writing ``images/shot-<sample>-<mode>.png``.
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
SHOTS = [
    ("modern-chain.pem", theme.LIGHT),
    ("modern-chain.pem", theme.DARK),
    ("broken-chain.pem", theme.LIGHT),
    ("broken-chain.pem", theme.DARK),
    ("self-signed-sha1.pem", theme.LIGHT),
    ("self-signed-sha1.pem", theme.DARK),
    ("expired-leaf.pem", theme.LIGHT),
]


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out_dir = os.path.join(ROOT, "images")
    os.makedirs(out_dir, exist_ok=True)
    samples = os.path.join(ROOT, "samples")

    for name, mode in SHOTS:
        window = MainWindow(mode=mode)
        window.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as handle:
            window.source.setPlainText(handle.read())
        window._on_read()
        window.show()
        app.processEvents()
        app.processEvents()
        base = os.path.splitext(name)[0]
        path = os.path.join(out_dir, f"shot-{base}-{mode}.png")
        window.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}  ({mode})")
        window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
