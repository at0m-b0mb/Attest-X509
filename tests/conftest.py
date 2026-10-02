"""
Shared fixtures.

The interesting choice here is that the certificate tests build their DER with
``tools/gen_samples.py`` — the same hand-rolled encoder that writes the files in
``samples/``. That keeps the test fixtures honest: every certificate a test
asserts about is a real X.509 structure that the parser walks exactly as it
would walk one off a live server, not a mock standing in for one.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "tools")):
    if path not in sys.path:
        sys.path.insert(0, path)

# The clock every sample grade is measured against, so the assertions below do
# not drift with the calendar.
REFERENCE_NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

SAMPLES_DIR = os.path.join(ROOT, "samples")


@pytest.fixture(scope="session")
def now() -> datetime:
    return REFERENCE_NOW


@pytest.fixture(scope="session")
def gen():
    """The hand-written DER encoder from ``tools/gen_samples.py``."""
    import gen_samples

    return gen_samples


@pytest.fixture(scope="session")
def samples() -> dict[str, str]:
    """Every file in ``samples/``, read once."""
    out: dict[str, str] = {}
    for name in sorted(os.listdir(SAMPLES_DIR)):
        if name.endswith(".pem"):
            with open(os.path.join(SAMPLES_DIR, name), encoding="utf-8") as fh:
                out[name] = fh.read()
    return out
