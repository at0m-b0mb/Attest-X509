"""Attest — read the certificate.

An offline X.509 reader: it walks the DER by hand, names every field in plain
words, draws a pasted chain as a ladder so you can see whether it actually
joins, and grades what it finds — without ever verifying a signature, checking
revocation, consulting a trust store, or calling anything safe.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
