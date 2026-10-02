"""
Getting from what was pasted to the bytes underneath.

A certificate on screen is almost always PEM: a base64 payload fenced between
``-----BEGIN CERTIFICATE-----`` and its matching END line, often several in a
row for a whole chain, and often surrounded by whatever else was in the file —
a text description from ``openssl x509 -text``, a private key, a mail client's
quoted indentation.

This module pulls the certificate blocks out of all that and decodes each to
DER. It reports what it found and what it could not use rather than failing the
whole paste on one bad block, and it recognises raw DER (and a chain of DER
values back to back) so a ``.crt`` or ``.cer`` opened as bytes works too.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

_BEGIN = re.compile(
    r"-{2,}BEGIN\s+(?:TRUSTED\s+|X509\s+)?CERTIFICATE-{2,}", re.IGNORECASE)
_END = re.compile(
    r"-{2,}END\s+(?:TRUSTED\s+|X509\s+)?CERTIFICATE-{2,}", re.IGNORECASE)

# Any other PEM label, so a paste that is only a private key can be told apart
# from a paste that is only noise.
_OTHER_PEM = re.compile(r"-{2,}BEGIN\s+([A-Z0-9 ]+?)-{2,}", re.IGNORECASE)

_B64 = re.compile(r"^[A-Za-z0-9+/=\s]*$")


@dataclass
class Block:
    """One PEM block, decoded or not."""

    index: int
    der: bytes = b""
    error: str = ""
    source: str = "pem"      # "pem" or "der"

    @property
    def ok(self) -> bool:
        return bool(self.der) and not self.error


@dataclass
class Extraction:
    """The result of reading a paste: the blocks, and what went wrong."""

    blocks: list[Block] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def good(self) -> list[Block]:
        return [b for b in self.blocks if b.ok]

    @property
    def bad(self) -> list[Block]:
        return [b for b in self.blocks if not b.ok]


def _decode_body(body: str) -> tuple[bytes, str]:
    """Base64-decode a PEM body, tolerating stray indentation and wrapping."""
    stripped = "".join(body.split())
    if not stripped:
        return b"", "the block between BEGIN and END is empty"
    if not _B64.match(body):
        # Keep going — the characters that do not belong are dropped below —
        # but say so, because it usually means the paste lost a line.
        stripped = re.sub(r"[^A-Za-z0-9+/=]", "", stripped)
    # A body whose length is not a multiple of four lost characters somewhere;
    # pad it so the rest decodes and let the DER walker complain if it is short.
    pad = (-len(stripped)) % 4
    try:
        der = base64.b64decode(stripped + "=" * pad, validate=False)
    except (ValueError, Exception) as exc:  # noqa: BLE001 - binascii.Error
        return b"", f"the base64 body did not decode ({exc})"
    if not der:
        return b"", "the base64 body decoded to nothing"
    return der, ""


def extract_pem(text: str) -> Extraction:
    """Find every CERTIFICATE block in *text* and decode it."""
    result = Extraction()
    pos = 0
    index = 0
    while True:
        begin = _BEGIN.search(text, pos)
        if not begin:
            break
        end = _END.search(text, begin.end())
        if not end:
            result.blocks.append(Block(
                index=index,
                error="a BEGIN CERTIFICATE line has no matching END line"))
            break
        der, err = _decode_body(text[begin.end():end.start()])
        result.blocks.append(Block(index=index, der=der, error=err))
        index += 1
        pos = end.end()

    if not result.blocks:
        others = {m.group(1).strip().upper() for m in _OTHER_PEM.finditer(text)}
        others = {o for o in others if "CERTIFICATE" not in o}
        if others:
            result.notes.append(
                "This paste holds " + ", ".join(sorted(others))
                + " but no CERTIFICATE block. Attest reads certificates only, "
                  "and never wants a private key.")
    return result


def looks_like_der(data: bytes) -> bool:
    """A DER certificate is a constructed SEQUENCE in long-form length."""
    return len(data) > 4 and data[0] == 0x30 and data[1] in (0x81, 0x82, 0x83)


def extract_der(data: bytes) -> Extraction:
    """Split a raw DER buffer into the certificates sitting in it."""
    from .asn1 import Asn1Error, parse_one

    result = Extraction()
    pos = 0
    index = 0
    while pos < len(data):
        try:
            node = parse_one(data, pos)
        except Asn1Error as exc:
            result.blocks.append(Block(
                index=index, source="der",
                error=f"the DER after byte {pos} did not parse ({exc})"))
            break
        result.blocks.append(
            Block(index=index, der=data[pos:pos + node.total_len], source="der"))
        pos += node.total_len
        index += 1
    return result


def extract(source: str | bytes) -> Extraction:
    """Read either a text paste or a raw file, whichever was handed over."""
    if isinstance(source, bytes):
        if looks_like_der(source):
            out = extract_der(source)
            out.notes.append(
                "Read as raw DER — no PEM armour was present.")
            return out
        source = source.decode("utf-8", errors="replace")
    return extract_pem(source)
