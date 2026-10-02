"""
A small DER reader.

X.509 is ASN.1 all the way down, so before Attest can say anything about a
certificate it has to be able to walk one. This module is that walker: it turns
a buffer of DER into a tree of :class:`Node` objects — tag, length, value, and
whatever children a constructed value contains — and offers the handful of
decoders a certificate actually needs (integers, object identifiers, the six
string types that turn up in a distinguished name, bit strings, booleans, and
the two time formats).

It is deliberately strict in the places where leniency would be a lie. DER
forbids the indefinite-length form, so a buffer that uses it is reported rather
than guessed at; a length that runs past the end of the buffer is an error, not
a truncation; and trailing bytes after a complete value are surfaced instead of
being silently dropped. Nothing here knows what a certificate *is* — that is
:mod:`attest.core.certificate`'s job. This file only knows how DER is shaped.

Pure standard library, and it never leaves the buffer it was handed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --- tag classes ------------------------------------------------------------
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

# --- universal tag numbers Attest cares about -------------------------------
BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
OBJECT_DESCRIPTOR = 7
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
NUMERIC_STRING = 18
PRINTABLE_STRING = 19
T61_STRING = 20
IA5_STRING = 22
UTC_TIME = 23
GENERALIZED_TIME = 24
GRAPHIC_STRING = 25
VISIBLE_STRING = 26
GENERAL_STRING = 27
UNIVERSAL_STRING = 28
BMP_STRING = 30

TAG_NAMES = {
    BOOLEAN: "BOOLEAN",
    INTEGER: "INTEGER",
    BIT_STRING: "BIT STRING",
    OCTET_STRING: "OCTET STRING",
    NULL: "NULL",
    OID: "OBJECT IDENTIFIER",
    UTF8_STRING: "UTF8String",
    SEQUENCE: "SEQUENCE",
    SET: "SET",
    NUMERIC_STRING: "NumericString",
    PRINTABLE_STRING: "PrintableString",
    T61_STRING: "T61String",
    IA5_STRING: "IA5String",
    UTC_TIME: "UTCTime",
    GENERALIZED_TIME: "GeneralizedTime",
    VISIBLE_STRING: "VisibleString",
    GENERAL_STRING: "GeneralString",
    UNIVERSAL_STRING: "UniversalString",
    BMP_STRING: "BMPString",
}

# The string types a Name, a SAN or a policy qualifier can legally use.
STRING_TAGS = frozenset({
    UTF8_STRING, NUMERIC_STRING, PRINTABLE_STRING, T61_STRING, IA5_STRING,
    GRAPHIC_STRING, VISIBLE_STRING, GENERAL_STRING, UNIVERSAL_STRING,
    BMP_STRING,
})


class Asn1Error(ValueError):
    """The buffer is not well-formed DER, or not the shape that was asked for."""


@dataclass
class Node:
    """One tag/length/value triple, with its children already walked."""

    tag_class: int
    constructed: bool
    number: int
    offset: int                 # where the identifier octet sits in the buffer
    header_len: int             # identifier + length octets
    length: int                 # length of the content octets
    value: bytes                # the content octets themselves
    children: list["Node"] = field(default_factory=list)

    # --- identity ----------------------------------------------------------
    @property
    def total_len(self) -> int:
        return self.header_len + self.length

    @property
    def is_universal(self) -> bool:
        return self.tag_class == UNIVERSAL

    @property
    def is_context(self) -> bool:
        return self.tag_class == CONTEXT

    def is_tag(self, number: int) -> bool:
        """True for a universal tag of this number, whatever its form."""
        return self.is_universal and self.number == number

    def is_ctx(self, number: int) -> bool:
        """True for a context-specific tag ``[number]``."""
        return self.is_context and self.number == number

    @property
    def tag_name(self) -> str:
        if self.is_universal:
            return TAG_NAMES.get(self.number, f"[UNIVERSAL {self.number}]")
        prefix = {APPLICATION: "APPLICATION", CONTEXT: "", PRIVATE: "PRIVATE"}[
            self.tag_class]
        inner = f"{prefix} {self.number}".strip()
        return f"[{inner}]"

    # --- navigation --------------------------------------------------------
    def child(self, index: int) -> "Node":
        try:
            return self.children[index]
        except IndexError as exc:  # pragma: no cover - guarded by callers
            raise Asn1Error(
                f"{self.tag_name} has {len(self.children)} children; "
                f"child {index} was asked for") from exc

    def find_ctx(self, number: int) -> "Node | None":
        for kid in self.children:
            if kid.is_ctx(number):
                return kid
        return None

    def expect(self, number: int) -> "Node":
        if not self.is_tag(number):
            raise Asn1Error(
                f"expected {TAG_NAMES.get(number, number)}, "
                f"found {self.tag_name}")
        return self


# --- parsing ----------------------------------------------------------------

def _read_identifier(data: bytes, pos: int) -> tuple[int, bool, int, int]:
    """Return (tag_class, constructed, number, bytes_consumed)."""
    if pos >= len(data):
        raise Asn1Error("buffer ended where a tag was expected")
    first = data[pos]
    tag_class = (first & 0xC0) >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1F
    used = 1
    if number == 0x1F:  # high-tag-number form: base-128, 7 bits per octet
        number = 0
        while True:
            if pos + used >= len(data):
                raise Asn1Error("buffer ended inside a multi-byte tag")
            byte = data[pos + used]
            used += 1
            number = (number << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
            if used > 6:
                raise Asn1Error("tag number is implausibly long")
    return tag_class, constructed, number, used


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    """Return (length, bytes_consumed)."""
    if pos >= len(data):
        raise Asn1Error("buffer ended where a length was expected")
    first = data[pos]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if count == 0:
        raise Asn1Error(
            "indefinite-length encoding found; that is BER, and DER — which is "
            "what a certificate must use — forbids it")
    if count == 0x7F:
        raise Asn1Error("reserved length form (0xFF) found")
    if pos + 1 + count > len(data):
        raise Asn1Error("buffer ended inside a long-form length")
    length = int.from_bytes(data[pos + 1:pos + 1 + count], "big")
    return length, 1 + count


def parse_one(data: bytes, pos: int = 0, depth: int = 0) -> Node:
    """Parse the single value that starts at *pos*, children and all."""
    if depth > 40:
        raise Asn1Error("nesting is deeper than any certificate needs")
    tag_class, constructed, number, id_len = _read_identifier(data, pos)
    length, len_len = _read_length(data, pos + id_len)
    header = id_len + len_len
    start = pos + header
    end = start + length
    if end > len(data):
        raise Asn1Error(
            f"a {length}-byte value at offset {pos} runs {end - len(data)} "
            f"bytes past the end of the buffer")
    node = Node(
        tag_class=tag_class, constructed=constructed, number=number,
        offset=pos, header_len=header, length=length, value=data[start:end])
    if constructed:
        inner = start
        while inner < end:
            kid = parse_one(data, inner, depth + 1)
            node.children.append(kid)
            inner += kid.total_len
        if inner != end:  # a child overran its parent's declared length
            raise Asn1Error(
                f"the children of {node.tag_name} at offset {pos} do not fill "
                f"its declared length exactly")
    return node


def parse(data: bytes) -> Node:
    """Parse exactly one top-level value and insist nothing follows it."""
    if not data:
        raise Asn1Error("there are no bytes to read")
    node = parse_one(data, 0)
    if node.total_len != len(data):
        raise Asn1Error(
            f"{len(data) - node.total_len} trailing byte(s) follow the "
            f"top-level {node.tag_name}")
    return node


def parse_all(data: bytes) -> list[Node]:
    """Parse a buffer that holds a run of values back to back."""
    out: list[Node] = []
    pos = 0
    while pos < len(data):
        node = parse_one(data, pos)
        out.append(node)
        pos += node.total_len
    return out


# --- decoders ---------------------------------------------------------------

def decode_integer(node: Node) -> int:
    """A DER INTEGER, read as the signed value it is defined to be."""
    node.expect(INTEGER)
    if not node.value:
        raise Asn1Error("an INTEGER must carry at least one content octet")
    return int.from_bytes(node.value, "big", signed=True)


def decode_boolean(node: Node) -> bool:
    node.expect(BOOLEAN)
    if len(node.value) != 1:
        raise Asn1Error("a BOOLEAN must be exactly one content octet")
    return node.value[0] != 0


def decode_oid(node: Node) -> str:
    """An OBJECT IDENTIFIER, rendered in dotted-decimal form."""
    node.expect(OID)
    data = node.value
    if not data:
        raise Asn1Error("an OBJECT IDENTIFIER cannot be empty")
    first = data[0]
    # The first two arcs share one octet: 40*arc1 + arc2, arc1 capped at 2.
    if first < 80:
        arcs = [first // 40, first % 40]
    else:
        arcs = [2, first - 80]
    acc = 0
    started = False
    for byte in data[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            arcs.append(acc)
            acc = 0
            started = False
    if started:
        raise Asn1Error("an OBJECT IDENTIFIER ended mid-arc")
    return ".".join(str(a) for a in arcs)


def decode_bit_string(node: Node) -> tuple[int, bytes]:
    """Return (unused trailing bits, the bytes themselves)."""
    node.expect(BIT_STRING)
    if not node.value:
        raise Asn1Error("a BIT STRING must carry its unused-bit count")
    unused = node.value[0]
    if unused > 7:
        raise Asn1Error(f"a BIT STRING cannot have {unused} unused bits")
    if unused and len(node.value) == 1:
        raise Asn1Error("a BIT STRING with no bytes cannot have unused bits")
    return unused, node.value[1:]


def bit_string_flags(node: Node, names: list[str]) -> list[str]:
    """Read a named-bit BIT STRING (KeyUsage) into the names that are set."""
    unused, data = decode_bit_string(node)
    total = len(data) * 8 - unused
    out: list[str] = []
    for index, name in enumerate(names):
        if index >= total:
            break
        byte = data[index // 8]
        if byte & (0x80 >> (index % 8)):
            out.append(name)
    return out


def decode_string(node: Node) -> str:
    """Any of the string types a distinguished name may use."""
    if node.number not in STRING_TAGS or not node.is_universal:
        raise Asn1Error(f"{node.tag_name} is not a character string")
    raw = node.value
    if node.number == BMP_STRING:
        return raw.decode("utf-16-be", errors="replace")
    if node.number == UNIVERSAL_STRING:
        return raw.decode("utf-32-be", errors="replace")
    if node.number == UTF8_STRING:
        return raw.decode("utf-8", errors="replace")
    # PrintableString, IA5String and friends are ASCII by definition; T61String
    # is not, but latin-1 is the reading every implementation settled on.
    return raw.decode("latin-1", errors="replace")


def _two(text: str, where: str) -> int:
    if len(text) != 2 or not text.isdigit():
        raise Asn1Error(f"{where} is not two digits in a certificate time")
    return int(text)


def decode_time(node: Node) -> datetime:
    """A UTCTime or GeneralizedTime, as a timezone-aware UTC datetime."""
    if node.is_tag(UTC_TIME):
        return _decode_utc_time(node.value.decode("ascii", errors="replace"))
    if node.is_tag(GENERALIZED_TIME):
        return _decode_generalized_time(
            node.value.decode("ascii", errors="replace"))
    raise Asn1Error(f"{node.tag_name} is not a time")


def _offset_of(text: str) -> tuple[str, timedelta]:
    """Split a trailing Z / +hhmm / -hhmm from a time string."""
    if text.endswith("Z"):
        return text[:-1], timedelta(0)
    if len(text) >= 5 and text[-5] in "+-":
        sign = -1 if text[-5] == "-" else 1
        hours = _two(text[-4:-2], "a zone hour")
        minutes = _two(text[-2:], "a zone minute")
        return text[:-5], sign * timedelta(hours=hours, minutes=minutes)
    # No zone at all. X.509 requires Z, so this is worth reporting upward, but
    # the only honest reading of the digits is UTC.
    return text, timedelta(0)


def _decode_utc_time(text: str) -> datetime:
    body, offset = _offset_of(text.strip())
    if len(body) not in (10, 12):
        raise Asn1Error(f"UTCTime {text!r} is not YYMMDDHHMM[SS]Z")
    yy = _two(body[0:2], "the year")
    # RFC 5280: 00-49 means 2000-2049, 50-99 means 1950-1999.
    year = 2000 + yy if yy < 50 else 1900 + yy
    second = _two(body[10:12], "the second") if len(body) == 12 else 0
    stamp = datetime(
        year, _two(body[2:4], "the month"), _two(body[4:6], "the day"),
        _two(body[6:8], "the hour"), _two(body[8:10], "the minute"), second,
        tzinfo=timezone.utc)
    return stamp - offset


def _decode_generalized_time(text: str) -> datetime:
    body, offset = _offset_of(text.strip())
    fraction = 0.0
    for sep in (".", ","):
        if sep in body:
            body, frac = body.split(sep, 1)
            frac = "".join(ch for ch in frac if ch.isdigit())
            fraction = float(f"0.{frac}") if frac else 0.0
            break
    if len(body) not in (10, 12, 14):
        raise Asn1Error(f"GeneralizedTime {text!r} is not YYYYMMDDHHMM[SS]")
    year = int(body[0:4])
    if not body[0:4].isdigit():
        raise Asn1Error(f"GeneralizedTime {text!r} has a non-numeric year")
    second = _two(body[12:14], "the second") if len(body) == 14 else 0
    minute = _two(body[10:12], "the minute") if len(body) >= 12 else 0
    stamp = datetime(
        year, _two(body[4:6], "the month"), _two(body[6:8], "the day"),
        _two(body[8:10], "the hour"), minute, second, tzinfo=timezone.utc)
    if fraction:
        stamp += timedelta(seconds=fraction)
    return stamp - offset


def hex_bytes(data: bytes, separator: str = ":") -> str:
    """Render bytes the way every certificate viewer does: ``ab:cd:ef``."""
    return separator.join(f"{b:02X}" for b in data)
