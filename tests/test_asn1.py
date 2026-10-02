"""
The DER walker.

These tests hold the parser to the two halves of its job: read correct DER
exactly, and *refuse* malformed DER loudly rather than inventing a reading for
it. The hand-written byte strings here are the point — every one is a shape a
real certificate can contain, or a shape a corrupt one does.
"""

import pytest

from attest.core import asn1
from attest.core.asn1 import Asn1Error


# --- lengths ----------------------------------------------------------------

def test_short_form_length():
    node = asn1.parse(b"\x02\x01\x07")
    assert node.length == 1
    assert node.header_len == 2
    assert asn1.decode_integer(node) == 7


def test_long_form_length_one_octet():
    body = b"A" * 200
    node = asn1.parse(b"\x04\x81\xC8" + body)
    assert node.length == 200
    assert node.header_len == 3
    assert node.value == body


def test_long_form_length_two_octets():
    body = b"B" * 300
    node = asn1.parse(b"\x04\x82\x01\x2C" + body)
    assert node.length == 300
    assert node.value == body


def test_indefinite_length_is_refused_by_name():
    with pytest.raises(Asn1Error, match="indefinite"):
        asn1.parse(b"\x30\x80\x02\x01\x01\x00\x00")


def test_reserved_length_form_is_refused():
    with pytest.raises(Asn1Error, match="reserved"):
        asn1.parse(b"\x04\xFF\x01")


def test_length_past_end_of_buffer_is_refused():
    with pytest.raises(Asn1Error, match="past the end"):
        asn1.parse(b"\x04\x10\x01\x02")


def test_trailing_bytes_are_reported_not_ignored():
    with pytest.raises(Asn1Error, match="trailing"):
        asn1.parse(b"\x02\x01\x01\xAA")


def test_empty_buffer_is_refused():
    with pytest.raises(Asn1Error):
        asn1.parse(b"")


def test_children_must_fill_their_parent_exactly():
    # a SEQUENCE claiming 3 bytes whose single child is 3 bytes long but
    # starts one byte in -> the child overruns
    with pytest.raises(Asn1Error):
        asn1.parse(b"\x30\x02\x02\x02\x01\x01")


# --- tags -------------------------------------------------------------------

def test_high_tag_number_form():
    node = asn1.parse(b"\x1F\x81\x00\x00")
    assert node.number == 128
    assert node.is_universal


def test_context_tags_are_recognised():
    node = asn1.parse(b"\xA3\x03\x02\x01\x05")
    assert node.is_context
    assert node.is_ctx(3)
    assert not node.is_ctx(0)
    assert node.constructed
    assert node.tag_name == "[3]"


def test_find_ctx_locates_an_optional_field():
    node = asn1.parse(b"\x30\x06\x80\x01\x01\x82\x01\x02")
    assert node.find_ctx(2).value == b"\x02"
    assert node.find_ctx(5) is None


def test_expect_names_what_it_wanted():
    node = asn1.parse(b"\x02\x01\x01")
    with pytest.raises(Asn1Error, match="SEQUENCE"):
        node.expect(asn1.SEQUENCE)


def test_tag_names_cover_the_universal_set():
    for number, name in asn1.TAG_NAMES.items():
        assert name and isinstance(name, str), number


def test_nesting_depth_is_bounded():
    deep = b"\x02\x01\x01"
    for _ in range(60):
        deep = b"\x30" + bytes([len(deep)]) + deep
    with pytest.raises(Asn1Error, match="deeper"):
        asn1.parse(deep)


def test_parse_all_reads_values_back_to_back():
    nodes = asn1.parse_all(b"\x02\x01\x01\x02\x01\x02\x02\x01\x03")
    assert [asn1.decode_integer(n) for n in nodes] == [1, 2, 3]


# --- integers ---------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (b"\x02\x01\x00", 0),
    (b"\x02\x01\x7F", 127),
    (b"\x02\x02\x00\x80", 128),
    (b"\x02\x01\xFF", -1),
    (b"\x02\x01\x80", -128),
    (b"\x02\x03\x01\x00\x01", 65537),
])
def test_integers_are_signed_as_der_defines(raw, expected):
    assert asn1.decode_integer(asn1.parse(raw)) == expected


def test_an_empty_integer_is_refused():
    with pytest.raises(Asn1Error, match="content octet"):
        asn1.decode_integer(asn1.parse(b"\x02\x00"))


# --- booleans ---------------------------------------------------------------

def test_boolean_true_and_false():
    assert asn1.decode_boolean(asn1.parse(b"\x01\x01\xFF")) is True
    assert asn1.decode_boolean(asn1.parse(b"\x01\x01\x00")) is False


def test_boolean_must_be_one_octet():
    with pytest.raises(Asn1Error, match="one content octet"):
        asn1.decode_boolean(asn1.parse(b"\x01\x02\xFF\xFF"))


# --- object identifiers -----------------------------------------------------

@pytest.mark.parametrize("raw,dotted", [
    (b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B", "1.2.840.113549.1.1.11"),
    (b"\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02", "1.2.840.10045.4.3.2"),
    (b"\x06\x03\x55\x1D\x11", "2.5.29.17"),
    (b"\x06\x03\x55\x04\x03", "2.5.4.3"),
    (b"\x06\x03\x2B\x65\x70", "1.3.101.112"),
])
def test_known_oids_round_trip_to_dotted_form(raw, dotted):
    assert asn1.decode_oid(asn1.parse(raw)) == dotted


def test_the_first_octet_packs_two_arcs():
    # 0x28 == 40 -> arc1 = 1, arc2 = 0
    assert asn1.decode_oid(asn1.parse(b"\x06\x01\x28")) == "1.0"
    # anything >= 80 is arc 2 with a large second arc
    assert asn1.decode_oid(asn1.parse(b"\x06\x01\x51")) == "2.1"


def test_an_oid_ending_mid_arc_is_refused():
    with pytest.raises(Asn1Error, match="mid-arc"):
        asn1.decode_oid(asn1.parse(b"\x06\x02\x2A\x86"))


def test_an_empty_oid_is_refused():
    with pytest.raises(Asn1Error, match="empty"):
        asn1.decode_oid(asn1.parse(b"\x06\x00"))


# --- bit strings ------------------------------------------------------------

def test_bit_string_reports_its_unused_bits():
    unused, data = asn1.decode_bit_string(asn1.parse(b"\x03\x02\x05\xA0"))
    assert unused == 5
    assert data == b"\xA0"


def test_bit_string_rejects_more_than_seven_unused_bits():
    with pytest.raises(Asn1Error, match="unused bits"):
        asn1.decode_bit_string(asn1.parse(b"\x03\x02\x08\xA0"))


def test_an_empty_bit_string_needs_its_count():
    with pytest.raises(Asn1Error, match="unused-bit count"):
        asn1.decode_bit_string(asn1.parse(b"\x03\x00"))


def test_named_bits_read_into_names():
    names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
    # 0xA0 with 5 unused = bits 0 and 2 set
    got = asn1.bit_string_flags(asn1.parse(b"\x03\x02\x05\xA0"), names)
    assert got == ["a", "c"]


def test_named_bits_span_more_than_one_byte():
    names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
    # bits 0 and 8 set: 0x80 0x80, 7 unused in the second byte
    got = asn1.bit_string_flags(asn1.parse(b"\x03\x03\x07\x80\x80"), names)
    assert got == ["a", "i"]


def test_named_bits_stop_at_the_declared_length():
    names = ["a", "b", "c"]
    got = asn1.bit_string_flags(asn1.parse(b"\x03\x02\x07\x80"), names)
    assert got == ["a"]


# --- strings ----------------------------------------------------------------

def test_printable_string():
    assert asn1.decode_string(asn1.parse(b"\x13\x02GB")) == "GB"


def test_utf8_string_decodes_as_utf8():
    raw = "München".encode("utf-8")
    node = asn1.parse(b"\x0C" + bytes([len(raw)]) + raw)
    assert asn1.decode_string(node) == "München"


def test_bmp_string_is_utf16_big_endian():
    raw = "Hi".encode("utf-16-be")
    node = asn1.parse(b"\x1E" + bytes([len(raw)]) + raw)
    assert asn1.decode_string(node) == "Hi"


def test_universal_string_is_utf32_big_endian():
    raw = "Hi".encode("utf-32-be")
    node = asn1.parse(b"\x1C" + bytes([len(raw)]) + raw)
    assert asn1.decode_string(node) == "Hi"


def test_ia5_string():
    assert asn1.decode_string(asn1.parse(b"\x16\x03a.b")) == "a.b"


def test_a_non_string_tag_is_refused():
    with pytest.raises(Asn1Error, match="not a character string"):
        asn1.decode_string(asn1.parse(b"\x02\x01\x01"))


# --- times ------------------------------------------------------------------

def test_utc_time_with_seconds():
    when = asn1.decode_time(asn1.parse(b"\x17\x0D" + b"260102030405Z"))
    assert (when.year, when.month, when.day) == (2026, 1, 2)
    assert (when.hour, when.minute, when.second) == (3, 4, 5)
    assert when.utcoffset().total_seconds() == 0


def test_utc_time_without_seconds():
    when = asn1.decode_time(asn1.parse(b"\x17\x0B" + b"2601020304Z"))
    assert when.second == 0


def test_utc_time_pivots_at_fifty():
    early = asn1.decode_time(asn1.parse(b"\x17\x0D" + b"490101000000Z"))
    late = asn1.decode_time(asn1.parse(b"\x17\x0D" + b"500101000000Z"))
    assert early.year == 2049
    assert late.year == 1950


def test_utc_time_with_a_numeric_zone_is_normalised():
    when = asn1.decode_time(asn1.parse(b"\x17\x11" + b"260102030405+0200"))
    assert when.hour == 1  # 03:04 at +02:00 is 01:04 UTC


def test_generalized_time():
    when = asn1.decode_time(asn1.parse(b"\x18\x0F" + b"20500102030405Z"))
    assert when.year == 2050


def test_generalized_time_with_a_fraction():
    when = asn1.decode_time(asn1.parse(b"\x18\x11" + b"20500102030405.5Z"))
    assert when.microsecond == 500000


def test_a_malformed_time_is_refused():
    with pytest.raises(Asn1Error):
        asn1.decode_time(asn1.parse(b"\x17\x04" + b"2601"))


def test_a_non_time_tag_is_refused():
    with pytest.raises(Asn1Error, match="not a time"):
        asn1.decode_time(asn1.parse(b"\x02\x01\x01"))


# --- formatting -------------------------------------------------------------

def test_hex_bytes_matches_what_viewers_print():
    assert asn1.hex_bytes(b"\xAB\xCD\xEF") == "AB:CD:EF"
    assert asn1.hex_bytes(b"\x00\x01", separator="") == "0001"
    assert asn1.hex_bytes(b"") == ""


def test_total_len_accounts_for_the_header():
    node = asn1.parse(b"\x04\x81\xC8" + b"A" * 200)
    assert node.total_len == 203
