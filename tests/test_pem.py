"""
Getting the bytes out of the paste.

Real pastes are messy: extra text above and below, several blocks in a row,
a block that lost a line, a mail client that indented everything, somebody who
copied a private key by mistake. The extractor has to survive all of that and
say what it could not use.
"""

import base64

from attest.core import pem

_DER = bytes.fromhex("3006020101020102")   # a tiny well-formed SEQUENCE
_B64 = base64.b64encode(_DER).decode()


def _armour(body: str, label: str = "CERTIFICATE") -> str:
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def test_one_block_is_found_and_decoded():
    out = pem.extract_pem(_armour(_B64))
    assert len(out.blocks) == 1
    assert out.good[0].der == _DER


def test_three_blocks_are_found_in_order():
    one = base64.b64encode(b"\x30\x03\x02\x01\x01").decode()
    two = base64.b64encode(b"\x30\x03\x02\x01\x02").decode()
    three = base64.b64encode(b"\x30\x03\x02\x01\x03").decode()
    out = pem.extract_pem(_armour(one) + _armour(two) + _armour(three))
    assert [b.index for b in out.blocks] == [0, 1, 2]
    assert [b.der[-1] for b in out.good] == [1, 2, 3]


def test_surrounding_prose_is_ignored():
    text = ("Certificate:\n    Data:\n        Version: 3 (0x2)\n\n"
            + _armour(_B64)
            + "\nread 1 certificate\n")
    assert pem.extract_pem(text).good[0].der == _DER


def test_a_wrapped_body_is_joined():
    body = "\n".join(_B64[i:i + 4] for i in range(0, len(_B64), 4))
    assert pem.extract_pem(_armour(body)).good[0].der == _DER


def test_indentation_from_a_mail_client_is_tolerated():
    body = "\n".join("    " + _B64[i:i + 4] for i in range(0, len(_B64), 4))
    assert pem.extract_pem(_armour(body)).good[0].der == _DER


def test_a_begin_with_no_end_is_reported():
    out = pem.extract_pem("-----BEGIN CERTIFICATE-----\n" + _B64)
    assert out.bad
    assert "no matching END" in out.bad[0].error


def test_an_empty_block_is_reported():
    out = pem.extract_pem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")
    assert out.bad
    assert "empty" in out.bad[0].error


def test_x509_and_trusted_labels_are_accepted():
    for label in ("X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
        out = pem.extract_pem(_armour(_B64, label))
        assert out.good, label


def test_a_lowercase_header_is_accepted():
    text = _armour(_B64).replace("CERTIFICATE", "Certificate")
    assert pem.extract_pem(text).good


def test_a_private_key_paste_is_named_without_being_read():
    text = _armour("bm90IGEga2V5", "PRIVATE KEY")
    out = pem.extract_pem(text)
    assert not out.blocks
    assert any("PRIVATE KEY" in note for note in out.notes)
    assert any("never wants a private key" in note for note in out.notes)


def test_a_paste_with_nothing_in_it_yields_nothing_and_no_noise():
    out = pem.extract_pem("hello, I have no certificate")
    assert not out.blocks
    assert not out.notes


def test_a_key_beside_a_certificate_still_reads_the_certificate():
    text = _armour("bm90IGEga2V5", "PRIVATE KEY") + _armour(_B64)
    out = pem.extract_pem(text)
    assert len(out.good) == 1
    assert out.good[0].der == _DER


# --- raw DER ----------------------------------------------------------------

def test_looks_like_der_recognises_a_long_form_sequence():
    assert pem.looks_like_der(b"\x30\x82\x01\x00" + b"\x00" * 10)
    assert not pem.looks_like_der(b"-----BEGIN CERTIFICATE-----")
    assert not pem.looks_like_der(b"\x30\x06\x02\x01\x01")   # short form


def test_extract_der_splits_a_concatenated_bundle():
    blob = b"\x30\x81\x03\x02\x01\x01" + b"\x30\x81\x03\x02\x01\x02"
    out = pem.extract_der(blob)
    assert len(out.good) == 2
    assert out.good[0].source == "der"


def test_extract_der_reports_where_it_stopped():
    blob = b"\x30\x81\x03\x02\x01\x01" + b"\x30\x81\xFF\x00"
    out = pem.extract_der(blob)
    assert len(out.good) == 1
    assert out.bad and "did not parse" in out.bad[0].error


def test_extract_dispatches_on_what_it_was_given():
    assert pem.extract(_armour(_B64)).good[0].der == _DER
    raw = b"\x30\x81\x06\x02\x01\x01\x02\x01\x02\x05\x00"
    out = pem.extract(raw)
    assert out.good and any("raw DER" in note for note in out.notes)


def test_extract_decodes_bytes_that_are_really_text():
    assert pem.extract(_armour(_B64).encode()).good[0].der == _DER
