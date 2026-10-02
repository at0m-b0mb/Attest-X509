"""
Reading a Certificate.

Every fixture here is DER assembled by hand with ``tools/gen_samples.py``, so
these tests exercise the real path: encode a certificate the way a CA would,
then insist the parser recovers exactly what was put in. The negative cases
matter just as much — a field that cannot be read must become a note, not a
silent default.
"""

from datetime import datetime, timezone

import pytest

from attest.core.certificate import CertificateError, parse_certificate
from attest.core.model import Role


@pytest.fixture
def leaf_der(gen):
    return gen.build_modern_leaf()


@pytest.fixture
def leaf(leaf_der):
    return parse_certificate(leaf_der)


@pytest.fixture
def root(gen):
    return parse_certificate(gen.build_root())


@pytest.fixture
def old(gen):
    return parse_certificate(gen.build_self_signed_sha1())


# --- the top-level shape ----------------------------------------------------

def test_a_certificate_is_a_three_element_sequence(gen):
    with pytest.raises(CertificateError, match="three elements"):
        parse_certificate(gen.seq(gen.integer(1)))


def test_bytes_that_are_not_der_at_all_are_refused():
    with pytest.raises(CertificateError, match="not well-formed DER"):
        parse_certificate(b"hello world, no certificate here")


def test_der_that_is_not_a_certificate_says_so():
    with pytest.raises(CertificateError, match="three elements"):
        parse_certificate(b"\x01\x02\x03\x04")


def test_an_empty_buffer_is_refused():
    with pytest.raises(CertificateError):
        parse_certificate(b"")


def test_the_der_length_and_fingerprint_are_recorded(leaf, leaf_der):
    assert leaf.der_length == len(leaf_der)
    assert len(leaf.fingerprint_sha256.split(":")) == 32


# --- version, serial, algorithms -------------------------------------------

def test_version_three_is_read_from_the_explicit_tag(leaf):
    assert leaf.version == 3


def test_a_v1_certificate_has_no_version_field(gen):
    der = gen.certificate(
        serial=5, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 1),
        extensions=[], signature_seed=1, version=1)
    cert = parse_certificate(der)
    assert cert.version == 1
    assert not cert.extensions


def test_the_serial_is_read_and_rendered_as_hex(leaf):
    assert leaf.serial == 0x04D28E6177BB0C39
    assert leaf.serial_hex == "04:D2:8E:61:77:BB:0C:39"


def test_a_serial_of_zero_renders_as_a_byte():
    from attest.core.certificate import _serial_hex
    assert _serial_hex(0) == "00"
    assert _serial_hex(255) == "FF"
    assert _serial_hex(256) == "01:00"
    assert _serial_hex(-1).startswith("-")


def test_the_signature_algorithm_is_named(leaf, root):
    assert leaf.signature_algorithm == "ecdsa-with-SHA256"
    assert leaf.signature_algorithm_oid == "1.2.840.10045.4.3.2"
    assert root.signature_algorithm == "sha256WithRSAEncryption"


def test_an_inner_outer_algorithm_mismatch_becomes_a_note(gen):
    tbs = gen.seq(
        gen.explicit(0, gen.integer(2)),
        gen.integer(9),
        gen.alg_rsa(gen.OID_SHA256_RSA),      # inner says SHA-256
        gen.ROOT_NAME,
        gen.validity(datetime(2026, 1, 1, tzinfo=timezone.utc),
                     datetime(2027, 1, 1, tzinfo=timezone.utc)),
        gen.LEAF_NAME,
        gen.rsa_spki(2048, 3),
    )
    der = gen.seq(tbs, gen.alg_rsa(gen.OID_SHA1_RSA),   # outer says SHA-1
                  gen.bit_string(b"\x00" * 8))
    cert = parse_certificate(der)
    assert any("differs from" in note for note in cert.parse_notes)


# --- names ------------------------------------------------------------------

def test_the_subject_is_read_attribute_by_attribute(leaf):
    assert leaf.subject.common_name == "shop.northwind.example"
    assert leaf.subject.organization == "Northwind Retail Ltd"
    assert leaf.subject.first("C") == "GB"
    assert leaf.subject.first("ST") == "Greater London"
    assert leaf.subject.first("OU") == ""


def test_a_name_renders_the_way_viewers_print_it(leaf):
    assert leaf.subject.rendered == (
        "C=GB, ST=Greater London, O=Northwind Retail Ltd, "
        "CN=shop.northwind.example")


def test_self_signed_is_a_statement_about_names(root, leaf):
    assert root.is_self_signed
    assert not leaf.is_self_signed
    assert root.issuer == root.subject


def test_names_compare_case_insensitively(gen):
    upper = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.name((gen.OID_CN, "EXAMPLE ROOT")),
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.name((gen.OID_CN, "example root")),
        spki=gen.rsa_spki(2048, 2), extensions=[], signature_seed=2))
    assert upper.is_self_signed


def test_an_unknown_rdn_attribute_keeps_its_oid_as_its_label(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.name(("1.2.3.4.5", "something")),
        spki=gen.rsa_spki(2048, 4), extensions=[], signature_seed=4))
    assert cert.subject.attributes[0].label == "1.2.3.4.5"
    assert cert.subject.label == "1.2.3.4.5=something"


def test_an_empty_name_is_empty_not_a_blank_string(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.seq(), spki=gen.rsa_spki(2048, 5),
        extensions=[], signature_seed=5))
    assert cert.subject.is_empty
    assert not cert.is_self_signed         # an empty name matches nothing
    assert cert.subject.label == "(no name)"


# --- validity ---------------------------------------------------------------

def test_the_validity_pair_is_read(leaf):
    assert leaf.not_before == datetime(2026, 9, 15, tzinfo=timezone.utc)
    assert leaf.not_after == datetime(2027, 10, 10, tzinfo=timezone.utc)
    assert leaf.validity_days == 390


def test_dates_past_2049_use_generalized_time(root):
    assert root.not_after.year == 2045
    assert not root.parse_notes   # 2045 is still UTCTime territory


def test_a_post_2050_date_encoded_as_utctime_is_flagged(gen):
    # UTCTime "500101..." reads as 1950, which is also before notBefore: the
    # point of the test is the note, which the encoder cannot produce by hand.
    tbs = gen.seq(
        gen.explicit(0, gen.integer(2)), gen.integer(1),
        gen.alg_rsa(gen.OID_SHA256_RSA), gen.ROOT_NAME,
        gen.seq(gen.utc_time(datetime(2026, 1, 1, tzinfo=timezone.utc)),
                gen.generalized_time(datetime(2030, 1, 1, tzinfo=timezone.utc))),
        gen.LEAF_NAME, gen.rsa_spki(2048, 6))
    cert = parse_certificate(
        gen.seq(tbs, gen.alg_rsa(gen.OID_SHA256_RSA),
                gen.bit_string(b"\x00" * 8)))
    assert any("GeneralizedTime" in note for note in cert.parse_notes)


def test_standing_against_a_clock(leaf):
    before = datetime(2026, 1, 1, tzinfo=timezone.utc)
    during = datetime(2027, 1, 1, tzinfo=timezone.utc)
    after = datetime(2028, 1, 1, tzinfo=timezone.utc)
    assert leaf.is_not_yet_valid(before) and not leaf.is_current(before)
    assert leaf.is_current(during)
    assert leaf.is_expired(after) and not leaf.is_current(after)
    assert leaf.days_until_expiry(during) == 282


def test_an_unreadable_validity_becomes_a_note(gen):
    tbs = gen.seq(
        gen.explicit(0, gen.integer(2)), gen.integer(1),
        gen.alg_rsa(gen.OID_SHA256_RSA), gen.ROOT_NAME,
        gen.seq(gen.tlv(0x17, b"nonsense!!!!Z"),
                gen.utc_time(datetime(2027, 1, 1, tzinfo=timezone.utc))),
        gen.LEAF_NAME, gen.rsa_spki(2048, 7))
    cert = parse_certificate(
        gen.seq(tbs, gen.alg_rsa(gen.OID_SHA256_RSA),
                gen.bit_string(b"\x00" * 8)))
    assert cert.not_before is None
    assert cert.not_after is not None
    assert any("did not read as a time" in note for note in cert.parse_notes)
    assert cert.validity_days is None


# --- public keys ------------------------------------------------------------

@pytest.mark.parametrize("bits", [1024, 2048, 3072, 4096])
def test_rsa_modulus_bit_length_is_exact(gen, bits):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(bits, seed=bits),
        extensions=[], signature_seed=bits))
    assert cert.public_key.kind == "RSA"
    assert cert.public_key.rsa_modulus_bits == bits
    assert cert.public_key.rsa_exponent == 65537
    assert cert.public_key.summary == f"RSA {bits}-bit"
    assert cert.public_key.badge == f"RSA-{bits}"


def test_an_odd_sized_modulus_is_not_rounded_up(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2047, seed=9),
        extensions=[], signature_seed=9))
    assert cert.public_key.rsa_modulus_bits == 2047


def test_an_ec_key_reports_its_named_curve(leaf):
    key = leaf.public_key
    assert key.kind == "EC"
    assert key.curve == "prime256v1"
    assert key.curve_nist == "P-256"
    assert key.curve_bits == 256
    assert key.summary == "EC prime256v1 (P-256)"
    assert key.badge == "P-256"


def test_an_unnamed_curve_is_reported_as_unknown(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_ecdsa(gen.OID_ECDSA_SHA256),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME,
        spki=gen.ec_spki("1.2.3.4.5", 256, seed=10),
        extensions=[], signature_seed=10))
    assert cert.public_key.curve_bits is None
    assert cert.public_key.curve == "1.2.3.4.5"
    assert any("not in Attest's table" in n for n in cert.public_key.notes
               + cert.parse_notes)


def test_an_unknown_key_algorithm_is_not_guessed_at(gen):
    spki = gen.seq(gen.seq(gen.oid("1.2.3.4.9")),
                   gen.bit_string(b"\x00" * 16))
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=spki, extensions=[], signature_seed=11))
    assert cert.public_key.kind == ""
    assert not cert.public_key.known
    assert cert.public_key.badge == "?"


def test_a_mis_sized_ec_point_is_noted(gen):
    spki = gen.seq(gen.seq(gen.oid(gen.OID_EC_PUBKEY), gen.oid(gen.OID_P256)),
                   gen.bit_string(b"\x04" + b"\x01" * 10))
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_ecdsa(gen.OID_ECDSA_SHA256),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=spki, extensions=[], signature_seed=12))
    assert any("needs 65" in note for note in cert.public_key.notes)


# --- extensions -------------------------------------------------------------

def test_subject_alt_name_splits_by_kind(old):
    assert old.san.present
    assert old.san.dns_names == ["nas01.mallard.example"]
    assert old.san.ip_addresses == ["192.168.1.40"]
    assert old.san.total == 2
    assert old.san.all_names == ["nas01.mallard.example", "192.168.1.40"]


def test_a_wildcard_is_detected_but_a_plain_name_is_not(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.name((gen.OID_CN, "*.wild.example")),
        spki=gen.rsa_spki(2048, 13),
        extensions=[gen.ext_san(dns=["*.wild.example", "wild.example"])],
        signature_seed=13))
    assert cert.san.wildcards == ["*.wild.example"]


def test_basic_constraints_ca_true_with_a_path_length(gen):
    cert = parse_certificate(gen.build_intermediate())
    bc = cert.basic_constraints
    assert bc.present and bc.ca and bc.critical
    assert bc.path_len == 0
    assert bc.summary == "CA:TRUE, pathlen:0, critical"
    assert cert.is_ca


def test_basic_constraints_ca_false_is_the_default_encoding(leaf):
    bc = leaf.basic_constraints
    assert bc.present and not bc.ca and bc.critical
    assert bc.path_len is None
    assert bc.summary == "CA:FALSE, critical"
    assert not leaf.is_ca


def test_absent_basic_constraints_stays_absent_not_false(gen):
    cert = parse_certificate(gen.build_no_san_leaf())
    assert cert.basic_constraints.present       # this sample does carry it
    bare = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 14),
        extensions=[], signature_seed=14))
    assert not bare.basic_constraints.present
    assert bare.basic_constraints.summary == "absent"


def test_key_usage_bits_are_read_by_name(leaf):
    assert leaf.key_usage_present
    assert leaf.key_usage == ["digitalSignature", "keyAgreement"]
    assert leaf.key_usage_critical


def test_key_cert_sign_is_read_on_a_ca(root):
    assert "keyCertSign" in root.key_usage
    assert "cRLSign" in root.key_usage


def test_extended_key_usage_purposes_are_named(leaf):
    assert leaf.ext_key_usage_present
    assert leaf.ext_key_usage == ["serverAuth", "clientAuth"]


def test_key_identifiers_are_read_as_hex(leaf, gen):
    assert leaf.subject_key_id
    assert leaf.authority_key_id
    assert len(leaf.subject_key_id.split(":")) == 20
    intermediate = parse_certificate(gen.build_intermediate())
    assert leaf.authority_key_id == intermediate.subject_key_id


def test_every_extension_is_listed_with_its_criticality(leaf):
    names = {e.name for e in leaf.extensions}
    assert {"basicConstraints", "keyUsage", "extKeyUsage", "subjectAltName",
            "subjectKeyIdentifier", "authorityKeyIdentifier"} <= names
    assert all(e.known for e in leaf.extensions)
    critical = {e.name for e in leaf.extensions if e.critical}
    assert critical == {"basicConstraints", "keyUsage"}


def test_an_unknown_extension_is_listed_as_unknown(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 15),
        extensions=[gen.extension("1.2.3.4.99", gen.integer(1))],
        signature_seed=15))
    ext = cert.extensions[0]
    assert not ext.known
    assert ext.display == "unknown (1.2.3.4.99)"


def test_a_duplicated_extension_is_called_out(gen):
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 16),
        extensions=[gen.ext_san(dns=["a.example"]),
                    gen.ext_san(dns=["b.example"])],
        signature_seed=16))
    assert any("more than once" in note for note in cert.parse_notes)


def test_extensions_on_a_v1_certificate_are_flagged(gen):
    tbs = gen.seq(
        gen.integer(1), gen.alg_rsa(gen.OID_SHA256_RSA), gen.ROOT_NAME,
        gen.validity(datetime(2026, 1, 1, tzinfo=timezone.utc),
                     datetime(2027, 1, 1, tzinfo=timezone.utc)),
        gen.LEAF_NAME, gen.rsa_spki(2048, 17),
        gen.explicit(3, gen.seq(gen.ext_san(dns=["a.example"]))))
    cert = parse_certificate(
        gen.seq(tbs, gen.alg_rsa(gen.OID_SHA256_RSA),
                gen.bit_string(b"\x00" * 8)))
    assert cert.version == 1 and cert.extensions
    assert any("require v3" in note for note in cert.parse_notes)


def test_an_ipv6_alt_name_renders_in_groups(gen):
    raw = bytes.fromhex("20010db8000000000000000000000001")
    ext = gen.extension(gen.OID_SAN, gen.seq(gen.implicit(7, raw)))
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 18),
        extensions=[ext], signature_seed=18))
    assert cert.san.ip_addresses == ["2001:db8:0:0:0:0:0:1"]


def test_an_unparseable_extension_body_is_noted_not_fatal(gen):
    ext = gen.extension(gen.OID_SAN, b"\x30\x81\xFF\x00")
    cert = parse_certificate(gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 19),
        extensions=[ext], signature_seed=19))
    assert cert.extensions           # still listed
    assert not cert.san.present      # but nothing was believed about it
    assert any("did not parse" in note for note in cert.parse_notes)


def test_role_defaults_to_only_until_the_bundle_assigns_one(leaf):
    assert leaf.role is Role.ONLY
    assert leaf.role.is_end_entity
    assert Role.ROOT.marker == "SELF-SIGNED ROOT"
    assert not Role.INTERMEDIATE.is_end_entity
