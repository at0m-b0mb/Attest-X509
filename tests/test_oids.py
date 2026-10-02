"""
The dictionary.

The table's job is to name what it knows and to be *visibly* silent about what
it does not. These tests hold both halves, and they check the small facts the
grader leans on — which hashes are broken, which are merely weak, how big a
named curve is.
"""

import pytest

from attest.core import oids


# --- the tables are well formed --------------------------------------------

@pytest.mark.parametrize("table_name", [
    "SIGNATURE_ALGORITHMS", "PUBLIC_KEY_ALGORITHMS", "CURVES",
    "RDN_ATTRIBUTES", "EXTENSIONS", "EXT_KEY_USAGES", "ACCESS_METHODS",
])
def test_every_key_is_a_dotted_oid(table_name):
    table = getattr(oids, table_name)
    assert table, table_name
    for key in table:
        parts = key.split(".")
        assert len(parts) >= 2, f"{table_name}: {key}"
        assert all(p.isdigit() for p in parts), f"{table_name}: {key}"


def test_key_usage_bits_are_in_rfc_order():
    assert oids.KEY_USAGE_BITS[0] == "digitalSignature"
    assert oids.KEY_USAGE_BITS[5] == "keyCertSign"
    assert oids.KEY_USAGE_BITS[6] == "cRLSign"
    assert len(oids.KEY_USAGE_BITS) == 9
    assert len(set(oids.KEY_USAGE_BITS)) == 9


# --- the ones the spec names explicitly ------------------------------------

@pytest.mark.parametrize("oid,name", [
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
    ("1.2.840.113549.1.1.1", "rsaEncryption"),
    ("1.2.840.10045.2.1", "id-ecPublicKey"),
    ("1.2.840.10045.3.1.7", "prime256v1"),
    ("1.3.132.0.34", "secp384r1"),
    ("2.5.29.17", "subjectAltName"),
    ("2.5.29.19", "basicConstraints"),
    ("2.5.29.15", "keyUsage"),
    ("2.5.29.37", "extKeyUsage"),
    ("2.5.29.35", "authorityKeyIdentifier"),
    ("2.5.29.14", "subjectKeyIdentifier"),
])
def test_the_required_oids_are_named(oid, name):
    assert oids.name_of(oid) == name


@pytest.mark.parametrize("oid,label", [
    ("2.5.4.3", "CN"), ("2.5.4.10", "O"), ("2.5.4.11", "OU"),
    ("2.5.4.6", "C"), ("2.5.4.8", "ST"), ("2.5.4.7", "L"),
    ("1.2.840.113549.1.9.1", "E"),
])
def test_rdn_labels_are_the_conventional_short_forms(oid, label):
    assert oids.rdn_label(oid) == label


def test_an_unknown_rdn_prints_as_its_oid():
    assert oids.rdn_label("1.2.3.4.5") == "1.2.3.4.5"


# --- unknown is never a guess ----------------------------------------------

def test_an_unknown_oid_comes_back_unchanged():
    assert oids.name_of("1.2.3.4.5.6.7") == "1.2.3.4.5.6.7"
    assert not oids.is_known("1.2.3.4.5.6.7")


def test_is_known_is_true_for_a_real_one():
    assert oids.is_known("1.2.840.113549.1.1.11")


def test_signature_algorithm_returns_none_for_an_unknown_oid():
    assert oids.signature_algorithm("1.2.3.4") is None


def test_curve_returns_none_for_an_unknown_oid():
    assert oids.curve("1.2.3.4") is None


# --- hash strength ---------------------------------------------------------

@pytest.mark.parametrize("oid", [
    "1.2.840.113549.1.1.2", "1.2.840.113549.1.1.3", "1.2.840.113549.1.1.4"])
def test_md_hashes_are_marked_broken(oid):
    alg = oids.signature_algorithm(oid)
    assert alg.broken_hash and not alg.weak_hash


@pytest.mark.parametrize("oid", [
    "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.10040.4.3"])
def test_sha1_is_marked_weak_not_broken(oid):
    alg = oids.signature_algorithm(oid)
    assert alg.weak_hash and not alg.broken_hash


@pytest.mark.parametrize("oid", [
    "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
    "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.3.101.112"])
def test_modern_algorithms_are_neither_weak_nor_broken(oid):
    alg = oids.signature_algorithm(oid)
    assert not alg.weak_hash and not alg.broken_hash


def test_every_signature_algorithm_declares_a_key_type():
    for oid, alg in oids.SIGNATURE_ALGORITHMS.items():
        assert alg.key_type in ("RSA", "ECDSA", "DSA", "EdDSA"), oid
        assert alg.name, oid


def test_no_algorithm_is_both_weak_and_broken():
    for oid, alg in oids.SIGNATURE_ALGORITHMS.items():
        assert not (alg.weak_hash and alg.broken_hash), oid


# --- curve sizes -----------------------------------------------------------

@pytest.mark.parametrize("oid,bits,nist", [
    ("1.2.840.10045.3.1.7", 256, "P-256"),
    ("1.3.132.0.34", 384, "P-384"),
    ("1.3.132.0.35", 521, "P-521"),
    ("1.3.132.0.33", 224, "P-224"),
])
def test_named_curves_carry_their_size(oid, bits, nist):
    found = oids.curve(oid)
    assert found.field_bits == bits
    assert found.nist_name == nist


def test_the_modern_curve_floor_is_p256():
    assert oids.EC_MODERN_BITS == 256
    assert oids.curve("1.2.840.10045.3.1.7").field_bits >= oids.EC_MODERN_BITS
    assert oids.curve("1.2.840.10045.3.1.1").field_bits < oids.EC_MODERN_BITS


def test_key_oid_groupings_do_not_overlap():
    assert oids.EC_KEY_OID not in oids.RSA_KEY_OIDS
    assert not (oids.RSA_KEY_OIDS & oids.EDDSA_KEY_OIDS)
