"""
The judgement.

Two things are under test here. The ordinary one: each finding fires on the
property it describes and on nothing else. The important one: the honesty
ceiling holds — the top grade stays reserved, an input that cannot answer a
question lowers the grade instead of being waved through, and no result ever
tells the reader that anything is safe.
"""

from datetime import datetime, timedelta, timezone

import pytest

from attest.core.grade import (
    CEILING_NOTE,
    MAX_LEAF_DAYS,
    _cap,
    _letter_for_score,
    analyze,
    grade_bundle,
    plural,
    read,
)
from attest.core.model import Role, Severity

UTC = timezone.utc


def _pem(der: bytes) -> str:
    import base64
    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def _titles(bundle) -> list[str]:
    return [f.title for f in bundle.findings]


def _has(bundle, fragment: str) -> bool:
    return any(fragment.lower() in f.title.lower() for f in bundle.findings)


# --- the letter scale -------------------------------------------------------

@pytest.mark.parametrize("score,letter", [
    (100, "A+"), (97, "A+"), (96, "A"), (93, "A"), (92, "A-"), (90, "A-"),
    (89, "B+"), (83, "B"), (80, "B-"), (77, "C+"), (73, "C"), (70, "C-"),
    (67, "D+"), (63, "D"), (60, "D-"), (59, "F"), (0, "F"),
])
def test_score_bands(score, letter):
    assert _letter_for_score(score) == letter


def test_cap_returns_the_worse_letter():
    assert _cap("A+", "B") == "B"
    assert _cap("D", "B") == "D"
    assert _cap("C", "C") == "C"


def test_plural_reads_as_english():
    assert plural(1, "day") == "1 day"
    assert plural(2, "day") == "2 days"
    assert plural(0, "block") == "0 blocks"
    assert plural(1, "polic", "ies") == "1 polic"


# --- the ceiling note is unconditional --------------------------------------

def test_every_grade_carries_the_ceiling_note(samples):
    for name, text in samples.items():
        bundle = analyze(text)
        assert bundle.grade.ceiling_note == CEILING_NOTE, name


def test_an_empty_paste_still_carries_the_ceiling_note():
    bundle = analyze("nothing here")
    assert bundle.grade.letter == "F"
    assert bundle.grade.ceiling_note == CEILING_NOTE
    assert not bundle.certificates


def test_the_ceiling_note_names_every_limit():
    low = CEILING_NOTE.lower()
    for limit in ("verify any signature", "revocation", "trust store",
                  "private key"):
        assert limit in low


def test_the_result_never_uses_safe_or_secure_as_a_verdict(samples):
    for name, text in samples.items():
        bundle = analyze(text)
        words = " ".join(
            [bundle.grade.headline]
            + [f.title for f in bundle.findings]).lower()
        for banned in ("safe", "secure", "trusted", "verified"):
            assert banned not in words, f"{name}: {banned}"


# --- the samples ------------------------------------------------------------

@pytest.mark.parametrize("name,letter,count", [
    ("modern-chain.pem", "A+", 3),
    ("broken-chain.pem", "D", 2),
    ("expired-leaf.pem", "D-", 1),
    ("no-san-leaf.pem", "C", 1),
    ("self-signed-sha1.pem", "F", 1),
])
def test_the_sample_set_spans_the_scale(samples, now, name, letter, count):
    bundle = analyze(samples[name], now=now)
    assert bundle.count == count, name
    assert bundle.grade.letter == letter, f"{name}: {bundle.grade.score}/100"


def test_every_sample_actually_parses(samples):
    for name, text in samples.items():
        bundle = read(text)
        assert bundle.certificates, name
        assert not bundle.blocks_failed, name


def test_findings_are_sorted_most_severe_first(samples):
    for name, text in samples.items():
        bundle = analyze(text)
        ranks = [f.severity.rank for f in bundle.findings]
        assert ranks == sorted(ranks, reverse=True), name


def test_every_finding_has_a_title_and_an_actionable_detail(samples):
    for name, text in samples.items():
        for finding in analyze(text).findings:
            assert finding.title and not finding.title.endswith("."), name
            assert len(finding.detail) > 40, f"{name}: {finding.title}"
            assert finding.detail.endswith((".", "…")), finding.title


def test_good_and_info_findings_never_cost_points(samples):
    for name, text in samples.items():
        for finding in analyze(text).findings:
            if finding.severity in (Severity.GOOD, Severity.INFO):
                assert finding.points == 0, f"{name}: {finding.title}"


def test_no_finding_mentions_a_brand_or_issuer_as_a_reason(samples):
    """Penalties describe the certificate, never who issued it."""
    for name, text in samples.items():
        for finding in analyze(text).findings:
            if finding.points:
                assert "Example Trust" not in finding.title, name
                assert "Zephyr" not in finding.title, name


# --- A+ is reserved ---------------------------------------------------------

def test_a_plus_requires_a_complete_chain(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    assert bundle.grade.letter == "A+"
    assert bundle.chain_complete
    assert bundle.all_links_matched
    assert max(f.severity.rank for f in bundle.findings) <= Severity.INFO.rank


def test_the_leaf_alone_cannot_reach_a_plus(gen, now):
    """Same leaf, same score — but with no chain above it, A+ is out of reach."""
    bundle = analyze(_pem(gen.build_modern_leaf()), now=now)
    assert bundle.count == 1
    assert bundle.grade.letter == "B+"
    assert "chain above it is unknown" in bundle.grade.headline


def test_a_chain_missing_its_root_is_capped_below_a_plus(gen, now):
    text = _pem(gen.build_modern_leaf()) + _pem(gen.build_intermediate())
    bundle = analyze(text, now=now)
    assert not bundle.chain_complete
    assert bundle.all_links_matched
    assert bundle.grade.letter != "A+"
    assert _has(bundle, "stops short of a root")


def test_an_unknown_algorithm_caps_the_grade_at_c(gen, now):
    der = gen.certificate(
        serial=1, sig_alg=gen.seq(gen.oid("1.2.3.4.5")),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(4096, 1),
        extensions=[gen.ext_basic_constraints(ca=False),
                    gen.ext_key_usage("digitalSignature"),
                    gen.ext_ext_key_usage(gen.OID_SERVER_AUTH),
                    gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=1)
    bundle = analyze(_pem(der), now=now)
    assert _has(bundle, "Unrecognised signature algorithm")
    assert bundle.grade.letter in ("C", "C-", "D+", "D", "D-", "F")
    assert "strength unknown" in bundle.grade.headline


def test_a_broken_link_caps_the_grade_at_d(samples, now):
    bundle = analyze(samples["broken-chain.pem"], now=now)
    assert not bundle.all_links_matched
    assert bundle.grade.letter in ("D", "D-", "F")
    assert "do not join" in bundle.grade.headline


# --- validity ---------------------------------------------------------------

def test_an_expired_certificate_is_an_alert(samples, now):
    bundle = analyze(samples["expired-leaf.pem"], now=now)
    expired = [f for f in bundle.findings if f.title == "Expired"]
    assert len(expired) == 1
    assert expired[0].severity is Severity.ALERT
    assert "2025-02-01" in expired[0].detail


def test_a_not_yet_valid_certificate_is_an_alert(samples):
    early = datetime(2020, 1, 1, tzinfo=UTC)
    bundle = analyze(samples["expired-leaf.pem"], now=early)
    assert _has(bundle, "Not yet valid")
    assert not _has(bundle, "Expired")


def test_expiring_within_thirty_days_is_a_warning(samples, gen):
    leaf = gen.build_modern_leaf()
    inside = datetime(2027, 10, 1, tzinfo=UTC)      # nine days to run
    bundle = analyze(_pem(leaf), now=inside)
    soon = [f for f in bundle.findings if f.title == "Expiring soon"]
    assert len(soon) == 1
    assert soon[0].severity is Severity.WARNING


def test_thirty_one_days_out_is_still_good(gen):
    bundle = analyze(_pem(gen.build_modern_leaf()),
                     now=datetime(2027, 9, 1, tzinfo=UTC))
    assert _has(bundle, "Within its validity window")
    assert not _has(bundle, "Expiring soon")


def test_a_leaf_longer_than_398_days_is_a_warning(samples, now):
    bundle = analyze(samples["self-signed-sha1.pem"], now=now)
    long_life = [f for f in bundle.findings
                 if f.title.startswith("Valid for longer")]
    assert len(long_life) == 1
    assert long_life[0].severity is Severity.WARNING
    assert str(MAX_LEAF_DAYS) in long_life[0].detail


def test_a_ca_with_a_long_life_is_only_informational(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    for finding in bundle.findings:
        if finding.title.startswith("A long life"):
            assert finding.severity is Severity.INFO
            assert finding.points == 0
    assert not _has(bundle, "Valid for longer")


def test_exactly_398_days_is_not_penalised(gen):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME, not_before=start,
        not_after=start + timedelta(days=MAX_LEAF_DAYS),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 2),
        extensions=[gen.ext_basic_constraints(ca=False),
                    gen.ext_key_usage("digitalSignature"),
                    gen.ext_ext_key_usage(gen.OID_SERVER_AUTH),
                    gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=2)
    bundle = analyze(_pem(der), now=start + timedelta(days=10))
    assert not _has(bundle, "Valid for longer")


# --- algorithms and keys ----------------------------------------------------

@pytest.mark.parametrize("sig_oid,title", [
    ("1.2.840.113549.1.1.4", "Signed with MD5"),
    ("1.2.840.113549.1.1.5", "Signed with SHA-1"),
])
def test_broken_and_weak_hashes_are_alerts(gen, sig_oid, title):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(sig_oid), issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 3),
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=3)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    hit = [f for f in bundle.findings if f.title == title]
    assert hit, _titles(bundle)
    assert hit[0].severity is Severity.ALERT


def test_sha256_is_good(samples, now):
    bundle = analyze(samples["no-san-leaf.pem"], now=now)
    hit = [f for f in bundle.findings if f.title == "Signed with SHA-256"]
    assert hit and hit[0].severity is Severity.GOOD


@pytest.mark.parametrize("bits,severity", [
    (512, Severity.ALERT),
    (1024, Severity.ALERT),
    (2047, Severity.ALERT),
    (2048, Severity.GOOD),
    (3072, Severity.GOOD),
    (4096, Severity.GOOD),
])
def test_rsa_sizes_are_judged_at_the_2048_bit_floor(gen, bits, severity):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(bits, seed=bits),
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=bits)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    key_findings = [f for f in bundle.findings if f.category == "key"]
    assert key_findings, _titles(bundle)
    assert key_findings[0].severity is severity
    assert str(bits) in key_findings[0].title


def test_p256_and_above_are_good(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    hit = [f for f in bundle.findings
           if f.title.startswith("Elliptic-curve key")]
    assert hit and hit[0].severity is Severity.GOOD


def test_a_curve_under_p256_is_a_warning(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_ecdsa(gen.OID_ECDSA_SHA256),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME,
        spki=gen.ec_spki("1.2.840.10045.3.1.1", 192, seed=4),
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=4)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    hit = [f for f in bundle.findings if "Elliptic curve of only" in f.title]
    assert hit and hit[0].severity is Severity.WARNING


def test_a_small_rsa_exponent_is_a_warning(gen):
    spki = gen.seq(gen.alg_rsa(gen.OID_RSA),
                   gen.bit_string(gen.seq(
                       gen.integer(gen.fake_modulus(2048, 5)), gen.integer(3))))
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=spki,
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=5)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    assert _has(bundle, "Small RSA exponent")


# --- identity ---------------------------------------------------------------

def test_a_leaf_without_san_is_an_alert(samples, now):
    bundle = analyze(samples["no-san-leaf.pem"], now=now)
    hit = [f for f in bundle.findings if f.title == "No subjectAltName"]
    assert hit and hit[0].severity is Severity.ALERT
    assert "commonName" in hit[0].detail
    assert "2017" in hit[0].detail


def test_a_ca_without_san_is_not_penalised(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    for finding in bundle.findings:
        if "No subjectAltName" in finding.title:
            assert finding.severity is Severity.INFO
            assert finding.points == 0


def test_a_wildcard_is_a_notice_that_explains_one_label(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.name((gen.OID_CN, "*.wild.example")),
        spki=gen.rsa_spki(2048, 6),
        extensions=[gen.ext_san(dns=["*.wild.example"])],
        signature_seed=6)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    hit = [f for f in bundle.findings if f.title == "Wildcard name present"]
    assert hit
    assert hit[0].severity is Severity.NOTICE
    assert "*.wild.example" in hit[0].detail
    assert "one label" in hit[0].detail


def test_a_commonname_outside_the_san_list_is_flagged(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.name((gen.OID_CN, "elsewhere.example")),
        spki=gen.rsa_spki(2048, 7),
        extensions=[gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=7)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    assert _has(bundle, "commonName is not among the SAN entries")


def test_an_empty_san_is_a_warning(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 8),
        extensions=[gen.ext_san()], signature_seed=8)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    hit = [f for f in bundle.findings if f.title == "An empty subjectAltName"]
    assert hit and hit[0].severity is Severity.WARNING


# --- self-signed ------------------------------------------------------------

def test_a_self_signed_leaf_is_a_notice(samples, now):
    bundle = analyze(samples["self-signed-sha1.pem"], now=now)
    hit = [f for f in bundle.findings if f.title == "Self-signed"]
    assert hit and hit[0].severity is Severity.NOTICE
    assert hit[0].points > 0


def test_a_self_signed_root_is_expected(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    hit = [f for f in bundle.findings if "Self-signed, as a root is" in f.title]
    assert hit and hit[0].severity is Severity.INFO
    assert hit[0].points == 0


# --- constraints ------------------------------------------------------------

def test_ca_true_on_something_presented_as_a_leaf_is_a_warning(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 9),
        extensions=[gen.ext_basic_constraints(ca=True),
                    gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=9)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    hit = [f for f in bundle.findings
           if f.title == "basicConstraints says CA:TRUE"]
    assert hit and hit[0].severity is Severity.WARNING
    assert "mint certificates" in hit[0].detail


def test_a_missing_key_usage_is_a_notice(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        subject=gen.LEAF_NAME, spki=gen.rsa_spki(2048, 10),
        extensions=[gen.ext_basic_constraints(ca=False),
                    gen.ext_san(dns=["shop.northwind.example"])],
        signature_seed=10)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    for title in ("No keyUsage extension", "No extendedKeyUsage extension"):
        hit = [f for f in bundle.findings if f.title == title]
        assert hit, _titles(bundle)
        assert hit[0].severity is Severity.NOTICE


def test_a_non_critical_ca_declaration_is_a_notice(gen):
    der = gen.certificate(
        serial=1, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2030, 1, 1, tzinfo=UTC),
        subject=gen.ROOT_NAME, spki=gen.rsa_spki(4096, 11),
        extensions=[gen.ext_basic_constraints(ca=True, critical=False),
                    gen.ext_key_usage("keyCertSign")],
        signature_seed=11)
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    assert _has(bundle, "not marked critical")


def test_a_v1_certificate_is_a_warning(gen):
    tbs = gen.seq(
        gen.integer(1), gen.alg_rsa(gen.OID_SHA256_RSA), gen.ROOT_NAME,
        gen.validity(datetime(2026, 1, 1, tzinfo=UTC),
                     datetime(2026, 12, 1, tzinfo=UTC)),
        gen.LEAF_NAME, gen.rsa_spki(2048, 12))
    der = gen.seq(tbs, gen.alg_rsa(gen.OID_SHA256_RSA),
                  gen.bit_string(b"\x00" * 8))
    bundle = analyze(_pem(der), now=datetime(2026, 6, 1, tzinfo=UTC))
    hit = [f for f in bundle.findings if "X.509 v1" in f.title]
    assert hit and hit[0].severity is Severity.WARNING


# --- the chain --------------------------------------------------------------

def test_roles_are_assigned_by_position(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    assert [c.role for c in bundle.certificates] == [
        Role.LEAF, Role.INTERMEDIATE, Role.ROOT]


def test_a_lone_self_signed_ca_is_read_as_a_root(gen, now):
    bundle = analyze(_pem(gen.build_root()), now=now)
    assert bundle.certificates[0].role is Role.ROOT


def test_a_lone_leaf_is_read_as_a_single_certificate(gen, now):
    bundle = analyze(_pem(gen.build_modern_leaf()), now=now)
    assert bundle.certificates[0].role is Role.ONLY


def test_each_matched_link_is_reported(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    assert len(bundle.links) == 2
    assert all(link.matched for link in bundle.links)
    assert all(link.verdict == "issuer matches" for link in bundle.links)
    assert sum(1 for f in bundle.findings if f.title.startswith("Link")) == 2


def test_a_broken_link_names_both_sides(samples, now):
    bundle = analyze(samples["broken-chain.pem"], now=now)
    link = bundle.links[0]
    assert not link.matched
    assert link.verdict == "ISSUER MISMATCH"
    hit = [f for f in bundle.findings if "is broken" in f.title]
    assert hit
    assert "Example Trust Issuing CA 2" in hit[0].detail
    assert "Zephyr PKI Root CA" in hit[0].detail


def test_a_complete_chain_is_noted_as_complete(samples, now):
    bundle = analyze(samples["modern-chain.pem"], now=now)
    assert bundle.chain_complete
    assert _has(bundle, "chain is complete as given")


def test_root_first_order_is_detected_and_reversed(gen, now):
    text = (_pem(gen.build_root()) + _pem(gen.build_intermediate())
            + _pem(gen.build_modern_leaf()))
    bundle = analyze(text, now=now)
    assert [c.role for c in bundle.certificates] == [
        Role.LEAF, Role.INTERMEDIATE, Role.ROOT]
    assert bundle.all_links_matched
    assert any("root-first" in note for note in bundle.parse_notes)


def test_key_identifier_disagreement_is_reported_when_names_agree(gen, now):
    """Same subject name, different key — the subtle case names alone miss."""
    impostor = gen.certificate(
        serial=99, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ICA_NAME,
        not_before=datetime(2024, 1, 1, tzinfo=UTC),
        not_after=datetime(2034, 1, 1, tzinfo=UTC),
        subject=gen.ICA_NAME,                       # the name the leaf expects
        spki=gen.rsa_spki(3072, 98),
        extensions=[gen.ext_basic_constraints(ca=True),
                    gen.ext_key_usage("keyCertSign"),
                    gen.ext_skid(gen.key_id(9999))],   # but a different key
        signature_seed=98)
    bundle = analyze(_pem(gen.build_modern_leaf()) + _pem(impostor), now=now)
    assert bundle.all_links_matched              # the names do join
    assert _has(bundle, "key identifiers disagree")


def test_key_identifiers_are_not_reported_twice_when_names_already_differ(
        samples, now):
    bundle = analyze(samples["broken-chain.pem"], now=now)
    assert not _has(bundle, "key identifiers disagree")


def test_an_issuer_that_is_not_a_ca_is_flagged(gen, now):
    not_a_ca = gen.certificate(
        serial=98, sig_alg=gen.alg_rsa(gen.OID_SHA256_RSA),
        issuer=gen.ROOT_NAME,
        not_before=datetime(2024, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        subject=gen.ICA_NAME, spki=gen.rsa_spki(3072, 97),
        extensions=[gen.ext_basic_constraints(ca=False)],
        signature_seed=97)
    bundle = analyze(_pem(gen.build_modern_leaf()) + _pem(not_a_ca), now=now)
    assert _has(bundle, "is not marked as a CA")


# --- bad input --------------------------------------------------------------

def test_a_block_that_does_not_parse_is_counted_and_explained(samples):
    broken = ("-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n"
              "-----END CERTIFICATE-----\n")
    bundle = analyze(broken + samples["no-san-leaf.pem"])
    assert bundle.count == 1
    assert bundle.blocks_failed == 1
    assert _has(bundle, "could not be read")
    assert any("block 1" in note for note in bundle.parse_notes)


def test_a_paste_of_only_a_key_grades_f_and_says_why():
    bundle = analyze("-----BEGIN PRIVATE KEY-----\nAAAA\n"
                     "-----END PRIVATE KEY-----\n")
    assert bundle.grade.letter == "F"
    assert not bundle.certificates
    assert any("PRIVATE KEY" in note for note in bundle.parse_notes)


def test_grade_bundle_is_idempotent_on_a_fresh_read(samples, now):
    first = grade_bundle(read(samples["modern-chain.pem"]), now=now)
    second = grade_bundle(read(samples["modern-chain.pem"]), now=now)
    assert first.grade.letter == second.grade.letter
    assert first.grade.score == second.grade.score
    assert _titles(first) == _titles(second)


def test_a_naive_clock_is_treated_as_utc(samples):
    naive = datetime(2026, 10, 2, 12, 0, 0)
    bundle = analyze(samples["modern-chain.pem"], now=naive)
    assert bundle.now.tzinfo is not None
    assert bundle.grade.letter == "A+"


def test_scores_stay_inside_zero_and_one_hundred(samples):
    for name, text in samples.items():
        score = analyze(text).grade.score
        assert 0 <= score <= 100, name
