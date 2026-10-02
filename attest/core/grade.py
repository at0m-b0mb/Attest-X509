"""
The judgement — findings first, then a letter.

The grader reads the certificates :mod:`attest.core.certificate` produced and
turns them into plain-English findings a person can act on, then a single
A+..F letter. Three principles shape it, all carried over from the rest of this
catalogue:

* **Honesty ceiling.** Attest reads bytes. It verifies no signature, checks no
  revocation list, consults no trust store, and never speaks to a server, so it
  cannot know whether a certificate is trusted, whether it has been revoked, or
  whether anyone still holds its private key. A high grade means the certificate
  is well formed and uses sound parameters — never that a connection using it is
  trustworthy, and the words "safe", "secure" and "trusted" never appear as a
  verdict.

* **Unknown beats a guess.** A single certificate pasted on its own cannot tell
  you about the chain above it, and an algorithm Attest does not recognise
  cannot be assumed strong. Both lower the ceiling rather than being waved
  through because nothing visibly failed.

* **Properties, not brands.** Every penalty is a property of the certificate
  itself — an elapsed date, a 1024-bit modulus, a missing subjectAltName, two
  names that do not join. Attest keeps no list of issuers it likes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import oids
from .certificate import CertificateError, parse_certificate
from .model import (
    Bundle,
    Certificate,
    ChainLink,
    Finding,
    Grade,
    Role,
    Severity,
    utc,
)
from .pem import extract

# Letters, best to worst, so ceilings can be compared as positions.
_LETTERS = [
    "A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F",
]

CEILING_NOTE = (
    "Attest reads the certificate you pasted. It does not verify any "
    "signature, does not check revocation (CRL or OCSP), does not consult a "
    "trust store, and cannot tell you whether a live server actually holds the "
    "matching private key. A high grade means the certificate is well-formed "
    "and uses sound parameters — never that a connection using it is "
    "trustworthy."
)

# The public-TLS maximum since 2020. Longer is not malformed; it is simply no
# longer accepted by the browsers for an end-entity certificate.
MAX_LEAF_DAYS = 398

# The day count at which "expiring" stops being housekeeping and starts being
# a finding.
EXPIRY_SOON_DAYS = 30


def plural(count: int, singular: str, suffix: str = "s") -> str:
    """"1 day" / "2 days" — because "1 day(s)" reads like a form, not a sentence."""
    return f"{count} {singular}" if count == 1 else f"{count} {singular}{suffix}"


def _letter_for_score(score: int) -> str:
    bands = [
        (97, "A+"), (93, "A"), (90, "A-"),
        (87, "B+"), (83, "B"), (80, "B-"),
        (77, "C+"), (73, "C"), (70, "C-"),
        (67, "D+"), (63, "D"), (60, "D-"),
    ]
    for floor, letter in bands:
        if score >= floor:
            return letter
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    """Return the worse (lower) of two letters."""
    return letter if _LETTERS.index(letter) >= _LETTERS.index(ceiling) else ceiling


# --- reading the paste ------------------------------------------------------

def read(source: str | bytes) -> Bundle:
    """Turn a paste into a :class:`Bundle` of parsed certificates."""
    bundle = Bundle()
    extraction = extract(source)
    bundle.parse_notes.extend(extraction.notes)
    bundle.blocks_found = len(extraction.blocks)

    for block in extraction.blocks:
        if not block.ok:
            bundle.blocks_failed += 1
            bundle.parse_notes.append(
                f"block {block.index + 1}: {block.error}")
            continue
        try:
            cert = parse_certificate(block.der, index=len(bundle.certificates))
        except CertificateError as exc:
            bundle.blocks_failed += 1
            bundle.parse_notes.append(f"block {block.index + 1}: {exc}")
            continue
        bundle.certificates.append(cert)

    _order_and_link(bundle)
    return bundle


def _links_for(certs: list[Certificate]) -> list[ChainLink]:
    return [
        ChainLink(
            child_index=i,
            parent_index=i + 1,
            matched=certs[i].issuer == certs[i + 1].subject,
            child_issuer=certs[i].issuer.rendered,
            parent_subject=certs[i + 1].subject.rendered,
        )
        for i in range(len(certs) - 1)
    ]


def _order_and_link(bundle: Bundle) -> None:
    """Assign each certificate its position, then read the joins between them.

    A chain in a TLS handshake or a bundle file is leaf-first, so that is the
    order Attest assumes. If reversing the blocks joins strictly more links
    than the order given, the file was almost certainly written root-first;
    Attest reorders it and says so rather than reporting a chain of breaks that
    are really a sorting problem.
    """
    certs = bundle.certificates
    if len(certs) > 1:
        forward = _links_for(certs)
        backward = _links_for(list(reversed(certs)))
        if sum(l.matched for l in backward) > sum(l.matched for l in forward):
            certs.reverse()
            bundle.parse_notes.append(
                "The blocks were written root-first; Attest reversed them so "
                "the leaf is read first, which is the order a TLS handshake "
                "sends them in.")
        for position, cert in enumerate(certs):
            cert.index = position

    bundle.links = _links_for(certs)

    count = len(certs)
    for i, cert in enumerate(certs):
        if count == 1:
            cert.role = (Role.ROOT if cert.is_self_signed and cert.is_ca
                         else Role.ONLY)
        elif i == 0:
            cert.role = Role.LEAF
        elif i == count - 1:
            cert.role = Role.ROOT if cert.is_self_signed else Role.INTERMEDIATE
        else:
            cert.role = Role.INTERMEDIATE


# --- the findings -----------------------------------------------------------

class _Ledger:
    """Collects findings and the points they cost."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.spent = 0

    def add(self, severity: Severity, title: str, detail: str, points: int = 0,
            category: str = "general", cert_index: int | None = None) -> None:
        self.findings.append(Finding(severity, title, detail, points, category,
                                     cert_index))
        self.spent += points


def _who(cert: Certificate, total: int) -> str:
    """How a finding should name the certificate it is about."""
    if total == 1:
        return "This certificate"
    return f"The {cert.role.value} ({cert.label})"


def _check_dates(cert: Certificate, led: _Ledger, now: datetime, total: int) -> None:
    who = _who(cert, total)
    if not cert.not_after or not cert.not_before:
        led.add(Severity.WARNING, "The validity dates did not read",
                f"{who} does not carry a readable notBefore/notAfter pair, so "
                f"Attest cannot say whether it is current.", 20, "validity",
                cert.index)
        return

    before = cert.not_before.strftime("%Y-%m-%d")
    after = cert.not_after.strftime("%Y-%m-%d")

    if cert.is_expired(now):
        days = -(cert.days_until_expiry(now) or 0)
        led.add(Severity.ALERT, "Expired",
                f"{who} expired on {after}, about {plural(days, 'day')} ago. Nothing "
                f"presenting it will be accepted until it is replaced.",
                40, "validity", cert.index)
    elif cert.is_not_yet_valid(now):
        led.add(Severity.ALERT, "Not yet valid",
                f"{who} does not become valid until {before}. Either the "
                f"certificate was issued ahead of time or the clock reading "
                f"this is wrong.", 35, "validity", cert.index)
    else:
        left = cert.days_until_expiry(now) or 0
        if left <= EXPIRY_SOON_DAYS:
            led.add(Severity.WARNING, "Expiring soon",
                    f"{who} expires on {after} — {plural(left, 'day')} from now. "
                    f"Renewal should already be in hand.", 14, "validity",
                    cert.index)
        else:
            led.add(Severity.GOOD, "Within its validity window",
                    f"{who} is valid from {before} to {after}; "
                    f"{plural(left, 'day')} remain"
                    f"{'s' if left == 1 else ''}.",
                    0, "validity", cert.index)

    span = cert.validity_days
    if span is None:
        return
    if cert.role.is_end_entity and not cert.is_ca:
        if span > MAX_LEAF_DAYS:
            led.add(Severity.WARNING, "Valid for longer than 398 days",
                    f"{who} covers {span} days. Since September 2020 the major "
                    f"browsers refuse a publicly-trusted server certificate "
                    f"issued for more than {MAX_LEAF_DAYS} days, so a span this "
                    f"long marks it as privately issued — or as predating the "
                    f"rule.", 12, "validity", cert.index)
    elif span > MAX_LEAF_DAYS:
        led.add(Severity.INFO, "A long life, as a CA has",
                f"{who} covers {span} days. That is expected of a certificate "
                f"authority — the 398-day limit applies to end-entity "
                f"certificates, not to the CAs above them.", 0, "validity",
                cert.index)


def _check_signature_algorithm(cert: Certificate, led: _Ledger, total: int) -> None:
    who = _who(cert, total)
    alg = oids.signature_algorithm(cert.signature_algorithm_oid)
    if alg is None:
        named = cert.signature_algorithm or "an OID Attest has no name for"
        led.add(Severity.NOTICE, "Unrecognised signature algorithm",
                f"{who} is signed with {named}. Attest will not guess at its "
                f"strength, so the grade is capped rather than assumed.",
                6, "algorithm", cert.index)
        return

    if alg.broken_hash:
        led.add(Severity.ALERT, f"Signed with {alg.hash_name}",
                f"{who} is signed using {alg.name}. {alg.hash_name} collisions "
                f"are cheap and have been for years — a second certificate with "
                f"the same signature can be constructed, so the signature "
                f"proves nothing about who issued this.", 40, "algorithm",
                cert.index)
    elif alg.weak_hash:
        led.add(Severity.ALERT, "Signed with SHA-1",
                f"{who} is signed using {alg.name}. A SHA-1 collision was "
                f"demonstrated in 2017 and chosen-prefix attacks followed; every "
                f"mainstream browser stopped accepting SHA-1 certificates in "
                f"2017. Treat the signature as decorative.", 30, "algorithm",
                cert.index)
    else:
        label = alg.hash_name or alg.name
        led.add(Severity.GOOD, f"Signed with {label}",
                f"{who} uses {alg.name}, which is current practice. Attest "
                f"reads the algorithm named in the certificate; it does not "
                f"verify the signature itself.", 0, "algorithm", cert.index)


def _check_key(cert: Certificate, led: _Ledger, total: int) -> None:
    who = _who(cert, total)
    key = cert.public_key
    kind = key.kind

    if kind == "RSA":
        bits = key.rsa_modulus_bits
        if bits is None:
            led.add(Severity.NOTICE, "The RSA modulus did not read",
                    f"{who} names an RSA key but its modulus could not be "
                    f"measured, so its size is unknown.", 8, "key", cert.index)
        elif bits < 1024:
            led.add(Severity.ALERT, f"RSA key of only {bits} bits",
                    f"{who} carries a {bits}-bit RSA key. Keys this small have "
                    f"been factored publicly; the key offers no protection at "
                    f"all.", 45, "key", cert.index)
        elif bits < 2048:
            led.add(Severity.ALERT, f"RSA key below 2048 bits ({bits})",
                    f"{who} carries a {bits}-bit RSA key. 2048 bits has been "
                    f"the floor for publicly-trusted certificates since 2013, "
                    f"and 1024-bit RSA is considered within reach of a "
                    f"well-resourced attacker.", 35, "key", cert.index)
        elif bits < 3072:
            led.add(Severity.GOOD, f"RSA key of {bits} bits",
                    f"{who} carries a {bits}-bit RSA key, which meets the "
                    f"current floor for public trust.", 0, "key", cert.index)
        else:
            led.add(Severity.GOOD, f"RSA key of {bits} bits",
                    f"{who} carries a {bits}-bit RSA key — comfortably above "
                    f"the 2048-bit floor.", 0, "key", cert.index)
        if key.rsa_exponent is not None and key.rsa_exponent < 65537:
            led.add(Severity.WARNING, f"Small RSA exponent ({key.rsa_exponent})",
                    f"{who} uses a public exponent of {key.rsa_exponent}. "
                    f"65537 is the universal choice; smaller values have a "
                    f"history of implementation attacks.", 10, "key", cert.index)

    elif kind == "EC":
        bits = key.curve_bits
        if bits is None:
            led.add(Severity.NOTICE, "Unrecognised elliptic curve",
                    f"{who} carries an EC key on a curve Attest cannot name "
                    f"({key.curve_oid or 'no named curve given'}), so its "
                    f"strength is unknown.", 8, "key", cert.index)
        elif bits < oids.EC_MODERN_BITS:
            led.add(Severity.WARNING, f"Elliptic curve of only {bits} bits",
                    f"{who} uses {key.curve}, a {bits}-bit curve. P-256 is the "
                    f"floor in current practice.", 14, "key", cert.index)
        else:
            led.add(Severity.GOOD, f"Elliptic-curve key on {key.curve}",
                    f"{who} uses {key.summary}. At {bits} bits this is at or "
                    f"above the strength expected of a 2048-bit RSA key, in a "
                    f"fraction of the size.", 0, "key", cert.index)

    elif kind == "EdDSA":
        led.add(Severity.GOOD, f"{key.algorithm} key",
                f"{who} uses {key.algorithm}, a modern signature scheme with no "
                f"parameter choices left to get wrong.", 0, "key", cert.index)

    elif kind == "DSA":
        led.add(Severity.WARNING, "DSA key",
                f"{who} carries a DSA key"
                + (f" of {key.key_bits} bits" if key.key_bits else "")
                + ". DSA is absent from every modern TLS profile and browsers "
                  "no longer accept it.", 20, "key", cert.index)

    else:
        led.add(Severity.NOTICE, "Unrecognised key algorithm",
                f"{who} names the key algorithm "
                f"{key.algorithm_oid or '(none)'}, which is not in Attest's "
                f"table. Its strength is unknown rather than assumed.",
                8, "key", cert.index)


def _check_self_signed(cert: Certificate, led: _Ledger, total: int) -> None:
    if not cert.is_self_signed:
        return
    who = _who(cert, total)
    if cert.role is Role.ROOT:
        led.add(Severity.INFO, "Self-signed, as a root is",
                f"{who} names itself as its own issuer, which is what a trust "
                f"anchor looks like. Whether any store actually contains it is "
                f"something Attest cannot see.", 0, "chain", cert.index)
    else:
        led.add(Severity.NOTICE, "Self-signed",
                f"{who} names itself as its own issuer, so no authority vouches "
                f"for it. Fine inside a lab or a private deployment; a browser "
                f"will refuse it unless it was installed by hand.",
                10, "chain", cert.index)


def _check_san(cert: Certificate, led: _Ledger, total: int) -> None:
    who = _who(cert, total)
    san = cert.san
    is_server_ish = cert.role.is_end_entity and not cert.is_ca

    if not san.present:
        if is_server_ish:
            cn = cert.subject.common_name
            led.add(Severity.ALERT, "No subjectAltName",
                    f"{who} carries no subjectAltName extension, so it names no "
                    f"host at all in the place browsers look. "
                    + (f"The commonName says {cn}, but commonName has not been "
                       f"honoured for host matching since 2017 — Chrome, Firefox "
                       f"and Safari all ignore it."
                       if cn else
                       "There is no commonName to fall back on either."),
                    25, "identity", cert.index)
        else:
            led.add(Severity.INFO, "No subjectAltName, as a CA needs none",
                    f"{who} issues certificates rather than identifying a host, "
                    f"so the absence of a subjectAltName is correct here.",
                    0, "identity", cert.index)
        return

    if san.total == 0:
        led.add(Severity.WARNING, "An empty subjectAltName",
                f"{who} carries a subjectAltName extension with nothing in it, "
                f"which names no host and is forbidden by RFC 5280.",
                15, "identity", cert.index)
        return

    shown = ", ".join(san.all_names[:6])
    if san.total > 6:
        shown += f", and {san.total - 6} more"
    led.add(Severity.GOOD, f"Names {plural(san.total, 'subject alternative name')}",
            f"{who} identifies itself through subjectAltName: {shown}.",
            0, "identity", cert.index)

    if san.wildcards:
        which = ", ".join(san.wildcards)
        led.add(Severity.NOTICE, "Wildcard name present",
                f"{who} covers {which}. A wildcard matches exactly one label: "
                f"\"*.example.com\" covers www.example.com but not "
                f"a.b.example.com, and not example.com itself. One such "
                f"certificate — and one private key — stands behind every "
                f"subdomain it covers.", 4, "identity", cert.index)

    if cert.subject.common_name and cert.subject.common_name not in san.all_names:
        led.add(Severity.NOTICE, "The commonName is not among the SAN entries",
                f"{who} has commonName {cert.subject.common_name}, which does "
                f"not appear in its subjectAltName list. Since browsers read "
                f"only the SAN list, that host is not actually covered.",
                6, "identity", cert.index)


def _check_constraints(cert: Certificate, led: _Ledger, total: int) -> None:
    who = _who(cert, total)
    bc = cert.basic_constraints

    if cert.role.is_end_entity and bc.present and bc.ca:
        led.add(Severity.WARNING, "basicConstraints says CA:TRUE",
                f"{who} sits in the position a server certificate occupies, but "
                f"declares itself a certificate authority. A CA certificate used "
                f"as an end-entity certificate can sign others; if its key is on "
                f"a web server, that web server can mint certificates.",
                12, "constraints", cert.index)

    if not bc.present:
        if cert.role is Role.INTERMEDIATE or (
                "keyCertSign" in cert.key_usage):
            led.add(Severity.WARNING, "No basicConstraints on a signing certificate",
                    f"{who} is used to sign other certificates but carries no "
                    f"basicConstraints extension, so it never states that it is "
                    f"a CA or how deep a chain it may anchor. RFC 5280 requires "
                    f"the extension, marked critical, on every CA certificate.",
                    12, "constraints", cert.index)
        elif cert.role.is_end_entity:
            led.add(Severity.NOTICE, "No basicConstraints",
                    f"{who} does not carry a basicConstraints extension. For an "
                    f"end-entity certificate the correct statement is CA:FALSE, "
                    f"marked critical; saying nothing leaves it to the reader.",
                    5, "constraints", cert.index)
    elif bc.ca and not bc.critical:
        led.add(Severity.NOTICE, "basicConstraints is not marked critical",
                f"{who} declares CA:TRUE in an extension that is not critical, "
                f"so a reader that does not understand the extension may ignore "
                f"the declaration. RFC 5280 requires it to be critical on a CA.",
                6, "constraints", cert.index)

    if not cert.key_usage_present:
        led.add(Severity.NOTICE, "No keyUsage extension",
                f"{who} does not say what its key may be used for. Without "
                f"keyUsage the key is unconstrained by the certificate — a "
                f"signing key and an encryption key look alike.",
                5, "constraints", cert.index)
    elif not cert.key_usage:
        led.add(Severity.WARNING, "keyUsage with no bits set",
                f"{who} carries a keyUsage extension in which no bit is set, "
                f"which permits nothing at all and is forbidden by RFC 5280.",
                12, "constraints", cert.index)
    else:
        led.add(Severity.GOOD, "keyUsage is stated",
                f"{who} limits its key to {', '.join(cert.key_usage)}.",
                0, "constraints", cert.index)

    if cert.role.is_end_entity and not cert.is_ca:
        if not cert.ext_key_usage_present:
            led.add(Severity.NOTICE, "No extendedKeyUsage extension",
                    f"{who} does not name the purposes it was issued for "
                    f"(serverAuth, clientAuth, codeSigning and so on), so "
                    f"nothing in the certificate narrows what it may be "
                    f"presented for.", 5, "constraints", cert.index)
        elif not cert.ext_key_usage:
            led.add(Severity.WARNING, "An empty extendedKeyUsage",
                    f"{who} carries an extendedKeyUsage extension that lists no "
                    f"purpose, which permits nothing.", 10, "constraints",
                    cert.index)
        else:
            led.add(Severity.GOOD, "extendedKeyUsage is stated",
                    f"{who} is issued for {', '.join(cert.ext_key_usage)}.",
                    0, "constraints", cert.index)

    if ("keyCertSign" in cert.key_usage and not cert.is_ca
            and cert.basic_constraints.present):
        led.add(Severity.WARNING, "keyCertSign without CA:TRUE",
                f"{who} claims the keyCertSign bit while basicConstraints says "
                f"CA:FALSE. The two statements contradict each other.",
                12, "constraints", cert.index)


def _check_version(cert: Certificate, led: _Ledger, total: int) -> None:
    who = _who(cert, total)
    if cert.version == 3:
        return
    if cert.version in (1, 2):
        led.add(Severity.WARNING, f"An X.509 v{cert.version} certificate",
                f"{who} predates version 3, so it can carry no extensions at "
                f"all — no subjectAltName, no basicConstraints, no keyUsage. "
                f"Nothing in current practice issues these.", 15, "format",
                cert.index)
    else:
        led.add(Severity.NOTICE, "Unreadable version field",
                f"{who} does not state a version Attest can read.", 6, "format",
                cert.index)


def _check_chain(bundle: Bundle, led: _Ledger) -> None:
    certs = bundle.certificates
    if len(certs) < 2:
        if certs and not certs[0].is_self_signed:
            led.add(Severity.INFO, "One certificate, no chain to read",
                    "Only one certificate was pasted, and it is not "
                    "self-signed, so the authority that issued it is named but "
                    "not present. Attest can say nothing about the chain above "
                    f"it — it was issued by {certs[0].issuer_label}, and that is "
                    "all the bytes reveal.", 0, "chain")
        return

    for link in bundle.links:
        child = certs[link.child_index]
        parent = certs[link.parent_index]
        if link.matched:
            led.add(Severity.GOOD, f"Link {link.child_index + 1} joins",
                    f"The {child.role.value}'s issuer name matches the "
                    f"{parent.role.value}'s subject name "
                    f"({parent.subject.label}). Names only — Attest does not "
                    f"verify that the parent's key actually signed the child.",
                    0, "chain")
        else:
            led.add(Severity.ALERT, f"Link {link.child_index + 1} is broken",
                    f"The {child.role.value} says it was issued by "
                    f"\"{link.child_issuer or '(no issuer name)'}\", but the "
                    f"next certificate in the file is "
                    f"\"{link.parent_subject or '(no subject name)'}\". These "
                    f"two do not join, so the bundle is not a chain as it "
                    f"stands.", 30, "chain")

    top = certs[-1]
    if top.is_self_signed:
        if bundle.all_links_matched:
            led.add(Severity.INFO, "The chain is complete as given",
                    f"Every link joins and the file ends in a self-signed "
                    f"certificate ({top.subject.label}), so the bundle is a "
                    f"complete chain on its own terms. Whether any trust store "
                    f"holds that root is outside what Attest can see.",
                    0, "chain")
    else:
        led.add(Severity.NOTICE, "The chain stops short of a root",
                f"The last certificate ({top.subject.label}) is not "
                f"self-signed — it names {top.issuer_label} as its issuer, and "
                f"that certificate is not in the file. Servers often omit the "
                f"root deliberately, since the client must already hold it, so "
                f"this is not necessarily wrong; it does mean Attest cannot see "
                f"where the chain ends.", 5, "chain")

    # Key-identifier corroboration: a second, independent way the links agree.
    # Only worth saying when the *names* matched — if they already disagree,
    # the key identifiers are the same news told twice.
    for link in bundle.links:
        child = certs[link.child_index]
        parent = certs[link.parent_index]
        if link.matched and child.authority_key_id and parent.subject_key_id:
            if child.authority_key_id != parent.subject_key_id:
                led.add(Severity.WARNING,
                        f"Link {link.child_index + 1}: the key identifiers disagree",
                        f"The {child.role.value}'s authorityKeyIdentifier points "
                        f"at a key whose identifier is "
                        f"{child.authority_key_id[:23]}…, while the "
                        f"{parent.role.value}'s subjectKeyIdentifier is "
                        f"{parent.subject_key_id[:23]}…. The names may match, "
                        f"but these say the parent's key is a different key.",
                        14, "chain")

    for i, cert in enumerate(certs[1:], start=1):
        if not cert.is_ca and not cert.is_self_signed:
            led.add(Severity.WARNING, f"The {cert.role.value} is not marked as a CA",
                    f"{cert.label} sits above the leaf in this bundle, so it is "
                    f"being presented as an issuer, but its basicConstraints "
                    f"does not say CA:TRUE. A conforming client will not build "
                    f"a chain through it.", 15, "chain", i)


def _check_notes(cert: Certificate, led: _Ledger, total: int) -> None:
    """Internal inconsistencies the parser recorded become findings."""
    who = _who(cert, total)
    for note in cert.parse_notes:
        led.add(Severity.NOTICE, "An inconsistency inside the certificate",
                f"{who}: {note}.", 4, "format", cert.index)


# --- the letter -------------------------------------------------------------

def grade_bundle(bundle: Bundle, now: datetime | None = None) -> Bundle:
    """Populate ``bundle.findings`` and ``bundle.grade`` in place."""
    bundle.now = utc(now) if now else datetime.now(timezone.utc)
    led = _Ledger()
    certs = bundle.certificates
    total = len(certs)

    if not certs:
        bundle.findings = []
        headline = ("No certificate found" if not bundle.blocks_found
                    else "Nothing in this paste parsed as a certificate")
        bundle.grade = Grade("F", 0, headline, CEILING_NOTE)
        return bundle

    for cert in certs:
        _check_version(cert, led, total)
        _check_dates(cert, led, bundle.now, total)
        _check_signature_algorithm(cert, led, total)
        _check_key(cert, led, total)
        _check_self_signed(cert, led, total)
        _check_san(cert, led, total)
        _check_constraints(cert, led, total)
        _check_notes(cert, led, total)

    _check_chain(bundle, led)

    if bundle.blocks_failed:
        led.add(Severity.WARNING,
                f"{plural(bundle.blocks_failed, 'block')} could not be read",
                "Part of this paste did not decode as a certificate, so the "
                "reading below covers only what did. The notes say which "
                "blocks and why.", 8, "format")

    score = max(0, min(100, 100 - led.spent))
    letter = _letter_for_score(score)
    headline, letter = _resolve_ceiling(bundle, led, score, letter)

    bundle.findings = sorted(led.findings, key=lambda f: -f.severity.rank)
    bundle.grade = Grade(letter=letter, score=score, headline=headline,
                         ceiling_note=CEILING_NOTE)
    return bundle


def _resolve_ceiling(bundle: Bundle, led: _Ledger, score: int,
                     letter: str) -> tuple[str, str]:
    """Apply the honesty ceilings, worst first, and name the result."""
    certs = bundle.certificates
    worst = max((f.severity.rank for f in led.findings), default=0)
    unknown_parameters = any(
        f.category in ("algorithm", "key") and f.severity is Severity.NOTICE
        for f in led.findings)

    # A broken join is not a detail; the bundle is not a chain.
    if bundle.links and not bundle.all_links_matched:
        return ("The certificates given do not join into a chain",
                _cap(letter, "D"))

    # An algorithm or curve Attest cannot name means it cannot judge strength.
    if unknown_parameters:
        return ("Parameters Attest cannot name — strength unknown",
                _cap(letter, "C"))

    # One certificate on its own says nothing about the chain above it.
    single_orphan = len(certs) == 1 and not certs[0].is_self_signed
    if single_orphan:
        letter = _cap(letter, "B+")
        if score >= 87:
            return ("Well-formed, but the chain above it is unknown", letter)
    else:
        # A+ is reserved for a complete, clean chain — nothing less.
        if (bundle.chain_complete and worst <= Severity.INFO.rank
                and score >= 97):
            return ("A complete chain, soundly parameterised", "A+")
        letter = _cap(letter, "A")

    if score >= 90:
        return ("Sound, with minor notes", letter)
    if score >= 75:
        return ("Workable, with weaknesses worth fixing", letter)
    if score >= 60:
        return ("Several real weaknesses", letter)
    return ("This certificate should not be in use", letter)


# --- the whole pipeline -----------------------------------------------------

def analyze(source: str | bytes, now: datetime | None = None) -> Bundle:
    """Read then grade — the whole pipeline in one call."""
    return grade_bundle(read(source), now=now)
