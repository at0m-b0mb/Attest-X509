"""
The shapes the reading produces.

Everything the parser learns about a certificate is poured into these
dataclasses, and everything the window and the command line draw reads from
them. Nothing here parses or scores — these are the nouns, defined once, so the
engine and the interface can never disagree about what a "rung", a "link" or a
"finding" is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(Enum):
    """How much a single finding should worry the reader."""

    GOOD = "good"        # a reassuring property, not a problem
    INFO = "info"        # worth knowing, not alarming
    NOTICE = "notice"    # a soft tell
    WARNING = "warning"  # a real weakness
    ALERT = "alert"      # a serious weakness

    @property
    def rank(self) -> int:
        return {
            Severity.GOOD: 0,
            Severity.INFO: 1,
            Severity.NOTICE: 2,
            Severity.WARNING: 3,
            Severity.ALERT: 4,
        }[self]


class Role(Enum):
    """Where a certificate sits in the stack that was pasted in.

    This is a *position*, not a verified fact: ``LEAF`` means "first block in
    the file", because that is the order TLS puts them in. Attest says which
    position it assumed and lets the chain links speak for themselves.
    """

    LEAF = "leaf"
    INTERMEDIATE = "intermediate"
    ROOT = "root"
    ONLY = "only"          # a single block that is not a self-signed CA

    @property
    def marker(self) -> str:
        return {
            Role.LEAF: "LEAF",
            Role.INTERMEDIATE: "INTERMEDIATE",
            Role.ROOT: "SELF-SIGNED ROOT",
            Role.ONLY: "SINGLE CERTIFICATE",
        }[self]

    @property
    def is_end_entity(self) -> bool:
        """Presented in the position a server certificate occupies."""
        return self in (Role.LEAF, Role.ONLY)


@dataclass(frozen=True)
class NameAttribute:
    """One attribute inside a distinguished name."""

    oid: str
    label: str      # the short form: CN, O, OU, C, ST, L
    long_name: str  # commonName, organizationName, ...
    value: str

    @property
    def rendered(self) -> str:
        return f"{self.label}={self.value}"


@dataclass
class Name:
    """A distinguished name, kept as the list of RDNs it really is."""

    rdns: list[list[NameAttribute]] = field(default_factory=list)

    @property
    def attributes(self) -> list[NameAttribute]:
        return [attr for rdn in self.rdns for attr in rdn]

    def first(self, label: str) -> str:
        for attr in self.attributes:
            if attr.label == label:
                return attr.value
        return ""

    def all(self, label: str) -> list[str]:
        return [a.value for a in self.attributes if a.label == label]

    @property
    def common_name(self) -> str:
        return self.first("CN")

    @property
    def organization(self) -> str:
        return self.first("O")

    @property
    def rendered(self) -> str:
        """The one-line form every certificate viewer prints."""
        if not self.rdns:
            return ""
        return ", ".join(
            "+".join(a.rendered for a in rdn) for rdn in self.rdns)

    @property
    def is_empty(self) -> bool:
        return not self.attributes

    @property
    def label(self) -> str:
        """The best short handle for a rung: CN, else O, else the whole DN."""
        return self.common_name or self.organization or self.rendered or "(no name)"

    def __eq__(self, other: object) -> bool:
        """Two names match when their rendered forms match, case-folded.

        RFC 5280 asks for attribute-by-attribute comparison with per-type
        rules; this is the practical reading every viewer uses, and it is the
        comparison Attest *reports* rather than one it claims to have verified.
        """
        if not isinstance(other, Name):
            return NotImplemented
        return _canon(self) == _canon(other)

    def __hash__(self) -> int:
        return hash(_canon(self))


def _canon(name: Name) -> str:
    return "/".join(
        "+".join(f"{a.label.lower()}={' '.join(a.value.split()).casefold()}"
                 for a in rdn)
        for rdn in name.rdns)


@dataclass
class PublicKeyInfo:
    """The subjectPublicKeyInfo, read as far as the parameters go."""

    algorithm_oid: str = ""
    algorithm: str = ""
    known: bool = False

    rsa_modulus_bits: int | None = None
    rsa_exponent: int | None = None

    curve_oid: str = ""
    curve: str = ""
    curve_nist: str = ""
    curve_bits: int | None = None

    key_bits: int = 0           # raw size of the BIT STRING, in bits
    notes: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        """"RSA", "EC", "EdDSA", "DSA", or "" when it was not recognised."""
        from . import oids
        if self.algorithm_oid in oids.RSA_KEY_OIDS:
            return "RSA"
        if self.algorithm_oid == oids.EC_KEY_OID:
            return "EC"
        if self.algorithm_oid in oids.EDDSA_KEY_OIDS:
            return "EdDSA"
        if self.algorithm_oid == "1.2.840.10040.4.1":
            return "DSA"
        return ""

    @property
    def summary(self) -> str:
        if self.kind == "RSA" and self.rsa_modulus_bits:
            return f"RSA {self.rsa_modulus_bits}-bit"
        if self.kind == "EC":
            if self.curve_nist:
                return f"EC {self.curve} ({self.curve_nist})"
            if self.curve:
                return f"EC {self.curve}"
            return "EC, unnamed curve"
        if self.kind == "EdDSA":
            return self.algorithm
        if self.kind == "DSA":
            return f"DSA {self.key_bits}-bit" if self.key_bits else "DSA"
        return self.algorithm or "unrecognised key algorithm"

    @property
    def badge(self) -> str:
        """The short form that fits on a rung of the ladder."""
        if self.kind == "RSA" and self.rsa_modulus_bits:
            return f"RSA-{self.rsa_modulus_bits}"
        if self.kind == "EC":
            return self.curve_nist or self.curve or "EC"
        if self.kind == "EdDSA":
            return self.algorithm
        return self.kind or "?"


@dataclass
class BasicConstraints:
    """basicConstraints, and whether it was there at all."""

    present: bool = False
    critical: bool = False
    ca: bool = False
    path_len: int | None = None

    @property
    def summary(self) -> str:
        if not self.present:
            return "absent"
        text = "CA:TRUE" if self.ca else "CA:FALSE"
        if self.ca and self.path_len is not None:
            text += f", pathlen:{self.path_len}"
        return text + (", critical" if self.critical else "")


@dataclass
class SubjectAltName:
    """subjectAltName, split by the kind of name each entry is."""

    present: bool = False
    critical: bool = False
    dns_names: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (len(self.dns_names) + len(self.ip_addresses)
                + len(self.emails) + len(self.uris) + len(self.other))

    @property
    def wildcards(self) -> list[str]:
        return [n for n in self.dns_names if n.startswith("*.")]

    @property
    def all_names(self) -> list[str]:
        return (self.dns_names + self.ip_addresses + self.emails
                + self.uris + self.other)


@dataclass
class Extension:
    """One X.509 extension, named where Attest knows the name."""

    oid: str
    name: str
    critical: bool
    known: bool
    raw_len: int
    summary: str = ""

    @property
    def display(self) -> str:
        return self.name if self.known else f"unknown ({self.oid})"


@dataclass
class Certificate:
    """One certificate, read as far as DER alone allows."""

    index: int = 0
    role: Role = Role.ONLY

    version: int = 1
    serial: int = 0
    serial_hex: str = ""

    signature_algorithm_oid: str = ""
    signature_algorithm: str = ""
    tbs_signature_algorithm_oid: str = ""

    issuer: Name = field(default_factory=Name)
    subject: Name = field(default_factory=Name)

    not_before: datetime | None = None
    not_after: datetime | None = None

    public_key: PublicKeyInfo = field(default_factory=PublicKeyInfo)

    extensions: list[Extension] = field(default_factory=list)
    san: SubjectAltName = field(default_factory=SubjectAltName)
    basic_constraints: BasicConstraints = field(default_factory=BasicConstraints)
    key_usage: list[str] = field(default_factory=list)
    key_usage_present: bool = False
    key_usage_critical: bool = False
    ext_key_usage: list[str] = field(default_factory=list)
    ext_key_usage_present: bool = False
    subject_key_id: str = ""
    authority_key_id: str = ""

    der_length: int = 0
    fingerprint_sha256: str = ""
    parse_notes: list[str] = field(default_factory=list)

    # --- derived -----------------------------------------------------------
    @property
    def is_self_signed(self) -> bool:
        """The issuer name equals the subject name.

        A statement about the *names*, nothing more. Attest never verifies the
        signature, so this is "self-issued" in the strict sense.
        """
        return (not self.subject.is_empty) and self.issuer == self.subject

    @property
    def is_ca(self) -> bool:
        return self.basic_constraints.present and self.basic_constraints.ca

    @property
    def validity_days(self) -> int | None:
        if not self.not_before or not self.not_after:
            return None
        return int((self.not_after - self.not_before).total_seconds() // 86400)

    def days_until_expiry(self, now: datetime) -> int | None:
        if not self.not_after:
            return None
        return int((self.not_after - now).total_seconds() // 86400)

    def is_expired(self, now: datetime) -> bool:
        return bool(self.not_after and now > self.not_after)

    def is_not_yet_valid(self, now: datetime) -> bool:
        return bool(self.not_before and now < self.not_before)

    def is_current(self, now: datetime) -> bool:
        return not self.is_expired(now) and not self.is_not_yet_valid(now)

    @property
    def label(self) -> str:
        return self.subject.label

    @property
    def issuer_label(self) -> str:
        return self.issuer.label


@dataclass
class ChainLink:
    """The join between one certificate and the one printed after it."""

    child_index: int
    parent_index: int
    matched: bool
    child_issuer: str
    parent_subject: str

    @property
    def verdict(self) -> str:
        return "issuer matches" if self.matched else "ISSUER MISMATCH"


@dataclass
class Finding:
    """One observation, in words a person can act on."""

    severity: Severity
    title: str
    detail: str
    points: int = 0
    category: str = "general"
    cert_index: int | None = None   # None when it is about the chain as a whole


@dataclass
class Grade:
    """The final letter, the number behind it, and the honesty caveat."""

    letter: str
    score: int
    headline: str
    ceiling_note: str


@dataclass
class Bundle:
    """Everything Attest learned from one paste."""

    certificates: list[Certificate] = field(default_factory=list)
    links: list[ChainLink] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    grade: Grade | None = None
    parse_notes: list[str] = field(default_factory=list)
    blocks_found: int = 0
    blocks_failed: int = 0
    now: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))

    @property
    def count(self) -> int:
        return len(self.certificates)

    @property
    def leaf(self) -> Certificate | None:
        return self.certificates[0] if self.certificates else None

    @property
    def top(self) -> Certificate | None:
        return self.certificates[-1] if self.certificates else None

    @property
    def all_links_matched(self) -> bool:
        return bool(self.links) and all(link.matched for link in self.links)

    @property
    def chain_complete(self) -> bool:
        """Every link joins, and the stack ends in a self-signed certificate."""
        top = self.top
        return (self.count > 1 and self.all_links_matched
                and top is not None and top.is_self_signed)

    def findings_for(self, index: int) -> list[Finding]:
        return [f for f in self.findings if f.cert_index == index]


def utc(when: datetime) -> datetime:
    """Normalise any datetime to UTC so comparisons are honest across zones."""
    if when.tzinfo is None:
        return when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)
