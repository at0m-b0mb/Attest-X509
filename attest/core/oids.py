"""
The dictionary.

A certificate says almost nothing in words. Its algorithms, its name
attributes, its extensions and its extended key usages are all object
identifiers — dotted strings like ``1.2.840.113549.1.1.11`` — and a reader that
cannot name them can only show you numbers. This module is the table that turns
them back into language, plus the small amount of knowledge that goes with
each: which hash a signature algorithm uses, how many bits of security a named
curve offers, which short label an RDN attribute is conventionally printed as.

An OID that is not in the table is never guessed at. :func:`name_of` hands back
the dotted form, and the grader treats "unknown" as a reason to lower its
confidence rather than a reason to assume the best.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- signature and public-key algorithms ------------------------------------

@dataclass(frozen=True)
class SigAlg:
    """One signature algorithm, and what it is made of."""

    name: str
    hash_name: str          # "SHA-256", "SHA-1", "MD5", "" when built in
    key_type: str           # "RSA", "ECDSA", "DSA", "EdDSA"
    broken_hash: bool       # MD2 / MD4 / MD5 — collisions are practical
    weak_hash: bool         # SHA-1 — collisions are demonstrated


SIGNATURE_ALGORITHMS: dict[str, SigAlg] = {
    "1.2.840.113549.1.1.2":  SigAlg("md2WithRSAEncryption", "MD2", "RSA", True, False),
    "1.2.840.113549.1.1.3":  SigAlg("md4WithRSAEncryption", "MD4", "RSA", True, False),
    "1.2.840.113549.1.1.4":  SigAlg("md5WithRSAEncryption", "MD5", "RSA", True, False),
    "1.2.840.113549.1.1.5":  SigAlg("sha1WithRSAEncryption", "SHA-1", "RSA", False, True),
    "1.2.840.113549.1.1.10": SigAlg("RSASSA-PSS", "", "RSA", False, False),
    "1.2.840.113549.1.1.11": SigAlg("sha256WithRSAEncryption", "SHA-256", "RSA", False, False),
    "1.2.840.113549.1.1.12": SigAlg("sha384WithRSAEncryption", "SHA-384", "RSA", False, False),
    "1.2.840.113549.1.1.13": SigAlg("sha512WithRSAEncryption", "SHA-512", "RSA", False, False),
    "1.2.840.113549.1.1.14": SigAlg("sha224WithRSAEncryption", "SHA-224", "RSA", False, False),
    "1.2.840.10040.4.3":     SigAlg("dsa-with-SHA1", "SHA-1", "DSA", False, True),
    "2.16.840.1.101.3.4.3.1": SigAlg("dsa-with-SHA224", "SHA-224", "DSA", False, False),
    "2.16.840.1.101.3.4.3.2": SigAlg("dsa-with-SHA256", "SHA-256", "DSA", False, False),
    "1.2.840.10045.4.1":     SigAlg("ecdsa-with-SHA1", "SHA-1", "ECDSA", False, True),
    "1.2.840.10045.4.3.1":   SigAlg("ecdsa-with-SHA224", "SHA-224", "ECDSA", False, False),
    "1.2.840.10045.4.3.2":   SigAlg("ecdsa-with-SHA256", "SHA-256", "ECDSA", False, False),
    "1.2.840.10045.4.3.3":   SigAlg("ecdsa-with-SHA384", "SHA-384", "ECDSA", False, False),
    "1.2.840.10045.4.3.4":   SigAlg("ecdsa-with-SHA512", "SHA-512", "ECDSA", False, False),
    "1.3.101.112":           SigAlg("Ed25519", "", "EdDSA", False, False),
    "1.3.101.113":           SigAlg("Ed448", "", "EdDSA", False, False),
}

PUBLIC_KEY_ALGORITHMS: dict[str, str] = {
    "1.2.840.113549.1.1.1":  "rsaEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.7":  "rsaesOaep",
    "1.2.840.10040.4.1":     "id-dsa",
    "1.2.840.10045.2.1":     "id-ecPublicKey",
    "1.2.840.10046.2.1":     "dhPublicNumber",
    "1.3.101.110":           "X25519",
    "1.3.101.111":           "X448",
    "1.3.101.112":           "Ed25519",
    "1.3.101.113":           "Ed448",
}

RSA_KEY_OIDS = frozenset({
    "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.7"})
EC_KEY_OID = "1.2.840.10045.2.1"
EDDSA_KEY_OIDS = frozenset({"1.3.101.112", "1.3.101.113"})


@dataclass(frozen=True)
class Curve:
    """A named elliptic curve: its spec name, its familiar name, its size."""

    name: str
    nist_name: str
    field_bits: int


CURVES: dict[str, Curve] = {
    "1.2.840.10045.3.1.1":    Curve("prime192v1", "P-192", 192),
    "1.3.132.0.33":           Curve("secp224r1", "P-224", 224),
    "1.2.840.10045.3.1.7":    Curve("prime256v1", "P-256", 256),
    "1.3.132.0.34":           Curve("secp384r1", "P-384", 384),
    "1.3.132.0.35":           Curve("secp521r1", "P-521", 521),
    "1.3.132.0.10":           Curve("secp256k1", "", 256),
    "1.3.132.0.31":           Curve("secp192k1", "", 192),
    "1.3.132.0.32":           Curve("secp224k1", "", 224),
    "1.3.36.3.3.2.8.1.1.7":   Curve("brainpoolP256r1", "", 256),
    "1.3.36.3.3.2.8.1.1.11":  Curve("brainpoolP384r1", "", 384),
    "1.3.36.3.3.2.8.1.1.13":  Curve("brainpoolP512r1", "", 512),
}

# Curves whose field is this size or larger are at or above the strength the
# public web expects of a 2048-bit RSA key.
EC_MODERN_BITS = 256


# --- distinguished-name attributes ------------------------------------------
# short label, long name

RDN_ATTRIBUTES: dict[str, tuple[str, str]] = {
    "2.5.4.3":  ("CN", "commonName"),
    "2.5.4.4":  ("SN", "surname"),
    "2.5.4.5":  ("serialNumber", "serialNumber"),
    "2.5.4.6":  ("C", "countryName"),
    "2.5.4.7":  ("L", "localityName"),
    "2.5.4.8":  ("ST", "stateOrProvinceName"),
    "2.5.4.9":  ("street", "streetAddress"),
    "2.5.4.10": ("O", "organizationName"),
    "2.5.4.11": ("OU", "organizationalUnitName"),
    "2.5.4.12": ("title", "title"),
    "2.5.4.15": ("businessCategory", "businessCategory"),
    "2.5.4.17": ("postalCode", "postalCode"),
    "2.5.4.42": ("GN", "givenName"),
    "2.5.4.43": ("initials", "initials"),
    "2.5.4.46": ("dnQualifier", "dnQualifier"),
    "2.5.4.65": ("pseudonym", "pseudonym"),
    "2.5.4.97": ("organizationIdentifier", "organizationIdentifier"),
    "1.2.840.113549.1.9.1": ("E", "emailAddress"),
    "0.9.2342.19200300.100.1.1":  ("UID", "userId"),
    "0.9.2342.19200300.100.1.25": ("DC", "domainComponent"),
    "1.3.6.1.4.1.311.60.2.1.1": ("jurisdictionL", "jurisdictionLocalityName"),
    "1.3.6.1.4.1.311.60.2.1.2": ("jurisdictionST", "jurisdictionStateOrProvinceName"),
    "1.3.6.1.4.1.311.60.2.1.3": ("jurisdictionC", "jurisdictionCountryName"),
}


# --- extensions -------------------------------------------------------------

EXTENSIONS: dict[str, str] = {
    "2.5.29.9":  "subjectDirectoryAttributes",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.16": "privateKeyUsagePeriod",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.33": "policyMappings",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.36": "policyConstraints",
    "2.5.29.37": "extKeyUsage",
    "2.5.29.46": "freshestCRL",
    "2.5.29.54": "inhibitAnyPolicy",
    "1.3.6.1.5.5.7.1.1":  "authorityInfoAccess",
    "1.3.6.1.5.5.7.1.11": "subjectInfoAccess",
    "1.3.6.1.5.5.7.1.24": "tlsFeature",
    "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
    "1.3.6.1.4.1.11129.2.4.3": "precertPoison",
    "2.16.840.1.113730.1.1": "nsCertType",
}

# KeyUsage is a named-bit BIT STRING; the order here *is* the bit order.
KEY_USAGE_BITS = [
    "digitalSignature", "nonRepudiation", "keyEncipherment",
    "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
    "encipherOnly", "decipherOnly",
]

EXT_KEY_USAGES: dict[str, str] = {
    "2.5.29.37.0":        "anyExtendedKeyUsage",
    "1.3.6.1.5.5.7.3.1":  "serverAuth",
    "1.3.6.1.5.5.7.3.2":  "clientAuth",
    "1.3.6.1.5.5.7.3.3":  "codeSigning",
    "1.3.6.1.5.5.7.3.4":  "emailProtection",
    "1.3.6.1.5.5.7.3.5":  "ipsecEndSystem",
    "1.3.6.1.5.5.7.3.6":  "ipsecTunnel",
    "1.3.6.1.5.5.7.3.7":  "ipsecUser",
    "1.3.6.1.5.5.7.3.8":  "timeStamping",
    "1.3.6.1.5.5.7.3.9":  "OCSPSigning",
    "1.3.6.1.5.5.7.3.21": "secureShellClient",
    "1.3.6.1.5.5.7.3.22": "secureShellServer",
    "1.3.6.1.4.1.311.10.3.3": "serverGatedCrypto",
    "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
}

ACCESS_METHODS: dict[str, str] = {
    "1.3.6.1.5.5.7.48.1": "OCSP",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
    "1.3.6.1.5.5.7.48.3": "timeStamping",
    "1.3.6.1.5.5.7.48.5": "caRepository",
}


# --- lookup -----------------------------------------------------------------

def name_of(oid: str) -> str:
    """The friendliest name Attest knows for *oid*, or the OID itself.

    Deliberately never a guess: an identifier the table does not carry comes
    back in dotted form, so the reader can see that it was not recognised.
    """
    if oid in SIGNATURE_ALGORITHMS:
        return SIGNATURE_ALGORITHMS[oid].name
    for table in (PUBLIC_KEY_ALGORITHMS, EXTENSIONS, EXT_KEY_USAGES,
                  ACCESS_METHODS):
        if oid in table:
            return table[oid]
    if oid in CURVES:
        return CURVES[oid].name
    if oid in RDN_ATTRIBUTES:
        return RDN_ATTRIBUTES[oid][1]
    return oid


def rdn_label(oid: str) -> str:
    """The short label a distinguished name is conventionally printed with."""
    if oid in RDN_ATTRIBUTES:
        return RDN_ATTRIBUTES[oid][0]
    return oid


def signature_algorithm(oid: str) -> SigAlg | None:
    return SIGNATURE_ALGORITHMS.get(oid)


def curve(oid: str) -> Curve | None:
    return CURVES.get(oid)


def is_known(oid: str) -> bool:
    return name_of(oid) != oid
