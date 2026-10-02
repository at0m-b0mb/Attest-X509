"""
Reading a Certificate out of DER.

RFC 5280 lays the structure out like this, and this module walks it in that
order:

    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT BIT STRING OPTIONAL,
        subjectUniqueID [2]  IMPLICIT BIT STRING OPTIONAL,
        extensions      [3]  EXPLICIT Extensions OPTIONAL  }

Two habits run through the whole file. A field that does not parse is recorded
as a note on the certificate and the read continues, because a certificate with
one strange extension is still worth showing; and nothing is ever inferred —
an absent extension stays absent rather than becoming a default, so the grader
can tell "says CA:FALSE" apart from "says nothing".

The signature value is read but never *checked*: Attest holds no trust store
and does no public-key arithmetic. That limit is the point, and it is stated in
every grade.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from . import oids
from .asn1 import (
    Asn1Error,
    Node,
    OCTET_STRING,
    SEQUENCE,
    bit_string_flags,
    decode_bit_string,
    decode_boolean,
    decode_integer,
    decode_oid,
    decode_string,
    decode_time,
    hex_bytes,
    parse,
)
from .model import (
    BasicConstraints,
    Certificate,
    Extension,
    Name,
    NameAttribute,
    PublicKeyInfo,
    SubjectAltName,
)


class CertificateError(ValueError):
    """The DER parsed, but it is not shaped like a certificate."""


# --- Name -------------------------------------------------------------------

def parse_name(node: Node) -> Name:
    """``Name ::= SEQUENCE OF RelativeDistinguishedName``."""
    name = Name()
    if not node.is_tag(SEQUENCE):
        raise CertificateError(f"a Name must be a SEQUENCE, found {node.tag_name}")
    for rdn_node in node.children:
        rdn: list[NameAttribute] = []
        for attr in rdn_node.children:
            if len(attr.children) < 2:
                continue
            try:
                oid = decode_oid(attr.child(0))
            except Asn1Error:
                continue
            raw = attr.child(1)
            try:
                value = decode_string(raw)
            except Asn1Error:
                # A DirectoryString can hold anything in practice; show the
                # bytes rather than dropping the attribute.
                value = hex_bytes(raw.value)
            short, long_name = oids.RDN_ATTRIBUTES.get(oid, (oid, oid))
            rdn.append(NameAttribute(oid=oid, label=short, long_name=long_name,
                                     value=value))
        if rdn:
            name.rdns.append(rdn)
    return name


# --- SubjectPublicKeyInfo ---------------------------------------------------

def parse_public_key(node: Node) -> PublicKeyInfo:
    """``SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }``.

    Anything that did not read lands on ``info.notes``; the caller copies those
    up onto the certificate so one list holds everything odd about it.
    """
    info = PublicKeyInfo()
    notes = info.notes
    if not node.is_tag(SEQUENCE) or len(node.children) < 2:
        notes.append("the subjectPublicKeyInfo is not the expected SEQUENCE")
        return info

    alg_node = node.child(0)
    if alg_node.children:
        try:
            info.algorithm_oid = decode_oid(alg_node.child(0))
        except Asn1Error as exc:
            notes.append(f"the public-key algorithm did not read ({exc})")
    info.algorithm = oids.name_of(info.algorithm_oid)
    info.known = info.algorithm_oid in oids.PUBLIC_KEY_ALGORITHMS

    try:
        unused, key_bytes = decode_bit_string(node.child(1))
    except Asn1Error as exc:
        notes.append(f"the public key bit string did not read ({exc})")
        return info
    info.key_bits = len(key_bytes) * 8 - unused

    kind = info.kind
    if kind == "RSA":
        _read_rsa(key_bytes, info, notes)
    elif kind == "EC":
        _read_ec(alg_node, key_bytes, info, notes)
    elif kind == "DSA":
        _read_dsa(alg_node, info, notes)
    return info


def _read_rsa(key_bytes: bytes, info: PublicKeyInfo, notes: list[str]) -> None:
    """``RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }``.

    The modulus bit length is the number everyone means by "key size", and it
    is ``bit_length()`` of the integer — not the byte count, which would read a
    2047-bit key as 2048.
    """
    try:
        inner = parse(key_bytes)
    except Asn1Error as exc:
        notes.append(f"the RSA key inside the bit string did not parse ({exc})")
        return
    if not inner.is_tag(SEQUENCE) or len(inner.children) < 2:
        notes.append("the RSA key is not a two-element SEQUENCE")
        return
    try:
        modulus = decode_integer(inner.child(0))
        info.rsa_exponent = decode_integer(inner.child(1))
    except Asn1Error as exc:
        notes.append(f"the RSA modulus or exponent did not read ({exc})")
        return
    if modulus <= 0:
        notes.append("the RSA modulus is not a positive integer")
        return
    info.rsa_modulus_bits = modulus.bit_length()


def _read_ec(alg_node: Node, key_bytes: bytes, info: PublicKeyInfo,
             notes: list[str]) -> None:
    """The curve lives in the algorithm parameters, not in the key itself."""
    if len(alg_node.children) >= 2:
        params = alg_node.child(1)
        try:
            info.curve_oid = decode_oid(params)
        except Asn1Error:
            notes.append(
                "this EC key specifies its curve explicitly rather than by "
                "name; Attest reports named curves only")
    if info.curve_oid:
        found = oids.curve(info.curve_oid)
        if found:
            info.curve = found.name
            info.curve_nist = found.nist_name
            info.curve_bits = found.field_bits
        else:
            info.curve = info.curve_oid
            notes.append(f"the named curve {info.curve_oid} is not in Attest's table")
    if key_bytes and key_bytes[0] not in (0x02, 0x03, 0x04):
        notes.append("the EC point does not begin with a known form octet")
    elif key_bytes and key_bytes[0] == 0x04 and info.curve_bits:
        expected = 1 + 2 * ((info.curve_bits + 7) // 8)
        if len(key_bytes) != expected:
            notes.append(
                f"the uncompressed EC point is {len(key_bytes)} bytes where "
                f"{info.curve} needs {expected}")


def _read_dsa(alg_node: Node, info: PublicKeyInfo, notes: list[str]) -> None:
    """DSA's size is the prime p in the parameters."""
    if len(alg_node.children) < 2:
        return
    params = alg_node.child(1)
    if params.is_tag(SEQUENCE) and params.children:
        try:
            info.key_bits = decode_integer(params.child(0)).bit_length()
        except Asn1Error as exc:
            notes.append(f"the DSA parameters did not read ({exc})")


# --- extensions -------------------------------------------------------------

def _general_names(node: Node, san: SubjectAltName) -> None:
    """``GeneralName`` is a CHOICE of context tags; read the ones we can show."""
    for entry in node.children:
        if not entry.is_context:
            continue
        number = entry.number
        if number == 2:       # dNSName, IA5String implicit
            san.dns_names.append(entry.value.decode("ascii", errors="replace"))
        elif number == 7:     # iPAddress, OCTET STRING implicit
            san.ip_addresses.append(_render_ip(entry.value))
        elif number == 1:     # rfc822Name
            san.emails.append(entry.value.decode("ascii", errors="replace"))
        elif number == 6:     # uniformResourceIdentifier
            san.uris.append(entry.value.decode("ascii", errors="replace"))
        elif number == 4:     # directoryName, EXPLICIT
            try:
                san.other.append("dirName:" + parse_name(entry.child(0)).rendered)
            except (Asn1Error, CertificateError, IndexError):
                san.other.append("dirName:(unreadable)")
        elif number == 0:     # otherName
            san.other.append("otherName")
        elif number == 8:     # registeredID
            try:
                san.other.append("registeredID:" + decode_oid(entry))
            except Asn1Error:
                san.other.append("registeredID")
        else:
            san.other.append(f"GeneralName[{number}]")


def _render_ip(data: bytes) -> str:
    if len(data) == 4:
        return ".".join(str(b) for b in data)
    if len(data) == 16:
        groups = [f"{data[i] << 8 | data[i + 1]:x}" for i in range(0, 16, 2)]
        return ":".join(groups)
    return hex_bytes(data)


def _parse_extension(ext_node: Node, cert: Certificate) -> Extension | None:
    """One ``Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }``."""
    if not ext_node.children:
        return None
    try:
        oid = decode_oid(ext_node.child(0))
    except Asn1Error as exc:
        cert.parse_notes.append(f"an extension had an unreadable OID ({exc})")
        return None

    critical = False
    value_node: Node | None = None
    for kid in ext_node.children[1:]:
        if kid.is_tag(1):  # BOOLEAN
            try:
                critical = decode_boolean(kid)
            except Asn1Error:
                critical = bool(kid.value and kid.value[0])
        elif kid.is_tag(OCTET_STRING):
            value_node = kid
    if value_node is None:
        cert.parse_notes.append(
            f"the extension {oids.name_of(oid)} carries no extnValue")
        return None

    ext = Extension(oid=oid, name=oids.EXTENSIONS.get(oid, oid), critical=critical,
                    known=oid in oids.EXTENSIONS, raw_len=len(value_node.value))

    # Every extnValue is an OCTET STRING wrapping the extension's own DER.
    try:
        inner = parse(value_node.value)
    except Asn1Error as exc:
        if ext.known:
            cert.parse_notes.append(
                f"the contents of {ext.name} did not parse ({exc})")
        ext.summary = f"{len(value_node.value)} bytes, unparsed"
        return ext

    try:
        ext.summary = _fill_from_extension(oid, inner, critical, cert)
    except (Asn1Error, CertificateError, IndexError) as exc:
        cert.parse_notes.append(f"{ext.display} did not read fully ({exc})")
        ext.summary = "unreadable"
    return ext


def _fill_from_extension(oid: str, inner: Node, critical: bool,
                         cert: Certificate) -> str:
    """Pour a recognised extension into the certificate; return its summary."""
    if oid == "2.5.29.17":  # subjectAltName
        san = SubjectAltName(present=True, critical=critical)
        _general_names(inner, san)
        cert.san = san
        return f"{san.total} name" + ("" if san.total == 1 else "s")

    if oid == "2.5.29.19":  # basicConstraints
        bc = BasicConstraints(present=True, critical=critical)
        for kid in inner.children:
            if kid.is_tag(1):
                bc.ca = decode_boolean(kid)
            elif kid.is_tag(2):
                bc.path_len = decode_integer(kid)
        cert.basic_constraints = bc
        return bc.summary

    if oid == "2.5.29.15":  # keyUsage
        cert.key_usage = bit_string_flags(inner, oids.KEY_USAGE_BITS)
        cert.key_usage_present = True
        cert.key_usage_critical = critical
        return ", ".join(cert.key_usage) or "no bits set"

    if oid == "2.5.29.37":  # extKeyUsage
        purposes = []
        for kid in inner.children:
            purpose = decode_oid(kid)
            purposes.append(oids.EXT_KEY_USAGES.get(purpose, purpose))
        cert.ext_key_usage = purposes
        cert.ext_key_usage_present = True
        return ", ".join(purposes) or "none listed"

    if oid == "2.5.29.14":  # subjectKeyIdentifier
        cert.subject_key_id = hex_bytes(inner.value)
        return cert.subject_key_id

    if oid == "2.5.29.35":  # authorityKeyIdentifier
        for kid in inner.children:
            if kid.is_ctx(0):
                cert.authority_key_id = hex_bytes(kid.value)
        return cert.authority_key_id or "present, no keyIdentifier"

    if oid == "2.5.29.31":  # cRLDistributionPoints
        n = len(inner.children)
        return f"{n} distribution point" + ("" if n == 1 else "s")

    if oid == "2.5.29.32":  # certificatePolicies
        n = len(inner.children)
        return f"{n} polic" + ("y" if n == 1 else "ies")

    if oid == "1.3.6.1.5.5.7.1.1":  # authorityInfoAccess
        methods = []
        for kid in inner.children:
            if kid.children:
                method = decode_oid(kid.child(0))
                methods.append(oids.ACCESS_METHODS.get(method, method))
        return ", ".join(methods) or "no access descriptions"

    if oid == "1.3.6.1.4.1.11129.2.4.2":
        return "embedded SCTs"

    if oid == "2.5.29.30":  # nameConstraints
        n = len(inner.children)
        return f"{n} subtree set" + ("" if n == 1 else "s")

    return inner.tag_name


# --- the whole certificate --------------------------------------------------

def parse_certificate(der: bytes, index: int = 0) -> Certificate:
    """Read one DER certificate. Raises :class:`CertificateError` if it is not one."""
    try:
        top = parse(der)
    except Asn1Error as exc:
        raise CertificateError(f"this is not well-formed DER: {exc}") from exc
    if not top.is_tag(SEQUENCE) or len(top.children) != 3:
        raise CertificateError(
            "a Certificate is a SEQUENCE of exactly three elements "
            "(tbsCertificate, signatureAlgorithm, signatureValue); this has "
            f"{len(top.children)}")

    cert = Certificate(index=index, der_length=len(der))
    cert.fingerprint_sha256 = hex_bytes(hashlib.sha256(der).digest())

    tbs, sig_alg, sig_value = top.children
    if not tbs.is_tag(SEQUENCE):
        raise CertificateError("the tbsCertificate is not a SEQUENCE")

    # --- outer signatureAlgorithm ------------------------------------------
    if sig_alg.children:
        try:
            cert.signature_algorithm_oid = decode_oid(sig_alg.child(0))
        except Asn1Error as exc:
            cert.parse_notes.append(f"the signatureAlgorithm did not read ({exc})")
    cert.signature_algorithm = oids.name_of(cert.signature_algorithm_oid)
    try:
        decode_bit_string(sig_value)
    except Asn1Error as exc:
        cert.parse_notes.append(f"the signatureValue is not a BIT STRING ({exc})")

    # --- tbsCertificate ----------------------------------------------------
    fields = list(tbs.children)
    pos = 0
    if fields and fields[0].is_ctx(0):
        try:
            cert.version = decode_integer(fields[0].child(0)) + 1
        except (Asn1Error, IndexError):
            cert.parse_notes.append("the version field did not read")
            cert.version = 0
        pos = 1
    else:
        cert.version = 1    # v1 is the DEFAULT, encoded by being absent

    if len(fields) < pos + 6:
        raise CertificateError(
            f"the tbsCertificate has {len(fields)} fields; a certificate needs "
            f"at least {pos + 6}")

    try:
        cert.serial = decode_integer(fields[pos])
    except Asn1Error as exc:
        cert.parse_notes.append(f"the serial number did not read ({exc})")
    cert.serial_hex = _serial_hex(cert.serial)

    inner_alg = fields[pos + 1]
    if inner_alg.children:
        try:
            cert.tbs_signature_algorithm_oid = decode_oid(inner_alg.child(0))
        except Asn1Error:
            pass

    cert.issuer = parse_name(fields[pos + 2])
    _read_validity(fields[pos + 3], cert)
    cert.subject = parse_name(fields[pos + 4])
    cert.public_key = parse_public_key(fields[pos + 5])
    cert.parse_notes.extend(cert.public_key.notes)

    for extra in fields[pos + 6:]:
        if extra.is_ctx(3) and extra.children:
            for ext_node in extra.child(0).children:
                ext = _parse_extension(ext_node, cert)
                if ext is not None:
                    cert.extensions.append(ext)
        elif extra.is_ctx(1):
            cert.parse_notes.append(
                "this certificate carries an issuerUniqueID, a v2 field no "
                "modern profile uses")
        elif extra.is_ctx(2):
            cert.parse_notes.append(
                "this certificate carries a subjectUniqueID, a v2 field no "
                "modern profile uses")

    _consistency_notes(cert)
    return cert


def _serial_hex(serial: int) -> str:
    if serial == 0:
        return "00"
    magnitude = abs(serial)
    width = (magnitude.bit_length() + 7) // 8
    body = hex_bytes(magnitude.to_bytes(width, "big"))
    return f"-{body}" if serial < 0 else body


def _read_validity(node: Node, cert: Certificate) -> None:
    """``Validity ::= SEQUENCE { notBefore Time, notAfter Time }``."""
    if not node.is_tag(SEQUENCE) or len(node.children) < 2:
        cert.parse_notes.append("the validity field is not a pair of times")
        return
    for which, kid in (("not_before", node.child(0)), ("not_after", node.child(1))):
        try:
            setattr(cert, which, decode_time(kid))
        except (Asn1Error, ValueError) as exc:
            cert.parse_notes.append(
                f"{which.replace('_', '')} did not read as a time ({exc})")
        else:
            # RFC 5280 pins the encoding by date; a certificate that gets it
            # wrong still parses, but the mismatch is worth saying out loud.
            stamp: datetime | None = getattr(cert, which)
            if stamp is not None:
                if stamp.year >= 2050 and kid.is_tag(23):
                    cert.parse_notes.append(
                        f"{which.replace('_', '')} is in 2050 or later but is "
                        f"encoded as UTCTime, which cannot express it")
                elif stamp.year < 2050 and kid.is_tag(24):
                    cert.parse_notes.append(
                        f"{which.replace('_', '')} is before 2050 but is "
                        f"encoded as GeneralizedTime; RFC 5280 asks for UTCTime")


def _consistency_notes(cert: Certificate) -> None:
    """Internal disagreements that are facts, not judgements."""
    if (cert.tbs_signature_algorithm_oid and cert.signature_algorithm_oid
            and cert.tbs_signature_algorithm_oid != cert.signature_algorithm_oid):
        cert.parse_notes.append(
            "the signature algorithm named inside the signed body "
            f"({oids.name_of(cert.tbs_signature_algorithm_oid)}) differs from "
            f"the one named outside it ({cert.signature_algorithm})")
    if cert.extensions and cert.version < 3:
        cert.parse_notes.append(
            f"extensions are present but the version field says v{cert.version}; "
            "extensions require v3")
    if cert.serial < 0:
        cert.parse_notes.append(
            "the serial number is negative; RFC 5280 requires a positive integer")
    seen: set[str] = set()
    for ext in cert.extensions:
        if ext.oid in seen:
            cert.parse_notes.append(
                f"the extension {ext.display} appears more than once, which "
                "RFC 5280 forbids")
        seen.add(ext.oid)
