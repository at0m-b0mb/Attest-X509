#!/usr/bin/env python3
"""
Write the synthetic sample certificates in ``samples/``.

There is no certificate library here and no key generation: this script encodes
DER by hand, tag by tag, so the files in ``samples/`` are *real* X.509
structures that Attest's own parser walks the same way it would walk a
certificate off a live server. That matters — a sample set made of mock objects
would prove nothing about the parser.

Every certificate here is fabricated. The "signatures" are deterministic filler
bytes, the RSA moduli are random odd integers of the right bit length, the EC
points are not on any curve, and no private key exists for any of them. They
authenticate nothing; they exist so that the reader has something honest to
read. Dates are anchored to a fixed reference so the files are reproducible and
the tests can grade them against a known clock.

    python3 tools/gen_samples.py
"""

from __future__ import annotations

import base64
import os
import random
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")

REF = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)


# --- DER encoding primitives -------------------------------------------------

def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def setof(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(parts))


def integer(value: int) -> bytes:
    if value == 0:
        return tlv(0x02, b"\x00")
    if value > 0:
        body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    else:
        # Two's complement, the width DER would choose.
        width = (value + 1).bit_length() // 8 + 1
        body = value.to_bytes(width, "big", signed=True)
    return tlv(0x02, body)


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    if len(arcs) < 2:
        raise ValueError(f"{dotted} is not an OID")
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunk))
    return tlv(0x06, bytes(body))


def null() -> bytes:
    return tlv(0x05, b"")


def boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xFF" if value else b"\x00")


def octet_string(data: bytes) -> bytes:
    return tlv(0x04, data)


def bit_string(data: bytes, unused: int = 0) -> bytes:
    return tlv(0x03, bytes([unused]) + data)


def printable(text: str) -> bytes:
    return tlv(0x13, text.encode("ascii"))


def utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode("utf-8"))


def ia5(text: str) -> bytes:
    return tlv(0x16, text.encode("ascii"))


def explicit(number: int, content: bytes) -> bytes:
    """``[number] EXPLICIT`` — a constructed context tag wrapping a value."""
    return tlv(0xA0 | number, content)


def implicit(number: int, content: bytes) -> bytes:
    """``[number] IMPLICIT`` over a primitive — the content octets, retagged."""
    return tlv(0x80 | number, content)


def utc_time(when: datetime) -> bytes:
    return tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def generalized_time(when: datetime) -> bytes:
    return tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def x509_time(when: datetime) -> bytes:
    """RFC 5280: UTCTime through 2049, GeneralizedTime from 2050."""
    return utc_time(when) if when.year < 2050 else generalized_time(when)


# --- X.509 building blocks ---------------------------------------------------

OID_RSA = "1.2.840.113549.1.1.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_SHA1_RSA = "1.2.840.113549.1.1.5"
OID_EC_PUBKEY = "1.2.840.10045.2.1"
OID_P256 = "1.2.840.10045.3.1.7"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

OID_CN, OID_O, OID_OU, OID_C, OID_ST, OID_L = (
    "2.5.4.3", "2.5.4.10", "2.5.4.11", "2.5.4.6", "2.5.4.8", "2.5.4.7")

OID_SKID = "2.5.29.14"
OID_KEY_USAGE = "2.5.29.15"
OID_SAN = "2.5.29.17"
OID_BASIC = "2.5.29.19"
OID_AKID = "2.5.29.35"
OID_EKU = "2.5.29.37"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

_STRING_FOR = {OID_C: printable, OID_CN: utf8, OID_O: utf8, OID_OU: utf8,
               OID_ST: utf8, OID_L: utf8}


def name(*pairs: tuple[str, str]) -> bytes:
    """``Name`` from (attribute OID, value) pairs, one RDN each."""
    return seq(*[
        setof(seq(oid(attr), _STRING_FOR.get(attr, utf8)(value)))
        for attr, value in pairs
    ])


def validity(not_before: datetime, not_after: datetime) -> bytes:
    return seq(x509_time(not_before), x509_time(not_after))


def alg_rsa(sig_oid: str) -> bytes:
    """An RSA AlgorithmIdentifier always carries an explicit NULL parameter."""
    return seq(oid(sig_oid), null())


def alg_ecdsa(sig_oid: str) -> bytes:
    """An ECDSA AlgorithmIdentifier carries no parameters at all."""
    return seq(oid(sig_oid))


def fake_modulus(bits: int, seed: int) -> int:
    """A deterministic odd integer of exactly *bits* bits.

    Not a product of two primes and never used for anything — the only property
    that matters here is that ``bit_length()`` comes back as *bits*, because
    that is the number Attest reports as the key size.
    """
    rng = random.Random(seed)
    value = rng.getrandbits(bits)
    value |= 1 << (bits - 1)   # exactly this many bits
    value |= 1                 # odd, as a modulus must be
    return value


def rsa_spki(bits: int, seed: int, exponent: int = 65537) -> bytes:
    inner = seq(integer(fake_modulus(bits, seed)), integer(exponent))
    return seq(alg_rsa(OID_RSA), bit_string(inner))


def ec_spki(curve_oid: str, field_bits: int, seed: int) -> bytes:
    size = (field_bits + 7) // 8
    rng = random.Random(seed)
    point = b"\x04" + bytes(rng.getrandbits(8) for _ in range(size * 2))
    return seq(seq(oid(OID_EC_PUBKEY), oid(curve_oid)), bit_string(point))


def key_id(seed: int, length: int = 20) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(length))


def extension(ext_oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = [oid(ext_oid)]
    if critical:
        parts.append(boolean(True))
    parts.append(octet_string(value))
    return seq(*parts)


def ext_basic_constraints(ca: bool, path_len: int | None = None,
                          critical: bool = True) -> bytes:
    parts: list[bytes] = []
    if ca:  # cA is DEFAULT FALSE, so FALSE is encoded by being absent
        parts.append(boolean(True))
    if path_len is not None:
        parts.append(integer(path_len))
    return extension(OID_BASIC, seq(*parts), critical)


def ext_key_usage(*names: str, critical: bool = True) -> bytes:
    from attest.core.oids import KEY_USAGE_BITS
    indices = [KEY_USAGE_BITS.index(n) for n in names]
    top = max(indices)
    width = top // 8 + 1
    data = bytearray(width)
    for index in indices:
        data[index // 8] |= 0x80 >> (index % 8)
    unused = (width * 8 - 1) - top
    return extension(OID_KEY_USAGE, bit_string(bytes(data), unused), critical)


def ext_ext_key_usage(*purpose_oids: str) -> bytes:
    return extension(OID_EKU, seq(*[oid(p) for p in purpose_oids]))


def ext_san(dns: list[str] | None = None, ips: list[str] | None = None,
            critical: bool = False) -> bytes:
    entries: list[bytes] = []
    for host in dns or []:
        entries.append(implicit(2, host.encode("ascii")))     # dNSName
    for address in ips or []:
        octets = bytes(int(part) for part in address.split("."))
        entries.append(implicit(7, octets))                   # iPAddress
    return extension(OID_SAN, seq(*entries), critical)


def ext_skid(data: bytes) -> bytes:
    return extension(OID_SKID, octet_string(data))


def ext_akid(data: bytes) -> bytes:
    return extension(OID_AKID, seq(implicit(0, data)))


def certificate(*, serial: int, sig_alg: bytes, issuer: bytes,
                not_before: datetime, not_after: datetime, subject: bytes,
                spki: bytes, extensions: list[bytes],
                signature_seed: int, version: int = 3) -> bytes:
    """Assemble a complete ``Certificate``.

    The signature is filler. The structure is not: this is the encoding a real
    certificate uses, which is why Attest's parser can read it.
    """
    tbs_parts = []
    if version != 1:
        tbs_parts.append(explicit(0, integer(version - 1)))
    tbs_parts += [
        integer(serial),
        sig_alg,                       # the inner copy, which must match
        issuer,
        validity(not_before, not_after),
        subject,
        spki,
    ]
    if extensions:
        tbs_parts.append(explicit(3, seq(*extensions)))
    tbs = seq(*tbs_parts)

    rng = random.Random(signature_seed)
    signature = bytes(rng.getrandbits(8) for _ in range(256))
    return seq(tbs, sig_alg, bit_string(signature))


def pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines)
            + "\n-----END CERTIFICATE-----\n")


# --- the cast ----------------------------------------------------------------

ROOT_NAME = name((OID_C, "GB"), (OID_O, "Example Trust Services"),
                 (OID_CN, "Example Trust Root R3"))
ICA_NAME = name((OID_C, "GB"), (OID_O, "Example Trust Services"),
                (OID_CN, "Example Trust Issuing CA 2"))
LEAF_NAME = name((OID_C, "GB"), (OID_ST, "Greater London"),
                 (OID_O, "Northwind Retail Ltd"),
                 (OID_CN, "shop.northwind.example"))

ROOT_KID = key_id(101)
ICA_KID = key_id(202)
LEAF_KID = key_id(303)


def build_root() -> bytes:
    return certificate(
        serial=0x5B1E_2C44_90A7_31F2,
        sig_alg=alg_rsa(OID_SHA256_RSA),
        issuer=ROOT_NAME,
        not_before=datetime(2020, 1, 15, tzinfo=timezone.utc),
        not_after=datetime(2045, 1, 14, tzinfo=timezone.utc),
        subject=ROOT_NAME,
        spki=rsa_spki(4096, seed=11),
        extensions=[
            ext_basic_constraints(ca=True),
            ext_key_usage("digitalSignature", "keyCertSign", "cRLSign"),
            ext_skid(ROOT_KID),
        ],
        signature_seed=1001,
    )


def build_intermediate() -> bytes:
    return certificate(
        serial=0x1C7A_3F08_B512_6D90,
        sig_alg=alg_rsa(OID_SHA256_RSA),
        issuer=ROOT_NAME,
        not_before=datetime(2024, 3, 1, tzinfo=timezone.utc),
        not_after=datetime(2034, 2, 28, tzinfo=timezone.utc),
        subject=ICA_NAME,
        spki=rsa_spki(3072, seed=22),
        extensions=[
            ext_basic_constraints(ca=True, path_len=0),
            ext_key_usage("digitalSignature", "keyCertSign", "cRLSign"),
            ext_skid(ICA_KID),
            ext_akid(ROOT_KID),
        ],
        signature_seed=1002,
    )


def build_modern_leaf() -> bytes:
    return certificate(
        serial=0x04D2_8E61_77BB_0C39,
        sig_alg=alg_ecdsa(OID_ECDSA_SHA256),
        issuer=ICA_NAME,
        not_before=datetime(2026, 9, 15, tzinfo=timezone.utc),
        not_after=datetime(2027, 10, 10, tzinfo=timezone.utc),   # 390 days
        subject=LEAF_NAME,
        spki=ec_spki(OID_P256, 256, seed=33),
        extensions=[
            ext_basic_constraints(ca=False),
            ext_key_usage("digitalSignature", "keyAgreement"),
            ext_ext_key_usage(OID_SERVER_AUTH, OID_CLIENT_AUTH),
            ext_san(dns=["shop.northwind.example", "www.northwind.example"]),
            ext_skid(LEAF_KID),
            ext_akid(ICA_KID),
        ],
        signature_seed=1003,
    )


def build_self_signed_sha1() -> bytes:
    """A 2011-era self-signed appliance certificate, still in service."""
    subject = name((OID_C, "US"), (OID_O, "Mallard Devices"),
                   (OID_OU, "IT"), (OID_CN, "nas01.mallard.example"))
    return certificate(
        serial=0x1F,
        sig_alg=alg_rsa(OID_SHA1_RSA),
        issuer=subject,
        not_before=datetime(2025, 4, 1, tzinfo=timezone.utc),
        not_after=datetime(2030, 3, 31, tzinfo=timezone.utc),    # 1824 days
        subject=subject,
        spki=rsa_spki(1024, seed=44),
        extensions=[
            ext_basic_constraints(ca=False),
            ext_key_usage("digitalSignature", "keyEncipherment"),
            ext_ext_key_usage(OID_SERVER_AUTH),
            ext_san(dns=["nas01.mallard.example"], ips=["192.168.1.40"]),
            ext_skid(key_id(404)),
        ],
        signature_seed=1004,
    )


def build_expired_leaf() -> bytes:
    subject = name((OID_C, "DE"), (OID_O, "Kestrel Logistics GmbH"),
                   (OID_CN, "portal.kestrel.example"))
    return certificate(
        serial=0x2A91_4C07_D3E8_1165,
        sig_alg=alg_rsa(OID_SHA256_RSA),
        issuer=ICA_NAME,
        not_before=datetime(2024, 2, 1, tzinfo=timezone.utc),
        not_after=datetime(2025, 2, 1, tzinfo=timezone.utc),
        subject=subject,
        spki=rsa_spki(2048, seed=55),
        extensions=[
            ext_basic_constraints(ca=False),
            ext_key_usage("digitalSignature", "keyEncipherment"),
            ext_ext_key_usage(OID_SERVER_AUTH),
            ext_san(dns=["portal.kestrel.example"]),
            ext_skid(key_id(505)),
            ext_akid(ICA_KID),
        ],
        signature_seed=1005,
    )


def build_no_san_leaf() -> bytes:
    """Modern in every respect but one: it names its host only in the CN."""
    subject = name((OID_C, "IN"), (OID_ST, "Maharashtra"),
                   (OID_O, "Peacock Analytics Pvt Ltd"),
                   (OID_CN, "reports.peacock.example"))
    return certificate(
        serial=0x66B0_12DD_4471_9E08,
        sig_alg=alg_rsa(OID_SHA256_RSA),
        issuer=ICA_NAME,
        not_before=datetime(2026, 6, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 5, 31, tzinfo=timezone.utc),
        subject=subject,
        spki=rsa_spki(2048, seed=66),
        extensions=[
            ext_basic_constraints(ca=False),
            ext_key_usage("digitalSignature", "keyEncipherment"),
            ext_ext_key_usage(OID_SERVER_AUTH),
            ext_skid(key_id(606)),
            ext_akid(ICA_KID),
        ],
        signature_seed=1006,
    )


def build_unrelated_root() -> bytes:
    """A perfectly good root — belonging to somebody else entirely."""
    subject = name((OID_C, "NL"), (OID_O, "Zephyr PKI B.V."),
                   (OID_CN, "Zephyr PKI Root CA"))
    return certificate(
        serial=0x77C3_90A1_55E2_30BB,
        sig_alg=alg_rsa(OID_SHA256_RSA),
        issuer=subject,
        not_before=datetime(2019, 6, 1, tzinfo=timezone.utc),
        not_after=datetime(2039, 5, 31, tzinfo=timezone.utc),
        subject=subject,
        spki=rsa_spki(4096, seed=77),
        extensions=[
            ext_basic_constraints(ca=True),
            ext_key_usage("digitalSignature", "keyCertSign", "cRLSign"),
            ext_skid(key_id(707)),
        ],
        signature_seed=1007,
    )


# --- the files ---------------------------------------------------------------

def samples() -> dict[str, str]:
    root = build_root()
    ica = build_intermediate()
    leaf = build_modern_leaf()
    return {
        # Leaf, intermediate, root — the order a TLS handshake sends them in.
        "modern-chain.pem": (
            "# A complete, modern chain: an ECDSA P-256 leaf under a 3072-bit\n"
            "# RSA issuing CA under a 4096-bit self-signed root. Synthetic;\n"
            "# the signatures are filler and no private key exists.\n"
            + pem(leaf) + pem(ica) + pem(root)),
        "broken-chain.pem": (
            "# The same leaf, bundled with a root it has nothing to do with —\n"
            "# the mistake behind most 'unable to get local issuer' errors.\n"
            + pem(leaf) + pem(build_unrelated_root())),
        "expired-leaf.pem": (
            "# A sound certificate whose date has simply run out.\n"
            + pem(build_expired_leaf())),
        "no-san-leaf.pem": (
            "# Names its host only in the commonName. Browsers stopped\n"
            "# reading the commonName for host matching in 2017.\n"
            + pem(build_no_san_leaf())),
        "self-signed-sha1.pem": (
            "# A self-signed appliance certificate of the old school:\n"
            "# SHA-1 over a 1024-bit RSA key, valid for five years.\n"
            + pem(build_self_signed_sha1())),
    }


def main() -> int:
    os.makedirs(SAMPLES, exist_ok=True)
    written = samples()
    for filename, text in sorted(written.items()):
        path = os.path.join(SAMPLES, filename)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"wrote samples/{filename}  ({len(text)} bytes)")

    # Prove they parse with Attest's own engine before claiming success.
    import sys
    sys.path.insert(0, ROOT)
    from attest.core.grade import analyze  # noqa: PLC0415

    print()
    for filename in sorted(written):
        with open(os.path.join(SAMPLES, filename), encoding="utf-8") as handle:
            bundle = analyze(handle.read(), now=REF)
        if not bundle.certificates:
            raise SystemExit(f"{filename} did not parse — refusing to ship it")
        print(f"  {filename:<22} {bundle.count} cert(s)  "
              f"grade {bundle.grade.letter:<2} ({bundle.grade.score}/100)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
