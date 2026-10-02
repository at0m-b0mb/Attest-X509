"""
Attest on the command line.

The same engine the window uses, with no Qt in sight — so it runs on a server,
in a pipe, or inside another script. Point it at a ``.pem``/``.crt``/``.der``
file or pipe PEM into standard input; add ``--json`` for machine-readable
output.

    attest server.pem
    openssl s_client -connect example.com:443 -showcerts </dev/null | attest -
    attest chain.pem --json

The pipe in the middle of that second line is doing the networking. Attest
never does: it reads whatever bytes arrive on stdin and nothing else.

The exit code answers one question — *did a certificate come out of this?* —
so that ``attest server.pem && deploy`` means something:

``0``
    At least one certificate was read. The grade is in the output, not in the
    exit code: Attest reports, and what counts as good enough to deploy is not
    its call to make.
``1``
    Nothing in the input parsed as a certificate. The report still prints, and
    says why.
``2``
    The input could not be read at all — no such file, or nothing on stdin.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core.grade import analyze, plural
from .core.model import Bundle

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "good": "\033[32m", "notice": "\033[33m", "warning": "\033[33m",
    "alert": "\033[31m", "info": "\033[90m", "brass": "\033[33m",
}


def _paint(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_C.get(key, '')}{text}{_C['reset']}"


def _wrap(text: str, width: int = 74, indent: str = "          ") -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(indent + current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(indent + current)
    return lines


def _report_text(bundle: Bundle, color: bool) -> str:
    grade = bundle.grade
    out: list[str] = []
    out.append(_paint(f"  {grade.letter}  ", "bold", color)
               + f" {grade.headline}  "
               + _paint(f"({grade.score}/100)", "dim", color))
    for line in _wrap(grade.ceiling_note, indent="  "):
        out.append(_paint(line, "dim", color))
    out.append("")

    for cert in bundle.certificates:
        tag = cert.role.marker
        out.append(_paint(f"{tag}", "brass", color)
                   + f"  {cert.subject.label}")
        out.append(f"  subject     {cert.subject.rendered}")
        out.append(f"  issuer      {cert.issuer.rendered}"
                   + (_paint("  (self-signed)", "dim", color)
                      if cert.is_self_signed else ""))
        out.append(f"  serial      {cert.serial_hex}")
        if cert.not_before and cert.not_after:
            days = cert.days_until_expiry(bundle.now)
            state = (f"{plural(days or 0, 'day')} left"
                     if cert.is_current(bundle.now)
                     else f"EXPIRED {plural(abs(days or 0), 'day')} ago"
                     if cert.is_expired(bundle.now) else "NOT YET VALID")
            key = "good" if cert.is_current(bundle.now) else "alert"
            out.append(f"  validity    {cert.not_before:%Y-%m-%d} → "
                       f"{cert.not_after:%Y-%m-%d}  "
                       + _paint(state, key, color))
        out.append(f"  key         {cert.public_key.summary}")
        out.append(f"  signature   {cert.signature_algorithm}")
        names = ", ".join(cert.san.all_names) if cert.san.present else "(none)"
        out.append(f"  alt names   {names}")
        out.append(f"  constraints {cert.basic_constraints.summary}")
        if cert.key_usage_present:
            out.append(f"  key usage   {', '.join(cert.key_usage)}")
        if cert.ext_key_usage_present:
            out.append(f"  issued for  {', '.join(cert.ext_key_usage)}")
        out.append(f"  sha256      {cert.fingerprint_sha256}")
        out.append("")

    if bundle.links:
        out.append(f"Chain ({plural(len(bundle.links), 'join')})")
        for link in bundle.links:
            child = bundle.certificates[link.child_index]
            parent = bundle.certificates[link.parent_index]
            key = "good" if link.matched else "alert"
            glyph = "---" if link.matched else "-/-"
            out.append(f"  {child.subject.label} "
                       + _paint(glyph, key, color)
                       + f" {parent.subject.label}   "
                       + _paint(link.verdict, key, color))
        state = ("complete as given" if bundle.chain_complete
                 else "does not end in a self-signed root")
        out.append(_paint(f"  chain: {state}", "dim", color))
        out.append("")

    out.append(f"Findings ({len(bundle.findings)})")
    for finding in bundle.findings:
        key = finding.severity.value
        tag = _paint(f"[{finding.severity.value:^7}]", key, color)
        points = _paint(f" -{finding.points}", "dim", color) if finding.points else ""
        where = (f" (cert {finding.cert_index + 1})"
                 if finding.cert_index is not None and bundle.count > 1 else "")
        out.append(f"  {tag} {finding.title}{where}{points}")
        for line in _wrap(finding.detail):
            out.append(_paint(line, "dim", color))
    for note in bundle.parse_notes:
        out.append(_paint(f"  note: {note}", "dim", color))
    return "\n".join(out)


def _report_json(bundle: Bundle) -> str:
    def name(value):
        return {
            "rendered": value.rendered,
            "common_name": value.common_name,
            "organization": value.organization,
            "attributes": [
                {"oid": a.oid, "label": a.label, "name": a.long_name,
                 "value": a.value}
                for a in value.attributes
            ],
        }

    data = {
        "grade": {
            "letter": bundle.grade.letter,
            "score": bundle.grade.score,
            "headline": bundle.grade.headline,
            "ceiling_note": bundle.grade.ceiling_note,
        },
        "read_at": bundle.now.isoformat(),
        "blocks_found": bundle.blocks_found,
        "blocks_failed": bundle.blocks_failed,
        "chain_complete": bundle.chain_complete,
        "certificates": [
            {
                "index": c.index,
                "role": c.role.value,
                "version": c.version,
                "serial": c.serial_hex,
                "subject": name(c.subject),
                "issuer": name(c.issuer),
                "self_signed": c.is_self_signed,
                "not_before": c.not_before.isoformat() if c.not_before else None,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "validity_days": c.validity_days,
                "days_until_expiry": c.days_until_expiry(bundle.now),
                "expired": c.is_expired(bundle.now),
                "not_yet_valid": c.is_not_yet_valid(bundle.now),
                "signature_algorithm": {
                    "oid": c.signature_algorithm_oid,
                    "name": c.signature_algorithm,
                },
                "public_key": {
                    "algorithm_oid": c.public_key.algorithm_oid,
                    "algorithm": c.public_key.algorithm,
                    "kind": c.public_key.kind,
                    "summary": c.public_key.summary,
                    "rsa_modulus_bits": c.public_key.rsa_modulus_bits,
                    "rsa_exponent": c.public_key.rsa_exponent,
                    "curve": c.public_key.curve or None,
                    "curve_oid": c.public_key.curve_oid or None,
                    "curve_bits": c.public_key.curve_bits,
                },
                "subject_alt_name": {
                    "present": c.san.present,
                    "dns": c.san.dns_names,
                    "ip": c.san.ip_addresses,
                    "email": c.san.emails,
                    "uri": c.san.uris,
                    "other": c.san.other,
                    "wildcards": c.san.wildcards,
                },
                "basic_constraints": {
                    "present": c.basic_constraints.present,
                    "critical": c.basic_constraints.critical,
                    "ca": c.basic_constraints.ca,
                    "path_len": c.basic_constraints.path_len,
                },
                "key_usage": c.key_usage,
                "key_usage_present": c.key_usage_present,
                "ext_key_usage": c.ext_key_usage,
                "ext_key_usage_present": c.ext_key_usage_present,
                "subject_key_id": c.subject_key_id or None,
                "authority_key_id": c.authority_key_id or None,
                "fingerprint_sha256": c.fingerprint_sha256,
                "der_length": c.der_length,
                "extensions": [
                    {"oid": e.oid, "name": e.name, "critical": e.critical,
                     "known": e.known, "summary": e.summary}
                    for e in c.extensions
                ],
                "parse_notes": c.parse_notes,
            }
            for c in bundle.certificates
        ],
        "links": [
            {"child": link.child_index, "parent": link.parent_index,
             "matched": link.matched, "child_issuer": link.child_issuer,
             "parent_subject": link.parent_subject}
            for link in bundle.links
        ],
        "findings": [
            {"severity": f.severity.value, "title": f.title, "detail": f.detail,
             "points": f.points, "category": f.category,
             "certificate": f.cert_index}
            for f in bundle.findings
        ],
        "parse_notes": bundle.parse_notes,
    }
    return json.dumps(data, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attest",
        description="Read an X.509 certificate or chain and grade what it says.")
    parser.add_argument("source", nargs="?", default="-",
                        help="path to a .pem/.crt/.der file, or - for stdin")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--no-color", action="store_true",
                        help="plain text, no ANSI")
    parser.add_argument("--version", action="version",
                        version=f"attest {__version__}")
    args = parser.parse_args(argv)

    if args.source == "-":
        raw = sys.stdin.buffer.read()
    else:
        try:
            with open(args.source, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            print(f"attest: cannot read {args.source}: {exc}", file=sys.stderr)
            return 2

    if not raw.strip():
        print("attest: no certificate given", file=sys.stderr)
        return 2

    bundle = analyze(raw)
    if args.json:
        print(_report_json(bundle))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(_report_text(bundle, color))

    # The report is printed either way — a paste that held no certificate still
    # gets its F and its reason. The code is what a shell can branch on, and
    # "nothing parsed" has to be distinguishable from "read it".
    return 0 if bundle.certificates else 1


if __name__ == "__main__":
    raise SystemExit(main())
