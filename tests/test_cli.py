"""
The command line.

The CLI is the engine's second front door, so these tests drive it the way a
script would: through ``main`` with real argument lists, real files and real
stdin, checking the exit codes and that ``--json`` is actually machine-readable.
"""

import io
import json
import os
import sys

import pytest

from attest import cli
from conftest import SAMPLES_DIR


def _run(capsys, argv, stdin: bytes | None = None):
    if stdin is not None:
        holder = io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")
        real = sys.stdin
        sys.stdin = holder
        try:
            code = cli.main(argv)
        finally:
            sys.stdin = real
    else:
        code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def _sample(name: str) -> str:
    return os.path.join(SAMPLES_DIR, name)


# --- exit codes -------------------------------------------------------------

def test_reading_a_sample_succeeds(capsys):
    code, out, _ = _run(capsys, [_sample("modern-chain.pem"), "--no-color"])
    assert code == 0
    assert "A+" in out


def test_a_missing_file_exits_two(capsys):
    code, _, err = _run(capsys, ["/no/such/certificate.pem"])
    assert code == 2
    assert "cannot read" in err


def test_empty_stdin_exits_two(capsys):
    code, _, err = _run(capsys, ["-"], stdin=b"   \n\n")
    assert code == 2
    assert "no certificate given" in err


# A shell has to be able to branch on this: `attest cert.pem && deploy` is
# worthless if a file holding no certificate at all exits 0. The report still
# prints — the code says whether anything was read, not whether it was good.

def test_a_paste_with_no_certificate_exits_one(capsys):
    code, out, _ = _run(capsys, ["-", "--no-color"], stdin=b"hello")
    assert code == 1
    assert "No certificate found" in out


def test_a_truncated_pem_exits_one(capsys):
    broken = (b"-----BEGIN CERTIFICATE-----\n"
              b"MIIDdzCCAl+gAwIBAgIJAKZ\n")
    code, out, _ = _run(capsys, ["-", "--no-color"], stdin=broken)
    assert code == 1
    assert "F" in out


def test_a_pasted_private_key_exits_one_and_is_refused_by_name(capsys):
    key = (b"-----BEGIN PRIVATE KEY-----\n"
           b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==\n"
           b"-----END PRIVATE KEY-----\n")
    code, out, _ = _run(capsys, ["-", "--no-color"], stdin=key)
    assert code == 1
    # The distinctive phrase from the parse note, not the ceiling note — which
    # also says "private key" and would pass this on its own.
    assert "never wants a private key" in out


def test_a_bundle_that_reads_exits_zero_whatever_its_grade(capsys):
    """The exit code is "did it parse", not "did it pass"."""
    for name in ("self-signed-sha1.pem", "expired-leaf.pem"):
        code, out, _ = _run(capsys, [_sample(name), "--no-color"])
        assert code == 0, name
        assert out.strip()


def test_a_grade_of_f_on_a_real_certificate_is_not_an_error_code(capsys):
    code, out, _ = _run(capsys, [_sample("self-signed-sha1.pem"), "--no-color"])
    assert code == 0
    assert out.lstrip().startswith("F")


# --- --version --------------------------------------------------------------

def test_version_prints_the_package_version(capsys):
    import attest

    with pytest.raises(SystemExit) as exit_info:
        _run(capsys, ["--version"])
    assert exit_info.value.code == 0
    out, err = capsys.readouterr()
    assert attest.__version__ in (out + err)
    assert "attest" in (out + err)


# --- stdin ------------------------------------------------------------------

def test_a_chain_arrives_through_a_pipe(capsys):
    with open(_sample("modern-chain.pem"), "rb") as handle:
        raw = handle.read()
    code, out, _ = _run(capsys, ["-", "--no-color"], stdin=raw)
    assert code == 0
    assert "SELF-SIGNED ROOT" in out
    assert "issuer matches" in out


# --- text output ------------------------------------------------------------

def test_the_text_report_names_the_fields_a_reader_needs(capsys):
    _, out, _ = _run(capsys, [_sample("modern-chain.pem"), "--no-color"])
    for line in ("subject", "issuer", "serial", "validity", "key",
                 "signature", "alt names", "constraints", "sha256"):
        assert line in out, line


def test_the_text_report_carries_the_ceiling_note(capsys):
    _, out, _ = _run(capsys, [_sample("no-san-leaf.pem"), "--no-color"])
    assert "does not verify any signature" in out
    assert "trust store" in out


def test_no_color_leaves_no_escape_sequences(capsys):
    _, out, _ = _run(capsys, [_sample("broken-chain.pem"), "--no-color"])
    assert "\033[" not in out


def test_an_expired_certificate_is_shouted_about(capsys):
    _, out, _ = _run(capsys, [_sample("expired-leaf.pem"), "--no-color"])
    assert "EXPIRED" in out


def test_a_broken_chain_shows_the_mismatch(capsys):
    _, out, _ = _run(capsys, [_sample("broken-chain.pem"), "--no-color"])
    assert "ISSUER MISMATCH" in out
    assert "-/-" in out


# --- json output ------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "modern-chain.pem", "broken-chain.pem", "expired-leaf.pem",
    "no-san-leaf.pem", "self-signed-sha1.pem"])
def test_json_is_valid_json_for_every_sample(capsys, name):
    code, out, _ = _run(capsys, [_sample(name), "--json"])
    assert code == 0
    json.loads(out)


def test_json_carries_the_grade_and_the_ceiling_note(capsys):
    _, out, _ = _run(capsys, [_sample("modern-chain.pem"), "--json"])
    data = json.loads(out)
    assert data["grade"]["letter"] == "A+"
    assert 0 <= data["grade"]["score"] <= 100
    assert "trust store" in data["grade"]["ceiling_note"]


def test_json_describes_every_certificate_and_link(capsys):
    _, out, _ = _run(capsys, [_sample("modern-chain.pem"), "--json"])
    data = json.loads(out)
    assert len(data["certificates"]) == 3
    assert len(data["links"]) == 2
    assert data["chain_complete"] is True
    roles = [c["role"] for c in data["certificates"]]
    assert roles == ["leaf", "intermediate", "root"]


def test_json_key_details_are_structured_not_prose(capsys):
    _, out, _ = _run(capsys, [_sample("modern-chain.pem"), "--json"])
    leaf = json.loads(out)["certificates"][0]
    assert leaf["public_key"]["kind"] == "EC"
    assert leaf["public_key"]["curve"] == "prime256v1"
    assert leaf["public_key"]["curve_bits"] == 256
    assert leaf["subject"]["common_name"] == "shop.northwind.example"
    assert leaf["subject_alt_name"]["dns"] == [
        "shop.northwind.example", "www.northwind.example"]
    assert leaf["basic_constraints"]["ca"] is False
    assert leaf["key_usage"] == ["digitalSignature", "keyAgreement"]


def test_json_findings_keep_their_severity_and_points(capsys):
    _, out, _ = _run(capsys, [_sample("self-signed-sha1.pem"), "--json"])
    findings = json.loads(out)["findings"]
    assert findings
    severities = {f["severity"] for f in findings}
    assert severities <= {"good", "info", "notice", "warning", "alert"}
    assert any(f["severity"] == "alert" and f["points"] > 0 for f in findings)


def test_json_reports_a_broken_link_as_false(capsys):
    _, out, _ = _run(capsys, [_sample("broken-chain.pem"), "--json"])
    data = json.loads(out)
    assert data["links"][0]["matched"] is False
    assert data["chain_complete"] is False


# --- module entry point -----------------------------------------------------

def test_module_main_routes_arguments_to_the_cli(capsys):
    from attest.__main__ import main as module_main

    argv = sys.argv
    sys.argv = ["attest", _sample("no-san-leaf.pem"), "--no-color"]
    try:
        code = module_main()
    finally:
        sys.argv = argv
    out, _ = capsys.readouterr()
    assert code == 0
    assert "No subjectAltName" in out


def test_the_package_declares_a_version():
    import attest

    assert attest.__version__.count(".") == 2
