# Changelog

All notable changes to Attest are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] — 2026-10-02

First release.

### The reader
- A **DER parser written for this tool** (`attest.core.asn1`): a tag/length/value
  walker with decoders for integers, object identifiers, bit strings with named
  bits, the ten character-string types a distinguished name may use, and both
  `UTCTime` and `GeneralizedTime`. Strict where leniency would be a lie — the
  indefinite-length form is refused by name, an over-running length is an error,
  trailing bytes are reported rather than dropped.
- **Certificate parsing** to RFC 5280: version, serial, both signature
  algorithm identifiers, issuer and subject distinguished names attribute by
  attribute, the validity pair, and the subjectPublicKeyInfo — including the
  RSA modulus read as a bit length rather than a byte count, and the EC named
  curve read out of the algorithm parameters.
- **Extensions** — subjectAltName (DNS, IP, email, URI, directory names),
  basicConstraints, keyUsage, extendedKeyUsage, subjectKeyIdentifier,
  authorityKeyIdentifier, CRL distribution points, certificate policies and
  authority information access, each with its criticality; anything unrecognised
  is listed as unknown rather than guessed at.
- **The chain ladder** — the pasted certificates drawn root-first as rungs, each
  with its subject, its issuer, key and signature badges, and a validity bar
  with the present moment marked on it. Between rungs, the join: solid gold when
  the child's issuer name matches the parent's subject name, dashed red when it
  does not. A bundle written root-first is detected and reordered, with a note.
- **Findings** — validity (expired, not yet valid, expiring, longer than 398
  days), signature strength (MD5 and friends, SHA-1), key strength (RSA below
  2048, curves below P-256, small exponents, DSA), identity (no subjectAltName,
  an empty one, a commonName outside it, wildcards), constraints (CA:TRUE in a
  leaf's position, non-critical CA declarations, absent keyUsage or
  extendedKeyUsage), format (v1 certificates, duplicated extensions), and the
  chain itself, including key identifiers that disagree where the names agree.
- **Grade** — A+ to F, with an honesty ceiling: A+ is reserved for a complete,
  clean chain; a lone certificate is capped at B+ and labelled *chain unknown*;
  parameters Attest cannot name cap it at C; a broken join caps it at D. The
  words "safe", "secure" and "trusted" never appear as a verdict.

### Interfaces
- A PyQt6 window in the house style — warm paper and gold, true-black dark mode,
  and an Auto theme that follows the OS.
- A dependency-free command line sharing the same engine, with text and `--json`
  output, standard-input support, and PEM or raw-DER input.

### Engineering
- The engine (`attest.core`) is pure standard library — no third-party
  dependencies, no network, no sockets.
- `tools/gen_samples.py` encodes real DER by hand, so every sample and every
  test fixture is a genuine X.509 structure the parser walks the way it would
  walk one off a live server.
- 413 tests across the DER walker, the OID table, the PEM extractor, the
  certificate parser, the grading pipeline and its ceilings, the CLI's text and
  JSON output, the painted ladder rendered off-screen in both themes, and a
  WCAG-AA contrast suite covering every text/background pairing.
- Off-screen screenshot capture and a repository-art generator whose social card
  is held inside GitHub's safe border by a registered-rectangle check and a
  pixel measurement of the rendered PNG.
