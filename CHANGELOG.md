# Changelog

All notable changes to Attest are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.1.0] — 2026-10-02

A review found the signature element was not doing its job, and a handful of
smaller gaps alongside it.

### Fixed
- **The chain ladder was colour-blind to cryptography.** The spine and the role
  marker were tinted only by whether a certificate was inside its validity
  window, and every badge got the same gold wash whatever it said — so
  `samples/self-signed-sha1.pem`, graded **F 13/100** for SHA-1 over a
  1024-bit key, rendered with a gold spine and badges whose pixels were
  identical to the A+ chain's `RSA-4096` / `SHA-256`. The spine, the role
  marker and each badge now carry the worst finding that actually applies to
  them: the key badge answers to the `key` findings, the signature badge to
  the `algorithm` findings, and the spine to the worst finding on that
  certificate of any kind. Gold while nothing worse than a note was found,
  amber for a real weakness, red for a serious one. The validity bar is
  deliberately unchanged — it is the one thing on a rung that *is* about dates.
  The window now carries a legend saying so, and a test asserts the painted
  pixels differ between a weak certificate and a sound one, in both themes.
- **The command line exited `0` when nothing parsed**, so `attest cert.pem &&
  deploy` could not tell a certificate from a file that held none. It now
  exits `1` when no certificate was read, `2` when the input could not be read
  at all, and `0` otherwise — the grade stays in the output, not the exit code.
- **`--version`** was missing despite a declared release version.
- Two docstrings copied from a sibling project still named that project and its
  domain; they now describe this one.
- Screenshot capture covered only some samples in both themes. The shot list is
  now derived from `samples/` rather than hand-written, so a sample cannot be
  left out, and a test asserts every sample is captured in both themes.

### Changed
- The README contact sheet now pairs a certificate whose own parameters are the
  problem (`self-signed-sha1`, F) with a chain that joins all the way to its
  root (`modern-chain`, A+), because the two all-gold ladders it held before
  showed neither.
- The README documents the exit codes, and its Install block now includes the
  `pip install .` that actually puts `attest` on the PATH.
- 436 tests, up from 413. Eighteen of the twenty-three new ones are regression
  tests that were run against the old code and watched to fail first — as was
  the one existing test that had asserted the wrong exit code. The other five
  are guards against over-correcting: that a real certificate graded F still
  exits `0`, and that the grader is never silent about a key or an algorithm,
  since a badge with nothing to colour by falls back to gold.

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
