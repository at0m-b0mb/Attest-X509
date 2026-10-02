<div align="center">

<img src="images/mark-180.png" width="88" alt="">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/banner-dark.png">
  <img src="images/banner.png" alt="Attest — read the certificate" width="100%">
</picture>

<br>

**An offline X.509 reader that walks the DER by hand, names every field in
plain words, draws a pasted chain as a ladder so you can see whether it
actually joins, and grades what it finds — while verifying no signature,
checking no revocation, and consulting no trust store.**

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-7A5D18?style=flat-square)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-7A5D18?style=flat-square)
![Offline](https://img.shields.io/badge/network-never-2C6249?style=flat-square)
![Tests](https://img.shields.io/badge/tests-436%20passing-2C6249?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-6B6554?style=flat-square)

**[Attest project site](https://at0m-b0mb.github.io/Attest-X509/)**

</div>

---

## Why

Nobody reads the certificate. The padlock appears or it does not, and when it
does not, the browser offers four words — *unable to get local issuer* — about a
document the server already handed you, in a format you can open.

Attest opens it. Paste a PEM block, or a whole bundle, and it names the subject
and issuer distinguished names attribute by attribute, every subjectAltName
entry, the serial, the key identifiers, the SHA-256 fingerprint, the signature
algorithm, and the key's real size — the RSA modulus read as a bit length, so a
2047-bit key is reported as 2047 and not rounded up to 2048.

Then it draws the chain as a ladder: one rung per certificate, root at the top,
and between two rungs the join — solid gold when the child's issuer name matches
the parent's subject name, dashed red when it does not. That picture answers the
question underneath most TLS misconfigurations, which is whether the file you
have is a chain at all. Colour on a rung is the grade, not decoration: the
spine, the role marker and each badge carry the worst finding that applies to
them, so a 1024-bit modulus arrives in red beside a sound certificate still in
gold. An F cannot be drawn looking like an A+.

Last comes the letter, A+ to F, and every finding that built it.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/screens-dark.png">
  <img src="images/screens.png" alt="A self-signed SHA-1 certificate graded F, and a complete three-certificate chain graded A+" width="100%">
</picture>
<br>
<sub>A self-signed appliance certificate — SHA-1 over a 1024-bit key — graded
<b>F, 13/100</b>; beside a three-certificate chain that joins all the way to its
own root, graded <b>A+, 100/100</b>.</sub>
</div>

## The honest part

Attest reads bytes. That is all it does, and all it claims.

It verifies **no signature** — it reports the algorithm a certificate names and
does no public-key arithmetic. It checks **no revocation**: no CRL, no OCSP, no
network. It consults **no trust store**, so a "self-signed root" here means a
certificate whose issuer name equals its subject name, not one your system
trusts. And it cannot tell you whether a live server still holds the matching
private key. A matched join is a match of *names*; the ladder refuses to draw a
tick, and the window carries a legend saying why.

So a high grade means the certificate is well-formed and uses sound parameters,
never that a connection using it is trustworthy. The words "safe", "secure",
"trusted" and "verified" never appear as a verdict, and a test over every sample
enforces that.

The same line shapes the grader. **A+ is reserved** for a complete chain —
every link joining, ending in a self-signed certificate — with nothing above an
informational note. **Unknown beats a guess:** a lone certificate says nothing
about the chain above it, so it is capped at **B+** and labelled *chain unknown*;
an algorithm or curve that is not in the table caps the grade at **C** instead
of being assumed strong; a broken join caps it at **D**, because the bundle is
not a chain. And every penalty is a property of the certificate itself — an
elapsed date, a 1024-bit modulus, an absent subjectAltName — never a list of
issuers Attest likes.

There is no certificate library underneath this. `attest/core/asn1.py` is a DER
tag/length/value walker written for this tool, and `attest/core/certificate.py`
walks the RFC 5280 `Certificate` structure on top of it. Attest needs no
cryptography dependency because it performs no cryptography.

## Install

```bash
git clone https://github.com/at0m-b0mb/Attest-X509.git
cd Attest-X509
python3 -m pip install -r requirements.txt   # just PyQt6, for the window
python3 -m pip install .                     # optional: puts `attest` on PATH
```

The engine and the command line need **no dependencies at all** — the standard
library, including the DER parser. PyQt6 is required only for the window. Skip
the last line and run everything as `python3 -m attest` from the checkout.

## Use

**The window:**

```bash
python3 -m attest          # or:  python3 run.py
```

Paste a certificate, open a `.pem` / `.crt` / `.der`, or load one of the five
bundled samples. Light, Dark and Auto are in the top-right.

**The command line** — same engine, no Qt, pipe-friendly:

```bash
python3 -m attest samples/broken-chain.pem     # always works, no install
attest chain.pem --json                        # machine-readable
cat cert.pem | attest -                        # from a pipe

# the pipe does the networking; Attest never does
openssl s_client -connect example.com:443 -showcerts </dev/null | attest -
```

```
  D   The certificates given do not join into a chain  (70/100)
  Attest reads the certificate you pasted. It does not verify any signature,
  does not check revocation (CRL or OCSP), does not consult a trust store…

LEAF  shop.northwind.example
  subject     C=GB, ST=Greater London, O=Northwind Retail Ltd, CN=shop.northwind.example
  issuer      C=GB, O=Example Trust Services, CN=Example Trust Issuing CA 2
  validity    2026-09-15 → 2027-10-10  372 days left
  key         EC prime256v1 (P-256)
  signature   ecdsa-with-SHA256

SELF-SIGNED ROOT  Zephyr PKI Root CA
  subject     C=NL, O=Zephyr PKI B.V., CN=Zephyr PKI Root CA
  issuer      C=NL, O=Zephyr PKI B.V., CN=Zephyr PKI Root CA  (self-signed)
  key         RSA 4096-bit
  signature   sha256WithRSAEncryption

Chain (1 join)
  shop.northwind.example -/- Zephyr PKI Root CA   ISSUER MISMATCH
  chain: does not end in a self-signed root

Findings (14)
  [ alert ] Link 1 is broken -30
          The leaf says it was issued by "C=GB, O=Example Trust Services, CN=Example
          Trust Issuing CA 2", but the next certificate in the file is "C=NL,
          O=Zephyr PKI B.V., CN=Zephyr PKI Root CA". These two do not join, so the
          bundle is not a chain as it stands.
```

The exit code answers *did a certificate come out of this?*, so a shell can
branch on it: `0` when at least one was read, `1` when nothing in the input
parsed as a certificate, `2` when the input could not be read at all. The grade
stays in the output — what is good enough to deploy is not Attest's call.

## What it checks

Attest starts at 100 and subtracts for what it finds. There are 53 findings
across seven families, each written so you can act on it:

| Family | What trips it |
|---|---|
| **Validity** | expired, not yet valid, under 30 days left, or over 398 days for an end-entity certificate |
| **Signature** | MD5, MD4, MD2 — collisions are cheap; SHA-1 — collisions are demonstrated, and browsers stopped accepting it in 2017 |
| **Key** | RSA under 2048 bits, a curve under P-256, a public exponent under 65537, DSA |
| **Identity** | no subjectAltName, an empty one, a commonName absent from it, a wildcard |
| **Constraints** | CA:TRUE in a leaf's position, a non-critical CA declaration, keyCertSign against CA:FALSE, no keyUsage or extendedKeyUsage |
| **Format** | X.509 v1, a duplicated extension, a version that contradicts its extensions, a negative serial |
| **Chain** | names that do not join, key identifiers that disagree where the names agree, an issuer not marked as a CA, a chain stopping short of a root |

A `GOOD` or `INFO` finding costs nothing — it is there so the report says what is
right as well as what is wrong. Findings sort most-severe first, with the points
each one cost, so the reasoning behind the letter stays on screen.

The parser is strict where leniency would be a lie. The indefinite-length form
is refused by name — that is BER, and DER forbids it. A length past the end of
the buffer is an error, not a truncation. Trailing bytes after a complete value
are reported, not dropped. An OID outside the table of 19 signature algorithms,
11 curves and 22 extensions comes back in dotted form rather than guessed at.
The samples are built by `tools/gen_samples.py`, which encodes real DER by hand,
so the fixtures the tests assert against are genuine X.509 structures — walked
exactly as one off a live server would be, not mocks standing in for them.

## Privacy

Attest never touches the network. It opens no sockets, resolves no names and
sends nothing anywhere; the whole analysis is the standard library reading bytes
you already have. A certificate you paste stays on your machine. It also has no
use for a private key, and says so if you paste one.

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

436 tests cover the DER walker and every malformed shape it must refuse, the OID
table, the PEM extractor, the certificate parser against hand-built DER, the
grading pipeline and its ceilings, the CLI's text, JSON and exit codes, and the
ladder painted off-screen in both themes — including an assertion on the pixels
that an F certificate's rung does not come out the colour of an A+ one. As the
house style demands, a contrast suite holds every text colour to WCAG AA in both
themes, so the palette cannot quietly regress.

## Layout

```
attest/
  core/              the engine — pure standard library, no Qt
    asn1.py            a DER tag/length/value walker, written for this
    oids.py            the dictionary: algorithms, curves, RDNs, extensions
    model.py           the dataclasses everything speaks in
    pem.py             a paste  ->  the DER blocks inside it
    certificate.py     DER  ->  a structured Certificate
    grade.py           findings, the chain, and the letter with its ceiling
  ui/                the window
    theme.py           the design system: one place for every token
    chain.py           the chain ladder — Attest's signature element,
                       tinted by the worst finding on each rung
    widgets.py         cards, chips, key/value rows
    main_window.py     the reader itself
  cli.py             the same engine on the command line
  app.py             the Qt entry point
  __main__.py        python3 -m attest — the window, or the CLI if given a file
samples/           five certificates: a modern chain, a mismatched bundle,
                   an expired leaf, a CN-only leaf, a SHA-1 relic
tests/             436 tests, including the contrast suite
tools/             gen_samples.py, capture_screenshots.py, brandkit.py
images/            marks, banners, screenshots, social card
run.py             python3 run.py  ==  python3 -m attest
```

## Colophon

Three typefaces do the work: **Iowan Old Style** carries the identity and the
figures, the system **sans** carries anything you read at length, and a **mono**
carries raw bytes and distinguished names. A serif/sans/mono mix reads as
authored rather than assembled. The palette is warm paper and two golds — a deep
brass that survives being set at small sizes, and a brighter shine reserved for
marks that carry no words. Dark mode is true black, `#000000`, with nothing in
the grey ramp that drifts towards blue. Colours are declared as light/dark pairs
at the point of definition, so there is no way to add one and forget the other
theme.

## License

MIT — see [LICENSE](LICENSE). For authorised, educational and personal use:
Attest is a reader, not a certificate authority.
