"""
The window.

Left: the PEM you pasted, opened from a file, or loaded from a sample. Right:
the reading — a grade with its ceiling note, the chain drawn as a ladder, one
card per certificate with every field the parser recovered, and every finding
in plain words. The window holds the current bundle and re-renders the whole
right side on a theme change, so the chips and the painted ladder always match
the active palette.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core.grade import analyze, plural
from ..core.model import Bundle, Certificate, Role, Severity
from . import theme
from .chain import ChainLadder
from .widgets import Card, Chip, hrule, key_value, label, mini_label

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

_SEV_TOKEN = {
    Severity.GOOD: "sev_good",
    Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice",
    Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}

_PLACEHOLDER = (
    "Attest reads an X.509 certificate the way a browser does not: field by "
    "field, in words. Paste a PEM block — or a whole chain — and it will tell "
    "you who the certificate names, when it stops being valid, what key and "
    "signature algorithm it rests on, and whether the certificates above it "
    "actually join. It verifies no signature and consults no trust store, so "
    "it never calls anything safe."
)


# A hex fingerprint is one unbroken "word" as far as a word-wrapping label is
# concerned, so a 95-character one would set the minimum width of the entire
# report and push every card off the edge of the pane. A zero-width space after
# each colon gives the layout somewhere to break without changing what is
# selected or copied out.
_ZWSP = "\u200B"


def breakable(text: str) -> str:
    """Let a long colon-separated run wrap, without altering its characters."""
    return text.replace(":", ":" + _ZWSP) if text.count(":") > 4 else text


class MainWindow(QWidget):
    def __init__(self, mode: str = theme.AUTO):
        super().__init__()
        self._mode_choice = mode
        self._mode = theme.resolve(mode)
        self._bundle: Bundle | None = None
        # Pinned by tools/capture_screenshots.py so the committed art is
        # byte-reproducible; None means read the real clock.
        self.fixed_now = None

        self.setWindowTitle("Attest")
        self.resize(1180, 800)
        self._build()
        self._apply_theme()

    # --- construction -------------------------------------------------------
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_source_pane())
        split.addWidget(self._build_report_pane())
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 6)
        split.setSizes([420, 740])

        host = QWidget()
        host.setObjectName("PageHost")
        host_lay = QVBoxLayout(host)
        host_lay.setContentsMargins(16, 12, 16, 16)
        host_lay.addWidget(split)
        root.addWidget(host, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Rail")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)

        mark = QLabel("ATTEST")
        mark.setObjectName("Wordmark")
        sub = QLabel("read the certificate")
        sub.setObjectName("WordmarkSub")
        wordmark = QVBoxLayout()
        wordmark.setSpacing(0)
        wordmark.addWidget(mark)
        wordmark.addWidget(sub)
        lay.addLayout(wordmark)
        lay.addStretch(1)

        lay.addWidget(mini_label("THEME"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Auto", "Light", "Dark"])
        self.theme_box.setCurrentText(self._mode_choice.capitalize())
        self.theme_box.setFixedWidth(110)
        self.theme_box.currentTextChanged.connect(self._on_theme_changed)
        lay.addWidget(self.theme_box)
        return bar

    def _build_source_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(label("Paste a certificate", "PageTitle"))
        lay.addWidget(label(
            "One PEM block or a whole chain, leaf first. Anything else in the "
            "paste is ignored, and a private key is never wanted here.",
            "PageIntro"))

        self.source = QPlainTextEdit()
        self.source.setObjectName("Mono")
        self.source.setPlaceholderText(
            "-----BEGIN CERTIFICATE-----\nMIIDd... \n-----END CERTIFICATE-----")
        lay.addWidget(self.source, 1)

        row = QHBoxLayout()
        read_btn = QPushButton("Read")
        read_btn.setObjectName("Primary")
        read_btn.clicked.connect(self._on_read)
        row.addWidget(read_btn)

        open_btn = QPushButton("Open file…")
        open_btn.clicked.connect(self._on_open)
        row.addWidget(open_btn)

        self.sample_btn = QPushButton("Load sample")
        self._build_sample_menu()
        row.addWidget(self.sample_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("Quiet")
        clear_btn.clicked.connect(self._on_clear)
        row.addWidget(clear_btn)
        row.addStretch(1)
        lay.addLayout(row)
        return pane

    def _build_sample_menu(self) -> None:
        menu = QMenu(self)
        try:
            names = sorted(f for f in os.listdir(_SAMPLES_DIR)
                           if f.endswith((".pem", ".crt", ".cer")))
        except OSError:
            names = []
        if not names:
            action = QAction("(no samples found)", self)
            action.setEnabled(False)
            menu.addAction(action)
        for name in names:
            pretty = os.path.splitext(name)[0].replace("-", " ").title()
            action = QAction(pretty, self)
            action.triggered.connect(lambda _=False, n=name: self._load_sample(n))
            menu.addAction(action)
        self.sample_btn.setMenu(menu)

    def _build_report_pane(self) -> QWidget:
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        # The report reflows to the pane; it never scrolls sideways, because a
        # finding half off the edge is a finding nobody reads.
        self.report_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._set_placeholder()
        return self.report_scroll

    # --- behaviour ----------------------------------------------------------
    def _on_theme_changed(self, text: str) -> None:
        self._mode_choice = text.lower()
        self._mode = theme.resolve(self._mode_choice)
        self._apply_theme()
        if self._bundle is not None:
            self._render_report(self._bundle)
        else:
            self._set_placeholder()

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.stylesheet(self._mode))

    def _on_read(self) -> None:
        source = self.source.toPlainText()
        if not source.strip():
            self._bundle = None
            self._set_placeholder(
                "Paste a PEM certificate, or load a sample, to begin.")
            return
        self._bundle = analyze(source, now=self.fixed_now)
        self._render_report(self._bundle)

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a certificate", "",
            "Certificates (*.pem *.crt *.cer *.der *.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as exc:
            self._set_placeholder(f"Could not open the file: {exc}")
            return
        from ..core.pem import looks_like_der
        if looks_like_der(raw):
            # Raw DER has no text form worth showing; read it directly and say so.
            self.source.setPlainText(
                f"(read {len(raw)} bytes of raw DER from "
                f"{os.path.basename(path)})")
            self._bundle = analyze(raw, now=self.fixed_now)
            self._render_report(self._bundle)
            return
        self.source.setPlainText(raw.decode("utf-8", errors="replace"))
        self._on_read()

    def _load_sample(self, name: str) -> None:
        path = os.path.join(_SAMPLES_DIR, name)
        try:
            with open(path, encoding="utf-8") as handle:
                self.source.setPlainText(handle.read())
        except OSError as exc:
            self._set_placeholder(f"Could not load the sample: {exc}")
            return
        self._on_read()

    def _on_clear(self) -> None:
        self.source.clear()
        self._bundle = None
        self._set_placeholder()

    # --- report rendering ---------------------------------------------------
    def _set_placeholder(self, text: str = "") -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(label("Nothing read yet", "Figure"))
        lay.addWidget(label(text or _PLACEHOLDER, "PageIntro"))
        lay.addStretch(2)
        self.report_scroll.setWidget(host)

    def _render_report(self, bundle: Bundle) -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(8, 4, 8, 16)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(self._grade_card(bundle))
        if bundle.certificates:
            lay.addWidget(self._chain_card(bundle))
            for cert in bundle.certificates:
                lay.addWidget(self._certificate_card(cert, bundle))
        lay.addWidget(self._findings_card(bundle))
        if bundle.parse_notes:
            notes = Card("Notes on the paste", flat=True)
            for note in bundle.parse_notes:
                notes.add(label(note, muted=True))
            lay.addWidget(notes)
        lay.addStretch(1)
        self.report_scroll.setWidget(host)

    def _grade_card(self, bundle: Bundle) -> QWidget:
        grade = bundle.grade
        card = Card()
        top = QHBoxLayout()

        letter = QLabel(grade.letter)
        letter.setStyleSheet(
            f"{theme.font_css('grade')} "
            f"color: {theme.color(theme.grade_token(grade.letter), self._mode)};")
        top.addWidget(letter)

        column = QVBoxLayout()
        column.setSpacing(2)
        shape = ("CERTIFICATE GRADE" if bundle.count <= 1 else
                 f"CHAIN GRADE  ·  {bundle.count} CERTIFICATES")
        column.addWidget(mini_label(f"{shape}  ·  SCORE {grade.score}/100"))
        column.addWidget(label(grade.headline, "PageTitle"))
        column.addStretch(1)
        top.addLayout(column, 1)
        card.add_layout(top)
        card.add(hrule())
        card.add(label(grade.ceiling_note, "Faint"))
        return card

    def _chain_card(self, bundle: Bundle) -> QWidget:
        card = Card("The chain, as it was given")
        if bundle.count > 1:
            joined = sum(1 for link in bundle.links if link.matched)
            card.add(label(
                f"{joined} of {plural(len(bundle.links), 'join')} match. "
                f"A solid gold "
                f"connector means the child's issuer name equals the parent's "
                f"subject name — names only. Attest verifies no signature, so a "
                f"match is a claim that lines up, not a proof.", "Faint"))
        # The rungs are tinted by severity, so the legend has to say so —
        # otherwise the colour is something the reader has to guess at.
        card.add(label(
            "Each rung's spine, role marker and badges carry the worst finding "
            "on that certificate: gold where nothing worse than a note was "
            "found, amber for a real weakness, red for a serious one. The "
            "validity bar is the exception — it answers only to the dates.",
            "Faint"))
        ladder = ChainLadder()
        ladder.set_data(bundle, self._mode)
        card.add(ladder)
        return card

    def _certificate_card(self, cert: Certificate, bundle: Bundle) -> QWidget:
        heading = (f"Certificate {cert.index + 1} of {bundle.count} "
                   f"— {cert.role.marker.lower()}")
        card = Card(heading if bundle.count > 1 else "The certificate")

        card.add(key_value("Subject", breakable(cert.subject.rendered),
                           self._mode, mono=True))
        card.add(key_value("Issuer", breakable(cert.issuer.rendered),
                           self._mode, mono=True))
        card.add(key_value("Serial", breakable(cert.serial_hex), self._mode,
                           mono=True))
        card.add(key_value("Version", f"v{cert.version}", self._mode))

        current = cert.is_current(bundle.now)
        days = cert.days_until_expiry(bundle.now)
        if cert.not_before and cert.not_after:
            span = cert.validity_days
            when = (f"{cert.not_before:%Y-%m-%d %H:%M} → "
                    f"{cert.not_after:%Y-%m-%d %H:%M} UTC   ({span} days)")
            card.add(key_value("Validity", when, self._mode, mono=True,
                               value_token=None if current else "sev_alert"))
            if days is not None:
                state = (f"{plural(days, 'day')} remaining"
                         if current and days >= 0
                         else f"expired {plural(abs(days), 'day')} ago"
                         if days < 0 else "not yet valid")
                card.add(key_value("Standing", state, self._mode,
                                   value_token="sev_good" if current
                                   else "sev_alert"))

        card.add(key_value("Public key", cert.public_key.summary, self._mode))
        card.add(key_value("Signed with", cert.signature_algorithm, self._mode))

        if cert.san.present:
            card.add(key_value("Alt names",
                               breakable(", ".join(cert.san.all_names)),
                               self._mode, mono=True))
        else:
            card.add(key_value("Alt names", "none — no subjectAltName extension",
                               self._mode,
                               value_token=None if cert.is_ca else "sev_alert"))

        card.add(key_value("Constraints", cert.basic_constraints.summary,
                           self._mode))
        card.add(key_value(
            "Key usage",
            ", ".join(cert.key_usage) if cert.key_usage_present else "not stated",
            self._mode))
        card.add(key_value(
            "Issued for",
            ", ".join(cert.ext_key_usage) if cert.ext_key_usage_present
            else "not stated", self._mode))
        if cert.subject_key_id:
            card.add(key_value("Subject key ID",
                               breakable(cert.subject_key_id),
                               self._mode, mono=True))
        if cert.authority_key_id:
            card.add(key_value("Authority key ID",
                               breakable(cert.authority_key_id),
                               self._mode, mono=True))
        card.add(key_value("SHA-256 fingerprint",
                           breakable(cert.fingerprint_sha256),
                           self._mode, mono=True))

        if cert.extensions:
            card.add(hrule())
            card.add(mini_label(f"{len(cert.extensions)} EXTENSIONS"))
            for ext in cert.extensions:
                mark = "critical" if ext.critical else ""
                card.add(key_value(
                    ext.display,
                    breakable(ext.summary) + (f"   [{mark}]" if mark else ""),
                    self._mode, mono=not ext.known))
        return card

    def _findings_card(self, bundle: Bundle) -> QWidget:
        card = Card(f"Findings ({len(bundle.findings)})")
        if not bundle.findings:
            card.add(label(
                "Nothing to report — no certificate was read from this paste.",
                muted=True))
            return card
        for position, finding in enumerate(bundle.findings):
            if position:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["base"])
            chip = Chip(finding.severity.value, _SEV_TOKEN[finding.severity],
                        self._mode)
            chip.setFixedWidth(84)
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)

            column = QVBoxLayout()
            column.setSpacing(2)
            head = QHBoxLayout()
            head.addWidget(label(finding.title, "body"))
            head.addStretch(1)
            if finding.cert_index is not None and bundle.count > 1:
                head.addWidget(label(f"cert {finding.cert_index + 1}", "Faint"))
            if finding.points:
                head.addWidget(label(f"−{finding.points}", "Faint"))
            column.addLayout(head)
            column.addWidget(label(finding.detail, muted=True))
            row.addLayout(column, 1)
            card.add_layout(row)
        return card
