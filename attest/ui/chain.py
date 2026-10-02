"""
The chain ladder — Attest's signature.

A certificate chain is a claim about parentage, and the only way to read it is
sideways: *this* certificate says it was issued by *that* name, and the next
certificate along says that name is its own. The ladder draws exactly that.
One rung per certificate, leaf at the bottom and root at the top, the way a
chain of trust is always pictured. Each rung carries the subject it identifies,
the issuer it names underneath in mono, a badge for its key and signature, and
a small validity bar showing where *now* falls between notBefore and notAfter.

The connective tissue is the information. Between two rungs Attest draws the
join: a solid gold line when the child's issuer name matches the parent's
subject name, and a dashed red one when it does not, labelled either way. That
single picture answers the question behind most TLS misconfigurations — "is
this actually a chain?" — which a list of fields cannot.

It is painted rather than assembled from labels for the same reason. And the
one thing it refuses to draw is a tick: a matched join is a match of *names*,
not a verified signature, and the legend says so.
"""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from . import theme
from ..core.model import Bundle, Certificate, Role

_RUNG_H = 92        # the box that holds one certificate
_JOIN_H = 44        # the gap between two rungs, where the connector lives
_PAD = 10
_SIDE = 4
_BAR_H = 6          # the validity bar
_RADIUS = 5


def _elide(text: str, width: float, font: QFont) -> str:
    return QFontMetrics(font).elidedText(
        text, Qt.TextElideMode.ElideMiddle, max(16, int(width)))


class ChainLadder(QWidget):
    """The pasted certificates as a ladder, root at the top, leaf at the bottom."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bundle: Bundle | None = None
        self._mode = theme.LIGHT
        self.setMinimumHeight(_RUNG_H + _PAD * 2)

    def set_data(self, bundle: Bundle, mode: str) -> None:
        self._bundle = bundle
        self._mode = mode
        self.setMinimumHeight(self._wanted_height())
        self.updateGeometry()
        self.update()

    def _wanted_height(self) -> int:
        count = max(1, self._bundle.count if self._bundle else 1)
        # A single rung carries a line of explanation beneath it; a ladder does
        # not need one, because the joins already say what is going on.
        footer = 38 if count == 1 else 0
        return _PAD * 2 + _RUNG_H * count + _JOIN_H * (count - 1) + footer

    def sizeHint(self) -> QSize:  # noqa: N802  (Qt override)
        return QSize(400, self._wanted_height())

    # --- painting -----------------------------------------------------------
    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731

        bundle = self._bundle
        if bundle is None or not bundle.certificates:
            painter.setPen(c("ink_faint"))
            painter.setFont(self._font("subtitle"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "No certificate to draw.")
            painter.end()
            return

        # Drawn top-down as root-first, which is the reverse of the stored
        # order: the bundle is leaf-first, the way a handshake sends it.
        order = list(reversed(bundle.certificates))
        width = self.width()

        for position, cert in enumerate(order):
            top = _PAD + position * (_RUNG_H + _JOIN_H)
            self._draw_rung(painter, cert, QRectF(_SIDE, top, width - _SIDE * 2,
                                                  _RUNG_H), bundle.now)
            if position < len(order) - 1:
                # The join below this rung belongs to the certificate beneath,
                # whose stored index is one lower than this one's.
                child = order[position + 1]
                link = next((l for l in bundle.links
                             if l.child_index == child.index), None)
                self._draw_join(painter, link,
                                QRectF(_SIDE, top + _RUNG_H,
                                       width - _SIDE * 2, _JOIN_H))

        if bundle.count == 1:
            self._draw_lone_note(painter, order[0],
                                 QRectF(_SIDE, _PAD + _RUNG_H,
                                        width - _SIDE * 2, _PAD + 4))
        painter.end()

    # --- one rung -----------------------------------------------------------
    def _draw_rung(self, painter: QPainter, cert: Certificate, box: QRectF,
                   now: datetime) -> None:
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731

        current = cert.is_current(now)
        accent = c("brass") if current else c("sev_alert")

        painter.setPen(QPen(c("rule"), 1))
        painter.setBrush(QBrush(c("surface")))
        painter.drawRoundedRect(box.adjusted(0.5, 0.5, -0.5, -0.5),
                                _RADIUS, _RADIUS)

        # A gold (or red) spine down the left edge marks the rung's standing.
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(accent))
        painter.drawRoundedRect(
            QRectF(box.left(), box.top() + 1, 3, box.height() - 2), 1.5, 1.5)

        left = box.left() + 16
        right = box.right() - 14
        marker_font = self._font("label")
        marker = cert.role.marker
        marker_w = QFontMetrics(marker_font).horizontalAdvance(marker) + 6

        # role marker, top right
        painter.setPen(accent if cert.role is not Role.INTERMEDIATE
                       else c("ink_faint"))
        painter.setFont(marker_font)
        painter.drawText(QRectF(right - marker_w, box.top() + 11, marker_w, 14),
                         Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                         marker)

        # subject, in bold — the thing this certificate identifies
        subject_font = self._font("body_bold")
        painter.setPen(c("ink"))
        painter.setFont(subject_font)
        subject_w = right - left - marker_w - 12
        painter.drawText(QRectF(left, box.top() + 9, subject_w, 18),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         _elide(cert.label, subject_w, subject_font))

        # issuer, in mono beneath it — the name the join is made of
        issuer_font = self._font("mono_small")
        painter.setPen(c("ink_muted"))
        painter.setFont(issuer_font)
        issued_by = ("self-signed" if cert.is_self_signed
                     else f"issued by {cert.issuer_label}")
        painter.drawText(QRectF(left, box.top() + 29, right - left, 16),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         _elide(issued_by, right - left, issuer_font))

        # key / signature badges
        badges = [cert.public_key.badge]
        alg = cert.signature_algorithm
        from ..core.oids import signature_algorithm
        sig = signature_algorithm(cert.signature_algorithm_oid)
        badges.append(sig.hash_name or sig.name if sig else (alg or "unknown alg"))
        x = left
        for text in badges:
            x = self._draw_badge(painter, text, x, box.top() + 50)

        self._draw_validity_bar(
            painter, cert,
            QRectF(x + 8, box.top() + 52, max(40.0, right - x - 8), 18), now)

    def _draw_badge(self, painter: QPainter, text: str, x: float,
                    y: float) -> float:
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731
        font = self._font("label")
        width = QFontMetrics(font).horizontalAdvance(text) + 14
        rect = QRectF(x, y, width, 18)
        painter.setPen(QPen(c("brass_edge"), 1))
        painter.setBrush(QBrush(c("brass_wash")))
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), 3, 3)
        painter.setPen(c("brass"))
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        return x + width + 6

    def _draw_validity_bar(self, painter: QPainter, cert: Certificate,
                           box: QRectF, now: datetime) -> None:
        """notBefore -> notAfter, with now marked where it falls."""
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731
        font = self._font("mono_small")
        painter.setFont(font)

        if not cert.not_before or not cert.not_after:
            painter.setPen(c("ink_faint"))
            painter.drawText(box, Qt.AlignmentFlag.AlignRight
                             | Qt.AlignmentFlag.AlignVCenter, "dates unreadable")
            return

        label = (f"{cert.not_before:%Y-%m-%d} → {cert.not_after:%Y-%m-%d}")
        label_w = QFontMetrics(font).horizontalAdvance(label) + 8
        painter.setPen(c("ink_faint"))
        painter.drawText(QRectF(box.right() - label_w, box.top(), label_w,
                                box.height()),
                         Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                         label)

        track = QRectF(box.left(), box.top() + (box.height() - _BAR_H) / 2,
                       max(24.0, box.width() - label_w - 10), _BAR_H)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(c("sunken")))
        painter.drawRoundedRect(track, _BAR_H / 2, _BAR_H / 2)

        span = (cert.not_after - cert.not_before).total_seconds() or 1.0
        fraction = (now - cert.not_before).total_seconds() / span
        inside = 0.0 <= fraction <= 1.0
        fill_token = "sev_good" if inside else "sev_alert"

        painter.setBrush(QBrush(c(fill_token)))
        if inside:
            painter.drawRoundedRect(
                QRectF(track.left(), track.top(),
                       max(2.0, track.width() * fraction), track.height()),
                _BAR_H / 2, _BAR_H / 2)
            marker_x = track.left() + track.width() * fraction
        else:
            # Out of window: fill the whole track and park the marker on the
            # edge it ran past, so the bar reads as "all used up" or "not begun".
            painter.drawRoundedRect(track, _BAR_H / 2, _BAR_H / 2)
            marker_x = track.right() if fraction > 1 else track.left()

        painter.setPen(QPen(c("ink"), 1))
        painter.setBrush(QBrush(c(fill_token)))
        painter.drawEllipse(QRectF(marker_x - 4, track.center().y() - 4, 8, 8))

    # --- the join between two rungs ----------------------------------------
    def _draw_join(self, painter: QPainter, link, box: QRectF) -> None:
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731
        matched = bool(link and link.matched)
        colour = c("brass") if matched else c("sev_alert")
        x = box.left() + 30

        pen = QPen(colour, 2)
        if matched:
            pen.setStyle(Qt.PenStyle.SolidLine)
        else:
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([3, 3])
        painter.setPen(pen)
        painter.drawLine(int(x), int(box.top() + 2), int(x), int(box.bottom() - 2))

        # a small node at the midpoint: filled when the names join, hollow when
        # they do not, so the state survives a greyscale print
        mid = box.center().y()
        painter.setPen(QPen(colour, 2))
        painter.setBrush(QBrush(colour) if matched
                         else QBrush(Qt.BrushStyle.NoBrush))
        painter.drawEllipse(QRectF(x - 4, mid - 4, 8, 8))

        painter.setFont(self._font("label"))
        painter.setPen(colour if not matched else c("ink_muted"))
        verdict = link.verdict if link else "no link"
        painter.drawText(QRectF(x + 14, mid - 9, box.width() - x - 20, 18),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                         verdict.upper() if not matched else verdict)

    def _draw_lone_note(self, painter: QPainter, cert: Certificate,
                        box: QRectF) -> None:
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731
        painter.setFont(self._font("small"))
        painter.setPen(c("ink_faint"))
        text = ("One certificate was pasted, and it signs itself — there is no "
                "chain above it."
                if cert.is_self_signed else
                f"One certificate was pasted. It names {cert.issuer_label} as "
                f"its issuer, but that certificate is not here.")
        painter.drawText(QRectF(box.left() + 16, box.top(), box.width() - 32, 34),
                         int(Qt.AlignmentFlag.AlignLeft
                             | Qt.AlignmentFlag.AlignTop
                             | Qt.TextFlag.TextWordWrap), text)

    # --- helpers ------------------------------------------------------------
    def _font(self, role: str) -> QFont:
        family, size, weight = theme.TYPE[role]
        font = QFont()
        font.setFamilies([family.split(",")[0].strip().strip('"')])
        font.setPixelSize(size)
        font.setWeight(QFont.Weight.DemiBold if weight >= 600
                       else QFont.Weight.Normal)
        return font
