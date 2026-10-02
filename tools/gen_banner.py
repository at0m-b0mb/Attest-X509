#!/usr/bin/env python3
"""
Repository art — the social card, the README banner, and the contact sheet.

Three surfaces, three sets of rules, all drawn from the same palette as the
application so the repo and the app read as one thing:

* **social-preview.png** — 1280x640, with GitHub's 40pt (80px) safe border.
  Every piece of information is registered with a :class:`SafeBox` as it is
  drawn, and ``check()`` refuses to write a file that crosses the border. The
  rendered PNG is then measured pixel by pixel, because an assertion about
  rectangles is only as good as the drawing that followed it.
* **banner.png / banner-dark.png** — 2560x800, a light/dark pair for a README
  ``<picture>``. A banner is never cropped, so its gold band may bleed.
* **screens.png / screens-dark.png** — a contact sheet of real, off-screen
  captures, one sheet per theme so neither README background gets a glaring
  slab.

The motif on the card and the banner is the chain ladder, redrawn here from the
actual values in ``samples/modern-chain.pem`` — so the card carries the
product's own data rather than an illustration of it.

Run ``python tools/capture_screenshots.py`` first; the contact sheet needs
those PNGs.
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "images")

SERIF = "/System/Library/Fonts/Supplemental/Iowan Old Style.ttc"
SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/Menlo.ttc"

# palette, straight from attest.ui.theme
PAPER = "#F3F1EC"
SURFACE = "#FFFFFF"
INK = "#1B1813"
INK_MUTED = "#575144"
INK_FAINT = "#847D6E"
RULE = "#DCD6C9"
RULE_STRONG = "#C4BCAA"
SUNKEN = "#EBE7DE"
BRASS = "#7A5D18"
SHINE = "#C39B24"
BRASS_WASH = "#F7F0DC"
BRASS_EDGE = "#E3D4A5"
GREEN = "#2C6249"
RED = "#8C1F16"

BLACK = "#000000"
D_SURFACE = "#131312"
D_INK = "#F3F0E9"
D_MUTED = "#A29C91"
D_FAINT = "#6B675F"
D_RULE = "#2B2B28"
D_SUNKEN = "#0A0A09"
D_BRASS = "#D9B75C"
D_SHINE = "#F1C84B"
D_BRASS_WASH = "#221D0E"
D_BRASS_EDGE = "#463A1A"
D_GREEN = "#67BE94"
D_RED = "#EE8B82"


def font(path: str, size: int, index: int = 0) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size, index=index)


class SafeBox:
    """Registers every meaningful rectangle and reports the tightest margin.

    Background art is simply never registered, so it is free to bleed; only the
    things a crop must not eat — wordmark, tagline, pitch, URL, the ladder
    panel — are handed to :meth:`add`.
    """

    def __init__(self, w: int, h: int, safe: int):
        self.w, self.h, self.safe = w, h, safe
        self.rects: list[tuple[str, tuple[int, int, int, int]]] = []

    def add(self, name: str, box: tuple[float, float, float, float]) -> None:
        self.rects.append((name, tuple(int(round(v)) for v in box)))

    def check(self) -> None:
        worst = None
        for name, (l, t, r, b) in self.rects:
            m = min(l, t, self.w - r, self.h - b)
            if worst is None or m < worst[0]:
                worst = (m, name, (l, t, r, b))
        if worst is None:
            return
        m, name, box = worst
        assert m >= self.safe, (
            f"{name} at {box} leaves a {m}px margin on a {self.w}x{self.h} "
            f"canvas; the safe border needs {self.safe}px.")
        print(f"  safe border ok — tightest: {name} at {m}px (need {self.safe})")


def _text(draw, xy, s, fnt, fill, ls=0, anchor="la"):
    """Draw text, optionally letter-spaced, and return its pixel width."""
    if ls == 0:
        draw.text(xy, s, font=fnt, fill=fill, anchor=anchor)
        l, t, r, b = draw.textbbox(xy, s, font=fnt, anchor=anchor)
        return r - l
    x, y = xy
    for ch in s:
        draw.text((x, y), ch, font=fnt, fill=fill, anchor="la")
        w = draw.textbbox((0, 0), ch, font=fnt)[2]
        x += w + ls
    return x - xy[0] - ls


def _round_rect(draw, box, radius, fill=None, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline,
                           width=width)


def _dashed_line(draw, x, y0, y1, fill, width, dash=6, gap=6):
    y = y0
    while y < y1:
        draw.line([(x, y), (x, min(y + dash, y1))], fill=fill, width=width)
        y += dash + gap


# --- the chain ladder motif, redrawn from a real sample ----------------------
# Subject, issuer, key badge, signature badge, how far through its validity it
# is, role marker — the actual values from samples/modern-chain.pem, read
# top-down as root first, the way the widget draws them.
_RUNGS = [
    ("Example Trust Root R3", "self-signed", "RSA-4096", "SHA-256", 0.27,
     "SELF-SIGNED ROOT"),
    ("Example Trust Issuing CA 2", "issued by Example Trust Root R3",
     "RSA-3072", "SHA-256", 0.26, ""),
    ("shop.northwind.example", "issued by Example Trust Issuing CA 2",
     "P-256", "SHA-256", 0.05, "LEAF"),
]
_JOINS = [True, True]


def _draw_ladder(draw, box, pal, ss, joins=None, title="THE CHAIN, AS GIVEN"):
    """Draw the three-rung ladder inside *box*."""
    joins = _JOINS if joins is None else joins
    x0, y0, x1, y1 = box
    _round_rect(draw, box, 10 * ss, fill=pal["surface"], outline=pal["rule"],
                width=max(1, ss))
    pad = 24 * ss
    f_subject = font(SANS, 19 * ss)
    f_issuer = font(MONO, 12 * ss)
    f_badge = font(SANS, 11 * ss)
    f_mark = font(SANS, 11 * ss)

    _text(draw, (x0 + pad, y0 + 16 * ss), title, f_mark, pal["faint"], ls=2 * ss)

    top = y0 + 48 * ss
    usable = (y1 - top - pad)
    rung_h = usable * 0.26
    join_h = (usable - rung_h * 3) / 2

    for index, (subject, issuer, key, sig, progress, mark) in enumerate(_RUNGS):
        ry = top + index * (rung_h + join_h)
        rect = (x0 + pad, ry, x1 - pad, ry + rung_h)
        _round_rect(draw, rect, 5 * ss, fill=pal["surface"],
                    outline=pal["rule"], width=max(1, ss))
        # the standing spine down the left edge
        draw.rounded_rectangle(
            (rect[0], rect[1] + ss, rect[0] + 3 * ss, rect[3] - ss),
            radius=ss, fill=pal["brass"])

        tx = rect[0] + 14 * ss
        _text(draw, (tx, ry + 9 * ss), subject, f_subject, pal["ink"])
        _text(draw, (tx, ry + 32 * ss), issuer, f_issuer, pal["muted"])
        if mark:
            _text(draw, (rect[2] - 12 * ss, ry + 11 * ss), mark, f_mark,
                  pal["brass"], anchor="ra")

        # badges
        bx = tx
        for text in (key, sig):
            w = draw.textbbox((0, 0), text, font=f_badge)[2] + 14 * ss
            _round_rect(draw, (bx, ry + 52 * ss, bx + w, ry + 70 * ss), 3 * ss,
                        fill=pal["brass_wash"], outline=pal["brass_edge"],
                        width=max(1, ss))
            _text(draw, (bx + w / 2, ry + 61 * ss), text, f_badge, pal["brass"],
                  anchor="mm")
            bx += w + 6 * ss

        # validity bar with the present moment marked on it
        bar_x0 = bx + 10 * ss
        bar_x1 = rect[2] - 14 * ss
        bar_y = ry + 61 * ss
        h = 6 * ss
        _round_rect(draw, (bar_x0, bar_y - h / 2, bar_x1, bar_y + h / 2),
                    h / 2, fill=pal["sunken"])
        fill_x = bar_x0 + (bar_x1 - bar_x0) * progress
        _round_rect(draw, (bar_x0, bar_y - h / 2, max(fill_x, bar_x0 + h),
                           bar_y + h / 2), h / 2, fill=pal["green"])
        draw.ellipse((fill_x - 4 * ss, bar_y - 4 * ss,
                      fill_x + 4 * ss, bar_y + 4 * ss),
                     fill=pal["green"], outline=pal["ink"], width=max(1, ss))

        # the join down to the next rung
        if index < len(_RUNGS) - 1:
            matched = joins[index]
            colour = pal["brass"] if matched else pal["red"]
            jx = rect[0] + 30 * ss
            jy0, jy1 = ry + rung_h + 3 * ss, ry + rung_h + join_h - 3 * ss
            if matched:
                draw.line([(jx, jy0), (jx, jy1)], fill=colour, width=2 * ss)
            else:
                _dashed_line(draw, jx, jy0, jy1, colour, 2 * ss,
                             dash=3 * ss, gap=3 * ss)
            mid = (jy0 + jy1) / 2
            if matched:
                draw.ellipse((jx - 4 * ss, mid - 4 * ss, jx + 4 * ss,
                              mid + 4 * ss), fill=colour)
            else:
                draw.ellipse((jx - 4 * ss, mid - 4 * ss, jx + 4 * ss,
                              mid + 4 * ss), outline=colour, width=2 * ss)
            _text(draw, (jx + 12 * ss, mid - 7 * ss),
                  "issuer matches" if matched else "ISSUER MISMATCH",
                  f_mark, pal["muted"] if matched else colour)


def _pal(dark: bool) -> dict:
    if dark:
        return dict(bg=BLACK, surface=D_SURFACE, ink=D_INK, muted=D_MUTED,
                    faint=D_FAINT, rule=D_RULE, rule_strong="#3D3C38",
                    sunken=D_SUNKEN, brass=D_BRASS, shine=D_SHINE,
                    brass_wash=D_BRASS_WASH, brass_edge=D_BRASS_EDGE,
                    green=D_GREEN, red=D_RED)
    return dict(bg=PAPER, surface=SURFACE, ink=INK, muted=INK_MUTED,
                faint=INK_FAINT, rule=RULE, rule_strong=RULE_STRONG,
                sunken=SUNKEN, brass=BRASS, shine=SHINE,
                brass_wash=BRASS_WASH, brass_edge=BRASS_EDGE,
                green=GREEN, red=RED)


# --- social card --------------------------------------------------------------

def render_card(path: str, dark: bool = False) -> None:
    W, H, SS, SAFE = 1280, 640, 2, 80
    pal = _pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)
    box = SafeBox(W * SS, H * SS, SAFE * SS)
    margin = 96 * SS  # author at 96, assert at 80

    lx = margin
    f_mark = font(SERIF, 86 * SS)
    wmw = _text(d, (lx, 150 * SS), "ATTEST", f_mark, pal["ink"])
    box.add("wordmark", (lx, 150 * SS, lx + wmw, 150 * SS + 86 * SS))
    d.line([(lx, 258 * SS), (lx + wmw, 258 * SS)], fill=pal["brass"],
           width=3 * SS)

    f_tag = font(SANS, 20 * SS)
    tgw = _text(d, (lx, 278 * SS), "READ THE CERTIFICATE", f_tag, pal["faint"],
                ls=4 * SS)
    box.add("tagline", (lx, 278 * SS, lx + tgw, 278 * SS + 24 * SS))

    f_pitch = font(SERIF, 36 * SS)
    d.text((lx, 330 * SS), "See what a certificate", font=f_pitch, fill=pal["ink"])
    d.text((lx, 374 * SS), "actually says.", font=f_pitch, fill=pal["ink"])
    box.add("pitch", (lx, 330 * SS, lx + 420 * SS, 374 * SS + 40 * SS))

    f_sub = font(SANS, 18 * SS)
    subs = ["An offline X.509 reader with its own DER parser.",
            "Grades A+ to F — and never calls anything safe."]
    for i, line in enumerate(subs):
        d.text((lx, (440 + i * 26) * SS), line, font=f_sub, fill=pal["muted"])
    box.add("sub", (lx, 440 * SS, lx + 430 * SS, (440 + 2 * 26) * SS))

    f_url = font(MONO, 17 * SS)
    urlw = _text(d, (lx, 516 * SS), "github.com/at0m-b0mb/Attest", f_url,
                 pal["brass"])
    box.add("url", (lx, 516 * SS, lx + urlw, 516 * SS + 20 * SS))

    panel = (700 * SS, 120 * SS, (W - 96) * SS, (H - 120) * SS)
    _draw_ladder(d, panel, pal, SS)
    box.add("ladder", panel)

    box.check()
    im = im.resize((W, H), Image.LANCZOS)
    im.save(path)
    _assert_safe_border(path, SAFE, pal["bg"])
    print(f"wrote {os.path.relpath(path, ROOT)}")


def _assert_safe_border(path: str, margin: int, bg_hex: str) -> None:
    """Measure the rendered PNG: no non-background ink inside the border."""
    im = Image.open(path).convert("RGB")
    W, H = im.size
    px = im.load()
    bg = tuple(int(bg_hex.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))

    def near(c):
        return all(abs(c[i] - bg[i]) <= 6 for i in range(3))

    pts = [(x, y) for y in range(0, H, 2) for x in range(0, W, 2)
           if not near(px[x, y])]
    if not pts:
        return
    l = min(p[0] for p in pts)
    r = max(p[0] for p in pts)
    t = min(p[1] for p in pts)
    b = max(p[1] for p in pts)
    m = min(l, W - 1 - r, t, H - 1 - b)
    assert m >= margin, f"content reaches {m}px from the edge (need {margin})"
    print(f"  measured card margins: L{l} R{W-1-r} T{t} B{H-1-b} — ok")


# --- banner -------------------------------------------------------------------

def render_banner(path: str, dark: bool = False) -> None:
    W, H, SS = 1280, 400, 2
    pal = _pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)

    # a gold band that may bleed to the right edge
    d.rectangle([(W - 150) * SS, 0, W * SS, H * SS], fill=pal["brass"])
    d.rectangle([(W - 156) * SS, 0, (W - 150) * SS, H * SS], fill=pal["shine"])

    lx = 80 * SS
    f_mark = font(SERIF, 100 * SS)
    _text(d, (lx, 120 * SS), "ATTEST", f_mark, pal["ink"])
    d.line([(lx, 246 * SS), (lx + 380 * SS, 246 * SS)], fill=pal["brass"],
           width=3 * SS)
    f_tag = font(SANS, 22 * SS)
    _text(d, (lx, 266 * SS), "READ THE CERTIFICATE", f_tag, pal["faint"],
          ls=5 * SS)
    f_sub = font(SANS, 21 * SS)
    d.text((lx, 306 * SS), "An offline X.509 certificate reader and grader.",
           font=f_sub, fill=pal["muted"])
    d.text((lx, 338 * SS), "Its own DER parser. No network, ever.",
           font=f_sub, fill=pal["muted"])

    panel = (720 * SS, 40 * SS, (W - 170) * SS, (H - 40) * SS)
    _draw_ladder(d, panel, pal, SS)

    im.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({im.size[0]}x{im.size[1]})")


# --- contact sheet ------------------------------------------------------------

def render_contact_sheet(path: str, shots: list[str], dark: bool = False) -> None:
    pal = _pal(dark)
    loaded = []
    for name in shots:
        p = os.path.join(IMG, name)
        if os.path.exists(p):
            loaded.append(Image.open(p).convert("RGB"))
    if not loaded:
        print(f"  (no screenshots for {os.path.basename(path)} — run capture first)")
        return

    gap, pad = 28, 40
    scale_w = 560
    thumbs = []
    for im in loaded:
        h = int(im.height * scale_w / im.width)
        thumbs.append(im.resize((scale_w, h), Image.LANCZOS))
    sheet_w = pad * 2 + scale_w * len(thumbs) + gap * (len(thumbs) - 1)
    sheet_h = pad * 2 + max(t.height for t in thumbs)
    sheet = Image.new("RGB", (sheet_w, sheet_h), pal["bg"])
    d = ImageDraw.Draw(sheet)
    x = pad
    for t in thumbs:
        sheet.paste(t, (x, pad))
        d.rectangle([x, pad, x + t.width - 1, pad + t.height - 1],
                    outline=pal["rule"], width=1)
        x += t.width + gap
    sheet.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({sheet_w}x{sheet_h})")


def main() -> int:
    os.makedirs(IMG, exist_ok=True)
    print("social card:")
    render_card(os.path.join(IMG, "social-preview.png"), dark=False)
    print("banner (light + dark):")
    render_banner(os.path.join(IMG, "banner.png"), dark=False)
    render_banner(os.path.join(IMG, "banner-dark.png"), dark=True)
    print("contact sheet (light + dark):")
    render_contact_sheet(os.path.join(IMG, "screens.png"),
                         ["shot-modern-chain-light.png",
                          "shot-broken-chain-light.png"], dark=False)
    render_contact_sheet(os.path.join(IMG, "screens-dark.png"),
                         ["shot-modern-chain-dark.png",
                          "shot-broken-chain-dark.png"], dark=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
