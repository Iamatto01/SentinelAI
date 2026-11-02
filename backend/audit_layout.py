"""Report card-boundary audit.

Detects the layout defect class that raster inspection catches late: a card frame
that does not enclose its own content. Every fix card is drawn with a rounded
rectangle; any text whose baseline falls below the rectangle's bottom edge while
starting inside its horizontal band is content escaping the card.

Also reports per-page ink coverage so that runaway page growth (dead space in a
panel) is visible without rasterising every page.
"""
import sys

import pdfplumber
import re

CARD_LEFT = 40.0      # leftX in report.js
CARD_RIGHT = 555.0    # leftX + w
FRAME_GAP = 1.5       # rounding tolerance


def _union_boxes(boxes, tol=4.0):
    """Union boxes that touch within `tol`, until stable.

    A rounded rectangle arrives as separate Bezier arcs and straight segments.
    Requiring one fragment to be *contained* in another never merges them, so
    the frame was never reconstructed. Overlap-on-any-axis does merge them.
    """
    boxes = list(boxes)
    changed = True
    while changed:
        changed = False
        out = []
        for b in boxes:
            for i, o in enumerate(out):
                if (b[0] <= o[2] + tol and b[2] >= o[0] - tol
                        and b[1] <= o[3] + tol and b[3] >= o[1] - tol):
                    out[i] = (min(b[0], o[0]), min(b[1], o[1]),
                              max(b[2], o[2]), max(b[3], o[3]))
                    changed = True
                    break
            else:
                out.append(b)
        boxes = out
    return boxes


def card_frames(page):
    """Card frames on a page, from both `rect` and `roundedRect` geometry.

    pdfplumber exposes a rounded rectangle as four Bezier arcs plus two straights
    under `page.curves`, never as a `page.rects` entry. Scanning only `rects`
    therefore saw the full-bleed header rules and nothing else, which is how a
    whole clipped card passed the gate.

    Returns (box, rounded). The flag matters: a rounded rectangle is drawn by
    `drawCard` as a container and must enclose its own body. A plain rectangle
    is a band, rule or accent - a section heading strip, the cover banner, the
    page footer bar - and legitimately has document flow running past its edge.
    Only containers are candidates for an overflow defect.
    """
    rect_frags = [(r["x0"], r["top"], r["x1"], r["bottom"], False) for r in page.rects]
    curve_frags = [(c["x0"], c["top"], c["x1"], c["bottom"], True)
                   for c in page.curves]
    line_frags = [(c["x0"], c["top"], c["x1"], c["bottom"], False)
                  for c in page.lines]
    # Card-wide fragments only. A full-width frame is a container; a 4pt accent
    # bar, a 60pt "AI GENERATED" pill or a severity chip is furniture drawn
    # inside one. Unioning those in let a chip 80pt above a PoC box glue itself
    # to it and invent a frame nothing was meant to fill.
    frags = [f for f in rect_frags + curve_frags + line_frags
             if (f[2] - f[0]) > 0.5 and (f[3] - f[1]) > 0.5
             and f[0] <= CARD_LEFT + 2 and f[2] >= CARD_RIGHT - 2]
    groups = []
    for box in _union_boxes([f[:4] for f in frags]):
        members = [f for f in frags
                   if box[0] - 2 <= f[0] and f[2] <= box[2] + 2
                   and box[1] - 2 <= f[1] and f[3] <= box[3] + 2]
        rounded = any(f[4] for f in members)
        groups.append((box, rounded))
    return [(b, r) for b, r in groups
            if b[0] <= CARD_LEFT + 2 and b[2] >= CARD_RIGHT - 2
            and (b[3] - b[1]) > 40]


def audit(path):
    escapes = []
    page_rows = []
    OVERRUN = 14.0   # how far past a frame a glyph can land and still be that card's
    with pdfplumber.open(path) as pdf:
        for pno, page in enumerate(pdf.pages, start=1):
            all_frames = sorted(card_frames(page), key=lambda f: f[0][1])
            frames = [b for b, rounded in all_frames if rounded]
            words = page.extract_words(use_text_flow=False)
            for i, (x0, top, x1, bottom) in enumerate(frames):
                # A card owns the text starting below its top edge, up to its own
                # bottom plus a short overrun, or up to the next frame - whichever
                # comes first. Text that starts inside a later card is that card's.
                limit = bottom + OVERRUN
                later = [f[1] for f, _ in all_frames if f[1] > top + 1]
                if later:
                    limit = min(limit, min(later))
                owned = [w for w in words
                         if x0 - 2 <= w["x0"] <= x1 + 2
                         and top - FRAME_GAP <= w["top"] < limit]
                overflow = [w for w in owned if w["bottom"] > bottom + FRAME_GAP]
                if overflow:
                    worst = max(overflow, key=lambda w: w["bottom"])
                    escapes.append((pno, round(bottom, 1), round(worst["bottom"], 1),
                                    worst["text"][:40], len(overflow)))
                # The converse defect: text drawn on top of a card's top edge,
                # which renders as visibly clipped glyphs.
                collide = [w for w in words
                           if x0 - 2 <= w["x0"] <= x1 + 2
                           and abs(w["top"] - top) < 2
                           and w["bottom"] > top]
                if collide:
                    escapes.append((pno, round(top, 1), round(collide[0]["bottom"], 1),
                                    "text on frame top: " + collide[0]["text"][:30],
                                    len(collide)))
            chars = sum(len(w["text"]) for w in words)
            page_rows.append((pno, len(frames), chars))
    return escapes, page_rows


def hidden_content(path):
    """Full-width fills painted underneath a later full-bleed cover band.

    The simplification cover once drew an "Evidence validation" panel at the top
    of the auto-created page 1, then painted the 135pt banner over it. No pixel
    survived, but the panel's text stayed in the PDF text layer, so copying text
    off the cover returned it interleaved with the visible title. Cover text
    sitting *on top* of the banner is correct design, so the defect is not "text
    near a band" - it is a fill that precedes the band in paint order and lies
    inside it. pdfplumber preserves that order within `page.rects`.
    """
    hits = []
    with pdfplumber.open(path) as pdf:
        for pno, page in enumerate(pdf.pages, start=1):
            rects = page.rects
            for i, r in enumerate(rects):
                if not (r["x0"] <= 1 and r["x1"] >= page.width - 1
                        and r["top"] <= 1 and (r["bottom"] - r["top"]) > 50):
                    continue
                for earlier in rects[:i]:
                    inside = (earlier["top"] >= r["top"] - 1
                              and earlier["bottom"] <= r["bottom"] + 1
                              and earlier["x0"] >= r["x0"] - 1
                              and earlier["x1"] <= r["x1"] + 1
                              and (earlier["bottom"] - earlier["top"]) > 20)
                    if inside:
                        hits.append((pno, round(r["bottom"], 1),
                                     round(earlier["top"], 1), round(earlier["bottom"], 1)))
    return hits


def cve_coverage(path):
    """CVE ids actually printed on the page.

    The two exports once disagreed: the simplified report carried a technology
    inventory and six NVD-matched nginx CVEs, while the full report carried no
    inventory section at all and cited nothing. Whatever else changes, the full
    report must never cite fewer advisories than the simplified one — it is the
    document an auditor reads.
    """
    text = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text.append(page.extract_text() or "")
    blob = "\n".join(text)
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", blob)), blob


def main():
    seen = {}
    escapes_total = 0
    buried_total = 0
    for name in ("simplify", "full"):
        path = rf"F:\FYP2PROJECT\output\sentinelai-127.0.0.1-6205-{name}-2026-10-30.pdf"
        escapes, page_rows = audit(path)
        cves, blob = cve_coverage(path)
        buried = hidden_content(path)
        escapes_total += len(escapes)
        buried_total += len(buried)
        seen[name] = cves
        total_chars = sum(c for _, _, c in page_rows)
        thin = [p for p, r, c in page_rows if c < 400]
        print(f"=== {name}: {len(page_rows)} pages, {total_chars} chars "
              f"({total_chars / len(page_rows):.0f}/page)")
        print(f"  technology inventory: {'present' if 'inventory' in blob.lower() else 'MISSING'}")
        print(f"  CVE ids cited: {len(cves)}"
              + (f" - {', '.join(sorted(cves))}" if cves else ""))
        if escapes:
            print(f"  CARD OVERFLOWS: {len(escapes)}")
            for pno, frame_bottom, text_bottom, text, n in escapes[:10]:
                print(f"   p{pno} frame ends {frame_bottom} but {n} words run to "
                      f"{text_bottom} (e.g. {text!r})")
        else:
            print("  CARD OVERFLOWS: none")
        if buried:
            print(f"  BURIED UNDER BANNER: {len(buried)} fill(s)")
            for pno, bb, et, eb in buried[:6]:
                print(f"   p{pno} banner ends {bb} but a fill drawn earlier spans "
                      f"{et}-{eb}")
        else:
            print("  BURIED UNDER BANNER: none")
        if thin:
            print(f"  near-empty pages: {[(p, c) for p, r, c in thin]}")

    missing = seen["simplify"] - seen["full"]
    if missing:
        print(f"\nFAIL: full report omits {len(missing)} CVE(s) the simplified one cites: "
              f"{', '.join(sorted(missing))}")
        return 1
    path_hits = escapes_total + buried_total
    if path_hits:
        print(f"\nFAIL: {path_hits} layout defect(s) across both exports.")
        return 1
    print(f"\nOK: full report cites every CVE the simplified report cites ({len(seen['full'])}); "
          "no card overflows and no text buried under a cover band.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
