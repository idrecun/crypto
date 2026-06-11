#!/usr/bin/env python3
"""Aritmeticko kolo za verifikator V(t, w) <=> w^3 + w + 5 = t.

Stablo tece s leva na desno (pejzazni format radi mdbook-a):
    g1 = w * w          -> w^2
    g2 = w^2 * w        -> w^3        g3 = w + 5
    g4 = w^3 + (w + 5)  -> t
w se deli vertikalnom sabirnicom s leve strane.

Renderuje se pomocu pycairo u book/src/images/circuit.png (uz autokrop PIL-om).
"""
import math
import cairo
from PIL import Image, ImageChops

# ---- stil ----------------------------------------------------------------
# gejtovi obojeni po tipu operacije: mnozenje (ljubicasto), sabiranje (zeleno)
MULT_FILL = (0.91, 0.87, 0.98)
MULT_LINE = (0.42, 0.33, 0.66)
ADD_FILL = (0.84, 0.93, 0.85)
ADD_LINE = (0.23, 0.52, 0.29)
WIRE = (0.20, 0.20, 0.23)   # zice
INK = (0.11, 0.11, 0.13)    # tekst
LW = 1.8                    # debljina zice
GLW = 2.4                   # debljina ruba gejta
GR = 30.0                   # poluprecnik gejta
SERIF = "DejaVu Serif"
PA = math.radians(38)       # ugao prikljucaka (mereno od horizontale)
EX, EY = GR * math.cos(PA), GR * math.sin(PA)

# centri gejtova (tok s leva na desno)
G1 = (200.0, 150.0)         # w * w
G2 = (350.0, 215.0)         # w^2 * w
G3 = (350.0, 355.0)         # w + 5
G4 = (500.0, 285.0)         # w^3 + (w + 5)
TLAB = (580.0, 285.0)       # labela izlaza t

BUSX = 70.0                 # x vertikalne sabirnice za w
BUS_Y0, BUS_Y1 = 131.5, 336.5
OUT_PNG = "/home/idrecun/repos/crypto/book/src/images/circuit.png"
SCALE = 2.0
CROP_PAD = 24               # margina (logicki px) oko sadrzaja


def bp(c, kind):
    """Tacka na rubu gejta: levo = ulazi, desno = izlaz."""
    cx, cy = c
    return {
        "lu": (cx - EX, cy - EY), "ll": (cx - EX, cy + EY),   # levi ulazi
        "r": (cx + GR, cy),                                   # desni izlaz
    }[kind]


def arrowhead(ctx, x, y, dx, dy):
    n = math.hypot(dx, dy)
    ux, uy = dx / n, dy / n
    l, w = 9.0, 4.5
    bx, by = x - ux * l, y - uy * l
    px, py = -uy * w, ux * w
    ctx.move_to(x, y)
    ctx.line_to(bx + px, by + py)
    ctx.line_to(bx - px, by - py)
    ctx.close_path()
    ctx.set_source_rgb(*WIRE)
    ctx.fill()


def edge(ctx, pts, arrow=True):
    ctx.set_source_rgb(*WIRE)
    ctx.set_line_width(LW)
    ctx.move_to(*pts[0])
    for p in pts[1:]:
        ctx.line_to(*p)
    ctx.stroke()
    if arrow:
        (x0, y0), (x1, y1) = pts[-2], pts[-1]
        arrowhead(ctx, x1, y1, x1 - x0, y1 - y0)


def htap(ctx, port, x0=BUSX):
    """Horizontalni odvod (sa sabirnice ili od konstante) do ulaza gejta."""
    edge(ctx, [(x0, port[1]), port])


def gate(ctx, c, sym):
    cx, cy = c
    fill, line = (MULT_FILL, MULT_LINE) if sym == "×" else (ADD_FILL, ADD_LINE)
    ctx.set_line_width(GLW)
    ctx.new_sub_path()
    ctx.arc(cx, cy, GR, 0, 2 * math.pi)
    ctx.set_source_rgb(*fill)
    ctx.fill_preserve()
    ctx.set_source_rgb(*line)
    ctx.stroke()
    ctx.set_source_rgb(*line)
    ctx.select_font_face(SERIF, cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
    ctx.set_font_size(30)
    xb, yb, tw, th, _, _ = ctx.text_extents(sym)
    ctx.move_to(cx - tw / 2 - xb, cy - th / 2 - yb)
    ctx.show_text(sym)


def label(ctx, x, y, s, size=21, slant=cairo.FONT_SLANT_ITALIC, anchor="c"):
    ctx.set_source_rgb(*INK)
    ctx.select_font_face(SERIF, slant, cairo.FONT_WEIGHT_NORMAL)
    ctx.set_font_size(size)
    xb, yb, tw, th, _, _ = ctx.text_extents(s)
    if anchor == "c":
        ox = x - tw / 2 - xb
    elif anchor == "r":
        ox = x - tw - xb
    else:
        ox = x - xb
    ctx.move_to(ox, y - th / 2 - yb)
    ctx.show_text(s)


def main():
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, int(620 * SCALE), int(420 * SCALE))
    ctx = cairo.Context(surface)
    ctx.scale(SCALE, SCALE)
    ctx.set_source_rgb(1, 1, 1)
    ctx.paint()

    # --- vertikalna w sabirnica ------------------------------------------
    edge(ctx, [(BUSX, BUS_Y0), (BUSX, BUS_Y1)], arrow=False)

    # --- ulazi (odvodi udesno) -------------------------------------------
    htap(ctx, bp(G1, "lu"))           # w -> g1
    htap(ctx, bp(G1, "ll"))           # w -> g1
    htap(ctx, bp(G2, "ll"))           # w -> g2
    htap(ctx, bp(G3, "lu"))           # w -> g3
    edge(ctx, [(BUSX, bp(G3, "ll")[1]), bp(G3, "ll")])  # 5 -> g3

    # --- unutrasnje grane stabla -----------------------------------------
    edge(ctx, [bp(G1, "r"), bp(G2, "lu")])   # w^2 -> g2
    edge(ctx, [bp(G2, "r"), bp(G4, "lu")])   # w^3 -> g4
    edge(ctx, [bp(G3, "r"), bp(G4, "ll")])   # w+5 -> g4
    edge(ctx, [bp(G4, "r"), (TLAB[0] - 18, TLAB[1])])    # -> t

    # --- gejtovi ----------------------------------------------------------
    gate(ctx, G1, "×")
    gate(ctx, G2, "×")
    gate(ctx, G3, "+")
    gate(ctx, G4, "+")

    # --- labele -----------------------------------------------------------
    label(ctx, BUSX, BUS_Y0 - 18, "w")                       # sabirnica
    label(ctx, BUSX - 10, bp(G3, "ll")[1], "5",
          slant=cairo.FONT_SLANT_NORMAL, anchor="r")
    label(ctx, TLAB[0], TLAB[1], "t")
    label(ctx, 278, 157, "w²", size=20)                      # meduzice
    label(ctx, 428, 225, "w³", size=20)
    label(ctx, 428, 347, "w + 5", size=20)

    surface.write_to_png(OUT_PNG)

    # --- autokrop na sadrzaj uz jednaku marginu --------------------------
    img = Image.open(OUT_PNG).convert("RGB")
    bg = Image.new("RGB", img.size, (255, 255, 255))
    l, t, r, b = ImageChops.difference(img, bg).getbbox()
    p = int(CROP_PAD * SCALE)
    img.crop((max(0, l - p), max(0, t - p),
              min(img.width, r + p), min(img.height, b + p))).save(OUT_PNG)
    print("wrote", OUT_PNG, img.crop((max(0, l - p), max(0, t - p),
          min(img.width, r + p), min(img.height, b + p))).size)


if __name__ == "__main__":
    main()
