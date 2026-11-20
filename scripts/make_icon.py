#!/usr/bin/env python3
"""Draws the Lens icon (magnifier on a rounded square) into assets/Lens.icns."""
import os, subprocess, sys, tempfile
from PIL import Image, ImageDraw

S = 1024
def draw():
    sc = 2
    im = Image.new("RGBA", (S*sc, S*sc), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    m = 100*sc
    d.rounded_rectangle([m, m, S*sc-m, S*sc-m], radius=190*sc, fill=(246, 248, 252, 255))
    blue = (47, 94, 232, 255)
    cx, cy, r = 470*sc, 460*sc, 215*sc
    d.ellipse([cx-r, cy-r, cx+r, cy+r], fill=(222, 231, 252, 255), outline=blue, width=58*sc)
    d.line([cx+r*0.72, cy+r*0.72, 780*sc, 770*sc], fill=blue, width=78*sc)
    for k, w in [(-0.35, .9), (0, .6), (0.35, .75)]:
        y = cy + r*k*1.1
        x0 = cx - r*0.5
        d.line([x0, y, x0 + r*w, y], fill=blue, width=26*sc)
    return im.resize((S, S), Image.LANCZOS)

img = draw()
out = sys.argv[1] if len(sys.argv) > 1 else "assets/Lens.icns"
with tempfile.TemporaryDirectory() as t:
    iset = os.path.join(t, "Lens.iconset"); os.makedirs(iset)
    for sz in (16, 32, 128, 256, 512):
        img.resize((sz, sz), Image.LANCZOS).save(f"{iset}/icon_{sz}x{sz}.png")
        img.resize((sz*2, sz*2), Image.LANCZOS).save(f"{iset}/icon_{sz}x{sz}@2x.png")
    subprocess.check_call(["iconutil", "-c", "icns", iset, "-o", out])
print("wrote", out)
