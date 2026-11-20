#!/usr/bin/env python3
"""Draws the Lens icon (white hexagon with aperture cuts on black) into assets/Lens.icns and docs/logo.svg."""
import math, os, subprocess, sys, tempfile
from PIL import Image, ImageDraw

S = 1024
CX = CY = 512
R = 292          # hexagon radius
CUT = 44         # cut width
def hexpts(r, rot=-90):
    return [(CX + r*math.cos(math.radians(rot + 60*k)), CY + r*math.sin(math.radians(rot + 60*k))) for k in range(6)]
RHO = 0.36 * R
def cuts(r=R):
    out = []
    for k in range(0, 6, 2):
        a = math.radians(-90 + 60*k)
        d = r * 1.12
        P = (CX + d*math.cos(a), CY + d*math.sin(a))
        t = a + math.acos(RHO / d)
        T = (CX + RHO*math.cos(t), CY + RHO*math.sin(t))
        # extend a little past the tangent point so the blade reads as a slit
        vx, vy = T[0]-P[0], T[1]-P[1]
        L = math.hypot(vx, vy)
        E = (T[0] + vx/L*18, T[1] + vy/L*18)
        out.append((P, E))
    return out

def draw():
    sc = 2
    im = Image.new("RGBA", (S*sc, S*sc), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    m = 100*sc
    d.rounded_rectangle([m, m, S*sc-m, S*sc-m], radius=190*sc, fill=(10, 10, 12, 255))
    white = (246, 246, 244, 255)
    rr = 40  # corner rounding
    inner = hexpts(R - rr*1.15)
    d.polygon([(x*sc, y*sc) for x, y in inner], fill=white)
    for i in range(6):
        (x1, y1), (x2, y2) = inner[i], inner[(i+1) % 6]
        d.line([x1*sc, y1*sc, x2*sc, y2*sc], fill=white, width=int(2*rr*sc))
    for x, y in inner:
        d.ellipse([(x-rr)*sc, (y-rr)*sc, (x+rr)*sc, (y+rr)*sc], fill=white)
    for (a, b) in cuts():
        d.line([a[0]*sc, a[1]*sc, b[0]*sc, b[1]*sc], fill=(10, 10, 12, 255), width=CUT*sc)
        d.ellipse([(b[0]-CUT/2)*sc, (b[1]-CUT/2)*sc, (b[0]+CUT/2)*sc, (b[1]+CUT/2)*sc], fill=(10, 10, 12, 255))
    return im.resize((S, S), Image.LANCZOS)

def svg():
    hs = " ".join(f"{x:.1f},{y:.1f}" for x, y in hexpts(R - 46))
    lines = "".join(f'<line x1="{a[0]:.1f}" y1="{a[1]:.1f}" x2="{b[0]:.1f}" y2="{b[1]:.1f}"/>' for a, b in cuts())
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {S} {S}"><rect x="100" y="100" width="824" height="824" rx="190" fill="#0a0a0c"/>'
            f'<polygon points="{hs}" fill="#f6f6f4" stroke="#f6f6f4" stroke-width="80" stroke-linejoin="round"/>'
            f'<g stroke="#0a0a0c" stroke-width="{CUT}" stroke-linecap="round">{lines}</g></svg>')

img = draw()
out = sys.argv[1] if len(sys.argv) > 1 else "assets/Lens.icns"
with tempfile.TemporaryDirectory() as t:
    iset = os.path.join(t, "Lens.iconset"); os.makedirs(iset)
    for sz in (16, 32, 128, 256, 512):
        img.resize((sz, sz), Image.LANCZOS).save(f"{iset}/icon_{sz}x{sz}.png")
        img.resize((sz*2, sz*2), Image.LANCZOS).save(f"{iset}/icon_{sz}x{sz}@2x.png")
    subprocess.check_call(["iconutil", "-c", "icns", iset, "-o", out])
img.save("assets/Lens-1024.png")
open("docs/logo.svg", "w").write(svg())
open("docs/favicon.svg", "w").write(svg())
print("wrote", out)
