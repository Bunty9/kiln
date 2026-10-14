#!/usr/bin/env python3
"""Record the Overview "burning card" edge into sprite sheets (assets/burn-<scheme>-<variant>.webp).

The live effect (SVG feTurbulence + feDisplacementMap, conic-mask hot spots, a crawling noise offset,
breathing burn depth, flicker) cost ~87% of a core with 2 cards.  This renders it offline, in headless
Chromium, into seamless loops, and the dashboard plays the frames back with a CSS border-image, so a
card costs almost nothing.  Every time function is periodic in T, so the loop has no seam.

  python3 scripts/burn/record.py            # writes assets/burn-{dark,light}-{0,1}{,s}.webp
  python3 scripts/burn/record.py --check    # also asserts the loop closes (last frame -> first)

The loop is T = 13/3 s.  The hot-spot masks are made 3-fold symmetric, so one 120 degree turn of the
original's 13 s rotation closes the loop at the original's speed.  The noise crawl keeps the original's
speed with a smaller travel; the breathing depth and the 2.3 s flicker run 3x / 1.06x faster.

Needs: playwright (with chromium) and Pillow with WebP.  Not shipped in the binary.
"""
import argparse, io, math, os, sys
from concurrent.futures import ProcessPoolExecutor

H = 64   # card height (.ch)
R = 10   # --r2
# The original's filter variants: (baseFrequency, seed, scale, dx amp, dx period s, dy amp, dy period s).
# It has three (kb0..2).  Two are shipped, kb0 and kb2: the third looks like kb0 and would cost another
# 130 KB per scheme.  Cards also mirror and shift in time, so two sheets give plenty of different edges.
VARIANTS = [
    (".03 .09", 7, 12, 14, 11, 6, 7),
    (".034 .08", 41, 11, 16, 9.5, 7, 6),
]
SCHEMES = {
    "dark": "--char:#070302;--rim:#9C330A;--hot:#FF9F3A;--core:#FFE2A0;--scorch:rgb(150 62 12/.45)",
    "light": "--char:#1F0E04;--rim:#B4410C;--hot:#FF8A1F;--core:#FFD27A;--scorch:rgb(140 72 20/.34)",
}
FL = [(0, .9), (12, 1), (19, .6), (31, .95), (44, .72), (58, 1), (71, .66), (86, .93), (100, .9)]  # the original's flicker


# the ring's box-shadows, top to bottom.  Two sheets: the sharp edge (char, rim, hot spots) at the screen's
# resolution, and the soft scorch under it at half that (a blur needs no detail, and a smooth gradient is
# what a lossy alpha plane bands on).
RING = {
    "e": "inset 0 0 0 calc(8px + var(--bd)) var(--char),inset 0 0 0 calc(9.5px + var(--bd)) var(--rim)",
    "s": "inset 0 0 5px calc(9.5px + var(--bd)) color-mix(in srgb,var(--hot) 40%,transparent),inset 0 0 16px calc(9px + var(--bd)) var(--scorch)",
}


def page(w, variant, layer):
    freq, seed, scale, *_ = VARIANTS[variant]
    return f"""<!doctype html><meta charset=utf-8><style>
@property --bd{{syntax:'<length>';inherits:true;initial-value:3px}}
@property --ha{{syntax:'<angle>';inherits:false;initial-value:0deg}}
@property --hb{{syntax:'<angle>';inherits:false;initial-value:0deg}}
html,body{{margin:0;background:transparent}}
#c{{position:absolute;left:40px;top:40px;width:{w}px;height:{H}px;border-radius:{R}px;position:absolute;isolation:isolate;overflow:hidden}}
.burn{{position:absolute;inset:-8px;z-index:-1;filter:url(#kb)}}
.burn::before,.burn::after{{content:"";position:absolute}}
.burn::before{{inset:0;border-radius:calc({R}px + 8px);box-shadow:{RING[layer]}}}
.burn::after{{display:{'block' if layer == 'e' else 'none'};--m:repeating-conic-gradient(from var(--ha),#0000 0 8%,#000 13% 18%,#0000 24% 33.3333%),repeating-conic-gradient(from var(--hb),#0000 0 5%,#000 9% 12.5%,#0000 18% 33.3333%);
 inset:calc(7px + var(--bd));border:2px solid var(--core);border-radius:calc({R}px + 1px - var(--bd));
 box-shadow:0 0 3px 1px var(--hot),0 0 12px 2px color-mix(in srgb,var(--hot) 45%,transparent),inset 0 0 6px var(--hot);
 -webkit-mask:var(--m);mask:var(--m);opacity:var(--fl)}}
</style>
<svg width=0 height=0 style=position:absolute><filter id=kb x="-20%" y="-50%" width="140%" height="200%" color-interpolation-filters=sRGB>
<feTurbulence type=fractalNoise baseFrequency="{freq}" numOctaves=4 seed={seed} result=n />
<feOffset id=off in=n result=o dx=0 dy=0 />
<feDisplacementMap in=SourceGraphic in2=o scale={scale} xChannelSelector=R yChannelSelector=G /></filter></svg>
<div id=c><span class=burn id=b></span></div>"""


def state(u, T, variant):
    """The original's animated values at loop position u in [0,1): returns (bd px, ha deg, hb deg, fl, dx, dy)."""
    _, _, _, ax, px, ay, py = VARIANTS[variant]
    bd = 3 - 1.5 * math.cos(2 * math.pi * u)                   # 1.5 -> 4.5 -> 1.5 px, ease-in-out (13 s originally)
    ha = 360 * T / 13 * u                                      # 13 s per turn originally: 120 deg per loop
    hb = -120 * u                                              # 19 s per turn reversed originally: 120 deg per loop
    f = (u * 2 % 1) * 100                                      # flicker: two 2.17 s cycles per loop (2.3 s originally)
    fl = next(a[1] + (b[1] - a[1]) * (f - a[0]) / (b[0] - a[0]) for a, b in zip(FL, FL[1:]) if f <= b[0])
    # crawl: the original sweeps +-ax over px seconds; keep its speed, shrink the travel to fit one loop
    dx = -ax * T / px * math.cos(2 * math.pi * u)
    dy = -ay * T / py * math.cos(2 * math.pi * u)
    return bd, ha, hb, fl, dx, dy


def record(job):
    scheme, variant, layer, a = job
    dpr = a.dpr if layer == "e" else a.dpr_soft
    from playwright.sync_api import sync_playwright
    from PIL import Image
    n = a.frames
    frames = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": a.w + 80, "height": H + 80}, device_scale_factor=dpr)
        pg.set_content(page(a.w, variant, layer))
        pg.evaluate("s=>document.getElementById('c').setAttribute('style', document.getElementById('c').getAttribute('style')+';'+s)", SCHEMES[scheme])
        for k in range(n + a.check):   # --check renders the closing frame (u = 1) too
            bd, ha, hb, fl, dx, dy = state(k / n, a.T, variant)
            pg.evaluate("""([bd,ha,hb,fl,dx,dy])=>{const s=document.getElementById('b').style;s.setProperty('--bd',bd+'px');s.setProperty('--ha',ha+'deg');s.setProperty('--hb',hb+'deg');s.setProperty('--fl',fl);
              const o=document.getElementById('off');o.setAttribute('dx',dx);o.setAttribute('dy',dy)}""", [bd, ha, hb, fl, dx, dy])
            png = pg.screenshot(clip={"x": 40, "y": 40, "width": a.w, "height": H}, omit_background=True)
            frames.append(Image.open(io.BytesIO(png)).convert("RGBA"))
        b.close()
    if a.check:
        from PIL import ImageChops
        d = ImageChops.difference(frames[0], frames.pop()).getchannel("A").getextrema()[1]
        assert d <= 2, f"loop does not close: max alpha difference {d}"
    fw, fh = frames[0].size
    sheet = Image.new("RGBA", (fw, fh * (n + 1)))  # +1 blank row: the border-image slice animation ends there
    for k, f in enumerate(frames):
        sheet.paste(f, (0, k * fh))
    out = os.path.join(a.out, f"burn-{scheme}-{variant}{'' if layer == 'e' else 's'}.webp")
    import numpy as np
    px = np.asarray(sheet).copy()
    px[px[..., 3] < a.min_alpha] = 0   # the scorch's faint tail costs bytes and is invisible
    q = (a.quality, a.alpha_quality) if layer == "e" else (a.quality_soft, 100)
    Image.fromarray(px).save(out, "WEBP", quality=q[0], alpha_quality=q[1], method=6)
    if a.png:
        sheet.save(out.replace(".webp", ".png"))
    return out, n, os.path.getsize(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--frames", type=int, default=40, help="frames per loop (about 9 fps)")
    ap.add_argument("--T", type=float, default=13 / 3, help="loop seconds; the hot-spot turn is 360*T/13 degrees, keep it 120")
    ap.add_argument("--w", type=int, default=300, help="recorded card width (css px); the dashboard stretches the middle")
    ap.add_argument("--dpr", type=float, default=2, help="scale of the edge sheet")
    ap.add_argument("--dpr-soft", dest="dpr_soft", type=float, default=1, help="scale of the scorch sheet")
    ap.add_argument("--quality-soft", dest="quality_soft", type=int, default=40)
    ap.add_argument("--quality", type=int, default=30)
    ap.add_argument("--alpha-quality", dest="alpha_quality", type=int, default=50)
    ap.add_argument("--min-alpha", dest="min_alpha", type=int, default=6)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--variants", default="0,1")
    ap.add_argument("--schemes", default="dark,light")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "..", "assets"))
    ap.add_argument("--png", action="store_true")
    ap.add_argument("--jobs", type=int, default=3)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    jobs = [(s, int(v), ly, a) for s in a.schemes.split(",") for v in a.variants.split(",") for ly in "es"]
    with ProcessPoolExecutor(a.jobs) as ex:
        tot = 0
        for out, n, size in ex.map(record, jobs):
            tot += size
            print(f"{os.path.basename(out)}: {n} frames, {size/1024:.0f} KB")
        print(f"total {tot/1024:.0f} KB")
