#!/usr/bin/env python3
"""Render the favicon PNGs and the 1200x630 social card from app/static/brand/favicon.svg.

Usage (from the repository root, with the dev requirements installed):

    python dev-tools/render_brand_assets.py

Requires Playwright with Chromium: `playwright install chromium`.
Writes favicon-16/32/48.png, apple-touch-icon.png (180), icon-192.png, icon-512.png and
social-card.png next to the SVG. The header mark in app/templates/base.html is a copy of
the same paths and must be updated by hand when the SVG changes.
"""

import base64
import pathlib
import re

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
BRAND = ROOT / "app" / "static" / "brand"
FONTS = ROOT / "app" / "static" / "fonts"

# Design tokens (light theme) used on the social card.
CANVAS, FG, FG2, FG3, ACCENT_FG = "#F3F6FA", "#0B1A2E", "#3D4F65", "#54667C", "#0B4B86"
NAME = "CredShare"
TAGLINE = "Secure one-time password sharing"
SENTENCE = "Encrypted in your browser, unlocked once with a key you choose, then deleted."
SPONSOR = "Sponsored by ArktIQ IT AS"

SIZES = [
    ("favicon-16.png", 16),
    ("favicon-32.png", 32),
    ("favicon-48.png", 48),
    ("apple-touch-icon.png", 180),
    ("icon-192.png", 192),
    ("icon-512.png", 512),
]


def sized_svg(svg, width, height):
    return re.sub(r"<svg\b", f'<svg width="{width}" height="{height}"', svg, count=1)


def font_face(weight):
    data = base64.b64encode((FONTS / f"PlusJakartaSans-{weight}-latin.woff2").read_bytes()).decode()
    return (
        "@font-face{font-family:'Plus Jakarta Sans';font-weight:%s;"
        "src:url(data:font/woff2;base64,%s) format('woff2');}" % (weight, data)
    )


def main():
    svg = (BRAND / "favicon.svg").read_text()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 800, "height": 800})
        for fname, size in SIZES:
            page.set_content(
                f'<html><body style="margin:0;background:transparent">{sized_svg(svg, size, size)}</body></html>'
            )
            page.locator("svg").screenshot(path=str(BRAND / fname), omit_background=True)
        page.close()

        # The card uses a header-weight outline; the favicon's is thickened for 16 px.
        mark = sized_svg(svg, 300, 338).replace('stroke-width="4"', 'stroke-width="2.6"', 1)
        card = browser.new_page(viewport={"width": 1200, "height": 630})
        card.set_content(
            f"""<!doctype html><html><head><meta charset="utf-8"><style>{font_face(500)}{font_face(700)}</style></head>
<body style="margin:0;width:1200px;height:630px;background:{CANVAS};font-family:'Plus Jakarta Sans',system-ui,sans-serif;display:flex;align-items:center;gap:72px;padding:0 110px;box-sizing:border-box;color:{FG}">
<div style="flex:none">{mark}</div>
<div style="display:grid;gap:18px">
  <div style="font-size:88px;font-weight:700;letter-spacing:-0.03em;line-height:1">{NAME}</div>
  <div style="font-size:38px;font-weight:500;color:{FG2};line-height:1.3">{TAGLINE}</div>
  <div style="font-size:24px;font-weight:500;color:{FG3};line-height:1.5;max-width:640px">{SENTENCE}</div>
  <div style="margin-top:14px;font-size:20px;color:{ACCENT_FG};font-weight:700;letter-spacing:.08em;text-transform:uppercase">{SPONSOR}</div>
</div></body></html>""",
            wait_until="networkidle",
        )
        card.wait_for_timeout(500)
        card.screenshot(path=str(BRAND / "social-card.png"))
        browser.close()
    print("written to", BRAND)


if __name__ == "__main__":
    main()
