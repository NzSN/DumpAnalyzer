#!/usr/bin/env python3
"""Render the architecture document and its DOT diagrams; no daemon execution."""

from __future__ import annotations

import html
import re
import subprocess
from pathlib import Path

from markdown_it import MarkdownIt


HERE = Path(__file__).resolve().parent
DOCS = HERE.parent
source = (DOCS / "architecture.md").read_text()
revision_match = re.search(r"Source revision: `([0-9a-f]{40})`", source)
if not revision_match:
    raise SystemExit("architecture.md must declare its inspected source revision")
revision = revision_match.group(1)

for dot_path in sorted(HERE.glob("*.dot")):
    subprocess.run(
        ["dot", "-Tsvg", str(dot_path), "-o", str(dot_path.with_suffix(".svg"))],
        check=True,
    )

md = MarkdownIt("commonmark").enable("table")
tokens = md.parse(source)
headings = []
for i, token in enumerate(tokens):
    if token.type == "heading_open" and token.tag == "h2":
        title = tokens[i + 1].content
        anchor = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        token.attrSet("id", anchor)
        headings.append((anchor, title))
body = md.renderer.render(tokens, md.options, {})


def embed_diagram(match: re.Match[str]) -> str:
    name, alt = match.groups()
    svg = (HERE / name).read_text()
    svg = svg[svg.index("<svg") :]
    svg = re.sub(r'\s(?:width|height)="[^"]*"', "", svg, count=2)
    svg = re.sub(
        r"<svg\b",
        '<svg role="img" aria-label="' + html.escape(alt, quote=True) + '"',
        svg,
        count=1,
    )
    svg = re.sub(r'id="([^"]+)"', lambda m: f'id="{Path(name).stem}-{m.group(1)}"', svg)
    title = html.escape(alt)
    return (
        '<figure class="diagram">'
        '<div class="diagram-tools" role="group" aria-label="Diagram controls">'
        '<button type="button" data-zoom="-1" aria-label="Zoom out">−</button>'
        '<button type="button" data-zoom="1" aria-label="Zoom in">+</button>'
        '<button type="button" data-fit>Fit</button>'
        '<output aria-live="polite">100%</output>'
        f'<a href="architecture/{name}" target="_blank" rel="noopener">Open SVG ↗</a>'
        '</div>'
        f'<div class="diagram-scroll" tabindex="0" aria-label="{title}; scroll after zooming">{svg}</div>'
        f'<figcaption>{title}</figcaption></figure>'
    )


body = re.sub(
    r'<p><img src="architecture/([^"/]+\.svg)" alt="([^"]*)"\s*/?></p>',
    embed_diagram,
    body,
)
body = re.sub(
    r'href="\.\./((?:src|specs|tests)/[^"]+)"',
    lambda m: f'href="https://github.com/NzSN/DumpAnalyzer/blob/{revision}/{m.group(1)}"',
    body,
)
nav = "".join(
    f'<a href="#{anchor}">{html.escape(title)}</a>' for anchor, title in headings
)
revision_short = revision[:7]
page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DumpAnalyzer architecture · blocks, control flow and data flow</title>
<style>
:root { color-scheme: light; --ink:#202e40; --muted:#546477; --line:#d5dde7; }
* { box-sizing:border-box; }
html { scroll-behavior:smooth; scroll-padding-top:1rem; }
body { margin:0; background:#f5f7fa; color:var(--ink); font:16px/1.65 system-ui,sans-serif; }
nav { position:fixed; inset:0 auto 0 0; width:240px; padding:28px 18px; background:#182b42; color:white; overflow:auto; }
nav strong { display:block; font-size:19px; margin-bottom:5px; }
nav small { display:block; color:#c2cfde; margin-bottom:24px; }
nav a { display:block; color:#e2eaf5; text-decoration:none; padding:10px 8px; border-radius:5px; line-height:1.45; font-size:14px; }
nav a:hover, nav a:focus-visible { background:#304a68; color:white; }
main { margin-left:240px; padding:40px clamp(20px,4vw,70px) 80px; max-width:2100px; }
h1 { font-size:clamp(28px,3vw,42px); line-height:1.2; margin:0 0 14px; letter-spacing:-.025em; }
h1 + p { font-size:13px; color:var(--muted); overflow-wrap:anywhere; }
h2 { font-size:25px; line-height:1.3; margin:64px 0 18px; padding-top:16px; border-top:1px solid var(--line); }
p,li { max-width:105ch; }
a { color:#1857a4; text-underline-offset:3px; }
code { font:0.87em ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
p code,li code,td code { background:#e9eef5; padding:2px 4px; border-radius:3px; }
pre { background:#e9eef5; padding:18px; overflow:auto; border-radius:5px; }
table { width:100%; border-collapse:collapse; margin:22px 0; font-size:14px; background:white; }
th,td { text-align:left; padding:12px 14px; border:1px solid var(--line); vertical-align:top; }
th { background:#e9eef5; }
th:first-child,td:first-child { width:23%; }
.diagram { margin:22px 0 28px; background:white; border:1px solid var(--line); border-radius:8px; overflow:hidden; }
.diagram-tools { display:flex; gap:8px; align-items:center; padding:10px 14px; border-bottom:1px solid var(--line); background:#fbfcfe; }
button { font:inherit; line-height:1.2; min-height:36px; min-width:38px; padding:5px 12px; background:white; color:var(--ink); border:1px solid #9aabbe; border-radius:4px; cursor:pointer; }
button:hover { background:#edf3fc; }
button:focus-visible,a:focus-visible,.diagram-scroll:focus-visible { outline:3px solid #367ac6; outline-offset:3px; }
output { font-size:13px; font-variant-numeric:tabular-nums; color:var(--muted); min-width:45px; }
.diagram-tools a { font-size:13px; margin-left:auto; }
.diagram-scroll { overflow:auto; padding:14px; }
.diagram.zoomed .diagram-scroll { max-height:85vh; }
.diagram-scroll svg { display:block; width:100%; height:auto; max-width:none; }
figcaption { padding:8px 14px; font-size:12px; color:var(--muted); border-top:1px solid var(--line); }
@media (max-width:800px) {
  nav { position:static; width:auto; padding:18px; }
  nav small { margin-bottom:10px; }
  nav a { display:inline-block; padding:7px; font-size:12px; }
  main { margin-left:0; padding:25px 16px 60px; }
  h2 { font-size:22px; margin-top:40px; }
  table { font-size:12px; }
  th,td { padding:8px; }
  .diagram-scroll { padding:6px; }
}
@media print {
  nav,.diagram-tools { display:none; }
  main { margin:0; padding:0; }
  body { background:white; font-size:11px; }
  h2 { break-before:page; margin-top:0; }
  .diagram-scroll { overflow:visible; max-height:none; }
  .diagram-scroll svg { width:100% !important; }
}
</style>
</head>
<body>
<nav aria-label="Architecture views"><strong>DumpAnalyzer</strong><small>Implemented architecture · __REVISION__<br>Blocks / control / data</small>__NAV__</nav>
<main>__BODY__</main>
<script>
document.querySelectorAll('.diagram').forEach(figure => {
  let zoom = 100;
  const svg = figure.querySelector('svg');
  const output = figure.querySelector('output');
  const setZoom = value => {
    zoom = Math.max(50, Math.min(400, value));
    svg.style.width = zoom + '%';
    figure.classList.toggle('zoomed', zoom > 100);
    output.value = zoom + '%';
  };
  figure.querySelectorAll('[data-zoom]').forEach(button => {
    button.addEventListener('click', () => setZoom(zoom + Number(button.dataset.zoom) * 25));
  });
  figure.querySelector('[data-fit]').addEventListener('click', () => setZoom(100));
});
</script>
</body>
</html>
"""
page = page.replace("__REVISION__", revision_short).replace("__NAV__", nav).replace("__BODY__", body)
output_path = DOCS / "architecture.html"
output_path.write_text(page)
print(f"Rendered {len(list(HERE.glob('*.dot')))} diagrams → {output_path}")
