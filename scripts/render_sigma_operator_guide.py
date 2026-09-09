#!/usr/bin/env python3
"""Render the authored operator guide to a self-contained instruction page.

Deliberately supports only the Markdown constructs used by this checked-in guide.
No JavaScript, third-party assets, remote rendering, or runtime dependencies.
"""

from __future__ import annotations

import argparse
from html import escape
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "customer/sigma/SETUP-AND-USAGE.md"
TARGET = ROOT / "customer/sigma/START-HERE.html"
TOKEN = re.compile(r"`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^)]+)\)")


def inline(value: str) -> str:
    output, offset = [], 0
    for match in TOKEN.finditer(value):
        output.append(escape(value[offset:match.start()]))
        code, bold, label, url = match.groups()
        if code is not None:
            output.append(f"<code>{escape(code)}</code>")
        elif bold is not None:
            output.append(f"<strong>{escape(bold)}</strong>")
        else:
            if not (url.startswith("https://") or re.fullmatch(r"[A-Za-z0-9._/-]+", url)):
                raise ValueError("unsupported guide link")
            output.append(f'<a href="{escape(url, quote=True)}">{escape(label)}</a>')
        offset = match.end()
    output.append(escape(value[offset:]))
    return "".join(output)


def render(markdown: str) -> str:
    lines = markdown.splitlines()
    chunks, navigation = [], []
    i = 0
    section_open = False
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("```"):
            code = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            if i == len(lines):
                raise ValueError("unclosed guide code block")
            chunks.append("<pre><code>" + escape("\n".join(code)) + "</code></pre>")
            i += 1
            continue
        heading = re.match(r"^(#{1,3}) (.+)$", line)
        if heading:
            level, title = len(heading[1]), heading[2]
            identifier = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
            if level == 2:
                if section_open:
                    chunks.append("</section>")
                chunks.append(f'<section aria-labelledby="{identifier}">')
                section_open = True
                navigation.append(f'<a href="#{identifier}">{escape(title)}</a>')
            chunks.append(f'<h{level} id="{identifier}">{inline(title)}</h{level}>')
            i += 1
            continue
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [value.strip() for value in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                    rows.append(cells)
                i += 1
            if not rows or any(len(row) != len(rows[0]) for row in rows):
                raise ValueError("inconsistent guide table")
            chunks.append('<div class="table-scroll"><table><thead><tr>' + "".join(
                f"<th>{inline(cell)}</th>" for cell in rows[0]) + "</tr></thead><tbody>")
            for row in rows[1:]:
                chunks.append("<tr>" + "".join(f"<td>{inline(cell)}</td>" for cell in row) + "</tr>")
            chunks.append("</tbody></table></div>")
            continue
        bullet = re.match(r"^(?:- |\d+\. )(.+)$", line)
        if bullet:
            ordered = not line.startswith("- ")
            tag = "ol" if ordered else "ul"
            chunks.append(f"<{tag}>")
            while i < len(lines):
                item = re.match(r"^\d+\. (.+)$" if ordered else r"^- (.+)$", lines[i])
                if not item:
                    break
                chunks.append(f"<li>{inline(item[1])}</li>")
                i += 1
            chunks.append(f"</{tag}>")
            continue
        paragraph = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not re.match(r"^(?:#|```|\||- |\d+\. )", lines[i]):
            paragraph.append(lines[i])
            i += 1
        text = " ".join(paragraph)
        style = ' class="draft"' if text.startswith("DRAFT") else ""
        chunks.append(f"<p{style}>{inline(text)}</p>")
    if section_open:
        chunks.append("</section>")
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>Sigma-to-Omni — setup and operating guide</title>
<style>
:root { color-scheme:light; font-family:system-ui,-apple-system,sans-serif; color:#202b38; background:#f3f5f7; }
body { max-width:1040px; margin:36px auto; padding:0 24px 48px; line-height:1.6; }
main { background:white; border:1px solid #dfe4ea; border-radius:12px; padding:28px 36px; }
h1 { font-size:2.1rem; line-height:1.2; } h2 { font-size:1.4rem; line-height:1.3; }
section { margin-top:34px; padding-top:12px; border-top:1px solid #dfe4ea; scroll-margin-top:20px; }
.draft { border-left:4px solid #957000; background:#fff8df; padding:12px 18px; }
nav { background:#edf2f6; border-radius:8px; padding:18px 24px; margin-bottom:22px; }
nav a { display:block; padding:3px 0; } a { color:#155b89; text-underline-offset:3px; overflow-wrap:anywhere; }
li { margin:8px 0; } p { overflow-wrap:anywhere; }
code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:.91em; background:#edf1f5; padding:2px 4px; border-radius:3px; overflow-wrap:anywhere; }
pre { background:#172a3a; color:#f3f7fb; padding:18px; border-radius:8px; overflow:auto; line-height:1.55; }
pre code { background:none; color:inherit; padding:0; white-space:pre; }
.table-scroll { overflow:auto; } table { border-collapse:collapse; width:100%; font-size:.94em; }
th,td { text-align:left; vertical-align:top; padding:11px; border-bottom:1px solid #dfe4ea; min-width:130px; }
th { background:#edf2f6; } footer { color:#526171; font-size:.9rem; padding:20px 4px; }
@media(max-width:650px) { body { margin:16px auto; padding:0 10px 24px; } main { padding:18px; } h1 { font-size:1.7rem; } pre { font-size:.85rem; } }
@media print { body { background:white; max-width:none; margin:0; padding:0; font-size:10pt; } main { border:0; padding:0; } nav { display:none; } h2,h3 { break-after:avoid; } pre { white-space:pre-wrap; overflow-wrap:anywhere; background:#f3f5f7; color:#202b38; } pre code { white-space:pre-wrap; } tr { break-inside:avoid; } .table-scroll { overflow:visible; } }
</style></head><body>
<nav aria-label="Guide contents"><strong>Migration operator guide · quick navigation</strong>
""" + "\n".join(navigation) + "</nav><main>\n" + "\n".join(chunks) + """
</main><footer>Self-contained instruction page. No scripts, tracking, uploads, or remote assets. Links open official reference documentation only when you choose them. Use your browser's Print option for a PDF copy.</footer>
</body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = render(SOURCE.read_text())
    if args.check:
        if not TARGET.exists() or TARGET.read_text() != result:
            raise SystemExit("Operator HTML is stale; run scripts/render_sigma_operator_guide.py")
        print("Operator instruction page is current.")
    else:
        TARGET.write_text(result)
        print("Rendered customer/sigma/START-HERE.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
