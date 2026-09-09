"""Load versioned source-to-Omni mapping rules for deterministic suggestions."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent / "rulebook"


def load_rulebook(source: str, version: str = "v2") -> str:
    """Concatenate common + source-specific fragments for a source/version."""
    base = _ROOT / version
    parts: list[str] = []
    for sub in ("common", source):
        d = base / sub
        if not d.is_dir():
            continue
        for md in sorted(d.glob("*.md")):
            parts.append(md.read_text().strip())
    return "\n\n---\n\n".join(parts)
