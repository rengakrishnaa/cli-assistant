"""Replaces value findings with typed placeholders. Context findings stay: meaning, not data."""

from __future__ import annotations

from typing import Iterable

from .classifier import scan
from .models import Finding


def redact(text: str, findings: Iterable[Finding] | None = None) -> tuple[str, int]:
    """Return (redacted_text, number_of_redactions). Findings must come from this same text."""
    if findings is None:
        findings = scan(text)
    targets = sorted((f for f in findings if f.kind == "value" and f.span), key=lambda f: f.span)
    merged: list[list] = []
    for f in targets:
        start, end = f.span
        if merged and start < merged[-1][1]:  # overlap: extend the previous span
            merged[-1][1] = max(merged[-1][1], end)
            if f.tier > merged[-1][2].tier:
                merged[-1][2] = f
        else:
            merged.append([start, end, f])
    out = text
    for start, end, f in reversed(merged):
        out = f"{out[:start]}[REDACTED:{f.rule}]{out[end:]}"
    return out, len(merged)


def redact_text(text: str) -> str:
    return redact(text)[0]
