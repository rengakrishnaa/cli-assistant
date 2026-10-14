"""Structured memory extraction from REDACTED text.

Deterministic pattern matching cannot be prompt-injected, which is the strongest defence
available. A local LLM extractor can replace it by implementing the Extractor protocol.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

INJECTION = re.compile(
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?"
    r"(?:previous|prior|above|earlier)\s+"
    r"(?:instructions|prompts?|rules)"
    r"|\b(?:system|developer)\s+prompt\b"
    r"|\byou\s+are\s+now\b"
    r"|\b(?:reveal|print|send|upload|exfiltrate)\s+"
    r"(?:all\s+|the\s+|your\s+)?"
    r"(?:memories|secrets|keys|api\s+keys|credentials|data)\b"
    r"|</?\s*(?:system|assistant|instructions?)\s*>",
    re.IGNORECASE,
)

_STOPWORDS = frozenset({"The", "This", "That", "We", "I", "It", "He", "She", "They", "You",
                        "Team", "Everyone", "Someone", "Dr"})
_PEOPLE = (
    re.compile(r"\b([A-Z][a-z]{1,29})\s+"
               r"(?:said|says|mentioned|asked|told|suggested|wants|thinks|noted|agreed)\b"),
    re.compile(r"\b(?:with|cc|ping|ask)\s+([A-Z][a-z]{1,29})\b"),
    re.compile(r"(?<![\w.])@([A-Za-z][\w.-]{1,29})"),
)
_PROJECTS = (
    re.compile(r"\b((?:[A-Z][A-Za-z0-9]+\s){1,3}"
               r"(?:Page|Project|Portal|Service|App|Dashboard|Migration|Launch|Roadmap))\b"),
    re.compile(r"\b(Q[1-4]\s+[A-Za-z]+\s+roadmap)\b", re.IGNORECASE),
)
_TOPICS = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in {
    "Stripe": r"\bstripe\b",
    "Payment Intent": r"\bpayment\s*intents?\b",
    "Payments": r"\b(?:payments?|checkout|billing)\b",
    "Security": r"\b(?:secret|api)\s+keys?\b|\bexpos\w+|\bsecurity\b|\brotat\w+",
    "Frontend": r"\bfront[- ]?end\b",
    "Backend": r"\bback[- ]?end\b",
    "Marketing": r"\bmarketing\b",
    "Product Launch": r"\blaunch\w*",
    "Roadmap": r"\broadmaps?\b",
    "Healthcare": r"\b(?:patient|diagnos\w*|medical|clinical|glucose)",
    "Cloud Infrastructure": r"(?<![a-z])(?:aws|gcp|azure|terraform|kubernetes|kubectl)(?![a-z])",
    "Shell": r"\b(?:export|sudo|ssh|chmod)\b",
    "Database": r"\b(?:database|postgres\w*|mysql|sqlite\w*)",
    "Web Platform": r"\b(?:fetch api|cors|http|mdn)\b",
}.items()}
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


@dataclass(frozen=True)
class ExtractedFields:
    people: tuple[str, ...]
    projects: tuple[str, ...]
    topics: tuple[str, ...]
    summary: str


BLOCKED_FIELDS = ExtractedFields((), (), (), "[withheld: routing verdict was 'blocked']")


class Extractor(Protocol):
    name: str

    def extract(self, redacted_text: str) -> ExtractedFields: ...


def detect_injection(text: str) -> tuple[str, ...]:
    return ("prompt_injection_suspected",) if INJECTION.search(text) else ()


def _unique(items) -> tuple[str, ...]:
    seen, out = set(), []
    for item in items:
        if item.casefold() not in seen:
            seen.add(item.casefold())
            out.append(item)
    return tuple(out)


def _title(phrase: str) -> str:
    return " ".join(word[:1].upper() + word[1:] for word in phrase.split())


def _summarize(text: str, max_chars: int = 240) -> str:
    flat = " ".join(text.split())
    summary = " ".join(_SENTENCE_END.split(flat)[:2])  # extractive: first two sentences
    return summary if len(summary) <= max_chars else summary[: max_chars - 1].rstrip() + "…"


class RuleBasedExtractor:
    name = "rules_v1"

    def extract(self, redacted_text: str) -> ExtractedFields:
        people = [m.group(1) for rx in _PEOPLE for m in rx.finditer(redacted_text)]
        projects = [_title(m.group(1)) for rx in _PROJECTS for m in rx.finditer(redacted_text)]
        topics = [name for name, rx in _TOPICS.items() if rx.search(redacted_text)]
        return ExtractedFields(
            people=_unique(p for p in people if p not in _STOPWORDS),
            projects=_unique(projects),
            topics=tuple(topics),
            summary=_summarize(redacted_text),
        )
