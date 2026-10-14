"""Local, deterministic sensitivity classifier. Pure functions: no I/O, no network.

Rule kinds:
  value   - data that must be redacted (a key, an email, an ID number)
  context - what the text is about (health, credentials, roadmaps)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Classification, Finding, Sensitivity

S, P, C, U = Sensitivity.SECRET, Sensitivity.PERSONAL, Sensitivity.CONFIDENTIAL, Sensitivity.PUBLIC
I = re.IGNORECASE
DEFAULT_UNMATCHED = P  # fail closed: unrecognised content is treated as personal


@dataclass(frozen=True)
class Rule:
    name: str
    tier: Sensitivity
    kind: str
    pattern: re.Pattern
    reason: str


def _rule(name, tier, kind, pattern, reason, flags=0) -> Rule:
    return Rule(name, tier, kind, re.compile(pattern, flags), reason)


RULES: tuple[Rule, ...] = (
    # --- secret: credential material (redacted) ---
    _rule("stripe_key", S, "value", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b",
          "Stripe secret or restricted API key"),
    _rule("aws_access_key_id", S, "value", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key ID"),
    _rule("github_token", S, "value", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token"),
    _rule("private_key_block", S, "value",
          r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
          "PEM private key block"),
    _rule("jwt", S, "value", r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}", "JSON Web Token"),
    _rule("url_credentials", S, "value", r"(?<=://)[^\s:/@]+:[^\s@/]+(?=@)",
          "Username and password inside a URL"),
    _rule("secret_assignment", S, "value",
          r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\w*\s*[:=]\s*[\"']?"
          r"(?P<v>(?!\[REDACTED)[^\s\"']{6,})",
          "Credential assigned to a variable or field", I),
    _rule("credential_mention", S, "context",
          r"\b(?:secret key|api key|private key|access token|client secret|password|credentials?)\b",
          "Text discusses credentials", I),
    # --- personal ---
    _rule("health_context", P, "context",
          r"\b(?:patient|diagnos\w*|prescri\w*|medical|clinical|symptoms?|blood pressure|glucose|therapy)\b",
          "Health or medical context", I),
    _rule("record_id", P, "value",
          r"\b(?:ID|MRN)\s*[:#]?\s*(?P<v>[A-Z0-9]{2,}(?:-[A-Z0-9]{2,})+)\b",
          "Identifier of a person's record", I),
    _rule("email", P, "value", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", "Email address"),
    _rule("phone", P, "value",
          r"(?<!\w)(?:\+\d{1,3}[\s-]?)?\d{3}[\s-]?\d{3}[\s-]?\d{4}(?!\w)",
          "Phone number"),
    _rule("government_id", P, "value",
          r"\b(?:\d{4}\s\d{4}\s\d{4}|[A-Z]{5}\d{4}[A-Z]|\d{3}-\d{2}-\d{4})\b",
          "Government ID format (Aadhaar, PAN, SSN)"),
    # --- confidential ---
    _rule("business_internal", C, "context",
          r"\b(?:roadmap|internal|confidential|proprietary|unreleased|forecast|revenue|ARR|MRR|"
          r"burn rate|gross margin|valuation|acquisition|board meeting|salar(?:y|ies)|headcount)\b",
          "Proprietary or internal business details", I),
    _rule("financial_figure", C, "context",
          r"[$ ₹ €£]\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:k|m|bn|cr|crore|lakh|million|billion)\b)?",
          "Monetary figure", I),
    # --- public indicators ---
    _rule("public_reference", U, "context",
          r"\b(?:documentation|docs|readme|wikipedia|open[- ]source|"
          r"public(?:ly)? (?:available|documented|released)|press release|changelog)\b",
          "Publicly available reference material", I),
)

_PRIVATE_CHANNEL = re.compile(r"\b(?:dm|direct message|private)\b", I)
_INTERNAL_SOURCE = re.compile(r"\b(?:internal|intranet|admin)\b", I)


def scan(text: str) -> list[Finding]:
    """Run every rule over the text. Used by the classifier, redactor, router and egress gate."""
    found = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            span = match.span("v") if "v" in rule.pattern.groupindex else match.span()
            found.append(Finding(rule.name, rule.tier, rule.kind, rule.reason, span))
    return found


def _metadata_findings(event_type: str | None, source: str | None) -> list[Finding]:
    found = []
    if source and event_type == "transcript" and _PRIVATE_CHANNEL.search(source):
        found.append(Finding("private_conversation", P, "context",
                             "Transcript from a private or direct-message channel", None))
    if source and _INTERNAL_SOURCE.search(source):
        found.append(Finding("internal_system", C, "context",
                             "Captured from an internal company system", None))
    return found


def classify(text: str, *, event_type: str | None = None, source: str | None = None) -> Classification:
    findings = scan(text) + _metadata_findings(event_type, source)
    sensitive = sorted({f.tier for f in findings if f.tier is not U}, reverse=True)
    if sensitive:
        tiers = tuple(sensitive)
    elif findings:  # only public indicators matched
        tiers = (U,)
    else:
        findings.append(Finding("fail_closed_default", DEFAULT_UNMATCHED, "context",
                                "No rule matched; unrecognised content is treated as personal", None))
        tiers = (DEFAULT_UNMATCHED,)
    return Classification(tier=tiers[0], tiers_detected=tiers, findings=tuple(findings))
