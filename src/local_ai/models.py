"""Plain data types shared by every layer. No I/O here."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Sensitivity(IntEnum):
    """Ordered so max() returns the most restrictive tier."""

    PUBLIC = 0
    CONFIDENTIAL = 1
    PERSONAL = 2
    SECRET = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, label: str) -> "Sensitivity":
        return cls[label.upper()]


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class RawEvent:
    id: str
    type: str
    app: str
    source: str
    content: str
    event_ts: int  # unix seconds, UTC
    concealed: bool = False


@dataclass(frozen=True)
class Finding:
    rule: str
    tier: Sensitivity
    kind: str  # "value" = data to redact, "context" = what the text is about
    reason: str
    span: tuple[int, int] | None  # offsets into the scanned text; never the text itself


@dataclass(frozen=True)
class Classification:
    tier: Sensitivity
    tiers_detected: tuple[Sensitivity, ...]
    findings: tuple[Finding, ...]

    def explain(self) -> dict:
        """Structured justification. Safe to print and store: rule names, never matched text."""
        reasons, seen = [], set()
        for f in self.findings:
            if (f.rule, f.tier) in seen:
                continue
            seen.add((f.rule, f.tier))
            reasons.append({"rule": f.rule, "tier": f.tier.label, "kind": f.kind, "reason": f.reason})
        return {
            "tier": self.tier.label,
            "tiers_detected": [t.label for t in self.tiers_detected],
            "reasons": reasons,
            "classifier": "local_rules_v1",
        }


@dataclass(frozen=True)
class Memory:
    id: str
    event_id: str
    event_ts: int
    created_at: int
    people: tuple[str, ...]
    projects: tuple[str, ...]
    topics: tuple[str, ...]
    summary: str  # always redacted
    sensitivity: Sensitivity
    tiers: tuple[Sensitivity, ...]
    flags: tuple[str, ...]
    explanation: dict
    extractor: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": iso(self.event_ts),
            "people": list(self.people),
            "projects": list(self.projects),
            "topics": list(self.topics),
            "summary": self.summary,
            "sensitivity": self.sensitivity.label,
            "tiers_detected": [t.label for t in self.tiers],
            "flags": list(self.flags),
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class RoutingDecision:
    route: str  # "local_ai" | "cloud_ai" | "blocked"
    action: str
    effective_sensitivity: str
    tiers_considered: tuple[str, ...]
    evaluation: tuple[dict, ...]
    reason: str
    policy_source: str
    payload_sha256: str = field(default="", repr=False)  # checked by egress, never printed

    def to_dict(self) -> dict:
        """Labels and reasons only, never payload text."""
        return {
            "route": self.route,
            "action": self.action,
            "effective_sensitivity": self.effective_sensitivity,
            "tiers_considered": list(self.tiers_considered),
            "reason": self.reason,
            "evaluation": list(self.evaluation),
            "policy_source": self.policy_source,
        }
