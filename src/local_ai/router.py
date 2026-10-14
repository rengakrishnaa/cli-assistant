"""Local-first routing: decides where a payload may be processed, before it is serialized."""

from __future__ import annotations

import hashlib
from typing import Iterable

from .classifier import DEFAULT_UNMATCHED, scan
from .config import Settings
from .models import RoutingDecision, Sensitivity

LOCAL, CLOUD, BLOCKED = "local_ai", "cloud_ai", "blocked"
CLOUD_CONSENT = {
    Sensitivity.CONFIDENTIAL: "send_confidential_data_to_cloud",
    Sensitivity.PERSONAL: "send_personal_data_to_cloud",
    Sensitivity.SECRET: "send_secret_data_to_cloud",
}


def decide(payload: str, settings: Settings, *, inherited: Iterable[Sensitivity] = (),
           flags: Iterable[str] = (), prefer: str = "auto", action: str = "answer") -> RoutingDecision:
    if prefer not in ("auto", "local", "cloud"):
        raise ValueError("prefer must be auto, local or cloud")
    flags = set(flags)
    steps: list[dict] = []

    def step(check: str, passed: bool, detail: str) -> None:
        steps.append({"check": check, "passed": passed, "detail": detail})

    # Route the bytes, not the label: re-scan exactly what would leave the process.
    findings = scan(payload)
    leaked = sorted({f.rule for f in findings if f.kind == "value" and f.tier is Sensitivity.SECRET})
    tiers = set(inherited) | {f.tier for f in findings if f.tier is not Sensitivity.PUBLIC}
    if not tiers:
        tiers = {DEFAULT_UNMATCHED}
        step("label_present", False, "payload has no label; fail-closed default 'personal' applied")
    if len(tiers) > 1:
        tiers.discard(Sensitivity.PUBLIC)  # public only counts when it stands alone
    effective = max(tiers)

    def verdict(route: str, reason: str) -> RoutingDecision:
        return RoutingDecision(
            route=route,
            action=action,
            effective_sensitivity=effective.label,
            tiers_considered=tuple(t.label for t in sorted(tiers, reverse=True)),
            evaluation=tuple(steps),
            reason=reason,
            policy_source=settings.source_path,
            payload_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )

    # 1. Credential tripwire: raw credential material never reaches any model.
    if leaked:
        step("credential_tripwire", False, f"credential patterns in payload: {', '.join(leaked)}")
        return verdict(BLOCKED, "payload still contains credential material after redaction")
    step("credential_tripwire", True, "no credential values in the outbound payload")

    # 2. Caller preference.
    if prefer == "local":
        step("caller_preference", True, "caller asked for local processing")
        return verdict(LOCAL, "local processing requested")

    # 3. Global cloud switch.
    if not settings.cloud_ai_enabled:
        step("cloud_ai_enabled", False, "cloud_ai_enabled = false")
        if prefer == "cloud":
            return verdict(BLOCKED, "cloud was requested but cloud AI is disabled")
        return verdict(LOCAL, "cloud AI is disabled; processing stays on this machine")
    step("cloud_ai_enabled", True, "cloud_ai_enabled = true")

    # 4. Per-tier consent.
    denied = []
    for tier in sorted(tiers, reverse=True):
        consent_key = CLOUD_CONSENT.get(tier)
        if consent_key is None:
            step("tier:public", True, "public data needs no extra consent")
            continue
        allowed = getattr(settings, consent_key)
        step(f"tier:{tier.label}", allowed, f"{consent_key} = {str(allowed).lower()}")
        if not allowed:
            denied.append(tier.label)

    # 5. Injection quarantine.
    if "prompt_injection_suspected" in flags:
        step("injection_quarantine", False, "content flagged as possible prompt injection")
        denied.append("quarantined content")
    if denied:
        if prefer == "cloud":
            return verdict(BLOCKED, f"cloud was requested but is not permitted for: {', '.join(denied)}")
        return verdict(LOCAL, f"cloud not permitted for: {', '.join(denied)}; using local AI")
    return verdict(CLOUD, "every tier present is permitted for cloud AI")
