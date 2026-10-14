"""The ONLY function allowed to turn data into a cloud request body.

Any future HTTP client must take its bytes from here. Checks run at the last moment:
the verdict, a hash proving the payload is exactly what was routed, and a final credential scan.
"""

from __future__ import annotations

import hashlib
import json

from .classifier import scan
from .models import RoutingDecision, Sensitivity


class EgressDenied(PermissionError):
    pass


def build_cloud_request(payload: str, decision: RoutingDecision, *, model: str = "cloud-model") -> bytes:
    if decision.route != "cloud_ai":
        raise EgressDenied(f"routing verdict is '{decision.route}'")
    if hashlib.sha256(payload.encode("utf-8")).hexdigest() != decision.payload_sha256:
        raise EgressDenied("payload differs from the text that was routed")
    if any(f.kind == "value" and f.tier is Sensitivity.SECRET for f in scan(payload)):
        raise EgressDenied("credential material detected at serialization time")
    body = {"model": model, "input": payload,
            "metadata": {"sensitivity": decision.effective_sensitivity}}
    return json.dumps(body, ensure_ascii=False).encode("utf-8")
