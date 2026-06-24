"""Stripe webhook facade."""

from __future__ import annotations

import server


def verify_signature(payload: bytes, header: str) -> bool:
    return server.verify_stripe_signature(payload, header)


def apply_event(event: dict[str, object]) -> dict[str, object]:
    return server.apply_stripe_event(event)
