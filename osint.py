"""Passive OSINT facade for domain, username and wallet analysis."""

from __future__ import annotations

import server


class OSINTService:
    def analyze_domain(self, target: str) -> dict[str, object]:
        return server.analyze(target)

    def analyze_username(self, username: str) -> dict[str, object]:
        return server.analyze_username(username)

    def analyze_wallet(self, address: str) -> dict[str, object]:
        return server.analyze_wallet(address)
