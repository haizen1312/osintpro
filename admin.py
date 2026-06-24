"""Admin metrics facade."""

from __future__ import annotations

import server


def growth_metrics() -> dict[str, object]:
    return server.admin_growth_metrics()
