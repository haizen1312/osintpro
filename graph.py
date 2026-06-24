"""Entity graph export facade."""

from __future__ import annotations

import server


def export_jsonld(graph: dict[str, object]) -> bytes:
    return server.graph_format_jsonld(graph)


def export_dot(graph: dict[str, object]) -> bytes:
    return server.graph_format_dot(graph)


def export_csv(graph: dict[str, object]) -> bytes:
    return server.graph_format_csv(graph)
