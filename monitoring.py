"""Monitoring facade for checks and notifications."""

from __future__ import annotations

import sqlite3

import server


def run_rows(connection: sqlite3.Connection, rows: list[sqlite3.Row]) -> dict[str, object]:
    return server.run_monitor_rows(connection, rows)


def email_body(domain: str, payload: dict[str, object]) -> str:
    return server.monitor_email_body(domain, payload)


def send_email(domain: str, payload: dict[str, object], recipient: str | None = None) -> tuple[bool, str]:
    return server.send_monitor_email(domain, payload, recipient)
