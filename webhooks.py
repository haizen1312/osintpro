"""Webhook notification facade."""

from __future__ import annotations

import sqlite3

import server


def clean_event(event_type: str) -> str:
    return server.clean_webhook_event(event_type)


def clean_url(url: str) -> str:
    return server.clean_webhook_url(url)


def trigger(
    connection: sqlite3.Connection,
    user_id: str,
    event_type: str,
    payload: dict[str, object],
) -> dict[str, int]:
    return server.deliver_user_webhooks(connection, user_id, event_type, payload)
