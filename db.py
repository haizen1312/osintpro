"""Database facade for OSINTPRO.

SQLite remains the active zero-cost backend. PostgreSQL settings are exposed as
configuration metadata until a real migration is funded and executed.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import sqlite3

import server


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    with server.db() as connection:
        yield connection


def initialize() -> None:
    server.init_db()


def status() -> dict[str, object]:
    return server.database_status()


def postgres_preview() -> dict[str, object]:
    return server.postgres_settings()
