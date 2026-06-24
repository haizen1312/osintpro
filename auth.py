"""Authentication facade for OSINTPRO tests and future route extraction."""

from __future__ import annotations

import sqlite3
import uuid

import server


class AuthService:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def register(self, nickname: str, password: str) -> dict[str, object]:
        normalized = server.normalize_nickname(nickname)
        hashed = server.password_hash(password)
        now = server.utc_now()
        user_id = str(uuid.uuid4())
        self.connection.execute(
            """
            INSERT INTO users (id, nickname, password_hash, plan, credits, created_at, updated_at)
            VALUES (?, ?, ?, 'Free', ?, ?, ?)
            """,
            (user_id, normalized, hashed, server.FREE_CREDITS, now, now),
        )
        return {"id": user_id, "nickname": normalized, "plan": "Free"}

    def authenticate(self, nickname: str, password: str) -> dict[str, object] | None:
        normalized = server.normalize_nickname(nickname)
        row = self.connection.execute(
            "SELECT * FROM users WHERE nickname = ?",
            (normalized,),
        ).fetchone()
        if not row or not server.verify_password(password, row["password_hash"]):
            return None
        return server.row_to_user(row)
