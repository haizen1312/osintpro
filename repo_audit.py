"""Repository Audit Lab facade."""

from __future__ import annotations

import server


class RepositoryAuditor:
    def audit(self, files: list[dict[str, object]], repository: str = "") -> dict[str, object]:
        return server.analyze_repository(files, repository)

    def sarif(self, audit: dict[str, object]) -> bytes:
        return server.format_sarif(audit)

    def dependency_advisories(self, files: list[tuple[str, str]]) -> list[dict[str, object]]:
        return server.dependency_advisories_for_files(files)
