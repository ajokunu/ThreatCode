"""Offline vulnerability database (SQLite-backed)."""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default database location
DEFAULT_DB_DIR = Path.home() / ".cache" / "threatcode" / "vulndb"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "vulndb.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version_introduced TEXT DEFAULT '',
    version_fixed TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    cvss_score REAL DEFAULT 0.0,
    summary TEXT DEFAULT '',
    aliases TEXT DEFAULT '[]',
    references_json TEXT DEFAULT '[]',
    PRIMARY KEY (id, ecosystem, package)
);

CREATE INDEX IF NOT EXISTS idx_vuln_ecosystem_package
    ON vulnerabilities(ecosystem, package);

CREATE TABLE IF NOT EXISTS os_vulnerabilities (
    id TEXT NOT NULL,
    os_family TEXT NOT NULL,
    os_version TEXT NOT NULL,
    package TEXT NOT NULL,
    version_fixed TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    cvss_score REAL DEFAULT 0.0,
    summary TEXT DEFAULT '',
    PRIMARY KEY (id, os_family, os_version, package)
);

CREATE INDEX IF NOT EXISTS idx_os_vuln_lookup
    ON os_vulnerabilities(os_family, os_version, package);
"""


class VulnDB:
    """SQLite-backed vulnerability database."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH

    def _connect(self) -> sqlite3.Connection:
        """Create a connection to the database."""
        return sqlite3.connect(str(self.db_path))

    def exists(self) -> bool:
        """Check if the database file exists."""
        return self.db_path.exists()

    def status(self) -> dict[str, Any]:
        """Get database status info."""
        if not self.exists():
            return {"exists": False, "path": str(self.db_path)}

        size = self.db_path.stat().st_size
        conn = self._connect()
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
            row = cursor.fetchone()
            count = row[0] if row else 0
        except sqlite3.OperationalError:
            count = 0
        finally:
            conn.close()

        mtime = datetime.datetime.fromtimestamp(
            self.db_path.stat().st_mtime,
            tz=datetime.timezone.utc,
        )

        return {
            "exists": True,
            "path": str(self.db_path),
            "size_mb": round(size / (1024 * 1024), 2),
            "entry_count": count,
            "last_updated": mtime.isoformat(),
        }

    def init_db(self) -> None:
        """Initialize the database schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def insert_vulnerability(
        self,
        *,
        vuln_id: str,
        ecosystem: str,
        package: str,
        version_introduced: str = "",
        version_fixed: str = "",
        severity: str = "medium",
        cvss_score: float = 0.0,
        summary: str = "",
        aliases: list[str] | None = None,
        references: list[str] | None = None,
    ) -> None:
        """Insert or replace a vulnerability record."""
        conn = self._connect()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO vulnerabilities
                   (id, ecosystem, package, version_introduced, version_fixed,
                    severity, cvss_score, summary, aliases, references_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vuln_id,
                    ecosystem,
                    package,
                    version_introduced,
                    version_fixed,
                    severity,
                    cvss_score,
                    summary,
                    json.dumps(aliases or []),
                    json.dumps(references or []),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def query(self, ecosystem: str, package: str) -> list[dict[str, Any]]:
        """Query vulnerabilities for a specific package."""
        if not self.exists():
            return []

        conn = self._connect()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                """SELECT * FROM vulnerabilities
                   WHERE ecosystem = ? AND package = ?""",
                (ecosystem, package),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def query_os(self, os_family: str, os_version: str, package: str) -> list[dict[str, Any]]:
        """Query OS-specific vulnerabilities for a package."""
        if not self.exists():
            return []
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                """SELECT * FROM os_vulnerabilities
                   WHERE os_family = ? AND os_version = ? AND package = ?""",
                (os_family, os_version, package),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def bulk_insert_os(self, records: list[dict[str, Any]]) -> int:
        """Bulk insert OS advisory records. Returns count inserted."""
        if not records:
            return 0
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            count = 0
            for rec in records:
                conn.execute(
                    """INSERT OR REPLACE INTO os_vulnerabilities
                       (id, os_family, os_version, package, version_fixed,
                        severity, cvss_score, summary)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rec.get("id", ""),
                        rec.get("os_family", ""),
                        rec.get("os_version", ""),
                        rec.get("package", ""),
                        rec.get("version_fixed", ""),
                        rec.get("severity", "medium"),
                        rec.get("cvss_score", 0.0),
                        rec.get("summary", ""),
                    ),
                )
                count += 1
            conn.commit()
            return count
        finally:
            conn.close()

    def bulk_insert(self, records: list[dict[str, Any]]) -> int:
        """Bulk insert vulnerability records. Returns count inserted."""
        if not records:
            return 0

        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            count = 0
            for rec in records:
                conn.execute(
                    """INSERT OR REPLACE INTO vulnerabilities
                       (id, ecosystem, package, version_introduced, version_fixed,
                        severity, cvss_score, summary, aliases, references_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rec.get("id", ""),
                        rec.get("ecosystem", ""),
                        rec.get("package", ""),
                        rec.get("version_introduced", ""),
                        rec.get("version_fixed", ""),
                        rec.get("severity", "medium"),
                        rec.get("cvss_score", 0.0),
                        rec.get("summary", ""),
                        json.dumps(rec.get("aliases", [])),
                        json.dumps(rec.get("references", [])),
                    ),
                )
                count += 1
            conn.commit()
            return count
        finally:
            conn.close()
