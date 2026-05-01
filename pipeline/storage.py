from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from config import DB_PATH


class IOCStorage:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 30000")
        try:
            self.conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.OperationalError:
            pass
        self.init_db()

    def init_db(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                source TEXT,
                first_seen TEXT,
                last_seen TEXT,
                confidence_score REAL DEFAULT 0.0,
                hit_count INTEGER DEFAULT 1,
                enrichment TEXT,
                tags TEXT,
                UNIQUE(value, type)
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feed_runs (
                id INTEGER PRIMARY KEY,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                record_count INTEGER DEFAULT 0,
                error TEXT,
                ran_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def upsert_iocs(self, records: Iterable[dict[str, Any]]) -> int:
        count = 0
        for record in records:
            self.upsert_ioc(record)
            count += 1
        self.conn.commit()
        return count

    def upsert_ioc(self, record: dict[str, Any]) -> None:
        existing = self.get_ioc(record["value"], record["type"])
        if existing is None:
            self.conn.execute(
                """
                INSERT INTO iocs (
                    value, type, source, first_seen, last_seen, confidence_score,
                    hit_count, enrichment, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["value"],
                    record["type"],
                    record.get("source"),
                    record.get("first_seen"),
                    record.get("last_seen"),
                    record.get("confidence_score", 0.0),
                    1,
                    json.dumps(record.get("enrichment", {})),
                    json.dumps(record.get("tags", [])),
                ),
            )
            return

        sources = self._merge_csv(existing["source"], record.get("source"))
        tags = self._merge_json_list(existing["tags"], record.get("tags", []))
        seen_values = list(filter(None, [existing["last_seen"], record.get("last_seen")]))
        last_seen = max(seen_values) if seen_values else None
        hit_count = len([source for source in sources.split(",") if source])

        self.conn.execute(
            """
            UPDATE iocs
            SET source = ?, last_seen = ?, hit_count = ?, tags = ?
            WHERE value = ? AND type = ?
            """,
            (
                sources,
                last_seen,
                hit_count,
                json.dumps(tags),
                record["value"],
                record["type"],
            ),
        )

    def get_ioc(self, value: str, ioc_type: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM iocs WHERE value = ? AND type = ?", (value, ioc_type)
        ).fetchone()

    def all_iocs(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM iocs"))

    def high_confidence_iocs(self, threshold: float) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM iocs WHERE confidence_score >= ? ORDER BY confidence_score DESC",
                (threshold,),
            )
        )

    def top_iocs(self, limit: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM iocs ORDER BY confidence_score DESC, last_seen DESC LIMIT ?",
                (limit,),
            )
        )

    def update_score(self, ioc_id: int, score: float) -> None:
        self.conn.execute(
            "UPDATE iocs SET confidence_score = ? WHERE id = ?", (score, ioc_id)
        )

    def update_enrichment(self, ioc_id: int, enrichment: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE iocs SET enrichment = ? WHERE id = ?",
            (json.dumps(enrichment, sort_keys=True), ioc_id),
        )

    def log_feed_run(
        self, source: str, status: str, record_count: int = 0, error: str | None = None
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO feed_runs (source, status, record_count, error)
            VALUES (?, ?, ?, ?)
            """,
            (source, status, record_count, error),
        )
        self.conn.commit()

    def stats(self) -> dict[str, Any]:
        total = self.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        by_type = self.conn.execute(
            "SELECT type, COUNT(*) AS count FROM iocs GROUP BY type ORDER BY type"
        ).fetchall()
        by_source = self.conn.execute(
            "SELECT source, COUNT(*) AS count FROM iocs GROUP BY source ORDER BY count DESC"
        ).fetchall()
        feed_runs = self.conn.execute(
            """
            SELECT source, status, record_count, error, ran_at
            FROM feed_runs
            ORDER BY ran_at DESC
            LIMIT 10
            """
        ).fetchall()
        return {
            "total": total,
            "by_type": [dict(row) for row in by_type],
            "by_source": [dict(row) for row in by_source],
            "recent_feed_runs": [dict(row) for row in feed_runs],
        }

    @staticmethod
    def _merge_csv(existing: str | None, new_value: str | None) -> str:
        values = set(filter(None, (existing or "").split(",")))
        if new_value:
            values.add(new_value)
        return ",".join(sorted(values))

    @staticmethod
    def _merge_json_list(existing: str | None, new_values: list[str]) -> list[str]:
        try:
            values = set(json.loads(existing or "[]"))
        except json.JSONDecodeError:
            values = set()
        values.update(new_values or [])
        return sorted(str(value) for value in values if value)
