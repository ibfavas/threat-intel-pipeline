from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from config import SOURCE_WEIGHTS
from pipeline.storage import IOCStorage


class ConfidenceScorer:
    def __init__(self, storage: IOCStorage) -> None:
        self.storage = storage

    def score_all(self) -> int:
        updated = 0
        for row in self.storage.all_iocs():
            score = self.score_row(row)
            self.storage.update_score(row["id"], score)
            updated += 1
        self.storage.conn.commit()
        return updated

    def score_row(self, row) -> float:
        breakdown = self.score_breakdown(row)
        return min(sum(breakdown.values()), 100)

    def score_breakdown(self, row) -> dict[str, float]:
        recency_score = self._recency_score(row["last_seen"] or row["first_seen"])
        source_score = self._source_score(row["source"])
        corroboration_score = min(max(row["hit_count"] - 1, 0) * 5, 25)
        return {
            "recency": recency_score,
            "source": source_score,
            "corroboration": corroboration_score,
        }

    @staticmethod
    def _recency_score(date_value: str | None) -> float:
        if not date_value:
            return 0.0
        seen = parse_datetime(date_value)
        if seen is None:
            return 0.0
        age_days = max((datetime.now(timezone.utc) - seen).total_seconds() / 86400, 0)
        if age_days >= 30:
            return 0.0
        return round(40 * (1 - age_days / 30), 2)

    @staticmethod
    def _source_score(sources: str | None) -> float:
        if not sources:
            return 0.0
        return max(SOURCE_WEIGHTS.get(source, 0) for source in sources.split(","))


def parse_datetime(value: str) -> datetime | None:
    candidates = [value, value.replace("Z", "+00:00")]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None
