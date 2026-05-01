from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any


IOCRecord = dict[str, Any]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class BaseIngestor(ABC):
    source: str

    @abstractmethod
    def fetch(self) -> Any:
        """Fetch raw feed data from the upstream source."""

    @abstractmethod
    def normalize(self, raw: Any) -> list[IOCRecord]:
        """Normalize raw feed data into the unified IOC model."""

    def ingest(self) -> list[IOCRecord]:
        raw = self.fetch()
        return self.normalize(raw)

    def make_record(
        self,
        *,
        value: str,
        ioc_type: str,
        first_seen: str | None = None,
        last_seen: str | None = None,
        tags: list[str] | None = None,
    ) -> IOCRecord:
        now = utc_now_iso()
        return {
            "value": value.strip(),
            "type": ioc_type,
            "source": self.source,
            "first_seen": first_seen or now,
            "last_seen": last_seen or first_seen or now,
            "confidence_score": 0.0,
            "hit_count": 1,
            "enrichment": {},
            "tags": sorted(set(tags or [])),
        }

