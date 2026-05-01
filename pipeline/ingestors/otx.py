from __future__ import annotations

from typing import Any

from config import OTX_API_KEY, OTX_LIMIT, OTX_MAX_PAGE
from pipeline.ingestors.base import BaseIngestor, IOCRecord


OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
}


class OTXIngestor(BaseIngestor):
    source = "otx"

    def __init__(
        self,
        api_key: str = OTX_API_KEY,
        limit: int = OTX_LIMIT,
        max_page: int = OTX_MAX_PAGE,
    ) -> None:
        self.api_key = api_key
        self.limit = limit
        self.max_page = max_page

    def fetch(self) -> list[dict[str, Any]]:
        if not self.api_key:
            raise RuntimeError("OTX_API_KEY is required for OTX ingestion")
        from OTXv2 import OTXv2

        client = OTXv2(self.api_key)
        pulses = client.getall(
            limit=self.limit,
            max_items=self.limit,
            max_page=self.max_page,
        )
        return pulses if isinstance(pulses, list) else pulses.get("results", [])

    def normalize(self, raw: list[dict[str, Any]]) -> list[IOCRecord]:
        records: list[IOCRecord] = []
        for pulse in raw:
            pulse_tags = pulse.get("tags") or []
            modified = pulse.get("modified") or pulse.get("created")
            for indicator in pulse.get("indicators", []):
                indicator_type = indicator.get("type")
                ioc_type = OTX_TYPE_MAP.get(indicator_type)
                value = (indicator.get("indicator") or "").strip()
                if not value or not ioc_type:
                    continue
                tags = sorted(set(pulse_tags + [indicator_type]))
                records.append(
                    self.make_record(
                        value=value,
                        ioc_type=ioc_type,
                        first_seen=pulse.get("created"),
                        last_seen=modified,
                        tags=tags,
                    )
                )
        return records
