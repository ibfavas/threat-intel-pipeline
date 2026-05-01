from __future__ import annotations

import csv
import io
import ipaddress
from urllib.parse import urlparse

import requests

from config import URLHAUS_RECENT_URL
from pipeline.ingestors.base import BaseIngestor, IOCRecord


class URLHausIngestor(BaseIngestor):
    source = "urlhaus"

    def __init__(self, endpoint: str = URLHAUS_RECENT_URL, timeout: int = 30) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def fetch(self) -> str:
        response = requests.get(self.endpoint, timeout=self.timeout)
        response.raise_for_status()
        return response.text

    def normalize(self, raw: str) -> list[IOCRecord]:
        header = None
        rows = []
        for line in raw.splitlines():
            if not line:
                continue
            if line.startswith("# "):
                possible_header = line[2:].strip()
                if possible_header.startswith("id,dateadded,url,"):
                    header = possible_header.split(",")
                continue
            if line.startswith("#"):
                continue
            rows.append(line)

        reader = csv.DictReader(io.StringIO("\n".join(rows)), fieldnames=header)
        records: list[IOCRecord] = []

        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            tags = self._split_tags(row.get("tags", ""))
            first_seen = row.get("dateadded") or None
            records.append(
                self.make_record(
                    value=url,
                    ioc_type="url",
                    first_seen=first_seen,
                    last_seen=first_seen,
                    tags=tags,
                )
            )

            domain = urlparse(url).hostname
            if domain:
                derived_type = "ip" if self._is_ip(domain) else "domain"
                records.append(
                    self.make_record(
                        value=domain,
                        ioc_type=derived_type,
                        first_seen=first_seen,
                        last_seen=first_seen,
                        tags=tags,
                    )
                )

        return records

    @staticmethod
    def _split_tags(tags: str) -> list[str]:
        return [
            tag.strip()
            for tag in tags.split(",")
            if tag.strip() and tag.strip().lower() != "none"
        ]

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
