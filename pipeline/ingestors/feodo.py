from __future__ import annotations

import csv
import io
import ipaddress

import requests

from config import FEODO_IP_BLOCKLIST_URL
from pipeline.ingestors.base import BaseIngestor, IOCRecord


class FeodoIngestor(BaseIngestor):
    source = "feodo"

    def __init__(self, endpoint: str = FEODO_IP_BLOCKLIST_URL, timeout: int = 30) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def fetch(self) -> str:
        response = requests.get(self.endpoint, timeout=self.timeout)
        response.raise_for_status()
        return response.text

    def normalize(self, raw: str) -> list[IOCRecord]:
        rows = (line for line in raw.splitlines() if line and not line.startswith("#"))
        reader = csv.DictReader(io.StringIO("\n".join(rows)))
        records: list[IOCRecord] = []

        for row in reader:
            ip = (row.get("dst_ip") or row.get("ip_address") or "").strip()
            if not self._is_ip(ip):
                continue
            malware = (row.get("malware") or row.get("malware_family") or "").strip()
            last_seen = row.get("last_online") or row.get("first_seen") or None
            tags = [malware] if malware else ["c2"]
            records.append(
                self.make_record(
                    value=ip,
                    ioc_type="ip",
                    first_seen=last_seen,
                    last_seen=last_seen,
                    tags=tags,
                )
            )

        return records

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

