from __future__ import annotations

import json
import ipaddress
import shlex
import subprocess
from pathlib import Path

from config import (
    CONFIDENCE_THRESHOLD,
    WAZUH_DOMAIN_LIST_PATH,
    WAZUH_IP_LIST_PATH,
    WAZUH_RELOAD_COMMAND,
)
from pipeline.storage import IOCStorage


class IOCExporter:
    def __init__(self, storage: IOCStorage, threshold: float = CONFIDENCE_THRESHOLD) -> None:
        self.storage = storage
        self.threshold = threshold

    def export_wazuh(
        self,
        ip_path: str | Path | None = None,
        domain_path: str | Path | None = None,
        reload_wazuh: bool = False,
    ) -> dict[str, int]:
        ip_path = Path(ip_path) if ip_path else WAZUH_IP_LIST_PATH
        domain_path = Path(domain_path) if domain_path else WAZUH_DOMAIN_LIST_PATH
        rows = self.storage.high_confidence_iocs(self.threshold)
        ip_lines: list[str] = []
        domain_lines: list[str] = []

        for row in rows:
            label = self._label(row["tags"])
            line = f"{row['value']}:{label}"
            if row["type"] == "ip" or self._is_ip(row["value"]):
                ip_lines.append(line)
            elif row["type"] == "domain":
                domain_lines.append(line)

        self._write_lines(ip_path, ip_lines)
        self._write_lines(domain_path, domain_lines)

        if reload_wazuh:
            subprocess.run(shlex.split(WAZUH_RELOAD_COMMAND), check=True)

        return {"ips": len(ip_lines), "domains": len(domain_lines)}

    def report(self, limit: int = 20) -> str:
        rows = self.storage.top_iocs(limit)
        lines = [
            f"{'score':>6}  {'type':<7}  {'sources':<18}  {'last_seen':<25}  value",
            "-" * 90,
        ]
        for row in rows:
            lines.append(
                f"{row['confidence_score']:>6.1f}  {row['type']:<7}  "
                f"{(row['source'] or ''):<18}  {(row['last_seen'] or ''):<25}  "
                f"{row['value']}"
            )
        return "\n".join(lines)

    @staticmethod
    def _write_lines(path: Path, lines: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(sorted(set(lines))) + ("\n" if lines else ""))

    @staticmethod
    def _label(tags_json: str | None) -> str:
        try:
            tags = json.loads(tags_json or "[]")
        except json.JSONDecodeError:
            tags = []
        if tags:
            return str(tags[0]).replace(" ", "-").lower()
        return "threat-intel"

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
