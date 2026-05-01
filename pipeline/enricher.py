from __future__ import annotations

import base64
import json
import time
from typing import Any

import requests

from config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_SLEEP_SECONDS,
    CONFIDENCE_THRESHOLD,
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_SLEEP_SECONDS,
)
from pipeline.storage import IOCStorage


class IOCEnricher:
    def __init__(
        self,
        storage: IOCStorage,
        threshold: float = CONFIDENCE_THRESHOLD,
        abuseipdb_key: str = ABUSEIPDB_API_KEY,
        virustotal_key: str = VIRUSTOTAL_API_KEY,
    ) -> None:
        self.storage = storage
        self.threshold = threshold
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key

    def enrich_high_confidence(
        self,
        limit: int | None = None,
        verbose: bool = False,
        ioc_type: str | None = None,
    ) -> int:
        rows = self.storage.high_confidence_iocs(self.threshold)
        if ioc_type:
            rows = [row for row in rows if row["type"] == ioc_type]
        if limit:
            rows = rows[:limit]

        updated = 0
        for row in rows:
            enrichment = self._existing_enrichment(row["enrichment"])

            if row["type"] == "ip":
                enrichment["asn"] = self._safe_call(self.enrich_ip_asn, row["value"])
                if self.abuseipdb_key:
                    enrichment["abuseipdb"] = self._safe_call(
                        self.enrich_abuseipdb, row["value"]
                    )
                    time.sleep(ABUSEIPDB_SLEEP_SECONDS)

            if row["type"] == "domain":
                enrichment["whois"] = self._safe_call(self.enrich_domain_whois, row["value"])

            if self.virustotal_key:
                enrichment["virustotal"] = self._safe_call(
                    self.enrich_virustotal, row["value"], row["type"]
                )
                time.sleep(VIRUSTOTAL_SLEEP_SECONDS)

            self.storage.update_enrichment(row["id"], enrichment)
            if verbose:
                print(self._enrichment_log_line(row["value"], enrichment))
            updated += 1

        self.storage.conn.commit()
        return updated

    def enrich_abuseipdb(self, ip: str) -> dict[str, Any]:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
        }

    def enrich_virustotal(self, value: str, ioc_type: str) -> dict[str, Any]:
        endpoint = self._virustotal_endpoint(value, ioc_type)
        response = requests.get(
            endpoint,
            headers={"x-apikey": self.virustotal_key},
            timeout=30,
        )
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation"),
        }

    def enrich_domain_whois(self, domain: str) -> dict[str, Any]:
        import whois

        result = whois.whois(domain)
        return {
            "registrar": self._json_safe(result.get("registrar")),
            "creation_date": self._json_safe(result.get("creation_date")),
            "expiration_date": self._json_safe(result.get("expiration_date")),
            "name_servers": self._json_safe(result.get("name_servers")),
        }

    def enrich_ip_asn(self, ip: str) -> dict[str, Any]:
        from ipwhois import IPWhois

        result = IPWhois(ip).lookup_rdap(depth=1)
        network = result.get("network") or {}
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country_code": result.get("asn_country_code"),
            "network_name": network.get("name"),
            "network_cidr": network.get("cidr"),
        }

    @staticmethod
    def _virustotal_endpoint(value: str, ioc_type: str) -> str:
        base = "https://www.virustotal.com/api/v3"
        if ioc_type == "ip":
            return f"{base}/ip_addresses/{value}"
        if ioc_type == "domain":
            return f"{base}/domains/{value}"
        if ioc_type == "hash":
            return f"{base}/files/{value}"
        if ioc_type == "url":
            encoded = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"{base}/urls/{encoded}"
        raise ValueError(f"Unsupported IOC type for VirusTotal: {ioc_type}")

    @staticmethod
    def _safe_call(func, *args) -> dict[str, Any]:
        try:
            return func(*args)
        except Exception as exc:
            return {"error": str(exc)}

    @staticmethod
    def _existing_enrichment(value: str | None) -> dict[str, Any]:
        try:
            return json.loads(value or "{}")
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, list):
            return [IOCEnricher._json_safe(item) for item in value]
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return value

    @staticmethod
    def _enrichment_log_line(value: str, enrichment: dict[str, Any]) -> str:
        abuse = enrichment.get("abuseipdb") or {}
        vt = enrichment.get("virustotal") or {}
        return (
            f"[+] Enriched {value}: "
            f"abuse_score={abuse.get('abuse_confidence_score', 'n/a')} "
            f"vt_malicious={vt.get('malicious', 'n/a')} "
            f"country={abuse.get('country_code', 'n/a')}"
        )
