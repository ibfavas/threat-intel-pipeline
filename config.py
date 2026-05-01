"""Runtime configuration for the threat intel pipeline.

Environment variables override these defaults. Keep secrets in a local .env file
or shell environment; never commit API keys.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("TIP_DB_PATH", DATA_DIR / "threat_intel.db"))

URLHAUS_RECENT_URL = os.getenv(
    "TIP_URLHAUS_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/"
)
FEODO_IP_BLOCKLIST_URL = os.getenv(
    "TIP_FEODO_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
)

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_LIMIT = int(os.getenv("TIP_OTX_LIMIT", "100"))
OTX_MAX_PAGE = int(os.getenv("TIP_OTX_MAX_PAGE", "5"))
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

CONFIDENCE_THRESHOLD = float(os.getenv("TIP_CONFIDENCE_THRESHOLD", "60"))

SOURCE_WEIGHTS = {
    "feodo": 35,
    "urlhaus": 30,
    "otx": 20,
}

WAZUH_IP_LIST_PATH = Path(
    os.getenv("TIP_WAZUH_IP_LIST", "/var/ossec/etc/lists/threat-intel-ips")
)
WAZUH_DOMAIN_LIST_PATH = Path(
    os.getenv("TIP_WAZUH_DOMAIN_LIST", "/var/ossec/etc/lists/threat-intel-domains")
)
WAZUH_RELOAD_COMMAND = os.getenv(
    "TIP_WAZUH_RELOAD_COMMAND", "sudo /var/ossec/bin/ossec-control reload"
)

ABUSEIPDB_SLEEP_SECONDS = float(os.getenv("TIP_ABUSEIPDB_SLEEP", "1"))
VIRUSTOTAL_SLEEP_SECONDS = float(os.getenv("TIP_VT_SLEEP", "16"))
