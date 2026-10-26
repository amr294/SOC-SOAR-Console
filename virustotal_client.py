import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# ERRORS
# ============================================================

class VirusTotalError(Exception):
    """Base class for VirusTotal lookup failures."""


class VirusTotalConfigError(VirusTotalError):
    """No API key is configured."""


class VirusTotalAuthError(VirusTotalError):
    """The API key was rejected (HTTP 401/403)."""


class VirusTotalQuotaError(VirusTotalError):
    """Rate or quota limit hit (HTTP 429). Retry later."""


class VirusTotalNotFound(VirusTotalError):
    """VirusTotal has no record of this indicator (HTTP 404)."""


# ============================================================
# CLIENT
# ============================================================

class VirusTotalClient:
    """
    Minimal VirusTotal API v3 client.

    Supports: IPv4, IPv6, Domain, and file hashes (MD5/SHA1/SHA256).

    API key lookup order:
        1. api_key argument
        2. VT_API_KEY environment variable
        3. vt_api_key.txt next to this file (first line)

    The free public API allows roughly 4 requests/minute and
    500/day, so min_interval defaults to just over 15 seconds.
    Pacing is done by the caller (EnrichmentWorker).
    """

    BASE_URL = "https://www.virustotal.com/api/v3"
    GUI_URL = "https://www.virustotal.com/gui"
    KEY_FILE = Path(__file__).resolve().parent / "vt_api_key.txt"

    # Detection policy (tune to taste).
    # 1-2 engine detections are often false positives, so they
    # are labelled Suspicious rather than Malicious.
    MALICIOUS_THRESHOLD = 3

    _ENDPOINTS = {
        "IPv4": ("ip_addresses", "ip-address"),
        "IPv6": ("ip_addresses", "ip-address"),
        "Domain": ("domains", "domain"),
        "MD5": ("files", "file"),
        "SHA1": ("files", "file"),
        "SHA256": ("files", "file"),
    }

    def __init__(
        self,
        api_key=None,
        http_get=None,
        min_interval=15.5,
        timeout=20
    ):
        self.api_key = api_key or self._load_key()
        self._http_get = http_get or self._urllib_get
        self.min_interval = min_interval
        self.timeout = timeout

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    @classmethod
    def _load_key(cls):
        key = os.environ.get("VT_API_KEY", "").strip()

        if key:
            return key

        try:
            lines = cls.KEY_FILE.read_text(
                encoding="utf-8"
            ).splitlines()
        except OSError:
            return None

        for line in lines:
            line = line.strip()
            if line:
                return line

        return None

    @property
    def configured(self):
        return bool(self.api_key)

    @classmethod
    def supports(cls, ioc_type):
        return ioc_type in cls._ENDPOINTS

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    def _urllib_get(self, url, headers):
        """
        Returns (status_code, body_text).
        HTTP error codes are returned, not raised.
        """

        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET"
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout
            ) as response:
                return (
                    response.status,
                    response.read().decode("utf-8")
                )

        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            return exc.code, body

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise VirusTotalError(
                f"Network error contacting VirusTotal: {exc}"
            ) from exc

    # --------------------------------------------------------
    # Lookup
    # --------------------------------------------------------

    def lookup(self, ioc_type, value):
        """
        Query VirusTotal for one indicator.

        Returns a dict ready for Database.save_ioc_intelligence():
            reputation, score, first_seen, last_checked, raw_data

        Raises a VirusTotalError subclass on failure.
        """

        if not self.configured:
            raise VirusTotalConfigError(
                "VirusTotal API key not configured. Set the "
                "VT_API_KEY environment variable or create "
                "vt_api_key.txt next to the SOAR files."
            )

        if ioc_type not in self._ENDPOINTS:
            raise VirusTotalError(
                f"VirusTotal lookup is not supported for "
                f"IOC type: {ioc_type}"
            )

        collection, gui_path = self._ENDPOINTS[ioc_type]

        url = f"{self.BASE_URL}/{collection}/{value}"

        status, body = self._http_get(
            url,
            {
                "x-apikey": self.api_key,
                "accept": "application/json"
            }
        )

        if status in (401, 403):
            raise VirusTotalAuthError(
                f"VirusTotal rejected the API key (HTTP {status})."
            )

        if status == 404:
            raise VirusTotalNotFound(
                f"{value} is not known to VirusTotal."
            )

        if status == 429:
            raise VirusTotalQuotaError(
                "VirusTotal rate/quota limit reached (HTTP 429)."
            )

        if status != 200:
            raise VirusTotalError(
                f"Unexpected VirusTotal response: HTTP {status}"
            )

        try:
            attributes = json.loads(body)["data"]["attributes"]
        except (ValueError, KeyError, TypeError) as exc:
            raise VirusTotalError(
                "Malformed VirusTotal response."
            ) from exc

        return self.normalize(
            ioc_type,
            value,
            attributes,
            f"{self.GUI_URL}/{gui_path}/{value}"
        )

    # --------------------------------------------------------
    # Normalization
    # --------------------------------------------------------

    @staticmethod
    def _fmt_epoch(value):
        if not isinstance(value, (int, float)):
            return None

        try:
            return datetime.fromtimestamp(
                value,
                tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            return None

    @classmethod
    def normalize(cls, ioc_type, value, attributes, link):
        stats = attributes.get("last_analysis_stats") or {}

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        total = malicious + suspicious + harmless + undetected

        if malicious >= cls.MALICIOUS_THRESHOLD:
            reputation = "Malicious"
        elif malicious > 0 or suspicious > 0:
            reputation = "Suspicious"
        elif total > 0:
            reputation = "Clean"
        else:
            reputation = "Unknown"

        # VT only provides a first-seen style date for some types.
        if ioc_type in ("MD5", "SHA1", "SHA256"):
            first_seen = cls._fmt_epoch(
                attributes.get("first_submission_date")
            )
        elif ioc_type == "Domain":
            first_seen = cls._fmt_epoch(
                attributes.get("creation_date")
            )
        else:
            first_seen = None

        details = {
            "vt_link": link,
            "stats": stats,
            "vt_reputation": attributes.get("reputation"),
            "last_analysis_date": cls._fmt_epoch(
                attributes.get("last_analysis_date")
            ),
            "tags": attributes.get("tags"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "network": attributes.get("network"),
            "registrar": attributes.get("registrar"),
            "type_description": attributes.get("type_description"),
            "meaningful_name": attributes.get("meaningful_name"),
            "threat_label": (
                (attributes.get("popular_threat_classification") or {})
                .get("suggested_threat_label")
            ),
        }

        details = {
            k: v for k, v in details.items()
            if v not in (None, "", [], {})
        }

        return {
            "reputation": reputation,
            "score": f"{malicious}/{total}",
            "first_seen": first_seen,
            "last_checked": datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "raw_data": json.dumps(details, ensure_ascii=False)
        }
