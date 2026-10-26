import json
import os
import tempfile
import time
from pathlib import Path

from backfill_iocs import backfill, clear_mock_intel
from database import Database
from enrichment_worker import EnrichmentWorker
from ioc_extractor import extract_iocs, is_public_ip
from soar_service import SOARService
from virustotal_client import (
    VirusTotalAuthError,
    VirusTotalClient,
    VirusTotalConfigError,
    VirusTotalError,
    VirusTotalNotFound,
    VirusTotalQuotaError,
)
from wazuh_ingest import WazuhIngestor

os.environ["SOAR_DEMO_MODE"] = "1"


def check(condition, message):
    if not condition:
        raise AssertionError(f"FAILED: {message}")

    print(f"  PASS: {message}")


def raises(exc_type, func, *args):
    try:
        func(*args)
    except exc_type:
        return True
    except Exception:
        return False

    return False


def vt_body(malicious=0, suspicious=0, harmless=0, undetected=0, **extra):
    attributes = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": 0,
        }
    }
    attributes.update(extra)

    return json.dumps({"data": {"attributes": attributes}})


class FakeVT:
    """Stands in for the network. Behaviour is switchable per test."""

    def __init__(self):
        self.calls = []
        self.response = (200, vt_body(malicious=7, harmless=60, undetected=3))

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        return self.response


def make_client(fake, key="test-key"):
    return VirusTotalClient(
        api_key=key,
        http_get=fake,
        min_interval=0
    )


if __name__ == "__main__":

    os.environ.pop("VT_API_KEY", None)

    print()
    print("==========================================")
    print("IOC ENRICHMENT TEST")
    print("==========================================")

    # --------------------------------------------------------
    # 1. IOC extraction
    # --------------------------------------------------------

    print()
    print("Testing IOC extraction...")

    check(
        extract_iocs("185.23.44.12", "10.0.0.5")
        == [("185.23.44.12", "IPv4")],
        "Public IP extracted, private IP ignored"
    )

    check(
        extract_iocs("127.0.0.1", "192.168.1.8") == [],
        "Loopback and RFC1918 produce no IOCs"
    )

    check(
        extract_iocs("8.8.8.8", "8.8.8.8") == [("8.8.8.8", "IPv4")],
        "Duplicate IOC is returned once"
    )

    check(
        extract_iocs("2606:4700:4700::1111")
        == [("2606:4700:4700::1111", "IPv6")],
        "Global IPv6 is extracted"
    )

    check(
        extract_iocs("not-an-ip", None) == [],
        "Garbage IP value is ignored"
    )

    sha256 = "a" * 64
    md5 = "B" * 32

    found = extract_iocs(
        None,
        None,
        {
            "syscheck": {
                "sha256_after": sha256,
                "md5_after": md5,
                "sha1_after": "xyz"
            }
        }
    )

    check(
        found == [(sha256, "SHA256"), (md5.lower(), "MD5")],
        "File hashes extracted from syscheck, bad hash ignored"
    )

    check(
        is_public_ip("8.8.8.8") and not is_public_ip("10.1.2.3"),
        "is_public_ip distinguishes public from private"
    )

    # --------------------------------------------------------
    # 2. VirusTotal client
    # --------------------------------------------------------

    print()
    print("Testing VirusTotal client...")

    fake = FakeVT()
    client = make_client(fake)

    fake.response = (
        200,
        vt_body(
            malicious=45,
            suspicious=2,
            harmless=30,
            undetected=12,
            country="RU",
            as_owner="Example AS"
        )
    )

    result = client.lookup("IPv4", "185.23.44.12")

    url, headers = fake.calls[-1]

    check(
        url.endswith("/ip_addresses/185.23.44.12"),
        "IPv4 lookup uses the ip_addresses endpoint"
    )
    check(
        headers.get("x-apikey") == "test-key",
        "API key sent in x-apikey header"
    )
    check(result["reputation"] == "Malicious", "45 detections -> Malicious")
    check(result["score"] == "45/89", "Score is malicious/total engines")
    check(
        json.loads(result["raw_data"])["country"] == "RU",
        "Extra context stored in raw_data"
    )
    check(
        "virustotal.com/gui/ip-address/185.23.44.12"
        in result["raw_data"],
        "raw_data includes the VirusTotal permalink"
    )

    fake.response = (200, vt_body(malicious=1, harmless=80, undetected=5))
    check(
        client.lookup("IPv4", "1.1.1.1")["reputation"] == "Suspicious",
        "1 detection -> Suspicious"
    )

    fake.response = (200, vt_body(harmless=70, undetected=15))
    check(
        client.lookup("Domain", "example.com")["reputation"] == "Clean",
        "No detections -> Clean"
    )

    fake.response = (200, vt_body())
    check(
        client.lookup("Domain", "example.com")["reputation"] == "Unknown",
        "No analysis data -> Unknown"
    )

    fake.response = (
        200,
        vt_body(malicious=10, first_submission_date=1700000000)
    )
    file_result = client.lookup("SHA256", sha256)
    check(
        file_result["first_seen"] == "2023-11-14 22:13:20"
        and fake.calls[-1][0].endswith(f"/files/{sha256}"),
        "File hash uses files endpoint and converts first_seen"
    )

    fake.response = (404, "{}")
    check(
        raises(VirusTotalNotFound, client.lookup, "IPv4", "1.2.3.4"),
        "HTTP 404 -> VirusTotalNotFound"
    )

    fake.response = (429, "{}")
    check(
        raises(VirusTotalQuotaError, client.lookup, "IPv4", "1.2.3.4"),
        "HTTP 429 -> VirusTotalQuotaError"
    )

    fake.response = (401, "{}")
    check(
        raises(VirusTotalAuthError, client.lookup, "IPv4", "1.2.3.4"),
        "HTTP 401 -> VirusTotalAuthError"
    )

    fake.response = (500, "oops")
    check(
        raises(VirusTotalError, client.lookup, "IPv4", "1.2.3.4"),
        "HTTP 500 -> VirusTotalError"
    )

    fake.response = (200, "not json")
    check(
        raises(VirusTotalError, client.lookup, "IPv4", "1.2.3.4"),
        "Malformed body -> VirusTotalError"
    )

    check(
        raises(VirusTotalError, client.lookup, "Email", "a@b.c"),
        "Unsupported IOC type is rejected"
    )

    check(
        raises(
            VirusTotalConfigError,
            make_client(fake, key=None).lookup,
            "IPv4",
            "8.8.8.8"
        ),
        "Missing API key -> VirusTotalConfigError"
    )

    os.environ["VT_API_KEY"] = "env-key"
    check(
        VirusTotalClient().api_key == "env-key",
        "API key read from VT_API_KEY"
    )
    os.environ.pop("VT_API_KEY")

    # --------------------------------------------------------
    # 3. Worker + service end to end
    # --------------------------------------------------------

    with tempfile.TemporaryDirectory() as tmp:

        database = Database(db_path=Path(tmp) / "enrich_test.db")

        service = SOARService(
            database=database,
            current_user="Analyst 01"
        )
        service.initialize()

        fake = FakeVT()
        worker = EnrichmentWorker(
            database,
            make_client(fake),
            poll_interval=0.05,
            quota_backoff=0.05
        )

        def intel(value):
            ioc = database.get_ioc_by_value(value)
            return database.get_ioc_intelligence(ioc["id"])

        def requests_for(value):
            ioc = database.get_ioc_by_value(value)
            return database.get_enrichment_requests(ioc_id=ioc["id"])

        def audit_actions():
            return [row["action"] for row in database.get_audit_log()]

        print()
        print("Testing worker: successful lookup...")

        database.add_ioc("8.8.8.8", "IPv4")

        service.request_ioc_enrichment("8.8.8.8", "Analyst 01")
        check(
            intel("8.8.8.8")["status"] == "Requested",
            "Request leaves IOC in Requested state"
        )

        check(worker.process_pending() == 1, "Worker handles one request")

        row = intel("8.8.8.8")
        check(
            row["status"] == "Cached Intelligence Available"
            and row["source"] == "VirusTotal"
            and row["reputation"] == "Malicious"
            and row["score"] == "7/70",
            "VirusTotal result cached on the IOC"
        )
        check(
            row["raw_data"] is not None and row["last_checked"],
            "raw_data and last_checked are stored"
        )
        check(
            requests_for("8.8.8.8")[0]["status"] == "Completed",
            "Enrichment request marked Completed"
        )
        check(
            "Enrichment Completed" in audit_actions(),
            "Completion written to the audit log"
        )

        calls_before = len(fake.calls)
        again = service.request_ioc_enrichment("8.8.8.8", "Analyst 01")
        worker.process_pending()
        check(
            again["request_id"] == 0 and len(fake.calls) == calls_before,
            "Cached IOC does not call VirusTotal again"
        )

        print()
        print("Testing worker: IOC unknown to VirusTotal...")

        database.add_ioc("1.2.3.4", "IPv4")
        fake.response = (404, "{}")
        service.request_ioc_enrichment("1.2.3.4", "Analyst 01")
        worker.process_pending()

        row = intel("1.2.3.4")
        check(
            row["status"] == "Cached Intelligence Available"
            and row["reputation"] == "Not Found",
            "404 is cached as 'Not Found', not treated as an error"
        )

        print()
        print("Testing worker: internal address...")

        fake.response = (200, vt_body(malicious=7, harmless=60, undetected=3))
        calls_before = len(fake.calls)

        service.request_ioc_enrichment("10.0.0.5", "Analyst 01")
        worker.process_pending()

        row = intel("10.0.0.5")
        check(
            row["reputation"] == "Internal"
            and row["source"] == "Local policy",
            "Private IP resolved locally"
        )
        check(
            len(fake.calls) == calls_before,
            "Private IP was never sent to VirusTotal"
        )

        print()
        print("Testing worker: rate limiting...")

        database.add_ioc("9.9.9.9", "IPv4")
        fake.response = (429, "{}")
        service.request_ioc_enrichment("9.9.9.9", "Analyst 01")

        check(worker.process_pending() == 0, "Quota hit resolves nothing")
        check(worker.quota_hit, "Worker records that it was rate limited")
        check(
            requests_for("9.9.9.9")[0]["status"] == "Requested"
            and intel("9.9.9.9")["status"] == "Requested",
            "Rate-limited request stays queued"
        )

        fake.response = (200, vt_body(harmless=70, undetected=15))
        check(worker.process_pending() == 1, "Queued request retried")
        check(
            intel("9.9.9.9")["reputation"] == "Clean",
            "Retry succeeds once quota is available"
        )

        print()
        print("Testing worker: failures and retry...")

        database.add_ioc("5.6.7.8", "IPv4")
        fake.response = (401, "{}")
        service.request_ioc_enrichment("5.6.7.8", "Analyst 01")
        worker.process_pending()

        check(
            intel("5.6.7.8")["status"] == "Failed"
            and requests_for("5.6.7.8")[0]["status"] == "Failed",
            "Auth error marks IOC and request Failed"
        )
        check(
            "Enrichment Failed" in audit_actions(),
            "Failure written to the audit log"
        )

        fake.response = (200, vt_body(malicious=5, harmless=50))
        retry = service.request_ioc_enrichment("5.6.7.8", "Analyst 01")
        check(
            retry["request_id"] != 0,
            "Analyst can retry a Failed IOC"
        )
        worker.process_pending()
        check(
            intel("5.6.7.8")["status"] == "Cached Intelligence Available",
            "Retry after failure succeeds"
        )

        print()
        print("Testing worker: no API key...")

        database.add_ioc("4.4.4.4", "IPv4")
        keyless = EnrichmentWorker(
            database,
            make_client(fake, key=None),
            poll_interval=0.05
        )
        service.request_ioc_enrichment("4.4.4.4", "Analyst 01")
        keyless.process_pending()

        check(
            intel("4.4.4.4")["status"] == "Failed"
            and "API key" in intel("4.4.4.4")["raw_data"],
            "Missing key fails clearly instead of hanging 'in progress'"
        )

        print()
        print("Testing worker: crash recovery...")

        database.add_ioc("3.3.3.3", "IPv4")
        service.request_ioc_enrichment("3.3.3.3", "Analyst 01")
        request_id = requests_for("3.3.3.3")[0]["id"]
        database.update_enrichment_request_status(
            request_id,
            "In Progress"
        )

        worker.recover_interrupted()
        check(
            requests_for("3.3.3.3")[0]["status"] == "Requested",
            "Request interrupted mid-lookup is re-queued"
        )
        worker.process_pending()

        print()
        print("Testing background thread...")

        database.add_ioc("2.2.2.2", "IPv4")
        worker.start()
        service.request_ioc_enrichment("2.2.2.2", "Analyst 01")

        deadline = time.time() + 5
        while time.time() < deadline:
            if intel("2.2.2.2")["status"] == "Cached Intelligence Available":
                break
            time.sleep(0.05)

        worker.stop()

        check(
            intel("2.2.2.2")["status"] == "Cached Intelligence Available",
            "Background thread fulfils a request on its own"
        )

        print()
        print("Testing startup seed does not clobber real results...")

        mock_before = intel("185.23.44.12")
        check(
            mock_before["raw_data"] is None,
            "185.23.44.12 starts with placeholder intelligence"
        )

        removed = clear_mock_intel(database)
        check(removed >= 1, "clear_mock_intel removes placeholder rows")
        check(
            intel("185.23.44.12") is None
            or intel("185.23.44.12")["status"] != "Cached Intelligence Available",
            "Placeholder intelligence cleared"
        )

        fake.response = (200, vt_body(malicious=9, harmless=50))
        service.request_ioc_enrichment("185.23.44.12", "Analyst 01")

        # (the earlier worker was stopped; use a fresh one)
        worker = EnrichmentWorker(
            database,
            make_client(fake),
            poll_interval=0.05
        )
        check(worker.process_pending() == 1, "Fresh worker processes the request")
        real = intel("185.23.44.12")

        service.initialize()  # what happens on every app launch

        after = intel("185.23.44.12")
        check(
            after["score"] == real["score"] == "9/59"
            and after["raw_data"] is not None,
            "Real VirusTotal result survives re-initialization"
        )

        # ----------------------------------------------------
        # 4. Ingest links IOCs
        # ----------------------------------------------------

        print()
        print("Testing ingest IOC linking...")

        ingestor = WazuhIngestor(database)

        event = {
            "id": "1700000000.1",
            "timestamp": "2026-10-02T01:00:00.000+0000",
            "rule": {"id": "5710", "level": 5, "description": "sshd: attempt"},
            "agent": {"name": "lab-host"},
            "decoder": {"name": "sshd"},
            "data": {"srcip": "45.33.32.156", "dstip": "192.168.1.8"}
        }

        outcome = ingestor.ingest_event(event)
        linked = [
            r["value"]
            for r in database.get_alert_iocs(outcome["alert_id"])
        ]
        check(
            linked == ["45.33.32.156"],
            "Public source IP linked, private destination skipped"
        )

        fim = dict(event)
        fim["id"] = "1700000000.2"
        fim["data"] = {}
        fim["syscheck"] = {"sha256_after": sha256}
        outcome = ingestor.ingest_event(fim)
        check(
            [r["value"] for r in database.get_alert_iocs(outcome["alert_id"])]
            == [sha256],
            "File hash from syscheck linked to the alert"
        )

        original_add_ioc = database.add_ioc

        def broken(*args, **kwargs):
            raise RuntimeError("disk on fire")

        database.add_ioc = broken
        lost = dict(event)
        lost["id"] = "1700000000.3"
        outcome = ingestor.ingest_event(lost)
        database.add_ioc = original_add_ioc

        check(
            outcome["created"]
            and database.get_alert(outcome["alert_id"]) is not None,
            "IOC failure never loses the alert"
        )

        # ----------------------------------------------------
        # 5. Backfill
        # ----------------------------------------------------

        print()
        print("Testing backfill of existing alerts...")

        database.add_alert(
            alert_id="ALT-OLD-1",
            source="Wazuh",
            rule_id="5710",
            rule_desc="old alert",
            severity="MEDIUM",
            state="NEW",
            assigned_to=None,
            source_event_id="old-1",
            source_severity=5,
            event_timestamp=None,
            src_ip="77.88.55.60",
            dst_ip="10.0.0.9",
            service="sshd",
            action=None,
            agent="lab-host",
            raw_event=json.dumps({"id": "old-1"})
        )

        scanned, new_iocs, links = backfill(database)
        check(
            database.get_ioc_by_value("77.88.55.60") is not None
            and [r["value"] for r in database.get_alert_iocs("ALT-OLD-1")]
            == ["77.88.55.60"],
            "Backfill links IOCs for alerts ingested earlier"
        )

        scanned2, new_iocs2, _ = backfill(database)
        check(new_iocs2 == 0, "Backfill is safe to run twice")

    print()
    print("==========================================")
    print("ALL ENRICHMENT TESTS PASSED")
    print("==========================================")
