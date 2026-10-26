import json
import tempfile
from pathlib import Path

from database import Database
from wazuh_ingest import WazuhIngestor


SAMPLE_EVENT = {
    "timestamp": "2026-09-28T19:02:20.236+0000",
    "rule": {
        "level": 3,
        "description": "Apparmor DENIED",
        "id": "52002",
        "firedtimes": 2,
        "mail": False,
        "groups": [
            "local",
            "syslog",
            "apparmor"
        ]
    },
    "agent": {
        "id": "000",
        "name": "amr-server"
    },
    "manager": {
        "name": "amr-server"
    },
    "id": "1790622140.50839",
    "full_log": (
        'Sep 28 19:02:19 amr-server kernel: '
        'audit: type=1400 audit(1790622139.634:793): '
        'apparmor="DENIED" operation="open" class="file" '
        'profile="who" '
        'name="/usr/share/coreutils/locales/uucore/en-US.ftl" '
        'pid=3374487 comm="who" requested_mask="r" '
        'denied_mask="r" fsuid=0 ouid=0'
    ),
    "predecoder": {
        "program_name": "kernel",
        "timestamp": "Sep 28 19:02:19",
        "hostname": "amr-server"
    },
    "decoder": {
        "parent": "kernel",
        "name": "kernel"
    },
    "data": {
        "status": "DENIED",
        "extra_data": "open"
    },
    "location": "journald"
}


def main():
    base_dir = Path(__file__).resolve().parent
    schema_path = base_dir / "schema.sql"

    with tempfile.TemporaryDirectory() as temp_dir:
        test_db_path = Path(temp_dir) / "wazuh_ingest_test.db"

        database = Database(
            db_path=test_db_path,
            schema_path=schema_path
        )

        database.initialize()

        ingestor = WazuhIngestor(database)

        print()
        print("==========================================")
        print("WAZUH INGESTION TEST")
        print("==========================================")

        # ----------------------------------------------------
        # 1. Parse the event
        # ----------------------------------------------------

        normalized = ingestor.parse_event(SAMPLE_EVENT)

        print()
        print("Normalized event:")
        print(f"  Alert ID: {normalized['alert_id']}")
        print(f"  Source: {normalized['source']}")
        print(f"  Source Event ID: {normalized['source_event_id']}")
        print(f"  Rule ID: {normalized['rule_id']}")
        print(f"  Rule Description: {normalized['rule_desc']}")
        print(f"  Source Severity: {normalized['source_severity']}")
        print(f"  SOAR Severity: {normalized['severity']}")
        print(f"  Service: {normalized['service']}")
        print(f"  Action: {normalized['action']}")
        print(f"  Agent: {normalized['agent']}")
        print(f"  Event Timestamp: {normalized['event_timestamp']}")

        assert normalized["source"] == "Wazuh"
        assert normalized["source_event_id"] == "1790622140.50839"
        assert normalized["rule_id"] == "52002"
        assert normalized["rule_desc"] == "Apparmor DENIED"
        assert normalized["source_severity"] == 3
        assert normalized["severity"] == "LOW"
        assert normalized["service"] == "kernel"
        assert normalized["action"] == "DENIED"
        assert normalized["agent"] == "amr-server"
        assert (
            normalized["event_timestamp"]
            == "2026-09-28T19:02:20.236+0000"
        )

        # ----------------------------------------------------
        # 2. First ingestion
        # ----------------------------------------------------

        first_result = ingestor.ingest_event(SAMPLE_EVENT)

        print()
        print("First ingestion:")
        print(f"  Status: {first_result['status']}")
        print(f"  Alert ID: {first_result['alert_id']}")

        assert first_result["status"] == "created"
        assert first_result["created"] is True

        alert_id = first_result["alert_id"]

        # ----------------------------------------------------
        # 3. Verify database record
        # ----------------------------------------------------

        alert = database.get_alert(alert_id)

        assert alert is not None
        assert alert["source"] == "Wazuh"
        assert alert["source_event_id"] == "1790622140.50839"
        assert alert["rule_id"] == "52002"
        assert alert["rule_desc"] == "Apparmor DENIED"
        assert alert["source_severity"] == 3
        assert alert["severity"] == "LOW"
        assert alert["state"] == "NEW"
        assert alert["assigned_to"] is None
        assert alert["service"] == "kernel"
        assert alert["action"] == "DENIED"
        assert alert["agent"] == "amr-server"
        assert (
            alert["event_timestamp"]
            == "2026-09-28T19:02:20.236+0000"
        )

        print()
        print("Database verification:")
        print("  Alert successfully stored.")

        # ----------------------------------------------------
        # 4. Second ingestion must be a duplicate
        # ----------------------------------------------------

        second_result = ingestor.ingest_event(SAMPLE_EVENT)

        print()
        print("Second ingestion:")
        print(f"  Status: {second_result['status']}")
        print(f"  Alert ID: {second_result['alert_id']}")

        assert second_result["status"] == "duplicate"
        assert second_result["created"] is False
        assert second_result["alert_id"] == alert_id

        # ----------------------------------------------------
        # 5. Confirm only one alert exists
        # ----------------------------------------------------

        alerts = database.get_all_alerts()

        assert len(alerts) == 1

        print()
        print(f"Total alerts in test database: {len(alerts)}")

        print()
        print("==========================================")
        print("ALL WAZUH INGESTION TESTS PASSED")
        print("==========================================")


if __name__ == "__main__":
    main()