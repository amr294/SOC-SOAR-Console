import os
from pathlib import Path

from database import Database
from soar_service import SOARService

os.environ["SOAR_DEMO_MODE"] = "1"


# ============================================================
# ISOLATED TEST DATABASE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
TEST_DB_PATH = BASE_DIR / "soar_service_test.db"


def check(condition, message):
    """
    Simple test assertion helper.
    """

    if not condition:
        raise AssertionError(
            f"FAILED: {message}"
        )

    print(
        f"  PASS: {message}"
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # 1. Start with a clean test database
    # --------------------------------------------------------

    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()

    database = Database(
        db_path=TEST_DB_PATH
    )

    service = SOARService(
        database=database,
        current_user="Analyst 01"
    )

    print()
    print("==========================================")
    print("SOAR SERVICE WORKFLOW TEST")
    print("==========================================")

    # --------------------------------------------------------
    # 2. Initialize
    # --------------------------------------------------------

    print()
    print("Initializing isolated test environment...")

    service.initialize()

    check(
        TEST_DB_PATH.exists(),
        "Isolated test database was created"
    )

    # --------------------------------------------------------
    # 3. Queue
    # --------------------------------------------------------

    print()
    print("Testing alert queue...")

    alerts = service.get_alert_queue()

    check(
        len(alerts) == 3,
        "Three seed alerts exist"
    )

    alt_1001 = service.get_alert(
        "ALT-1001"
    )

    check(
        alt_1001["state"] == "NEW",
        "ALT-1001 starts as NEW"
    )

    check(
        alt_1001["assignee"] == "Unassigned",
        "ALT-1001 starts unassigned"
    )

    # --------------------------------------------------------
    # 4. Claim
    # --------------------------------------------------------

    print()
    print("Testing claim workflow...")

    claimed = service.claim_alert(
        "ALT-1001",
        "Analyst 01"
    )

    check(
        claimed["state"] == "ASSIGNED",
        "Claim changes state to ASSIGNED"
    )

    check(
        claimed["assignee"] == "Analyst 01",
        "Alert is assigned to Analyst 01"
    )

    # --------------------------------------------------------
    # 5. Ownership protection
    # --------------------------------------------------------

    print()
    print("Testing ownership protection...")

    try:

        service.claim_alert(
            "ALT-1001",
            "Analyst 02"
        )

        raise AssertionError(
            "Analyst 02 was incorrectly allowed "
            "to claim ALT-1001"
        )

    except ValueError:

        print(
            "  PASS: Another analyst cannot claim "
            "an already assigned alert"
        )

    # --------------------------------------------------------
    # 6. Start investigation
    # --------------------------------------------------------

    print()
    print("Testing investigation workflow...")

    investigating = (
        service.start_investigation(
            "ALT-1001",
            "Analyst 01"
        )
    )

    check(
        investigating["state"]
        == "INVESTIGATING",
        "Alert changes to INVESTIGATING"
    )

    # --------------------------------------------------------
    # 7. Save investigation workspace
    # --------------------------------------------------------

    print()
    print(
        "Testing investigation workspace..."
    )

    saved = service.save_investigation(
        "ALT-1001",
        "Analyst 01",
        "Reviewed SSH authentication activity.",
        "Repeated failed SSH authentication attempts observed.",
        "Source IP 185.23.44.12 generated the activity."
    )

    check(
        saved["notes"]
        == "Reviewed SSH authentication activity.",
        "Investigation notes are persisted"
    )

    check(
        saved["findings"]
        == "Repeated failed SSH authentication attempts observed.",
        "Investigation findings are persisted"
    )

    check(
        saved["evidence"]
        == "Source IP 185.23.44.12 generated the activity.",
        "Investigation evidence is persisted"
    )

    # --------------------------------------------------------
    # 8. Cached IOC
    # --------------------------------------------------------

    print()
    print("Testing cached IOC behavior...")

    cached = service.request_ioc_enrichment(
        "185.23.44.12",
        "Analyst 01",
        "ALT-1001"
    )

    check(
        cached["request_id"] == 0,
        "Cached IOC does not create a new request"
    )

    check(
        cached["intelligence"]["status"]
        == "Cached Intelligence Available",
        "Cached intelligence remains available"
    )

    # --------------------------------------------------------
    # 9. Unknown IOC enrichment request
    # --------------------------------------------------------

    print()
    print(
        "Testing unknown IOC enrichment..."
    )

    enrichment = service.request_ioc_enrichment(
        "10.0.0.5",
        "Analyst 01",
        "ALT-1001"
    )

    request_id = enrichment["request_id"]

    check(
        request_id > 0,
        "Unknown IOC creates an enrichment request"
    )

    check(
        enrichment["intelligence"]["status"]
        == "Requested",
        "Unknown IOC changes to Requested"
    )

    # --------------------------------------------------------
    # 10. Duplicate enrichment request
    # --------------------------------------------------------

    print()
    print(
        "Testing duplicate enrichment protection..."
    )

    duplicate = service.request_ioc_enrichment(
        "10.0.0.5",
        "Analyst 01",
        "ALT-1001"
    )

    check(
        duplicate["request_id"] == request_id,
        "Duplicate request reuses existing request"
    )

    # --------------------------------------------------------
    # 11. Unauthorized investigation modification
    # --------------------------------------------------------

    print()
    print(
        "Testing investigation ownership protection..."
    )

    try:

        service.save_investigation(
            "ALT-1001",
            "Analyst 02",
            "Unauthorized notes",
            "Unauthorized findings",
            "Unauthorized evidence"
        )

        raise AssertionError(
            "Analyst 02 was incorrectly allowed "
            "to modify Analyst 01's investigation"
        )

    except PermissionError:

        print(
            "  PASS: Another analyst cannot modify "
            "the investigation"
        )

    # --------------------------------------------------------
    # 12. Escalation with mandatory report
    # --------------------------------------------------------

    print()
    print("Testing escalation workflow...")

    escalation = service.escalate_alert(
        alert_id="ALT-1001",
        analyst_username="Analyst 01",
        summary=(
            "Repeated SSH authentication failures "
            "were detected."
        ),
        evidence=(
            "Multiple failed authentication attempts "
            "originated from 185.23.44.12."
        ),
        findings=(
            "The source generated suspicious SSH "
            "authentication activity."
        ),
        recommendation=(
            "Block the source IP and investigate "
            "the targeted host."
        )
    )

    check(
        escalation["alert"]["state"]
        == "ESCALATED",
        "Alert changes to ESCALATED"
    )

    report = escalation["report"]

    check(
        report["alert_id"] == "ALT-1001",
        "Escalation report is linked to alert"
    )

    check(
        report["analyst_username"]
        == "Analyst 01",
        "Escalation report records the analyst"
    )

    # --------------------------------------------------------
    # 13. Reports
    # --------------------------------------------------------

    print()
    print("Testing report retrieval...")

    reports = service.get_reports()

    check(
        len(reports) == 1,
        "One escalation report exists"
    )

    report_by_id = service.get_report(
        report["id"]
    )

    check(
        report_by_id["id"] == report["id"],
        "Specific report can be retrieved"
    )

    # --------------------------------------------------------
    # 14. Second analyst workflow
    # --------------------------------------------------------

    print()
    print(
        "Testing second analyst workflow..."
    )

    service.start_investigation(
        "ALT-1003",
        "Analyst 02"
    )

    check(
        service.get_alert(
            "ALT-1003"
        )["state"] == "INVESTIGATING",
        "Analyst 02 can start own investigation"
    )

    # --------------------------------------------------------
    # 15. Close alert
    # --------------------------------------------------------

    print()
    print("Testing alert closure workflow...")

    closed = service.close_alert(
        alert_id="ALT-1003",
        analyst_username="Analyst 02",
        disposition="Benign",
        notes="Test closure by Analyst 02."
    )

    check(
        closed["state"] == "CLOSED",
        "Alert changes to CLOSED"
    )

    check(
        closed["disposition"] == "Benign",
        "Closing disposition is persisted"
    )

    # --------------------------------------------------------
    # 16. Unauthorized closure
    # --------------------------------------------------------

    print()
    print("Testing closure ownership protection...")

    try:

        service.close_alert(
            alert_id="ALT-1003",
            analyst_username="Analyst 01",
            disposition="Benign",
            notes="Unauthorized attempt"
        )

        raise AssertionError(
            "Analyst 01 was incorrectly allowed "
            "to close Analyst 02's alert"
        )

    except PermissionError:

        print(
            "  PASS: Analyst cannot close "
            "another analyst's alert"
        )

    # --------------------------------------------------------
    # 17. My Alerts
    # --------------------------------------------------------

    print()
    print("Testing My Alerts...")

    my_alerts = service.get_my_alerts(
        "Analyst 01"
    )

    my_ids = {
        alert["id"]
        for alert in my_alerts
    }

    check(
        "ALT-1001" in my_ids,
        "Analyst 01 sees owned alert"
    )

    # --------------------------------------------------------
    # 18. Audit log
    # --------------------------------------------------------

    print()
    print("Testing audit log...")

    audit = service.get_audit_log(
        alert_id="ALT-1001"
    )

    actions = {
        event["action"]
        for event in audit
    }

    check(
        "Alert Assigned" in actions,
        "Assignment generated an audit event"
    )

    check(
        "Investigation Started" in actions,
        "Investigation generated an audit event"
    )

    check(
        "Workspace Updated" in actions,
        "Workspace update generated an audit event"
    )

    check(
        "Enrichment Requested" in actions
        or "Enrichment Cache Reused" in actions,
        "IOC enrichment generated an audit event"
    )

    check(
        "Alert Escalated" in actions,
        "Escalation generated an audit event"
    )

    # --------------------------------------------------------
    # 19. Analyst statistics
    # --------------------------------------------------------

    print()
    print("Testing analyst statistics...")

    stats = service.get_analyst_stats()

    check(
        len(stats) == 3,
        "Statistics exist for all analysts"
    )

    # --------------------------------------------------------
    # 20. Availability
    # --------------------------------------------------------

    print()
    print("Testing analyst availability...")

    updated = service.set_analyst_availability(
        "Analyst 01",
        "Away / Offline"
    )

    check(
        updated["availability"]
        == "Away / Offline",
        "Analyst availability changes"
    )

    service.set_analyst_availability(
        "Analyst 01",
        "Available"
    )

    restored = service.get_analyst(
        "Analyst 01"
    )

    check(
        restored["availability"]
        == "Available",
        "Analyst availability can be restored"
    )

    # --------------------------------------------------------
    # 21. Final alert states
    # --------------------------------------------------------

    print()
    print("Final alert states:")

    for alert in service.get_alert_queue():

        print(
            f"  {alert['id']} | "
            f"{alert['severity']} | "
            f"{alert['state']} | "
            f"{alert['assignee']}"
        )

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    print()
    print("==========================================")
    print("ALL SOAR SERVICE TESTS PASSED")
    print("==========================================")
    print()
    print(
        f"Test database: {TEST_DB_PATH}"
    )