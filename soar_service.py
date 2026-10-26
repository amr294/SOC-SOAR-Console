import os
import uuid
from database import Database


class SOARService:
    """
    Application/service layer for the SOC SOAR platform.

    Responsibilities:
    - Apply SOAR workflow rules
    - Coordinate database operations
    - Validate analyst actions
    - Create audit events
    - Provide clean data for the GUI

    The GUI should call this service instead of directly
    manipulating the SQLite database.
    """

    def __init__(
        self,
        database=None,
        current_user="Analyst 01"
    ):
        """
        Initialize the SOAR service.

        current_user represents the analyst currently using
        the SOAR console.
        """

        self.database = database or Database()

        self.current_user = current_user

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def initialize(self):
        """
        Initialize the database and make sure prototype
        data exists.
        """

        self.database.initialize()
        self.database.seed_default_analysts()

        # Keep prototype records out of normal lab data by default.
        # Set SOAR_DEMO_MODE=1 to create the example alerts/IOCs used
        # for a local demonstration and by the standalone test scripts.
        demo_mode = os.environ.get("SOAR_DEMO_MODE", "").strip().lower()
        if demo_mode in {"1", "true", "yes", "on"}:
            self.database.seed_mock_alerts()
            self.database.seed_mock_iocs()

    # ========================================================
    # ANALYST OPERATIONS
    # ========================================================

    def get_analyst(self, username):
        """
        Retrieve an analyst by username.

        Raises:
            ValueError: if the analyst does not exist.
        """

        analyst = self.database.get_analyst_by_username(username)

        if analyst is None:
            raise ValueError(
                f"Analyst does not exist: {username}"
            )

        return analyst

    def get_all_analysts(self):
        """
        Return all analysts.
        """

        return self.database.get_all_analysts()

    def set_analyst_availability(
        self,
        username,
        availability
    ):
        """
        Update analyst availability and create an audit event.
        """

        analyst = self.get_analyst(
            username
        )

        valid_statuses = {
            "Available",
            "Away / Offline"
        }

        if availability not in valid_statuses:
            raise ValueError(
                f"Invalid availability: {availability}"
            )

        rows_updated = (
            self.database.update_analyst_availability(
                username,
                availability
            )
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to update availability "
                f"for {username}"
            )

        self.database.add_audit_event(
            action="Availability Change",
            analyst_id=analyst["id"],
            details=(
                f"Status set to {availability}"
            )
        )

        return self.get_analyst(
            username
        )

    # ========================================================
    # ALERT QUEUE
    # ========================================================

    def _build_alert_view(self, alert):
        """
        Convert a database alert record into the alert
        structure expected by the GUI.

        The GUI should not need to understand SQLite column
        names or database relationships.
        """

        alert_data = dict(alert)

        alert_id = alert_data["id"]

        # ----------------------------------------------------
        # Assigned analyst
        # ----------------------------------------------------

        alert_data["assignee"] = (
            alert_data["assigned_username"]
            if alert_data["assigned_username"]
            else "Unassigned"
        )

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        alert_data["timestamp"] = alert_data["created_at"]

        # ----------------------------------------------------
        # Investigation workspace
        # ----------------------------------------------------

        investigation = (
            self.database.get_investigation(
                alert_id
            )
        )

        if investigation:

            alert_data["notes"] = (
                investigation["notes"]
            )

            alert_data["findings"] = (
                investigation["findings"]
            )

            alert_data["evidence"] = (
                investigation["evidence"]
            )

        else:

            alert_data["notes"] = ""
            alert_data["findings"] = ""
            alert_data["evidence"] = ""

        # ----------------------------------------------------
        # IOCs
        # ----------------------------------------------------

        ioc_rows = (
            self.database.get_alert_iocs(
                alert_id
            )
        )

        alert_data["iocs"] = [
            row["value"]
            for row in ioc_rows
        ]

        # ----------------------------------------------------
        # Investigation timeline
        #
        # The timeline is derived from the audit log.
        # This avoids maintaining two separate histories.
        # ----------------------------------------------------

        audit_events = (
            self.database.get_audit_log(
                alert_id=alert_id
            )
        )

        timeline = []

        for event in reversed(audit_events):

            timeline.append(
                f"[{event['timestamp']}] "
                f"{event['action']} | "
                f"{event['details']}"
            )

        alert_data["timeline"] = timeline

        return alert_data

    def _build_queue_alert_view(self, alert):
        """
        Build the lightweight alert structure required by queue pages.

        Queue cards do not need investigation notes, IOC relationships, or
        audit history. Avoiding those extra lookups is important because the
        queue may contain many alerts.
        """

        alert_data = dict(alert)

        alert_data["assignee"] = (
            alert_data["assigned_username"]
            if alert_data["assigned_username"]
            else "Unassigned"
        )

        alert_data["timestamp"] = alert_data["created_at"]

        return alert_data

    def get_alert_queue(self):
        """
        Return lightweight alert data for queue pages.

        Raw event payloads and investigation-related records are not
        loaded for every queue item. They are loaded on demand when an
        analyst opens an alert.
        """

        alerts = self.database.get_alert_queue()

        return [
            self._build_queue_alert_view(alert)
            for alert in alerts
        ]

    def get_alert_count(self):
        """
        Return the total number of alerts currently stored.
        """

        return self.database.get_alert_count()

    def get_my_alerts(self, analyst_username=None):
        """
        Return alerts assigned to a specific analyst.

        If no username is provided, use the current service user.
        """

        username = (
            analyst_username
            if analyst_username
            else getattr(
                self,
                "current_user",
                None
            )
        )

        if username is None:
            raise ValueError(
                "Analyst username is required."
            )

        analyst = self.get_analyst(
            username
        )

        alerts = self.database.get_alert_queue()

        my_alerts = [
            alert
            for alert in alerts
            if alert["assigned_to"] == analyst["id"]
        ]

        return [
            self._build_queue_alert_view(alert)
            for alert in my_alerts
        ]

    def get_alert(self, alert_id):
        """
        Retrieve one alert in GUI-ready form.

        Raises:
            ValueError: if the alert does not exist.
        """

        alert = self.database.get_alert(
            alert_id
        )

        if alert is None:
            raise ValueError(
                f"Alert does not exist: {alert_id}"
            )

        return self._build_alert_view(
            alert
        )

    # ========================================================
    # ALERT CLAIMING
    # ========================================================

    def claim_alert(
        self,
        alert_id,
        analyst_username
    ):
        """
        Claim an unassigned NEW alert.

        Workflow:

            NEW + Unassigned
                    ↓
                 ASSIGNED

        The analyst who successfully claims the alert
        becomes its assigned analyst.

        An alert already assigned to another analyst
        cannot be claimed.

        Returns:
            Updated alert as a dictionary.
        """

        analyst = self.get_analyst(
            analyst_username
        )

        alert = self.get_alert(alert_id)

        # ----------------------------------------------------
        # Validate current alert state.
        # ----------------------------------------------------

        if alert["state"] != "NEW":
            raise ValueError(
                f"Alert {alert_id} cannot be claimed "
                f"because its state is {alert['state']}."
            )

        if alert["assigned_to"] is not None:
            raise ValueError(
                f"Alert {alert_id} is already assigned "
                f"to {alert['assigned_username']}."
            )

        # ----------------------------------------------------
        # Assign the alert.
        # ----------------------------------------------------

        rows_updated = self.database.assign_alert(
            alert_id,
            analyst["id"]
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to claim alert {alert_id}. "
                "The alert may have been claimed by "
                "another analyst."
            )

        # ----------------------------------------------------
        # Record the action in the audit log.
        # ----------------------------------------------------

        self.database.add_audit_event(
            action="Alert Assigned",
            analyst_id=analyst["id"],
            alert_id=alert_id,
            details=(
                f"Alert assigned to "
                f"{analyst['username']}"
            )
        )

        # ----------------------------------------------------
        # Return the updated alert.
        # ----------------------------------------------------

        return self.get_alert(alert_id)

    # ========================================================
    # INVESTIGATION WORKFLOW
    # ========================================================

    def start_investigation(
        self,
        alert_id,
        analyst_username
    ):
        """
        Start investigating an assigned alert.

        Workflow:

            ASSIGNED
                ↓
            INVESTIGATING

        The alert must be assigned to the analyst
        requesting the investigation.
        """

        analyst = self.get_analyst(
            analyst_username
        )

        alert = self.get_alert(alert_id)

        # ----------------------------------------------------
        # Validate state.
        # ----------------------------------------------------

        if alert["state"] != "ASSIGNED":
            raise ValueError(
                f"Alert {alert_id} cannot start investigation "
                f"because its state is {alert['state']}."
            )

        # ----------------------------------------------------
        # Validate ownership.
        # ----------------------------------------------------

        if alert["assigned_to"] != analyst["id"]:
            raise PermissionError(
                f"Alert {alert_id} is assigned to "
                f"{alert['assigned_username']}, not "
                f"{analyst['username']}."
            )

        # ----------------------------------------------------
        # Update workflow state.
        # ----------------------------------------------------

        rows_updated = (
            self.database.update_alert_state(
                alert_id,
                "INVESTIGATING"
            )
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to start investigation "
                f"for {alert_id}."
            )

        # ----------------------------------------------------
        # Create investigation workspace.
        # ----------------------------------------------------

        self.database.create_investigation(
            alert_id
        )

        # ----------------------------------------------------
        # Record audit event.
        # ----------------------------------------------------

        self.database.add_audit_event(
            action="Investigation Started",
            analyst_id=analyst["id"],
            alert_id=alert_id,
            details=(
                f"{analyst['username']} started "
                f"investigating alert"
            )
        )

        return self.get_alert(alert_id)

    # ========================================================
    # INVESTIGATION WORKSPACE
    # ========================================================

    def get_investigation(self, alert_id):
        """
        Retrieve the investigation workspace for an alert.
        """

        alert = self.get_alert(alert_id)

        investigation = self.database.get_investigation(
            alert_id
        )

        if investigation is None:
            raise ValueError(
                f"No investigation exists for alert {alert_id}."
            )

        return dict(investigation)

    def save_investigation(
        self,
        alert_id,
        analyst_username,
        notes,
        findings,
        evidence
    ):
        """
        Save analyst investigation notes, findings,
        and evidence.

        The alert must be assigned to the requesting analyst.
        """

        analyst = self.get_analyst(
            analyst_username
        )

        alert = self.get_alert(alert_id)

        # ----------------------------------------------------
        # Validate ownership.
        # ----------------------------------------------------

        if alert["assigned_to"] != analyst["id"]:
            raise PermissionError(
                f"Alert {alert_id} is assigned to "
                f"{alert['assigned_username']}, not "
                f"{analyst['username']}."
            )

        # ----------------------------------------------------
        # Make sure the investigation exists.
        # ----------------------------------------------------

        investigation = self.database.get_investigation(
            alert_id
        )

        if investigation is None:
            raise ValueError(
                f"No investigation workspace exists for "
                f"{alert_id}."
            )

        # ----------------------------------------------------
        # Save the workspace.
        # ----------------------------------------------------

        rows_updated = (
            self.database.save_investigation(
                alert_id,
                notes,
                findings,
                evidence
            )
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to save investigation "
                f"for {alert_id}."
            )

        # ----------------------------------------------------
        # Record audit event.
        # ----------------------------------------------------

        self.database.add_audit_event(
            action="Workspace Updated",
            analyst_id=analyst["id"],
            alert_id=alert_id,
            details=(
                f"{analyst['username']} updated "
                f"the investigation workspace"
            )
        )

        return self.get_investigation(
            alert_id
        )

    # ========================================================
    # IOC INTELLIGENCE
    # ========================================================

    def get_ioc_intelligence(
        self,
        ioc_value=None
    ):
        """
        Return IOC intelligence in the structure expected
        by the GUI.

        If ioc_value is supplied:
            return one IOC.

        Otherwise:
            return all known IOCs keyed by IOC value.
        """

        if ioc_value is not None:

            ioc = self.database.get_ioc_by_value(
                ioc_value
            )

            if ioc is None:
                raise ValueError(
                    f"IOC does not exist: {ioc_value}"
                )

            intelligence = (
                self.database.get_ioc_intelligence(
                    ioc["id"]
                )
            )

            if intelligence is None:

                return {
                    "type": ioc["type"],
                    "status": "Unknown",
                    "reputation": "N/A",
                    "source": "N/A",
                    "score": "N/A",
                    "first_seen": "N/A",
                    "last_checked": "N/A"
                }

            return {
                "type": intelligence["type"],
                "status": intelligence["status"],
                "reputation": (
                    intelligence["reputation"]
                    or "N/A"
                ),
                "source": (
                    intelligence["source"]
                    or "N/A"
                ),
                "score": (
                    intelligence["score"]
                    or "N/A"
                ),
                "first_seen": (
                    intelligence["first_seen"]
                    or "N/A"
                ),
                "last_checked": (
                    intelligence["last_checked"]
                    or "N/A"
                )
            }

        # ----------------------------------------------------
        # Return all IOCs
        # ----------------------------------------------------

        result = {}

        for ioc in self.database.get_all_iocs():

            intelligence = (
                self.database.get_ioc_intelligence(
                    ioc["id"]
                )
            )

            if intelligence:

                result[ioc["value"]] = {
                    "type": intelligence["type"],
                    "status": intelligence["status"],
                    "reputation": (
                        intelligence["reputation"]
                        or "N/A"
                    ),
                    "source": (
                        intelligence["source"]
                        or "N/A"
                    ),
                    "score": (
                        intelligence["score"]
                        or "N/A"
                    ),
                    "first_seen": (
                        intelligence["first_seen"]
                        or "N/A"
                    ),
                    "last_checked": (
                        intelligence["last_checked"]
                        or "N/A"
                    )
                }

            else:

                result[ioc["value"]] = {
                    "type": ioc["type"],
                    "status": "Unknown",
                    "reputation": "N/A",
                    "source": "N/A",
                    "score": "N/A",
                    "first_seen": "N/A",
                    "last_checked": "N/A"
                }

        return result

    # ========================================================
    # IOC ENRICHMENT
    # ========================================================

    def request_ioc_enrichment(
        self,
        ioc_value,
        analyst_username,
        alert_id=None
    ):
        """
        Request enrichment for an IOC.

        Human-in-the-loop:
        the analyst explicitly requests the operation.

        If alert_id is supplied, the analyst must own
        that alert.

        Cached intelligence is reused automatically by
        the database layer.
        """

        analyst = self.get_analyst(
            analyst_username
        )

        # ----------------------------------------------------
        # Validate alert ownership when applicable.
        # ----------------------------------------------------

        if alert_id is not None:

            alert = self.get_alert(
                alert_id
            )

            if alert["assigned_to"] != analyst["id"]:
                raise PermissionError(
                    f"Alert {alert_id} is assigned to "
                    f"{alert['assignee']}, not "
                    f"{analyst['username']}."
                )

            if alert["state"] in {
                "CLOSED",
                "ESCALATED"
            }:
                raise ValueError(
                    f"Alert {alert_id} is already "
                    f"{alert['state']}."
                )

        # ----------------------------------------------------
        # IOC must already exist.
        #
        # IOC extraction will create IOC records later.
        # Enrichment should operate on normalized IOCs.
        # ----------------------------------------------------

        ioc = self.database.get_ioc_by_value(
            ioc_value
        )

        if ioc is None:
            raise ValueError(
                f"IOC does not exist: {ioc_value}"
            )

        # ----------------------------------------------------
        # Ask database layer to create/reuse request.
        # ----------------------------------------------------

        request_id = (
            self.database.create_enrichment_request(
                ioc_id=ioc["id"],
                alert_id=alert_id,
                analyst_id=analyst["id"]
            )
        )

        # ----------------------------------------------------
        # Determine what happened.
        # ----------------------------------------------------

        if request_id == 0:

            message = (
                f"Cached intelligence reused "
                f"for IOC {ioc_value}"
            )

            action = "Enrichment Cache Reused"

        else:

            message = (
                f"Enrichment requested "
                f"for IOC {ioc_value}"
            )

            action = "Enrichment Requested"

        # ----------------------------------------------------
        # Audit the action.
        # ----------------------------------------------------

        self.database.add_audit_event(
            action=action,
            analyst_id=analyst["id"],
            alert_id=alert_id,
            details=message
        )

        return {
            "ioc": ioc_value,
            "request_id": request_id,
            "intelligence": self.get_ioc_intelligence(
                ioc_value
            )
        }

        # ========================================================
    # ALERT CLOSURE
    # ========================================================

    def close_alert(
        self,
        alert_id,
        analyst_username,
        disposition,
        notes=""
    ):
        """
        Close an alert owned by the analyst.

        Closing requires:
        - ownership
        - valid disposition
        - alert not already closed/escalated
        """

        analyst = self.get_analyst(
            analyst_username
        )

        alert = self.get_alert(
            alert_id
        )

        # ----------------------------------------------------
        # Ownership validation
        # ----------------------------------------------------

        if alert["assigned_to"] != analyst["id"]:
            raise PermissionError(
                f"Alert {alert_id} is assigned to "
                f"{alert['assignee']}, not "
                f"{analyst['username']}."
            )

        # ----------------------------------------------------
        # State validation
        # ----------------------------------------------------

        if alert["state"] in {
            "CLOSED",
            "ESCALATED"
        }:
            raise ValueError(
                f"Alert {alert_id} is already "
                f"{alert['state']}."
            )

        # ----------------------------------------------------
        # Validate disposition
        # ----------------------------------------------------

        valid_dispositions = {
            "True Positive",
            "False Positive",
            "Benign",
            "Duplicate",
            "Other"
        }

        if disposition not in valid_dispositions:
            raise ValueError(
                f"Invalid disposition: {disposition}"
            )

        # ----------------------------------------------------
        # Save disposition
        # ----------------------------------------------------

        rows_updated = (
            self.database.update_alert_disposition(
                alert_id,
                disposition
            )
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to save disposition "
                f"for {alert_id}."
            )

        # ----------------------------------------------------
        # Change workflow state
        # ----------------------------------------------------

        rows_updated = (
            self.database.update_alert_state(
                alert_id,
                "CLOSED"
            )
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to close alert {alert_id}."
            )

        # ----------------------------------------------------
        # Build audit details
        # ----------------------------------------------------

        details = (
            f"Closed as {disposition}"
        )

        if notes:
            details += (
                f" | Closing notes: {notes}"
            )

        # ----------------------------------------------------
        # Record audit event
        # ----------------------------------------------------

        self.database.add_audit_event(
            action="Alert Closed",
            analyst_id=analyst["id"],
            alert_id=alert_id,
            details=details
        )

        return self.get_alert(
            alert_id
        )


    # ========================================================
    # ALERT ESCALATION
    # ========================================================

    def escalate_alert(
        self,
        alert_id,
        analyst_username,
        summary,
        evidence,
        findings,
        recommendation
    ):
        """
        Escalate an alert with a mandatory investigation report.

        Required:
        - ownership
        - INVESTIGATING state
        - all report sections
        """

        analyst = self.get_analyst(
            analyst_username
        )

        alert = self.get_alert(
            alert_id
        )

        # ----------------------------------------------------
        # Ownership validation
        # ----------------------------------------------------

        if alert["assigned_to"] != analyst["id"]:
            raise PermissionError(
                f"Alert {alert_id} is assigned to "
                f"{alert['assignee']}, not "
                f"{analyst['username']}."
            )

        # ----------------------------------------------------
        # Escalation requires active investigation
        # ----------------------------------------------------

        if alert["state"] != "INVESTIGATING":
            raise ValueError(
                f"Alert {alert_id} cannot be escalated "
                f"from state {alert['state']}."
            )

        # ----------------------------------------------------
        # Validate mandatory report fields
        # ----------------------------------------------------

        report_fields = {
            "summary": summary,
            "evidence": evidence,
            "findings": findings,
            "recommendation": recommendation
        }

        for field_name, value in report_fields.items():

            if not value or len(value.strip()) <= 5:
                raise ValueError(
                    f"{field_name.title()} is required "
                    f"for escalation."
                )

        # ----------------------------------------------------
        # Generate report ID
        # ----------------------------------------------------

        report_id = (
            f"REP-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

        # ----------------------------------------------------
        # Create report
        # ----------------------------------------------------

        self.database.add_report(
            report_id=report_id,
            alert_id=alert_id,
            analyst_id=analyst["id"],
            severity=alert["severity"],
            status="Awaiting Management",
            summary=summary.strip(),
            evidence=evidence.strip(),
            findings=findings.strip(),
            recommendation=recommendation.strip()
        )

        # ----------------------------------------------------
        # Change alert state
        # ----------------------------------------------------

        rows_updated = (
            self.database.update_alert_state(
                alert_id,
                "ESCALATED"
            )
        )

        if rows_updated != 1:
            raise RuntimeError(
                f"Failed to escalate alert {alert_id}."
            )

        # ----------------------------------------------------
        # Record audit event
        # ----------------------------------------------------

        self.database.add_audit_event(
            action="Alert Escalated",
            analyst_id=analyst["id"],
            alert_id=alert_id,
            details=(
                f"Escalated to management. "
                f"Report {report_id} created."
            )
        )

        return {
            "alert": self.get_alert(
                alert_id
            ),
            "report": dict(
                self.database.get_report(
                    report_id
                )
            )
        }


    # ========================================================
    # REPORTS
    # ========================================================

    def get_reports(
        self,
        alert_id=None,
        analyst_username=None
    ):
        """
        Retrieve reports for the GUI.
        """

        analyst_id = None

        if analyst_username:

            analyst = self.get_analyst(
                analyst_username
            )

            analyst_id = analyst["id"]

        reports = self.database.get_reports(
            alert_id=alert_id,
            analyst_id=analyst_id
        )

        return [
            dict(report)
            for report in reports
        ]

    def get_report(self, report_id):
        """
        Retrieve one report.
        """

        report = self.database.get_report(
            report_id
        )

        if report is None:
            raise ValueError(
                f"Report does not exist: {report_id}"
            )

        return dict(report)


    # ========================================================
    # AUDIT LOG
    # ========================================================

    def get_audit_log(
        self,
        alert_id=None,
        analyst_username=None
    ):
        """
        Retrieve audit events for the GUI.
        """

        analyst_id = None

        if analyst_username:

            analyst = self.get_analyst(
                analyst_username
            )

            analyst_id = analyst["id"]

        events = self.database.get_audit_log(
            alert_id=alert_id,
            analyst_id=analyst_id
        )

        return [
            {
                "time": event["timestamp"],
                "user": (
                    event["analyst_username"]
                    or "SYSTEM"
                ),
                "action": event["action"],
                "alert_id": (
                    event["alert_id"]
                    or "N/A"
                ),
                "details": (
                    event["details"]
                    or ""
                )
            }
            for event in events
        ]


    # ========================================================
    # ANALYST STATISTICS
    # ========================================================

    def get_analyst_stats(self):
        """
        Calculate workload statistics for every analyst.

        Availability comes from analysts.

        Workload comes from alerts/reports.

        These concepts remain separate.
        """

        analysts = (
            self.database.get_all_analysts()
        )

        alerts = (
            self.database.get_all_alerts()
        )

        reports = (
            self.database.get_reports()
        )

        stats = []

        for analyst in analysts:

            analyst_id = analyst["id"]

            assigned = sum(
                1
                for alert in alerts
                if alert["assigned_to"] == analyst_id
                and alert["state"] == "ASSIGNED"
            )

            investigating = sum(
                1
                for alert in alerts
                if alert["assigned_to"] == analyst_id
                and alert["state"] == "INVESTIGATING"
            )

            closed = sum(
                1
                for alert in alerts
                if alert["assigned_to"] == analyst_id
                and alert["state"] == "CLOSED"
            )

            escalated = sum(
                1
                for report in reports
                if report["analyst_id"] == analyst_id
            )

            stats.append(
                (
                    analyst["username"],
                    analyst["availability"],
                    assigned,
                    investigating,
                    closed,
                    escalated
                )
            )

        return stats
    # ========================================================
    # TEST / DEMONSTRATION
    # ========================================================


if __name__ == "__main__":

    service = SOARService()

    service.initialize()

    print()
    print("==========================================")
    print("SOC SOAR SERVICE TEST")
    print("==========================================")

    # --------------------------------------------------------
    # 1. Test analyst
    # --------------------------------------------------------

    analyst_username = "Analyst 01"

    analyst = service.get_analyst(
        analyst_username
    )

    print()
    print("Current analyst:")
    print(
        f"  {analyst['username']} "
        f"(ID {analyst['id']})"
    )

    # --------------------------------------------------------
    # 2. Display current alert queue
    # --------------------------------------------------------

    print()
    print("Current alert queue:")

    alerts = service.get_alert_queue()

    for alert in alerts:

        assigned_to = (
            alert["assigned_username"]
            if alert["assigned_username"]
            else "Unassigned"
        )

        print(
            f"  {alert['id']} | "
            f"{alert['severity']} | "
            f"{alert['state']} | "
            f"{assigned_to}"
        )

    # --------------------------------------------------------
    # 3. Create a dedicated service-test alert
    # --------------------------------------------------------

    test_alert_id = "ALT-SERVICE-TEST"

    existing_test_alert = None

    try:
        existing_test_alert = service.get_alert(
            test_alert_id
        )
    except ValueError:
        existing_test_alert = None

    if existing_test_alert is None:

        service.database.add_alert(
            alert_id=test_alert_id,
            source="SOAR Service Test",
            source_event_id="SERVICE-TEST-001",
            rule_id="TEST-001",
            rule_desc="Service Layer Test Alert",
            severity="LOW",
            state="NEW",
            assigned_to=None,
            src_ip="192.0.2.10",
            dst_ip="192.0.2.20",
            service="TEST",
            action="TEST",
            agent="service-test-agent",
            raw_event="Synthetic alert used for service-layer testing."
        )

    # --------------------------------------------------------
    # 4. Claim the test alert
    # --------------------------------------------------------

    print()
    print(
        f"Claiming {test_alert_id}..."
    )

    claimed_alert = service.claim_alert(
        test_alert_id,
        analyst_username
    )

    print(
        f"  State: "
        f"{claimed_alert['state']}"
    )

    print(
        f"  Assigned to: "
        f"{claimed_alert['assigned_username']}"
    )

    # --------------------------------------------------------
    # 5. Start investigation
    # --------------------------------------------------------

    print()
    print(
        f"Starting investigation for "
        f"{test_alert_id}..."
    )

    investigating_alert = (
        service.start_investigation(
            test_alert_id,
            analyst_username
        )
    )

    print(
        f"  State: "
        f"{investigating_alert['state']}"
    )

    print(
        f"  Assigned to: "
        f"{investigating_alert['assigned_username']}"
    )

    # --------------------------------------------------------
    # 6. Create/read investigation workspace
    # --------------------------------------------------------

    print()
    print(
        "Reading investigation workspace..."
    )

    investigation = service.get_investigation(
        test_alert_id
    )

    print(
        f"  Alert ID: "
        f"{investigation['alert_id']}"
    )

    print(
        f"  Notes: "
        f"{investigation['notes']}"
    )

    # --------------------------------------------------------
    # 7. Save investigation workspace
    # --------------------------------------------------------

    print()
    print(
        "Saving investigation workspace..."
    )

    saved_investigation = (
        service.save_investigation(
            test_alert_id,
            analyst_username,
            "Service layer test notes.",
            "Service layer test findings.",
            "Synthetic evidence for service testing."
        )
    )

    print(
        f"  Notes: "
        f"{saved_investigation['notes']}"
    )

    print(
        f"  Findings: "
        f"{saved_investigation['findings']}"
    )

    print(
        f"  Evidence: "
        f"{saved_investigation['evidence']}"
    )

    # --------------------------------------------------------
    # 8. Display audit timeline
    # --------------------------------------------------------

    print()
    print(
        f"Audit timeline for "
        f"{test_alert_id}:"
    )

    audit_events = (
        service.database.get_audit_log(
            alert_id=test_alert_id
        )
    )

    for event in audit_events:

        print(
            f"  {event['timestamp']} | "
            f"{event['analyst_username']} | "
            f"{event['action']} | "
            f"{event['details']}"
        )

    print()
    print(
        "SOAR service test completed successfully."
    )