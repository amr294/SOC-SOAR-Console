import hashlib
import json

from database import Database
from ioc_extractor import extract_iocs


class WazuhIngestor:
    """
    Convert Wazuh JSON alerts into normalized SOAR alerts.

    Responsibilities:
    - Validate a Wazuh event
    - Extract the fields needed by the SOAR database
    - Normalize Wazuh numeric rule levels into SOAR severity labels
    - Generate a stable internal SOAR alert ID
    - Prevent duplicate ingestion using source_event_id
    """

    SOURCE_NAME = "Wazuh"

    @staticmethod
    def normalize_severity(level):
        """
        Convert the Wazuh numeric rule level into the SOAR
        severity categories used by the application.

        This is a SOAR normalization rule, not a Wazuh label.
        """

        if not isinstance(level, int):
            raise ValueError("Wazuh rule level must be an integer.")

        if level < 0 or level > 16:
            raise ValueError(
                f"Invalid Wazuh rule level: {level}"
            )

        if level <= 3:
            return "LOW"

        if level <= 7:
            return "MEDIUM"

        if level <= 11:
            return "HIGH"

        return "CRITICAL"

    @staticmethod
    def generate_alert_id(source_event_id):
        """
        Generate a deterministic internal SOAR alert ID.

        The same Wazuh event ID always produces the same
        internal alert ID.
        """

        digest = hashlib.sha256(
            f"Wazuh:{source_event_id}".encode("utf-8")
        ).hexdigest()[:12].upper()

        return f"ALT-WAZUH-{digest}"

    @staticmethod
    def _first_value(*values):
        """
        Return the first value that is not None.
        """

        for value in values:
            if value is not None:
                return value

        return None

    @staticmethod
    def parse_event(event):
        """
        Convert one Wazuh event dictionary into the normalized
        fields expected by Database.add_alert().
        """

        if not isinstance(event, dict):
            raise ValueError("Wazuh event must be a dictionary.")

        rule = event.get("rule")
        if not isinstance(rule, dict):
            raise ValueError("Wazuh event is missing the rule object.")

        source_event_id = event.get("id")
        if not source_event_id:
            raise ValueError(
                "Wazuh event is missing its source event ID."
            )

        rule_id = rule.get("id")
        rule_desc = rule.get("description")
        source_severity = rule.get("level")

        if rule_id is None:
            raise ValueError(
                "Wazuh event is missing rule.id."
            )

        if not rule_desc:
            raise ValueError(
                "Wazuh event is missing rule.description."
            )

        severity = WazuhIngestor.normalize_severity(
            source_severity
        )

        agent = event.get("agent")
        if not isinstance(agent, dict):
            agent = {}

        predecoder = event.get("predecoder")
        if not isinstance(predecoder, dict):
            predecoder = {}

        decoder = event.get("decoder")
        if not isinstance(decoder, dict):
            decoder = {}

        data = event.get("data")
        if not isinstance(data, dict):
            data = {}

        # Prefer the actual decoder name.
        # Fall back to the predecoder program name.
        service = WazuhIngestor._first_value(
            decoder.get("name"),
            predecoder.get("program_name")
        )

        # Wazuh event structures can vary, so support the
        # common locations for source/destination IP fields.
        src_ip = WazuhIngestor._first_value(
            data.get("srcip"),
            data.get("src_ip"),
            event.get("srcip"),
            event.get("src_ip")
        )

        dst_ip = WazuhIngestor._first_value(
            data.get("dstip"),
            data.get("dst_ip"),
            event.get("dstip"),
            event.get("dst_ip")
        )

        # Normalize the action/status field where available.
        action = WazuhIngestor._first_value(
            data.get("status"),
            data.get("action"),
            event.get("action")
        )

        agent_name = agent.get("name")

        raw_event = json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":")
        )

        return {
            "alert_id": WazuhIngestor.generate_alert_id(
                str(source_event_id)
            ),
            "source": WazuhIngestor.SOURCE_NAME,
            "source_event_id": str(source_event_id),
            "rule_id": str(rule_id),
            "rule_desc": str(rule_desc),
            "source_severity": source_severity,
            "severity": severity,
            "state": "NEW",
            "assigned_to": None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": service,
            "action": action,
            "agent": agent_name,
            "raw_event": raw_event,
            "event_timestamp": event.get("timestamp")
        }

    def __init__(self, database=None):
        """
        Create an ingestor using the supplied Database instance.
        """

        self.database = database or Database()

    def ingest_event(self, event):
        """
        Parse and insert one Wazuh event.

        Returns:
            dict describing whether a new alert was created
            or the event was already present.
        """

        normalized = self.parse_event(event)

        existing_alert = (
            self.database.get_alert_by_source_event_id(
                normalized["source"],
                normalized["source_event_id"]
            )
        )

        if existing_alert:
            return {
                "status": "duplicate",
                "created": False,
                "alert_id": existing_alert["id"],
                "source_event_id": normalized["source_event_id"]
            }

        self.database.add_alert(
            alert_id=normalized["alert_id"],
            source=normalized["source"],
            rule_id=normalized["rule_id"],
            rule_desc=normalized["rule_desc"],
            severity=normalized["severity"],
            state=normalized["state"],
            assigned_to=normalized["assigned_to"],
            source_event_id=normalized["source_event_id"],
            source_severity=normalized["source_severity"],
            event_timestamp=normalized["event_timestamp"],
            src_ip=normalized["src_ip"],
            dst_ip=normalized["dst_ip"],
            service=normalized["service"],
            action=normalized["action"],
            agent=normalized["agent"],
            raw_event=normalized["raw_event"]
        )

        self._link_iocs(normalized, event)

        return {
            "status": "created",
            "created": True,
            "alert_id": normalized["alert_id"],
            "source_event_id": normalized["source_event_id"]
        }

    def _link_iocs(self, normalized, event):
        """
        Create IOC records for public IPs and file hashes found in
        the alert and link them to it.

        This never contacts an external service: enrichment is
        still triggered explicitly by an analyst. A failure here
        must not lose the alert, which is already stored.
        """

        try:
            for value, ioc_type in extract_iocs(
                normalized["src_ip"],
                normalized["dst_ip"],
                event
            ):
                ioc_id = self.database.add_ioc(value, ioc_type)

                self.database.link_ioc_to_alert(
                    normalized["alert_id"],
                    ioc_id
                )

        except Exception as exc:
            print(
                f"[ingest] IOC extraction failed for "
                f"{normalized['alert_id']}: {exc}"
            )

    def ingest_json_line(self, line):
        """
        Parse one JSON line from alerts.json and ingest it.
        """

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid Wazuh JSON: {exc}"
            ) from exc

        return self.ingest_event(event)