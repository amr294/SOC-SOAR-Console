import json
import threading
import time
from datetime import datetime, timezone

from database import Database
from ioc_extractor import is_public_ip
from virustotal_client import (
    VirusTotalClient,
    VirusTotalError,
    VirusTotalNotFound,
    VirusTotalQuotaError,
)


class EnrichmentWorker:
    """
    Fulfils enrichment requests that analysts create from the GUI.

    Human-in-the-loop is preserved: nothing is sent to VirusTotal
    until an analyst clicks "Request Enrichment". This worker only
    picks up rows in enrichment_requests with status 'Requested'.

    Lifecycle of a request:
        Requested -> In Progress -> Completed | Failed

    ioc_intelligence mirrors the outcome so the existing GUI
    (cached / in-progress / retry button) works unchanged:
        success or "not in VT"  -> Cached Intelligence Available
        error                   -> Failed (GUI offers a retry)
        rate limited            -> stays Requested, retried later

    Internal (RFC1918, loopback, link-local...) addresses are never
    sent to VirusTotal. They are resolved locally as "Internal".
    """

    SOURCE = "VirusTotal"

    def __init__(
        self,
        database=None,
        client=None,
        poll_interval=3.0,
        quota_backoff=60.0
    ):
        self.database = database or Database()
        self.client = client or VirusTotalClient()
        self.poll_interval = poll_interval
        self.quota_backoff = quota_backoff

        self._stop = threading.Event()
        self._thread = None
        self._last_call = None
        self.quota_hit = False

    # ========================================================
    # PUBLIC API
    # ========================================================

    @property
    def is_configured(self):
        return self.client.configured

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop.clear()

        self._thread = threading.Thread(
            target=self._run,
            name="EnrichmentWorker",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

        if self._thread is not None:
            self._thread.join(timeout=5)

    def recover_interrupted(self):
        """
        A request left 'In Progress' means the app closed mid-lookup.
        Put it back in the queue.
        """

        self.database.execute(
            """
            UPDATE enrichment_requests
            SET status = 'Requested', completed_at = NULL
            WHERE status = 'In Progress'
            """
        )

    def process_pending(self):
        """
        Process every request currently in 'Requested' state,
        oldest first. Returns the number of requests resolved
        (completed or failed). Stops early if rate limited.
        """

        self.quota_hit = False
        handled = 0

        for request in self._pending_requests():

            if self._stop.is_set():
                break

            outcome = self._process_request(request)

            if outcome == "quota":
                self.quota_hit = True
                break

            handled += 1

        return handled

    # ========================================================
    # INTERNALS
    # ========================================================

    def _run(self):
        try:
            self.recover_interrupted()
        except Exception as exc:
            print(f"[enrichment] recovery failed: {exc}")

        if not self.is_configured:
            print(
                "[enrichment] No VirusTotal API key found. Public "
                "IOC lookups will fail until VT_API_KEY is set or "
                "vt_api_key.txt exists."
            )

        while not self._stop.is_set():

            try:
                self.process_pending()
            except Exception as exc:
                print(f"[enrichment] worker error: {exc}")

            self._stop.wait(
                self.quota_backoff
                if self.quota_hit
                else self.poll_interval
            )

    def _pending_requests(self):
        return self.database.fetch_all(
            """
            SELECT
                er.id,
                er.ioc_id,
                er.alert_id,
                i.value,
                i.type
            FROM enrichment_requests AS er
            INNER JOIN iocs AS i
                ON er.ioc_id = i.id
            WHERE er.status = 'Requested'
            ORDER BY er.id ASC
            """
        )

    def _pace(self):
        """
        Respect the API's per-minute limit. The first call is
        immediate; later calls wait out client.min_interval.
        """

        if self._last_call is not None:
            remaining = (
                self.client.min_interval
                - (time.monotonic() - self._last_call)
            )

            if remaining > 0:
                self._stop.wait(remaining)

        self._last_call = time.monotonic()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def _process_request(self, request):
        """
        Returns 'done', 'failed', or 'quota'.
        """

        request_id = request["id"]
        value = request["value"]
        ioc_type = request["type"]

        try:
            self.database.update_enrichment_request_status(
                request_id,
                "In Progress"
            )

            # ------------------------------------------------
            # Internal addresses: resolve locally.
            # ------------------------------------------------

            if ioc_type in ("IPv4", "IPv6") and not is_public_ip(value):

                self._complete(
                    request,
                    {
                        "reputation": "Internal",
                        "score": "N/A",
                        "first_seen": None,
                        "last_checked": self._now(),
                        "raw_data": json.dumps({
                            "note": "Private/non-routable address. "
                                    "Not sent to VirusTotal."
                        })
                    },
                    source="Local policy",
                    summary=f"{value}: internal address, not queried"
                )
                return "done"

            # ------------------------------------------------
            # Public indicator: ask VirusTotal.
            # ------------------------------------------------

            if self.client.configured:
                self._pace()

            try:
                result = self.client.lookup(ioc_type, value)

            except VirusTotalNotFound:
                self._complete(
                    request,
                    {
                        "reputation": "Not Found",
                        "score": "N/A",
                        "first_seen": None,
                        "last_checked": self._now(),
                        "raw_data": json.dumps({
                            "note": "VirusTotal has no record of "
                                    "this indicator."
                        })
                    },
                    source=self.SOURCE,
                    summary=f"{value}: not found in VirusTotal"
                )
                return "done"

            except VirusTotalQuotaError as exc:
                # Not the analyst's fault and not final:
                # put it back and try again after a pause.
                self.database.update_enrichment_request_status(
                    request_id,
                    "Requested"
                )
                print(f"[enrichment] {exc} Backing off.")
                return "quota"

            except VirusTotalError as exc:
                self._fail(request, str(exc))
                return "failed"

            self._complete(
                request,
                result,
                source=self.SOURCE,
                summary=(
                    f"{value}: {result['reputation']} "
                    f"({result['score']}) via VirusTotal"
                )
            )
            return "done"

        except Exception as exc:
            # Never let one bad row kill the worker.
            try:
                self._fail(request, f"Unexpected error: {exc}")
            except Exception:
                pass

            return "failed"

    def _complete(self, request, result, source, summary):
        self.database.save_ioc_intelligence(
            request["ioc_id"],
            "Cached Intelligence Available",
            reputation=result["reputation"],
            source=source,
            score=result["score"],
            first_seen=result["first_seen"],
            last_checked=result["last_checked"],
            raw_data=result["raw_data"]
        )

        self.database.update_enrichment_request_status(
            request["id"],
            "Completed"
        )

        self.database.add_audit_event(
            action="Enrichment Completed",
            alert_id=request["alert_id"],
            details=summary
        )

    def _fail(self, request, message):
        self.database.save_ioc_intelligence(
            request["ioc_id"],
            "Failed",
            last_checked=self._now(),
            raw_data=json.dumps({"error": message})
        )

        self.database.update_enrichment_request_status(
            request["id"],
            "Failed"
        )

        self.database.add_audit_event(
            action="Enrichment Failed",
            alert_id=request["alert_id"],
            details=f"{request['value']}: {message}"
        )
