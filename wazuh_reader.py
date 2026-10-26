import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from database import Database
from wazuh_ingest import WazuhIngestor


class WazuhReader:
    """
    Read Wazuh alerts remotely over SSH and send them
    to the Wazuh ingestion layer.

    Modes:
        once  -> read the latest event once
        follow -> continuously follow new events
    """

    # Configure these through environment variables for each lab.
    # Do not hard-code private infrastructure addresses in the public repo.
    WAZUH_HOST = os.environ.get("WAZUH_HOST", "").strip()
    WAZUH_USER = os.environ.get("WAZUH_USER", "soarreader").strip()
    WAZUH_ALERT_FILE = os.environ.get(
        "WAZUH_ALERT_FILE",
        "/var/ossec/logs/alerts/alerts.json"
    ).strip()

    def __init__(
        self,
        database=None,
        host=None,
        username=None,
        alert_file=None,
        private_key=None
    ):
        self.database = database or Database()

        self.host = (
            host or os.environ.get("WAZUH_HOST", "").strip()
            or self.WAZUH_HOST
        )
        self.username = (
            username or os.environ.get("WAZUH_USER", "").strip()
            or self.WAZUH_USER
        )
        self.alert_file = (
            alert_file or os.environ.get("WAZUH_ALERT_FILE", "").strip()
            or self.WAZUH_ALERT_FILE
        )

        configured_key = (
            private_key
            or os.environ.get("WAZUH_SSH_KEY", "").strip()
            or (Path.home() / ".ssh" / "id_ed25519")
        )
        self.private_key = Path(configured_key)

        if not self.host:
            raise ValueError(
                "Wazuh host is not configured. Set WAZUH_HOST or pass --host."
            )

        if not self.private_key.exists():
            raise FileNotFoundError(
                f"SSH private key not found: {self.private_key}"
            )

        self.ingestor = WazuhIngestor(self.database)

    def build_ssh_command(self, mode):
        """
        Build the SSH command used to read the Wazuh log.
        """

        if mode == "once":
            remote_command = (
                f"tail -n 1 "
                f"{shlex.quote(self.alert_file)}"
            )

        elif mode == "follow":
            remote_command = (
                f"tail ---disable-inotify -n 0 -F "
                f"{shlex.quote(self.alert_file)}"
            )

        else:
            raise ValueError(
                f"Unsupported reader mode: {mode}"
            )

        return [
            "ssh",
            "-i",
            str(self.private_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            f"{self.username}@{self.host}",
            remote_command
        ]

    def process_line(self, line):
        """
        Parse one line of Wazuh JSON and ingest it.
        """

        line = line.strip()

        if not line:
            return None

        try:
            event = json.loads(line)

        except json.JSONDecodeError:
            print(
                "[SKIP] Received non-JSON output:"
            )
            print(line)
            return None

        try:
            result = self.ingestor.ingest_event(event)

        except Exception as exc:
            print()
            print("[ERROR] Failed to ingest Wazuh event:")
            print(exc)
            return None

        return result

    def run_once(self):
        """
        Read and ingest the latest Wazuh event.
        """

        command = self.build_ssh_command("once")

        print()
        print("==========================================")
        print("WAZUH LIVE INGESTION - ONCE")
        print("==========================================")

        print()
        print("Connecting to Wazuh...")
        print(
            f"  Host: {self.username}@{self.host}"
        )

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30
        )

        if process.returncode != 0:
            raise RuntimeError(
                "SSH command failed:\n"
                + process.stderr.strip()
            )

        lines = process.stdout.splitlines()

        if not lines:
            print()
            print("No event received.")
            return

        for line in lines:
            result = self.process_line(line)

            if result:
                print()
                print("Ingestion result:")
                print(f"  Status: {result['status']}")
                print(
                    f"  Alert ID: {result['alert_id']}"
                )
                print(
                    f"  Source Event ID: "
                    f"{result['source_event_id']}"
                )

        print()
        print("==========================================")

    def run_forever(self, reconnect_delay=5):
        """
        Continuously follow new Wazuh events.

        If the SSH connection terminates, reconnect after
        the configured delay.
        """

        print()
        print("==========================================")
        print("WAZUH LIVE INGESTION - FOLLOW")
        print("==========================================")

        print()
        print("Press Ctrl+C to stop the reader.")

        while True:
            process = None

            try:
                command = self.build_ssh_command("follow")

                print()
                print(
                    f"[CONNECT] "
                    f"{self.username}@{self.host}"
                )

                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1
                )

                while True:
                    line = process.stdout.readline()

                    if line == "":
                        break

                    line = line.strip()

                    if not line:
                        continue

                    result = self.process_line(line)

                    if result:
                        print(
                            f"[{result['status'].upper()}] "
                            f"{result['alert_id']} | "
                            f"{result['source_event_id']}",
                            flush=True
                        )

                stderr_output = ""

                if process.stderr:
                    stderr_output = process.stderr.read().strip()

                return_code = process.wait()

                if stderr_output:
                    print()
                    print("[SSH STDERR]")
                    print(stderr_output)

                print()
                print(
                    f"[DISCONNECT] SSH exited with "
                    f"code {return_code}"
                )

                print(
                    f"[RECONNECT] Waiting "
                    f"{reconnect_delay} seconds..."
                )

                time.sleep(reconnect_delay)

            except KeyboardInterrupt:
                print()
                print("[STOP] Wazuh reader stopped.")

                if process and process.poll() is None:
                    process.terminate()

                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()

                break

            except Exception as exc:
                print()
                print(
                    f"[ERROR] Reader failure: {exc}"
                )

                if process and process.poll() is None:
                    process.terminate()

                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()

                time.sleep(reconnect_delay)


def main():
    parser = argparse.ArgumentParser(
        description="Read Wazuh alerts over SSH."
    )

    parser.add_argument(
        "--mode",
        choices=["once", "follow"],
        default="once",
        help="Reader mode."
    )

    parser.add_argument(
        "--db",
        default=None,
        help="Optional SQLite database path."
    )

    parser.add_argument(
        "--host",
        default=os.environ.get("WAZUH_HOST", "").strip() or None,
        help="Wazuh manager hostname/IP (or set WAZUH_HOST)."
    )

    parser.add_argument(
        "--user",
        default=os.environ.get("WAZUH_USER", "soarreader").strip(),
        help="SSH username (or set WAZUH_USER)."
    )

    parser.add_argument(
        "--alert-file",
        default=os.environ.get(
            "WAZUH_ALERT_FILE",
            "/var/ossec/logs/alerts/alerts.json"
        ),
        help="Remote Wazuh alert file path."
    )

    parser.add_argument(
        "--key",
        default=os.environ.get("WAZUH_SSH_KEY", "").strip() or None,
        help="SSH private-key path (or set WAZUH_SSH_KEY)."
    )

    args = parser.parse_args()

    if not args.host:
        parser.error(
            "Wazuh host is required. Set WAZUH_HOST or pass --host."
        )

    database = Database(
        db_path=args.db
    )

    reader = WazuhReader(
        database=database,
        host=args.host,
        username=args.user,
        alert_file=args.alert_file,
        private_key=args.key
    )

    if args.mode == "once":
        reader.run_once()

    else:
        reader.run_forever()


if __name__ == "__main__":
    main()