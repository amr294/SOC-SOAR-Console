# SOC SOAR Console

A local, human-in-the-loop SOAR-style console built with Python, CustomTkinter, and SQLite. It consumes alerts from an existing Wazuh manager, provides an analyst investigation workflow, and supports analyst-requested VirusTotal enrichment.

This is a portfolio and lab project, not a production-ready multi-user SOAR platform.

## What it demonstrates

- Read-only SSH consumption of Wazuh's `alerts.json` stream.
- Alert normalization and source-event deduplication.
- An alert queue with filtering, search, and pagination.
- Manual alert assignment and investigation notes/findings/evidence.
- Extraction of public IP indicators and file hashes.
- Analyst-triggered VirusTotal API v3 enrichment with local caching, error handling, retry, and rate-limit handling.
- Closure with a required disposition and escalation with a required report.
- SQLite persistence and audit logging of significant analyst/system actions.
- Standalone tests for ingestion, workflow operations, IOC extraction, and enrichment behavior.

## Architecture

```text
Wazuh Manager
    |
    | read-only SSH; tails the configured Wazuh alert file
    v
Wazuh Reader -> Wazuh Ingestor -> SQLite
                                  ^   |
                                  |   v
SOAR GUI <- SOAR Service <--------+  Enrichment Worker -> VirusTotal API
```

Wazuh remains responsible for event collection, rule evaluation, and alert generation. The console records the analyst's actions after an alert exists. It does not automatically adjudicate alerts, block IPs on FortiGate, isolate endpoints, or execute response playbooks.

## Requirements

- Windows 10/11 is the primary GUI environment.
- Python 3.11 or newer is recommended.
- SSH client available on the workstation.
- Access to a Wazuh manager account that can read the configured alert file without `sudo`.
- A VirusTotal API key is optional for enrichment; other local workflow features can be exercised without it.

Install the GUI dependency:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration

The Wazuh connection is configured through environment variables. The repository intentionally contains no lab IP address, SSH private key, API key, or live SQLite database.

In PowerShell, set the values for your own lab before launching the app:

```powershell
$env:WAZUH_HOST = "REPLACE_WITH_YOUR_WAZUH_MANAGER_HOST_OR_IP"
$env:WAZUH_USER = "soarreader"
$env:WAZUH_ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
$env:WAZUH_SSH_KEY = "$HOME\.ssh\id_ed25519"
```

`WAZUH_HOST` is required to enable live ingestion. The SSH private key stays on your workstation. The reader uses key-based SSH and does not need an administrative account. Configure the remote account and file permissions on the Wazuh host separately; do not copy a private key into this repository.

For VirusTotal enrichment, set the key in the process environment. Do not paste it into source files or commit a key file:

```powershell
$env:VT_API_KEY = "SET_YOUR_OWN_KEY_LOCALLY"
```

Close and reopen the terminal to clear these session variables when appropriate. Never publish real credentials in screenshots, logs, example files, issues, or commits. A local `vt_api_key.txt` is also ignored by Git for compatibility with the client, but environment-variable configuration is preferred.

## Run the console

```powershell
python .\soar_gui.py
```

If `WAZUH_HOST` is unset, the GUI can still be opened locally, but the live Wazuh reader will show that it is not configured. Configure the SSH connection and restart the application to receive live alerts.

The application creates its local SQLite database (`soar.db`) beside the source files if needed. The database is local state and is intentionally excluded from version control.

### Demo data

The app does not seed prototype alert/IOC records unless `SOAR_DEMO_MODE=1` (or `true`, `yes`, `on`) is set. To explicitly enable the three example alerts and example IOC records for a demo session:

```powershell
$env:SOAR_DEMO_MODE = "1"
python .\soar_gui.py
```

Unset demo mode for normal lab use:

```powershell
Remove-Item Env:SOAR_DEMO_MODE -ErrorAction SilentlyContinue
```

Changing this setting does not automatically delete demo records that already exist in a database. Use a separate fresh database for demos when possible.

## Run the tests

The supplied tests are standalone scripts rather than pytest-discoverable test functions. Run them from the repository root:

```powershell
python .\test_wazuh_ingest.py
python .\test_soar_service.py
python .\test_enrichment.py
```

These tests exercise ingestion, workflow, and enrichment logic using isolated databases and mocked VirusTotal responses; they do not require a live Wazuh server or consume live VirusTotal quota. After installing `requirements.txt`, perform a GUI smoke test on your workstation and verify live ingestion against your own Wazuh host.

## Utilities

- `backfill_iocs.py` links extracted IOCs to alerts already in an existing database. Review `--dry-run` output first and back up the database before a write operation.
- `migrate_wazuh_schema.py` is a one-off migration for an existing database. Back up your database first and use `--db` to identify it. Do not run a migration against your only copy of valuable data.

## Data and safety boundaries

- Use only an isolated lab that you own or are authorized to administer.
- Do not commit live alert databases, raw logs, backups, SSH keys, passwords, tokens, or API keys.
- Only public IPs and file hashes are intended for VirusTotal submission; private/non-routable addresses are handled locally.
- VirusTotal enrichment is initiated by the analyst. The application does not perform automated network/endpoint response.
- The current application uses a single local analyst session and local SQLite storage. Multi-user authentication, analyst switching, historical backfill after reader downtime, cache expiry, custom detection engineering, cross-source correlation, and response playbooks are outside the current scope.

## Related project documentation

The complete lab build, FortiGate/Wazuh integration, SOC dashboard, and SOAR workflow evidence are documented in the [SIEM Monitoring Home Lab repository](https://github.com/amr294/SIEM-Monitoring-Home-Lab), particularly:

- [Current Lab Architecture](https://github.com/amr294/SIEM-Monitoring-Home-Lab/blob/main/docs/00-Current-Lab-Architecture.md)
- [FortiGate → Wazuh Integration](https://github.com/amr294/SIEM-Monitoring-Home-Lab/blob/main/docs/16-FortiGate-Wazuh-Integration.md)
- [SOC Monitoring Dashboard](https://github.com/amr294/SIEM-Monitoring-Home-Lab/blob/main/docs/17-SOC-Monitoring-Dashboard.md)
- [SOAR Console and Incident Response Workflow](https://github.com/amr294/SIEM-Monitoring-Home-Lab/blob/main/docs/18-SOAR-Console-and-Incident-Response.md)

