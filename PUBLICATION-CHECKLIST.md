# Public Release Checklist

Before pushing this project to a public GitHub repository:

- [ ] Confirm `vt_api_key.txt`, `.env`, SSH keys, local SQLite databases, backups, logs, and `__pycache__` are absent from the staged file list.
- [ ] If any real key was ever committed to any remote, revoke/rotate it and clean repository history as needed.
- [ ] Run `Get-ChildItem -Filter *.py | ForEach-Object {
    python -m py_compile $_.FullName
}`.
- [ ] Run all three test scripts from the README in a clean environment.
- [ ] Install `requirements.txt` and launch the GUI on Windows.
- [ ] Verify the GUI says the Wazuh reader is not configured when `WAZUH_HOST` is unset, and verify live ingestion after configuring it.
- [ ] Verify VirusTotal enrichment with a locally configured key without displaying the key.
- [ ] Decide what license, if any, to add before granting reuse rights.
- [ ] Review screenshots and documentation for usernames, internal addresses, credentials, or live security data.
- [ ] Review the exact staged files with `git diff --cached --name-only` before committing.
