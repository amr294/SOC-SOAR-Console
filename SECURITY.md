# Security Policy

## Scope

This project is a local defensive security lab and portfolio application. Do not use it against systems you do not own or have explicit permission to test.

## Reporting a concern

Please do not publish credentials, private logs, or sensitive exploit details in a public issue. Contact the repository owner through GitHub to coordinate a private report.

## Secret handling

Never commit VirusTotal API keys, SSH private keys, passwords, local `.env` files, Wazuh alert databases, or real alert/log exports. If a valid credential is ever committed or exposed, revoke/rotate it; deleting it from the latest file does not remove it from Git history.
