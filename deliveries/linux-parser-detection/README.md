# Linux Parser & Detection

## Overview
This module parses Linux forensic artifacts into normalized events
and detects potentially suspicious activity for analyst review.

## Project Structure

- `core/`: NormalizedEvent and NormalizedFinding models.
- `parsers/linux/`: Linux artifact parsers.
- `detection/linux/`: Linux detection rules.
- `samples/linux/`: Sample forensic artifacts.
- `tests/`: Unit tests.

## Supported Parsers

| Parser | Input | Extracted Data |
|---|---|---|
| auth_parser | auth.log | Login events, usernames, source IPs, sudo |
| cron_parser | crontab | Schedule, user, command |
| ssh_parser | authorized_keys | SSH key metadata and identifiers |
| systemd_parser | systemd service output | Service details and unit paths |

## Detection Rules

| Rule ID | Description |
|---|---|
| LINUX-AUTH-001 | Repeated failed logins from the same IP |
| LINUX-CRON-001 | Cron commands executing scripts from suspicious temporary paths |
| LINUX-SSH-001 | Unexpected authorized SSH keys |

All findings are potential findings requiring analyst review.
They must not automatically be treated as confirmed compromise.

## Evidence Handling

- Events and findings should retain evidence references.
- SSH private key contents must never be exposed.
- Public key data should not be unnecessarily exposed in findings.
- Unknown or malformed input lines should be ignored safely.

## Running Tests

Activate the virtual environment and run:

```bash
pytest -v
Current Limitations
- Parsing is limited to the supported input formats and patterns.
- Unrecognized log formats or malformed entries may be skipped.
- SSH key detection requires an expected baseline.
- Detection results require manual analyst validation.
- Systemd parsing currently focuses on service information extraction.
Testing
The test suite covers:
- Authentication parsing and repeated failed login detection.
- Cron parsing and suspicious temporary-path commands.
- SSH authorized key parsing and baseline comparison.
- Systemd service parsing.
- Invalid and incomplete input handling.
Handoff
This module is part of the larger DFIR project.
The team leader is responsible for reviewing and integrating
the completed files into the main GitHub repository.
