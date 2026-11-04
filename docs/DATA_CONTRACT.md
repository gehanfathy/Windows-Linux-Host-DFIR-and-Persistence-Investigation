# DFIR Data Contract

## Purpose

This document defines the common data format used by Windows and Linux
collectors, parsers, detection rules, and the central DFIR application.

All team members must follow this contract.

---

## 1. Normalized Event

Every event from Windows or Linux must follow this structure:

```json
{
  "event_id": "evt-000001",
  "case_id": "case-000001",
  "host_id": "WIN-LAB-01",
  "platform": "windows",
  "event_type": "failed_login",
  "timestamp": "2026-11-04T10:15:00Z",
  "severity": "medium",
  "source": "security.evtx",
  "evidence_reference": "security.evtx:event-4625",
  "message": "Failed login for user administrator",
  "metadata": {
    "username": "administrator",
    "source_ip": "192.168.1.20",
    "original_event_id": 4625
  }
}
```

### Required Event Fields

| Field | Type | Description |
|---|---|---|
| `event_id` | string | Unique event identifier |
| `case_id` | string | Investigation case identifier |
| `host_id` | string | Source host identifier |
| `platform` | string | `windows` or `linux` |
| `event_type` | string | Normalized event category |
| `timestamp` | string | UTC timestamp in ISO 8601 format |
| `severity` | string | `low`, `medium`, `high`, or `critical` |
| `source` | string | Original evidence source |
| `evidence_reference` | string | Exact evidence location |
| `message` | string | Human-readable event description |
| `metadata` | object | Additional platform-specific information |

---

## 2. Supported Platforms

The `platform` field must contain only:

```text
windows
linux
```

Operating system versions may be stored inside `metadata`.

---

## 3. Supported Event Types

The initial supported event types are:

```text
failed_login
successful_login
account_created
account_modified
persistence_detected
process_execution
network_connection
file_modified
service_created
scheduled_task_created
cron_modified
ssh_key_modified
```

New event types must be documented before implementation.

---

## 4. Severity Values

Only these severity values are allowed:

```text
low
medium
high
critical
```

Severity describes the priority of the event. It does not prove that the
host is compromised.

---

## 5. Normalized Finding

Detection rules must produce findings using this structure:

```json
{
  "finding_id": "finding-000001",
  "case_id": "case-000001",
  "host_id": "LINUX-LAB-01",
  "platform": "linux",
  "title": "Suspicious Cron Persistence",
  "description": "A cron entry executes a script from /tmp.",
  "severity": "high",
  "rule_id": "LINUX-CRON-001",
  "mitre_technique": "T1053.003",
  "status": "unverified",
  "evidence_reference": "/var/log/syslog:line-120"
}
```

### Required Finding Fields

| Field | Type | Description |
|---|---|---|
| `finding_id` | string | Unique finding identifier |
| `case_id` | string | Related investigation case |
| `host_id` | string | Host where the finding was detected |
| `platform` | string | `windows` or `linux` |
| `title` | string | Short finding title |
| `description` | string | Finding explanation |
| `severity` | string | Finding priority |
| `rule_id` | string | Detection rule identifier |
| `status` | string | Finding review status |
| `evidence_reference` | string | Supporting evidence location |

Allowed values for `status` are:

```text
unverified
confirmed
rejected
inconclusive
```

The `mitre_technique` field is optional.

---

## 6. Normalized IOC

IOC means Indicator of Compromise.

Every IOC must follow this structure:

```json
{
  "ioc_id": "ioc-000001",
  "case_id": "case-000001",
  "host_id": "WIN-LAB-01",
  "ioc_type": "ip_address",
  "value": "192.168.1.20",
  "source": "security.evtx",
  "evidence_reference": "security.evtx:event-4625",
  "confidence": "medium"
}
```

Allowed IOC types:

```text
ip_address
domain
file_path
file_hash
username
email
registry_key
scheduled_task
service_name
ssh_key
```

Allowed confidence values:

```text
low
medium
high
```

---

## 7. Timestamp Format

All timestamps must use UTC and ISO 8601 format:

```text
2026-11-04T10:15:00Z
```

Do not send local timestamps without timezone information.

---

## 8. Evidence Reference

Every event, finding, and IOC must be traceable to the original evidence.

Examples:

```text
auth.log:line-120
security.evtx:event-4625
sysmon.json:record-55
/var/spool/cron/crontabs/user:line-8
```

The application must not display a detection without an evidence reference.

---

## 9. Security and Quality Rules

1. Windows and Linux components must use the same normalized structure.
2. Platform-specific fields must be placed inside `metadata`.
3. Passwords, tokens, and secrets must never be stored in events.
4. Real sensitive evidence must not be committed to GitHub.
5. Detection results are potential findings and require analyst review.
6. New fields or event types must be discussed before implementation.
7. All components must validate data before sending or storing it.
