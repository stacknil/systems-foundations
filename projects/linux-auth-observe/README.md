# linux-auth-observe

`linux-auth-observe` is a small deterministic mini-lab for normalizing Linux auth evidence into JSONL, filtering it, and generating a short Markdown report.

## Supported Inputs

- `journalctl --output=json` line-delimited exports
- Ubuntu or Debian `auth.log`
- RHEL or CentOS `secure`

## Non-Goals

- `audit.log`
- real-time tailing or monitoring
- databases or storage layers
- packaging or publishing workflows

## Validation Status

- `pytest -q` currently passes for parser behavior, filtering, summary generation, CLI workflow, golden regression checks, and syslog year-rollover coverage
- `normalize` is covered against the three supported fixture families
- `filter` is covered for `user`, `IP`, and `service` constraints
- `summary` is covered for readable Markdown output
- `error-output` is covered as an optional JSONL artifact for parse failures during batch normalization

## Related Notes

- [Auth event schema](../../notes/auth-event-schema.md)
- [Journald and syslog basics](../../notes/journald-syslog-basics.md)

## Assumptions

- Syslog inputs are line-oriented and follow a standard auth/syslog prefix with no embedded year
- Syslog timestamps are interpreted in a chosen timezone, defaulting to `local`
- If `--year` is provided, it anchors the first syslog record and later `Dec -> Jan` transitions roll forward into the next year
- If `--year` is omitted, the parser infers the starting year from the first syslog record relative to the current time in the chosen timezone; if the first record would land more than about half a year in the future, it is treated as the previous year
- Journal inputs are one JSON object per line and map from `MESSAGE`, `_PID`, `_COMM`, and `_SYSTEMD_UNIT` when available
- `_PID` is preserved as contextual process metadata when present; it should not be read as a guaranteed identity anchor on its own
- Unsupported or malformed records fail clearly per line without stopping the full batch

## End-to-End Workflow

```bash
python -m pip install -e .[dev]

python -m linux_auth_observe normalize \
  --input tests/fixtures/ubuntu_auth.log \
  --source auto \
  --year 2026 \
  --timezone Asia/Shanghai \
  --output output/events.jsonl

python -m linux_auth_observe filter \
  --input output/events.jsonl \
  --user alice \
  --ip 192.0.2.10 \
  --service sshd

python -m linux_auth_observe summary \
  --input output/events.jsonl \
  --output output/summary.md

python -m linux_auth_observe normalize \
  --input tests/fixtures/ubuntu_auth_with_error.log \
  --source auto \
  --year 2026 \
  --timezone Asia/Shanghai \
  --output output/events.jsonl \
  --error-output output/parse-errors.jsonl
```

The intended flow is `normalize -> filter -> summary`, with `--error-output` available when you want a structured JSONL artifact for parse failures while the batch continues.

## Event Schema

Each normalized row is one JSON object with a fixed schema:

```json
{
  "ts": "2026-04-08T13:20:01Z",
  "host": "lab-host",
  "collector": "auth.log",
  "parser": "syslog_auth",
  "event_family": "auth",
  "event_type": "ssh_login_failure",
  "outcome": "failure",
  "user": "alice",
  "src_ip": "192.0.2.10",
  "src_port": 51422,
  "service": "sshd",
  "unit": null,
  "pid": 1234,
  "program": "sshd",
  "message": "Failed password for alice from 192.0.2.10 port 51422 ssh2",
  "raw": "Apr  8 21:20:01 lab-host sshd[1234]: Failed password for alice from 192.0.2.10 port 51422 ssh2"
}
```
