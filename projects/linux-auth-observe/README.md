# linux-auth-observe

`linux-auth-observe` is a small deterministic mini-lab for normalizing Linux auth evidence into JSONL, filtering it, and generating a short Markdown report.

## Scope

- Supported inputs in v0.1:
  - `journalctl --output=json` line-delimited exports
  - Ubuntu or Debian `auth.log`
  - RHEL or CentOS `secure`
- Supported outputs:
  - normalized JSONL
  - filtered JSONL to stdout
  - Markdown summary report
- Not included in v0.1:
  - `audit.log`
  - real-time tailing
  - databases
  - packaging or publishing workflows

## Quickstart

```bash
python -m pip install -e .[dev]
python -m linux_auth_observe normalize --input tests/fixtures/ubuntu_auth.log --source auto --year 2026 --timezone Asia/Shanghai --output output/events.jsonl
python -m linux_auth_observe filter --input output/events.jsonl --user alice --ip 192.0.2.10 --service sshd
python -m linux_auth_observe summary --input output/events.jsonl --output output/summary.md
python -m pytest -q
```

`normalize` defaults to the current UTC year and the local system timezone when parsing yearless syslog timestamps. Pass `--year` and `--timezone` to replay fixtures deterministically.

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
