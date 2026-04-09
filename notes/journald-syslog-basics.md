# journald and syslog basics

## Why both formats exist

Linux auth evidence often lands in one of two places:

- classic syslog text files such as `/var/log/auth.log` and `/var/log/secure`
- the systemd journal, commonly exported with `journalctl --output=json`

This mini-lab supports both because they are the most common beginner-friendly evidence sources without adding extra services or databases.

## auth.log vs secure vs journald

- `auth.log` is the common auth syslog file on Ubuntu and Debian systems
- `secure` is the roughly equivalent auth syslog file on RHEL and CentOS systems
- journald stores structured records in the systemd journal and can be exported as one JSON object per line

For v0.1, `auth.log` and `secure` are treated as the same broad syslog family with distro-specific filenames, while journald is treated as a separate structured source family.

## v0.1 assumptions

- Syslog inputs are line-oriented and use a standard prefix like `Apr  8 21:20:01 host sshd[1234]: ...`
- Syslog timestamps do not include a year or timezone, so normalization must choose both explicitly or infer them
- The parser reads syslog files in order; if a file moves from `Dec 31` to `Jan 1`, later rows are treated as the next calendar year
- When no explicit year is supplied, the starting year is inferred from the first syslog row relative to the current date in the chosen timezone
- Journal inputs are one JSON object per line and use `__REALTIME_TIMESTAMP` as the authoritative event time
- v0.1 keeps the parser set intentionally small and deterministic

## Year and timezone behavior

- `--timezone` controls how yearless syslog timestamps are interpreted before conversion to UTC
- `--year` fixes the starting year for the first syslog row in a batch
- If `--year` is omitted, the parser uses the current date in the selected timezone as its anchor and only falls back to the previous year when the first parsed month and day would otherwise land far in the future
- journald records do not use this inference path because their exported timestamps already include absolute time

## What gets normalized

The parser currently targets these families:

- SSH login success and failure evidence
- `sudo` command execution and session activity
- `su` session activity
- common PAM session open and close events
- a basic journald-only `service_state_change` event for common `systemd` started, stopped, and failed states

## What is intentionally excluded

- `audit.log`
- binary journal files read directly from disk
- real-time tailing
- long-tail PAM variants that need broader heuristics

The goal is a reviewable training lab, not full SIEM coverage.
