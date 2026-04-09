# journald and syslog basics

## Why both formats exist

Linux auth evidence often lands in one of two places:

- classic syslog text files such as `/var/log/auth.log` and `/var/log/secure`
- the systemd journal, commonly exported with `journalctl --output=json`

This mini-lab supports both because they are the most common beginner-friendly evidence sources without adding extra services or databases.

## v0.1 assumptions

- Syslog inputs are line-oriented and use a standard prefix like `Apr  8 21:20:01 host sshd[1234]: ...`
- Syslog timestamps do not include a year or timezone, so normalization needs a reference year and timezone
- Journal inputs are one JSON object per line and use `__REALTIME_TIMESTAMP` as the authoritative event time
- v0.1 keeps the parser set intentionally small and deterministic

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
