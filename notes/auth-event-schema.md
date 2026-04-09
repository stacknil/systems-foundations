# auth event schema

## Fixed normalized row

Each output record is one JSON object with this stable shape:

- `ts`: UTC timestamp in ISO-8601 form
- `host`: source hostname from the record
- `collector`: source family such as `auth.log`, `secure`, or `journald`
- `parser`: parser name responsible for the mapping
- `event_family`: fixed to `auth` in v0.1
- `event_type`: normalized event category
- `outcome`: `success` or `failure`
- `user`: best-effort principal or actor for the event
- `src_ip`: source IP when present
- `src_port`: source port when present
- `service`: normalized service name used for filtering
- `unit`: systemd unit when available
- `pid`: process id when present
- `program`: source program such as `sshd`, `sudo`, or `systemd`
- `message`: parsed message body without the syslog prefix
- `raw`: original input line or journal JSON line for traceability

## Event types in v0.1

- `ssh_login_success`
- `ssh_login_failure`
- `sudo_command`
- `sudo_session_open`
- `sudo_session_close`
- `su_session`
- `session_open`
- `session_close`
- `service_state_change`

## Field conventions

- `raw` is always preserved unchanged so a reviewer can trace the normalized record back to its evidence
- `service` is normalized for filtering, for example `sshd.service` becomes `sshd`
- `user` prefers the actor when the log clearly exposes one, such as `sudo` or `su` messages with `by alice(...)`
- `service_state_change` is only emitted from journald inputs in v0.1
