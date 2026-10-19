# Process evidence and envelope schema

## Why process evidence needs context

A PID answers "which process table slot?" only for a limited time. Linux can reuse a PID after a process exits, so a saved PID is not a durable identity by itself.

This lab combines:

- `host_id`
- PID
- `/proc/<pid>/stat` start time in clock ticks

The resulting `process_id` is `host_id:pid:start_time_ticks`. Because start time is measured from system boot and the envelope has no boot identifier, it is a same-boot snapshot identity rather than a cross-reboot durable identity. It is not a cryptographic identity and not a guarantee that two independently collected records observed exactly the same execution context.

## Evidence envelope

Every JSON artifact uses:

```json
{
  "schema": "stacknil.system-evidence.v1",
  "source": "procfs",
  "host_id": "lab-host",
  "observed_at": "2026-07-05T00:00:00Z",
  "records": []
}
```

- `schema` identifies the shared outer contract.
- `source` names the saved evidence family, such as `procfs` or `procfs+ss`.
- `host_id` is a stable, sanitized host identifier supplied by the operator.
- `observed_at` is an explicit timezone-aware collection time normalized to UTC. Fractional inputs retain up to microsecond precision; more than six fractional-second digits are rejected rather than truncated.
- `records` contains artifact-specific normalized records.

The envelope is deliberately small so LogLens, telemetry-lab, or later evidence experiments can consume the same outer shape without pretending that every record family has the same inner fields.

## Temporal cohort contract

`process_diff.json` is directional evidence, so its four inputs must form one comparable temporal cohort:

```text
before process instant == before socket-link instant
after process instant  == after socket-link instant
before instant < after instant
```

Observation times are compared as timezone-aware instants. For example, `2026-07-05T00:00:00Z` and `2026-07-05T08:00:00+08:00` are equivalent. Equal or reversed before/after instants and mismatched process/socket-link pairs fail closed before any records are compared.

Subsecond precision is retained so two captures within one second can still satisfy strict ordering. If two captures have the same normalized instant, the lab cannot infer their order and refuses to produce a directional diff.

Paired timestamps are cohort provenance, not atomicity proof. Procfs and saved `ss` inputs may still have been collected sequentially, and socket evidence provides PID context rather than an execution-instance identity independent of procfs.

## Process record

Process records preserve:

- PID and parent PID
- parent process snapshot identity when the parent was exported
- process name and state
- real and effective UID/GID
- resolved executable path
- argv
- start time in clock ticks

The executable path is contextual evidence. It does not prove the path still points to the same inode or that the file contents are trusted. Stronger integrity claims would require separate file metadata or hashing evidence.

## Process and socket link

Saved `ss -H -a -n -t -u -p` output can connect a TCP or UDP socket to a PID when the command had enough permission and the process remained visible. The lab records:

- listener or endpoint state
- local and remote address/port
- loopback, wildcard, or specific local exposure
- reported PID and process name
- linked procfs identity when available

Missing process context is not converted into false certainty. The socket remains in the artifact with `linked=false`.

`process_name` on a socket link is the name reported by `ss`, including when it
differs from the PID-associated procfs process's `name`. This preserves both
observations. A name disagreement can follow legitimate changes and does not prove
PID reuse or misconduct; agreement cannot rule out reuse between saved captures.

`linked=true` describes an unambiguous PID association in the supplied records.
It does not independently verify that `ss` observed the procfs execution instance.
The link's `process_id`, executable, UID and GID are procfs-derived context. Duplicate
PID candidates fail instead of selecting the first or last record. During `diff`,
process IDs must agree with their declared host/PID/start fields, and linked records
must reference the paired process record with matching PID, executable, UID and GID.
An unlinked record must not claim that procfs identity or context. Contradictory raw
artifacts remain available; a failed comparison produces no downstream diff.

The telemetry adapter checks change-identity self-consistency. Its diff input does
not contain the complete paired procfs artifacts, so it cannot repeat cohort
validation or prove instance ownership. Names are contextual and excluded from the
existing link identity: a name-only difference does not create a link-change event.
Rejecting name mismatches as an identity test would both lose legitimate observations
and still miss PID/name reuse. No confidence or verification field is introduced.

`wildcard` means the socket was bound to an any-address value such as `0.0.0.0` or `::`. It does not prove external reachability because firewall, namespace, routing, and host policy are outside this snapshot.

## Diff interpretation

A diff can support review questions such as:

- Did a new process appear under an unexpected UID or executable path?
- Did a process with the same snapshot identity change executable or argv?
- Did a listener move from loopback-only to a wildcard address?
- Did a process connect to a new remote endpoint?
- Did a socket lose its process link because collection context changed?

These are evidence prompts, not compromise verdicts. The normalized artifacts are intended to support later detection reasoning while preserving bounded claims.
