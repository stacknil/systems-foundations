# v0.3.0 Release Notes

## Title

408-to-Security Bridge

## Summary

`systems-foundations` now has four small, deterministic Linux/systems foundations mini-labs. This release adds the permission and process evidence paths and connects the process diff artifact to the existing telemetry-lab event contract without adding a fifth mini-lab.

The release remains local-file based and reviewable:

- permission state becomes normalized evidence and a Markdown drift report
- saved procfs and `ss` context become process snapshots, socket links, a diff, and a report
- `process_diff.json` can be adapted into telemetry-lab-compatible JSONL events

## Included In v0.3.0

- `projects/linux-permission-observe`
- `notes/408-to-linux-security.md`
- `projects/linux-process-observe`
- `notes/process-evidence-schema.md`
- the `stacknil.system-evidence.v1` evidence envelope
- the `linux-process-observe adapt` command
- adapter golden output and malformed-input coverage

## Adapter Contract

The adapter reads an existing `process_diff.json` and writes one JSON object per line with the required telemetry-lab fields:

| system-evidence diff | telemetry-lab event |
| --- | --- |
| `observed_at` | `timestamp` |
| process `added/removed/modified` | `event_type=process_added/process_removed/process_modified` |
| socket-link `added/removed` | `event_type=socket_link_added/socket_link_removed` |
| `process_id` | `source` |
| executable or formatted socket endpoint | `target` |
| `added/removed/modified` | `status` |
| snapshot comparison observation semantics | `metadata.time_semantics=snapshot_diff_observed_at` |

Each event includes deterministic metadata with the evidence schema, source, host, record type, identity, record index, and field changes. An unlinked socket uses a deterministic `host_id:pid:<pid>` source fallback when a PID is available.

`metadata.time_semantics` is `snapshot_diff_observed_at`. The event `timestamp`
is the diff observation time, not an inferred process-start, process-exit, or
socket-occurrence time. A window containing several adapter rows therefore
represents evidence deltas observed in one snapshot comparison; it does not
prove that those system activities happened together.

Run the bridge with:

```bash
python -m linux_process_observe adapt \
  --input output/diff/process_diff.json \
  --output output/diff/telemetry_events.jsonl
```

The output can be supplied as `input_path` to telemetry-lab's existing window workflow. That downstream repository owns its window, deduplication, and investigation demo artifacts; this release does not duplicate those workflows or change their schemas.

## Validation Status

- All four mini-lab pytest suites pass locally.
- `linux-process-observe` covers adapter golden output, malformed diff records, unlinked socket source fallback, and CLI error reporting.
- The adapter output satisfies telemetry-lab's required `timestamp`, `event_type`, `source`, `target`, and `status` event fields.

## Non-Goals

- no fifth mini-lab
- no live procfs crawling or real-time monitoring
- no `/proc/net/tcp` parsing, pcap, raw sockets, or packet sockets
- no auditd parser
- no database, network service, web UI, cloud dependency, or EDR agent behavior
