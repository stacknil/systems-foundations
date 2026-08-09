# linux-process-observe

`linux-process-observe` is a deterministic mini-lab for connecting saved Linux process identity evidence to saved socket state.

It reads local files only. It does not inspect the live host, run a resident agent, or claim EDR coverage.

## Supported Inputs

- a saved procfs export containing numeric PID directories
- `status`, `stat`, `cmdline`, and `exe` evidence for each exported PID
- saved `ss -H -a -n -t -u -p` text for TCP/UDP process/socket context

The fixture-friendly procfs export uses this layout:

```text
proc/
  120/
    status
    stat
    cmdline
    exe
```

`cmdline` may contain real NUL separators or the text escape `\0`. `exe` contains the resolved `/proc/<pid>/exe` target as UTF-8 text; a real symlink is also accepted.

## Outputs

| Artifact | Contents |
| --- | --- |
| `process_snapshot.json` | Process identity, parent PID/identity, state, UID/GID, executable path, argv, and start time |
| `process_socket_links.json` | Listening sockets and network endpoints linked to process evidence when possible |
| `process_diff.json` | Added, removed, or modified processes plus added or removed process/socket links |
| `report.md` | Reviewer-friendly Markdown summary of the normalized diff |
| `telemetry_events.jsonl` | telemetry-lab-compatible events adapted from `process_diff.json` |

All JSON artifacts use the same envelope:

```json
{
  "schema": "stacknil.system-evidence.v1",
  "source": "procfs",
  "host_id": "lab-host",
  "observed_at": "2026-07-05T00:00:00Z",
  "records": []
}
```

`observed_at` is required, must include a timezone, and is normalized to UTC. Record ordering is deterministic.

## Workflow

```bash
python -m pip install -e ".[dev]"

python -m linux_process_observe snapshot \
  --proc-root tests/fixtures/baseline/proc \
  --ss tests/fixtures/baseline/ss.txt \
  --host-id lab-host \
  --observed-at 2026-07-05T00:00:00Z \
  --output-dir output/baseline

python -m linux_process_observe snapshot \
  --proc-root tests/fixtures/changed/proc \
  --ss tests/fixtures/changed/ss.txt \
  --host-id lab-host \
  --observed-at 2026-07-05T00:05:00Z \
  --output-dir output/changed

python -m linux_process_observe diff \
  --before-processes output/baseline/process_snapshot.json \
  --after-processes output/changed/process_snapshot.json \
  --before-links output/baseline/process_socket_links.json \
  --after-links output/changed/process_socket_links.json \
  --output-dir output/diff
```

To bridge the diff into the existing telemetry-lab event contract:

```bash
python -m linux_process_observe adapt \
  --input output/diff/process_diff.json \
  --output output/diff/telemetry_events.jsonl
```

The adapter output has the required `timestamp`, `event_type`, `source`, `target`, and `status` fields. A process change maps to `process_added`, `process_removed`, or `process_modified`; a process/socket link change maps to `socket_link_added` or `socket_link_removed`. The process ID is the event source, the executable or endpoint is the target, and the diff change type is the status. Each row also keeps deterministic evidence metadata for traceability. `metadata.time_semantics` is `snapshot_diff_observed_at`: `timestamp` is when the snapshot comparison was observed, not an inferred process or socket occurrence time.

The JSONL can be supplied as `input_path` to telemetry-lab's existing `run window` configuration to produce its normal window features, alerts, summary, and run manifest. telemetry-lab's demo-specific deduplication and investigation workflows remain in that repository; this lab does not add a second copy of those commands or a fifth mini-lab.

## Identity And Link Semantics

- `process_id` is `host_id:pid:start_time_ticks`; PID alone is not treated as durable identity because Linux can reuse it.
- `parent_process_id` links to the same snapshot identity when the parent PID is present in the saved procfs export; otherwise it is `null`.
- UID/GID fields come from the saved procfs `status` record. Parent PID and start time come from `stat`.
- The executable path is context, not proof of the executable file's contents or integrity.
- Socket links use PID context reported by `ss`. A socket is retained with `linked=false` when no process context is available.
- `exposure=loopback`, `wildcard`, or `specific` describes the local bind address; it is not a firewall or reachability verdict.

## Validation Status

Pytest covers procfs parsing, `ss` parsing, process identity, socket linking, malformed inputs, timezone normalization, golden artifacts, diffs, reports, and the CLI workflow.
The adapter adds golden JSONL coverage, an unlinked-socket source fallback test, malformed diff coverage, and CLI error reporting coverage.

## Non-Goals

- no live `/proc` crawling or real-time monitoring
- no `/proc/net/tcp` parsing
- no Unix socket parsing
- no eBPF, netlink subscription, packet capture, or raw sockets
- no process termination, policy enforcement, or EDR agent behavior
- no database, service, web UI, or cloud dependency

## Related Note

- [Process evidence and envelope schema](../../notes/process-evidence-schema.md)
