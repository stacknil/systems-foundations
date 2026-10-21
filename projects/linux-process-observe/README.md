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

### Saved ss users field

After the six socket columns, process context may be absent or a complete users field:

```text
tail      := empty | "users:(" reference ("," reference)* ")"
reference := "(" '"' nonempty-name '"' ",pid=" digits ",fd=" digits ")"
```

For example, `users:(("worker-a",pid=120,fd=3),("worker-b",pid=220,fd=4))` is accepted. Names may contain spaces, commas and parentheses inside quotes, but not double quotes. PID and FD text use decimal digits; key order and delimiters must match the grammar, without extra internal spacing. PID conversion is unchanged, and FD is not stored. References are sorted and deduplicated by `(pid, name)`, including when only FD differs.

An absent field retains an unlinked socket. A present empty list, malformed member, truncated delimiter, missing wrapper or unconsumed suffix rejects the saved input rather than admitting a matching subset. The CLI returns 1 with contextual `input=ss` stderr and no new snapshot output. Error line numbers count nonblank lines, including an optional header.

This is a bounded saved-input profile. Thread attributes, alternate key order, quote escapes, fd-less references and extra tail metadata are unsupported; acceptance of every native ss variant is not claimed.


## Outputs

| Artifact | Contents |
| --- | --- |
| `process_snapshot.json` | Process identity, parent PID/identity, state, UID/GID, executable path, argv, and start time |
| `process_socket_links.json` | Listening sockets and network endpoints linked to process evidence when possible |
| `process_diff.json` | Added, removed, or modified processes plus added or removed process/socket links |
| `report.md` | Reviewer-friendly Markdown summary of the normalized diff |
| `telemetry_events.jsonl` | telemetry-lab-compatible events adapted from `process_diff.json` |

The three system-evidence `.json` artifacts use the same envelope:

```json
{
  "schema": "stacknil.system-evidence.v1",
  "source": "procfs",
  "host_id": "lab-host",
  "observed_at": "2026-07-05T00:00:00Z",
  "records": []
}
```

`observed_at` is required, must include a timezone, and is normalized to UTC. Whole-second inputs keep the existing `...00Z` form; fractional inputs retain up to microsecond precision so captures within the same second remain orderable. Inputs with more than six fractional-second digits fail closed instead of being silently truncated. Record ordering is deterministic.

A diff is produced only for a valid temporal cohort: the process and socket-link artifacts within each snapshot must represent the same observation instant, and the before instant must be strictly earlier than the after instant. Equivalent timezone representations compare as instants, not raw strings. Matching timestamps describe the intended snapshot cohort; they do not prove procfs and `ss` were collected atomically.

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

The adapter output has the required `timestamp`, `event_type`, `source`, `target`, and `status` fields. A process change maps to `process_added`, `process_removed`, or `process_modified`; a process/socket link change maps to `socket_link_added` or `socket_link_removed`. The process ID is the event source, the executable or endpoint is the target, and the diff change type is the status. Each row also keeps deterministic evidence metadata for traceability. `metadata.adapter_contract` is `stacknil.system-evidence.telemetry.v1`, separate from the source `metadata.evidence_schema`; `metadata.time_semantics` is `snapshot_diff_observed_at`: `timestamp` is when the snapshot comparison was observed, not an inferred process or socket occurrence time.

The JSONL can be supplied as `input_path` to telemetry-lab's existing `run window` configuration to produce its normal window features, alerts, summary, and run manifest. telemetry-lab's demo-specific deduplication and investigation workflows remain in that repository; this lab does not add a second copy of those commands or a fifth mini-lab.

## Identity And Link Semantics

- `process_id` is `host_id:pid:start_time_ticks`; PID alone is not treated as durable identity because Linux can reuse it.
- `start_time_ticks` is measured from system boot. Because the envelope has no boot identifier, `process_id` is a same-boot snapshot identity, not a cross-reboot durable identity.
- `parent_process_id` links to the same snapshot identity when the parent PID is present in the saved procfs export; otherwise it is `null`.
- UID/GID fields come from the saved procfs `status` record. Parent PID and start time come from `stat`.
- The executable path is context, not proof of the executable file's contents or integrity.
- Socket links use PID context reported by `ss`. `linked=true` means an unambiguous PID association within the supplied records, not independent verification of the socket's execution instance. A socket is retained with `linked=false` when no matching procfs context is available.
- A link's `process_name` preserves the name reported by `ss`; the selected process's name remains in `process_snapshot.json`. A disagreement is retained as context, without proving PID reuse or malicious behavior. Names can legitimately change, and matching names cannot exclude PID reuse between source captures.
- Link `process_id`, executable, UID and GID come from the PID-associated procfs record. Duplicate PID candidates are rejected rather than reconciled by input order. `diff` rejects process IDs inconsistent with their host/PID/start fields, dangling linked identities, and links whose procfs-derived fields disagree with the paired process artifact, even when timestamps match.
- The standalone telemetry adapter validates identity self-consistency; it does not have the paired procfs artifact and cannot independently revalidate a socket's process attribution. Link-name-only changes do not create new events: the link diff remains added/removed by the existing identity and endpoint key.
- `exposure=loopback`, `wildcard`, or `specific` describes the local bind address; it is not a firewall or reachability verdict.

## Validation Status

Pytest covers procfs parsing, `ss` parsing, process identity, socket linking, malformed inputs, timezone and subsecond normalization, fail-closed temporal cohort validation, golden artifacts, diffs, reports, and the CLI workflow.
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

## Saved Filesystem Failure Contract

Use a trusted, stable saved export on a local filesystem. Discovery keeps its
existing profile: numeric entries resolving to directories are parsed, including
directory symlinks; other entries are ignored, including broken numeric directory
links. This is not a completeness check for every numbered entry or a path sandbox.

Required `status`, `stat`, `cmdline`, text `exe`, and `ss` inputs must resolve to
regular files. Directory, FIFO, socket and device objects are rejected. Reads check
the opened descriptor as well as the path; POSIX nonblocking open prevents a FIFO
replacement between inspection and open from waiting for a writer. This does not
provide an arbitrary filesystem timeout or protection against all concurrent changes.

A real `exe` symlink remains supported: its UTF-8 target text is context and is
read without following the executable target. A dangling executable target is
therefore valid evidence; a broken required-file link is incomplete input. Invalid
UTF-8 in text or executable-link targets rejects the snapshot before output writes.
Executable paths remain descriptive, not authenticated identity or integrity proof.

Input failures return CLI exit 1 with operation, input category, native error type
and field/PID context where available. Missing PID files keep the existing
`ValueError` classification, as does invalid UTF-8 in `cmdline`; `PermissionError`
and other UTF-8 decoding error types are retained. The supplied input path remains
visible. Filesystem and UTF-8 diagnostics do not echo raw field contents; existing
parser diagnostics can include an offending malformed field value.
An unreadable export cannot become successful empty evidence. A readable empty
export with empty `ss` input remains valid.

`snapshot` validates its inputs before creating or changing output artifacts;
input-validation failure preserves existing evidence. Output filesystem failures
in `snapshot` and `diff` report `input=output` and exit 1. Multi-artifact writes
remain sequential, **not transactional**: a later write failure can leave an
earlier artifact updated. No atomic acquisition or multi-file rollback is claimed.

Run the failure suite from this project directory:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/test_native_read_failures.py -v
python -m pytest -q
```

Permission controls require a non-root POSIX user on a filesystem enforcing mode
bits, such as native ext4 under WSL2. Root and non-POSIX runs explicitly skip those
controls; link/FIFO probes also declare their POSIX requirement. Tests use synthetic
files and restore denied permissions in `finally` blocks. Existing golden evidence,
schemas, adapter semantics and successful command names are unchanged.

Decisions: skipping unreadable discovered PIDs would silently lose evidence;
rejecting every symlink would break the supported executable context profile.
Both alternatives are rejected. Transactional output publication needs a separate
storage/compatibility design and is not implied by these input-read guarantees.
