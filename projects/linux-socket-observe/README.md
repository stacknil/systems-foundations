# linux-socket-observe

`linux-socket-observe` is a deterministic, local-file-based mini-lab for normalizing Linux networking state snapshots and comparing them over time.

It is intentionally narrow: ingest a bounded set of `ss` and `iproute2` command outputs, turn them into one reviewable JSON snapshot, and emit a Markdown diff when the state changes.

## Supported Inputs

- `ss` text output
- `ip -j addr show`
- `ip -j link show`
- `ip -j neigh show`
- optional `ip -s -s link show`

## Commands

- `snapshot`: build one normalized snapshot JSON file from one set of saved command outputs
- `diff`: compare two normalized snapshots and write one Markdown report

## Workflow

The intended release workflow is:

1. Build a normalized snapshot from one set of local command-output files.
2. Build a second normalized snapshot from a later set of files.
3. Run `diff` to generate the Markdown report that summarizes added, removed, and changed state.
4. Review the JSON snapshot artifact and Markdown diff together.

```bash
python -m linux_socket_observe snapshot \
  --ss tests/fixtures/baseline/ss.txt \
  --ip-addr tests/fixtures/baseline/ip_addr.json \
  --ip-link tests/fixtures/baseline/ip_link.json \
  --ip-neigh tests/fixtures/baseline/ip_neigh.json \
  --ip-link-stats tests/fixtures/baseline/ip_link_stats.txt \
  --output output/baseline.json

python -m linux_socket_observe snapshot \
  --ss tests/fixtures/changed/ss.txt \
  --ip-addr tests/fixtures/changed/ip_addr.json \
  --ip-link tests/fixtures/changed/ip_link.json \
  --ip-neigh tests/fixtures/changed/ip_neigh.json \
  --ip-link-stats tests/fixtures/changed/ip_link_stats.txt \
  --output output/changed.json

python -m linux_socket_observe diff \
  --before output/baseline.json \
  --after output/changed.json \
  --output output/diff.md
```

If `snapshot` receives malformed `ss` or `iproute2` input, the current CLI returns a non-zero exit code and prints a bounded stderr line that includes the command, input name, path, error type, and message. `diff` behaves the same way for malformed snapshot inputs.

## Snapshot Schema

Each snapshot is one JSON object with four normalized sections:

- `sockets`
- `interfaces`
- `addresses`
- `neighbors`

Interface statistics are attached to `interfaces[].stats` only when `--ip-link-stats` is provided.

The current snapshot schema version is `0.1.0`.

## Assumptions

- Inputs are local point-in-time command-output snapshots, not live streams.
- `ss` parsing is limited to the bounded text shape covered by the current fixtures and tests.
- `ip -j addr show`, `ip -j link show`, and `ip -j neigh show` are expected to decode to JSON lists.
- The diff report is a state comparison aid, not packet analysis or traffic attribution.

## Non-Goals

- `/proc/net/tcp`
- pcap parsing
- live capture
- raw sockets or packet sockets
- databases or storage backends

## Validation Status

- `python -m pytest -q` currently passes locally for this mini-lab
- golden regression coverage locks the normalized baseline and changed snapshot artifacts
- parser coverage includes `ss` text, `ip -j addr show`, `ip -j link show`, `ip -j neigh show`, and optional `ip -s -s link show`
- malformed input coverage includes bad `ss` text and bad `ip -j link show` JSON
- CLI coverage includes `snapshot`, `diff`, and clean failure reporting for malformed inputs
